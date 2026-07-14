"""
Tenx DML Builder Module
======================

This module provides the core logic for parsing 10x template patterns into a format
that can be stored in Splunk's KV store and used for search-time event inflation.

Template Format
---------------
10x templates use `$` as the variable separator. Variables appear as:
- `$` - Simple variable placeholder (replaced by var1, var2, etc.)
- `$(format)` - Timestamp variable with Java SimpleDateFormat pattern
- `$(epoch)` - Special case for milliseconds since Unix epoch

Example template:
    `$INFO [main] MyService - User $ performed $ at $(yyyy-MM-dd'T'HH:mm:ss.SSS'Z')`

This would be split into:
- part_0: "" (empty, template starts with variable)
- pattern_parts: ["INFO [main] MyService - User ", " performed ", " at __TENX_TS__"]
- pattern_terminator: "" (empty, template ends with timestamp)
- timestamp_format: "%Y-%m-%dT%H:%M:%S.%3QZ" (converted to Splunk strftime)

Timestamp Conversion
-------------------
Java SimpleDateFormat patterns are converted to Splunk strftime format:
- yyyy -> %Y (4-digit year)
- MM -> %m (2-digit month)
- dd -> %d (day of month)
- HH -> %H (24-hour)
- mm -> %M (minute)
- ss -> %S (second)
- SSS -> %3Q (milliseconds)
- Z -> %z (timezone)

Usage
-----
    builder = TenxDMLBuilder(
        timestamp_placeholder='__TENX_TS__',
        variable_separator='$'
    )

    # Parse template into KV store format
    record = builder.build_kv_record_data('abc123', '$INFO User $ logged in')

    # Build searchable DML line
    dml_line = builder.build_pure_dml_line('abc123', '$INFO User $ logged in')

See Also
--------
- macros.conf: The tenx-inflate macro that uses this data at search time
- tenx_dml_to_kv.py: Alert action that calls this builder
- collections.conf: KV store schema definition
"""

import logging

logger = logging.getLogger(__name__)


def convert_timestamp_segment(char, count):
	"""
	Convert a single Java SimpleDateFormat pattern character to Splunk strftime format.

	This function handles the conversion of individual timestamp format characters
	from Java's SimpleDateFormat notation to Splunk's strftime notation. The conversion
	is not always exact due to differences between the two format systems.

	Args:
		char (str): A single character from Java SimpleDateFormat pattern.
			Common values: y (year), M (month), d (day), H (hour), m (minute),
			s (second), S (subsecond), z/Z (timezone)
		count (int): Number of consecutive occurrences of the character.
			Affects output format (e.g., 'yy' vs 'yyyy')

	Returns:
		str: The equivalent Splunk strftime format string, or None if not recognized.

	Examples:
		>>> convert_timestamp_segment('y', 4)  # yyyy
		'%Y'
		>>> convert_timestamp_segment('M', 2)  # MM
		'%m'
		>>> convert_timestamp_segment('S', 3)  # SSS (milliseconds)
		'%3Q'

	Note:
		Some conversions are approximate as Splunk strftime has limitations:
		- No non-zero-padded variants for day/month/hour/minute/second
		- Limited timezone format options
	"""
	# Year: yyyy -> %Y (4-digit), yy -> %y (2-digit)
	if char == 'y':
		if count >= 4:
			return '%Y'
		return '%y'

	# Month: MMMM -> %B (full name), MMM -> %b (abbrev), MM/M -> %m (numeric)
	if char == 'M':
		if count >= 4:
			return '%B'
		if count == 3:
			return '%b'
		return '%m'  # Note: Splunk always zero-pads, no single-digit variant

	# Week in year
	if char == 'w':
		return '%V'  # Note: Splunk always zero-pads

	# Day in year
	if char == 'D':
		return '%j'  # Note: Splunk always zero-pads

	# Day in month
	if char == 'd':
		return '%d'  # Note: Splunk always zero-pads

	# Day name: EEEE -> %A (full), E/EE/EEE -> %a (abbreviated)
	if char == 'E':
		if count >= 4:
			return '%A'
		return '%a'

	# AM/PM marker
	if char == 'a':
		return '%p'

	# Hour in day (0-23): H or k
	if char == 'H' or char == 'k':
		return '%H'  # Note: Splunk always zero-pads

	# Hour in am/pm (0-11): K or h
	if char == 'K' or char == 'H':
		return '%I'  # Note: Splunk always zero-pads

	# Minute in hour
	if char == 'm':
		return '%M'  # Note: Splunk always zero-pads

	# Second in minute
	if char == 's':
		return '%S'  # Note: Splunk always zero-pads

	# Subsecond (milliseconds/microseconds): SSS -> %3Q, SSSSSS -> %6Q
	if char == 'S':
		return '%' + str(count) + 'Q'

	# Timezone: z -> abbreviated name (PST), Z -> RFC 822 (+0800)
	if char == 'z':
		return '%Z'  # Note: Only abbreviated form supported

	if char == 'Z':
		return '%z'

	# ISO 8601 timezone: X -> +08, XX -> +0800, XXX -> +08:00
	if char == 'X':
		if count == 1:
			return '%:::z'
		return '%:z'

	# Return None for unrecognized characters (will be handled by caller)
	return None


def to_splunk_time_format(s):
	"""
	Returns a Splunk strftime compatible time format string.
	"""
	if not s:
		return ""

	if s == 'epoch':
		# 'epoch' is a special case for timestamp format, which just means "ms since epoch".
		# %s is the seconds since epoch, and %Q is the ms leftover.
		#
		return '%s%Q'

	result = ''
	current_alpha = ''
	current_alpha_count = 0

	for char in s:
		if char == current_alpha:
			current_alpha_count += 1
			continue

		if current_alpha_count > 0:
			segment = convert_timestamp_segment(current_alpha, current_alpha_count)
			# Handle unrecognized timestamp characters - keep them as-is
			result += segment if segment is not None else (current_alpha * current_alpha_count)
			current_alpha = ''
			current_alpha_count = 0

		if char.isalpha():
			current_alpha = char
			current_alpha_count = 1
			continue

		if char == '%':
			result += '%%'  # Splunk strftime timestamp parts with %, so for actual % we need to use %%
		else:
			result += char

	if current_alpha_count > 0:
		segment = convert_timestamp_segment(current_alpha, current_alpha_count)
		result += segment if segment is not None else (current_alpha * current_alpha_count)

	return result


RECORD_PATTERN_HASH = "pattern_hash"
RECORD_PATTERN = "pattern"
RECORD_PATTERN_PARTS = "pattern_parts"
RECORD_PART_0 = "part_0"
RECORD_PATTERN_TERMINATOR = "pattern_terminator"
RECORD_TIMESTAMP_FORMAT = "timestamp_format"

RECORD_HEADERS = [
	RECORD_PATTERN_HASH, RECORD_PATTERN, RECORD_PATTERN_PARTS, RECORD_PART_0, RECORD_PATTERN_TERMINATOR, RECORD_TIMESTAMP_FORMAT
]


class TenxDMLBuilder:
	"""
	Class for converting a 10x pattern into various models to store in splunk
	"""

	def __init__(self, timestamp_placeholder, variable_separator, escape_character='/'):
		self.timestamp_placeholder = timestamp_placeholder
		self.variable_separator = variable_separator
		self.escape_character = escape_character

	def build_pure_dml_line(self, key, pattern):
		"""
		Returns a line to store in the pure dml sourcetype.

		The line format is "<pattern key> <processed pattern>", where the processed pattern is just the
		pattern, stripped from variables separators and new lines, which might hinder actual search.

		The "$0(" escape (a plain variable immediately followed by a literal '(', see
		build_kv_record_data) is stripped as a pair, so the escape digit doesn't linger as a
		stray "0" in the searchable preview text. Only a real, unescaped "$0(" marker is
		collapsed this way - an escaped literal "$0(" occurring in the raw source text is left
		alone, matching how build_kv_record_data decides what counts as escaped.
		"""
		normalized = self._collapse_dollar_zero_escape(pattern)

		return key + " " + normalized.replace(self.variable_separator, "").replace("\r\n", " ").replace("\n", " ")

	def _collapse_dollar_zero_escape(self, pattern):
		"""
		Removes the disambiguation '0' from every real (unescaped) "<variable_separator>0("
		occurrence, leaving an escaped (literal) occurrence of the same three characters
		untouched. Tracks escape_character state the same way build_kv_record_data does, so
		the two functions agree on what counts as "escaped".
		"""
		sep = self.variable_separator
		esc = self.escape_character
		pattern_length = len(pattern)
		result = []
		currently_escaping = False
		index = 0

		while index < pattern_length:
			current_char = pattern[index]

			if current_char == esc:
				currently_escaping = not currently_escaping
				result.append(current_char)
				index += 1
				continue

			if current_char == sep:
				if currently_escaping:
					currently_escaping = False
				elif index < pattern_length - 2 and pattern[index+1] == '0' and pattern[index+2] == '(':
					result.append(sep + '(')
					index += 3
					continue

			result.append(current_char)
			index += 1

		return ''.join(result)

	def build_kv_record_data(self, pattern_hash, base_pattern):
		"""
		Returns the record we place in the KV store for the event pattern.

		The record comprises of several parts:
		* pattern				- The raw pattern provided. While this isn't currently used in the decoding
								  process, we save it for future use.
		* pattern_parts			- The parts of the pattern after splitting it with variable_separator, excluding
								  the first and last parts. If the pattern has 2 parts or less, this is an empty list.
		* part_0				- The first part of the pattern. If the pattern is only 1 part long, this is empty
		* pattern_terminator	- The last part of the pattern, always contains something (a pattern is never empty)
		* timestamp_format		- The format for the timestamp of this pattern, used with Splunk's strftime to render
								  the actual timestamp for each individual event.
		"""
		pattern_parts = []
		current_part = ''
		currently_escaping = False
		timestamp_format = None

		pattern_length = len(base_pattern)
		index = 0

		# Spliting the pattern based on the variable separator
		#
		while index < pattern_length:
			current_char = base_pattern[index]

			if current_char == self.escape_character:
				if currently_escaping:
					current_part += current_char

				currently_escaping = not currently_escaping

			elif current_char == self.variable_separator:
				if currently_escaping:
					current_part += current_char
					currently_escaping = False

				else:
					if index < pattern_length - 2 and base_pattern[index+1] == '(':
						# Timestamp are special variables, which are encoded in the form of $(<timestamp>)
						# We replace the value with a place holder, and extract the format for use in the macro.
						#
						current_part += self.timestamp_placeholder
						timestamp_start = index + 2

						while base_pattern[index] != ')' and index < pattern_length:
							index += 1

						timestamp_end = index

						timestamp_format = base_pattern[timestamp_start:timestamp_end]

					elif index < pattern_length - 2 and base_pattern[index+1] == '0' and base_pattern[index+2] == '(':
						# A plain (non-timestamp) variable whose value is immediately followed by a
						# literal '(' is encoded as "$0(" rather than bare "$(", so it isn't misread
						# as the start of a timestamp specifier. The '0' carries no value of its own
						# (offset 0 always means "a new variable", never a back-reference) - skip it
						# so it isn't glued onto the next pattern part as literal text.
						#
						pattern_parts.append(current_part)
						current_part = ''
						index += 1

					else:
						# Really a variable at this point, so we split.
						#
						pattern_parts.append(current_part)
						current_part = ''

			else:
				current_part += current_char

			index += 1

		# Even if empty, we append the current part, as if we did a simple 'pattern.split(self.value_separator)'
		#
		pattern_parts.append(current_part)

		timestamp_format = to_splunk_time_format(timestamp_format)
		part_0 = ""

		if timestamp_format:
			actual_parts = pattern_parts[:-1]
		else:
			actual_parts = pattern_parts[1:-1]

			if len(pattern_parts) >= 2:
				part_0 = pattern_parts[0]

		pattern_terminator = pattern_parts[-1]

		return {
			RECORD_PATTERN_HASH: pattern_hash,
			RECORD_PATTERN: base_pattern,
			RECORD_PATTERN_PARTS: actual_parts,
			RECORD_PART_0: part_0,
			RECORD_PATTERN_TERMINATOR: pattern_terminator,
			RECORD_TIMESTAMP_FORMAT: timestamp_format
		}
