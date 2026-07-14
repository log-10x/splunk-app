"""
Unit tests for tenx_dml_builder module.

Tests the template parsing and timestamp conversion logic without requiring Splunk.
"""
import sys
import os

# Add the bin directory to path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'bin'))

import pytest
from tenx_dml_builder import (
	convert_timestamp_segment,
	to_splunk_time_format,
	TenxDMLBuilder,
	RECORD_PATTERN_HASH,
	RECORD_PATTERN,
	RECORD_PATTERN_PARTS,
	RECORD_PART_0,
	RECORD_PATTERN_TERMINATOR,
	RECORD_TIMESTAMP_FORMAT
)


class TestConvertTimestampSegment:
	"""Tests for convert_timestamp_segment function."""

	def test_year_4_digit(self):
		assert convert_timestamp_segment('y', 4) == '%Y'

	def test_year_2_digit(self):
		assert convert_timestamp_segment('y', 2) == '%y'

	def test_month_full_name(self):
		assert convert_timestamp_segment('M', 4) == '%B'

	def test_month_abbreviated(self):
		assert convert_timestamp_segment('M', 3) == '%b'

	def test_month_numeric(self):
		assert convert_timestamp_segment('M', 2) == '%m'
		assert convert_timestamp_segment('M', 1) == '%m'

	def test_day_of_month(self):
		assert convert_timestamp_segment('d', 2) == '%d'
		assert convert_timestamp_segment('d', 1) == '%d'

	def test_day_name_full(self):
		assert convert_timestamp_segment('E', 4) == '%A'

	def test_day_name_abbreviated(self):
		assert convert_timestamp_segment('E', 3) == '%a'
		assert convert_timestamp_segment('E', 1) == '%a'

	def test_hour_24(self):
		assert convert_timestamp_segment('H', 2) == '%H'
		assert convert_timestamp_segment('k', 2) == '%H'

	def test_minute(self):
		assert convert_timestamp_segment('m', 2) == '%M'

	def test_second(self):
		assert convert_timestamp_segment('s', 2) == '%S'

	def test_milliseconds(self):
		assert convert_timestamp_segment('S', 3) == '%3Q'

	def test_microseconds(self):
		assert convert_timestamp_segment('S', 6) == '%6Q'

	def test_timezone_abbreviated(self):
		assert convert_timestamp_segment('z', 1) == '%Z'

	def test_timezone_rfc822(self):
		assert convert_timestamp_segment('Z', 1) == '%z'

	def test_am_pm(self):
		assert convert_timestamp_segment('a', 1) == '%p'

	def test_week_in_year(self):
		assert convert_timestamp_segment('w', 2) == '%V'

	def test_day_in_year(self):
		assert convert_timestamp_segment('D', 3) == '%j'

	def test_unrecognized_returns_none(self):
		assert convert_timestamp_segment('x', 1) is None
		assert convert_timestamp_segment('Q', 1) is None


class TestToSplunkTimeFormat:
	"""Tests for to_splunk_time_format function."""

	def test_empty_string(self):
		assert to_splunk_time_format('') == ''

	def test_none_returns_empty(self):
		assert to_splunk_time_format(None) == ''

	def test_epoch_special_case(self):
		assert to_splunk_time_format('epoch') == '%s%Q'

	def test_simple_date(self):
		result = to_splunk_time_format('yyyy/MM/dd')
		assert result == '%Y/%m/%d'

	def test_simple_time(self):
		result = to_splunk_time_format('HH:mm:ss')
		assert result == '%H:%M:%S'

	def test_date_with_time(self):
		result = to_splunk_time_format('yy/MM/dd HH:mm:ss')
		assert result == '%y/%m/%d %H:%M:%S'

	def test_percent_escaping(self):
		result = to_splunk_time_format('yyyy%MM%dd')
		assert result == '%Y%%%m%%%d'

	def test_quoted_literals_simplified(self):
		# Single quotes are just passed through (not alpha)
		result = to_splunk_time_format("yyyy-MM-dd'T'HH:mm:ss")
		# The 'T' becomes just T (alpha T is unrecognized, kept as-is)
		assert 'T' in result


class TestTenxDMLBuilder:
	"""Tests for TenxDMLBuilder class."""

	@pytest.fixture
	def builder(self):
		return TenxDMLBuilder(
			timestamp_placeholder='__TENX_TS__',
			variable_separator='$'
		)

	def test_build_pure_dml_line_simple(self, builder):
		result = builder.build_pure_dml_line('abc123', '$INFO User $ logged in')
		assert result == 'abc123 INFO User  logged in'

	def test_build_pure_dml_line_no_variables(self, builder):
		result = builder.build_pure_dml_line('xyz', 'Static message')
		assert result == 'xyz Static message'

	def test_build_pure_dml_line_newlines_removed(self, builder):
		result = builder.build_pure_dml_line('key', 'Line1\nLine2\r\nLine3')
		assert result == 'key Line1 Line2 Line3'

	def test_build_kv_record_simple_pattern(self, builder):
		result = builder.build_kv_record_data('hash1', '$INFO User $ logged in')

		assert result[RECORD_PATTERN_HASH] == 'hash1'
		assert result[RECORD_PATTERN] == '$INFO User $ logged in'
		assert result[RECORD_PART_0] == ''
		assert result[RECORD_PATTERN_PARTS] == ['INFO User ']
		assert result[RECORD_PATTERN_TERMINATOR] == ' logged in'
		assert result[RECORD_TIMESTAMP_FORMAT] == ''

	def test_build_kv_record_with_timestamp(self, builder):
		result = builder.build_kv_record_data(
			'hash2',
			'$(yyyy-MM-dd HH:mm:ss) INFO User $ logged in'
		)

		assert result[RECORD_PATTERN_HASH] == 'hash2'
		assert result[RECORD_TIMESTAMP_FORMAT] == '%Y-%m-%d %H:%M:%S'
		assert '__TENX_TS__' in result[RECORD_PATTERN_TERMINATOR] or any(
			'__TENX_TS__' in part for part in result[RECORD_PATTERN_PARTS]
		)

	def test_build_kv_record_pattern_starts_with_text(self, builder):
		result = builder.build_kv_record_data('hash3', 'Starting text $ middle $ end')

		assert result[RECORD_PART_0] == 'Starting text '
		assert result[RECORD_PATTERN_PARTS] == [' middle ']
		assert result[RECORD_PATTERN_TERMINATOR] == ' end'

	def test_build_kv_record_multiple_variables(self, builder):
		result = builder.build_kv_record_data('hash4', '$A$B$C$D$')

		# Pattern: $A$B$C$D$ splits into ['', 'A', 'B', 'C', 'D', '']
		# part_0 = '', pattern_parts = ['A', 'B', 'C', 'D'], terminator = ''
		assert result[RECORD_PART_0] == ''
		assert result[RECORD_PATTERN_TERMINATOR] == ''
		assert len(result[RECORD_PATTERN_PARTS]) == 4

	def test_build_kv_record_no_variables(self, builder):
		result = builder.build_kv_record_data('hash5', 'Just static text')

		assert result[RECORD_PATTERN_HASH] == 'hash5'
		assert result[RECORD_PATTERN] == 'Just static text'
		assert result[RECORD_PATTERN_TERMINATOR] == 'Just static text'

	def test_build_kv_record_epoch_timestamp(self, builder):
		result = builder.build_kv_record_data('hash6', '$(epoch) Event occurred')

		assert result[RECORD_TIMESTAMP_FORMAT] == '%s%Q'

	def test_escaped_variable_separator(self, builder):
		# Test that /$ is treated as literal $
		result = builder.build_kv_record_data('hash7', 'Price is /$100 for $')

		assert result[RECORD_PATTERN] == 'Price is /$100 for $'
		# The escaped $ should not be treated as a variable separator


class TestDollarZeroEscape:
	"""
	Tests for the "$0(" escape: a plain (non-timestamp) variable whose value is immediately
	followed by a literal '(' in the source text is encoded as "$0(" rather than bare "$(",
	so it isn't misread as the start of a "$(<timestamp>)" specifier. Offset 0 always means
	"a new variable" (never a back-reference), so the '0' carries no value of its own and
	must not leak into the reassembled text.
	"""

	@pytest.fixture
	def builder(self):
		return TenxDMLBuilder(
			timestamp_placeholder='__TENX_TS__',
			variable_separator='$'
		)

	def test_dollar_zero_does_not_leak_into_terminator(self, builder):
		result = builder.build_kv_record_data('h1', 'status$0(pending)')

		assert result[RECORD_PART_0] == 'status'
		assert result[RECORD_PATTERN_PARTS] == []
		assert result[RECORD_PATTERN_TERMINATOR] == '(pending)'
		assert result[RECORD_TIMESTAMP_FORMAT] == ''

	def test_dollar_zero_reassembles_correctly(self, builder):
		result = builder.build_kv_record_data('h1', 'status$0(pending)')

		reassembled = result[RECORD_PART_0] + '200' + ''.join(result[RECORD_PATTERN_PARTS]) + result[RECORD_PATTERN_TERMINATOR]

		assert reassembled == 'status200(pending)'

	def test_dollar_zero_mid_pattern(self, builder):
		# the escape can occur on ANY variable in the pattern, not just the last one
		result = builder.build_kv_record_data('h2', 'a$0(b)c$d')

		assert result[RECORD_PART_0] == 'a'
		assert result[RECORD_PATTERN_PARTS] == ['(b)c']
		assert result[RECORD_PATTERN_TERMINATOR] == 'd'

	def test_dollar_zero_is_not_confused_with_a_real_timestamp(self, builder):
		# bare "$(" must still be read as a timestamp specifier, unaffected by the $0 fix
		result = builder.build_kv_record_data('h3', '$(epoch) Event occurred')

		assert result[RECORD_TIMESTAMP_FORMAT] == '%s%Q'

	def test_dollar_followed_by_literal_digit_zero_then_other_text_is_still_a_variable(self, builder):
		# "$0x" ('(' does not follow) is just a plain variable; the literal "0x" is ordinary text
		result = builder.build_kv_record_data('h4', 'a$0x')

		assert result[RECORD_PART_0] == 'a'
		assert result[RECORD_PATTERN_TERMINATOR] == '0x'

	def test_pure_dml_line_strips_the_escape_digit_too(self, builder):
		result = builder.build_pure_dml_line('h1', 'status$0(pending)')

		assert result == 'h1 status(pending)'

	def test_pure_dml_line_leaves_an_escaped_dollar_zero_alone(self, builder):
		# an escaped "$" immediately followed by literal "0(" is real source text, not the
		# disambiguation marker - build_kv_record_data preserves it verbatim (via its own
		# escape-tracking), and build_pure_dml_line must agree, not silently drop the '0'.
		escaped_builder = TenxDMLBuilder(
			timestamp_placeholder='__TENX_TS__',
			variable_separator='$',
			escape_character='/'
		)

		result = escaped_builder.build_pure_dml_line('h1', 'a/$0(b)c')

		assert result == 'h1 a/0(b)c'

	def test_pure_dml_line_dollar_zero_still_collapses_after_an_escaped_dollar(self, builder):
		# a genuine (unescaped) $0( elsewhere in the same pattern must still collapse, even
		# when an escaped literal $ also appears earlier in the pattern.
		escaped_builder = TenxDMLBuilder(
			timestamp_placeholder='__TENX_TS__',
			variable_separator='$',
			escape_character='/'
		)

		result = escaped_builder.build_pure_dml_line('h1', '/$100 then status$0(pending)')

		assert result == 'h1 /100 then status(pending)'

	def test_multiple_dollar_zero_escapes_in_one_pattern(self, builder):
		result = builder.build_kv_record_data('h5', 'a$0(b)c$0(d)e')

		assert result[RECORD_PART_0] == 'a'
		assert result[RECORD_PATTERN_PARTS] == ['(b)c']
		assert result[RECORD_PATTERN_TERMINATOR] == '(d)e'

	def test_dollar_zero_escape_at_start_of_pattern(self, builder):
		result = builder.build_kv_record_data('h6', '$0(x)')

		assert result[RECORD_PART_0] == ''
		assert result[RECORD_PATTERN_PARTS] == []
		assert result[RECORD_PATTERN_TERMINATOR] == '(x)'


class TestTenxDMLBuilderCustomConfig:
	"""Tests for TenxDMLBuilder with custom configuration."""

	def test_custom_timestamp_placeholder(self):
		builder = TenxDMLBuilder(
			timestamp_placeholder='<<TS>>',
			variable_separator='$'
		)
		result = builder.build_kv_record_data('h1', '$(yyyy) Event')

		# Check that custom placeholder is used
		assert '<<TS>>' in result[RECORD_PATTERN_TERMINATOR] or any(
			'<<TS>>' in str(part) for part in result[RECORD_PATTERN_PARTS]
		)

	def test_custom_variable_separator(self):
		builder = TenxDMLBuilder(
			timestamp_placeholder='__TS__',
			variable_separator='@'
		)
		result = builder.build_pure_dml_line('key', '@INFO User @ logged in')

		# @ should be removed like $ normally is
		assert result == 'key INFO User  logged in'

	def test_custom_escape_character(self):
		builder = TenxDMLBuilder(
			timestamp_placeholder='__TS__',
			variable_separator='$',
			escape_character='\\'
		)
		# With \ as escape, \$ should be literal $
		result = builder.build_kv_record_data('h2', 'Price is \\$100 for $')

		# The result should have the escaped $ preserved
		assert result[RECORD_PATTERN] == 'Price is \\$100 for $'
