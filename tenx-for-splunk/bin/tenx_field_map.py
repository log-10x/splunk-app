#!/usr/bin/env python3
"""
Index-time field map for compact events
=======================================

Data models, their accelerations, Enterprise Security and every saved search that does not go
through `tx` read an event's fields as Splunk stores it. A compact event is stored as
`~<hash>,<value>,<value>,...`, so none of the original event's fields exist there, and the
original sourcetype's search-time extractions find nothing in that text.

This tool writes, for one compact sourcetype, a small Splunk app that rebuilds those fields
while the event is indexed:

* transforms.conf, one index-time transform per template. REGEX matches that template's
  compact line and captures each value; FORMAT writes every original field as `name::"value"`,
  the value made of the template's own text and the captured values; WRITE_META = true stores
  the result as indexed fields. FORMAT may join text and captures only at index time
  (transforms.conf.spec: "You cannot create concatenated fields with FORMAT at search time"),
  and the engine splits one field's value over several compact values, which is why this is
  an index-time step.
* props.conf, the compact sourcetype: the parsing settings of the app's own [tenx_encoded]
  stanza, the generated TRANSFORMS- list, and `rename = <original sourcetype>`. Renamed data
  "only uses the search-time configuration for the target sourcetype" (props.conf.spec), so
  the original add-on's aliases, calculated fields, lookups, eventtypes and tags run on the
  indexed fields.
* props.conf and transforms.conf, search-time: the hash and values of a compact event for `tx`
  (tenx_fm_hash_vars, the regex of the app's tenx-hash-vars-extraction with the leading "~"
  required), under the rename target's own stanza. The compact sourcetype's REPORT-tenx cannot do
  this: a renamed event runs only the target's search-time rules (Splunk Enterprise 10.4.3: a
  REPORT-tenx in the compact stanza gave tenx_hash on 0 of 662 renamed events; this one gives it
  on 662 of 662, and on 0 of 662 uncompacted events of the target sourcetype, whose text never
  starts with "~").
* every FORMAT also writes tenx_mapped::"1" (--mark), so an event whose template had a transform
  is told apart from one indexed before its transform existed: `sourcetype::<compact>
  NOT tenx_mapped::1` counts the latter. `tx` hides an event with tenx_mapped from its `extract`
  (see macros.conf [tx]): the add-on's extractions with MV_ADD would otherwise add every indexed
  field a second time.
* fields.conf, INDEXED_VALUE = false for fields that searches match with wildcards. Splunk
  looks the words of `field="*value*"` up in the index before it reads the field, and on a
  compact event the words of template text are not in the index.
* app.conf and metadata/default.meta (export = system).

* one more index-time transform, first in the list, writes tenx_compact_st::"<compact sourcetype>"
  on every event of the compact sourcetype (--sourcetype-field), compact or not. It is how `tx`
  finds these events: `tenx-events` (tenx-for-splunk, Settings > Advanced search > Search macros)
  must name it, for example `index=* (sourcetype::tenx_encoded OR tenx_compact_st::tenx_win)`;
  gen prints this line. `sourcetype::tenx_win` does not do: Splunk checks it against the
  event's search-time sourcetype, the rename target, whenever the search also compares a field
  at search time, so `index=X host=Y sourcetype::tenx_win` returns no event (Splunk Enterprise
  10.4.3: 0 of 662 renamed events; without host=Y, 662).

Which fields a template yields is decided by a "first link" reader, applied to the template's
text with a marker in place of every value, and applied unchanged to raw text by `verify`:

* xml-windows: the Windows add-on's XML extractions, copied from Splunk_TA_windows 12.0.0
  default/transforms.conf ([system_xml_block] with [system_props_xml_kv] and
  [system_props_xml_attributes], [eventdata_xml_block] with [eventdata_xml_data],
  [renderinginfo_xml_block] with [rendering_info_xml_data]).
* json: one field per JSON leaf, named the way Splunk names JSON fields: nested object keys
  joined with ".", an array adding "{}" to the name of its elements
  (`requestParameters.launchPermission.add.items{}.userId`). Read from field names in Splunk's
  own detections for aws:cloudtrail, not from a running Splunk.
* kv: `name=value` and `name="value"` pairs delimited by whitespace. A conservative subset of
  Splunk's automatic key-value extraction, whose exact rules were not available to read.

Rules this keeps from the first generator of these files (b2_gen.py), each counted in the report:

* The app's template store keeps a hash without its leading and trailing spaces, and compact
  lines carry the hash as the engine wrote it (26 of 1,783 hashes on the 4663 sample carry
  one). The REGEX allows spaces on both sides of the hash by default.
* FORMAT cannot express every value: text with a line break, text with a double quote (FORMAT
  values are quoted), text holding `$<digit>` (read as a capture group), and a capture group
  followed by a digit (`$1` then `2` reads as `$12`). Such a value is written by one
  index-time INGEST_EVAL transform, last in the TRANSFORMS- list (`--eval-values on`, the
  default; `off` leaves the field out and the report names it, as the first generated files did).
  The template's own transform writes which form of the field its template has,
  tenx_fmf_<name>::"<form>", and the compact values the form reads, tenx_fmv_<name>_<j>::"$<group>";
  the INGEST_EVAL builds each such field as a case() over its forms, the template text as SPL
  strings through urldecode() (no line break, quote, backslash, '$' or '%' in the .conf line),
  then removes the working fields (`:=null()`, transforms.conf.spec). One transform serves
  every template because an INGEST_EVAL has no REGEX of its own: it "overrides all but one of
  other index-time settings (such as REGEX, DEST_KEY, etc)" (transforms.conf.spec), so one per
  template would run on every event once per template. A field whose name is a compact value
  is still left out: "The capability of the search-time |eval operator to name the destination
  field based on the value of another field (like "| eval {destname}=1") is NOT available for
  index-time evaluations" (transforms.conf.spec). So is one whose name is not a plain field
  name (a JSON path): NOT CHECKED whether INGEST_EVAL takes such a name as written.
  A field name for FORMAT must be one capture group or a literal field name.
* Whitespace at the ends of a value is dropped for the xml-windows reader, as the add-on's
  search-time extraction drops it (Splunk 10.4.3: LogonProcessName "NtLmSsp " in the XML reads
  as "NtLmSsp", and UserAccountControl, whose text starts with a line break and two tabs, as
  "%%2080 ..."). With `--eval-values off` only spaces and tabs are dropped, as before;
  `--trim-values off` keeps all of it, as the first generated files did.
* A field whose value holds the timestamp is written as the event wrote it (`--timestamp-values
  text`, the default) by the same INGEST_EVAL, which renders the compact epoch with the
  record's format in UTC the way tenx-inflate does at search time. `epoch` writes the epoch
  digits the compact line carries, by FORMAT, as the first generated files did; `skip` leaves
  the field out.
* Transform stanza names carry the template's position in the sorted input by default, because
  two hashes can be equal once their punctuation is replaced by `_`.

`verify` proves offline, on a sample, that (1) the marked template text expands every compact
event to its raw event, and (2) the fields the generated transforms write, applied in Python
to each compact line, equal the fields the same reader finds in the raw event. It does not
prove what Splunk does with the generated files.

Usage
-----
    tenx_field_map.py gen --records <kv_rows.json | templates.json> [--records ...]
        --target windows-security | <target.json> [--sourcetype ...] [--rename ...] --out <app dir>
    tenx_field_map.py verify --records ... --target ... --encoded <encoded.log> --raw <raw.log>
    tenx_field_map.py gen ... --cap-file <compact cap file> [--splunkd <management URL>]
    tenx_field_map.py activate --app <app dir> --cap-file <compact cap file> --splunkd <management URL>

`--cap-file` keeps the Receiver's compact cap file to the templates whose transform is active where
the data is parsed, so an event goes compact only once its fields can be written (see "The engine's
compact cap file" below).

Standard library only.
"""

import argparse
import base64
import collections
import configparser
import csv
import datetime
import hashlib
import json
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.parse
import urllib.request

# The app's own modules sit beside this file; `python3 -I` leaves the script's folder off the path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tenx_consts  # noqa: E402
import tenx_dml_builder  # noqa: E402

TIMESTAMP_PLACEHOLDER = tenx_consts.DEFAULT_CONFIG['timestamp_placeholder']
VARIABLE_SEPARATOR = tenx_consts.DEFAULT_CONFIG['variable_separator']

# Marker for compact value k. With a timestamp, value 0 is the epoch and values 1..n follow the
# template's plain variables; without one, value 0 is the first plain variable.
MARK = "\x00%d\x00"
MARK_RE = re.compile(r"\x00(\d+)\x00")
MARK_SPLIT = re.compile(r"(\x00\d+\x00)")

WHY_LINE_BREAK = "line break in template text"
WHY_QUOTE = "double quote in template text"
WHY_DOLLAR_DIGIT = "dollar-digit in template text"
WHY_GROUP_DIGIT = "group followed by a digit"
WHY_NAME_MIXES = "name mixes text and a value"
WHY_NAME_NOT_FIELD = "name not a field name"
WHY_TIMESTAMP = "value carries the timestamp"
WHY_SPLIT_ESCAPE = "escape sequence split by a value"
WHY_RESERVED = "name collides with a Splunk default field"
WHY_EVAL_NAME = "name from a value, which INGEST_EVAL cannot write"
WHY_EVAL_NAME_SHAPE = "name INGEST_EVAL does not take as written"
WHY_EVAL_TWICE = "second value of a field INGEST_EVAL writes"
WHY_EVAL_FORMAT = "timestamp directive not rendered at index time"

# Values FORMAT cannot write that INGEST_EVAL writes instead (--eval-values on): text with a line
# break, a double quote or $<digit>, and a capture group followed by a digit.
EVAL_REASONS = frozenset((WHY_LINE_BREAK, WHY_QUOTE, WHY_DOLLAR_DIGIT, WHY_GROUP_DIGIT))
# Working fields the template's own FORMAT writes for the INGEST_EVAL, which removes them.
EVAL_FORM_PREFIX = 'tenx_fmf_'
EVAL_VALUE_PREFIX = 'tenx_fmv_'
EVAL_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')
# What Splunk drops at the ends of an extracted value: spaces and tabs (LogonProcessName "NtLmSsp "
# reads as "NtLmSsp"), and line breaks (UserAccountControl's text in the XML starts with a line
# break and two tabs; the add-on's extraction of the raw event starts at "%%2080").
TRIM_CHARS = ' \t\r\n\v\f'

# Field names Splunk gives every event itself. An indexed field whose name equals one of them,
# ignoring case, does not arrive under its own name: on Splunk Enterprise 10.4.3 the
# indexed field eventType came back as extracted_eventType on all 8,100 CloudTrail events, while
# KV_MODE = json on the same events uncompacted gave eventType, so the add-on's rules would not find it. The names:
# the default fields Splunk returned on every event of a REST export (host, source,
# sourcetype, index, splunk_server, linecount, punct, eventtype, tag, tag::*, timestamp, _*), plus
# date_*, timestartpos and timeendpos, which Splunk computes for every event. Only the eventtype
# collision was seen renamed; that the others are renamed the same way is not checked. Names built from a value at index time
# ($<group>) cannot be checked here; verify counts the ones a sample produces.
RESERVED_FIELDS = frozenset(('host', 'source', 'sourcetype', 'index', 'splunk_server', 'linecount', 'punct',
	'eventtype', 'tag', 'timestamp', 'timestartpos', 'timeendpos'))
RESERVED_PREFIXES = ('_', 'tag::', 'date_')

# Put in a reader's output where text cannot be decoded without the value that follows it (a
# JSON backslash in template text, the escaped character in the value). FORMAT refuses it.
UNDECODABLE = "\x01"

REFUSED_UNSAFE = "the app does not expand this template (expand_unsafe: %s)"
REFUSED_CONFLICT = "two different templates under one hash"
REFUSED_COUNT = "number of values unknown (no timestamp, no text before the first value, no pattern)"
REFUSED_NO_FIELDS = "the reader found no field"

# Settings of the app's [tenx_encoded] stanza that are copied, in this order, then every key
# with one of the prefixes in the stanza's own order. Every other key of the stanza is listed
# in the report as not copied, so a parsing setting added to the app later is seen, not lost.
COPIED_KEYS = ('DATETIME_CONFIG', 'LINE_BREAKER', 'SHOULD_LINEMERGE', 'NO_BINARY_CHECK', 'TRUNCATE')
COPIED_PREFIXES = ('TRANSFORMS-', 'SEDCMD-')
SOURCE_STANZA = 'tenx_encoded'
# The indexed field every FORMAT writes, unless --mark none.
MARK_FIELD = 'tenx_mapped'
# Indexed field every event of the compact sourcetype gets, for tenx-events (see the docstring).
SOURCETYPE_FIELD = 'tenx_compact_st'
# Search-time hash and values of a compact event under the rename target (see the docstring).
HASH_TRANSFORM = 'tenx_fm_hash_vars'
HASH_REGEX = '^~(?<tenx_hash>[^,]+)(?:,(?<tenx_var_0>[^,]+)(?:,(?<tenx_vars>.*))?)?'

# re.escape's set of escaped characters on Python 3.7 and later, written out so the generated
# REGEX does not depend on the interpreter, plus "/" (escaped by the first generator as well).
_REGEX_SPECIAL = frozenset('()[]{}?*+-|^$\\.&~# \t\n\r\v\f/')

WINDOWS_WILDCARD_FIELDS = ('object_file_path', 'object_path', 'object_file_name', 'ObjectName', 'ObjectType',
	'process_path', 'process_name', 'ProcessName', 'file_path', 'file_name')

# Built-in target descriptions. Any key can be overridden on the command line or given in a
# JSON file with the same keys.
TARGETS = {
	'windows-security': {
		'reader': 'xml-windows',
		'sourcetype': 'tenx_win',
		'rename': 'XmlWinEventLog',
		'transform_prefix': 'tenx_win',
		'transforms_class': 'tenx_win',
		# Fields ESCU's EventCode 4663 detections match with wildcard values.
		'indexed_value_false': list(WINDOWS_WILDCARD_FIELDS),
		'description': 'Compact Windows Security events',
	},
}


# ---------------------------------------------------------------------------------------------
# Template records

Template = collections.namedtuple('Template', 'key written_hash parts part_0 terminator timestamp_format '
	'expand_unsafe pattern')


def _as_list(value):
	if value is None:
		return []
	if isinstance(value, list):
		return value
	# A plain string is taken as one part, as the first generator did. Every one of the 1,879 rows
	# exported from a KV store held a list.
	return [value]


def _from_kv_row(row):
	# pattern_hash keeps the hash as the engine wrote it, outer spaces included (78 of 6,647 rows
	# of one KV store); _key holds it trimmed.
	written = row.get('pattern_hash')
	if not written or written.strip() != row['_key']:
		written = row['_key']
	return Template(
		key=row['_key'], written_hash=written, parts=_as_list(row.get('pattern_parts')),
		part_0=row.get('part_0') or '', terminator=row.get('pattern_terminator') or '',
		timestamp_format=row.get('timestamp_format') or '', expand_unsafe=row.get('expand_unsafe') or '',
		pattern=row.get('pattern'))


def _from_template_line(obj, builder):
	written = obj['templateHash']
	# The app's KV store holds the hash without surrounding spaces (4663 sample: the 26
	# hashes that carry one are stored stripped, and every other field of the record equals
	# what TenxDMLBuilder makes of the template).
	key = written.strip()
	rec = builder.build_kv_record_data(key, obj['template'])
	return Template(
		key=key, written_hash=written, parts=list(rec[tenx_dml_builder.RECORD_PATTERN_PARTS]),
		part_0=rec[tenx_dml_builder.RECORD_PART_0] or '', terminator=rec[tenx_dml_builder.RECORD_PATTERN_TERMINATOR],
		timestamp_format=rec[tenx_dml_builder.RECORD_TIMESTAMP_FORMAT] or '',
		expand_unsafe=rec[tenx_dml_builder.RECORD_EXPAND_UNSAFE] or '', pattern=obj['template'])


def load_templates(path):
	"""
	Template records from a file in either form: the JSON array the KV store REST endpoint
	returns for collection tenx_dml (rows with _key, pattern_parts, part_0, pattern_terminator,
	timestamp_format, expand_unsafe), or the engine's templates.json, one
	{"templateHash", "template"} object per line, read with the app's own TenxDMLBuilder.
	"""
	with open(path, encoding='utf-8') as f:
		text = f.read()

	if text.lstrip().startswith('['):
		return [_from_kv_row(r) for r in json.loads(text)]

	builder = tenx_dml_builder.TenxDMLBuilder(timestamp_placeholder=TIMESTAMP_PLACEHOLDER,
		variable_separator=VARIABLE_SEPARATOR)
	return [_from_template_line(json.loads(line), builder) for line in text.splitlines() if line.strip()]


def _same_template(a, b):
	return (a.parts, a.part_0, a.terminator, a.timestamp_format) == (b.parts, b.part_0, b.terminator, b.timestamp_format)


def merge_templates(lists):
	"""
	One template per key, and the keys refused because two different templates share them.
	Returns (dict key -> Template, dict key -> reason).
	"""
	by_key, refused = {}, {}

	for templates in lists:
		for t in templates:
			seen = by_key.get(t.key)
			if seen is None:
				by_key[t.key] = t
			elif not _same_template(seen, t):
				refused[t.key] = REFUSED_CONFLICT

	for key in refused:
		del by_key[key]

	return by_key, refused


def hash_keys_in(path):
	"""The template keys (stripped hashes) named in a templates.json or KV export file."""
	return set(t.key for t in load_templates(path))


# ---------------------------------------------------------------------------------------------
# Marked text

def value_count(t):
	"""
	How many values a compact line of this template carries, or None when the record alone
	does not say. Follows the app's tenx-inflate macro: with a timestamp, the epoch then one
	value per entry of pattern_parts; without one, part_0, value 0, then pattern_parts zipped
	with values 1..n, then the terminator.
	"""
	if t.timestamp_format:
		return len(t.parts) + 1

	if t.parts or t.part_0:
		return len(t.parts) + 1

	# No timestamp, nothing before the first value, no middle parts: the template is either a
	# literal line (no value) or one value followed by the terminator. Only the original
	# pattern tells: it starts with an unescaped variable separator in the second case.
	if t.pattern is None:
		return None

	return 1 if t.pattern.startswith(VARIABLE_SEPARATOR) else 0


def marked_text(t):
	"""
	The template's text with MARK % k in place of compact value k. Returns (text, value count);
	raises ValueError when the count is unknown.
	"""
	n = value_count(t)
	if n is None:
		raise ValueError(REFUSED_COUNT)

	ts = MARK % 0
	out = []

	if t.timestamp_format:
		for i, part in enumerate(t.parts):
			out.append(part.replace(TIMESTAMP_PLACEHOLDER, ts))
			out.append(MARK % (i + 1))
		out.append(t.terminator.replace(TIMESTAMP_PLACEHOLDER, ts))
		return ''.join(out), n

	if n == 0:
		return t.terminator, 0

	out.append(t.part_0)
	out.append(MARK % 0)
	for i, part in enumerate(t.parts):
		out.append(part)
		out.append(MARK % (i + 1))
	out.append(t.terminator)
	return ''.join(out), n


# ---------------------------------------------------------------------------------------------
# Readers: which (name, value) pairs a text yields. Both may contain markers.

class XmlWindowsReader(object):
	"""
	Splunk_TA_windows 12.0.0 default/transforms.conf, lines 1003 to 1062: the System,
	EventData and RenderingInfo blocks, then <tag>value</tag> and attributes in System and
	RenderingInfo, <Data Name='X'>value</Data> in EventData.

	Then the UserData block ([userdata_xml_block], transforms.conf:1012-1014) with the rules the
	add-on applies to it for source XmlWinEventLog:Security (props.conf:299-300 and 401):
	[logfilecleared_xml_block] (transforms.conf:1433-1436) and [LogFileClearedData_from_user_data]
	(1438-1441), <tag>value</tag> inside <LogFileCleared>, as written by event 1102 (log cleared);
	and [SubjectUserName_from_user_data] (1443-1446), the text of <SubjectUserName> anywhere in
	UserData as Caller_User_Name. The add-on's UserData rules for other sources
	([source::XmlWinEventLog:System], props.conf:290 and 203-204) are not included. Checked
	against those rules on a synthetic event only; NOT CHECKED on Splunk.

	The add-on matches a closing tag to its opening tag with a back-reference. A tag name that
	is a compact value is a marker, and the closing tag carries its own marker, so a marker
	tag accepts any closing tag.
	"""
	name = 'xml-windows'
	raw_split = r'\n(?=<Event xmlns)'
	# Splunk 10.4.3 gives LogonProcessName "NtLmSsp" for <Data Name='LogonProcessName'>NtLmSsp </Data>
	# (50 of 662 events); an indexed field keeps what FORMAT writes.
	trims_values = True
	field_name = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')

	BLOCKS = (
		('System', re.compile(r"(?ms)<System(?:\s+[^>]+)?>(.*?)<\/System>")),
		('EventData', re.compile(r"(?ms)<EventData(?:\s+[^>]+)?>(.*?)<\/EventData>")),
		('RenderingInfo', re.compile(r"(?ms)<RenderingInfo(?:\s+[^>]+)?>(.*?)<\/RenderingInfo>")),
	)
	KV = re.compile(r"(?ms)<(\w+|\x00\d+\x00)>([^<]*)<\/(\w+|\x00\d+\x00)>")
	ATTR = re.compile(r"(?ms)\s([^\s=]+)\s*=\s*(['\"])([^<]*?)\2")
	DATA = re.compile(r"<(?:\w+)\sName='([^>]*)'\/?>([^<]*)(?:<\/[^>]*>)?")
	USERDATA = re.compile(r"(?ms)<UserData(?:\s+[^>]+)?>(.*?)<\/UserData>")
	LOGFILECLEARED = re.compile(r"(?ms)<LogFileCleared(?:\s+[^>]+)?>(.*?)<\/LogFileCleared>")
	SUBJECT_USER_NAME = re.compile(r"(?ms)<SubjectUserName(?:\s+[^>]+)?>(.*?)<\/SubjectUserName>")

	def _kv(self, body, out):
		for m in self.KV.finditer(body):
			opening, value, closing = m.groups()
			if MARK_RE.fullmatch(opening) is None and opening != closing:
				continue
			out.append((opening, value))

	def pairs(self, text):
		out = []
		for block, rx in self.BLOCKS:
			for body in rx.findall(text):
				if block in ('System', 'RenderingInfo'):
					self._kv(body, out)
					if block == 'System':
						for m in self.ATTR.finditer(body):
							out.append((m.group(1), m.group(3)))
				else:
					for m in self.DATA.finditer(body):
						out.append((m.group(1), m.group(2)))
		for body in self.USERDATA.findall(text):
			for cleared in self.LOGFILECLEARED.findall(body):
				self._kv(cleared, out)
			for m in self.SUBJECT_USER_NAME.finditer(body):
				out.append(('Caller_User_Name', m.group(1)))
		return out


class JsonReader(object):
	"""
	One pair per JSON leaf (string, number, true, false, null), named by its path: object keys
	joined with ".", "{}" added for each array level. An empty object or array yields nothing.
	Strings are decoded (\\" becomes ", \\\\ becomes \\). A marker outside a string is part of a
	bare value. Text that is not one JSON value yields nothing.
	"""
	name = 'json'
	raw_split = r'\n'
	trims_values = False  # NOT CHECKED: no JSON value with edge spaces in the CloudTrail sample
	field_name = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\{\})*(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\{\})*)*\Z')

	_WS = ' \t\r\n'
	_ESC = {'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}

	def pairs(self, text):
		self._s, self._i, self._out = text, 0, []
		try:
			self._value('')
			self._skip()
			if self._i != len(self._s):
				return []
		except (IndexError, KeyError, ValueError):
			return []
		return self._out

	def _skip(self):
		s = self._s
		while self._i < len(s) and s[self._i] in self._WS:
			self._i += 1

	def _value(self, path):
		self._skip()
		c = self._s[self._i]
		if c == '{':
			self._object(path)
		elif c == '[':
			self._array(path)
		elif c == '"':
			self._out.append((path, self._string()))
		else:
			start = self._i
			s = self._s
			while self._i < len(s) and s[self._i] not in ',]}' and s[self._i] not in self._WS:
				self._i += 1
			if self._i == start:
				raise ValueError('empty value')
			self._out.append((path, s[start:self._i]))

	def _object(self, path):
		self._i += 1
		self._skip()
		if self._s[self._i] == '}':
			self._i += 1
			return
		while True:
			self._skip()
			if self._s[self._i] != '"':
				raise ValueError('key expected')
			key = self._string()
			self._skip()
			if self._s[self._i] != ':':
				raise ValueError('colon expected')
			self._i += 1
			self._value(key if not path else path + '.' + key)
			self._skip()
			c = self._s[self._i]
			self._i += 1
			if c == '}':
				return
			if c != ',':
				raise ValueError('comma expected')

	def _array(self, path):
		self._i += 1
		self._skip()
		if self._s[self._i] == ']':
			self._i += 1
			return
		while True:
			self._value(path + '{}')
			self._skip()
			c = self._s[self._i]
			self._i += 1
			if c == ']':
				return
			if c != ',':
				raise ValueError('comma expected')

	def _string(self):
		s = self._s
		self._i += 1
		buf = []
		while True:
			c = s[self._i]
			if c == '"':
				self._i += 1
				return ''.join(buf)
			if c == '\\':
				e = s[self._i + 1]
				if e == 'u':
					buf.append(chr(int(s[self._i + 2:self._i + 6], 16)))
					self._i += 6
				elif e == '\x00':
					# The engine cut the token at the backslash: the escaped character is the
					# first character of the value. Only this string is lost.
					buf.append(UNDECODABLE)
					self._i += 1
				else:
					buf.append(self._ESC[e])
					self._i += 2
				continue
			buf.append(c)
			self._i += 1


class KeyValueReader(object):
	"""
	`name=value` and `name="value"` where the pair starts the text or follows whitespace. A
	quoted value runs to the next double quote and must be followed by whitespace or the end;
	an unquoted value runs to the next whitespace. A name is a field name or one compact value.
	This is a conservative subset of Splunk's automatic key-value extraction (KV_MODE = auto),
	whose exact rules (other separators, single quotes, escapes, name cleaning) were not
	available to read.
	"""
	name = 'kv'
	raw_split = r'\n'
	trims_values = False  # NOT CHECKED
	field_name = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')

	PAIR = re.compile(r'(?<!\S)((?:[A-Za-z0-9_]|\x00\d+\x00)+)=(?:"([^"]*)"(?=\s|\Z)|(\S*))')

	def pairs(self, text):
		out = []
		for m in self.PAIR.finditer(text):
			value = m.group(2) if m.group(2) is not None else m.group(3)
			out.append((m.group(1), value))
		return out


READERS = {r.name: r for r in (XmlWindowsReader, JsonReader, KeyValueReader)}


# ---------------------------------------------------------------------------------------------
# REGEX and FORMAT

def regex_escape(text):
	return ''.join('\\' + c if c in _REGEX_SPECIAL else c for c in text)


def compact_line_regex(key, n, hash_match='tolerant'):
	"""
	The REGEX of a template's transform: the hash after "~", then n comma-separated captures.
	'tolerant' allows spaces on both sides of the hash, as compact lines carry hashes the app's
	store keeps stripped; 'exact' is the form of the first generated files (662-event sample).
	"""
	space = ' *' if hash_match == 'tolerant' else ''
	head = '^~' + space + regex_escape(key) + space
	if n == 0:
		return head + '$'
	return head + ',' + ','.join(['([^,]*)'] * n) + '$'


def to_format(expr, is_name, field_name=None, mixed_names=False):
	"""
	Marked text as FORMAT text: literal pieces and $<group>, group = value index + 1. Returns
	(text, None), or (None, reason) when FORMAT cannot express it.

	A name is one capture group or a literal field name. With mixed_names, a name that joins
	text and captures (a JSON path through a key the engine stored as a value) is written as
	that concatenation; whether Splunk accepts a concatenated name in FORMAT is NOT CHECKED.
	"""
	pieces = MARK_SPLIT.split(expr)
	out = []

	for i, piece in enumerate(pieces):
		m = MARK_RE.fullmatch(piece)
		if m:
			following = pieces[i + 1] if i + 1 < len(pieces) else ''
			if following[:1].isdigit():
				return None, WHY_GROUP_DIGIT
			out.append('$%d' % (int(m.group(1)) + 1))
		else:
			if UNDECODABLE in piece:
				return None, WHY_SPLIT_ESCAPE
			if '"' in piece:
				return None, WHY_QUOTE
			if '\n' in piece or '\r' in piece:
				return None, WHY_LINE_BREAK
			if re.search(r'\$\d', piece):
				return None, WHY_DOLLAR_DIGIT
			out.append(piece)

	text = ''.join(out)

	if is_name:
		if len(pieces) == 3 and pieces[0] == '' and pieces[2] == '':
			return text, None
		if MARK_RE.search(expr):
			if not mixed_names:
				return None, WHY_NAME_MIXES
			if not field_name.match(MARK_RE.sub('x', expr)):
				return None, WHY_NAME_NOT_FIELD
			return text, None
		if not field_name.match(text):
			return None, WHY_NAME_NOT_FIELD

	return text, None


# ---------------------------------------------------------------------------------------------
# INGEST_EVAL

# Literal text written as a quoted SPL string; anything else goes through urldecode(), so a
# line break, a tab, a quote, a backslash, '$' or '%' never sits in the .conf line or the string.
_SPL_PLAIN = re.compile(r'[A-Za-z0-9 _.:/-]*\Z')


def spl_text(text):
	"""Literal text as an SPL expression."""
	if _SPL_PLAIN.match(text):
		return '"%s"' % text
	return 'urldecode("%s")' % ''.join(c if c.isascii() and c.isalnum() else ''.join('%%%02X' % b for b in c.encode('utf-8'))
		for c in text)


_TS_TOKEN = re.compile(r'%(?:%|-[HIMSdmj]|:::z|:z|\d+Q|[A-Za-z])|[^%]+')
_TS_DATE = frozenset(('%Y', '%y', '%B', '%b', '%m', '%-m', '%V', '%j', '%-j', '%d', '%-d', '%A', '%a'))


def spl_timestamp(v, fmt):
	"""
	SPL that renders the compact epoch v (an SPL expression: 13 or 19 digits) with the record's
	Splunk strftime format in UTC, the way the app's tenx-inflate macro does at search time:
	hours, minutes and seconds from the epoch by arithmetic, fraction digits copied from the
	value, the zone as UTC, and the date with strftime() from that day's noon shifted by the
	instance's own offset at noon, which is the UTC date in every zone. Returns None for a
	directive this does not render.
	"""
	if fmt == tenx_dml_builder.EPOCH_PASSTHROUGH:
		return v
	sec = 'tonumber(substr(%s, 1, 10))' % v
	sod = '(%s - floor(%s / 86400) * 86400)' % (sec, sec)
	noon = '(%s - %s + 43200)' % (sec, sod)
	tz = 'strftime(%s, "%%z")' % noon
	utc = '(%s - if(substr(%s, 1, 1) == "-", -1, 1) * (tonumber(substr(%s, 2, 2)) * 3600 + tonumber(substr(%s, 4, 2)) * 60))' % (
		noon, tz, tz, tz)
	hour = 'floor(%s / 3600)' % sod
	minute = 'floor((%s %% 3600) / 60)' % sod
	second = '(%s %% 60)' % sod
	hour12 = 'if(%s %% 12 == 0, 12, %s %% 12)' % (hour, hour)

	def two(x):
		return 'substr("0" . %s, -2)' % x

	time_parts = {
		'%H': two(hour), '%-H': 'tostring(%s)' % hour, '%I': two(hour12), '%-I': 'tostring(%s)' % hour12,
		'%M': two(minute), '%-M': 'tostring(%s)' % minute, '%S': two(second), '%-S': 'tostring(%s)' % second,
		'%p': 'if(%s < 12, "AM", "PM")' % hour, '%Z': '"UTC"', '%z': '"+0000"', '%:z': '"+00:00"', '%:::z': '"+00"',
		'%%': '"%"',
	}
	out, date = [], []

	def flush():
		if date:
			out.append('strftime(%s, "%s")' % (utc, ''.join(date)))
			del date[:]

	for m in _TS_TOKEN.finditer(fmt):
		tok = m.group(0)
		if tok in _TS_DATE:
			date.append(tok)
		elif not tok.startswith('%'):
			if date and _SPL_PLAIN.match(tok):
				date.append(tok)
			else:
				flush()
				out.append(spl_text(tok))
		else:
			flush()
			q = re.fullmatch(r'%(\d+)Q', tok)
			if q:
				out.append('substr(%s . "000000000", 11, %s)' % (v, q.group(1)))
			elif tok in time_parts:
				out.append(time_parts[tok])
			else:
				return None
	flush()
	return ' . '.join(out) if out else '""'


def eval_field_name(prefix, name, j=None):
	return '%s%s' % (prefix, name) if j is None else '%s%s_%d' % (prefix, name, j)


def ingest_eval_text(field_map):
	"""
	The one INGEST_EVAL of the field map: each field as a case() over its forms, keyed on the form
	the event's template transform wrote, then the working fields removed. An event whose template
	has no form of a field gets null(), which writes no field.
	"""
	by_name = collections.OrderedDict()
	for (name, pieces, ts), form in field_map.forms.items():
		by_name.setdefault(name, []).append((form, pieces, ts))
	exprs = []
	for name, forms in by_name.items():
		branches = []
		for form, pieces, ts in forms:
			parts = []
			for piece in pieces:
				if isinstance(piece, int):
					value = 'coalesce(%s, "")' % eval_field_name(EVAL_VALUE_PREFIX, name, abs(piece))
					parts.append(spl_timestamp(value, ts) if piece < 0 else value)
				else:
					parts.append(spl_text(piece))
			branches.append('%s=="%d", %s' % (eval_field_name(EVAL_FORM_PREFIX, name), form, ' . '.join(parts) or '""'))
		exprs.append('%s=case(%s)' % (name, ', '.join(branches)))
	for name, count in field_map.eval_values_per_name.items():
		exprs.append('%s:=null()' % eval_field_name(EVAL_FORM_PREFIX, name))
		exprs.extend('%s:=null()' % eval_field_name(EVAL_VALUE_PREFIX, name, j) for j in range(1, count + 1))
	return ', '.join(exprs)


def eval_value(form_key, groups, timestamp_format):
	"""The value a form gives for the captured values `groups` (verify's Python reading)."""
	name, pieces, ts = form_key
	out = []
	for piece in pieces:
		if isinstance(piece, int):
			v = groups[abs(piece) - 1] or ''
			out.append(format_timestamp(v, ts) if piece < 0 else v)
		else:
			out.append(piece)
	return ''.join(out)


def reserved_name(name):
	"""True when an indexed field of this name would collide with a Splunk default field."""
	low = name.lower()
	return low in RESERVED_FIELDS or low.startswith(RESERVED_PREFIXES)


def _shown(expr):
	"""Marked text for a report: markers as $<group>."""
	return MARK_RE.sub(lambda m: '$%d' % (int(m.group(1)) + 1), expr)


def sanitize(key):
	return re.sub(r'[^A-Za-z0-9_]', '_', key)


def stanza_name(prefix, position, key, style):
	if style == 'indexed':
		return '%s_%05d_%s' % (prefix, position, sanitize(key))
	if style == 'hash':
		return '%s_%s' % (prefix, sanitize(key))
	if style == 'stable':
		return '%s_%s_%s' % (prefix, sanitize(key), hashlib.sha1(key.encode('utf-8')).hexdigest()[:8])
	raise ValueError('unknown stanza name style: %s' % style)


# evals: the fields of the template INGEST_EVAL writes, as (name, form, capture groups the form reads).
Transform = collections.namedtuple('Transform', 'key stanza regex format fields value_count evals', defaults=((),))


class FieldMap(object):
	"""
	The transforms for a set of templates, and what was left out and why.
	"""

	def __init__(self, templates, reader, prefix, stanza_names='indexed', hash_match='tolerant',
			timestamp_values='epoch', keep=None, refused=None, mixed_names=False, trim_values=None,
			reserved_names='skip', reserved_prefix='extracted_', mark=None, eval_values=False):
		self.reader = reader
		# Values FORMAT cannot write, and with timestamp_values 'text' the timestamp as the event
		# wrote it, go to one INGEST_EVAL transform (see ingest_eval_text). Off: left out as before.
		self.eval_values = eval_values
		self.timestamp_values = timestamp_values
		# (name, pieces, timestamp format) -> form number, from 1 in order of first use. A piece is
		# literal text or the 1-based position of a compact value in the form.
		self.forms = collections.OrderedDict()
		# name -> the most values one of its forms reads
		self.eval_values_per_name = collections.OrderedDict()
		self.eval_fields = collections.Counter()
		self.timestamp_text_fields = collections.Counter()
		# Written last by every FORMAT as <mark>::"1", unless None.
		self.mark = mark
		# A literal name that collides with a Splunk default field: 'skip' leaves it out, 'prefix'
		# writes it as <reserved_prefix><name>. Both are counted in the report.
		self.reserved_names = reserved_names
		self.reserved_prefix = reserved_prefix
		self.reserved = collections.Counter()
		# Spaces and tabs at the ends of a value come only from template text (a compact value
		# never holds one), so trimming the marked text trims the value Splunk would see.
		self.trim_values = reader.trims_values if trim_values is None else trim_values
		# With INGEST_EVAL on, line breaks at the ends go too (TRIM_CHARS); off, spaces and tabs only,
		# as the first generated files had it.
		self.trim_chars = TRIM_CHARS if eval_values else ' \t'
		self.transforms = []
		self.refused = dict(refused or {})
		self.skipped = collections.Counter()
		self.skipped_detail = []
		self.timestamp_fields = collections.Counter()
		# Per template, the name expressions of pairs left out or written as epoch: what verify
		# expects to differ from raw.
		self.explained = collections.defaultdict(list)
		self.literal_names = collections.Counter()
		self.mixed_names = collections.Counter()
		self.templates_in = len(templates) + len(self.refused)
		self.templates_kept = 0
		self.outer_space_hashes = 0

		seen_stanzas = {}

		# Position in the sorted input, before any template is filtered out or refused, so
		# a stanza's name does not depend on which others are kept.
		for position, key in enumerate(sorted(set(templates) | set(self.refused))):
			if key in self.refused:
				continue
			t = templates[key]
			if keep is not None and key not in keep:
				continue
			self.templates_kept += 1
			if t.written_hash != t.key:
				self.outer_space_hashes += 1

			if t.expand_unsafe:
				self.refused[key] = REFUSED_UNSAFE % t.expand_unsafe
				continue

			try:
				text, n = marked_text(t)
			except ValueError as e:
				self.refused[key] = str(e)
				continue

			stanza = stanza_name(prefix, position, key, stanza_names)
			if stanza in seen_stanzas:
				raise ValueError('stanza name %s is the same for hashes %r and %r; use --stanza-names indexed'
					% (stanza, seen_stanzas[stanza], key))
			seen_stanzas[stanza] = key

			tokens = []
			evals = []
			for name_expr, value_expr in reader.pairs(text):
				name, why = to_format(name_expr, True, reader.field_name, mixed_names)
				if name is None:
					self._skip(key, stanza, 'name: ' + why, name_expr)
					continue
				if self.trim_values:
					value_expr = value_expr.strip(self.trim_chars)
				value, why = to_format(value_expr, False)
				carries_ts = bool(t.timestamp_format) and (MARK % 0) in value_expr
				by_eval = False
				if value is None:
					if not (self.eval_values and why in EVAL_REASONS):
						self._skip(key, stanza, 'value: ' + why, name_expr)
						continue
					by_eval = True
				elif value == '':
					continue
				if carries_ts and not by_eval:
					if timestamp_values == 'skip':
						self._skip(key, stanza, 'value: ' + WHY_TIMESTAMP, name_expr)
						continue
					by_eval = timestamp_values == 'text'
					if not by_eval:
						self.timestamp_fields[_shown(name_expr)] += 1
						self.explained[key].append(name_expr)
				if '$' not in name and reserved_name(name):
					self.reserved[name] += 1
					if self.reserved_names == 'skip':
						self._skip(key, stanza, 'name: ' + WHY_RESERVED, name_expr)
						continue
					self.explained[key].extend([name_expr, self.reserved_prefix + name_expr])
					name = self.reserved_prefix + name
				if by_eval:
					reason = self._eval_field(name, value_expr, t.timestamp_format if carries_ts else '', evals)
					if reason:
						self._skip(key, stanza, reason, name_expr)
					elif carries_ts:
						self.timestamp_text_fields[name] += 1
					continue
				tokens.append('%s::"%s"' % (name, value))
				if '$' not in name:
					self.literal_names[name] += 1
				elif not name.startswith('$'):
					self.mixed_names[name] += 1

			for name, form, groups in evals:
				tokens.append('%s%s::"%d"' % (EVAL_FORM_PREFIX, name, form))
				tokens.extend('%s%s_%d::"$%d"' % (EVAL_VALUE_PREFIX, name, j, g) for j, g in enumerate(groups, 1))
				self.eval_fields[name] += 1
				self.literal_names[name] += 1

			if not tokens:
				self.refused[key] = REFUSED_NO_FIELDS
				continue

			fields = len(tokens) - sum(1 + len(groups) for _, _, groups in evals) + len(evals)
			if self.mark:
				tokens.append('%s::"1"' % self.mark)
			self.transforms.append(Transform(key, stanza, compact_line_regex(key, n, hash_match), ' '.join(tokens),
				fields, n, tuple(evals)))

	def _eval_field(self, name, value_expr, timestamp_format, evals):
		"""
		Records a field INGEST_EVAL writes for this template: its form, and the capture groups the
		form reads, in order. Returns None, or the reason the field is left out.
		"""
		if '$' in name:
			return 'name: ' + WHY_EVAL_NAME
		if not EVAL_NAME.match(name):
			return 'name: ' + WHY_EVAL_NAME_SHAPE
		if any(n == name for n, _, _ in evals):
			return 'value: ' + WHY_EVAL_TWICE
		if UNDECODABLE in value_expr:
			return 'value: ' + WHY_SPLIT_ESCAPE
		groups, pieces = [], []
		for piece in MARK_SPLIT.split(value_expr):
			m = MARK_RE.fullmatch(piece)
			if m is None:
				if piece:
					pieces.append(piece)
				continue
			k = int(m.group(1))
			if k + 1 not in groups:
				groups.append(k + 1)
			pieces.append(groups.index(k + 1) + 1)
		ts = timestamp_format if timestamp_format and 1 in groups else ''
		if ts:
			if spl_timestamp('v', ts) is None:
				return 'value: ' + WHY_EVAL_FORMAT
			# the epoch is value 0, group 1: mark its position in the form
			pieces = [-p if isinstance(p, int) and groups[p - 1] == 1 else p for p in pieces]
		key = (name, tuple(pieces), ts)
		form = self.forms.setdefault(key, len(self.forms) + 1)
		self.eval_values_per_name[name] = max(self.eval_values_per_name.get(name, 0), len(groups))
		evals.append((name, form, tuple(groups)))
		return None

	def _skip(self, key, stanza, reason, name_expr):
		self.skipped[reason] += 1
		self.explained[key].append(name_expr)
		self.skipped_detail.append({'hash': key, 'stanza': stanza, 'field': _shown(name_expr), 'reason': reason})

	def report(self):
		per = [t.fields for t in self.transforms]
		refused = collections.Counter(self.refused.values())
		return collections.OrderedDict([
			('templates', len(self.transforms)),
			('fields_per_template_min_max', [min(per), max(per)] if per else []),
			('skipped', dict(self.skipped)),
			('literal_field_names', len(self.literal_names)),
			('mixed_field_names', len(self.mixed_names)),
			('templates_in_input', self.templates_in),
			('templates_selected', self.templates_kept),
			('hashes_with_outer_spaces', self.outer_space_hashes),
			('templates_without_transform', dict(refused)),
			('timestamp_written_as_epoch', dict(self.timestamp_fields)),
			('timestamp_written_as_text', dict(self.timestamp_text_fields)),
			('written_by_ingest_eval', collections.OrderedDict([
				('templates_per_field', dict(self.eval_fields)),
				('forms_per_field', dict(collections.Counter(name for name, _, _ in self.forms))),
				('working_fields_per_event_max', max([sum(1 + len(g) for _, _, g in t.evals) for t in self.transforms] or [0]))])),
			('reserved_field_names', collections.OrderedDict([
				('action', 'left out' if self.reserved_names == 'skip' else 'written as %s<name>' % self.reserved_prefix),
				('templates_per_name', dict(self.reserved))])),
			('values_per_template_max', max([t.value_count for t in self.transforms] or [0])),
			('skipped_detail', self.skipped_detail),
			('templates_without_transform_detail', [{'hash': k, 'reason': v} for k, v in sorted(self.refused.items())]),
		])


# ---------------------------------------------------------------------------------------------
# Target description and the generated app

def load_target(name_or_path, overrides):
	if name_or_path in TARGETS:
		target = dict(TARGETS[name_or_path])
	elif name_or_path:
		with open(name_or_path, encoding='utf-8') as f:
			target = json.load(f)
	else:
		target = {}

	for k, v in overrides.items():
		if v is not None:
			target[k] = v

	for required in ('reader', 'sourcetype', 'rename'):
		if not target.get(required):
			raise ValueError('the target needs "%s"' % required)
	if target['reader'] not in READERS:
		raise ValueError('unknown reader %s (one of %s)' % (target['reader'], ', '.join(sorted(READERS))))

	target.setdefault('transform_prefix', sanitize(target['sourcetype']))
	target.setdefault('transforms_class', target['transform_prefix'])
	target.setdefault('indexed_value_false', [])
	target.setdefault('description', 'Compact events renamed to %s' % target['rename'])
	target.setdefault('app_name', 'tenx_fieldmap_' + sanitize(target['sourcetype']))
	return target


def default_app_props():
	return os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'default', 'props.conf')


def parsing_settings(props_path):
	"""
	The settings of [tenx_encoded] in the app's props.conf that apply where data is parsed.
	Returns (list of (key, value) to copy, list of keys not copied).
	"""
	parser = configparser.RawConfigParser(strict=False, interpolation=None)
	parser.optionxform = str
	parser.read(props_path, encoding='utf-8')
	stanza = parser[SOURCE_STANZA]

	copied = [(k, stanza[k]) for k in COPIED_KEYS if k in stanza]
	copied += [(k, v) for k, v in stanza.items() if k.startswith(COPIED_PREFIXES)]
	names = set(k for k, _ in copied)
	return copied, [k for k in stanza if k not in names]


def sourcetype_stanza(target):
	return '%s_sourcetype' % target['transform_prefix']


def eval_stanza(target):
	return '%s_ingest_eval' % target['transform_prefix']


def props_text(target, field_map, settings, search_hash=True, sourcetype_field=SOURCETYPE_FIELD):
	lines = [
		'# %s. Index-time: the app\'s [%s] parsing plus one' % (target['description'], SOURCE_STANZA),
		'# generated transform per template. Search-time: renamed to the add-on\'s sourcetype.',
		'[%s]' % target['sourcetype'],
	]
	lines += ['%s = %s' % kv for kv in settings]
	names = ([sourcetype_stanza(target)] if sourcetype_field else []) + [t.stanza for t in field_map.transforms]
	if field_map.forms:
		names.append(eval_stanza(target))
	lines.append('TRANSFORMS-%s = %s' % (target['transforms_class'], ', '.join(names)))
	lines.append('rename = %s' % target['rename'])
	if search_hash:
		lines += ['',
			'# Search-time, for `tx`: the hash and values of these events once renamed. A renamed event runs only',
			'# the search-time rules of the target, so this sits in the target\'s stanza; text that does not start',
			'# with "~" (every uncompacted %s event) gets nothing from it.' % target['rename'],
			'[%s]' % target['rename'],
			'REPORT-%s = %s' % (HASH_TRANSFORM, HASH_TRANSFORM)]
	return '\n'.join(lines) + '\n'


def transforms_text(field_map, search_hash=True, target=None, sourcetype_field=SOURCETYPE_FIELD):
	stanzas = ['[%s]\nREGEX = %s\nFORMAT = %s\nWRITE_META = true\n' % (t.stanza, t.regex, t.format)
		for t in field_map.transforms]
	if sourcetype_field and target:
		stanzas.insert(0, '# Every event of %s, for tenx-events.\n[%s]\nREGEX = .\nFORMAT = %s::"%s"\nWRITE_META = true\n' % (
			target['sourcetype'], sourcetype_stanza(target), sourcetype_field, target['sourcetype']))
	if field_map.forms and target:
		stanzas.append('# Values FORMAT cannot write (a line break, a double quote, $<digit>) and timestamps as written,\n'
			'# built from the tenx_fmf_* and tenx_fmv_* fields the transforms above write, which it then removes.\n'
			'# Last in the TRANSFORMS- list.\n[%s]\nINGEST_EVAL = %s\n' % (eval_stanza(target), ingest_eval_text(field_map)))
	header = ('# Generated by tenx_field_map.py from the app\'s template records: one index-time transform per '
		'template.\n\n')
	text = header + '\n'.join(stanzas)
	if search_hash:
		text += ('\n# Search-time: tenx-hash-vars-extraction (tenx-for-splunk) with the leading "~" required.\n'
			'[%s]\nREGEX = %s\n' % (HASH_TRANSFORM, HASH_REGEX))
	return text


def fields_text(target):
	lines = ['# Fields that searches match with wildcard values. On compact events the words of these values',
		'# can sit in template text, not in the event\'s index tokens.']
	for name in target['indexed_value_false']:
		lines += ['[%s]' % name, 'INDEXED_VALUE = false']
	return '\n'.join(lines) + '\n'


def app_conf_text(target):
	return ('# Generated by tenx_field_map.py. Install where %s is parsed and searched.\n'
		'[install]\nstate = enabled\n[ui]\nis_visible = false\nlabel = %s\n[launcher]\nversion = 0.0.1\n'
		% (target['sourcetype'], target['app_name']))


def write_app(out_dir, target, field_map, settings, search_hash=True, sourcetype_field=SOURCETYPE_FIELD):
	for sub in ('default', 'metadata'):
		os.makedirs(os.path.join(out_dir, sub), exist_ok=True)

	# transforms.conf before props.conf: an instance that reads the folder between the two writes
	# finds every transform the old props.conf names. Each file is written through a temporary file
	# and a rename, and a file whose content would not change is left as it is.
	files = collections.OrderedDict([
		(os.path.join('default', 'transforms.conf'), transforms_text(field_map, search_hash, target, sourcetype_field)),
		(os.path.join('default', 'props.conf'), props_text(target, field_map, settings, search_hash, sourcetype_field)),
		(os.path.join('default', 'app.conf'), app_conf_text(target)),
		(os.path.join('metadata', 'default.meta'), '[]\nexport = system\n'),
	])
	if target['indexed_value_false']:
		files[os.path.join('default', 'fields.conf')] = fields_text(target)

	sizes = {}
	for rel, text in files.items():
		write_if_changed(os.path.join(out_dir, rel), text)
		sizes[rel] = len(text.encode('utf-8'))
	return sizes


# ---------------------------------------------------------------------------------------------
# verify

def format_timestamp(epoch, fmt):
	"""The compact epoch rendered with the record's Splunk strftime format, in UTC."""
	if fmt == tenx_dml_builder.EPOCH_PASSTHROUGH:
		return epoch
	sec, frac = int(epoch[:10]), epoch[10:]
	t = datetime.datetime.fromtimestamp(sec, datetime.timezone.utc)
	fmt = re.sub(r'%(\d+)Q', lambda m: (frac + '000000000')[:int(m.group(1))], fmt)
	fmt = fmt.replace('%-H', str(t.hour)).replace('%-I', str(t.hour % 12 or 12)).replace('%-M', str(t.minute)) \
		.replace('%-S', str(t.second)).replace('%:::z', '+00').replace('%:z', '+00:00')
	return t.strftime(fmt)


def split_compact(line):
	m = re.match(r'^~?([^,]+)(?:,(.*))?$', line)
	if m is None:
		return None, []
	return m.group(1), ([] if m.group(2) is None else m.group(2).split(','))


def expand(text, values, timestamp_format):
	def value(m):
		k = int(m.group(1))
		if k == 0 and timestamp_format:
			return format_timestamp(values[0], timestamp_format)
		return values[k]
	return MARK_RE.sub(value, text)


def raw_events(path, split):
	with open(path, encoding='utf-8', newline='') as f:
		text = f.read().replace('\r', '')
	return [e for e in re.split(split, text.strip('\n')) if e != '']


_FORMAT_TOKEN = re.compile(r'(\S+?)::"([^"]*)"')


def apply_transform(transform, compact_line, forms=None):
	"""
	Pairs the transform writes for one compact line, as Python reads REGEX and FORMAT, and with the
	field map's forms, the fields its INGEST_EVAL builds from the working fields.
	"""
	m = re.match(transform.regex, compact_line)
	if m is None:
		return None
	groups = m.groups()

	def sub(text):
		return re.sub(r'\$(\d+)', lambda g: groups[int(g.group(1)) - 1] or '', text)

	pairs = [(sub(n), sub(v)) for n, v in _FORMAT_TOKEN.findall(transform.format)
		if n != MARK_FIELD and not n.startswith((EVAL_FORM_PREFIX, EVAL_VALUE_PREFIX))]
	if transform.evals and forms is not None:
		by_number = dict((form, key) for key, form in forms.items())
		for name, form, groups_used in transform.evals:
			key = by_number[form]
			pairs.append((name, eval_value(key, [groups[g - 1] for g in groups_used], key[2])))
	return pairs


def verify(templates, field_map, encoded_path, raw_path, raw_split=None, out=sys.stdout):
	"""
	1. Every compact line, expanded from its template's marked text, equals one raw event (CR
	   removed from the raw text: the engine drops it, engine PR #240).
	2. For every line that passed 1, the pairs its transform writes equal the pairs the reader
	   finds in the raw event (non-empty values, field names the reader accepts).
	Returns a dict of counts.
	"""
	reader = field_map.reader
	remaining = collections.Counter(raw_events(raw_path, raw_split or reader.raw_split))
	raw_total = sum(remaining.values())
	by_key = {t.key: t for t in field_map.transforms}

	lines = ok = 0
	differs, no_template, no_transform, no_match = [], 0, 0, 0
	fields_equal = explained_only = 0
	reserved_dynamic = collections.Counter()
	missing, extra = collections.Counter(), collections.Counter()

	with open(encoded_path, encoding='utf-8') as f:
		compact_lines = f.read().splitlines()

	for line in compact_lines:
		if not line:
			continue
		lines += 1
		written, values = split_compact(line)
		key = (written or '').strip()
		t = templates.get(key)
		if t is None:
			no_template += 1
			continue
		try:
			text, n = marked_text(t)
		except ValueError:
			differs.append((key, 'value count unknown'))
			continue
		if len(values) != n:
			differs.append((key, 'value count %d vs %d' % (len(values), n)))
			continue
		expanded = expand(text, values, t.timestamp_format)
		if remaining[expanded] <= 0:
			differs.append((key, expanded[:120]))
			continue
		remaining[expanded] -= 1
		ok += 1

		transform = by_key.get(key)
		if transform is None:
			no_transform += 1
			continue
		written_pairs = apply_transform(transform, line, field_map.forms)
		if written_pairs is None:
			no_match += 1
			continue
		got = collections.Counter((n_, v) for n_, v in written_pairs if v != '')
		for n_ in set(n_ for n_, _ in got if reserved_name(n_)):
			reserved_dynamic[n_] += 1
		want = collections.Counter((n_, v.strip(field_map.trim_chars) if field_map.trim_values else v)
			for n_, v in reader.pairs(expanded) if v != '' and reader.field_name.match(n_))
		want = collections.Counter({k: c for k, c in want.items() if k[1] != ''})
		if got == want:
			fields_equal += 1
		else:
			lost = set(n_ for n_, _ in (want - got))
			added = set(n_ for n_, _ in (got - want))
			for name in lost:
				missing[name] += 1
			for name in added:
				extra[name] += 1
			known = set(expand(e, values, t.timestamp_format) for e in field_map.explained.get(key, ()))
			if not (lost | added) - known:
				explained_only += 1

	result = collections.OrderedDict([
		('compact_lines', lines), ('raw_events', raw_total), ('expanded_equal_raw', ok),
		('expanded_differ', len(differs)), ('lines_without_template', no_template),
		('lines_without_transform', no_transform), ('transform_regex_did_not_match', no_match),
		('events_all_fields_equal', fields_equal), ('events_differing_only_as_reported', explained_only),
		('reserved_names_from_values_events', dict(reserved_dynamic)),
		('fields_missing_or_different_events', dict(missing)), ('fields_extra_or_different_events', dict(extra)),
	])

	out.write('expansion from marked text equals a raw event (CR removed): %d of %d\n' % (ok, lines))
	for d in differs[:5]:
		out.write('  differs: %r\n' % (d,))
	out.write('lines whose template is not in the records: %d\n' % no_template)
	out.write('lines whose template has no transform: %d; transform REGEX did not match: %d\n' % (no_transform, no_match))
	checked = ok - no_transform - no_match
	out.write('fields written by the transforms equal the reader\'s fields on the raw event: %d of %d\n'
		% (fields_equal, checked))
	out.write('events whose differences are all fields the generation report names (left out, or the timestamp '
		'written as epoch): %d of %d\n' % (explained_only, checked - fields_equal))
	if reserved_dynamic:
		out.write('names built from values that collide with a Splunk default field (events): %s\n' % dict(reserved_dynamic))
	for name in sorted(set(missing) | set(extra)):
		out.write('  %s: raw has it and the transform does not (or not equal) on %d events, '
			'the transform writes it and raw does not (or not equal) on %d\n' % (name, missing[name], extra[name]))
	return result


# ---------------------------------------------------------------------------------------------
# The engine's compact cap file
#
# With `compactReceiverFieldNames: [templateHash]` and `compactReceiverDefault: false`, the Receiver
# sends compact only the events whose template is listed `true` in its cap file
# (compactReceiverLookupFile, pipelines/run/receive/compact in the config repository) and every other
# event whole. An event sent compact before its template's transform is active where the data is
# parsed is indexed without its fields and cannot be repaired, so a hash joins the list only after
# its transform is active there:
#
# * gen --cap-file first rewrites the file without the listed hashes that no longer have a transform,
#   then writes the app, then writes <cap file>.pending, the list as it should be once the app is
#   active. gen never adds a hash to the cap file itself.
# * activate restarts the instance that parses the data when the pending list adds templates (a
#   conf reload does not reach a stream that is already flowing, see below), reads the app's
#   transforms and props back from that instance over REST, and only when every stanza equals the
#   generated one renames the pending list over the cap file. gen --splunkd runs it right after
#   writing the app, for an app written in place on that instance.
#
# Rows: `"<hash>",true`, the hash as the engine writes it (outer spaces kept), always quoted (a hash
# can start with "#", the CSV comment character, or hold a space), sorted. A row whose value does not
# start with `true` (a template kept whole on purpose) is carried over as written and wins over a
# transform. Every write goes to a temporary file in the same folder that is then renamed over the
# target, so the engine, which reloads the file when it changes, never reads half a list. A file whose
# content would not change is not written, so a GitOps checkout holding it changes only when the list
# changes.

CAP_HEADER = 'pattern_hash,value\n'
CAP_PENDING_SUFFIX = '.pending'
# Measured on Splunk Enterprise 10.4.3, one instance, with one compact event of the template sent
# after each step: a transform stanza written to the app takes effect for a new input stream after
# POST conf-transforms/_reload and conf-props/_reload, but a stream (host, source and sourcetype) that
# already carried events before the reload keeps the configuration it started with: 0 of 9 events of
# such a stream got the new transform over 3 minutes, also after reloading the HEC input, and a
# forwarder's stream carries events all day. After a restart every stream uses the new
# configuration. So activate restarts the instance when the pending list adds templates.
RESTART_ENDPOINT = '/services/server/control/restart'


def cap_hashes(field_map, templates):
	"""The templateHash value of each template the field map has a transform for."""
	return set(templates[t.key].written_hash for t in field_map.transforms)


def read_cap(path):
	"""(hashes whose value starts with true, the other rows as (hash, value)) of a cap file."""
	listed, kept = set(), []
	if not os.path.exists(path):
		return listed, kept
	with open(path, encoding='utf-8', newline='') as f:
		rows = list(csv.reader(f))
	for row in rows[1:]:
		if not row or not row[0]:
			continue
		value = row[1] if len(row) > 1 else ''
		if value.startswith('true'):
			listed.add(row[0])
		else:
			kept.append((row[0], value))
	return listed, kept


def cap_text(hashes, kept=()):
	kept_hashes = set(h for h, _ in kept)
	rows = sorted([(h, 'true') for h in hashes if h not in kept_hashes] + list(kept))
	return CAP_HEADER + ''.join('"%s",%s\n' % (h.replace('"', '""'), v) for h, v in rows)


def write_if_changed(path, text):
	"""
	Writes text to path through a temporary file in the same folder and a rename. Returns False,
	writing nothing, when the file already holds exactly this text.
	"""
	try:
		with open(path, encoding='utf-8', newline='') as f:
			if f.read() == text:
				return False
	except (IOError, OSError):
		pass
	folder = os.path.dirname(os.path.abspath(path))
	os.makedirs(folder, exist_ok=True)
	# mkstemp creates the file readable by its owner only; give it the mode the file has, or the mode
	# open() would give a new file.
	try:
		mode = os.stat(path).st_mode & 0o777
	except (IOError, OSError):
		umask = os.umask(0)
		os.umask(umask)
		mode = 0o666 & ~umask
	fd, tmp = tempfile.mkstemp(prefix='.%s.' % os.path.basename(path), suffix='.tmp', dir=folder)
	try:
		with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
			f.write(text)
			f.flush()
			os.fsync(f.fileno())
		os.chmod(tmp, mode)
		os.replace(tmp, path)
	except BaseException:
		if os.path.exists(tmp):
			os.remove(tmp)
		raise
	return True


def cap_before_app(path, hashes):
	"""
	Before the app is written: the cap file without the listed hashes that have no transform any
	more (created with its header alone when absent). Returns a summary for the report.
	"""
	listed, kept = read_cap(path)
	kept_hashes = set(h for h, _ in kept)
	now = (listed & hashes) - kept_hashes
	written = write_if_changed(path, cap_text(now, kept))
	return collections.OrderedDict([('cap_file', path), ('listed_before', len(listed)),
		('removed', len(listed - hashes)), ('listed_now', len(now)), ('cap_file_written', written),
		('waiting_for_activation', len(hashes - kept_hashes - now)), ('rows_kept_as_written', len(kept))])


def cap_after_app(path, hashes):
	"""After the app is written: the pending list, every template with a transform."""
	_, kept = read_cap(path)
	return write_if_changed(path + CAP_PENDING_SUFFIX, cap_text(hashes, kept))


class Splunkd(object):
	"""The management port of the instance that parses the data (REST, JSON)."""

	def __init__(self, url, auth=None, token=None, tls_verify=True):
		self.url = url.rstrip('/')
		self.headers = {}
		if token:
			self.headers['Authorization'] = 'Splunk %s' % token
		elif auth:
			self.headers['Authorization'] = 'Basic ' + base64.b64encode(auth.encode('utf-8')).decode('ascii')
		self.ctx = None
		if self.url.startswith('https') and not tls_verify:
			self.ctx = ssl.create_default_context()
			self.ctx.check_hostname = False
			self.ctx.verify_mode = ssl.CERT_NONE

	def call(self, method, path, params=None):
		params = dict(params or {}, output_mode='json')
		url, data = self.url + path, None
		if method == 'GET':
			url += '?' + urllib.parse.urlencode(params)
		else:
			data = urllib.parse.urlencode(params).encode('ascii')
		req = urllib.request.Request(url, data=data, method=method, headers=self.headers)
		with urllib.request.urlopen(req, context=self.ctx, timeout=120) as res:
			body = res.read()
		return json.loads(body) if body.strip() else {}

	def stanzas(self, app, conf):
		"""The stanzas of <conf>.conf that app holds, as the instance reads them now: name -> settings."""
		res = self.call('GET', '/servicesNS/nobody/%s/configs/conf-%s' % (urllib.parse.quote(app), conf),
			{'count': 0})
		return dict((e['name'], e.get('content', {})) for e in res.get('entry', [])
			if e.get('acl', {}).get('app') == app)


def read_conf(path):
	parser = configparser.RawConfigParser(strict=False, interpolation=None, delimiters=('=',),
		comment_prefixes=('#',), empty_lines_in_values=False)
	parser.optionxform = str
	parser.read(path, encoding='utf-8')
	return collections.OrderedDict((name, dict(parser[name])) for name in parser.sections())


_BOOLEAN = {'true': '1', 't': '1', 'yes': '1', '1': '1', 'false': '0', 'f': '0', 'no': '0', '0': '0'}


def _same_setting(key, written, held):
	# REST returns a boolean setting as 1 or 0 (WRITE_META = true comes back as "1").
	a, b = str(written).strip(), str(held).strip()
	return a == b or (a.lower() in _BOOLEAN and _BOOLEAN[a.lower()] == _BOOLEAN.get(b.lower()))


def not_installed(splunkd, app_dir, app_name):
	"""The stanzas of the app's transforms.conf and props.conf the instance does not hold as written."""
	differ = []
	for conf in ('transforms', 'props'):
		have = splunkd.stanzas(app_name, conf)
		for name, settings in read_conf(os.path.join(app_dir, 'default', conf + '.conf')).items():
			got = have.get(name)
			if got is None:
				differ.append('%s.conf [%s] missing' % (conf, name))
			elif not all(_same_setting(k, v, got.get(k, '')) for k, v in settings.items()):
				differ.append('%s.conf [%s] differs' % (conf, name))
	return differ


def wait_for(splunkd, seconds=600):
	"""After a restart: True once the management port answers again."""
	deadline = time.time() + seconds
	time.sleep(10)
	while time.time() < deadline:
		try:
			splunkd.call('GET', '/services/server/info')
			return True
		except Exception:
			time.sleep(5)
	return False


def activate(app_dir, cap_file, splunkd, app_name=None, out=sys.stdout):
	"""
	When the pending list adds templates, restarts the instance; then checks that it holds the app as
	generated, and only then renames the pending list over the cap file. Returns 0, or 1 with the cap
	file left as it was.
	"""
	pending = cap_file + CAP_PENDING_SUFFIX
	if not os.path.exists(pending):
		out.write('activate: nothing pending (%s)\n' % pending)
		return 0
	app_name = app_name or os.path.basename(os.path.abspath(app_dir))
	before, _ = read_cap(cap_file)
	after, _ = read_cap(pending)
	restarted = bool(after - before)
	if restarted:
		splunkd.call('POST', RESTART_ENDPOINT)
		if not wait_for(splunkd):
			out.write('activate: the instance did not come back after the restart; cap file left as it was\n')
			return 1
	differ = not_installed(splunkd, app_dir, app_name)
	if differ:
		out.write('activate: the instance does not hold app %s as generated (%d stanzas, first %s); '
			'cap file left as it was\n' % (app_name, len(differ), differ[0]))
		return 1
	os.replace(pending, cap_file)
	out.write('activate: app %s %schecked; %s lists %d templates (%d added, %d removed)\n'
		% (app_name, 'restarted and ' if restarted else '', cap_file, len(after), len(after - before),
			len(before - after)))
	return 0


# ---------------------------------------------------------------------------------------------
# Command line

def _build(args):
	overrides = {
		'reader': args.reader, 'sourcetype': args.sourcetype, 'rename': args.rename,
		'transform_prefix': args.transform_prefix, 'transforms_class': args.transforms_class,
		'app_name': args.app_name,
		'indexed_value_false': None if args.indexed_value_false is None
			else [f for f in args.indexed_value_false.split(',') if f],
	}
	target = load_target(args.target, overrides)
	templates, refused = merge_templates([load_templates(p) for p in args.records])
	keep = None
	if args.only_hashes_in:
		keep = set()
		for p in args.only_hashes_in:
			keep |= hash_keys_in(p)
	field_map = FieldMap(templates, READERS[target['reader']](), target['transform_prefix'],
		stanza_names=args.stanza_names, hash_match=args.hash_match, timestamp_values=args.timestamp_values,
		keep=keep, refused=refused, mixed_names=args.mixed_names,
		reserved_names=args.reserved_names, reserved_prefix=args.reserved_prefix,
		trim_values={'auto': None, 'on': True, 'off': False}[args.trim_values],
		mark=None if args.mark == 'none' else args.mark, eval_values=args.eval_values == 'on')
	return target, templates, field_map


def build_parser():
	ap = argparse.ArgumentParser(description='Index-time field map for compact events (see the module docstring).')
	sub = ap.add_subparsers(dest='mode')
	sub.required = True

	for mode in ('gen', 'verify'):
		p = sub.add_parser(mode)
		p.add_argument('--records', action='append', required=True,
			help='KV store export (JSON array) or templates.json; repeat to merge')
		p.add_argument('--only-hashes-in', action='append',
			help='keep only the templates named in this templates.json or KV export')
		p.add_argument('--target', help='built-in target (%s) or a JSON file' % ', '.join(sorted(TARGETS)))
		p.add_argument('--reader', choices=sorted(READERS))
		p.add_argument('--sourcetype', help='the compact sourcetype the generated props.conf defines')
		p.add_argument('--rename', help='the original sourcetype, whose search-time rules should run')
		p.add_argument('--transform-prefix')
		p.add_argument('--transforms-class')
		p.add_argument('--app-name')
		p.add_argument('--indexed-value-false', help='comma-separated field names for fields.conf')
		p.add_argument('--stanza-names', choices=('indexed', 'hash', 'stable'), default='indexed',
			help='indexed: <prefix>_<position>_<hash> (default); hash: <prefix>_<hash>, refused on a clash; '
				'stable: <prefix>_<hash>_<sha1 prefix>, unchanged when templates are added')
		p.add_argument('--hash-match', choices=('tolerant', 'exact'), default='tolerant')
		p.add_argument('--timestamp-values', choices=('text', 'epoch', 'skip'), default='text',
			help='a field holding the timestamp: text: as the event wrote it, by INGEST_EVAL (default); '
				'epoch: the epoch digits of the compact line, by FORMAT; skip: left out')
		p.add_argument('--eval-values', choices=('on', 'off'), default='on',
			help='on: values FORMAT cannot write (a line break, a double quote, $<digit>, a group followed by a digit) '
				'are written by one INGEST_EVAL transform (default); off: left out and reported')
		p.add_argument('--trim-values', choices=('auto', 'on', 'off'), default='auto',
			help='drop spaces and tabs at the ends of a value; auto: as the reader\'s Splunk extraction does '
				'(xml-windows on, json and kv off)')
		p.add_argument('--reserved-names', choices=('skip', 'prefix'), default='skip',
			help='a field named like a Splunk default field (eventtype, host, source, ...; any case): '
				'skip it (default) or write it under --reserved-prefix; both are reported')
		p.add_argument('--reserved-prefix', default='extracted_',
			help='prefix for --reserved-names prefix (default extracted_, the name Splunk 10.4.3 itself gave)')
		p.add_argument('--mark', default=MARK_FIELD,
			help='indexed field every FORMAT writes as <mark>::"1" (default %s; none: no mark). `tx` keeps the '
				'indexed fields of an event that has it from being extracted a second time' % MARK_FIELD)
		p.add_argument('--mixed-names', action='store_true',
			help='write names that join text and values (NOT CHECKED on Splunk; off by default)')
		if mode == 'gen':
			p.add_argument('--out', required=True, help='the app folder to write')
			p.add_argument('--report', help='report path (default: <out>_report.json)')
			p.add_argument('--app-props', default=default_app_props(), help='the app props.conf holding [tenx_encoded]')
			p.add_argument('--search-hash', choices=('on', 'off'), default='on',
				help='on: write the search-time hash and values extraction under the rename target, which `tx` needs')
			p.add_argument('--sourcetype-field', default=SOURCETYPE_FIELD,
				help='indexed field every event of the compact sourcetype gets as <field>::"<sourcetype>", which '
					'tenx-events names so that `tx` finds these events (default %s; none: not written)' % SOURCETYPE_FIELD)
			p.add_argument('--cap-file', help='the Receiver\'s compact cap file (compactReceiverLookupFile, keyed on '
				'templateHash): drop listed templates that lost their transform, and write <cap file>.pending, '
				'which activate makes the cap file once the app is active where the data is parsed')
			_splunkd_args(p, required=False)
		else:
			p.add_argument('--encoded', required=True)
			p.add_argument('--raw', required=True)
			p.add_argument('--raw-split', help='regex between raw events (default: the reader\'s)')

	p = sub.add_parser('activate', help='restart the parsing instance when templates are added, check it holds the app, '
		'then list them')
	p.add_argument('--app', required=True, help='the app folder gen wrote, as installed on the instance')
	p.add_argument('--app-name', help='the app\'s name on the instance (default: the folder name)')
	p.add_argument('--cap-file', required=True)
	_splunkd_args(p, required=True)
	return ap


def _splunkd_args(p, required):
	p.add_argument('--splunkd', required=required,
		help='management URL of the instance that parses the data, e.g. https://127.0.0.1:8089; with gen, '
			'activate runs right after the app is written (the app folder is on that instance), and restarts it '
			'when templates are added')
	p.add_argument('--splunkd-auth-env', default='TENX_SPLUNKD_AUTH',
		help='environment variable holding user:password (default TENX_SPLUNKD_AUTH)')
	p.add_argument('--splunkd-token-env', default='TENX_SPLUNKD_TOKEN',
		help='environment variable holding a session key, used instead of user:password (default TENX_SPLUNKD_TOKEN)')
	p.add_argument('--tls-verify', choices=('on', 'off'), default='on',
		help='off: accept the instance\'s certificate without checking it (a self-signed management port)')


def _splunkd(args):
	return Splunkd(args.splunkd, auth=os.environ.get(args.splunkd_auth_env),
		token=os.environ.get(args.splunkd_token_env), tls_verify=args.tls_verify == 'on')


def main(argv=None):
	args = build_parser().parse_args(argv)
	if args.mode == 'activate':
		return activate(args.app, args.cap_file, _splunkd(args), args.app_name)

	target, templates, field_map = _build(args)

	if args.mode == 'verify':
		result = verify(templates, field_map, args.encoded, args.raw, args.raw_split)
		return 0 if result['expanded_differ'] == 0 and result['transform_regex_did_not_match'] == 0 else 1

	settings, not_copied = parsing_settings(args.app_props)
	sourcetype_field = None if args.sourcetype_field == 'none' else args.sourcetype_field
	cap = None
	if args.cap_file:
		hashes = cap_hashes(field_map, templates)
		cap = cap_before_app(args.cap_file, hashes)
	sizes = write_app(args.out, target, field_map, settings, args.search_hash == 'on', sourcetype_field)
	if args.cap_file:
		cap['pending_file_written'] = cap_after_app(args.cap_file, hashes)
	report = field_map.report()
	if cap is not None:
		report['compact_cap'] = cap
	report['settings_copied_from_tenx_encoded'] = [k for k, _ in settings]
	report['settings_not_copied'] = not_copied
	report['file_bytes'] = sizes
	report['target'] = target
	report['sourcetype_field'] = sourcetype_field
	report_path = args.report or args.out.rstrip(os.sep) + '_report.json'
	with open(report_path, 'w', encoding='utf-8') as f:
		json.dump(report, f, indent=1)
	summary = collections.OrderedDict((k, report[k]) for k in ('templates', 'fields_per_template_min_max', 'skipped',
		'literal_field_names', 'templates_without_transform', 'timestamp_written_as_epoch', 'timestamp_written_as_text',
		'written_by_ingest_eval', 'reserved_field_names'))
	sys.stdout.write(json.dumps(summary, indent=1) + '\nreport: %s\n' % report_path)
	if sourcetype_field:
		sys.stdout.write('for tx: add %s::%s to the tenx-events macro, for example\n'
			'    index=* (sourcetype::tenx_encoded OR %s::%s)\n' % (sourcetype_field, target['sourcetype'], sourcetype_field,
			target['sourcetype']))
	if cap is not None:
		sys.stdout.write('compact cap: %s\n' % json.dumps(cap))
		if args.splunkd:
			return activate(args.out, args.cap_file, _splunkd(args))
	return 0


if __name__ == '__main__':
	sys.exit(main())
