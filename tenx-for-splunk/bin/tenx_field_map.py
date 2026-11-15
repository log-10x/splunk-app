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
    tenx_field_map.py gen --rules lookup ... --cap-file <compact cap file> [--splunkd <management URL> --probe-index <index>]
    tenx_field_map.py activate --app <app dir> --cap-file <compact cap file> --splunkd <management URL> --probe-index <index>
    tenx_field_map.py check --app <app dir> --cap-file <compact cap file> --splunkd <management URL> --probe-index <index>

`--rules lookup` writes one static index-time rule per compact sourcetype and one row per template in
lookups/<prefix>_fields.csv.gz, so a template added later changes only that file, which Splunk rereads
on its own, with no reload and no restart, for streams that are already sending (see "Lookup rules"
below). `--cap-file` keeps the Receiver's compact cap file to the templates whose row Splunk was seen to
apply, so an event goes compact only once its fields can be written (see "The engine's compact cap
file" below); it needs `--rules lookup`.

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

# Why a template's row has no event time recipe (see "Event time").
WHY_TIME_NO_PREFIX = "TIME_PREFIX not found in the template text"
WHY_TIME_PREFIX_VALUE = "TIME_PREFIX match includes a value"
WHY_TIME_EMPTY = "no text after the TIME_PREFIX match"
WHY_TIME_FORMAT = "timestamp directive not rendered at index time"
# Splunk's own defaults for the settings the event time rule reads (props.conf.spec).
TIME_DEFAULT_LOOKAHEAD = 128
TIME_DEFAULT_DAYS_AGO = 2000
TIME_DEFAULT_DAYS_HENCE = 2

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
# --reserved-names restore: one search-time transform per reserved name, under the rename target's stanza,
# that reads the indexed <reserved_prefix><name> and writes <name>. A search-time field may carry such a
# name: KV_MODE = json gives eventType on uncompacted CloudTrail events. Extractions run before field
# aliases, calculated fields and lookups (props.conf.spec), so the add-on's rules that read the name
# (FIELDALIAS-... = eventType AS app, EVAL-user's eventType="AwsConsoleSignIn") find it.
RESTORE_TRANSFORM = 'tenx_fm_restore_'
RESTORE_REGEX = '^([\\s\\S]*)$'

# re.escape's set of escaped characters on Python 3.7 and later, written out so the generated
# REGEX does not depend on the interpreter, plus "/" (escaped by the first generator as well).
_REGEX_SPECIAL = frozenset('()[]{}?*+-|^$\\.&~# \t\n\r\v\f/')

# --rules lookup (see "Lookup rules" below).
RULES_TRANSFORMS = 'transforms'
RULES_LOOKUP = 'lookup'
# Values a template may have for the static rule: its regex is cut from LOOKUP_VALUE_GROUP repeated
# this many times, and with the 15 groups that follow the values no reference passes 999, so a value
# count stays three digits (Splunk Enterprise 10.4.3: replace() with 437, 915 and 1,215 groups and
# references up to \1215 gave every value). A CloudTrail UpdateSAMLProvider event has 422 values.
LOOKUP_MAX_VALUES = 984
# One value: the rule's regex (PCRE) and this module's reading of it (Python re, which has no POSIX
# classes). [:cntrl:] keeps a line break out of a value, so text of two lines gets no fields, and needs
# no backslash: the rule cuts its regex from a string constant by length, which an escape would change.
LOOKUP_VALUE_GROUP = ',([^,[:cntrl:]]*)'
LOOKUP_VALUE_GROUP_PY = ',([^,\\x00-\\x1f\\x7f]*)'
# Appended to the compact line, after "|<timestamp text>|", so the replacement can write these
# characters by reference instead of as text: replace() reads a backslash followed by digits as a
# reference (greedily), so a literal backslash, and a digit right after a reference, would be read wrong.
LOOKUP_TAIL = '0123456789\\\t\n\r'
LOOKUP_COLUMNS = ('hash', 'n', 'e', 't', 'f')
# With an event time rule (see "Event time"), one more column: the recipe of the text after TIME_PREFIX.
LOOKUP_TIME_COLUMN = 'w'
# The file must stay under limits.conf [lookup] ingest_max_memtable_bytes (default 10485760): above it
# lookup() fails at index time and Splunk drops the event (see "Lookup rules").
LOOKUP_DEFAULT_MAX_BYTES = 10000000
REFUSED_TOO_MANY = "more values than the lookup rule takes (%d)"
# The indexed field a compact event gets when the lookup rule writes none of its fields, and its values:
# no row for the hash; a row the rule cannot use; a line that does not have the row's values; and the
# floor copy of the file answered, so the rows were not read (see "Lookup failures").
UNMAPPED_FIELD = 'tenx_unmapped'
WHY_NO_ROW = 'no_row'
WHY_BAD_ROW = 'bad_row'
WHY_NO_MATCH = 'no_match'
WHY_NO_TABLE = 'no_table'
# The one row of the floor copy, a hash no template has.
FLOOR_HASH = 'tenx-fm-floor'

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
	# A key may hold "-" and single ":" after its first character, as KV_MODE = json names them
	# (requestParameters.x-amz-request-payer, requestParameters.encryptionContext.aws:lambda:FunctionArn on
	# raw CloudTrail events); Splunk Enterprise 10.4.3 keeps an index-time field of such a name under that
	# name and finds it when a search names it. "::" and a trailing ":" stay out: they would read as the
	# separator of index-time field text.
	field_name = re.compile(r'[A-Za-z_](?:[A-Za-z0-9_-]|:(?=[A-Za-z0-9_-]))*(?:\{\})*'
		r'(?:\.[A-Za-z_](?:[A-Za-z0-9_-]|:(?=[A-Za-z0-9_-]))*(?:\{\})*)*\Z')
	# KV_MODE = json gives a field for an empty string ("acl": "" is acl="" on raw CloudTrail events).
	keeps_empty = True

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


class DelimsReader(object):
	r"""
	A transforms.conf DELIMS extraction with pair delimiters space and comma and the key-value
	delimiter "=", as the FortiGate add-on's [field_extract] (DELIMS = "\ ,", "="), read from what Splunk
	Enterprise 10.4.3 extracted on 239 raw FortiGate events with KV_MODE = none:
	* a pair runs from a delimiter (or the start) to the next delimiter outside double quotes; its key is
	  the text before the first "=", and a value in double quotes loses them;
	* the key is cleaned as Splunk cleans extracted names: text before the first letter goes (a syslog
	  priority "<190>date=" gives date: 62 of 62 such events), and every other character that is not a
	  letter, digit or "_" becomes "_". A compact value in that leading text is read as the digits of a
	  priority, so a value that holds letters there would give Splunk another name (not checked);
	* the first value of a key is kept: tz="UTC-5:00" ... tz=-0500 gave tz "UTC-5:00";
	* inside double quotes a backslash escapes the next character: \\ gives one backslash and \" a double
	  quote that does not end the value (msg="...XSS\\" gave ...XSS\, filename="sample\\test.xls" gave
	  sample\test.xls, forwardedfor="abcd0e.xff\"></script>..." gave abcd0e.xff"></script>...); before any
	  other character the backslash stays (rawdata="...charset\=UTF-8" gave ...charset\=UTF-8). A backslash
	  before a compact value stays as well: a compact value holds no double quote and no backslash;
	* an empty quoted value is a field with an empty value (user="").
	Not checked: msg="... a=b \"quoted\" c=" gave "... a=b "quoted" c" (the last "=" not kept; this reader
	keeps it), how Splunk names a key that is empty once cleaned, and an empty value without quotes.
	"""
	name = 'delims'
	raw_split = r'\n'
	trims_values = False
	keeps_empty = True
	field_name = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')

	PAIR = re.compile(r'(?:^|(?<=[ ,]))([^ ,="]+)=(?:"((?:[^"\\]|\\.)*)"(?=[ ,]|\Z)|([^ ,]*))', re.S)
	ESCAPE = re.compile(r'\\([\\"])')

	@staticmethod
	def clean(key):
		"""
		The key as Splunk names it: other characters as "_", and no text before the first letter. A
		compact value before the first letter of text goes with it (read as a priority's digits); a key
		with no letter in its text, a compact value alone for example, is kept as it is.
		"""
		parts = [p for p in MARK_SPLIT.split(key) if p]
		first = next((i for i, p in enumerate(parts) if not MARK_RE.fullmatch(p) and re.search('[A-Za-z]', p)), None)
		out = []
		for i, part in enumerate(parts):
			if MARK_RE.fullmatch(part):
				if first is None or i > first:
					out.append(part)
				continue
			if first is not None and i < first:
				continue
			if i == first:
				part = re.sub(r'^[^A-Za-z]+', '', part)
			out.append(re.sub(r'[^A-Za-z0-9_]', '_', part))
		return ''.join(out)

	def pairs(self, text):
		out, seen = [], set()
		for m in self.PAIR.finditer(text):
			key = self.clean(m.group(1))
			if not key or key in seen:
				continue
			seen.add(key)
			if m.group(2) is None and m.group(3) == '':
				# An empty value without quotes: left out, as before (not checked against Splunk).
				continue
			out.append((key, self.ESCAPE.sub(r'\1', m.group(2)) if m.group(2) is not None else m.group(3)))
		return out


READERS = {r.name: r for r in (XmlWindowsReader, JsonReader, KeyValueReader, DelimsReader)}


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
# recipe, ts_format, epoch: --rules lookup only (the lookup row; see "Lookup rules"). time_recipe: the
# text after TIME_PREFIX, with an event time rule only (see "Event time").
Transform = collections.namedtuple('Transform',
	'key stanza regex format fields value_count evals recipe ts_format epoch time_recipe',
	defaults=((), '', '', False, ''))


# ---------------------------------------------------------------------------------------------
# Event time
#
# Splunk fixes _time when it parses an event, from the text after the first match of the sourcetype's
# TIME_PREFIX, read with TIME_FORMAT over at most MAX_TIMESTAMP_LOOKAHEAD characters (props.conf.spec,
# TIME_PREFIX, MAX_TIMESTAMP_LOOKAHEAD, TIME_FORMAT). A compact event's text has none of that text, so
# without a rule its _time is what the app's tenx-event-time gives it: the template's first timestamp
# slot when that is an epoch in Splunk's window, otherwise the time the event arrived. In a CloudTrail
# event the engine's first timestamp is userIdentity.sessionContext.attributes.creationDate when that
# field is present (1,489 of 3,617 one-slot templates of a 25,566-event sample), not eventTime, which
# the add-on's TIME_PREFIX names.
#
# With an event time rule (--time-props, --time-prefix, --time-format; --rules lookup only), gen applies
# TIME_PREFIX to each template's marked text, and the template's row carries, in column w, the recipe of
# the text that follows the first match: template text and references to the compact values, up to
# MAX_TIMESTAMP_LOOKAHEAD characters of template text, so the expansion covers at least that many. The
# static rule rebuilds that text with the same replace() as the fields, keeps its first
# MAX_TIMESTAMP_LOOKAHEAD characters, reads it with each format in turn (strptime, the first that reads
# it wins) and sets _time when the result lies within MAX_DAYS_AGO and MAX_DAYS_HENCE of the time the
# event is indexed. Every other event keeps the _time it had. The rule runs after tenx-event-time: gen
# puts the copied TRANSFORMS- of [tenx_encoded] first in its own list, which Splunk applies in list
# order (props.conf.spec, TRANSFORMS-<class>).
#
# Measured on Splunk Enterprise 10.4.3 with the AWS add-on 8.3.1 (aws:cloudtrail: TIME_PREFIX
# \"eventTime\"\s*\:\s*\", TIME_FORMAT %Y-%m-%dT%H:%M:%S%Z, MAX_TIMESTAMP_LOOKAHEAD 28), on 25,566 raw
# events: eval strptime() with the add-on's TIME_FORMAT on the 28 characters after the prefix equals
# _time on 17,466 and returns null on the other 8,100, whose eventTime carries six fraction digits that
# the timestamp processor reads; strptime() with "%Y-%m-%dT%H:%M:%S.%6N%Z" tried second makes it 25,566
# of 25,566. Hence --time-format, which adds formats after the add-on's. A _time set this way, through a
# pd: key, metered the event's text and nothing more (2,000 events of 58 bytes, 116,000 bytes in
# license_usage.log with no rule and with each of three ways of setting a fractional _time: inline, from a
# pd: text key, from a pd: time key).
#
# Not reproduced: the timestamp processor's own recognition when a sourcetype has no TIME_FORMAT
# (datetime.xml), its use of the previous event's time outside the day window (MAX_DAYS_AGO), and TZ
# (gen refuses a stanza that sets it). A text that no format reads leaves _time as it was.

TimeRule = collections.namedtuple('TimeRule', 'prefix formats lookahead max_days_ago max_days_hence')


def _python_regex(pcre):
	"""A PCRE pattern as Python's re reads it: named groups (?<name>...) become (?P<name>...)."""
	return re.sub(r'\(\?<(?![=!])', '(?P<', pcre)


def time_prefix_regex(rule):
	return re.compile(_python_regex(rule.prefix))


def read_time_settings(props_path, stanza):
	"""The timestamp settings of a sourcetype in an add-on's props.conf: [default], then its own stanza."""
	parser = configparser.RawConfigParser(strict=False, interpolation=None)
	parser.optionxform = str
	parser.read(props_path, encoding='utf-8')
	out = {}
	for section in ('default', stanza):
		if parser.has_section(section):
			for k, v in parser.items(section):
				if k in ('TIME_PREFIX', 'TIME_FORMAT', 'MAX_TIMESTAMP_LOOKAHEAD', 'MAX_DAYS_AGO', 'MAX_DAYS_HENCE', 'TZ',
						'DATETIME_CONFIG'):
					out[k] = v.strip()
	return out


def make_time_rule(settings, prefix=None, formats=(), lookahead=None):
	"""
	The event time rule from a sourcetype's settings (read_time_settings) and the command line, or None
	when there is nothing to read the time with. Raises ValueError for settings the rule does not follow.
	"""
	if settings.get('DATETIME_CONFIG', '').upper() in ('CURRENT', 'NONE'):
		raise ValueError('DATETIME_CONFIG = %s: Splunk does not read a time from the text' % settings['DATETIME_CONFIG'])
	if settings.get('TZ'):
		raise ValueError('TZ = %s is set: the rule reads the text in the zone of the indexer (NOT CHECKED), so it is '
			'not written' % settings['TZ'])
	all_formats = ([settings['TIME_FORMAT']] if settings.get('TIME_FORMAT') else []) + list(formats)
	if not all_formats:
		raise ValueError('no TIME_FORMAT: Splunk recognises the timestamp itself (datetime.xml), which the rule does '
			'not reproduce; give --time-format')
	for fmt in all_formats:
		if '"' in fmt or '\\' in fmt:
			raise ValueError('a time format with a double quote or a backslash is not written: %r' % fmt)
	if prefix is None:
		prefix = settings.get('TIME_PREFIX') or '^'
	if lookahead is None:
		lookahead = int(settings.get('MAX_TIMESTAMP_LOOKAHEAD') or TIME_DEFAULT_LOOKAHEAD)
	rule = TimeRule(prefix, tuple(all_formats), lookahead, int(settings.get('MAX_DAYS_AGO') or TIME_DEFAULT_DAYS_AGO),
		int(settings.get('MAX_DAYS_HENCE') or TIME_DEFAULT_DAYS_HENCE))
	time_prefix_regex(rule)
	return rule


def time_text(rule, text, prefix_re=None):
	"""The text Splunk reads the time from: what follows the first TIME_PREFIX match, cut to the lookahead."""
	m = (prefix_re or time_prefix_regex(rule)).search(text)
	if m is None:
		return None
	rest = text[m.end():]
	return rest[:rule.lookahead] if rule.lookahead > 0 else rest


# ---------------------------------------------------------------------------------------------
# Lookup rules
#
# With --rules lookup the app holds one static index-time rule per compact sourcetype, and the
# per-template data sits in a lookup file the rule reads with lookup(). Adding a template changes
# only that file: Splunk rereads a lookup used by lookup() at index time every
# ingest_lookup_refresh_period_secs (limits.conf [lookup], default 60), with no reload and no
# restart, and a stream that is already sending uses the new rows (Splunk Enterprise 10.4.3: a row
# added by a rename reached a running HEC stream 38 s later). Per-template transforms reach such a
# stream only after a restart.
#
# The rule (lookup_eval_text): for an event whose text starts with "~", look up the trimmed hash,
# getting n (values), t (timestamp format, or empty) and f (the recipe); render the timestamp as text
# when t is set; then one replace() on
#     <compact line>|<timestamp text>|0123456789\<tab><line feed><carriage return>
# with the regex "^~[^,[:cntrl:]]*" + ",([^,[:cntrl:]]*)" * n + "[|]([^|[:cntrl:]]*)[|]" + "([^|])" * 14 + "$" and the
# recipe as the replacement. The result is index-time field text, name::"value" pairs as WRITE_META
# writes them, which the rule appends to _meta. A compact line that does not have n values leaves the
# text unchanged and gets nothing. replace() reads "\<digits>" as a reference to that group when it
# exists and leaves it as text when it does not; any other backslash is text (10.4.3, measured at
# search and index time alike). So the recipe refers to group k for value k-1, n+1 for the timestamp
# text, n+2..n+11 for a digit right after a reference, n+12 for a backslash and n+13..n+15 for tab,
# line feed and carriage return; it holds no other backslash. In the field text a value's backslash is
# written "\\" and its double quote "\"" (how Splunk writes them itself), and a line break inside a
# value reads back as a space, as for an INGEST_EVAL field.
#
# If the lookup file is missing, or larger than limits.conf ingest_max_memtable_bytes (default
# 10485760), lookup() fails at index time and Splunk drops the event (10.4.3: 0 of 6 and 0 of 22 events
# indexed; see "Lookup failures"). The rule calls lookup() for compact events only, so whole events are
# kept, and the file is gzipped (the limit counts the file: 20,001 rows of 27.8 MB as a 0.63 MB .csv.gz
# worked).

# ---------------------------------------------------------------------------------------------
# Lookup failures
#
# lookup() at index time throws when the table it names cannot be read, and Splunk then drops the event
# ("Runtime exception in pipeline=typing processor=regexreplacement", "Uncaught exception in pipeline
# execution (regexreplacement) - getting next event"). Nothing in the rule can catch it: coalesce() does
# not, a rule earlier in the list does not keep the event, RULESET- drops it the same way, and a table
# name that is not a literal does not compile ("Error compiling INGEST_EVAL expression ... Invalid
# function argument"; the rule is then skipped). Splunk Enterprise 10.4.3, two compact and one whole
# event per case, the rule as generated before the floor and the marker, and as generated now:
#
#   dropped: no file; no definition (the name is then read as a file name); a file only in default/; a
#     file splunkd cannot read (mode 000); a file named .csv.gz that is not gzip; a header without the
#     column `hash`. The same with a floor copy in another app, except the first two.
#   kept, no fields (the rule as generated now marks them): a header alone or an empty file (no_row); a
#     row with two columns, a value count that is not a number or over 240, an empty recipe, two rows for
#     one hash (bad_row; max_matches = 1 does not change it); a line with fewer values (no_match);
#     the hash not in the file (no_row).
#   kept, with fields: half of the gzip file (the rows before the cut are read); a file whose metadata
#     gives no one read access.
#
# A file deleted while Splunk holds its table: events keep their fields until the next refresh
# (ingest_lookup_refresh_period_secs), then one of three, seen on four deletions: every event fails and is
# dropped (a table read once: 27 of 27 events over 82 s, until the file was back); the table reads as
# empty (a table whose file had been put back before: 37 of 37 kept, no_row; and a probe event, no_row);
# or the table keeps the rows it read (a table rewritten six times by renames: probe events kept their
# fields for the 150 s the file was missing). Once the file is back, the table reads as empty until the
# next refresh (13 events, 39 s), then rows again. A file overwritten in place with half its gzip bytes kept
# giving rows. ingest_max_memtable_bytes (limits.conf [lookup]) is one value for the whole instance; no
# lookup definition setting changes it for one table.
#
# So the generated files guard what they can, and the cap file covers the rest:
# * the rule builds its regex only from a row it can use, and gives a compact event it writes no
#   fields for the indexed field tenx_unmapped with the reason: no_row, bad_row, no_match, or no_table
#   when the floor copy answered;
# * the floor app (<app>_floor, --floor on) holds the lookup definition and a file of the same name with
#   the one row FLOOR_HASH. Splunk reads a lookup file from the first app, in app folder name order,
#   that holds one (measured with three apps: a file only in another app is read; "a_x" before "b_x" before
#   "b_x_floor"), so the floor is read only when the field map app has no file, or no definition, when
#   Splunk opens the table. It is not read for a table Splunk already holds;
# * gen writes the file through a rename, never over --lookup-max-bytes, and before the rule;
# * check (see "The engine's compact cap file") probes listed templates and empties the cap file as soon
#   as a probe event comes back without its fields or does not come back, so the Receiver sends them whole
#   (measured with a check every 10 s: the Receiver read the empty list 19 s after the file was replaced by
#   one with no rows, and 24 s after it was deleted).

def lookup_stanza(target):
	return '%s_fields' % target['transform_prefix']


def lookup_eval_stanza(target):
	return '%s_fields_eval' % target['transform_prefix']


def lookup_file_name(target):
	return '%s_fields.csv.gz' % target['transform_prefix']


def lookup_line_regex(n):
	"""The regex the rule builds for a template of n values (Python and PCRE read it alike)."""
	return ('^~[^,\\x00-\\x1f\\x7f]*' + LOOKUP_VALUE_GROUP_PY * n + (',?' if n == 0 else '')
		+ '[|]([^|\\x00-\\x1f\\x7f]*)[|]' + '([^|])' * len(LOOKUP_TAIL) + '$')


def _tail_group(n, c):
	return n + 2 + LOOKUP_TAIL.index(c)


def recipe_text(pieces, n):
	"""
	pieces: ('text', s) or ('group', k). The replacement text for replace(): text as written, except a
	backslash, tab, line feed or carriage return, and an ASCII digit right after a reference, which
	refer to their group of the tail.
	"""
	out = []
	after_ref = False
	for kind, v in pieces:
		if kind == 'group':
			out.append('\\%d' % v)
			after_ref = True
			continue
		for c in v:
			if c in '\\\t\n\r' or (after_ref and c in '0123456789'):
				out.append('\\%d' % _tail_group(n, c))
				after_ref = True
			else:
				out.append(c)
				after_ref = False
	return ''.join(out)


def meta_escape(text):
	"""A value's text inside the quotes of index-time field text."""
	return text.replace('\\', '\\\\').replace('"', '\\"')


def splunk_replace_expand(replacement, groups):
	"""
	replace()'s reading of a replacement, as measured on Splunk 10.4.3: a backslash and the digits that
	follow it name a group, which is written when it exists (groups[0] is the whole match), and the
	text is kept as written when it does not; every other character is text.
	"""
	out, i = [], 0
	while i < len(replacement):
		c = replacement[i]
		if c == '\\' and i + 1 < len(replacement) and replacement[i + 1] in '0123456789':
			j = i + 1
			while j < len(replacement) and replacement[j] in '0123456789':
				j += 1
			k = int(replacement[i + 1:j])
			out.append((groups[k] or '') if k < len(groups) else replacement[i:j])
			i = j
			continue
		out.append(c)
		i += 1
	return ''.join(out)


_META_PAIR = re.compile(r'(\S+?)::"((?:[^"\\]|\\.)*)"')


def parse_meta(text):
	"""(name, value) pairs of index-time field text name::"value", with \\ and \" read back."""
	return [(m.group(1), re.sub(r'\\(["\\])', r'\1', m.group(2))) for m in _META_PAIR.finditer(text)]


_TS_TIME_TOKENS = ('%H', '%-H', '%I', '%-I', '%M', '%-M', '%S', '%-S', '%p', '%Z', '%z', '%:z', '%:::z')


def lookup_ts_supported(fmt):
	"""True when the rule renders this timestamp format: the directives spl_timestamp renders, %1Q to %9Q
	for the fraction, no '%%', and no '|' or line break in the text."""
	if fmt == tenx_dml_builder.EPOCH_PASSTHROUGH:
		return True
	if '%%' in fmt or '|' in fmt or '\n' in fmt or '\r' in fmt:
		return False
	for m in _TS_TOKEN.finditer(fmt):
		tok = m.group(0)
		if not tok.startswith('%'):
			continue
		if tok in _TS_DATE or tok in _TS_TIME_TOKENS or re.fullmatch(r'%[1-9]Q', tok):
			continue
		return False
	return True


def lookup_eval_text(lookup_def, time_rule=None):
	"""The static INGEST_EVAL of --rules lookup (see "Lookup rules"). Every intermediate value sits in a
	pd: key, which is not indexed. A compact event the rule writes no fields for gets UNMAPPED_FIELD with
	the reason (see "Lookup failures"). With time_rule, the row's column w also sets _time (see "Event
	time"); without it the text is as before."""
	row, f, t, e, x, m, nt, ok, why = ('$pd:tenx_fm_%s$' % k for k in ('row', 'f', 't', 'e', 'x', 'm', 'n', 'ok', 'why'))
	w, wt, tt = ('$pd:tenx_fm_%s$' % k for k in ('w', 'wt', 'tt'))
	n = 'tonumber(%s)' % nt
	sec = 'tonumber(substr(%s, 1, 10))' % e
	sod = '(%s - floor(%s / 86400) * 86400)' % (sec, sec)
	noon = '(%s - %s + 43200)' % (sec, sod)
	tz = 'strftime(%s, "%%z")' % noon
	utc = '(%s - if(substr(%s, 1, 1) == "-", -1, 1) * (tonumber(substr(%s, 2, 2)) * 3600 + tonumber(substr(%s, 4, 2)) * 60))' % (
		noon, tz, tz, tz)
	hour = 'floor(%s / 3600)' % sod
	minute = 'floor((%s %% 3600) / 60)' % sod
	second = '(%s %% 60)' % sod
	hour12 = 'if(%s %% 12 == 0, 12, %s %% 12)' % (hour, hour)

	def two(v):
		return 'substr("0" . %s, -2)' % v

	pieces = [('%:::z', '"+00"'), ('%:z', '"+00:00"'), ('%z', '"+0000"'), ('%Z', '"UTC"'), ('%-H', 'tostring(%s)' % hour),
		('%H', two(hour)), ('%-I', 'tostring(%s)' % hour12), ('%I', two(hour12)), ('%-M', 'tostring(%s)' % minute),
		('%M', two(minute)), ('%-S', 'tostring(%s)' % second), ('%S', two(second)), ('%p', 'if(%s < 12, "AM", "PM")' % hour)]
	pieces += [('%%%dQ' % k, 'substr(%s . "000000000", 11, %d)' % (e, k)) for k in range(1, 10)]
	fmt = t
	for token, expr in pieces:
		fmt = 'replace(%s, "%s", %s)' % (fmt, token, expr)
	ts = 'if(len(%s) > 0, strftime(%s, %s), "")' % (t, utc, fmt)
	regex = '"^~[^,[:cntrl:]]*" . substr("%s", 1, %d * %s) . if(%s == 0, ",?", "") . "[|]([^|[:cntrl:]]*)[|]%s$"' % (
		LOOKUP_VALUE_GROUP * LOOKUP_MAX_VALUES, len(LOOKUP_VALUE_GROUP), n, n, '([^|])' * len(LOOKUP_TAIL))
	tail = '"|0123456789" . urldecode("%5C%09%0A%0D")'
	compact = 'substr(_raw, 1, 1)=="~"'
	columns = '"n", "t", "f"' + (', "%s"' % LOOKUP_TIME_COLUMN if time_rule else '')
	exprs = [
		'%s=if(%s, lookup("%s", json_object("hash", trim(replace(_raw, "(?s)^~([^,]*).*$", "\\1"))), '
		'json_array(%s)), null())' % (row, compact, lookup_def, columns),
		'%s=json_extract(%s, "f")' % (f, row),
		'%s=json_extract(%s, "t")' % (t, row),
		'%s=json_extract(%s, "n")' % (nt, row),
		# A row the rule can use: a recipe of name::value pairs, and a value count of at most LOOKUP_MAX_VALUES in digits. Any
		# other row (a cut line, a column missing, two rows for one hash) builds no regex, so replace() never
		# gets a regex it cannot compile.
		'%s=if(isnotnull(%s) AND isnotnull(%s), if(match(%s, "::") AND match(%s, "^[0-9]{1,3}$"), if(%s <= %d, 1, 0), 0), 0)' % (
			ok, f, nt, f, nt, n, LOOKUP_MAX_VALUES),
		'%s=if(len(%s) > 0, replace(_raw, "^~[^,]*,([^,|]*).*$", "\\1"), "")' % (e, t),
		'%s=if(%s == 1, _raw . "|" . %s . %s, null())' % (x, ok, ts, tail),
		'%s=if(isnull(%s), null(), replace(%s, %s, %s))' % (m, x, x, regex, f),
		# _meta is null on an event no earlier rule gave an indexed field (an HEC event without "fields").
		'_meta=if(isnull(%s) OR %s==%s, _meta, coalesce(_meta, "") . " " . %s)' % (m, m, x, m),
		'%s=case(%s, null(), isnull(%s) AND isnull(%s), "%s", %s != 1, "%s", isnull(%s) OR %s==%s, "%s")' % (
			why, compact.replace('==', '!='), f, nt, WHY_NO_ROW, ok, WHY_BAD_ROW, m, m, x, WHY_NO_MATCH),
		# No row: the floor copy of the file, which holds only FLOOR_HASH, says the rows are missing as a whole.
		'%s=if(%s=="%s", if(isnull(json_extract(lookup("%s", json_object("hash", "%s"), json_array("n")), "n")), "%s", "%s"), %s)' % (
			why, why, WHY_NO_ROW, lookup_def, FLOOR_HASH, WHY_NO_ROW, WHY_NO_TABLE, why),
		'_meta=if(isnull(%s), _meta, coalesce(_meta, "") . " %s::" . %s)' % (why, UNMAPPED_FIELD, why),
	]
	if time_rule:
		text = 'replace(%s, %s, %s)' % (x, regex, w)
		if time_rule.lookahead > 0:
			text = 'substr(%s, 1, %d)' % (text, time_rule.lookahead)
		exprs += [
			'%s=json_extract(%s, "%s")' % (w, row, LOOKUP_TIME_COLUMN),
			# Only for an event whose fields were written (the same regex matched), and a row with a recipe.
			'%s=if(isnull(%s) OR %s==%s OR coalesce(len(%s), 0)==0, null(), %s)' % (wt, m, m, x, w, text),
			# One format is strptime() alone: Splunk Enterprise 10.4.3 refuses to compile an INGEST_EVAL that calls
			# coalesce() with one argument ("Invalid function argument") and then writes none of the transform's fields.
			'%s=if(isnull(%s), null(), %s)' % (tt, wt, time_parse_text(wt, time_rule.formats)),
			'_time=if(isnotnull(%s) AND %s >= time() - %d AND %s <= time() + %d, %s, _time)' % (
				tt, tt, time_rule.max_days_ago * 86400, tt, time_rule.max_days_hence * 86400, tt),
		]
	return ', '.join(exprs)


def time_parse_text(text, formats):
	"""The eval expression that reads <text> with the rule's formats: strptime() for one format, the first that parses
	(coalesce) for more than one."""
	parts = ['strptime(%s, "%s")' % (text, fmt) for fmt in formats]
	return parts[0] if len(parts) == 1 else 'coalesce(%s)' % ', '.join(parts)


def lookup_columns(field_map):
	return LOOKUP_COLUMNS + ((LOOKUP_TIME_COLUMN,) if field_map.time_rule else ())


def lookup_rows(field_map, templates):
	"""The rows of the lookup file, sorted by hash: hash (trimmed), n, e (1 when value 0 is the
	timestamp), t (the format the rule renders, or empty), f (the recipe), and with an event time rule
	w (the recipe of the time text, or empty)."""
	timed = field_map.time_rule is not None
	return [(t.key, str(t.value_count), '1' if t.epoch else '0', t.ts_format, t.recipe) + ((t.time_recipe,) if timed else ())
		for t in sorted(field_map.transforms, key=lambda t: t.key)]


def lookup_file_bytes(rows, columns=LOOKUP_COLUMNS):
	"""The gzipped CSV, byte for byte the same for the same rows (no time in the gzip header)."""
	import gzip
	import io
	buf = io.StringIO(newline='')
	w = csv.writer(buf, lineterminator='\n')
	w.writerow(columns)
	w.writerows(rows)
	return gzip.compress(buf.getvalue().encode('utf-8'), mtime=0)


def read_lookup_file(path):
	"""hash -> row dict of a lookup file gen wrote."""
	import gzip
	with gzip.open(path, 'rt', encoding='utf-8', newline='') as f:
		return dict((r['hash'], r) for r in csv.DictReader(f))


def _lookup_groups(transform, compact_line):
	"""The groups the static rule's regex gives for one compact line (groups[0] the whole subject), or None."""
	head = re.match(r'^~?([^,]*)', compact_line)
	if head is None:
		return None
	ts = ''
	if transform.ts_format:
		v0 = re.match(r'^~[^,]*,([^,|]*)', compact_line)
		ts = format_timestamp(v0.group(1), transform.ts_format) if v0 else ''
	subject = compact_line + '|' + ts + '|' + LOOKUP_TAIL
	m = re.match(lookup_line_regex(transform.value_count), subject)
	if m is None:
		return None
	return [m.group(0)] + list(m.groups())


def apply_lookup_row(transform, compact_line):
	"""
	The pairs the static rule writes for one compact line with this template's row, as Splunk was
	measured to read the regex and the replacement; None when the line does not have its n values.
	"""
	groups = _lookup_groups(transform, compact_line)
	if groups is None:
		return None
	text = splunk_replace_expand(transform.recipe, groups)
	return [(n, v) for n, v in parse_meta(text) if n != MARK_FIELD]


def apply_lookup_time(transform, compact_line, rule):
	"""The text the static rule reads the event time from for one compact line, or None (see "Event time")."""
	if not transform.time_recipe:
		return None
	groups = _lookup_groups(transform, compact_line)
	if groups is None:
		return None
	text = splunk_replace_expand(transform.time_recipe, groups)
	return text[:rule.lookahead] if rule.lookahead > 0 else text


class FieldMap(object):
	"""
	The transforms for a set of templates, and what was left out and why.
	"""

	def __init__(self, templates, reader, prefix, stanza_names='indexed', hash_match='tolerant',
			timestamp_values='epoch', keep=None, refused=None, mixed_names=False, trim_values=None,
			reserved_names='skip', reserved_prefix='extracted_', mark=None, eval_values=False, rules=RULES_TRANSFORMS,
			time_rule=None):
		self.reader = reader
		# A value that is empty in the template is written as name::"" when the reader's Splunk extraction keeps
		# such a field (Splunk Enterprise 10.4.3 keeps an index-time name::"" as a field with an empty value).
		self.keeps_empty = getattr(reader, 'keeps_empty', False)
		# Event time (see "Event time"): --rules lookup only.
		if time_rule is not None and rules != RULES_LOOKUP:
			raise ValueError('an event time rule needs --rules lookup')
		self.time_rule = time_rule
		self._time_re = time_prefix_regex(time_rule) if time_rule is not None else None
		self.time_rows = 0
		self.time_skipped = collections.Counter()
		# transforms: one REGEX/FORMAT transform per template (and the INGEST_EVAL above); lookup: one row
		# of the lookup file per template for the static rule (see "Lookup rules"). The lookup recipe
		# writes every value FORMAT cannot, so eval_values does not apply to it.
		self.rules = rules
		self.mixed_names_on = mixed_names
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
		# writes it as <reserved_prefix><name>, and 'restore' does the same and also gives the field
		# back under its own name at search time (see RESTORE_TRANSFORM). All are counted in the report.
		self.reserved_names = reserved_names
		self.reserved_prefix = reserved_prefix
		self.reserved = collections.Counter()
		# Spaces and tabs at the ends of a value come only from template text (a compact value
		# never holds one), so trimming the marked text trims the value Splunk would see.
		self.trim_values = reader.trims_values if trim_values is None else trim_values
		# With INGEST_EVAL on, line breaks at the ends go too (TRIM_CHARS); off, spaces and tabs only,
		# as the first generated files had it. The lookup recipe writes line breaks, so it trims as eval on.
		self.trim_chars = TRIM_CHARS if (eval_values or rules == RULES_LOOKUP) else ' \t'
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

			if rules == RULES_LOOKUP:
				row = self._lookup_row(t, key, stanza, text, n)
				if row is not None:
					self.transforms.append(row)
				continue

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
				elif value == '' and not self.keeps_empty:
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
					if self.reserved_names != 'restore':
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

	def _lookup_row(self, t, key, stanza, text, n):
		"""
		The lookup row of one template (a Transform with recipe, ts_format and epoch), or None with the
		reason in self.refused. Pairs are chosen as for FORMAT, but every value is written: a quote, a
		backslash, a line break or a digit after a value need no INGEST_EVAL here.
		"""
		if n > LOOKUP_MAX_VALUES:
			self.refused[key] = REFUSED_TOO_MANY % LOOKUP_MAX_VALUES
			return None
		fmt = t.timestamp_format
		ts_text = False
		pieces = []
		fields = 0

		def groups_of(expr, ts_group):
			out = []
			for piece in MARK_SPLIT.split(expr):
				m = MARK_RE.fullmatch(piece)
				if m is None:
					if piece:
						out.append(('text', piece))
				elif int(m.group(1)) == 0 and ts_group:
					out.append(('group', n + 1))
				else:
					out.append(('group', int(m.group(1)) + 1))
			return out

		for name_expr, value_expr in self.reader.pairs(text):
			name, why = to_format(name_expr, True, self.reader.field_name, self.mixed_names_on)
			if name is None:
				self._skip(key, stanza, 'name: ' + why, name_expr)
				continue
			if self.trim_values:
				value_expr = value_expr.strip(self.trim_chars)
			if UNDECODABLE in value_expr:
				self._skip(key, stanza, 'value: ' + WHY_SPLIT_ESCAPE, name_expr)
				continue
			if value_expr == '' and not self.keeps_empty:
				continue
			carries_ts = bool(fmt) and (MARK % 0) in value_expr
			as_text = False
			if carries_ts:
				if self.timestamp_values == 'skip':
					self._skip(key, stanza, 'value: ' + WHY_TIMESTAMP, name_expr)
					continue
				if self.timestamp_values == 'text' and fmt != tenx_dml_builder.EPOCH_PASSTHROUGH:
					if not lookup_ts_supported(fmt):
						self._skip(key, stanza, 'value: ' + WHY_EVAL_FORMAT, name_expr)
						continue
					as_text = True
				elif self.timestamp_values == 'epoch':
					self.timestamp_fields[_shown(name_expr)] += 1
					self.explained[key].append(name_expr)
			literal_name = '$' not in name
			if literal_name and reserved_name(name):
				self.reserved[name] += 1
				if self.reserved_names == 'skip':
					self._skip(key, stanza, 'name: ' + WHY_RESERVED, name_expr)
					continue
				if self.reserved_names != 'restore':
					self.explained[key].extend([name_expr, self.reserved_prefix + name_expr])
				name = self.reserved_prefix + name
				name_expr = self.reserved_prefix + name_expr
			value = [(k, meta_escape(v) if k == 'text' else v) for k, v in groups_of(value_expr, as_text)]
			if pieces:
				pieces.append(('text', ' '))
			pieces += groups_of(name_expr, False) + [('text', '::"')] + value + [('text', '"')]
			fields += 1
			ts_text = ts_text or as_text
			if as_text:
				self.timestamp_text_fields[name] += 1
			if literal_name:
				self.literal_names[name] += 1
			elif not name.startswith('$'):
				self.mixed_names[name] += 1

		if not pieces:
			self.refused[key] = REFUSED_NO_FIELDS
			return None
		if self.mark:
			pieces.append(('text', ' %s::"1"' % self.mark))
		time_recipe = ''
		if self.time_rule is not None:
			time_pieces, why = self._time_pieces(text, n, fmt, groups_of)
			if why:
				self.time_skipped[why] += 1
			else:
				self.time_rows += 1
				time_recipe = recipe_text(time_pieces, n)
				ts_text = ts_text or ('group', n + 1) in time_pieces
		return Transform(key, stanza, '', '', fields, n, (), recipe_text(pieces, n), fmt if ts_text else '',
			bool(fmt), time_recipe)

	def _time_pieces(self, text, n, fmt, groups_of):
		"""
		(pieces, None): the text after the template's first TIME_PREFIX match, up to the lookahead counted
		in template text; or (None, the reason there is none). The timestamp slot is its rendered text
		(group n+1), as in a field; an epoch format is its digits as written.
		"""
		m = self._time_re.search(text)
		if m is None:
			return None, WHY_TIME_NO_PREFIX
		if '\x00' in m.group(0):
			return None, WHY_TIME_PREFIX_VALUE
		as_text = bool(fmt) and fmt != tenx_dml_builder.EPOCH_PASSTHROUGH
		limit = self.time_rule.lookahead
		pieces, literal = [], 0
		for kind, v in groups_of(text[m.end():], as_text):
			if limit > 0 and literal >= limit:
				break
			if kind == 'text' and limit > 0:
				v = v[:limit - literal]
				literal += len(v)
			pieces.append((kind, v))
		if not pieces:
			return None, WHY_TIME_EMPTY
		if ('group', n + 1) in pieces and not lookup_ts_supported(fmt):
			return None, WHY_TIME_FORMAT
		return pieces, None

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
		out = self._report(per, refused)
		if self.time_rule is not None:
			out['event_time'] = collections.OrderedDict([('rule', dict(self.time_rule._asdict())),
				('templates_with_rule', self.time_rows), ('templates_without_rule', dict(self.time_skipped))])
		return out

	def _report(self, per, refused):
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
				('action', 'left out' if self.reserved_names == 'skip' else (
					'written as %s<name>' % self.reserved_prefix if self.reserved_names == 'prefix' else
					'written as %s<name>, given back as <name> at search time' % self.reserved_prefix)),
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


def restored_names(field_map):
	"""The literal reserved names --reserved-names restore gives back at search time, sorted."""
	if field_map.reserved_names != 'restore':
		return []
	return sorted(field_map.reserved)


def restore_stanza(name):
	return RESTORE_TRANSFORM + sanitize(name)


def props_text(target, field_map, settings, search_hash=True, sourcetype_field=SOURCETYPE_FIELD):
	lines = [
		'# %s. Index-time: the app\'s [%s] parsing plus one' % (target['description'], SOURCE_STANZA),
		'# generated transform per template. Search-time: renamed to the add-on\'s sourcetype.',
		'[%s]' % target['sourcetype'],
	]
	first = []
	if field_map.time_rule is not None:
		# The rule sets _time after tenx-event-time has: the copied TRANSFORMS- go first in the generated
		# list, which Splunk applies in list order, instead of in classes of their own.
		first = [s.strip() for k, v in settings if k.startswith('TRANSFORMS-') for s in v.split(',') if s.strip()]
		settings = [(k, v) for k, v in settings if not k.startswith('TRANSFORMS-')]
	lines += ['%s = %s' % kv for kv in settings]
	if field_map.rules == RULES_LOOKUP:
		lines[1] = '# generated rule reading one lookup row per template. Search-time: renamed to the add-on\'s sourcetype.'
		names = first + ([sourcetype_stanza(target)] if sourcetype_field else []) + [lookup_eval_stanza(target)]
	else:
		names = ([sourcetype_stanza(target)] if sourcetype_field else []) + [t.stanza for t in field_map.transforms]
	if field_map.forms:
		names.append(eval_stanza(target))
	if first:
		lines.append('# %s first, then the fields and the event time from the template\'s row.' % ', '.join(first))
	lines.append('TRANSFORMS-%s = %s' % (target['transforms_class'], ', '.join(names)))
	lines.append('rename = %s' % target['rename'])
	if search_hash:
		lines += ['',
			'# Search-time, for `tx`: the hash and values of these events once renamed. A renamed event runs only',
			'# the search-time rules of the target, so this sits in the target\'s stanza; text that does not start',
			'# with "~" (every uncompacted %s event) gets nothing from it.' % target['rename'],
			'[%s]' % target['rename'],
			'REPORT-%s = %s' % (HASH_TRANSFORM, HASH_TRANSFORM)]
	restored = restored_names(field_map)
	if restored:
		if not search_hash:
			lines += ['', '[%s]' % target['rename']]
		lines += ['# Search-time: each name Splunk does not keep for an indexed field, given back from %s<name>.'
			% field_map.reserved_prefix,
			'REPORT-tenx_fm_restore = %s' % ', '.join(restore_stanza(n) for n in restored)]
	return '\n'.join(lines) + '\n'


def transforms_text(field_map, search_hash=True, target=None, sourcetype_field=SOURCETYPE_FIELD):
	if field_map.rules == RULES_LOOKUP:
		stanzas = ['# The template rows, read by the rule below at index time (lookups/%s).\n[%s]\nfilename = %s\n'
			'case_sensitive_match = true\n' % (lookup_file_name(target), lookup_stanza(target), lookup_file_name(target)),
			'# Every compact event: its template\'s row gives the fields, written to _meta. The same for every\n'
			'# template, so adding one changes only the lookup file.\n[%s]\nINGEST_EVAL = %s\n' % (
				lookup_eval_stanza(target), lookup_eval_text(lookup_stanza(target), field_map.time_rule))]
	else:
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
		'template.\n\n') if field_map.rules != RULES_LOOKUP else (
		'# Generated by tenx_field_map.py: one index-time rule for every template of the sourcetype.\n\n')
	text = header + '\n'.join(stanzas)
	if search_hash:
		text += ('\n# Search-time: tenx-hash-vars-extraction (tenx-for-splunk) with the leading "~" required.\n'
			'[%s]\nREGEX = %s\n' % (HASH_TRANSFORM, HASH_REGEX))
	for name in restored_names(field_map):
		text += ('\n# Search-time: %s, written at index time as %s%s.\n[%s]\nSOURCE_KEY = %s%s\nREGEX = %s\n'
			'FORMAT = %s::$1\n' % (name, field_map.reserved_prefix, name, restore_stanza(name), field_map.reserved_prefix,
				name, RESTORE_REGEX, name))
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


def write_app(out_dir, target, field_map, settings, search_hash=True, sourcetype_field=SOURCETYPE_FIELD,
		lookup_bytes=None):
	for sub in ('default', 'metadata'):
		os.makedirs(os.path.join(out_dir, sub), exist_ok=True)

	# transforms.conf before props.conf: an instance that reads the folder between the two writes
	# finds every transform the old props.conf names. Each file is written through a temporary file
	# and a rename, and a file whose content would not change is left as it is.
	files = collections.OrderedDict()
	if field_map.rules == RULES_LOOKUP:
		# First: the rule must never run without its file (a missing file drops compact events).
		files[os.path.join('lookups', lookup_file_name(target))] = lookup_bytes
	files.update([
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
		sizes[rel] = len(text) if isinstance(text, bytes) else len(text.encode('utf-8'))
	return sizes


FLOOR_SUFFIX = '_floor'


def floor_dir(out_dir):
	"""The floor app's folder: beside the app, its name the app's name followed by _floor, so it sorts after it."""
	return os.path.abspath(out_dir).rstrip(os.sep) + FLOOR_SUFFIX


def floor_file_bytes():
	"""The floor copy of the lookup file: the header and the one row FLOOR_HASH, which no template has."""
	return lookup_file_bytes([(FLOOR_HASH, '0', '0', '', '')])


def write_floor_app(out_dir, target):
	"""
	The floor app (see "Lookup failures"): the lookup definition and a lookup file of the same name holding only
	FLOOR_HASH. It never changes when templates are added. Returns the sizes of the files.
	"""
	d = floor_dir(out_dir)
	name = os.path.basename(d)
	files = collections.OrderedDict([
		(os.path.join('lookups', lookup_file_name(target)), floor_file_bytes()),
		(os.path.join('default', 'transforms.conf'), '# Generated by tenx_field_map.py: the floor copy of the lookup the '
			'index-time rule of %s reads.\n# Splunk reads it only when the app %s has no file of this name; the rule then '
			'marks\n# every compact event %s::%s instead of failing on it.\n[%s]\nfilename = %s\ncase_sensitive_match = true\n'
			% (target['sourcetype'], os.path.basename(os.path.abspath(out_dir)), UNMAPPED_FIELD, WHY_NO_TABLE,
				lookup_stanza(target), lookup_file_name(target))),
		(os.path.join('default', 'app.conf'), '# Generated by tenx_field_map.py. Install it wherever %s is installed.\n'
			'[install]\nstate = enabled\n[ui]\nis_visible = false\nlabel = %s\n[launcher]\nversion = 0.0.1\n'
			% (os.path.basename(os.path.abspath(out_dir)), name)),
		(os.path.join('metadata', 'default.meta'), '[]\nexport = system\n'),
	])
	sizes = {}
	for rel, data in files.items():
		write_if_changed(os.path.join(d, rel), data)
		sizes[os.path.join(name, rel)] = len(data) if isinstance(data, bytes) else len(data.encode('utf-8'))
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
	   finds in the raw event (field names the reader accepts; values not empty, unless the reader's
	   Splunk extraction keeps empty values).
	3. With an event time rule, the text the rule reads the time from equals the text after the first
	   TIME_PREFIX match in the raw event, cut to the lookahead (see "Event time").
	Returns a dict of counts.
	"""
	reader = field_map.reader
	remaining = collections.Counter(raw_events(raw_path, raw_split or reader.raw_split))
	raw_total = sum(remaining.values())
	by_key = {t.key: t for t in field_map.transforms}
	keep_empty = field_map.keeps_empty
	rule = field_map.time_rule
	time_counts = collections.Counter()
	time_examples = []

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
		if rule is not None:
			want_t = time_text(rule, expanded, field_map._time_re)
			got_t = apply_lookup_time(transform, line, rule)
			if want_t is None:
				time_counts['raw_without_prefix'] += 1
			elif got_t is None:
				time_counts['no_rule'] += 1
			elif got_t == want_t:
				time_counts['equal'] += 1
			else:
				time_counts['differ'] += 1
				if len(time_examples) < 5:
					time_examples.append((key, want_t, got_t))
		if field_map.rules == RULES_LOOKUP:
			written_pairs = apply_lookup_row(transform, line)
		else:
			written_pairs = apply_transform(transform, line, field_map.forms)
		if written_pairs is None:
			no_match += 1
			continue
		got = collections.Counter((n_, v) for n_, v in written_pairs if keep_empty or v != '')
		for n_ in set(n_ for n_, _ in got if reserved_name(n_)):
			reserved_dynamic[n_] += 1
		if field_map.reserved_names == 'restore':
			# What the search-time restore gives back under the field's own name.
			back = set(field_map.reserved_prefix + n_ for n_ in field_map.reserved)
			got = collections.Counter(dict(((n_[len(field_map.reserved_prefix):] if n_ in back else n_, v), c)
				for (n_, v), c in got.items()))
		want = collections.Counter((n_, v.strip(field_map.trim_chars) if field_map.trim_values else v)
			for n_, v in reader.pairs(expanded) if (keep_empty or v != '') and reader.field_name.match(n_))
		want = collections.Counter({k: c for k, c in want.items() if keep_empty or k[1] != ''})
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
	if rule is not None:
		result['event_time_text'] = dict(time_counts)

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
	if rule is not None:
		out.write('event time text: equal to the raw event\'s text after TIME_PREFIX on %d, differs on %d, no rule for '
			'the template %d, raw event without the prefix %d\n' % (time_counts['equal'], time_counts['differ'],
				time_counts['no_rule'], time_counts['raw_without_prefix']))
		for d in time_examples:
			out.write('  time text differs: %r\n' % (d,))
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
# * activate (--rules lookup only) checks that the instance holds the app's static rule, then proves
#   that each template the pending list adds gets its fields from the instance: it sends one compact
#   event per such template, of the template's own shape with placeholder values, on one probe stream
#   (host tenx-fm-probe, source tenx:fm:probe, the compact sourcetype, into --probe-index) through the
#   management port's receivers/simple endpoint, and searches for them. The stream carries an event
#   before the probes in every run, so it is a stream that is already sending. A template whose probe
#   event was indexed with tenx_mapped joins the cap file; the others stay pending, and activate repeats
#   the probes every --poll seconds until --timeout. Nothing is restarted or reloaded: the instance
#   rereads the lookup file on its own (limits.conf ingest_lookup_refresh_period_secs, default 60 s).
#   gen --splunkd runs it right after writing the app, for an app written in place on that instance.
# * check proves the converse for templates already listed: it sends probe events of a few listed
#   templates on the same probe stream, and when one of them is indexed without its fields, or is not
#   indexed within --check-timeout (an index-time error drops an event), it empties the list at once
#   (rows that do not start with `true` are kept) and leaves every listed template pending, so the
#   Receiver sends them whole until activate has proven them again. The loop runs it on every turn.
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
# Per-template transforms (--rules transforms) are not activated: on Splunk Enterprise 10.4.3 a
# transform stanza added to the app takes effect after POST conf-transforms/_reload and
# conf-props/_reload only for an input stream (host, source and sourcetype) that starts afterwards; a
# stream that already carried events keeps the configuration it started with (0 of 9 events over 3
# minutes, also after reloading the HEC input), and so does a changed stanza that the stream already
# applies (0 of 22). Only a restart reaches such a stream.
PROBE_HOST = 'tenx-fm-probe'
PROBE_SOURCE = 'tenx:fm:probe'
# A hash no template has: the event that opens the probe stream gets no fields.
HEARTBEAT_LINE = '~tenx-fm-heartbeat,probe'


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
	binary = isinstance(text, bytes)
	try:
		with (open(path, 'rb') if binary else open(path, encoding='utf-8', newline='')) as f:
			if f.read() == text:
				return False
	except (IOError, OSError, UnicodeDecodeError):
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
		with (os.fdopen(fd, 'wb') if binary else os.fdopen(fd, 'w', encoding='utf-8', newline='')) as f:
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

	def __init__(self, url, auth=None, token=None, tls_verify=True, hec_url=None, hec_token=None):
		self.url = url.rstrip('/')
		self.hec_url, self.hec_token = (hec_url or '').rstrip('/'), hec_token
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

	def send(self, lines, index, host, source, sourcetype):
		"""Raw lines into the parsing pipeline, one event per line: through HTTP Event Collector when hec_url
		is set (the path compact events take from the Receiver, so the probe is parsed where they are), else
		through the management port's receivers/simple (the compact sourcetype breaks on line ends)."""
		if self.hec_url:
			body = '\n'.join(json.dumps({'event': l, 'index': index, 'host': host, 'source': source, 'sourcetype': sourcetype})
				for l in lines).encode('utf-8')
			req = urllib.request.Request(self.hec_url + '/services/collector/event', data=body, method='POST',
				headers={'Authorization': 'Splunk %s' % self.hec_token})
			with urllib.request.urlopen(req, context=self.ctx, timeout=120) as res:
				res.read()
			return
		q = urllib.parse.urlencode({'index': index, 'host': host, 'source': source, 'sourcetype': sourcetype})
		req = urllib.request.Request(self.url + '/services/receivers/simple?' + q, data=('\n'.join(lines) + '\n').encode('utf-8'),
			method='POST', headers=self.headers)
		with urllib.request.urlopen(req, context=self.ctx, timeout=120) as res:
			res.read()

	def search(self, spl):
		"""Rows of a one-shot search over all time."""
		res = self.call('POST', '/services/search/jobs', {'search': spl, 'exec_mode': 'oneshot', 'count': 0,
			'earliest_time': '0', 'latest_time': '+10y'})
		return res.get('results', [])

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


def lookup_app(app_dir):
	"""(compact sourcetype, lookup file path) of an app gen wrote with --rules lookup, or None."""
	props = read_conf(os.path.join(app_dir, 'default', 'props.conf'))
	transforms = read_conf(os.path.join(app_dir, 'default', 'transforms.conf'))
	for name, settings in props.items():
		if 'rename' not in settings:
			continue
		for k, v in settings.items():
			if not k.startswith('TRANSFORMS-'):
				continue
			for stanza in (x.strip() for x in v.split(',')):
				if stanza.endswith('_fields_eval') and 'INGEST_EVAL' in transforms.get(stanza, {}):
					table = transforms.get(stanza[:-len('_eval')], {}).get('filename')
					if table:
						return name, os.path.join(app_dir, 'lookups', table)
	return None


def probe_line(written_hash, row, now):
	"""A compact line of the template's shape: value 0 the time now (19 digits) when it is the
	timestamp, every other value the word probe."""
	n = int(row['n'])
	values = [('%d000000000' % now) if (k == 0 and row['e'] == '1') else 'probe' for k in range(n)]
	return '~%s,%s' % (written_hash, ','.join(values))


def probe_states(splunkd, index, sourcetype, since):
	"""hash -> (True when a probe event of that hash indexed since `since` has tenx_mapped, the reasons
	tenx_unmapped gives on the others)."""
	rows = splunkd.search('search index="%s" host="%s" source="%s" _index_earliest=%d | eval tenx_fm_probe_h=trim('
		'replace(_raw, "^~([^,]*).*$", "\\1")), tenx_fm_probe_m=if(isnull(%s), 0, 1), tenx_fm_probe_w=%s | stats '
		'max(tenx_fm_probe_m) as m values(tenx_fm_probe_w) as w by tenx_fm_probe_h' % (index, PROBE_HOST, PROBE_SOURCE,
			int(since), MARK_FIELD, UNMAPPED_FIELD))
	states = {}
	for r in rows:
		w = r.get('w') or []
		states[r['tenx_fm_probe_h']] = (r.get('m') == '1', sorted(w if isinstance(w, list) else [w]))
	return states


def probe_results(splunkd, index, sourcetype, since):
	"""hash -> True when a probe event of that hash indexed since `since` has tenx_mapped."""
	return dict((h, v[0]) for h, v in probe_states(splunkd, index, sourcetype, since).items())


def activate(app_dir, cap_file, splunkd, app_name=None, probe_index=None, timeout=300, poll=10, out=sys.stdout,
		clock=time.time, sleep=time.sleep):
	"""
	Lists in the cap file each template the pending list adds once a probe event of it, sent on the
	probe stream, is indexed with its fields; removals take effect at once. Never restarts or reloads
	anything. Returns 0 when the cap file equals the pending list, 1 otherwise (the pending list kept).
	"""
	pending = cap_file + CAP_PENDING_SUFFIX
	if not os.path.exists(pending):
		out.write('activate: nothing pending (%s)\n' % pending)
		return 0
	app_name = app_name or os.path.basename(os.path.abspath(app_dir))
	layout = lookup_app(app_dir)
	if layout is None:
		out.write('activate: app %s has per-template transforms, which reach a running stream only after a restart; '
			'generate it with --rules lookup; cap file left as it was\n' % app_name)
		return 1
	sourcetype, table = layout
	before, kept = read_cap(cap_file)
	after, _ = read_cap(pending)
	added = sorted(after - before)
	differ = not_installed(splunkd, app_dir, app_name)
	if differ:
		out.write('activate: the instance does not hold app %s as generated (%d stanzas, first %s); '
			'cap file left as it was\n' % (app_name, len(differ), differ[0]))
		return 1
	floor = floor_dir(app_dir)
	if added and os.path.isdir(floor) and not_installed(splunkd, floor, app_name + FLOOR_SUFFIX):
		out.write('activate: the instance does not hold the floor app %s, without which a missing lookup file drops compact '
			'events; cap file left as it was\n' % (app_name + FLOOR_SUFFIX))
		return 1
	confirmed = set()
	if added:
		if not probe_index:
			out.write('activate: --probe-index is needed to prove new templates; cap file left as it was\n')
			return 1
		rows = read_lookup_file(table)
		start = clock()
		splunkd.send([HEARTBEAT_LINE], probe_index, PROBE_HOST, PROBE_SOURCE, sourcetype)
		probes = 0
		while True:
			todo = [h for h in added if h not in confirmed and h.strip() in rows]
			if not todo:
				break
			# Until the instance has read the new file, one template stands for all of them.
			batch = todo if confirmed else todo[:1]
			splunkd.send([probe_line(h, rows[h.strip()], int(clock())) for h in batch], probe_index, PROBE_HOST, PROBE_SOURCE,
				sourcetype)
			probes += len(batch)
			sleep(poll)
			seen = probe_results(splunkd, probe_index, sourcetype, start - 1)
			confirmed |= set(h for h in todo if seen.get(h.strip()))
			if clock() - start > timeout:
				break
		missing = [h for h in added if h not in confirmed]
		out.write('activate: %d of %d new templates indexed with their fields on the probe stream (%d probe events, '
			'%.0f s)%s\n' % (len(confirmed), len(added), probes, clock() - start,
				'' if not missing else '; not yet: %s' % ', '.join(repr(h) for h in missing[:5])))
	now = (before & after) | confirmed
	if now == after:
		# Written anew rather than renamed: the pending file can be as old as the cap file it replaces (check
		# writes both at once), and the Receiver sees a change by the file's time.
		write_if_changed(cap_file, open(pending, encoding='utf-8', newline='').read())
		os.remove(pending)
		out.write('activate: %s lists %d templates (%d added, %d removed)\n' % (cap_file, len(after), len(confirmed),
			len(before - after)))
		return 0
	write_if_changed(cap_file, cap_text(now, kept))
	out.write('activate: %s lists %d templates; %d still pending\n' % (cap_file, len(now), len(after - now)))
	return 1


def check(app_dir, cap_file, splunkd, app_name=None, probe_index=None, sample=1, timeout=60, poll=10, out=sys.stdout,
		clock=time.time, sleep=time.sleep, rng=None):
	"""
	Probes `sample` listed templates, chosen at random. When every probe is indexed with its fields, returns 0 and
	changes nothing. When one is indexed without them or is not indexed within `timeout` seconds, the cap
	file keeps only its rows that do not start with true, every listed template is left pending
	(<cap file>.pending, merged with a pending list already there), and returns 1: the Receiver sends
	those templates whole until activate proves them again.
	"""
	import random
	listed, kept = read_cap(cap_file)
	if not listed:
		out.write('check: nothing listed (%s)\n' % cap_file)
		return 0
	app_name = app_name or os.path.basename(os.path.abspath(app_dir))
	layout = lookup_app(app_dir)
	if layout is None or not probe_index:
		out.write('check: needs an app generated with --rules lookup and --probe-index; cap file left as it was\n')
		return 2
	sourcetype, table = layout
	if not os.path.exists(table):
		# Splunk keeps the rows it read until its next refresh, then fails on every compact event: withdraw now.
		withdraw(cap_file, 'the lookup file %s is missing' % table, out)
		return 1
	rows = read_lookup_file(table)
	probed = sorted((rng or random.Random()).sample(sorted(h for h in listed if h.strip() in rows), min(sample, len(listed))))
	why = None
	if len(probed) < min(sample, len(listed)):
		why = 'a listed template has no row in %s' % table
	else:
		start = clock()
		splunkd.send([probe_line(h, rows[h.strip()], int(clock())) for h in probed], probe_index, PROBE_HOST, PROBE_SOURCE,
			sourcetype)
		while True:
			sleep(poll)
			states = probe_states(splunkd, probe_index, sourcetype, start - 1)
			got = [states.get(h.strip()) for h in probed]
			bad = [(h, g[1]) for h, g in zip(probed, got) if g is not None and not g[0]]
			if bad:
				why = 'probe of %r indexed without its fields (%s=%s)' % (bad[0][0], UNMAPPED_FIELD, ','.join(bad[0][1]) or 'none')
				break
			if all(got):
				out.write('check: %d of %d listed templates probed, all indexed with their fields (%.0f s)\n' % (
					len(probed), len(listed), clock() - start))
				return 0
			if clock() - start > timeout:
				why = '%d of %d probes not indexed within %.0f s' % (sum(1 for g in got if g is None), len(probed), timeout)
				break
	withdraw(cap_file, why, out)
	return 1


def withdraw(cap_file, why, out=sys.stdout):
	"""The cap file keeps only its rows that do not start with true; every listed template is left pending."""
	listed, kept = read_cap(cap_file)
	pending = cap_file + CAP_PENDING_SUFFIX
	waiting, _ = read_cap(pending)
	write_if_changed(pending, cap_text(listed | waiting, kept))
	write_if_changed(cap_file, cap_text((), kept))
	out.write('check: %s; %s now lists none of its %d templates, which stay pending until activate proves them again\n' % (
		why, cap_file, len(listed)))


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
	time_rule = None
	if args.time_props or args.time_format or args.time_prefix is not None:
		settings = read_time_settings(args.time_props, target['rename']) if args.time_props else {}
		time_rule = make_time_rule(settings, args.time_prefix, args.time_format or (), args.time_lookahead)
	field_map = FieldMap(templates, READERS[target['reader']](), target['transform_prefix'],
		stanza_names=args.stanza_names, hash_match=args.hash_match, timestamp_values=args.timestamp_values,
		keep=keep, refused=refused, mixed_names=args.mixed_names,
		reserved_names=args.reserved_names, reserved_prefix=args.reserved_prefix,
		trim_values={'auto': None, 'on': True, 'off': False}[args.trim_values],
		mark=None if args.mark == 'none' else args.mark, eval_values=args.eval_values == 'on', rules=args.rules,
		time_rule=time_rule)
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
		p.add_argument('--reserved-names', choices=('skip', 'prefix', 'restore'), default='skip',
			help='a field named like a Splunk default field (eventtype, host, source, ...; any case): '
				'skip it (default), write it under --reserved-prefix (prefix), or write it under the prefix and give it '
				'back under its own name at search time, under the rename target (restore); all are reported')
		p.add_argument('--reserved-prefix', default='extracted_',
			help='prefix for --reserved-names prefix and restore (default extracted_, the name Splunk 10.4.3 itself gave)')
		p.add_argument('--mark', default=MARK_FIELD,
			help='indexed field every FORMAT writes as <mark>::"1" (default %s; none: no mark). `tx` keeps the '
				'indexed fields of an event that has it from being extracted a second time' % MARK_FIELD)
		p.add_argument('--mixed-names', action='store_true',
			help='write names that join text and values (NOT CHECKED on Splunk; off by default)')
		p.add_argument('--rules', choices=(RULES_TRANSFORMS, RULES_LOOKUP), default=RULES_TRANSFORMS,
			help='transforms: one index-time transform per template (default); lookup: one static rule per sourcetype '
				'and one row per template in lookups/<prefix>_fields.csv.gz, so adding a template changes only that '
				'file, which Splunk rereads without a restart (needed for --cap-file)')
		p.add_argument('--time-props',
			help='with --rules lookup: the add-on\'s props.conf; its [default] and [<rename>] TIME_PREFIX, TIME_FORMAT, '
				'MAX_TIMESTAMP_LOOKAHEAD, MAX_DAYS_AGO and MAX_DAYS_HENCE set _time from the template\'s text after '
				'TIME_PREFIX, as Splunk sets it on the original event (see "Event time")')
		p.add_argument('--time-prefix', help='TIME_PREFIX for the event time rule, instead of the add-on\'s')
		p.add_argument('--time-format', action='append',
			help='a strptime format tried after the add-on\'s TIME_FORMAT (repeat for more); alone, it starts the rule')
		p.add_argument('--time-lookahead', type=int, help='MAX_TIMESTAMP_LOOKAHEAD for the rule, instead of the add-on\'s')
		if mode == 'gen':
			p.add_argument('--out', required=True, help='the app folder to write')
			p.add_argument('--report', help='report path (default: <out>_report.json)')
			p.add_argument('--app-props', default=default_app_props(), help='the app props.conf holding [tenx_encoded]')
			p.add_argument('--search-hash', choices=('on', 'off'), default='on',
				help='on: write the search-time hash and values extraction under the rename target, which `tx` needs')
			p.add_argument('--sourcetype-field', default=SOURCETYPE_FIELD,
				help='indexed field every event of the compact sourcetype gets as <field>::"<sourcetype>", which '
					'tenx-events names so that `tx` finds these events (default %s; none: not written)' % SOURCETYPE_FIELD)
			p.add_argument('--lookup-max-bytes', type=int, default=LOOKUP_DEFAULT_MAX_BYTES,
				help='with --rules lookup, refuse to write a lookup file larger than this (default %d; Splunk drops '
					'compact events when the file passes limits.conf ingest_max_memtable_bytes, default 10485760)'
					% LOOKUP_DEFAULT_MAX_BYTES)
			p.add_argument('--floor', choices=('on', 'off'), default='on',
				help='with --rules lookup, also write the floor app <out>_floor (default on): the lookup definition and a '
					'file of the same name holding one row, which Splunk reads when the app\'s own file is missing, so the rule '
					'marks compact events %s::%s instead of dropping them' % (UNMAPPED_FIELD, WHY_NO_TABLE))
			p.add_argument('--cap-file', help='the Receiver\'s compact cap file (compactReceiverLookupFile, keyed on '
				'templateHash): drop listed templates that lost their transform, and write <cap file>.pending, '
				'which activate makes the cap file once the app is active where the data is parsed')
			_splunkd_args(p, required=False)
		else:
			p.add_argument('--encoded', required=True)
			p.add_argument('--raw', required=True)
			p.add_argument('--raw-split', help='regex between raw events (default: the reader\'s)')

	p = sub.add_parser('activate', help='prove on a probe stream that the parsing instance writes the fields of the '
		'templates the pending list adds, then list them; nothing is restarted')
	p.add_argument('--app', required=True, help='the app folder gen wrote, as installed on the instance')
	p.add_argument('--app-name', help='the app\'s name on the instance (default: the folder name)')
	p.add_argument('--cap-file', required=True)
	_splunkd_args(p, required=True)

	p = sub.add_parser('check', help='probe a few listed templates; when one is indexed without its fields or not at all, '
		'list none of them until activate has proven them again')
	p.add_argument('--app', required=True, help='the app folder gen wrote, as installed on the instance')
	p.add_argument('--app-name', help='the app\'s name on the instance (default: the folder name)')
	p.add_argument('--cap-file', required=True)
	p.add_argument('--sample', type=int, default=1, help='listed templates probed per run, chosen at random (default 1)')
	_splunkd_args(p, required=True, timeout=60, timeout_help='seconds check waits for its probe events (default 60)')
	return ap


def _splunkd_args(p, required, timeout=300, timeout_help='seconds activate keeps probing (default 300)'):
	p.add_argument('--splunkd', required=required,
		help='management URL of the instance that parses the data, e.g. https://127.0.0.1:8089; with gen, '
			'activate runs right after the app is written (the app folder is on that instance)')
	p.add_argument('--probe-index',
		help='index for the probe events activate sends (one small event per new template); keep it out of data '
			'model and detection index lists')
	p.add_argument('--timeout', type=float, default=timeout, help=timeout_help)
	p.add_argument('--poll', type=float, default=10, help='seconds between probe rounds (default 10)')
	p.add_argument('--splunkd-auth-env', default='TENX_SPLUNKD_AUTH',
		help='environment variable holding user:password (default TENX_SPLUNKD_AUTH)')
	p.add_argument('--splunkd-token-env', default='TENX_SPLUNKD_TOKEN',
		help='environment variable holding a session key, used instead of user:password (default TENX_SPLUNKD_TOKEN)')
	p.add_argument('--probe-hec',
		help='HTTP Event Collector URL to send the probe events to, e.g. https://indexer:8088: the endpoint the Receiver '
			'sends to, so a probe is parsed where the compact events are (default: the --splunkd management port, '
			'which parses them on that instance)')
	p.add_argument('--probe-hec-token-env', default='TENX_PROBE_HEC_TOKEN',
		help='environment variable holding the HEC token for --probe-hec (default TENX_PROBE_HEC_TOKEN)')
	p.add_argument('--tls-verify', choices=('on', 'off'), default='on',
		help='off: accept the instance\'s certificate without checking it (a self-signed management port)')


def _splunkd(args):
	return Splunkd(args.splunkd, auth=os.environ.get(args.splunkd_auth_env),
		token=os.environ.get(args.splunkd_token_env), tls_verify=args.tls_verify == 'on', hec_url=args.probe_hec,
		hec_token=os.environ.get(args.probe_hec_token_env))


def main(argv=None):
	args = build_parser().parse_args(argv)
	if args.mode == 'activate':
		return activate(args.app, args.cap_file, _splunkd(args), args.app_name, args.probe_index, args.timeout, args.poll)
	if args.mode == 'check':
		return check(args.app, args.cap_file, _splunkd(args), args.app_name, args.probe_index, args.sample, args.timeout,
			args.poll)

	try:
		target, templates, field_map = _build(args)
	except ValueError as e:
		sys.stderr.write('%s: %s\n' % (args.mode, e))
		return 2

	if args.mode == 'verify':
		result = verify(templates, field_map, args.encoded, args.raw, args.raw_split)
		return 0 if result['expanded_differ'] == 0 and result['transform_regex_did_not_match'] == 0 else 1

	settings, not_copied = parsing_settings(args.app_props)
	sourcetype_field = None if args.sourcetype_field == 'none' else args.sourcetype_field
	if args.cap_file and args.rules != RULES_LOOKUP:
		sys.stderr.write('gen: --cap-file needs --rules lookup (per-template transforms reach a running stream only '
			'after a restart)\n')
		return 2
	lookup_bytes = None
	if args.rules == RULES_LOOKUP:
		rows = lookup_rows(field_map, templates)
		lookup_bytes = lookup_file_bytes(rows, lookup_columns(field_map))
		if len(lookup_bytes) > args.lookup_max_bytes:
			sys.stderr.write('gen: the lookup file would be %d bytes, over --lookup-max-bytes %d; nothing written\n'
				% (len(lookup_bytes), args.lookup_max_bytes))
			return 2
	cap = None
	if args.cap_file:
		hashes = cap_hashes(field_map, templates)
		cap = cap_before_app(args.cap_file, hashes)
	sizes = {}
	if args.rules == RULES_LOOKUP and args.floor == 'on':
		# First, so the definition and a file of its name exist before the rule that reads them.
		sizes.update(write_floor_app(args.out, target))
	sizes.update(write_app(args.out, target, field_map, settings, args.search_hash == 'on', sourcetype_field, lookup_bytes))
	if args.cap_file:
		cap['pending_file_written'] = cap_after_app(args.cap_file, hashes)
	report = field_map.report()
	if cap is not None:
		report['compact_cap'] = cap
	report['settings_copied_from_tenx_encoded'] = [k for k, _ in settings]
	report['settings_not_copied'] = not_copied
	report['file_bytes'] = sizes
	report['rules'] = args.rules
	if lookup_bytes is not None:
		report['lookup_rows'] = len(rows)
		report['lookup_csv_bytes'] = sum(len(','.join(r)) + 1 for r in rows)
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
	if args.rules == RULES_LOOKUP and args.floor == 'on':
		sys.stdout.write('floor app: %s; install it wherever %s is installed\n' % (floor_dir(args.out),
			os.path.basename(os.path.abspath(args.out))))
	if cap is not None:
		sys.stdout.write('compact cap: %s\n' % json.dumps(cap))
		if args.splunkd:
			return activate(args.out, args.cap_file, _splunkd(args), None, args.probe_index, args.timeout, args.poll)
	return 0


if __name__ == '__main__':
	sys.exit(main())
