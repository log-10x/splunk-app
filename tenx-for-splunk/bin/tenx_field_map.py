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
  starts with "~"). With several targets, the compact sourcetype's stanza holds it as well, for an
  event that keeps the compact sourcetype because its tenx_sourcetype names none of them.
* every FORMAT also writes tenx_mapped::"1" (--mark), so an event whose template had a transform
  is told apart from one indexed before its transform existed: `sourcetype::<compact>
  NOT tenx_mapped::1` counts the latter. `tx` hides an event with tenx_mapped from its `extract`
  (see macros.conf [tx]): the add-on's extractions with MV_ADD would otherwise add every indexed
  field a second time.
* with --addon, search-time copies of the add-on's rules that read the event's text (a REPORT- with no
  SOURCE_KEY, or one reading a block such as EventData_Xml), each reading the indexed field that holds
  the same text, in the add-on's own stanza and in a class that sorts right after the rule's class (see
  "Add-on rules that read the event's text"). Without them the Windows add-on gives no dest, src,
  src_ip, process_id or 4688 process fields on a mapped event.
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

Several original sourcetypes
----------------------------
Some add-ons keep the rules of one source under several sourcetypes and pick one per event from the event's text
at index time: the Fortinet FortiGate Add-on 1.6.10 sets fortigate_traffic, fortigate_utm, fortigate_event or
fortigate_anomaly from type= ([fgt_log] TRANSFORMS force_sourcetype_fortigate, DEST_KEY = MetaData:Sourcetype). A
compact event's text holds no type=, so the sender picks: it sets tenx_sourcetype by the line's type=, as it does
for txf. A map with several --rename sourcetypes (--target fortigate) has one compact sourcetype, one lookup file,
one cap file and one Receiver for all of them, writes no rename line, and ends its TRANSFORMS- list with

    SOURCE_KEY = field:tenx_sourcetype
    REGEX = ^(fortigate_traffic|fortigate_utm|fortigate_event|fortigate_anomaly)$
    DEST_KEY = MetaData:Sourcetype
    FORMAT = sourcetype::$1

(SOURCE_KEY = field:<name> reads an indexed field, transforms.conf.spec), so every event of the compact sourcetype,
compact or whole, is stored under the sourcetype its sender named, and the add-on's search-time rules run on it as
on the raw event; `tstats ... by sourcetype` counts it there as well. The search-time extraction for `tx`, the
restored reserved names and the copies of text rules sit under each of those sourcetypes; `tx` finds the events by
tenx_compact_st, which a map with several sourcetypes therefore always writes. An event whose tenx_sourcetype names
none of them keeps the compact sourcetype. Splunk Enterprise 10.4.3, FortiGate add-on 1.6.10: 1,000,000 of 1,000,000
BOTS v1 traffic events and 239 of 239 events of four log types stored under the sourcetype the sender named.

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
* delims: a DELIMS extraction with pair delimiters space and comma and the key-value delimiter "=", as
  the FortiGate add-on's [field_extract], read from what Splunk extracted on raw FortiGate events.
* windows-classic: classic Windows event log text, as Splunk's wel-message, wel-eq-kv and wel-col-kv
  read it (the header's name=value lines, and the message's "name:" lines).

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
        --target windows-security | windows-security-classic | fortigate | <target.json> [--sourcetype ...] [--rename ...]
        [--addon <add-on dir>] --out <app dir>
    tenx_field_map.py gen --rules lookup --target ... --out <app dir>        (no --records: before the first event)
    tenx_field_map.py gen --target fortigate --out <app dir>                 (no --records, no lookup: fields from the Receiver)
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

Before the first event
----------------------
A map's rules read whole events of the compact sourcetype as well as compact ones: the parsing settings copied from
[tenx_encoded] (one event per line, no line merging), tenx_compact_st, and the original sourcetype (an index-time rule
with several targets, the search-time rename line with one). Splunk applies the index-time ones while it indexes an
event, so an event indexed before the map is installed keeps Splunk's default parsing (lines merged where a heavy
forwarder reads the Receiver's output folder), the compact sourcetype with several targets, and no tenx_compact_st, so
`tx` does not find it. None of these rules depends on the templates: gen without --records writes the map with them, an
empty lookup file and the floor app, to install before the first event of the source. A later gen with the records
writes the same rules, the template rows, and the search-time rules some templates need (a restored reserved name, a
copy of an add-on rule); activate names any stanza the installed app lacks.

Fields from the Receiver
------------------------
With splunkFieldsForm, the Receiver sends each compact event's fields with it (HEC fields, or a line's meta that
[tenx-record-unwrap] adds to _meta), and its time with the line. Splunk then needs no template row, lookup rule or
time rule, only the rules that do not depend on templates: gen without --records and without --rules lookup writes
those (parsing, tenx_compact_st, the original sourcetype, the search-time hash), and leaves out the target's time
rule, which reads template rows. With --records, or with --time-props, --time-prefix or --time-format, a time rule
still needs --rules lookup.

Standard library only.
"""

import argparse
import base64
import collections
import configparser
import glob
import csv
import datetime
import hashlib
import io
import json
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.error
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
# The lookup rule writes such a field: the backslash is a token delimiter of the Receiver, so "abc\/def="
# in a JSON string is template text "abc", the backslash, and a value "/def=" (CloudTrail sessionToken). The
# row's recipe holds SPLIT_ESCAPE where the backslash was; after the replace() the rule decodes it with the
# value's first character: "/" reads as itself, "n", "t" and "r" as a space (as a line break or tab in any
# indexed value), and a field holding any other escape is left out. A private-use character no template
# text holds (gen refuses a template that does).
SPLIT_ESCAPE = "\ue000"
SPLIT_ESCAPE_KEEP = "/"
SPLIT_ESCAPE_SPACE = "ntr"
# The \u escapes JSON encoders write to keep text HTML-safe (Gson, used for AWS CloudTrail, writes "=" as \u003d at the
# end of a sessionToken), decoded by the rule; any other \u escape leaves the field out.
SPLIT_ESCAPE_UNICODE = (('003c', '<'), ('003e', '>'), ('0026', '&'), ('003d', '='), ('0027', "'"))

REFUSED_UNSAFE = "the app does not expand this template (expand_unsafe: %s)"
REFUSED_CONFLICT = "two different templates under one hash"
REFUSED_COUNT = "number of values unknown (no timestamp, no text before the first value, no pattern)"
REFUSED_SENTINEL = "the template text holds U+E000, which the lookup rule uses to mark a split escape"
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
COPIED_KEYS = ('DATETIME_CONFIG', 'LINE_BREAKER', 'SHOULD_LINEMERGE', 'NO_BINARY_CHECK', 'TRUNCATE', 'ADD_EXTRA_TIME_FIELDS')
COPIED_PREFIXES = ('TRANSFORMS-', 'SEDCMD-')
SOURCE_STANZA = 'tenx_encoded'
# The indexed field every FORMAT writes, unless --mark none.
MARK_FIELD = 'tenx_mapped'
# Indexed field every event of the compact sourcetype gets, for tenx-events (see the docstring).
SOURCETYPE_FIELD = 'tenx_compact_st'
# Search-time hash and values of a compact event under the rename target (see the docstring).
# Named after the map's transform prefix (hash_stanza), as is every name a generated app defines, so two maps of one
# target coexist on one instance; where both put a class in the same original sourcetype's stanza, Splunk Enterprise
# 10.4.3 keeps the value of the first class that extracts a field and adds none (three REPORT- classes writing one
# field gave it one value).
HASH_TRANSFORM = 'hash_vars'
HASH_REGEX = '^~(?<tenx_hash>[^,]+)(?:,(?<tenx_var_0>[^,]+)(?:,(?<tenx_vars>.*))?)?'
# --reserved-names restore: one search-time transform per reserved name, under the rename target's stanza,
# that reads the indexed <reserved_prefix><name> and writes <name>. A search-time field may carry such a
# name: KV_MODE = json gives eventType on uncompacted CloudTrail events. Extractions run before field
# aliases, calculated fields and lookups (props.conf.spec), so the add-on's rules that read the name
# (FIELDALIAS-... = eventType AS app, EVAL-user's eventType="AwsConsoleSignIn") find it.
RESTORE_TRANSFORM = 'restore_'
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
# classes). A value holds no comma and no control character except a carriage return: a line feed stays
# out, so two compact lines a line-merging input joined into one event get no fields, while the carriage
# return of a CR LF line end, which the engine leaves at the end of the value before the template's line
# feed (the OpenTelemetry Collector keeps CR LF; Fluent Bit's records had none), is part of the value. The
# group needs no backslash: the rule cuts its regex from a string constant by length, which an escape
# would change, so LOOKUP_CR stands for the carriage return and the rule puts one in after the cut.
LOOKUP_CR = '@'
LOOKUP_VALUE_GROUP = ',([^,[:cntrl:]]*(?:@[^,[:cntrl:]]*)*)'
LOOKUP_VALUE_GROUP_PY = ',([^,\\x00-\\x1f\\x7f]*(?:\\r[^,\\x00-\\x1f\\x7f]*)*)'
# Control characters at the two ends of a field value, which the rule drops for a reader whose add-on trims values.
# Template text there is cut when the app is generated, and a compact value holds no space at either end; this is
# for a value's own carriage return at the end of a field (AccessList "%%1538\r" before "\n\t\t\t\t"). A space is
# not dropped: the one between two fields follows the closing quote of a value that ends with "::" (an IPv6 address
# such as transip=:: or ipaddr="2001:db8::"), and dropping it joined that field with the next (Splunk Enterprise
# 10.4.3: transip read back as "::transport::0" with the POSIX class [:space:]; "::" with [:cntrl:]).
LOOKUP_EDGE_SPACE_PY = (re.compile('::"[\\x00-\\x1f\\x7f]+'), re.compile('[\\x00-\\x1f\\x7f]+"'))
# Appended to the compact line, after "|<timestamp text>|", so the replacement can write these
# characters by reference instead of as text: replace() reads a backslash followed by digits as a
# reference (greedily), so a literal backslash, and a digit right after a reference, would be read wrong.
LOOKUP_TAIL = '0123456789\\\t\n\r'
LOOKUP_COLUMNS = ('hash', 'n', 'e', 't', 'f')
# With an event time rule (see "Event time"), one more column: the recipe of the text after TIME_PREFIX.
LOOKUP_TIME_COLUMN = 'w'
# Kept under limits.conf [lookup] ingest_max_memtable_bytes (default 10485760). A missing file makes lookup()
# fail at index time and Splunk drop the event (see "Lookup rules"); gzip files of 12.8 MB and 25.6 MB, over
# that setting, still mapped 2 of 2 events each on Splunk 10.4.3, so the bound is kept as a margin only.
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

# The indexed field a map with several original sourcetypes reads each event's sourcetype from: the field
# the sender sets for txf (see "Several original sourcetypes").
RENAME_FIELD = 'tenx_sourcetype'

# Built-in target descriptions. Any key can be overridden on the command line or given in a
# JSON file with the same keys.
TARGETS = {
	'windows-security': {
		'reader': 'xml-windows',
		'sourcetype': 'tenx_win',
		'rename': 'XmlWinEventLog',
		# The source the compact events carry (Fluent Bit: event_source): the add-on's
		# [source::XmlWinEventLog:Security] rules apply to them only with it.
		'source': 'XmlWinEventLog:Security',
		# Fields ESCU's EventCode 4663 detections match with wildcard values.
		'indexed_value_false': list(WINDOWS_WILDCARD_FIELDS),
		'description': 'Compact Windows Security events',
	},
	# Windows Security events as classic text (WinEventLog), the form a Universal Forwarder's WinEventLog input
	# writes with renderXml = false: the add-on's rules are those of the sourcetype WinEventLog and of the sources
	# WinEventLog:Security and WinEventLog... (Splunk's own wel-* extractions).
	'windows-security-classic': {
		'reader': 'windows-classic',
		'sourcetype': 'tenx_wincl',
		'rename': 'WinEventLog',
		'source': 'WinEventLog:Security',
		# EventType= in the header is a Splunk default field name (eventtype, any case).
		'reserved_names': 'restore',
		# Stored as WinEventLog while indexed, like the raw event after the add-on's own index-time fix-up, so tstats
		# by sourcetype counts it there; the sender sets tenx_sourcetype WinEventLog as it does for txf.
		'rename_field': RENAME_FIELD,
		'description': 'Compact Windows Security events, classic text',
	},
	# One FortiGate stream, several sourcetypes: the add-on keeps each log type's rules under its own
	# sourcetype and sets it from the line's type= (see "Several original sourcetypes"). The sender sets
	# tenx_sourcetype by type= as it does for txf, and the map sets each event's sourcetype from it.
	'fortigate': {
		'reader': 'delims',
		'sourcetype': 'tenx_fgt',
		'rename': ['fortigate_traffic', 'fortigate_utm', 'fortigate_event', 'fortigate_anomaly'],
		# The UTM lines' eventtype= is a Splunk default field name; Splunk gives the raw event's text value
		# under eventtype, beside the event types.
		'reserved_names': 'restore',
		# The add-on's [fortigate_*] stanzas have TIME_PREFIX = ^ and no TIME_FORMAT: Splunk recognises
		# date= and time= itself. The rule reads the same two fields.
		'time_prefix': r'\bdate=',
		'time_format': ['%Y-%m-%d time=%H:%M:%S'],
		'description': 'Compact FortiGate events',
	},
	# Palo Alto Networks PAN-OS syslog (the Splunk Add-on for Palo Alto Networks): one map for the log types the
	# add-on stores by the line's fourth value ([pan:log] TRANSFORMS-sourcetype). The csv reader takes each
	# sourcetype's FIELDS from the add-on (--addon), and the compact events' source names their sourcetype (see
	# "Rules that read a compact event's text").
	'palo-alto': {
		'reader': 'csv',
		'sourcetype': 'tenx_pan',
		# pan:log last: a line none of the add-on's rules routes stays under the sourcetype it came in with.
		'rename': ['pan:traffic', 'pan:threat', 'pan:system', 'pan:config', 'pan:hipmatch', 'pan:correlation',
			'pan:userid', 'pan:globalprotect', 'pan:decryption', 'pan:log'],
		'reserved_names': 'restore',
		# Splunk fixes _time before the add-on's rule renames the event, with the settings of the sourcetype it
		# came in with: [pan:log] TIME_PREFIX = ^(?:[^,]*,){5}, [pan:firewall] ^(?:[^,]*,){6}, neither with a
		# TIME_FORMAT, so Splunk recognises the value after the sixth comma (generated_time) itself, and reads the
		# digits that open the next value as its fraction: 21:46:38,10.0.2.107 gave 21:46:38.10 (97,736 of 97,736
		# BOTS v2 traffic lines, Splunk Enterprise 10.4.3). strptime() with %N reads the same digits (10.0.2.107
		# .10, 192.168 .192, 7.1 .7) and gives null when none follow; the plain format then reads the time.
		'time_prefix': r'^(?:[^,]*,){6}',
		'time_format': ['%Y/%m/%d %H:%M:%S,%N', '%Y/%m/%d %H:%M:%S'],
		'description': 'Compact Palo Alto Networks events',
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
		rows = json.loads(text)
		for i, r in enumerate(rows):
			if not isinstance(r, dict) or '_key' not in r:
				raise ValueError('%s: row %d is not a template record of the KV store (no _key)' % (path, i + 1))
		return [_from_kv_row(r) for r in rows]

	builder = tenx_dml_builder.TenxDMLBuilder(timestamp_placeholder=TIMESTAMP_PLACEHOLDER,
		variable_separator=VARIABLE_SEPARATOR)
	records = []
	for n, line in enumerate(text.splitlines(), 1):
		if not line.strip():
			continue
		try:
			obj = json.loads(line)
		except ValueError:
			raise ValueError('%s: line %d is not JSON' % (path, n))
		if isinstance(obj, dict) and 'templateHash' not in obj and isinstance(obj.get('messages'), list):
			# A KV store export that failed: Splunk's REST answer, such as {"messages":[{"type":"ERROR","text":"Unauthorized"}]}.
			said = '; '.join(str(m.get('text', '')) for m in obj['messages'] if isinstance(m, dict)) or 'no text'
			raise ValueError('%s holds no template records: Splunk answered "%s". Export the KV store again with a '
				'user and password or token that can read it' % (path, said))
		if not isinstance(obj, dict) or 'templateHash' not in obj or 'template' not in obj:
			raise ValueError('%s: line %d is not a template record (no templateHash and template)' % (path, n))
		records.append(_from_template_line(obj, builder))
	return records


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

	def _kv(self, body, out, kind='element'):
		for m in self.KV.finditer(body):
			opening, value, closing = m.groups()
			if MARK_RE.fullmatch(opening) is None and opening != closing:
				continue
			out.append((opening, value, kind))

	def read(self, text):
		"""(name, value, kind) of every field, kind 'element', 'attribute' or 'data' (the item of the text
		it comes from: <X>v</X>, X='v', <Data Name='X'>v</Data>)."""
		out = []
		for block, rx in self.BLOCKS:
			for body in rx.findall(text):
				if block in ('System', 'RenderingInfo'):
					self._kv(body, out)
					if block == 'System':
						for m in self.ATTR.finditer(body):
							out.append((m.group(1), m.group(3), 'attribute'))
				else:
					for m in self.DATA.finditer(body):
						out.append((m.group(1), m.group(2), 'data'))
		for body in self.USERDATA.findall(text):
			for cleared in self.LOGFILECLEARED.findall(body):
				self._kv(cleared, out, 'userdata')
			for m in self.SUBJECT_USER_NAME.finditer(body):
				out.append(('Caller_User_Name', m.group(1), 'userdata'))
		return out

	def pairs(self, text):
		return [(name, value) for name, value, _ in self.read(text)]

	def items(self, text):
		"""Counter of (name, kind) of the fields of a text whose name is not a compact value."""
		return collections.Counter((name, kind) for name, _, kind in self.read(text) if MARK_RE.search(name) is None)


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
	  quote that does not end the value (msg="a b\\" gave a b\, f="s\\t.txt" gave s\t.txt, g="x\"></y"
	  gave x"></y); before any other character the backslash stays (r="c\=d" gave c\=d). A backslash
	  before a compact value stays as well: a compact value holds no double quote and no backslash;
	* spaces at both ends of a quoted value go, and a quoted value that is empty, or empty once its
	  spaces go, gives no field: msg=" Fortigate scheduled update ..." gave "Fortigate scheduled update ..."
	  (50 of 50 events), user="" gave no value (isnull(user) on 2,660 of 2,660 FortiGate UTM events), and on
	  probe lines "  a b  " gave "a b", "x " gave "x", " " and "" gave no value.
	* a double quote that opens a value and has no closing double quote after it runs to the end of the text, and
	  no pair is read inside it: a line ending in msg="some text with key=value in it gave msg "some text with
	  key=value in it" and no field key (Splunk Enterprise 10.4.3, 2 of 2 lines of that form in FortiGate sample
	  files).
	Not checked: msg="... a=b \"quoted\" c=" gave "... a=b "quoted" c" (the last "=" not kept; this reader
	keeps it), how Splunk names a key that is empty once cleaned, an empty value without quotes, and tabs or
	line breaks at the ends of a value.
	"""
	name = 'delims'
	raw_split = r'\n'
	trims_values = True
	keeps_empty = False
	field_name = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')

	PAIR = re.compile(r'(?:^|(?<=[ ,]))([^ ,="]+)=(?:"((?:[^"\\]|\\.)*)"(?=[ ,]|\Z)|"((?:[^"\\]|\\.)*)\Z|([^ ,]*))', re.S)
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
			quoted = m.group(2) if m.group(2) is not None else m.group(3)
			if quoted is None and m.group(4) == '':
				# An empty value without quotes: left out, as before (not checked against Splunk).
				continue
			out.append((key, self.ESCAPE.sub(r'\1', quoted) if quoted is not None else m.group(4)))
		return out


class CsvReader(object):
	r"""
	A transforms.conf DELIMS extraction with one set of delimiters and a FIELDS list: positional values, the
	n-th value under the n-th name (Palo Alto Networks PAN-OS syslog: DELIMS = ",", FIELDS = "future_use1",
	"receive_time", ...). Read from what Splunk Enterprise 10.4.3 extracted with the Splunk Add-on for Palo Alto
	Networks 4.0.0 ([extract_traffic]) on probe lines, each a BOTS v2 traffic line with one value changed:
	* a value runs to the next delimiter; values past the last name are dropped, and names past the last value
	  get nothing;
	* spaces at both ends of a value go ("  dns  " gave dns), and a value that is empty then gives no field
	  (",," and "\"\"" alike);
	* a value that opens with a double quote runs to the next double quote followed by a delimiter or the end of
	  the text and loses those two quotes: "Client,Server" gave Client,Server and "a""b,c" gave a""b,c; inside
	  it a backslash before a double quote or a backslash goes ("a\"b,c" gave a"b,c);
	* outside quotes too, a backslash before a double quote or a backslash goes and the quote is text:
	  \"used-by-malware,able-to-transfer-file\" gave "used-by-malware and able-to-transfer-file" (an elastic panw
	  decryption fixture line);
	* a double quote with no such closing quote, opening a value ("abc,...) or inside one (a"b,...), takes the
	  rest of the text as that value, quotes kept, and no later value is read;
	* a tab inside a value stays.
	Not checked: a backslash before another character inside quotes (kept here), spaces between a closing
	quote and the delimiter (allowed here), a quote inside an unquoted value that a later quote closes (the
	value then runs to that quote here), tabs at the ends of a value (kept here), a name listed twice in FIELDS
	(the first value kept here) and an empty name (no field here).

	Which names a text takes (layouts): each layout is (route, names, delimiters). With several, the first
	whose route (a regex) finds the text: the add-on's own index-time rule that sets the event's sourcetype
	(Palo Alto: [pan_traffic] REGEX = ^[^,]+,[^,]+,[^,]+,TRAFFIC,), applied to the template's text, so a
	template gets the names of the sourcetype its events are stored under. A template that no route finds gets
	no field. A compact value holds no delimiter and no double quote.
	"""
	name = 'csv'
	raw_split = r'\n'
	trims_values = True
	keeps_empty = False
	field_name = re.compile(r'[A-Za-z_][A-Za-z0-9_.:\-]*\Z')

	def __init__(self, layouts=()):
		self.layouts = [(re.compile(_python_regex(r)) if r else None, list(names), delims) for r, names, delims in layouts]

	def layout(self, text):
		for route, names, delims in self.layouts:
			if route is None or route.search(text):
				return names, delims
		return None, None

	@staticmethod
	def split(text, delims=','):
		out, pos, n = [], 0, len(text)
		while True:
			start = j = pos
			while j < n and text[j] == ' ':
				j += 1
			if j < n and text[j] == '"':
				k, buf, closed = j + 1, [], None
				while k < n:
					c = text[k]
					if c == '\\' and k + 1 < n and text[k + 1] in '"\\':
						buf.append(text[k + 1])
						k += 2
						continue
					if c == '"':
						m = k + 1
						while m < n and text[m] == ' ':
							m += 1
						if m == n or text[m] in delims:
							closed = m
							break
					buf.append(c)
					k += 1
				if closed is None:
					out.append(text[start:].strip(' '))
					return out
				out.append(''.join(buf).strip(' '))
				if closed == n:
					return out
				pos = closed + 1
				continue
			k, buf = j, []
			while k < n and text[k] not in delims and text[k] != '"':
				if text[k] == '\\' and k + 1 < n and text[k + 1] in '"\\':
					buf.append(text[k + 1])
					k += 2
					continue
				buf.append(text[k])
				k += 1
			if k < n and text[k] == '"':
				m = k + 1
				while m < n:
					if text[m] == '"':
						e = m + 1
						while e < n and text[e] == ' ':
							e += 1
						if e == n or text[e] in delims:
							break
					m += 1
				if m >= n:
					out.append(text[start:].strip(' '))
					return out
				out.append(text[start:m + 1].strip(' '))
				e = m + 1
				while e < n and text[e] == ' ':
					e += 1
				if e == n:
					return out
				pos = e + 1
				continue
			out.append((text[start:j] + ''.join(buf)).strip(' '))
			if k == n:
				return out
			pos = k + 1

	def pairs(self, text):
		names, delims = self.layout(text)
		if names is None:
			return []
		out, seen = [], set()
		for name, value in zip(names, self.split(text, delims)):
			if not name or value == '' or name in seen:
				continue
			seen.add(name)
			out.append((name, value))
		return out

	def items(self, text):
		return collections.Counter((name, 'column') for name, _ in self.pairs(text))


# ---------------------------------------------------------------------------------------------
# A positional rule on a compact line
#
# An add-on that reads positional values (DELIMS with FIELDS, as the Splunk Add-on for Palo Alto Networks reads
# PAN-OS syslog) reads a compact event's text too, and the Receiver's line "~<hash>,<value>,<value>,..." is
# comma-separated: its n-th value lands under the n-th name. Splunk Enterprise 10.4.3 keeps an indexed field over what
# a search-time rule extracts under the same name (an HEC event with src_ip indexed kept that value alone), so the
# columns the map writes are safe; every column the raw event leaves empty, or does not have, but the compact line
# reaches would get a value raw has not (dest_user, dvc_name, and through the add-on's EVAL- user and dvc).
#
# So for the csv reader the map also writes tenx_blank, naming those columns for each template (BlankFieldReader), and
# at search time nulls what the rule reads there (blank_overrides): EVAL-<column> = if(<column named>, null(),
# <column>) for each column, and the add-on's own EVAL- that read such a field again under their names with each
# reference guarded the same way, as calculated fields read the fields as extracted and aliased, before any of them.
# A raw event has no tenx_blank and keeps every value. Measured on 100,000 BOTS v2 Palo Alto events against raw:
# every field of a plain search equal but the event type err0r (a word of the raw text), Network_Traffic and Change
# equal on every field and event. The cost is search time on compact events (about 2 times on a stats over six
# fields, about 5 times on every field of every event; raw events about the same). Considered and measured: giving
# compact events their own source, whose [source::] stanza leaves the add-on's text rule out (Splunk takes a
# [source::] class over the sourcetype's), which costs no search time but leaves source different from raw on every
# compact event; and nulling the columns alone, which leaves dvc and user wrong.

BLANK_FIELD = 'tenx_blank'


class BlankFieldReader(object):
	"""
	The reader's pairs and one more, tenx_blank: the columns a positional rule reading the compact line would fill (the
	first 1 + values names of the template's layout: the hash, then one per value) that the map does not write.
	"""

	def __init__(self, reader, csv_reader):
		self.reader, self.csv_reader = reader, csv_reader

	def __getattr__(self, name):
		return getattr(self.reader, name)

	def pairs(self, text):
		out = list(self.reader.pairs(text))
		names, _ = self.csv_reader.layout(text)
		if names is None:
			return out
		written = set(n for n, _ in out)
		blank = []
		for name in names[:len(set(MARK_RE.findall(text))) + 1]:
			if name and name not in written and name not in blank:
				blank.append(name)
		# Always written, '-' when no column is blank: its presence marks a compact event of a csv map, which the
		# rules for reserved names read (see blank_overrides).
		out.append((BLANK_FIELD, ' '.join(blank) or '-'))
		return out


class WindowsClassicReader(object):
	r"""
	Classic Windows event log text (sourcetype WinEventLog), as Splunk's own search-time rules for sources
	WinEventLog... read it (Splunk Enterprise 10.4.3 etc/system/default/transforms.conf, applied by the Windows
	add-on's [source::(WMI:WinEventLog|WinEventLog)...] REPORT-0MESSAGE = wel-message, wel-eq-kv, wel-col-kv):
	* [wel-message] REGEX = (?sm)^(?<_pre_msg>.+)\nMessage=(?<Message>.+)$: the text up to the last line that
	  starts with Message= is _pre_msg, the rest is Message;
	* [wel-eq-kv] SOURCE_KEY = _pre_msg, DELIMS = "\n","=", MV_ADD = true: each header line name=value;
	* [wel-col-kv] SOURCE_KEY = Message, REGEX = \n([^:\n\r]+):[ \t]++([^\n]*), FORMAT = $1::$2, MV_ADD = true:
	  each later line of the message "name:" followed by spaces or tabs and the value (the possessive [ \t]++ leaves
	  no space or tab at the start of the value; greedy reads the same here, as the value may be empty).
	Names are cleaned as Splunk cleans extracted keys (CLEAN_KEYS, transforms.conf.spec): every character that is
	not a letter or digit becomes "_", then leading "_" and digits go ("\tAccount Name" gives Account_Name). A name
	found again is written again (MV_ADD: the subject's and the new logon's Account_Name). A value that is empty
	gives no field. Message itself is a field: its line breaks and tabs are written as spaces by an indexed field
	(see "Lookup rules"). Not checked against Splunk here: a header value holding "=" (taken as everything after
	the first "="), and a name that is a compact value.
	"""
	name = 'windows-classic'
	raw_split = r'\n(?=\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AaPp][Mm]\n)'
	# Splunk drops whitespace at the ends of a search-time extraction's value (measured for the XML reader); the
	# section rules of the add-on capture "\t\tNT AUTHORITY\SYSTEM" after "Security ID:" and give it without the tabs.
	trims_values = True
	keeps_empty = False
	field_name = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')

	MESSAGE = re.compile(r'(?s)^(.+)\nMessage=(.+)$')
	COLON = re.compile(r'\n([^:\n\r]+):[ \t]+([^\n]*)')

	@staticmethod
	def clean(key):
		parts = [p for p in MARK_SPLIT.split(key) if p]
		out = []
		for p in parts:
			out.append(p if MARK_RE.fullmatch(p) else re.sub(r'[^A-Za-z0-9]', '_', p))
		name = ''.join(out)
		return re.sub(r'^[_0-9]+', '', name)

	def pairs(self, text):
		m = self.MESSAGE.match(text)
		if m is None:
			return []
		# A forwarder's multi-line record can end with the line feed after the event's last line, which the raw
		# event, broken before the next date line, does not hold.
		pre, message = m.group(1), m.group(2).rstrip('\n')
		out = []
		for line in pre.split('\n'):
			if '=' not in line:
				continue
			k, v = line.split('=', 1)
			k = self.clean(k)
			if k and v != '':
				out.append((k, v))
		out.append(('Message', message))
		for c in self.COLON.finditer(message):
			k = self.clean(c.group(1))
			if k and c.group(2) != '':
				out.append((k, c.group(2)))
		return out


READERS = {r.name: r for r in (XmlWindowsReader, JsonReader, KeyValueReader, DelimsReader, WindowsClassicReader, CsvReader)}


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
# order (props.conf.spec, TRANSFORMS-<class>). An event with the indexed field tenx_time=sender keeps the
# time its sender gave it, as tenx-event-time keeps it: a heavy forwarder that reads the compact events
# back from files (the app's [tenx-record-unwrap]) gives each the _time it parsed for the raw event.
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

# Values a TIME_PREFIX match may span: a compact value holds no comma and no control character (see "Lookup
# rules"), so these stand for any of them.
TIME_PREFIX_PROBES = ('', 'x', '0', ' ', 'a b', 'Z9-x', ':', '=')


def prefix_match_is_stable(prefix_re, text, end):
	"""
	Whether the first TIME_PREFIX match on a template's marked text ends at the same template text for whatever
	values it spans: with each probe in place of every value (TIME_PREFIX_PROBES), the match must end where the
	template text that follows the match on the marked text begins (Palo Alto's ^(?:[^,]*,){6} spans the syslog
	header's values and still ends after the sixth comma, which is template text).
	"""
	head, rest = text[:end], text[end:]
	for probe in TIME_PREFIX_PROBES:
		h, r = MARK_RE.sub(lambda _: probe, head), MARK_RE.sub(lambda _: probe, rest)
		m = prefix_re.search(h + r)
		if m is None or m.end() != len(h):
			return False
	return True


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
# with the regex "^~[^,[:cntrl:]]*" + ",([^,[:cntrl:]]*(?:<CR>[^,[:cntrl:]]*)*)" * n + "[|]([^|[:cntrl:]]*)[|]" +
# "([^|])" * 14 + "$" (a value holds no comma and no control character but a carriage return; see
# LOOKUP_VALUE_GROUP) and the recipe as the replacement. The result is index-time field text, name::"value" pairs as WRITE_META
# writes them, which the rule appends to _meta. A compact line that does not have n values leaves the
# text unchanged and gets nothing. replace() reads "\<digits>" as a reference to that group when it
# exists and leaves it as text when it does not; any other backslash is text (10.4.3, measured at
# search and index time alike). So the recipe refers to group k for value k-1, n+1 for the timestamp
# text, n+2..n+11 for a digit right after a reference, n+12 for a backslash and n+13..n+15 for tab,
# line feed and carriage return; it holds no other backslash. In the field text a value's backslash is
# written "\\" and its double quote "\"" (how Splunk writes them itself), and a line break inside a
# value reads back as a space, as for an INGEST_EVAL field. For a reader whose add-on trims values
# (xml-windows) the rule then drops whitespace at the two ends of each field value, which only a value's
# own carriage return can leave there (template text at the ends is cut when the app is generated).
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


def split_escape_eval(m):
	"""The SPL that decodes SPLIT_ESCAPE in the field text m: "/" as itself, a line break or tab escape as a space, the
	\\u escapes of SPLIT_ESCAPE_UNICODE as their characters."""
	text = 'replace(replace(%s, "%s([%s])", "\\1"), "%s[%s]", " ")' % (m, SPLIT_ESCAPE, SPLIT_ESCAPE_KEEP, SPLIT_ESCAPE,
		SPLIT_ESCAPE_SPACE)
	for code, char in SPLIT_ESCAPE_UNICODE:
		text = 'replace(%s, "(?i)%su%s", "%s")' % (text, SPLIT_ESCAPE, code, char)
	return text


def lookup_eval_text(lookup_def, time_rule=None, trim=False):
	"""The static INGEST_EVAL of --rules lookup (see "Lookup rules"). Every intermediate value sits in a
	pd: key, which is not indexed. A compact event the rule writes no fields for gets UNMAPPED_FIELD with
	the reason (see "Lookup failures"). With time_rule, the row's column w also sets _time (see "Event
	time"); without it the text is as before. With trim, whitespace at the two ends of each field value is
	dropped, as the add-on of a reader that trims values drops it."""
	row, f, t, e, x, m, nt, ok, why = ('$pd:tenx_fm_%s$' % k for k in ('row', 'f', 't', 'e', 'x', 'm', 'n', 'ok', 'why'))
	mt = '$pd:tenx_fm_mt$'
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
	regex = '"^~[^,[:cntrl:]]*" . replace(substr("%s", 1, %d * %s), "%s", urldecode("%%0D")) . if(%s == 0, ",?", "") . "[|]([^|[:cntrl:]]*)[|]%s$"' % (
		LOOKUP_VALUE_GROUP * LOOKUP_MAX_VALUES, len(LOOKUP_VALUE_GROUP), n, LOOKUP_CR, n, '([^|])' * len(LOOKUP_TAIL))
	quote = 'urldecode("%22")'
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
		'%s=if(len(%s) > 0, replace(_raw, "(?s)^~[^,]*,([^,|]*).*$", "\\1"), "")' % (e, t),
		'%s=if(%s == 1, _raw . "|" . %s . %s, null())' % (x, ok, ts, tail),
		'%s=if(isnull(%s), null(), replace(%s, %s, %s))' % (m, x, x, regex, f),
		# A JSON escape the Receiver split at its backslash (see SPLIT_ESCAPE): decoded with the value's first character,
		# and a field that holds any other escape is left out.
		'%s=if(isnull(%s) OR %s==%s, %s, replace(%s, %s, ""))' % (m, m, m, x, m, split_escape_eval(m),
			'"[^ ]+::" . %s . "([^" . %s . urldecode("%%5C%%5C") . "]|" . urldecode("%%5C%%5C") . ".)*%s([^" . %s . '
			'urldecode("%%5C%%5C") . "]|" . urldecode("%%5C%%5C") . ".)*" . %s . " ?"' % (quote, quote, SPLIT_ESCAPE, quote,
				quote)),
	] + ([
		'%s=if(isnull(%s) OR %s==%s, %s, replace(replace(%s, "::" . %s . "[[:cntrl:]]+", "::" . %s), '
		'"[[:cntrl:]]+" . %s, %s))' % (mt, m, m, x, m, m, quote, quote, quote, quote),
	] if trim else []) + [
		# _meta is null on an event no earlier rule gave an indexed field (an HEC event without "fields").
		'_meta=if(isnull(%s) OR %s==%s, _meta, coalesce(_meta, "") . " " . %s)' % (m, m, x, mt if trim else m),
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
			# tenx_time=="sender" is null, not false, on an event without the field, so it is tested first, as in the
			# app's tenx-event-time.
			'_time=if(tenx_time=="sender", _time, if(isnotnull(%s) AND %s >= time() - %d AND %s <= time() + %d, %s, _time))' % (
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


def lookup_file_problem(path):
	"""
	Why the lookup file at `path` cannot be read as gen writes it, or None. While the file Splunk reads is missing,
	cannot be read, is not gzip or has no hash column, lookup() fails in the static rule and Splunk drops every
	compact event of the map's sourcetype, floor app or not (Splunk Enterprise 10.4.3). This reads the copy gen
	wrote, the one installed from it.
	"""
	import gzip
	if not os.path.exists(path):
		return 'is missing'
	try:
		with gzip.open(path, 'rt', encoding='utf-8', newline='') as f:
			header = next(csv.reader(f), None)
	except (OSError, EOFError, UnicodeDecodeError, csv.Error) as e:
		return 'cannot be read as gzip CSV (%s)' % e
	if not header or 'hash' not in header:
		return 'has no hash column'
	return None


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


def apply_lookup_row(transform, compact_line, trim=False):
	"""
	The pairs the static rule writes for one compact line with this template's row, as Splunk was
	measured to read the regex and the replacement; None when the line does not have its n values. With
	trim, whitespace at the two ends of each value goes, as the rule drops it for a reader that trims.
	"""
	groups = _lookup_groups(transform, compact_line)
	if groups is None:
		return None
	text = split_escape_decode(splunk_replace_expand(transform.recipe, groups))
	if trim:
		text = LOOKUP_EDGE_SPACE_PY[1].sub('"', LOOKUP_EDGE_SPACE_PY[0].sub('::"', text))
	return [(n, v) for n, v in parse_meta(text) if n != MARK_FIELD]


_SPLIT_KEEP = re.compile(SPLIT_ESCAPE + '([' + re.escape(SPLIT_ESCAPE_KEEP) + '])')
_SPLIT_SPACE = re.compile(SPLIT_ESCAPE + '[' + SPLIT_ESCAPE_SPACE + ']')
_SPLIT_LEFT = re.compile(r'[^ ]+::"([^"\\]|\\.)*' + SPLIT_ESCAPE + r'([^"\\]|\\.)*" ?')


def split_escape_decode(text):
	"""The lookup rule's decoding of SPLIT_ESCAPE in index-time field text, as Python reads it."""
	text = _SPLIT_SPACE.sub(' ', _SPLIT_KEEP.sub(r'\1', text))
	for code, char in SPLIT_ESCAPE_UNICODE:
		text = re.sub('(?i)' + SPLIT_ESCAPE + 'u' + code, lambda _m, c=char: c, text)
	return _SPLIT_LEFT.sub('', text)


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
		# Fields written with a JSON escape split by a value (see SPLIT_ESCAPE), per field name.
		self.split_escapes = collections.Counter()
		# Spaces and tabs at the ends of a value come only from template text (a compact value never
		# holds one), so trimming the marked text trims the value Splunk would see. A compact value can
		# end with the carriage return of a CR LF line end; the lookup rule trims that at index time.
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
			if SPLIT_ESCAPE in text:
				self.refused[key] = REFUSED_SENTINEL
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
				# The escaped character is the first one of the value right after it: the rule decodes it (see SPLIT_ESCAPE).
				if all(MARK_RE.match(value_expr, i + 1) for i, c in enumerate(value_expr) if c == UNDECODABLE):
					value_expr = value_expr.replace(UNDECODABLE, SPLIT_ESCAPE)
					self.split_escapes[_shown(name_expr)] += 1
				else:
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
		if '\x00' in m.group(0) and not prefix_match_is_stable(self._time_re, text, m.end()):
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
			('fields_with_a_split_escape', dict(self.split_escapes)),
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
# Add-on rules that read the event's text
#
# Some search-time rules of an add-on read the event's text, not a field: a REPORT- transform with no
# SOURCE_KEY (it reads _raw), or one whose SOURCE_KEY is a block of the text that another of the add-on's
# transforms cuts out of _raw (Splunk_TA_windows 12.0.0: [eventdata_xml_block] writes EventData_Xml, and
# [process_id_for_windows_security_from_xml__var1] reads ProcessId from EventData_Xml). On a mapped event
# _raw is the compact text, so such a rule finds nothing, and every field it gives, with every alias,
# calculated field, lookup and tag built on it, is missing (Splunk 10.4.3, Windows add-on 12.0.0, 662
# Security events: dest on 612, src on 224, src_ip on 114, process_id on 257, the 4688 process fields on 36).
#
# With --addon, gen reads the add-on's props.conf and transforms.conf (default/, then local/ over it) and,
# for each such rule in the stanzas that apply to the renamed events ([<rename>] and the source:: stanzas
# matching the target's source), writes a copy that reads the same text from the field the map indexes
# for it:
#
# * The rule's REGEX is cut into the text before the value, the value, and the text after it (the value is
#   the capture group of the field the rule writes, with the lookaheads right before it). The text before
#   and after must enclose one item that the reader writes as a field: <Data Name='X'>...</Data> (an
#   EventData value, field X), <X>...</X> (an element, field X) or <E X='...' (an attribute, field X). A
#   name written as a small alternation (ProcessI(d|D)) gives each of its names, and an optional part
#   (attributes in <EventID.*?>, ".*" after the item) is read as absent. A rule whose text around the value
#   is anything else (a condition on a second item, free text) is not copied, and the report says why.
# * The copy is SOURCE_KEY = X, REGEX = \A<value>\z (with the rule's flags), FORMAT as the rule's with its
#   group numbers shifted. gen checks it against the rule on synthetic events before writing it: for each
#   of a set of values, the rule on event text holding the item and the copy on the value must give the
#   same fields, and the rule must give nothing on the same text without the item.
# * It runs where the rule runs: in the same stanza, in a class named <rule's class>-<prefix>. Splunk runs
#   REPORT- classes in ASCII order of their names, and "-" sorts before every letter, digit and "_", so
#   the copy runs right after the rule's own class (gen refuses when another class of the add-on starts
#   with <class>-), and everything that reads the field later (later classes, aliases, calculated fields,
#   lookups) finds it as on the raw event. On a raw event the rule has written the field when the copy
#   runs, and the copy adds nothing: a search-time extraction keeps the value a field already has unless
#   MV_ADD is set (transforms.conf.spec), and the copy never sets it; where the rule found nothing, the
#   item is absent, and so is the field the copy reads. When a later transform of the same class writes
#   the same field, the copy would run after it, so gen does not write that copy.
#
# Not given by a copy: a field the map does not index (the XML blocks themselves, EventData_Xml and
# System_Props_Xml), and the fields of rules whose text is not one item (Splunk_TA_windows 12.0.0: the
# rules that read a Data value only for EventID 5156, 5157 or 4798, and the free-text msad_* rules).

TEXT_RULE_INFIX = '_text_'


def read_splunk_conf(path):
	"""A Splunk .conf file as stanza -> {key: value}, in file order. A value continues on the next line
	when its line ends with a backslash; a line starting with # is a comment. A missing file is empty."""
	out = collections.OrderedDict()
	if not os.path.isfile(path):
		return out
	stanza, key, buf = 'default', None, []
	with open(path, encoding='utf-8-sig') as f:
		for line in f:
			line = line.rstrip('\r\n')
			if key is not None:
				more = line.endswith('\\')
				buf.append(line[:-1] if more else line)
				if not more:
					out.setdefault(stanza, collections.OrderedDict())[key] = '\n'.join(buf).strip()
					key, buf = None, []
				continue
			text = line.strip()
			if not text or text.startswith('#'):
				continue
			m = re.match(r'^\[(.*)\]$', text)
			if m:
				stanza = m.group(1)
				out.setdefault(stanza, collections.OrderedDict())
				continue
			if '=' not in text:
				continue
			k, v = (x.strip() for x in text.split('=', 1))
			if line.endswith('\\'):
				key, buf = k, [v[:-1]]
				continue
			out.setdefault(stanza, collections.OrderedDict())[k] = v
	if key is not None:
		out.setdefault(stanza, collections.OrderedDict())[key] = '\n'.join(buf).strip()
	return out


class AddonError(ValueError):
	"""An add-on folder that --addon cannot read."""


def read_addon(addon_dir):
	"""(props, transforms) of an add-on folder: default/, then local/ over it, key by key."""
	merged = []
	for conf in ('props', 'transforms'):
		out = collections.OrderedDict()
		for sub in ('default', 'local'):
			for name, settings in read_splunk_conf(os.path.join(addon_dir, sub, conf + '.conf')).items():
				out.setdefault(name, collections.OrderedDict()).update(settings)
		merged.append(out)
	if not merged[0]:
		raise AddonError('no props.conf under %s (default/ or local/)' % addon_dir)
	return merged[0], merged[1]


def quoted_list(value):
	"""A transforms.conf <quoted string list> ("a","b" or ",", "="): the strings, with the escapes tab, line feed,
	carriage return, backslash and double quote read."""
	out = []
	for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', value or ''):
		out.append(re.sub(r'\\(.)', lambda e: {'t': '\t', 'n': '\n', 'r': '\r'}.get(e.group(1), e.group(1)), m.group(1)))
	return out


def csv_layouts(addon_dir, sourcetypes, by_sourcetype=False):
	"""
	(layouts, report) for the csv reader from an add-on: for each sourcetype, the names (FIELDS) and delimiters
	(DELIMS, one set) of the first REPORT- transform of its stanza that reads the event's text that way, and,
	with several sourcetypes, the REGEX of the add-on's index-time transform that stores an event under it
	(DEST_KEY = MetaData:Sourcetype, FORMAT = sourcetype::<it>), which picks a template's layout.
	"""
	props, transforms = read_addon(addon_dir)
	routes = collections.OrderedDict()
	for settings in props.values():
		for key, value in settings.items():
			if not key.startswith('TRANSFORMS-'):
				continue
			for name in [x.strip() for x in value.split(',') if x.strip()]:
				t = transforms.get(name, {})
				m = re.match(r'\s*sourcetype::(\S+)\s*$', str(t.get('FORMAT', '')))
				if str(t.get('DEST_KEY', '')).strip() == 'MetaData:Sourcetype' and m and t.get('REGEX'):
					routes.setdefault(m.group(1), str(t['REGEX']).strip())
	layouts, report, names_of = [], collections.OrderedDict(), collections.OrderedDict()
	for st in sourcetypes:
		found = None
		for key, value in props.get(st, {}).items():
			if not key.startswith('REPORT-'):
				continue
			for name in [x.strip() for x in value.split(',') if x.strip()]:
				t = transforms.get(name, {})
				delims = quoted_list(t.get('DELIMS'))
				if _source_key(t) == '_raw' and len(delims) == 1 and t.get('FIELDS'):
					found = (name, quoted_list(t['FIELDS']), delims[0])
					break
			if found:
				break
		if found is None:
			report[st] = 'no REPORT- transform of [%s] reads the text with one DELIMS set and FIELDS' % st
			continue
		route = routes.get(st) if len(sourcetypes) > 1 else None
		if len(sourcetypes) > 1 and route is None:
			report[st] = 'no index-time rule of the add-on stores an event under %s, so no template is read as one' % st
			continue
		layouts.append((route, found[1], found[2]))
		names_of[st] = found[1]
		report[st] = '%s: %d names, delimiters %r%s' % (found[0], len(found[1]), found[2],
			', templates whose text %s finds' % route if route else '')
	return (layouts, report, names_of) if by_sourcetype else (layouts, report)


def blank_overrides(props, transforms, stanza, columns, reserved_prefix=None):
	"""
	The search-time settings the map writes in [stanza] so that what the add-on's DELIMS rule reads
	from a compact line where the map wrote no field (tenx_blank names those columns) is null, as on the raw event, with
	source left as it is. A field is tainted by a column when it is the column, or an add-on rule that runs before the
	calculated fields (REPORT or EXTRACT reading a field, FIELDALIAS) derives it from a tainted field. Then:
	* each add-on EVAL- that reads a tainted field is written again under its own name with each such reference in
	  if(<its column is blank>, null(), <field>); Splunk 10.4.3 takes the map's EVAL- over the add-on's for the same
	  name and stanza (measured: an app named fg_* over Splunk_TA_paloalto_networks; search-time precedence puts the
	  later name first), and a calculated field reads the fields as they were before any calculated field ran;
	* every other tainted field gets EVAL-<field> = if(<its column is blank>, null(), <field>).
	Returns [(key, value)] in order.
	"""
	settings = props.get(stanza, {})
	taint = collections.OrderedDict((c, {c}) for c in columns if c)

	def rule_reads():
		out = []
		for key, value in settings.items():
			kind = key.split('-', 1)[0].upper()
			if kind == 'REPORT':
				for t in [x.strip() for x in value.split(',') if x.strip()]:
					tr = transforms.get(t, {})
					sk = _source_key(tr)
					if sk != '_raw':
						out.append(({sk}, set(written_names(tr))))
			elif kind == 'EXTRACT':
				m = re.search(r'\s+in\s+([A-Za-z_][A-Za-z0-9_]*)\s*$', value)
				if m:
					out.append(({m.group(1)}, set(re.findall(r'\(\?P?<([A-Za-z_]\w*)>', value))))
			elif kind == 'FIELDALIAS':
				for a, how, b in re.findall(r'("[^"]+"|\S+)\s+(AS(?:NEW)?)\s+("[^"]+"|\S+)', value, re.I):
					out.append(({a.strip('"')}, {b.strip('"')}, how.upper() == 'AS'))
		return [r if len(r) == 3 else r + (False,) for r in out]

	reads = rule_reads()
	# An alias with AS writes its field from the source alone (the raw event's object is log_subtype's value though the
	# object column is empty), so the field's taint is the source's; any other rule adds to what the field had.
	for ins, outs, replaces in reads:
		if replaces:
			for o in outs:
				taint.pop(o, None)
	changed = True
	while changed:
		changed = False
		for ins, outs, replaces in reads:
			src = set().union(*[taint[i] for i in ins if i in taint]) if any(i in taint for i in ins) else None
			if not src:
				continue
			for o in outs:
				if not taint.setdefault(o, set()) >= src:
					taint[o] |= src
					changed = True

	def cond(name):
		cols = sorted(taint[name])
		return 'match(%s, "(^| )(%s)( |$)")' % (BLANK_FIELD, '|'.join(regex_escape(c) for c in cols))

	def guarded(name):
		if name in restored:
			# Written as <prefix><name> and given back at search time after the add-on's rule, which reads the compact
			# line under the name first: on a compact event the written value is the one.
			return 'if(isnotnull(%s), \'%s%s\', \'%s\')' % (BLANK_FIELD, reserved_prefix, name, name)
		return 'if(%s, null(), \'%s\')' % (cond(name), name)

	# Columns the map writes under the reserved prefix that a search-time rule can still set: Splunk keeps its own
	# host, source, sourcetype, index and splunk_server over an extraction (a userid line's source column left
	# source as it was), and assigns eventtype and tag itself.
	restored = set(c for c in taint if reserved_prefix and reserved_name(c) and not c.startswith(RESERVED_PREFIXES)
		and c.lower() not in ('host', 'source', 'sourcetype', 'index', 'splunk_server', 'eventtype', 'tag'))

	def guard_expr(value):
		# mvfilter() takes an expression of one field, so tenx_blank inside it is not a valid expression and Splunk
		# drops the calculated field, the add-on's own included, since the map's takes its name (measured: Invalid eval
		# expression, The arguments to the 'mvfilter' function are invalid). Such a call is guarded whole instead:
		# mvfilter() of a field that is not there is null, so the result is the same.
		parts, pos, held = [], 0, []
		for start, inner, end in call_spans(value, 'mvfilter'):
			if start < pos:
				continue
			call = value[start:end]
			names = sorted(expr_fields(value[inner:end - 1]) & set(taint))
			if names and names[0] in restored:
				call = 'if(isnotnull(%s), %s, %s)' % (BLANK_FIELD, rewrite_expr_fields(call,
					lambda n: "'%s%s'" % (reserved_prefix, n) if n == names[0] else None), call)
			elif names:
				call = 'if(%s, null(), %s)' % (' OR '.join(cond(n) for n in names), call)
			parts += [value[pos:start], '"\x00%d\x00"' % len(held)]
			held.append(call)
			pos = end
		text = rewrite_expr_fields(''.join(parts) + value[pos:], lambda n: guarded(n) if n in taint else None)
		for i, call in enumerate(held):
			text = text.replace('"\x00%d\x00"' % i, call)
		return text

	out, own = [], set()
	for key, value in settings.items():
		if not key.startswith('EVAL-'):
			continue
		own.add(key[len('EVAL-'):])
		if not (expr_fields(value) & set(taint)):
			continue
		out.append((key, guard_expr(value)))
	for name in taint:
		if name not in own:
			out.append(('EVAL-%s' % name, guarded(name)))
	return out


def call_spans(expr, function):
	"""(start, start of the arguments, end) of each call to an eval function in an expression, outside string literals
	and quoted names, in order; a call inside another comes after it."""
	masked = re.sub(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'', lambda m: m.group(0)[0] + 'x' * (len(m.group(0)) - 2) + m.group(0)[0],
		expr)
	out = []
	for m in re.finditer(r'(?<![A-Za-z0-9_.:{}])%s\s*\(' % re.escape(function), masked, re.I):
		depth = 0
		for j in range(m.end() - 1, len(masked)):
			depth += {'(': 1, ')': -1}.get(masked[j], 0)
			if depth == 0:
				out.append((m.start(), m.end(), j + 1))
				break
	return out


def rewrite_expr_fields(expr, replace):
	"""An eval expression with each field reference (a word outside string literals that is not a function or keyword,
	or a name in single quotes) given by replace(name), or kept when replace returns None."""
	out, pos = [], 0
	token = re.compile(r'"(?:[^"\\]|\\.)*"|\'([^\']+)\'|' + _EXPR_WORD.pattern)
	for m in token.finditer(expr):
		out.append(expr[pos:m.start()])
		text = m.group(0)
		if text.startswith('"'):
			out.append(text)
		else:
			name = m.group(1) if text.startswith("'") else text
			is_call = expr[m.end():].lstrip().startswith('(') and not text.startswith("'")
			new = None if is_call or name.upper() in _EXPR_KEYWORDS else replace(name)
			out.append(new if new is not None else text)
		pos = m.end()
	out.append(expr[pos:])
	return ''.join(out)


def source_pattern_matches(pattern, source):
	"""Whether a [source::<pattern>] stanza applies to a source: "..." is any text, "*" any text without a
	path separator, "(", "|" and ")" group as in a regular expression, every other character is itself."""
	out, i = [], 0
	while i < len(pattern):
		if pattern.startswith('...', i):
			out.append('.*')
			i += 3
			continue
		c = pattern[i]
		out.append('[^/\\\\]*' if c == '*' else (c if c in '()|' else re.escape(c)))
		i += 1
	try:
		return re.fullmatch(''.join(out), source) is not None
	except re.error:
		return False


try:
	import re._parser as _sre_parse  # Python 3.11 and later
	import re._constants as _sre_c
except ImportError:  # Python 3.9 and 3.10
	import sre_parse as _sre_parse
	import sre_constants as _sre_c

_LANGUAGE_MAX = 256
_REPEATS = tuple(x for x in (getattr(_sre_c, n, None) for n in ('MAX_REPEAT', 'MIN_REPEAT', 'POSSESSIVE_REPEAT')) if x)


def _language(items):
	"""The strings a parsed regex matches when each optional or repeated part takes its fewest
	repetitions, or None when that set is not small and finite (any character, a negated class, ...)."""
	out = ['']
	for op, av in items:
		if op is _sre_c.LITERAL:
			alts = [chr(av)]
		elif op is _sre_c.IN:
			alts = []
			for iop, iav in av:
				if iop is _sre_c.LITERAL:
					alts.append(chr(iav))
				elif iop is _sre_c.RANGE and iav[1] - iav[0] < 16:
					alts.extend(chr(c) for c in range(iav[0], iav[1] + 1))
				else:
					return None
		elif op is _sre_c.BRANCH:
			alts = []
			for branch in av[1]:
				sub = _language(branch)
				if sub is None:
					return None
				alts.extend(sub)
		elif op is _sre_c.SUBPATTERN:
			alts = _language(av[-1])
			if alts is None:
				return None
		elif op in _REPEATS:
			low, _, sub = av
			if low == 0:
				continue
			one = _language(sub)
			if one is None or low > 3:
				return None
			alts = ['']
			for _ in range(low):
				alts = [a + b for a in alts for b in one]
		elif op in (_sre_c.AT, _sre_c.ASSERT, _sre_c.ASSERT_NOT):
			continue
		else:
			return None
		out = [a + b for a in out for b in alts]
		if len(out) > _LANGUAGE_MAX:
			return None
	return sorted(set(out))


def regex_language(pcre):
	"""_language of a PCRE pattern, or None."""
	try:
		return _language(list(_sre_parse.parse(_python_regex(pcre))))
	except (re.error, TypeError, ValueError, OverflowError, RecursionError):
		return None


def regex_pieces(src):
	"""
	The groups and the top-level pieces of a regex source. groups: (start, end, kind, number, name) in the
	order they open, kind 'capture', 'other' (non-capturing) or 'look' (lookaround), number the capture
	number or None. pieces: (start, end) of each piece at depth 0, with its quantifier.
	"""
	groups, stack, pieces = [], [], []
	i, n, number = 0, len(src), 0

	def piece(start, end):
		j = end
		while j < n and src[j] in '*+?{':
			if src[j] == '{':
				k = src.find('}', j)
				if k < 0 or not re.fullmatch(r'\{\d*(?:,\d*)?\}', src[j:k + 1]):
					break
				j = k + 1
			else:
				j += 1
		pieces.append((start, j))
		return j

	while i < n:
		c = src[i]
		if c == '\\':
			end = min(i + 2, n)
			i = end if stack else piece(i, end)
			continue
		if c == '[':
			j = i + 1
			if j < n and src[j] == '^':
				j += 1
			if j < n and src[j] == ']':
				j += 1
			while j < n and src[j] != ']':
				j += 2 if src[j] == '\\' else 1
			end = min(j + 1, n)
			i = end if stack else piece(i, end)
			continue
		if c == '(':
			if src.startswith('(?#', i):
				j = src.find(')', i)
				i = n if j < 0 else j + 1
				continue
			named = re.match(r"\(\?(?:P?<([A-Za-z_]\w*)>|'([A-Za-z_]\w*)')", src[i:])
			flags = re.match(r'\(\?[a-zA-Z-]*\)', src[i:])
			if named:
				number += 1
				kind, num, name = 'capture', number, named.group(1) or named.group(2)
			elif src.startswith(('(?=', '(?!', '(?<=', '(?<!'), i):
				kind, num, name = 'look', None, None
			elif flags:
				if not stack:
					pieces.append((i, i + flags.end()))
				i += flags.end()
				continue
			elif src.startswith('(?', i):
				kind, num, name = 'other', None, None
			else:
				number += 1
				kind, num, name = 'capture', number, None
			stack.append(len(groups))
			groups.append([i, None, kind, num, name])
			i += 1
			continue
		if c == ')' and stack:
			g = groups[stack.pop()]
			g[1] = i + 1
			i = piece(g[0], g[1]) if not stack else i + 1
			continue
		if stack:
			i += 1
		elif c == '|':
			pieces.append((i, i + 1))
			i += 1
		else:
			i = piece(i, i + 1)
	return [tuple(g) for g in groups], pieces


# Items of the text the xml-windows reader writes as fields, and the blocks of the event it reads them in.
XML_ITEM_BLOCKS = {'data': ('EventData',), 'element': ('System', 'RenderingInfo'), 'attribute': ('System',)}
# The names the System block of every Windows event uses (the event schema's System element: its child elements
# and their attributes). The reader writes each as a field, so a copy that reads such a name as another kind of item
# (Data Name='ProcessID', where Execution ProcessID='4' is in every event) would read the wrong item.
XML_SYSTEM_NAMES = {
	'element': frozenset(('Provider', 'EventID', 'Version', 'Level', 'Task', 'Opcode', 'Keywords', 'TimeCreated',
		'EventRecordID', 'Correlation', 'Execution', 'Channel', 'Computer', 'Security')),
	'attribute': frozenset(('Name', 'Guid', 'EventSourceName', 'Qualifiers', 'SystemTime', 'ActivityID', 'RelatedActivityID',
		'ProcessID', 'ThreadID', 'ProcessorID', 'SessionID', 'KernelTime', 'UserTime', 'ProcessorTime', 'UserID')),
}
_ITEM_OPEN = (
	('data', re.compile("<Data\\s+Name=(['\"])([A-Za-z_][\\w.\\-]*)\\1>\\Z")),
	('element', re.compile('<([A-Za-z_][\\w.\\-]*)>\\Z')),
	('attribute', re.compile("<([A-Za-z_][\\w.\\-]*)\\s+([A-Za-z_][\\w.\\-]*)=(['\"])\\Z")),
)
# Values the copy of a rule is checked on (see "Add-on rules that read the event's text").
TEXT_RULE_PROBES = ('x', 'value', 'a b', '-', '0', '4', '0x3c8', '10.0.1.14', '::1', '127.0.0.1', '::ffff:10.1.2.3',
	'host.example.local', 'AR-WIN-DC$', 'C:\\Windows\\System32\\svchost.exe', '"C:\\Program Files\\a b\\x.exe" --c',
	'%%2080', 'a=b;c', '2023-10-13T00:35:42.412381800Z', '{54849625-5478-4994-A5BA-3E3B0328C30D}', 'x &amp; y', 'N/A',
	'12a', 'a12')


def _item_of(before, after):
	"""(kind, field name, element) of the item the text before and after a value encloses (element: the
	element an attribute belongs to, else None), None when it is not one item, and False when the text
	cannot occur in XML (an attribute value not enclosed in a pair of the same quote, as from a class
	like [}{'"] on both sides of a name)."""
	m = _ITEM_UNPAIRED.match(before)
	if m and (m.group(1) != m.group(3) or m.group(1) not in '\'"'):
		return False
	for kind, rx in _ITEM_OPEN:
		m = rx.match(before)
		if not m:
			continue
		if kind == 'data':
			return (kind, m.group(2), None) if after == '</Data>' else None
		if kind == 'element':
			return (kind, m.group(1), None) if after == '</%s>' % m.group(1) else None
		return (kind, m.group(2), m.group(1)) if after == m.group(3) else None
	return None


_ITEM_UNPAIRED = re.compile("<Data\\s*Name=(.)([A-Za-z_][\\w.\\-]*)(.)>\\Z")


def probe_event_text(kind, name, value, block=None, element=None):
	"""Synthetic event text for checking a copy: the item (none when value is None) among other items, as
	_raw, or as the text of the block (System, EventData) a rule's SOURCE_KEY names."""
	system = "<Provider Name='Probe-Provider'/><Level>0</Level><Channel>Security</Channel>"
	data = "<Data Name='ProbeBefore'>before</Data>"
	if value is not None:
		if kind == 'data':
			data += "<Data Name='%s'>%s</Data>" % (name, value)
		elif kind == 'element':
			system += '<%s>%s</%s>' % (name, value, name)
		else:
			system += "<%s %s='%s'/>" % (element or 'ProbeElement', name, value)
	data += "<Data Name='ProbeAfter'>after</Data>"
	if block == 'System':
		return system
	if block == 'EventData':
		return data
	return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>%s</System>"
		"<EventData>%s</EventData></Event>" % (system, data))


def report_outputs(regex, fmt, text):
	"""The fields a search-time REPORT transform writes for one text, as Python reads REGEX (already in
	Python syntax): its named groups when FORMAT is empty, else FORMAT's name::$k and name::"$k" pairs. Outer
	whitespace is dropped, as Splunk drops it from an extracted value. None when REGEX does not match."""
	m = re.search(regex, text)
	if m is None:
		return None
	if not fmt:
		return dict((k, v.strip(TRIM_CHARS)) for k, v in m.groupdict().items() if v is not None)
	out = {}
	for name, _, k in re.findall(r'([^\s:"]+)::("?)\$(\d+)\2', fmt):
		v = m.group(int(k)) if int(k) <= len(m.groups()) else None
		if v is not None:
			out[name] = v.strip(TRIM_CHARS)
	return out


def written_names(transform):
	"""The field names a transform writes: FORMAT's literal names, else the named groups of REGEX."""
	fmt = str(transform.get('FORMAT', '')).strip()
	if fmt:
		return sorted(set(n for n in re.findall(r'([^\s:"]+)::', fmt) if not n.startswith('$')))
	return sorted(set(re.findall(r'\(\?P?<([A-Za-z_]\w*)>', str(transform.get('REGEX', '')))))


TextRule = collections.namedtuple('TextRule', 'stanza cls name source_key regex format rule field kind')


def _source_key(transform):
	return str(transform.get('SOURCE_KEY', '_raw') or '_raw').strip()


def text_rule_copies(props, transforms, rename, source=None, prefix='tenx_fm', seen=None, xml=True, word_values=False):
	"""
	The field-reading copies of an add-on's rules that read the event's text (see "Add-on rules that read
	the event's text"), for the xml-windows reader. A copy is not written for a name the System block of
	every event holds as another kind of item (XML_SYSTEM_NAMES), since the field would then not be only
	the item the rule reads. What is written depends on the add-on alone, so a template added later still
	changes only the lookup file. seen: {field name: {item kind: most items of that name in one template}}
	over the templates (XmlWindowsReader.items); a copy whose name the templates hold as another kind of
	item, or more than once, is written and named in the report's warnings. Returns (copies, report): a list
	of TextRule in the order they are written, and an OrderedDict naming each rule considered and what was
	done with it.
	"""
	seen = seen or {}
	stanzas = [r for r in (rename if isinstance(rename, list) else [rename]) if r in props]
	if source:
		stanzas += [s for s in props if s.startswith('source::') and source_pattern_matches(s[len('source::'):], source)]
	classes = []
	for st in stanzas:
		for key, value in props[st].items():
			if key.startswith('REPORT-'):
				classes.append((key[len('REPORT-'):], st, [x.strip() for x in value.split(',') if x.strip()]))
	class_names = set(c for c, _, _ in classes)

	# A block: a transform that reads _raw with REGEX <X(?:\s+[^>]+)?>(.*?)</X> and FORMAT Y::$1 writes the
	# text of element X as field Y.
	# Only a field another of these transforms reads (SOURCE_KEY) is a block.
	keys = set(_source_key(transforms.get(n, {})) for _, _, names in classes for n in names)
	blocks, block_regex = {}, {}
	for _, _, names in classes:
		for tname in names:
			t = transforms.get(tname, {})
			if _source_key(t) == '_raw' and _block_of(t) and _block_of(t)[1] in keys:
				blocks[_block_of(t)[1]] = _block_of(t)[0]
				block_regex[_block_of(t)[1]] = _python_regex(str(t.get('REGEX', '')).strip())

	report = collections.OrderedDict([('stanzas', stanzas), ('blocks', dict(blocks)), ('copied', []), ('not_copied', []),
		('warnings', [])])
	copies, derived = [], []
	for cls, st, names in sorted(classes, key=lambda c: c[0]):
		for pos, tname in enumerate(names):
			t = transforms.get(tname)
			if t is None:
				continue
			sk = _source_key(t)
			if sk != '_raw' and sk not in blocks:
				continue
			regex, fmt = str(t.get('REGEX', '')).strip(), str(t.get('FORMAT', '')).strip()
			entry = collections.OrderedDict([('class', cls), ('stanza', st), ('transform', tname), ('source_key', sk),
				('writes', written_names(t))])
			reason, items, candidates = _copy_plan(regex, fmt, sk, blocks)
			if not xml:
				# A reader of text, not of XML items: no rule is copied to read one item, each is applied per template.
				reason, items, candidates = 'the %s reader writes no XML items' % WindowsClassicReader.name, (), ()
			if _block_of(t):
				reason, candidates = 'writes the whole text of element %s as %s; the map writes the items the reader reads, ' \
					'not whole elements' % _block_of(t), ()
			hard = reason and reason.startswith(TEXT_RULE_HARD)
			if hard:
				report['not_copied'].append(dict(entry, why=reason))
				continue
			# A later transform of the class that reads a field runs on a mapped event too, before the copy's class.
			later = [n for n in names[pos + 1:] if n in transforms and set(written_names(transforms[n])) & set(entry['writes'])
				and _source_key(transforms[n]) != '_raw' and _source_key(transforms[n]) not in blocks]
			if later:
				report['not_copied'].append(dict(entry, why='a later transform of its class (%s) writes the same field, '
					'so a copy running after the class would come too late' % ', '.join(later)))
				continue
			copy_cls = '%s-%s' % (cls, prefix)
			between = sorted(c for c in class_names if cls < c <= copy_cls)
			if between:
				report['not_copied'].append(dict(entry, why='the class %s of the add-on sorts between %s and the copy\'s '
					'class' % (between[0], cls)))
				continue
			def per_template(why, covered=()):
				# gen applies the rule to each template's text (see "Rules the copies cannot read from one field"),
				# and the copy reads the indexed field that carries the result.
				outputs = ([(out, int(k)) for out, _, k in re.findall(r'([^\s:"]+)::("?)\$(\d+)\2', fmt)] if fmt else
					[(g, g) for g in re.findall(r'\(\?P?<([A-Za-z_]\w*)>', regex)])
				words = frozenset(WORD_GROUP.findall(regex)) if word_values else frozenset()
				rule = DerivedRule(tname, _python_regex(regex), block_regex.get(sk),
					[(out, g, '%s%s%s_%s' % (prefix, TEXT_RULE_DERIVED, sanitize(tname), sanitize(out))) for out, g in outputs],
					tuple(covered), words)
				derived.append(rule)
				for out, g, field in rule.outputs:
					name = '%s%s%s_%s' % (prefix, TEXT_RULE_INFIX, sanitize(tname), sanitize(out))
					# A word group's field carries the whole value; the copy keeps its first word, as the rule does on raw text.
					copies.append(TextRule(st, copy_cls, name, field, '\\A(\\S+)' if g in words else '\\A([\\s\\S]*)\\z',
						'%s::$1' % out, tname, field, 'template'))
					report['copied'].append(collections.OrderedDict([('class', cls), ('stanza', st), ('transform', tname),
						('reads', 'the rule on each template\'s text, indexed as %s' % field), ('copy', name),
						('writes', [out]), ('why_per_template', why)]))

			if reason:
				per_template(reason)
				continue
			refused_items, read_items = [], []
			for item, copy_regex, copy_fmt, failed in candidates:
				kind, field = item[0], item[1]
				clash = sorted(k for k, names in XML_SYSTEM_NAMES.items() if k != kind and field in names)
				if not failed and clash:
					failed = 'every event\'s System block holds %s as an %s, so the field is not only the item the rule reads' % (
						field, ' and '.join(clash))
				if failed:
					report['not_copied'].append(dict(entry, reads='%s %s' % (kind, field), why=failed))
					refused_items.append('%s %s' % (kind, field))
					continue
				name = '%s%s%s' % (prefix, TEXT_RULE_INFIX, sanitize(tname))
				if len(items) > 1:
					name += '_' + sanitize(field)
				copies.append(TextRule(st, copy_cls, name, field, copy_regex, copy_fmt, tname, field, kind))
				read_items.append(field)
				other = dict((k, c) for k, c in seen.get(field, {}).items() if k != kind or c > 1)
				if other:
					report['warnings'].append('%s reads %s %s, which templates also hold as %s' % (name, kind, field,
						', '.join('%s (up to %d in one template)' % kc for kc in sorted(other.items()))))
				report['copied'].append(collections.OrderedDict([('class', cls), ('stanza', st), ('transform', tname),
					('reads', '%s %s' % (kind, field)), ('copy', name), ('writes', entry['writes'])]))
			if refused_items:
				# The items no copy reads (Data ProcessID) are covered per template, after the copies.
				per_template('no copy reads %s' % ', '.join(refused_items), read_items)
	# A rule that sorts earlier and writes the same field on some raw events, with no copy that reads one field: on
	# those events the raw event has its value, and a later copy gives the field another one.
	by_field = collections.defaultdict(list)
	for c in copies:
		for out in written_names(transforms[c.rule]):
			by_field[out].append(c)
	for out, cs in by_field.items():
		plain = [c for c in cs if c.kind != 'template']
		earlier = sorted(set(c.rule for c in cs if c.kind == 'template' and plain and c.cls < plain[0].cls))
		if plain and earlier:
			report['warnings'].append('%s: on the events where %s gives %s on the raw event and the per-template copy '
				'cannot (its condition reads a compact value), %s gives the %s %s instead' % (out, ', '.join(earlier), out,
					plain[0].name, plain[0].kind, plain[0].field))
	return copies, report, derived


# Reasons a rule gets no copy at all: the rest (not one item, not fixed text around the value) get a copy that reads
# the field gen writes for each template the rule matches.
TEXT_RULE_HARD = ('writes the block', 'writes the whole text', 'no REGEX', 'takes field names', 'REGEX not read',
	'writes no field')
TEXT_RULE_DERIVED = '_fr_'
# covered: the fields the rule's own copies read; a template whose text the rule captures from one of them needs no
# field of its own.
DerivedRule = collections.namedtuple('DerivedRule', 'rule regex block outputs covered words', defaults=((), frozenset()))
# A named group that reads one word, (?<name>\S+): on the raw event it stops at the first space or tab of the value.
WORD_GROUP = re.compile(r'\(\?P?<([A-Za-z_]\w*)>\\S\+\)')


def _block_of(transform):
	"""(element, field) when a transform writes the text of an XML element as a field (REGEX
	<X(?:\\s+[^>]+)?>(.*?)</X>, FORMAT Y::$1), else None."""
	fm = re.match(r'^([A-Za-z_]\w*)::\$1$', str(transform.get('FORMAT', '')).strip())
	rm = re.match(r'^(?:\(\?[a-z]+\))?<([A-Za-z_]\w*)\(\?:\\s\+\[\^>\]\+\)\?>\(\.\*\?\)<\\?/([A-Za-z_]\w*)>$',
		str(transform.get('REGEX', '')).strip())
	if fm and rm and rm.group(1) == rm.group(2):
		return rm.group(1), fm.group(1)
	return None


def _copy_plan(regex, fmt, sk, blocks):
	"""(why one rule gets no copy, or None; the items it reads; per item (item, copy REGEX, copy FORMAT, why
	that copy failed its check or None))."""
	if sk == '_raw' and re.match(r'^([A-Za-z_]\w*)::\$1$', fmt) and fmt.split('::')[0] in blocks:
		return 'writes the block %s; the map writes the fields inside it' % fmt.split('::')[0], (), ()
	if not regex:
		return 'no REGEX', (), ()
	if re.search(r'\$\d+::', fmt) or (fmt and '::' not in fmt):
		return 'takes field names from the text; the map writes those fields itself', (), ()
	try:
		py_rule = _python_regex(regex)
		re.compile(py_rule)
		groups, pieces = regex_pieces(regex)
	except re.error as e:
		return 'REGEX not read here: %s' % e, (), ()
	if fmt:
		wanted = set(int(k) for k in re.findall(r'::"?\$(\d+)', fmt))
		outs = [g for g in groups if g[2] == 'capture' and g[3] in wanted]
	else:
		outs = [g for g in groups if g[2] == 'capture' and g[4]]
	if not outs:
		return 'writes no field', (), ()
	if any(regex[a:b] == '|' for a, b in pieces):
		return 'an alternation at the top of the pattern', (), ()
	lo, hi = min(g[0] for g in outs), max(g[1] for g in outs)
	around = [p for p in pieces if p[0] <= lo and hi <= p[1]]
	if not around:
		return 'the fields it writes are not one piece of the pattern', (), ()
	k = pieces.index(around[0])
	v0, v1 = around[0]
	while k > 0 and regex.startswith(('(?=', '(?!'), pieces[k - 1][0]):
		k -= 1
		v0 = pieces[k][0]
	fl = re.match(r'^\(\?[a-zA-Z]+\)', regex)
	flags = fl.group(0) if fl else ''
	before, value, after = regex[len(flags):v0], regex[v0:v1], regex[v1:]
	if not _fixed_edge(before, last=True) or not _fixed_edge(after, last=False):
		return 'the value is not enclosed by fixed text on both sides', (), ()
	opens, closes = regex_language(flags + before), regex_language(flags + after)
	if not opens or not closes:
		return 'the text around the value is not a fixed item', (), ()
	items = set()
	for o in opens:
		for c in closes:
			item = _item_of(o, c)
			if item is None:
				return 'the text around the value is not one item (%r ... %r)' % (o[:70], c[:70]), (), ()
			if item:
				items.add(item)
	if not items:
		return 'the text around the value is not one item', (), ()
	block = blocks.get(sk)
	items = sorted(it for it in items if block is None or block in XML_ITEM_BLOCKS[it[0]])
	if not items:
		return 'reads an item of %s that the map does not write' % block, (), ()
	shift = sum(1 for g in groups if g[2] == 'capture' and g[0] < v0)
	copy_fmt = re.sub(r'\$(\d+)', lambda m: '$%d' % (int(m.group(1)) - shift), fmt) if fmt else ''
	copy_regex = flags + '\\A' + value + '\\z'
	py_copy = _python_regex(copy_regex).replace('\\z', '\\Z')
	return None, items, [(item, copy_regex, copy_fmt, _check_copy(py_rule, fmt, py_copy, copy_fmt, item, block))
		for item in items]


def _fixed_edge(src, last):
	"""Whether the piece of src next to the value (its last piece when last, else its first) is fixed text
	that closes or opens an item: one character, ">", "<" or a quote, or a class of quotes, matched exactly
	once. An optional or repeated piece there (\\D* before </Data>) could take characters of the value."""
	_, pieces = regex_pieces(src)
	if not pieces:
		return False
	a, b = pieces[-1] if last else pieces[0]
	text = src[a:b]
	if text in ('>', '\\>', '<', '\\<', "'", '"'):
		return True
	m = re.match(r'^\[([^\]]*)\]$', text)
	return bool(m) and set(m.group(1).replace('\\', '')) <= set('\'"{}')


def _check_copy(py_rule, fmt, py_copy, copy_fmt, item, block):
	"""Why the copy of a rule does not give what the rule gives on synthetic events, or None."""
	kind, field, element = item
	if report_outputs(py_rule, fmt, probe_event_text(kind, field, None, block, element)):
		return 'the rule gives a field on the text without the item'
	for v in TEXT_RULE_PROBES:
		if kind == 'attribute' and ("'" in v or '"' in v):
			continue
		want = report_outputs(py_rule, fmt, probe_event_text(kind, field, v, block, element)) or {}
		got = report_outputs(py_copy, copy_fmt, v.strip(TRIM_CHARS)) or {}
		if want != got:
			return 'on the value %r the rule gives %r, a copy reading %s %r' % (v, want, field, got)
	return None


def text_rule_props(copies):
	"""props.conf lines of the copies: stanza -> ['REPORT-<class> = <names>', ...], classes in order."""
	out = collections.OrderedDict()
	for c in copies:
		classes = out.setdefault(c.stanza, collections.OrderedDict())
		classes.setdefault(c.cls, []).append(c.name)
	return collections.OrderedDict((st, ['REPORT-%s = %s' % (cls, ', '.join(names)) for cls, names in classes.items()])
		for st, classes in out.items())


# Rules the copies cannot read from one field
#
# A rule whose text is a condition on a second item ((?ms)<EventID>(5156|5157)</EventID>.*<Data Name='SourceAddress'>
# (?<src_ip>[^<]+)</Data>) or free text cannot be copied as a rule that reads one field: a search-time rule reads one
# field and cannot join two. For these, gen applies the rule itself to each template's text (to the block the rule
# reads, cut by the add-on's own block rule), and when it matches, the template's row writes one more indexed field
# per field the rule writes, <prefix>_fr_<rule>_<field>, holding the text the rule captured (template text and
# compact values). The copy, in the class right after the rule's, reads that field. The result must not depend on the
# values: gen applies the rule again with every value replaced by each of DERIVE_PROBES (the same value everywhere,
# and a different one per value), and writes the field only when the rule matches every time and captures the same
# text with the values put in. Otherwise, as when the rule does not match the template, the template's row writes
# nothing for it, and the field is missing on its events, as it was without --addon.

DERIVE_PROBES = ('x', '0', '4', '5156', '5157', '4798', '10.0.1.14', '::1', '127.0.0.1', 'a b', '-', '%%14592',
	'C:\\Windows\\System32\\svchost.exe', 'A user account was changed.', 'Changed Attributes:\n x')
# The probes for the windows-classic reader leave out the one with a line feed: the lookup rule writes no field for an
# event whose compact value holds a line feed (LOOKUP_VALUE_GROUP), so a rule's result on such a value never reaches an
# index. In classic text every rule that reads a section ("Subject:", then "\tAccount Name:\t\t<value>" on the next
# lines) stops its value at the line's end, which only that probe moved.
DERIVE_PROBES_NO_LINE_FEED = tuple(v for v in DERIVE_PROBES if '\n' not in v)


def derive_pairs(rule, text, probes=DERIVE_PROBES):
	"""The (indexed field, marked text) pairs a DerivedRule gives for a template's marked text, and whether a match
	was dropped because its result depends on the values."""
	src = text
	if rule.block is not None:
		m = re.search(rule.block, text)
		if m is None:
			return [], False
		src = m.group(1)
	m = re.search(rule.regex, src)
	if m is None:
		return [], False
	got = [(field, m.group(g)) for _, g, field in rule.outputs if m.group(g) is not None]
	for v in probes:
		for each in (False, True):
			def put(mm, v=v, each=each):
				return v + mm.group(1) if each else v
			mv = re.search(rule.regex, MARK_RE.sub(put, src))
			if mv is None:
				return [], True
			for (_, g, field), (_, marked) in zip([o for o in rule.outputs if m.group(o[1]) is not None], got):
				want = MARK_RE.sub(put, marked)
				if mv.group(g) == want:
					continue
				# A word group whose text is exactly one value: the field carries the whole value and the copy cuts it
				# at its first space or tab (see WORD_GROUP), so a probe with a space reads the same as raw text.
				if g in rule.words and MARK_RE.fullmatch(marked) and want.split() and mv.group(g) == want.split()[0]:
					continue
				return [], True
	return got, False


# ---------------------------------------------------------------------------------------------
# The fields the data models need (--fields cim)
#
# Every indexed field takes index space (the classic Windows Message field made a mapped index 10 times its raw
# index). With --fields cim the map writes only the fields that the CIM data models, and the add-on's event types,
# read on the event, directly or through the add-on's own search-time rules: starting from every field name the CIM
# models use (their fields, calculations and constraints) and every field the add-on's event types search, the
# inputs of each rule that writes a needed field are needed too (FIELDALIAS, EVAL, LOOKUP, a REPORT or EXTRACT that
# reads a field), until nothing is added. A field whose name the map takes from a value is kept. Every other field is
# left out: a search that reads it directly finds it through txf, not on the indexed event.

_SEARCH_FIELD = re.compile(r'(?<![A-Za-z0-9_.:{}])([A-Za-z_][A-Za-z0-9_.:{}-]*)\s*(?:!=|<=|>=|=|<|>|\s+IN\s*\()', re.I)
_EXPR_WORD = re.compile(r'[A-Za-z_][A-Za-z0-9_.:{}]*')
_EXPR_KEYWORDS = frozenset(('AND', 'OR', 'NOT', 'IN', 'LIKE', 'TRUE', 'FALSE', 'NULL', 'AS', 'BY', 'XOR'))


def expr_fields(expr):
	"""Field names an eval expression reads: words outside string literals that are not functions or keywords, and
	names in single quotes."""
	text = re.sub(r'"(?:[^"\\]|\\.)*"', ' ', expr)
	names = set(re.findall(r"'([^']+)'", text))
	text = re.sub(r"'[^']*'", ' ', text)
	for m in _EXPR_WORD.finditer(text):
		if text[m.end():].lstrip().startswith('(') or m.group(0).upper() in _EXPR_KEYWORDS:
			continue
		names.add(m.group(0))
	return names


def search_fields(search):
	"""Field names a search string compares (name=value, name!=value, name IN (...))."""
	return set(m.group(1) for m in _SEARCH_FIELD.finditer(search or ''))


_SEARCH_TAG = re.compile(r'(?<![A-Za-z0-9_])tag\s*=\s*"?([A-Za-z0-9_:-]+)"?')
_SEARCH_TOKEN = re.compile(r'\(|\)|"(?:[^"\\]|\\.)*"|`[^`]*`|[^\s()]+')


def tags_can_match(search, tags):
	"""Whether an event carrying every tag in tags can match the search part of a dataset's constraint: tag=x is
	true when x is among tags, index=_x (one of Splunk's own indexes) is false, any other term is true, NOT is true,
	terms side by side (or AND) must all be true and OR needs one side. Endpoint.Processes (tag=process tag=report) can match the Windows add-on's tags;
	Application_State's (tag=listening tag=port) OR (tag=process tag=report) can match tags holding either pair."""
	tokens = _SEARCH_TOKEN.findall(search or '')
	pos = [0]

	def peek():
		return tokens[pos[0]] if pos[0] < len(tokens) else None

	def take():
		pos[0] += 1
		return tokens[pos[0] - 1]

	def unary():
		t = take()
		if t.upper() == 'NOT':
			if peek() is not None:
				unary()
			return True
		if t == '(':
			v = disjunction()
			if peek() == ')':
				take()
			return v
		m = _SEARCH_TAG.fullmatch(t)
		if m:
			return m.group(1) in tags
		# Splunk's own indexes (Splunk_Audit's index=_internal) hold no event of an add-on.
		return re.fullmatch(r'index\s*=\s*"?_\S*', t) is None

	def conjunction():
		v = True
		while peek() is not None and peek() != ')' and peek().upper() != 'OR':
			if peek().upper() == 'AND':
				take()
				continue
			v = unary() and v
		return v

	def disjunction():
		v = conjunction()
		while peek() is not None and peek().upper() == 'OR':
			take()
			v = conjunction() or v
		return v

	return disjunction()


def _dataset_search(obj):
	"""A dataset's search: its constraints, and for a BaseSearch dataset (Endpoint's) its base search up to the first pipe."""
	parts = ['(%s)' % c['search'] for c in obj.get('constraints', []) if c.get('search')]
	if obj.get('baseSearch'):
		parts.append('(%s)' % obj['baseSearch'].split('|')[0])
	return ' '.join(parts)


def cim_fields(cim_dir, tags=None):
	"""Every field name the CIM data models of cim_dir use: dataset fields, calculation outputs and inputs, and the
	fields their constraints and base searches read. With tags, only the models with a root dataset an event carrying
	those tags can match (tags_can_match), so a model the add-on's events never reach adds no name."""
	names = set()
	for path in sorted(glob.glob(os.path.join(cim_dir, 'default', 'data', 'models', '*.json'))):
		with open(path, encoding='utf-8') as f:
			model = json.load(f)
		roots = [o for o in model.get('objects', []) if o.get('parentName') in ('BaseEvent', 'BaseSearch')]
		if tags is not None:
			searches = [_dataset_search(o) for o in roots]
			if not any(_SEARCH_TAG.search(q) and tags_can_match(q, tags) for q in searches):
				continue
		for obj in model.get('objects', []):
			for fld in obj.get('fields', []):
				names.add(fld.get('fieldName'))
			for calc in obj.get('calculations', []):
				for fld in calc.get('outputFields', []):
					names.add(fld.get('fieldName'))
				names |= expr_fields(calc.get('expression') or '')
				names |= set(calc.get('inputField') and [calc['inputField']] or [])
			for c in obj.get('constraints', []):
				names |= search_fields(c.get('search'))
			if obj.get('baseSearch'):
				parts = obj['baseSearch'].split('|')
				names |= search_fields(parts[0])
				for part in parts[1:]:
					if re.match(r'\s*eval\s', part):
						names |= expr_fields(re.sub(r'^\s*eval\s', '', part))
	names.discard(None)
	return names


def addon_rules(props, transforms, stanzas):
	"""[(written names, read names)] of the add-on's search-time rules in the given props stanzas."""
	rules = []
	for st in stanzas:
		for key, value in props.get(st, {}).items():
			kind = key.split('-', 1)[0].upper()
			if kind == 'FIELDALIAS':
				for a, b in re.findall(r'("[^"]+"|\S+)\s+AS(?:NEW)?\s+("[^"]+"|\S+)', value, re.I):
					rules.append(({b.strip('"')}, {a.strip('"')}))
			elif kind == 'EVAL':
				rules.append(({key.split('-', 1)[1]}, expr_fields(value)))
			elif kind == 'LOOKUP':
				m = re.match(r'\s*\S+\s+(.*?)(?:\s+OUTPUT(?:NEW)?\s+(.*))?$', value, re.I | re.S)
				if not m:
					continue
				ins = set(x.strip().split()[-1].strip('"') for x in m.group(1).split(',') if x.strip())
				outs = set(x.strip().split()[-1].strip('"') for x in (m.group(2) or '').split(',') if x.strip())
				rules.append((outs or {'*'}, ins))
			elif kind in ('REPORT', 'EXTRACT'):
				names = [x.strip() for x in value.split(',')] if kind == 'REPORT' else []
				for t in names:
					tr = transforms.get(t, {})
					sk = str(tr.get('SOURCE_KEY', '_raw')).strip()
					if sk == '_raw':
						continue
					fmt, regex = str(tr.get('FORMAT', '')), str(tr.get('REGEX', ''))
					outs = set(re.findall(r'([A-Za-z_][A-Za-z0-9_]*)::', fmt)) | set(re.findall(r'\(\?P?<([A-Za-z_]\w*)>', regex))
					rules.append((outs or {'*'}, {sk}))
				if kind == 'EXTRACT':
					m = re.search(r'\s+in\s+([A-Za-z_][A-Za-z0-9_]*)\s*$', value)
					if m:
						rules.append((set(re.findall(r'\(\?P?<([A-Za-z_]\w*)>', value)), {m.group(1)}))
	return rules


def needed_fields(addon_dir, cim_dir, stanzas, copies=()):
	"""The fields the CIM models and the add-on's event types read, closed over the add-on's rules (see above).
	copies: the TextRule copies gen writes of the add-on's rules that read the event's text; such a copy reads an
	indexed field (Data CommandLine for Process_Command_Line), which is then needed when the rule's field is."""
	props, transforms = read_addon(addon_dir)
	eventtypes = collections.OrderedDict()
	for sub in ('default', 'local'):
		eventtypes.update(read_splunk_conf(os.path.join(addon_dir, sub, 'eventtypes.conf')))
	tags = set()
	for sub in ('default', 'local'):
		for settings in read_splunk_conf(os.path.join(addon_dir, sub, 'tags.conf')).values():
			tags |= set(k for k, v in settings.items() if str(v).strip().lower() == 'enabled')
	needed = cim_fields(cim_dir, tags)
	for settings in eventtypes.values():
		needed |= search_fields(settings.get('search'))
	rules = addon_rules(props, transforms, stanzas)
	rules += [(set(written_names(transforms.get(c.rule, {}))), {c.field}) for c in copies]
	while True:
		before = len(needed)
		for outs, ins in rules:
			if '*' in outs or outs & needed:
				needed |= ins
		if len(needed) == before:
			return needed


class NeededFieldsReader(object):
	"""A reader that keeps only the fields of needed_fields; a name that holds a compact value is kept."""

	def __init__(self, reader, needed):
		self.reader, self.needed = reader, frozenset(needed)

	def __getattr__(self, name):
		return getattr(self.reader, name)

	def pairs(self, text):
		return [(n, v) for n, v in self.reader.pairs(text) if n in self.needed or MARK_RE.search(n)]


class LeaveOutReader(object):
	"""A reader without the fields --leave-out names: the map does not write them (each indexed field costs index space,
	and a field such as classic Windows Message, which an indexed field cannot hold with its line breaks, may not be
	worth it)."""

	def __init__(self, reader, names):
		self.reader, self.names = reader, frozenset(names)

	def __getattr__(self, name):
		return getattr(self.reader, name)

	def pairs(self, text):
		return [(n, v) for n, v in self.reader.pairs(text) if n not in self.names]


class TextRuleReader(object):
	"""A reader with the pairs of derive_pairs added after its own, for the rules of "Rules the copies cannot read
	from one field". Counts, per rule, the texts it wrote fields for and the texts it left out."""

	def __init__(self, reader, rules, probes=DERIVE_PROBES):
		self.reader, self.rules, self.probes = reader, list(rules), probes
		self.written, self.dependent = collections.Counter(), collections.Counter()

	def __getattr__(self, name):
		return getattr(self.reader, name)

	def pairs(self, text):
		out = list(self.reader.pairs(text))
		have = set(name for name, _ in out)
		for rule in self.rules:
			got, dependent = derive_pairs(rule, text, self.probes)
			# A field the map writes from the same text already (UserData's SubjectUserName as Caller_User_Name), or
			# text one of the rule's own copies reads from its field.
			outs = dict((field, out_name) for out_name, _, field in rule.outputs)
			got = [(f, v) for f, v in got if outs[f] not in have and not any(n in rule.covered and val.strip(TRIM_CHARS) ==
				v.strip(TRIM_CHARS) for n, val in out)]
			if got:
				self.written[rule.rule] += 1
				out.extend(got)
			elif dependent:
				self.dependent[rule.rule] += 1
		return out


def template_items(templates, reader):
	"""{field name: {item kind: most items of that name in one template}} over the templates, for readers
	that say which item a field comes from (XmlWindowsReader.items); {} for the others."""
	seen = {}
	if not hasattr(reader, 'items'):
		return seen
	for t in templates.values():
		try:
			text, _ = marked_text(t)
		except ValueError:
			continue
		for (name, kind), count in reader.items(text).items():
			kinds = seen.setdefault(name, {})
			kinds[kind] = max(kinds.get(kind, 0), count)
	return seen


def addon_text_rules(addon_dir, target, templates):
	"""(copies, report, derived rules) for gen --addon: the copies of the add-on's rules that read the event's text
	(the xml-windows reader), or, for another reader, the report of those rules with none copied."""
	props, transforms = read_addon(addon_dir)
	reader = READERS[target['reader']]()
	copies, report, derived = text_rule_copies(props, transforms, target['rename'], target.get('source'),
		target['transform_prefix'], template_items(templates, reader), xml=target['reader'] == XmlWindowsReader.name,
		word_values=target['reader'] == WindowsClassicReader.name)
	if target['reader'] not in (XmlWindowsReader.name, WindowsClassicReader.name):
		for c in report['copied']:
			report['not_copied'].append(dict(c, why='the %s reader has no copies of rules that read the text'
				% target['reader']))
		copies, report['copied'], derived = [], [], []
	report['addon'] = os.path.abspath(addon_dir)
	report['source'] = target.get('source')
	return copies, report, derived


def text_rule_transforms(copies):
	"""transforms.conf text of the copies."""
	parts = []
	for c in copies:
		parts.append('# Search-time: [%s] of the add-on reads the %s %s in the event\'s text; this reads the field.\n'
			'[%s]\nSOURCE_KEY = %s\nREGEX = %s\n%s' % (c.rule, c.kind, c.field, c.name, c.source_key, c.regex,
			('FORMAT = %s\n' % c.format) if c.format else ''))
	return '\n'.join(parts)


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
	# One original sourcetype (a string) or several (a list, or names separated by commas on the command line).
	names = target['rename'] if isinstance(target['rename'], list) else str(target['rename']).split(',')
	names = [n.strip() for n in names if n.strip()]
	if not names or len(set(names)) != len(names):
		raise ValueError('"rename" needs one or more different sourcetype names')
	for n in names:
		if not RENAME_NAME.match(n):
			raise ValueError('"rename": %r is not a sourcetype name the map writes (letters, digits, _ - : . only)' % n)
	target['rename'] = names[0] if len(names) == 1 else names
	if len(names) > 1:
		target.setdefault('rename_field', RENAME_FIELD)
	if target.get('rename_field') is not None and not EVAL_NAME.match(target['rename_field']):
		raise ValueError('"rename_field": %r is not a field name' % target['rename_field'])
	if target.get('reserved_names') not in (None, 'skip', 'prefix', 'restore'):
		raise ValueError('"reserved_names": skip, prefix or restore')
	if isinstance(target.get('time_format'), str):
		target['time_format'] = [target['time_format']]

	target.setdefault('transform_prefix', sanitize(target['sourcetype']))
	target.setdefault('transforms_class', target['transform_prefix'])
	target.setdefault('indexed_value_false', [])
	target.setdefault('description', 'Compact events renamed to %s' % ', '.join(names))
	target.setdefault('app_name', 'tenx_fieldmap_' + sanitize(target['sourcetype']))
	return target


# A sourcetype name the rename rule writes: no character its regex or FORMAT would read as syntax.
RENAME_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_:.\-]*\Z')


def renames(target):
	"""The original sourcetypes of the target, as a list."""
	return target['rename'] if isinstance(target['rename'], list) else [target['rename']]


def several(target):
	"""True when each event is stored under the original sourcetype its rename_field names, by an index-time rule,
	instead of a rename line: always for several original sourcetypes, and for one when the target names the field."""
	return len(renames(target)) > 1 or bool(target.get('rename_field'))


def rename_stanza(target):
	return '%s_rename' % target['transform_prefix']


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


def map_prefix(target):
	return target['transform_prefix'] if target else 'tenx_fm'


def restore_stanza(target, name):
	return '%s_%s%s' % (map_prefix(target), RESTORE_TRANSFORM, sanitize(name))


def hash_stanza(target):
	return '%s_%s' % (map_prefix(target), HASH_TRANSFORM)


def props_text(target, field_map, settings, search_hash=True, sourcetype_field=SOURCETYPE_FIELD, text_rules=()):
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
	if several(target):
		lines[1] = lines[1].replace('Search-time: renamed to the add-on\'s sourcetype.',
			'Then each event\'s sourcetype is set to the add-on\'s.')
	if field_map.forms:
		names.append(eval_stanza(target))
	if several(target):
		names.append(rename_stanza(target))
	if first:
		lines.append('# %s first, then the fields and the event time from the template\'s row.' % ', '.join(first))
	if several(target):
		lines.append('# Last: the event\'s sourcetype from its %s (see transforms.conf [%s]).' % (target['rename_field'],
			rename_stanza(target)))
	lines.append('TRANSFORMS-%s = %s' % (target['transforms_class'], ', '.join(names)))
	if not several(target):
		lines.append('rename = %s' % target['rename'])
	elif search_hash:
		# An event whose rename field names none of the targets keeps this sourcetype (FortiGate: a line the add-on
		# does not type stays fgt_log) and runs this stanza's search-time rules.
		lines += ['# Search-time, for `tx`: the hash and values of an event that keeps this sourcetype because its',
			'# %s names none of the sourcetypes below.' % target['rename_field'],
			'REPORT-%s = %s' % (hash_stanza(target), hash_stanza(target))]
	restored = restored_names(field_map)
	by_stanza = text_rule_props(text_rules)
	note = ('# Search-time: the add-on\'s rules that read the event\'s text, as copies that read the field the map\n'
		'# indexes for that text, each in a class that sorts right after the rule\'s own class (see "Add-on rules\n'
		'# that read the event\'s text" in tenx_field_map.py). On an uncompacted event the rule has already\n'
		'# written the field when its copy runs, and the copy adds nothing.')
	for i, rename in enumerate(renames(target)):
		in_rename = False
		if search_hash:
			if i == 0:
				lines += ['',
					'# Search-time, for `tx`: the hash and values of these events once renamed. A renamed event runs only',
					'# the search-time rules of the target, so this sits in the target\'s stanza; text that does not start',
					'# with "~" (every uncompacted %s event) gets nothing from it.' % rename]
			else:
				lines += ['', '# As above, for %s.' % rename]
			lines += ['[%s]' % rename, 'REPORT-%s = %s' % (hash_stanza(target), hash_stanza(target))]
			in_rename = True
		if restored:
			if not in_rename:
				lines += ['', '[%s]' % rename]
				in_rename = True
			lines += ['# Search-time: each name Splunk does not keep for an indexed field, given back from %s<name>.'
				% field_map.reserved_prefix,
				'REPORT-%s_restore = %s' % (map_prefix(target), ', '.join(restore_stanza(target, n) for n in restored))]
		if rename in by_stanza:
			if not in_rename:
				lines += ['', '[%s]' % rename]
			lines += [note] + by_stanza.pop(rename)
			note = '# Search-time: as above, for the rules of this stanza of the add-on.'
	for stanza, entries in by_stanza.items():
		lines += ['', '[%s]' % stanza, note] + entries
	for stanza, settings in (target.get('blank_evals') or {}).items():
		lines += ['', '# Search-time: what the add-on\'s DELIMS rule reads from a compact line where the map wrote no field (the',
			'# columns %s names) is null, as on the raw event: the add-on\'s calculated fields that read such a field, again' % BLANK_FIELD,
			'# with each reference guarded, and every other such field nulled. On any other event %s is null and' % BLANK_FIELD,
			'# nothing changes.', '[%s]' % stanza]
		lines += ['%s = %s' % kv for kv in settings]
	return '\n'.join(lines) + '\n'


def transforms_text(field_map, search_hash=True, target=None, sourcetype_field=SOURCETYPE_FIELD, text_rules=()):
	if field_map.rules == RULES_LOOKUP:
		stanzas = ['# The template rows, read by the rule below at index time (lookups/%s).\n[%s]\nfilename = %s\n'
			'case_sensitive_match = true\n' % (lookup_file_name(target), lookup_stanza(target), lookup_file_name(target)),
			'# Every compact event: its template\'s row gives the fields, written to _meta. The same for every\n'
			'# template, so adding one changes only the lookup file.\n[%s]\nINGEST_EVAL = %s\n' % (
				lookup_eval_stanza(target), lookup_eval_text(lookup_stanza(target), field_map.time_rule, field_map.trim_values))]
	else:
		stanzas = ['[%s]\nREGEX = %s\nFORMAT = %s\nWRITE_META = true\n' % (t.stanza, t.regex, t.format)
			for t in field_map.transforms]
	if sourcetype_field and target:
		stanzas.insert(0, '# Every event of %s, for tenx-events.\n[%s]\nREGEX = .\nFORMAT = %s::"%s"\nWRITE_META = true\n' % (
			target['sourcetype'], sourcetype_stanza(target), sourcetype_field, target['sourcetype']))
	if field_map.forms and target:
		stanzas.append('# Values FORMAT cannot write (a line break, a double quote, $<digit>) and timestamps as written,\n'
			'# built from the tenx_fmf_* and tenx_fmv_* fields the transforms above write, which it then removes.\n'
			'# Last in the TRANSFORMS- list%s.\n[%s]\nINGEST_EVAL = %s\n' % (
				' but the sourcetype rule' if several(target) else '', eval_stanza(target), ingest_eval_text(field_map)))
	if target and several(target):
		stanzas.append(rename_transform_text(target))
	header = ('# Generated by tenx_field_map.py from the app\'s template records: one index-time transform per '
		'template.\n\n') if field_map.rules != RULES_LOOKUP else (
		'# Generated by tenx_field_map.py: one index-time rule for every template of the sourcetype.\n\n')
	text = header + '\n'.join(stanzas)
	if search_hash:
		text += ('\n# Search-time: tenx-hash-vars-extraction (tenx-for-splunk) with the leading "~" required.\n'
			'[%s]\nREGEX = %s\n' % (hash_stanza(target), HASH_REGEX))
	for name in restored_names(field_map):
		text += ('\n# Search-time: %s, written at index time as %s%s.\n[%s]\nSOURCE_KEY = %s%s\nREGEX = %s\n'
			'FORMAT = %s::$1\n' % (name, field_map.reserved_prefix, name, restore_stanza(target, name), field_map.reserved_prefix,
				name, RESTORE_REGEX, name))
	if text_rules:
		text += '\n' + text_rule_transforms(text_rules)
	return text


def rename_transform_text(target):
	"""The index-time rule of a map with several original sourcetypes (see "Several original sourcetypes")."""
	return ('# Every event of %s whose %s names one of the add-on\'s sourcetypes is stored under that sourcetype,\n'
		'# so the add-on\'s search-time rules run on it. Last in the TRANSFORMS- list. Any other event keeps %s.\n'
		'[%s]\nSOURCE_KEY = field:%s\nREGEX = ^(%s)$\nDEST_KEY = MetaData:Sourcetype\nFORMAT = sourcetype::$1\n' % (
			target['sourcetype'], target['rename_field'], target['sourcetype'], rename_stanza(target),
			target['rename_field'], '|'.join(regex_escape(n) for n in renames(target))))


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
		lookup_bytes=None, text_rules=()):
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
		(os.path.join('default', 'transforms.conf'), transforms_text(field_map, search_hash, target, sourcetype_field,
			text_rules)),
		(os.path.join('default', 'props.conf'), props_text(target, field_map, settings, search_hash, sourcetype_field,
			text_rules)),
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

	# Lines end at a line feed only: a value can hold the carriage return of a CR LF line end.
	with open(encoded_path, encoding='utf-8', newline='') as f:
		compact_lines = f.read().split('\n')

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
		# raw_events reads the raw file without carriage returns; the fields are read from the expansion,
		# which keeps those of the values.
		if remaining[expanded.replace('\r', '')] <= 0:
			differs.append((key, expanded[:120]))
			continue
		remaining[expanded.replace('\r', '')] -= 1
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
			written_pairs = apply_lookup_row(transform, line, field_map.trim_values)
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
#   the probes every --poll seconds until --timeout (by default the instance's lookup refresh period plus
#   three --poll). Nothing is restarted or reloaded: the instance
#   rereads the lookup file on its own (limits.conf ingest_lookup_refresh_period_secs, default 60 s;
#   activate reads the instance's value over REST). A probe that is indexed without its fields before
#   then is expected (the instance still holds the earlier file); one indexed later than that period plus
#   one --poll after activate started means the row does not work, and that template stays pending and is
#   not probed again in this run. gen --splunkd runs activate right after writing the app, for an app
#   written in place on that instance.
# * check proves the converse for templates already listed: it fails at once when a listed template
#   has no row in the app's lookup file, else it sends probe events of a few listed templates on the
#   same probe stream, and when one of them is indexed without its fields, or is not indexed within its
#   --timeout while Splunk logs dropping the map's events (an index-time error drops an event), it empties
#   the list at once (rows that do not start with `true` are kept) and leaves every listed template
#   pending, so the Receiver sends them whole until activate has proven them again. A probe not indexed in
#   time with no such log (a backlog, a restart) leaves the list as it is and check returns 2. The loop runs it on every turn, and activate runs it on every
#   probe round (--check-timeout), so activating new templates never holds up the check of the listed
#   ones: a lookup that stops giving rows while activate waits is found within one round.
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
# check writes the index time up to which it has counted the map's compact events indexed without their
# fields to <cap file>.checked; the next check counts from there (from the cap file's own time the first time).
CAP_CHECKED_SUFFIX = '.checked'
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
# With --probe-hec given once per parsing node, each probe carries the node it was sent to in this indexed field.
PROBE_NODE_FIELD = 'tenx_fm_probe_node'
# limits.conf [lookup] ingest_lookup_refresh_period_secs as shipped; activate reads the instance's own value.
LOOKUP_REFRESH_DEFAULT = 60
# Without --timeout, activate probes for the refresh period plus this many --poll rounds.
ACTIVATE_TIMEOUT_POLLS = 3


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


class TlsVerifyError(Exception):
	"""The certificate of a Splunk endpoint did not verify; str() is one line for the person running the tool."""

	def __init__(self, url, detail):
		Exception.__init__(self, 'the certificate of %s did not verify (%s); add --tls-ca-file with the PEM file of the '
			'authority that signed it, or, for an instance with Splunk\'s default self-signed certificate, --tls-verify off'
			% (url, detail))


def _certificate_failure(e):
	"""The verification message of an exception urlopen raised for a certificate that did not verify, or None."""
	reason = getattr(e, 'reason', e)
	if isinstance(reason, ssl.SSLCertVerificationError):
		return getattr(reason, 'verify_message', None) or str(reason)
	if isinstance(reason, ssl.SSLError) and 'CERTIFICATE_VERIFY_FAILED' in str(reason):
		return 'CERTIFICATE_VERIFY_FAILED'
	return None


def urlopen_checked(req, context, timeout):
	"""urllib.request.urlopen, with a certificate that does not verify raised as TlsVerifyError."""
	try:
		return urllib.request.urlopen(req, context=context, timeout=timeout)
	except (urllib.error.URLError, ssl.SSLError) as e:
		detail = _certificate_failure(e)
		if detail is None:
			raise
		parts = urllib.parse.urlsplit(req.full_url)
		raise TlsVerifyError('%s://%s' % (parts.scheme, parts.netloc), detail)


class Splunkd(object):
	"""The management port of the instance that parses the data (REST, JSON)."""

	def __init__(self, url, auth=None, token=None, tls_verify=True, hec_url=None, hec_token=None, ca_file=None):
		self.url = url.rstrip('/')
		# hec_url: one HTTP Event Collector URL, or a list with one per parsing node (each indexer's or heavy
		# forwarder's own endpoint, not a load balancer), which activate and check then prove one by one.
		urls = [u.rstrip('/') for u in (hec_url if isinstance(hec_url, (list, tuple)) else [hec_url]) if u]
		self.hec_url, self.hec_token = (urls[0] if urls else ''), hec_token
		self.nodes = urls if len(urls) > 1 else [None]
		self.headers = {}
		if token:
			self.headers['Authorization'] = 'Splunk %s' % token
		elif auth:
			self.headers['Authorization'] = 'Basic ' + base64.b64encode(auth.encode('utf-8')).decode('ascii')
		self.ctx = None
		if not tls_verify:
			self.ctx = ssl.create_default_context()
			self.ctx.check_hostname = False
			self.ctx.verify_mode = ssl.CERT_NONE
		elif ca_file:
			# Certificates are checked against these authorities only, host name included (the management port and
			# every HTTP Event Collector given).
			self.ctx = ssl.create_default_context(cafile=ca_file)

	def call(self, method, path, params=None):
		params = dict(params or {}, output_mode='json')
		url, data = self.url + path, None
		if method == 'GET':
			url += '?' + urllib.parse.urlencode(params)
		else:
			data = urllib.parse.urlencode(params).encode('ascii')
		req = urllib.request.Request(url, data=data, method=method, headers=self.headers)
		with urlopen_checked(req, self.ctx, 120) as res:
			body = res.read()
		return json.loads(body) if body.strip() else {}

	def send_node(self, node, lines, index, host, source, sourcetype):
		"""The lines to one parsing node's HTTP Event Collector, each event carrying PROBE_NODE_FIELD = the
		node's host:port. True when the node took them; False when it cannot be reached or answers that it is
		busy (503): a node that is down receives no events either, so it is left out, not counted as wrong."""
		label = urllib.parse.urlsplit(node).netloc
		body = '\n'.join(json.dumps({'event': l, 'index': index, 'host': host, 'source': source, 'sourcetype': sourcetype,
			'fields': {PROBE_NODE_FIELD: label}}) for l in lines).encode('utf-8')
		req = urllib.request.Request(node + '/services/collector/event', data=body, method='POST',
			headers={'Authorization': 'Splunk %s' % self.hec_token})
		try:
			with urlopen_checked(req, self.ctx, 10) as res:
				res.read()
		except urllib.error.HTTPError as e:
			if e.code == 503:
				return False
			raise
		except (urllib.error.URLError, OSError):
			return False
		return True

	def send(self, lines, index, host, source, sourcetype):
		"""Raw lines into the parsing pipeline, one event per line: through HTTP Event Collector when hec_url
		is set (the path compact events take from the Receiver, so the probe is parsed where they are), else
		through the management port's receivers/simple (the compact sourcetype breaks on line ends).
		Returns the nodes that took them: [None] for the one endpoint, else those of self.nodes that answered."""
		if self.nodes != [None]:
			return [n for n in self.nodes if self.send_node(n, lines, index, host, source, sourcetype)]
		if self.hec_url:
			body = '\n'.join(json.dumps({'event': l, 'index': index, 'host': host, 'source': source, 'sourcetype': sourcetype})
				for l in lines).encode('utf-8')
			req = urllib.request.Request(self.hec_url + '/services/collector/event', data=body, method='POST',
				headers={'Authorization': 'Splunk %s' % self.hec_token})
			with urlopen_checked(req, self.ctx, 120) as res:
				res.read()
			return [None]
		q = urllib.parse.urlencode({'index': index, 'host': host, 'source': source, 'sourcetype': sourcetype})
		req = urllib.request.Request(self.url + '/services/receivers/simple?' + q, data=('\n'.join(lines) + '\n').encode('utf-8'),
			method='POST', headers=self.headers)
		with urlopen_checked(req, self.ctx, 120) as res:
			res.read()
		return [None]

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
	"""The stanzas of the app's transforms.conf and props.conf the instance does not hold as written. An instance
	without the app at all answers 404 for its namespace: one entry says so."""
	differ = []
	for conf in ('transforms', 'props'):
		try:
			have = splunkd.stanzas(app_name, conf)
		except urllib.error.HTTPError as e:
			if e.code != 404:
				raise
			return ['app %s is not on the instance' % app_name]
		for name, settings in read_conf(os.path.join(app_dir, 'default', conf + '.conf')).items():
			got = have.get(name)
			if got is None:
				differ.append('%s.conf [%s] missing' % (conf, name))
			elif not all(_same_setting(k, v, got.get(k, '')) for k, v in settings.items()):
				differ.append('%s.conf [%s] differs' % (conf, name))
	return differ


LookupApp = collections.namedtuple('LookupApp', 'sourcetype table field')

# The indexed field the sourcetype rule of gen writes: [<prefix>_sourcetype] FORMAT = <field>::"<sourcetype>".
SOURCETYPE_FORMAT = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)::"([^"]*)"$')


def lookup_app(app_dir):
	"""(compact sourcetype, lookup file path, the indexed field every event of the sourcetype gets or None) of an app
	gen wrote with --rules lookup, or None. The compact sourcetype is the stanza whose TRANSFORMS- list holds the lookup
	rule; it has a rename line, or, with several original sourcetypes, a sourcetype rule instead."""
	props = read_conf(os.path.join(app_dir, 'default', 'props.conf'))
	transforms = read_conf(os.path.join(app_dir, 'default', 'transforms.conf'))
	for name, settings in props.items():
		for k, v in settings.items():
			if not k.startswith('TRANSFORMS-'):
				continue
			listed = [x.strip() for x in v.split(',')]
			for stanza in listed:
				if stanza.endswith('_fields_eval') and 'INGEST_EVAL' in transforms.get(stanza, {}):
					table = transforms.get(stanza[:-len('_eval')], {}).get('filename')
					if table:
						field = None
						for other in listed:
							m = SOURCETYPE_FORMAT.match(str(transforms.get(other, {}).get('FORMAT', '')).strip())
							if other.endswith('_sourcetype') and m and m.group(2) == name:
								field = m.group(1)
						return LookupApp(name, os.path.join(app_dir, 'lookups', table), field)
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


def node_states(splunkd, index, sourcetype, since):
	"""(hash, node) -> probe_states' pair, per node when splunkd has one HEC endpoint per parsing node
	(node = the URL), else (hash, None)."""
	if splunkd.nodes == [None]:
		return dict(((h, None), v) for h, v in probe_states(splunkd, index, sourcetype, since).items())
	by_label = dict((urllib.parse.urlsplit(n).netloc, n) for n in splunkd.nodes)
	rows = splunkd.search('search index="%s" host="%s" source="%s" _index_earliest=%d | eval tenx_fm_probe_h=trim('
		'replace(_raw, "^~([^,]*).*$", "\\1")), tenx_fm_probe_n=coalesce(%s, ""), tenx_fm_probe_m=if(isnull(%s), 0, 1), '
		'tenx_fm_probe_w=%s | stats max(tenx_fm_probe_m) as m values(tenx_fm_probe_w) as w by tenx_fm_probe_h tenx_fm_probe_n' % (
			index, PROBE_HOST, PROBE_SOURCE, int(since), PROBE_NODE_FIELD, MARK_FIELD, UNMAPPED_FIELD))
	states = {}
	for r in rows:
		n = by_label.get(r.get('tenx_fm_probe_n'))
		if n:
			w = r.get('w') or []
			states[(r['tenx_fm_probe_h'], n)] = (r.get('m') == '1', sorted(w if isinstance(w, list) else [w]))
	return states


def _on(node):
	return '' if node is None else ' sent to %s' % node


def probe_results(splunkd, index, sourcetype, since):
	"""hash -> True when a probe event of that hash indexed since `since` has tenx_mapped."""
	return dict((h, v[0]) for h, v in probe_states(splunkd, index, sourcetype, since).items())


def lookup_refresh_secs(splunkd):
	"""(seconds, True) from the instance's limits.conf [lookup] ingest_lookup_refresh_period_secs, or
	(LOOKUP_REFRESH_DEFAULT, False) when it cannot be read."""
	try:
		res = splunkd.call('GET', '/services/configs/conf-limits/lookup')
		for e in res.get('entry', []):
			v = e.get('content', {}).get('ingest_lookup_refresh_period_secs')
			if v not in (None, ''):
				return float(v), True
	except Exception:
		pass
	return float(LOOKUP_REFRESH_DEFAULT), False


def _netloc(url):
	return urllib.parse.urlsplit(url).netloc


def parsing_endpoints(splunkd):
	"""The URLs the probes go to: each HTTP Event Collector given, or the management port named by --splunkd
	(receivers/simple) when none is."""
	if not splunkd.hec_url:
		return [splunkd.url]
	return [splunkd.hec_url] if splunkd.nodes == [None] else list(splunkd.nodes)


def probes_parsed_on(splunkd):
	"""True when the instance --splunkd names parses the probes: no HTTP Event Collector given, or one on the same
	host. False when they go to other hosts, such as a search head's indexers or heavy forwarders."""
	host = (urllib.parse.urlsplit(splunkd.url).hostname or '').lower()
	return any((urllib.parse.urlsplit(u).hostname or '').lower() == host for u in parsing_endpoints(splunkd))


def activate(app_dir, cap_file, splunkd, app_name=None, probe_index=None, timeout=None, poll=10, out=sys.stdout,
		clock=time.time, sleep=time.sleep, check_timeout=60, rng=None):
	"""
	Lists in the cap file each template the pending list adds once a probe event of it, sent on the
	probe stream, is indexed with its fields; removals take effect at once. Never restarts or reloads
	anything. Returns 0 when the cap file equals the pending list, 1 otherwise (the pending list kept).

	While it waits, every probe round also runs check on one listed template (check_timeout is check's
	timeout), so a loop that runs activate is never longer than one round without a check: when that
	probe comes back without its fields or does not come back, check withdraws the list and activate
	returns 1 at once. A new template whose probe, indexed once the instance must have reread the lookup
	file (ingest_lookup_refresh_period_secs plus one poll after the start), has no fields stays pending
	and is not probed again in this run. timeout None: the refresh period plus three polls, so a run ends
	about two rounds after every probe was parsed with the installed file.

	With one HEC endpoint per parsing node (splunkd.nodes), every probe goes to every node, and a template
	is listed only once the probe sent to each node that took that round's probes came back with its fields:
	a node that answers without them holds it back, a node that cannot be reached is left out until it
	answers again.
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
	sourcetype, table = layout.sourcetype, layout.table
	before, kept = read_cap(cap_file)
	after, _ = read_cap(pending)
	added = sorted(after - before)
	differ = not_installed(splunkd, app_dir, app_name)
	if differ:
		out.write('activate: the instance does not hold app %s as generated (%d stanzas, first %s); install the app '
			'folders as gen wrote them, whole, and run activate again; cap file left as it was\n' % (app_name, len(differ),
			differ[0]))
		return 1
	floor = floor_dir(app_dir)
	if added and os.path.isdir(floor):
		if probes_parsed_on(splunkd):
			if not_installed(splunkd, floor, app_name + FLOOR_SUFFIX):
				out.write('activate: the instance does not hold the floor app %s, without which a missing lookup file drops '
					'compact events; cap file left as it was\n' % (app_name + FLOOR_SUFFIX))
				return 1
		else:
			# The floor app acts only where the compact events are parsed. A search head named by --splunkd, apart from
			# the HTTP Event Collector that takes the probes, does not need it, and this tool cannot read the parsing
			# instances' apps from here.
			out.write('activate: %s was not checked: the compact events are parsed at %s, not at %s, the one instance this '
				'tool reads apps from; install the floor app on each instance that parses them\n' % (app_name + FLOOR_SUFFIX,
				', '.join(_netloc(n) for n in parsing_endpoints(splunkd)), _netloc(splunkd.url)))
	confirmed, failed = set(), {}
	if added:
		if not probe_index:
			out.write('activate: --probe-index is needed to prove new templates; cap file left as it was\n')
			return 1
		problem = lookup_file_problem(table)
		if problem:
			out.write('activate: the lookup file %s %s; Splunk drops the compact events of %s while the file it reads is '
				'like that; cap file left as it was\n' % (table, problem, sourcetype))
			return 1
		rows = read_lookup_file(table)
		refresh, read_from_instance = lookup_refresh_secs(splunkd)
		if timeout is None:
			timeout = refresh + ACTIVATE_TIMEOUT_POLLS * poll
		start = clock()
		# A probe indexed from this time on was parsed with the file that was installed when activate started.
		settled = start + refresh + poll
		splunkd.send([HEARTBEAT_LINE], probe_index, PROBE_HOST, PROBE_SOURCE, sourcetype)
		probes, checks, away = 0, 0, set()
		while True:
			todo = [h for h in added if h not in confirmed and h not in failed and h.strip() in rows]
			if not todo:
				break
			now = clock()
			# Until one template has its fields, one stands for all of them (after the refresh period, the
			# next one once it has failed), so a lookup that gives no rows costs one probe a round.
			batch = todo if confirmed else todo[:1]
			up = splunkd.send([probe_line(h, rows[h.strip()], int(now)) for h in batch], probe_index, PROBE_HOST, PROBE_SOURCE,
				sourcetype)
			away |= set(splunkd.nodes) - set(up)
			probes += len(batch) * len(up)
			if before:
				# check's probe of a listed template, in place of the wait for this round's probes.
				held = io.StringIO()
				checks += 1
				if check(app_dir, cap_file, splunkd, app_name, probe_index, 1, check_timeout, poll, held, clock, sleep, rng) == 1:
					out.write(held.getvalue())
					# check also fails, leaving the list, when it counts compact events indexed without their fields for
					# a reason the list does not cause (no_row, no_match): the probing goes on. Only a withdrawn list stops it.
					if not read_cap(cap_file)[0]:
						out.write('activate: stopped after %.0f s, the list withdrawn by check; %d of %d new templates '
							'had their fields; all stay pending\n' % (clock() - start, len(confirmed), len(added)))
						return 1
			else:
				sleep(poll)
			seen = node_states(splunkd, probe_index, sourcetype, start - 1)
			confirmed |= set(h for h in todo if up and all(seen.get((h.strip(), n), (False,))[0] for n in up))
			now = clock()
			if now >= settled:
				late = node_states(splunkd, probe_index, sourcetype, settled)
				for h in todo:
					got = [late[(h.strip(), n)] for n in up if (h.strip(), n) in late]
					if h not in confirmed and got and not all(g[0] for g in got):
						failed[h] = sorted(set(w for g in got if not g[0] for w in g[1]))
			if now - start > timeout:
				break
		missing = [h for h in added if h not in confirmed and h not in failed]
		out.write('activate: %d of %d new templates indexed with their fields on the probe stream (%d probe events, '
			'%d checks, %.0f s of at most %.0f, lookup refresh %.0f s%s)%s%s\n' % (len(confirmed), len(added), probes, checks,
				clock() - start, timeout, refresh, '' if read_from_instance else ', the default: not read from the instance',
				'' if not failed else '; without their fields after the file was read: %s' % ', '.join(
					'%r (%s=%s)' % (h, UNMAPPED_FIELD, ','.join(failed[h]) or 'none') for h in sorted(failed)[:5]),
				'' if not missing else '; not yet: %s' % ', '.join(repr(h) for h in missing[:5])))
		if away:
			out.write('activate: did not answer in at least one round, so left out of those rounds: %s\n' % ', '.join(sorted(away)))
		if failed and not confirmed and all(failed[h] == [WHY_NO_ROW] for h in failed):
			# Splunk 10.4.3: a lookup file moved away and back, so that it had again the modification time it had when
			# Splunk last read it, was not reread in 75 s (probe no_row), and was read within 75 s once touched; a file
			# put back with an older time than the one it replaced was read.
			out.write('activate: every probe came back %s=%s, so the instance has not read the rows of %s. Splunk rereads a '
				'lookup file when its modification time changes: a file put back with the time it had when Splunk last read '
				'it (moved back, or copied with its time kept: cp -p, docker cp, rsync -a) stays unread until it is touched '
				'on that instance\n' % (UNMAPPED_FIELD, WHY_NO_ROW, os.path.basename(table)))
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
	Probes `sample` listed templates, chosen at random. When every probe is indexed with its fields, or nothing
	is listed, counts the compact events of the map's sourcetype indexed without their fields since the previous
	check and returns 0 when there are none, else 1 (check_unmapped says when the list is emptied). When one is
	indexed without them, the cap file keeps only its rows that do not start with true, every listed template
	is left pending (<cap file>.pending, merged with a pending list already there), and returns 1: the Receiver
	sends those templates whole until activate proves them again. When one is not indexed within `timeout`
	seconds, the same happens only if Splunk logged dropping events of the map's sourcetype in that time, or
	_internal cannot be read; otherwise the list is left as it was, the templates not checked are named, and it
	returns 2.

	With one HEC endpoint per parsing node (splunkd.nodes), the probes go to every node, and the answer of
	each node that took them counts; a node that cannot be reached is left out. When no node takes them,
	nothing is checked and check returns 2 without changing the list.
	"""
	import random
	listed, kept = read_cap(cap_file)
	layout = lookup_app(app_dir)
	if layout and check_dropped(cap_file, splunkd, layout[0], clock, out):
		return 1
	if not listed:
		# Nothing to probe; a Receiver that compacts every template (receiverOptimize true) still sends
		# compact events that have no row, so those are counted.
		out.write('check: nothing listed (%s)\n' % cap_file)
		return check_unmapped(cap_file, splunkd, layout.sourcetype, clock, out, layout.field) if layout else 0
	app_name = app_name or os.path.basename(os.path.abspath(app_dir))
	if layout is None or not probe_index:
		out.write('check: needs an app generated with --rules lookup and --probe-index; cap file left as it was\n')
		return 2
	sourcetype, table = layout.sourcetype, layout.table
	problem = lookup_file_problem(table)
	if problem:
		# Splunk keeps the rows it read until its next refresh, then fails on every compact event: withdraw now.
		withdraw(cap_file, 'the lookup file %s %s' % (table, problem), out)
		return 1
	rows = read_lookup_file(table)
	without = sorted(h for h in listed if h.strip() not in rows)
	why = None
	if without:
		why = '%d listed templates have no row in %s (first %r)' % (len(without), table, without[0])
	else:
		probed = sorted((rng or random.Random()).sample(sorted(listed), min(sample, len(listed))))
		start = clock()
		up = splunkd.send([probe_line(h, rows[h.strip()], int(clock())) for h in probed], probe_index, PROBE_HOST, PROBE_SOURCE,
			sourcetype)
		away = '' if len(up) == len(splunkd.nodes) else '; did not answer, left out: %s' % ', '.join(
			sorted(set(splunkd.nodes) - set(up)))
		if not up:
			out.write('check: no parsing node took the probes%s; nothing checked, cap file left as it was\n' % away)
			return 2
		pairs = [(h, n) for h in probed for n in up]
		while True:
			sleep(poll)
			states = node_states(splunkd, probe_index, sourcetype, start - 1)
			got = [states.get((h.strip(), n)) for h, n in pairs]
			bad = [(h, n, g[1]) for (h, n), g in zip(pairs, got) if g is not None and not g[0]]
			if bad:
				why = 'probe of %r%s indexed without its fields (%s=%s)' % (bad[0][0], _on(bad[0][1]), UNMAPPED_FIELD,
					','.join(bad[0][2]) or 'none')
				break
			if all(got):
				out.write('check: %d of %d listed templates probed%s, all indexed with their fields (%.0f s)%s\n' % (
					len(probed), len(listed), '' if up == [None] else ' on %d nodes' % len(up), clock() - start, away))
				return check_unmapped(cap_file, splunkd, sourcetype, clock, out, layout.field)
			if clock() - start > timeout:
				late = [(h, n) for (h, n), g in zip(pairs, got) if g is None]
				why = '%d of %d probes not indexed within %.0f s%s' % (len(late), len(pairs), timeout,
					'' if up == [None] else ' (%s)' % ', '.join(sorted(set(n for _, n in late))))
				# A probe that has not come back is not a failed proof: behind an indexing backlog, or right after a
				# restart, it is indexed later (measured: a check right after an indexer restart, and one behind a HEC
				# backlog, emptied lists whose rows worked). It is one when Splunk dropped it, which its own log says
				# (DROP_SEARCH); without that log (no _internal for the role) it is taken as one, as before. A drop
				# logged after this window is counted by the next check (check_dropped), whose window starts here.
				drops = dropped_since(splunkd, sourcetype, start - 1, clock() + 1)
				if drops is None or drops:
					break
				out.write('check: %s and Splunk logged no dropped event of %s; not checked: %s; cap file left as it '
					'was, run check again\n' % (why, sourcetype, ', '.join(sorted(set(repr(h) for h, _ in late)))))
				return 2
	withdraw(cap_file, why, out)
	return 1


# A compact event Splunk drops because the map's index-time lookup() failed (a lookup file Splunk finds but cannot load:
# unreadable, not gzip, no hash column) leaves one splunkd.log line per event on the node that parsed it, the event's
# sourcetype at the end of its confkey (Splunk Enterprise 10.4.3):
#   ERROR pipeline [... typing] - Runtime exception in  pipeline=typing processor=regexreplacement error='Invalid function
#   argument' confkey='source::<source>|host::<host>|tenx_win|'
DROP_SEARCH = ('search index=_internal sourcetype=splunkd "Runtime exception" "processor=regexreplacement" "%s" '
	'_index_earliest=%d _index_latest=%d | rex "confkey=\'[^\']*\\|(?<tenx_fm_st>[^|\']+)\\|\'" '
	'| where tenx_fm_st="%s" | stats count, min(_time) as first, max(_time) as last by host')


def dropped_since(splunkd, sourcetype, since, until):
	"""
	[(node, count, first, last)] of the compact events of `sourcetype` Splunk dropped from `since` to `until` (epoch
	seconds, index time of its own log lines) because an index-time rule failed on them, read from _internal; None when
	the caller cannot read _internal (its role does not search it), so a count of 0 would mean nothing.
	"""
	if not splunkd.search('| tstats count where index=_internal earliest=-1h | where count>0'):
		return None
	rows = splunkd.search(DROP_SEARCH % (sourcetype, int(since), int(until), sourcetype))
	got = []
	for r in rows:
		n = int(float(r.get('count') or 0))
		if n:
			got.append((r.get('host') or '?', n, float(r.get('first') or 0), float(r.get('last') or 0)))
	return sorted(got)


def check_window(cap_file, clock):
	"""(since, until): from the previous check (from the cap file's own time the first time) to now."""
	try:
		with open(cap_file + CAP_CHECKED_SUFFIX, encoding='utf-8') as f:
			since = float(f.read().strip())
	except (IOError, OSError, ValueError):
		since = os.path.getmtime(cap_file) if os.path.exists(cap_file) else 0
	return since, clock()


def check_dropped(cap_file, splunkd, sourcetype, clock, out):
	"""
	Counts the compact events of `sourcetype` Splunk dropped since the previous check (see DROP_SEARCH). When there
	are any, the list is emptied (the Receiver then sends the map's events whole, and lookup() is not called on a whole
	event), the window moves on, and it returns True. A caller that cannot read _internal is told so, and False.
	"""
	since, until = check_window(cap_file, clock)
	got = dropped_since(splunkd, sourcetype, since, until)
	if got is None:
		out.write('check: cannot read _internal, so events Splunk dropped are not counted; give the role index _internal\n')
		return False
	if not got:
		return False
	write_if_changed(cap_file + CAP_CHECKED_SUFFIX, '%d\n' % int(until))
	t = lambda e: time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(e))
	what = '%d compact events of %s were dropped by Splunk since %s, its index-time lookup failing on the map\'s lookup ' \
		'file (%s)' % (sum(n for _, n, _, _ in got), sourcetype, t(since),
		'; '.join('%s %d, first %s, last %s' % (h, n, t(a), t(b)) for h, n, a, b in got))
	if read_cap(cap_file)[0]:
		withdraw(cap_file, what, out)
	else:
		out.write('check: %s; the cap file lists no template\n' % what)
	return True


def unmapped_since(splunkd, sourcetype, since, until, field=None):
	"""
	{reason: count} of the compact events of `sourcetype` indexed without their fields (tenx_unmapped) from
	`since` to `until` (epoch seconds, index time), probe events left out: the search of the saved search
	Field Map Events Without Fields, held to one compact sourcetype. With `field`, the indexed field every event
	of the sourcetype gets (SOURCETYPE_FIELD), events stored under another sourcetype by a map with several
	original sourcetypes are counted as well.
	"""
	which = 'sourcetype="%s"' % sourcetype if not field else '(sourcetype="%s" OR %s="%s")' % (sourcetype, field, sourcetype)
	rows = splunkd.search('| tstats count where index=* %s %s=* NOT host="%s" _index_earliest=%d '
		'_index_latest=%d by %s' % (which, UNMAPPED_FIELD, PROBE_HOST, int(since), int(until), UNMAPPED_FIELD))
	got = {}
	for r in rows:
		n = int(float(r.get('count') or 0))
		if n:
			got[r.get(UNMAPPED_FIELD) or '?'] = n
	return got


def check_unmapped(cap_file, splunkd, sourcetype, clock, out, field=None):
	"""
	Counts the compact events of `sourcetype` indexed without their fields since the previous check (from the cap
	file's own time the first time) and returns 0 when there are none, else 1:
	* no_row: templates the lookup has no row for arrived compact, so the Receiver compacts templates the cap file
	  does not list (receiverOptimize true in its arguments, or another map's cap file). Taking the listed
	  templates off the list would not stop that.
	* no_match: an event of a listed template has values its row does not take (a value holding a line feed), while
	  the probe of the same run had its fields: a matter of those events, not of the list.
	  For these two the list is left as it is.
	* bad_row, no_table: the row or the whole lookup file fails, for every event of the templates concerned, so the
	  list is emptied, as when a probe comes back without its fields.
	"""
	state = cap_file + CAP_CHECKED_SUFFIX
	since, until = check_window(cap_file, clock)
	got = unmapped_since(splunkd, sourcetype, since, until, field)
	write_if_changed(state, '%d\n' % int(until))
	if not got:
		return 0
	what = '%d compact events of %s were indexed without their fields since %s (%s)' % (sum(got.values()), sourcetype,
		time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(since)), ', '.join('%s %d' % kv for kv in sorted(got.items())))
	if set(got) - {WHY_NO_ROW, WHY_NO_MATCH} and read_cap(cap_file)[0]:
		withdraw(cap_file, what, out)
		return 1
	causes = []
	if WHY_NO_ROW in got:
		causes.append('templates the lookup file has no row for arrived compact: the Receiver compacts templates the '
			'cap file does not list (receiverOptimize true in its arguments, or another map\'s cap file), or the lookup '
			'file Splunk holds lacks their rows')
	if WHY_NO_MATCH in got:
		causes.append('events of listed templates hold values their row does not take (a value holding a control character other than a carriage return, such as a line feed or a NUL byte)')
	out.write('check: %s: %s; the cap file is left as it was\n' % (what, '; '.join(causes) or 'the cap file lists no template'))
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
		'reader': args.reader, 'sourcetype': args.sourcetype, 'rename': args.rename, 'rename_field': args.rename_field,
		'transform_prefix': args.transform_prefix, 'transforms_class': args.transforms_class,
		'app_name': args.app_name, 'source': getattr(args, 'source', None),
		'indexed_value_false': None if args.indexed_value_false is None
			else [f for f in args.indexed_value_false.split(',') if f],
		'reserved_names': args.reserved_names, 'time_prefix': args.time_prefix, 'time_format': args.time_format,
		'leave_out': None if args.leave_out is None else [f for f in args.leave_out.split(',') if f],
	}
	target = load_target(args.target, overrides)
	templates, refused = merge_templates([load_templates(p) for p in args.records or ()])
	keep = None
	if args.only_hashes_in:
		keep = set()
		for p in args.only_hashes_in:
			keep |= hash_keys_in(p)
	time_rule = None
	time_prefix, time_formats = target.get('time_prefix'), target.get('time_format') or ()
	if (args.rules != RULES_LOOKUP and not args.records and not args.time_props and not args.time_format
			and args.time_prefix is None):
		# No template rows for a target's time rule to read (see "Fields from the Receiver").
		time_prefix, time_formats = None, ()
	if args.time_props or time_formats or time_prefix is not None:
		settings = {}
		if args.time_props:
			# Several original sourcetypes: one rule for all, so their timestamp settings must agree.
			each = [read_time_settings(args.time_props, r) for r in renames(target)]
			if any(e != each[0] for e in each[1:]):
				raise ValueError('--time-props: the timestamp settings of %s differ; one rule reads them all'
					% ', '.join(renames(target)))
			settings = each[0]
		time_rule = make_time_rule(settings, time_prefix, time_formats, args.time_lookahead)
	reader, text_rules = READERS[target['reader']](), None
	if target['reader'] == CsvReader.name:
		columns = getattr(args, 'columns', None) or target.get('columns')
		if columns:
			header = [c.strip() for c in (columns.split(',') if isinstance(columns, str) else columns)]
			layouts, layout_report = [(None, header, getattr(args, 'delimiter', None) or target.get('delimiter') or ',')], {}
		elif getattr(args, 'addon', None):
			try:
				layouts, layout_report = csv_layouts(args.addon, renames(target))
			except OSError as e:
				raise AddonError(str(e))
		else:
			raise ValueError('the csv reader needs the column names: --columns a,b,c, or --addon with the add-on whose '
				'REPORT- transforms list them (DELIMS and FIELDS)')
		if not layouts:
			raise ValueError('the csv reader found no column names: %s' % '; '.join('%s: %s' % kv for kv in layout_report.items()))
		reader = CsvReader(layouts)
		target['layouts'] = layout_report
	if isinstance(reader, CsvReader):
		# See "A positional rule on a compact line": tenx_blank and the search-time rules that null what such a rule
		# reads from a compact line where the map wrote no field.
		csv_reader = reader
		if getattr(args, 'addon', None):
			props, transforms = read_addon(args.addon)
			_, _, by_sourcetype = csv_layouts(args.addon, renames(target), by_sourcetype=True)
		else:
			props, transforms, by_sourcetype = {}, {}, collections.OrderedDict((st, header) for st in renames(target))
		prefix = args.reserved_prefix if target.get('reserved_names') == 'restore' else None
		target['blank_evals'] = collections.OrderedDict(
			(st, blank_overrides(props, transforms, st, columns, prefix)) for st, columns in by_sourcetype.items())
	leave_out = target.get('leave_out') or []
	if leave_out:
		reader = LeaveOutReader(reader, leave_out)
	if getattr(args, 'fields', 'all') == 'cim' and not (getattr(args, 'addon', None) and getattr(args, 'cim', None)):
		raise ValueError('--fields cim needs --addon and --cim (the folders of the add-on and of Splunk_SA_CIM)')
	if getattr(args, 'addon', None):
		try:
			copies, report, derived = addon_text_rules(args.addon, target, templates)
		except OSError as e:
			raise AddonError(str(e))
		if getattr(args, 'fields', 'all') == 'cim':
			stanzas = renames(target)
			if target.get('source'):
				props, _ = read_addon(args.addon)
				stanzas = stanzas + [st for st in props if st.startswith('source::') and source_pattern_matches(
					st[len('source::'):], target['source'])]
			reader = NeededFieldsReader(reader, needed_fields(args.addon, args.cim, stanzas, copies))
		if derived:
			reader = TextRuleReader(reader, derived, DERIVE_PROBES_NO_LINE_FEED if target['reader'] == WindowsClassicReader.name
				else DERIVE_PROBES)
		text_rules = (copies, report, reader)
	if target.get('blank_evals'):
		reader = BlankFieldReader(reader, csv_reader)
	field_map = FieldMap(templates, reader, target['transform_prefix'],
		stanza_names=args.stanza_names, hash_match=args.hash_match, timestamp_values=args.timestamp_values,
		keep=keep, refused=refused, mixed_names=args.mixed_names,
		reserved_names=target.get('reserved_names') or 'skip', reserved_prefix=args.reserved_prefix,
		trim_values={'auto': None, 'on': True, 'off': False}[args.trim_values],
		mark=None if args.mark == 'none' else args.mark, eval_values=args.eval_values == 'on', rules=args.rules,
		time_rule=time_rule)
	field_map.text_rules = text_rules
	return target, templates, field_map


def build_parser():
	ap = argparse.ArgumentParser(description='Index-time field map for compact events (see the module docstring).')
	sub = ap.add_subparsers(dest='mode')
	sub.required = True

	for mode in ('gen', 'verify'):
		p = sub.add_parser(mode)
		p.add_argument('--records', action='append', required=mode == 'verify',
			help='KV store export (JSON array) or templates.json; repeat to merge' + ('' if mode == 'verify' else
				'. Without it, gen writes the map with no template, to install before the first event of the compact '
				'sourcetype (see "Before the first event")'))
		p.add_argument('--only-hashes-in', action='append',
			help='keep only the templates named in this templates.json or KV export')
		p.add_argument('--target', help='built-in target (%s) or a JSON file' % ', '.join(sorted(TARGETS)))
		p.add_argument('--reader', choices=sorted(READERS))
		p.add_argument('--sourcetype', help='the compact sourcetype the generated props.conf defines')
		p.add_argument('--rename', help='the original sourcetype, whose search-time rules should run; several, '
			'separated by commas: each event is stored under the one its --rename-field names (see "Several original '
			'sourcetypes")')
		p.add_argument('--rename-field', help='with several --rename sourcetypes, the indexed field the sender sets to '
			'the event\'s original sourcetype (default %s)' % RENAME_FIELD)
		p.add_argument('--source', help='the source the compact events carry (windows-security: XmlWinEventLog:Security); '
			'with --addon, the add-on\'s source:: stanzas that match it are read as well')
		p.add_argument('--transform-prefix')
		p.add_argument('--transforms-class')
		p.add_argument('--app-name')
		p.add_argument('--indexed-value-false', help='comma-separated field names for fields.conf')
		p.add_argument('--leave-out', help='comma-separated field names the map does not write')
		p.add_argument('--columns', help='csv reader: the column names, in order, separated by commas (a header list); '
			'without it the names come from the add-on (--addon)')
		p.add_argument('--delimiter', help='csv reader with --columns: the delimiter (default a comma)')
		p.add_argument('--fields', choices=('all', 'cim'), default='all',
			help='all: every field the reader finds (default); cim: only the fields the CIM data models and the add-on\'s '
				'event types read, through the add-on\'s rules (needs --addon and --cim; see "The fields the data models '
				'need")')
		p.add_argument('--cim', help='with --fields cim, the folder of Splunk_SA_CIM (its default/data/models/*.json)')
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
		p.add_argument('--reserved-names', choices=('skip', 'prefix', 'restore'),
			help='a field named like a Splunk default field (eventtype, host, source, ...; any case): '
				'skip it, write it under --reserved-prefix (prefix), or write it under the prefix and give it '
				'back under its own name at search time, under the rename target (restore); all are reported (default: '
				'the target\'s, else skip)')
		p.add_argument('--reserved-prefix', default='extracted_',
			help='prefix for --reserved-names prefix and restore (default extracted_, the name Splunk 10.4.3 itself gave)')
		p.add_argument('--mark', default=MARK_FIELD,
			help='indexed field every FORMAT writes as <mark>::"1" (default %s; none: no mark). `tx` keeps the '
				'indexed fields of an event that has it from being extracted a second time' % MARK_FIELD)
		p.add_argument('--mixed-names', action='store_true',
			help='write names that join text and values (checked on Splunk 9.4.15, 10.4.3 and 10.6.0.5 with the CloudTrail map; off by default)')
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
			p.add_argument('--addon', help='the folder of the original sourcetype\'s add-on (its default/ and local/ '
				'props.conf and transforms.conf are read): for each of its search-time rules that read the event\'s text, '
				'which finds nothing on a compact event, write a copy that reads the field the map indexes for that '
				'text (xml-windows reader; see "Add-on rules that read the event\'s text")')
			p.add_argument('--report', help='report path (default: <out>_report.json)')
			p.add_argument('--app-props', default=default_app_props(), help='the app props.conf holding [tenx_encoded]')
			p.add_argument('--search-hash', choices=('on', 'off'), default='on',
				help='on: write the search-time hash and values extraction under the rename target, which `tx` needs')
			p.add_argument('--sourcetype-field', default=SOURCETYPE_FIELD,
				help='indexed field every event of the compact sourcetype gets as <field>::"<sourcetype>", which '
					'tenx-events names so that `tx` finds these events (default %s; none: not written)' % SOURCETYPE_FIELD)
			p.add_argument('--lookup-max-bytes', type=int, default=LOOKUP_DEFAULT_MAX_BYTES,
				help='with --rules lookup, refuse to write a lookup file larger than this (default %d, below '
					'limits.conf ingest_max_memtable_bytes, 10485760)' % LOOKUP_DEFAULT_MAX_BYTES)
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
	p.add_argument('--check-timeout', type=float, default=60,
		help='seconds each round waits for the probe of a listed template it sends, as check does (default 60); when '
			'that probe is indexed without its fields or not in time, the list is withdrawn and activate stops')
	_splunkd_args(p, required=True)

	p = sub.add_parser('check', help='probe a few listed templates; when one is indexed without its fields or not at all, '
		'list none of them until activate has proven them again')
	p.add_argument('--app', required=True, help='the app folder gen wrote, as installed on the instance')
	p.add_argument('--app-name', help='the app\'s name on the instance (default: the folder name)')
	p.add_argument('--cap-file', required=True)
	p.add_argument('--sample', type=int, default=1, help='listed templates probed per run, chosen at random (default 1)')
	_splunkd_args(p, required=True, timeout=60, timeout_help='seconds check waits for its probe events (default 60)')
	return ap


def _splunkd_args(p, required, timeout=None, timeout_help='seconds activate keeps probing (default: the instance\'s '
		'ingest_lookup_refresh_period_secs plus three --poll, 90 s with the defaults)'):
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
	p.add_argument('--probe-hec', action='append',
		help='HTTP Event Collector URL to send the probe events to, e.g. https://indexer:8088: the endpoint the Receiver '
			'sends to, so a probe is parsed where the compact events are (default: the --splunkd management port, '
			'which parses them on that instance). Where several instances parse the data (indexer peers, heavy '
			'forwarders behind a load balancer), give it once for each of them, with each node\'s own endpoint: '
			'activate then lists a template only once every node that answers returns its probe with fields, and '
			'check probes every node')
	p.add_argument('--probe-hec-token-env', default='TENX_PROBE_HEC_TOKEN',
		help='environment variable holding the HEC token for --probe-hec (default TENX_PROBE_HEC_TOKEN)')
	p.add_argument('--tls-verify', choices=('on', 'off'), default='on',
		help='off: accept the instance\'s certificate without checking it (a self-signed management port)')
	p.add_argument('--tls-ca-file',
		help='PEM file of the certificate authorities that signed the certificates of --splunkd and --probe-hec; they '
			'are checked against these instead of the system\'s, host name included')


def _splunkd(args):
	return Splunkd(args.splunkd, auth=os.environ.get(args.splunkd_auth_env),
		token=os.environ.get(args.splunkd_token_env), tls_verify=args.tls_verify == 'on', hec_url=args.probe_hec,
		hec_token=os.environ.get(args.probe_hec_token_env), ca_file=args.tls_ca_file)


def main(argv=None):
	args = build_parser().parse_args(argv)
	try:
		return _main(args)
	except TlsVerifyError as e:
		sys.stderr.write('%s: %s\n' % (args.mode, e))
		return 1


def _main(args):
	if args.mode == 'activate':
		return activate(args.app, args.cap_file, _splunkd(args), args.app_name, args.probe_index, args.timeout, args.poll,
			check_timeout=args.check_timeout)
	if args.mode == 'check':
		return check(args.app, args.cap_file, _splunkd(args), args.app_name, args.probe_index, args.sample, args.timeout,
			args.poll)

	try:
		target, templates, field_map = _build(args)
	except AddonError as e:
		sys.stderr.write('%s: --addon: %s\n' % (args.mode, e))
		return 2
	except ValueError as e:
		sys.stderr.write('%s: %s\n' % (args.mode, e))
		return 2

	if args.mode == 'verify':
		result = verify(templates, field_map, args.encoded, args.raw, args.raw_split)
		return 0 if result['expanded_differ'] == 0 and result['transform_regex_did_not_match'] == 0 else 1

	settings, not_copied = parsing_settings(args.app_props)
	sourcetype_field = None if args.sourcetype_field == 'none' else args.sourcetype_field
	if several(target) and not sourcetype_field:
		sys.stderr.write('gen: with several --rename sourcetypes, events are stored under the original sourcetype, so '
			'tenx-events finds them only by --sourcetype-field; it cannot be none\n')
		return 2
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
	text_rules, text_report = (), None
	if field_map.text_rules is not None:
		text_rules, text_report, reader = field_map.text_rules
		if isinstance(reader, TextRuleReader):
			for c in text_report['copied']:
				if c['reads'].startswith('the rule on each'):
					c['templates_written'] = reader.written.get(c['transform'], 0)
					c['templates_left_out_value_dependent'] = reader.dependent.get(c['transform'], 0)
	elif target['reader'] == XmlWindowsReader.name:
		sys.stderr.write('gen: without --addon, the add-on\'s rules that read the event\'s text, not a field, give '
			'nothing on mapped events; give --addon <the add-on\'s folder> to write copies that read the indexed fields\n')
	cap = None
	if args.cap_file:
		hashes = cap_hashes(field_map, templates)
		cap = cap_before_app(args.cap_file, hashes)
	sizes = {}
	if args.rules == RULES_LOOKUP and args.floor == 'on':
		# First, so the definition and a file of its name exist before the rule that reads them.
		sizes.update(write_floor_app(args.out, target))
	sizes.update(write_app(args.out, target, field_map, settings, args.search_hash == 'on', sourcetype_field, lookup_bytes,
		text_rules))
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
	if text_report is not None:
		report['addon_rules_reading_text'] = text_report
	report_path = args.report or args.out.rstrip(os.sep) + '_report.json'
	with open(report_path, 'w', encoding='utf-8') as f:
		json.dump(report, f, indent=1)
	summary = collections.OrderedDict((k, report[k]) for k in ('templates', 'fields_per_template_min_max', 'skipped',
		'literal_field_names', 'templates_without_transform', 'timestamp_written_as_epoch', 'timestamp_written_as_text',
		'written_by_ingest_eval', 'reserved_field_names'))
	if text_report is not None:
		summary['addon_rules_reading_text'] = collections.OrderedDict([
			('copied', ['%s (%s): %s' % (c['transform'], c['reads'], ', '.join(c['writes'])) for c in text_report['copied']]),
			('not_copied', len(text_report['not_copied'])), ('warnings', text_report['warnings'])])
	sys.stdout.write(json.dumps(summary, indent=1) + '\nreport: %s\n' % report_path)
	if not report['templates'] and report.get('templates_selected'):
		# Exit code unchanged: the app is still written, it just maps nothing.
		reasons = ', '.join('%s: %d' % kv for kv in sorted(report['templates_without_transform'].items()))
		sys.stderr.write('gen: none of the %d templates read got a rule (%s), so the app writes no field. '
			'Check that --target or --reader matches these records.\n' % (report['templates_selected'], reasons))
	if sourcetype_field:
		sys.stdout.write('for tx: add %s::%s to the tenx-events macro, for example\n'
			'    index=* (sourcetype::tenx_encoded OR %s::%s)\n' % (sourcetype_field, target['sourcetype'], sourcetype_field,
			target['sourcetype']))
	if several(target):
		sys.stdout.write('sender: set %s on every event of %s to its original sourcetype, one of %s; an event without '
			'one of them keeps %s\n' % (target['rename_field'], target['sourcetype'], ', '.join(renames(target)),
			target['sourcetype']))
	if args.rules == RULES_LOOKUP and args.floor == 'on':
		sys.stdout.write('floor app: %s; install it on every instance that parses the compact events\n'
			% floor_dir(args.out))
	if not args.records:
		sys.stdout.write('no templates: install the map before the first event of %s; run gen again with --records once '
			'its templates are stored\n' % target['sourcetype'])
	if cap is not None:
		sys.stdout.write('compact cap: %s\n' % json.dumps(cap))
		if args.splunkd:
			return activate(args.out, args.cap_file, _splunkd(args), None, args.probe_index, args.timeout, args.poll)
	return 0


if __name__ == '__main__':
	sys.exit(main())
