#!/usr/bin/env python3
"""
Which saved searches, alerts and dashboard panels change when a source moves to compact events
==============================================================================================

Reads the saved searches and dashboards of a search head, over its REST API or from files, and
says for each one what moving the named sourcetypes or indexes to compact events asks of it:

* unchanged        it runs as it is and returns what it returned on the raw events;
* needs tx         `tx` written in front of its search terms; it reads only the events' text;
* needs txf        `txf` written in front of its search terms;
* needs field map  it reads fields Splunk stored with the event (data models, `tstats`), which a
                   compact event has only through a field map;
* limit            a shape the app's README lists as behaving differently on compact events; the
                   reason quotes the README;
* not classified   the tool cannot tell: a macro it cannot expand, `map`, a subsearch whose
                   results become search terms, a dashboard token without a value, a shape not
                   measured;
* not affected     it reads none of the moved data.

Every verdict rests on a measured result or on a sentence of the README, and the reason says
which. What was measured (Splunk Enterprise 10.4.3, the Windows add-on 12.0.0, CIM 8.8.0, 8,311
Windows Security events indexed raw, compact with tenx_sourcetype, and compact through a field
map):

* without a field map, a search over compact events finds an event only where its words are
  values ("Kerberos": 0 of 21; "NULL SID": 0 of 107) and its original sourcetype not at all
  (`sourcetype=XmlWinEventLog`: 0 of 8,311); with `txf` in front, 21, 107 and 8,311; `stats` and
  `tstats` by index, host and source count compact events as raw ones;
* through a field map, a field comparison returns what it returns on raw events, also where the
  value is template text (LogonProcessName=Kerberos 21, SubjectUserSid="NULL SID" 71; EventCode,
  ObjectType, wildcard values, action, user, tag, eventtype and Logon_Type equal too), and so does
  `sourcetype=XmlWinEventLog` (the map renames the event); a word of the text does not (Kerberos
  0 of 21), nor a command that reads `_raw` (`rex`, `search <word>`), nor punct and linecount,
  nor `tstats` on sourcetype (0 of 8,311); `tstats` by index, host and source does;
* `txf` on mapped events finds the words and the text again (21 of 21, 107 of 107).

The edit printed for `tx` and `txf` puts the index, host, source and time terms written at the
top level of the search before the macro and every other term after it, as the README's Usage
section asks (time modifiers before the macro, the original sourcetype after `txf`).

Usage
-----
    tenx_search_report.py --splunkd https://<search head>:8089 --sourcetype XmlWinEventLog \\
        [--index wineventlog] [--field-map XmlWinEventLog] [--app <app>] [--csv report.csv]
    tenx_search_report.py --dir <folder of savedsearches.conf, macros.conf and dashboard files> \\
        --sourcetype XmlWinEventLog [--field-map XmlWinEventLog] [--csv report.csv]

Over REST the tool reads saved searches and views, and expands each search's macros with Splunk's
search parser (search/parser with parse_only, which runs nothing); it starts no search job.
Credentials come from TENX_SPLUNKD_TOKEN (a Splunk authentication token) or TENX_SPLUNKD_AUTH
(user:password).

Standard library only.
"""

import argparse
import csv
import fnmatch
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET

# The app's own modules sit beside this file; found also when Python runs isolated (-I) or from another folder.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tenx_prefilter_parser as pp  # noqa: E402

UNCHANGED = 'unchanged'
NEEDS_TX = 'needs tx'
NEEDS_TXF = 'needs txf'
NEEDS_MAP = 'needs field map'
LIMIT = 'limit'
NOT_CLASSIFIED = 'not classified'
NOT_AFFECTED = 'not affected'
# Worst first: the verdict of a search is the first of these that one of its findings gives.
VERDICTS = (NOT_CLASSIFIED, LIMIT, NEEDS_MAP, NEEDS_TXF, NEEDS_TX, UNCHANGED, NOT_AFFECTED)
# The order of the summary line.
SUMMARY_ORDER = (UNCHANGED, NEEDS_TX, NEEDS_TXF, NEEDS_MAP, LIMIT, NOT_CLASSIFIED, NOT_AFFECTED)

# Sentences of tenx-for-splunk/README.md as written there (line breaks aside; " [...] " stands for words left out);
# tests/test_tenx_search_report.py checks that each one is in the README.
README = {
	'words': 'A word that exists only in a template is not in the index, so a plain keyword search over compact '
		'data finds the events where the word is a value and misses the others.',
	'no_keywords': 'Without `tx`, a keyword search over compact data returns only the events where the word is a '
		'value, and a search with no keywords returns compact `~hash,...` rows.',
	'txf': '`tx` gives an expanded event the fields Splunk extracts from its text. The `txf` macro also applies '
		'the search-time knowledge of the event\'s original sourcetype, as its add-on defines it',
	'sourcetype': 'The sourcetype before or after `tx` is the compact sourcetype (`sourcetype=tenx_encoded`); each '
		'event\'s original sourcetype is in the field `tenx_sourcetype`.',
	'not_words': 'Under `NOT` through the `tx` and `txf` macros, two kinds of word can return fewer events than on '
		'the original lines: a wildcard inside a word (`Se*Privilege`), and `TERM()` of part of a longer term [...] '
		'Outside `NOT`, both match as on the original lines.',
	'pipe_not': 'Under `NOT` in `| tx`, the same words give the exact opposite of the word, which can be more events '
		'than Splunk\'s own `NOT` returns on the original lines.',
	'major_term': '`TERM()` of text that holds a major breaker, outside `NOT`, and `NOT CASE()` can return more events '
		'than on the original lines, never fewer. Under `NOT` through the macros, such a `TERM()` can return fewer.',
	'comma': 'A search word after `tx` with a comma outside quotes, such as `4625,` in `4625, 4624`, is matched '
		'literally by Splunk, so the search stops with a message. Remove the comma, or put the text in quotes.',
	'punct': '`linecount` and `punct` are computed by Splunk from the compact text it indexes, so on expanded '
		'events they differ from the raw event\'s.',
	'xml_profile': '`txf` gives the add-on\'s search-time fields, so three fields that depend on that indexing '
		'(`xmlns`, `vendor_privilege`, `privilege_id`) are not on expanded events.',
	'data_models': 'Data models, their accelerations, `tstats` and saved searches that do not use `tx` read the '
		'fields Splunk stored with an event. The field map writes a compact event\'s original fields while it is '
		'indexed, so these searches read them.',
	'tstats_sourcetype': '`tstats` reads the indexed sourcetype, which stays `tenx_win`: `| tstats count where '
		'sourcetype=XmlWinEventLog` counts uncompacted events only. Use `where (sourcetype=XmlWinEventLog OR '
		'tenx_sourcetype=XmlWinEventLog)`, or a data model, which applies the rename.',
	'eventtype_words': 'Event types that match words of the original text, such as `err0r` in the Windows add-on '
		'and `aws_cloudtrail_delete_events` in the AWS add-on, do not match mapped events.',
	'dest_4798': 'On Windows EventID 4798, 5156 and 5157, `dest` is the event\'s Computer and `src_ip` and '
		'`dest_ip` are not written.',
	'xml_blocks': 'The add-on\'s XML block fields `EventData_Xml` and `System_Props_Xml` are not written.',
	'privilege_dash': '`vendor_privilege` and `privilege_id` carry `-` on events where the raw event has neither.',
	'session_token': 'On CloudTrail, `responseElements.credentials.sessionToken` is not written.',
	'long_value': 'A plain search shows a mapped field longer than 1,000 characters, such as a PowerShell '
		'`ScriptBlockText`, cut to its first 1,000',
	'date_fields': 'Mapped events carry no `date_*` fields (`date_hour`, `date_wday` and the others), which Splunk '
		'gives raw events it reads from a file, so a detection that reads them, such as a business-hours one, '
		'matches no mapped event.',
}

TIME_FIELDS = pp.TIME_FIELDS | frozenset(('_index_earliest', '_index_latest'))
# Terms the edit puts before the macro: they select compact events as they select raw ones (README, Usage, Rules).
BEFORE_MACRO = frozenset(('index', 'host', 'source', 'splunk_server')) | TIME_FIELDS
# Fields compact events carry as the raw events do (measured: stats and tstats by host and source equal).
SAME_ON_COMPACT = frozenset(('index', 'host', 'source', 'splunk_server', '_time', '_indextime')) | TIME_FIELDS
METADATA = SAME_ON_COMPACT | frozenset(('sourcetype', 'eventtype', 'tag'))
MACROS_OF_THE_APP = re.compile(r'`(?:tx|txf|txf\([^`()]*\)|tenx-inflate|tenx-inflate-debug|tenx-events|tenx-templates)`')
APP_COMMANDS = frozenset(('tx', 'tenxsearch'))
DATA_MODEL_COMMANDS = frozenset(('datamodel', 'pivot'))
# Generating commands that read no indexed event.
NO_EVENTS = frozenset(('inputlookup', 'makeresults', 'rest', 'mstats', 'mcatalog', 'gentimes', 'inputcsv', 'history',
	'tenxreplay', 'tenxrecompile', 'tenxprefilter'))
# Generating commands that read what an index holds rather than its events.
INDEX_METADATA = frozenset(('metadata', 'eventcount', 'dbinspect', 'walklex', 'typeahead'))
OTHER_SEARCH = frozenset(('savedsearch', 'loadjob'))
SUBSEARCH_ONLY = frozenset(('multisearch', 'union', 'set'))
# Commands a subsearch may start with, written without the pipe.
GENERATING = NO_EVENTS | INDEX_METADATA | OTHER_SEARCH | SUBSEARCH_ONLY | DATA_MODEL_COMMANDS | frozenset((
	'tstats', 'from', 'tx', 'tenxsearch', 'inputintelligence', 'ldapsearch', 'dbxquery'))
TRANSFORMING = frozenset(('stats', 'chart', 'timechart', 'top', 'rare', 'contingency', 'xyseries', 'tstats', 'sistats',
	'sitimechart', 'sichart', 'sitop', 'sirare', 'geostats', 'pivot', 'associate', 'correlate', 'fieldsummary',
	'transpose', 'mstats'))
# Commands that read an event's text unless an option names another field: command -> that option.
TEXT_READERS = {'rex': 'field', 'regex': None, 'spath': 'input', 'xpath': 'field', 'xmlkv': None,
	'xmlunescape': None, 'kv': None, 'extract': None, 'multikv': None, 'erex': 'fromfield', 'cluster': 'field',
	'highlight': None, 'kvform': 'field'}
# Commands after which a `tx` search still reads only what tx gives (the text and the event's metadata).
TX_SAFE_COMMANDS = frozenset(('head', 'tail', 'reverse', 'stats', 'timechart', 'chart', 'table', 'fields', 'sort',
	'dedup', 'rex', 'top', 'rare', 'eventstats', 'streamstats', 'bin', 'bucket', 'where', 'eval', 'rename', 'search',
	'fillnull', 'sendemail', 'outputlookup', 'collect'))
# Words of those commands that are not field names.
SPL_WORDS = frozenset(('count', 'span', 'limit', 'by', 'as', 'over', 'and', 'or', 'not', 'in', 'like', 'true', 'false',
	'null', 'desc', 'asc', 'useother', 'usenull', 'showcount', 'showperc', 'percentfield', 'countfield', 'consecutive',
	'keepempty', 'sortby', 'mode', 'max_match', 'offset_field', 'outputnew', 'value', 'override', 'keeplast', 'bins',
	'start', 'end', 'aligntime', 'partial', 'cont', 'sep', 'format', 'append', 'allnum', 'delim', 'labelfield',
	'field', 'window', 'global', 'current', 'time_window', 'reset_before', 'reset_after', 'reset_on_change', 'sed'))
TSTATS_OPTIONS = re.compile(r'(?<![A-Za-z0-9_])(?:prestats|local|append|summariesonly|include_reduced_buckets|'
	r'allow_old_summaries|chunk_size|fillnull_value)\s*=\s*("(?:\\.|[^"\\])*"|\S+)')
LIMIT_FIELDS = (
	(re.compile(r'^date_\w+$'), 'date'),
	(re.compile(r'^(?:punct|linecount)$'), 'punct'),
	(re.compile(r'^(?:EventData_Xml|System_Props_Xml)$'), 'xml_blocks'),
	(re.compile(r'^(?:vendor_privilege|privilege_id)$'), 'privilege'),
	(re.compile(r'^xmlns$'), 'xmlns'),
	(re.compile(r'^responseElements\.credentials\.sessionToken$'), 'session_token'),
	(re.compile(r'^ScriptBlockText$'), 'long_value'),
)
EVENTTYPE_WORDS = frozenset(('err0r', 'aws_cloudtrail_delete_events'))
DEST_FIELDS = frozenset(('dest', 'src_ip', 'dest_ip'))
DEST_EVENTS = re.compile(r'(?<![0-9])(?:4798|5156|5157)(?![0-9])')
IDENT = re.compile(r'(?<![A-Za-z0-9_.:{}@$-])[A-Za-z_][A-Za-z0-9_.:{}@-]*')
OPERATOR_END = re.compile(r'(?:!=|<=|>=|=|<|>)$')
OPERATOR_START = re.compile(r'^(?:!=|<=|>=|=|<|>)')
TOKEN = re.compile(r'\$([^$\s|]+)(?:\|[a-z]+)?\$')
TOKEN_VALUE = 'tenx_token_value'


class Move(object):
	"""What moves to compact events: sourcetypes and indexes (fnmatch patterns), and the sourcetypes a field map covers."""

	def __init__(self, sourcetypes=(), indexes=(), mapped=()):
		self.sourcetypes = [s for s in sourcetypes if s]
		self.indexes = [i for i in indexes if i]
		self.mapped = [m for m in mapped if m]
		if not self.sourcetypes and not self.indexes:
			raise ValueError('name at least one --sourcetype or --index that moves')

	@staticmethod
	def match(value, patterns):
		v = value.lower()
		return any(fnmatch.fnmatchcase(v, p.lower()) or fnmatch.fnmatchcase(p.lower(), v) for p in patterns)

	def reads(self, sourcetypes, indexes):
		"""(whether a search naming these sourcetypes and indexes can read moved events, why not)."""
		if sourcetypes and self.sourcetypes and not any(self.match(s, self.sourcetypes) for s in sourcetypes):
			return False, 'It names sourcetype %s, which does not move.' % ', '.join(sourcetypes)
		if indexes and self.indexes and not any(self.match(i, self.indexes) for i in indexes):
			return False, 'It names index %s, which does not move.' % ', '.join(indexes)
		return True, None

	def is_mapped(self, sourcetypes):
		"""Whether every moved sourcetype the search can read is covered by a field map."""
		if not self.mapped:
			return False
		if not self.sourcetypes:
			return True
		named = [s for s in sourcetypes if self.match(s, self.sourcetypes)]
		return all(self.match(s, self.mapped) for s in (named or self.sourcetypes))


class Result(object):
	def __init__(self, verdict, reasons, edit=''):
		self.verdict, self.reasons, self.edit = verdict, list(dict.fromkeys(r for r in reasons if r)), edit

	@property
	def reason(self):
		return ' '.join(self.reasons)

	def __repr__(self):
		return 'Result(%r, %r, %r)' % (self.verdict, self.reasons, self.edit)


def worst(results):
	"""One Result for several findings: the worst verdict, with the reasons of that verdict and of the worse ones."""
	results = [r for r in results if r is not None]
	verdict = min((r.verdict for r in results), key=VERDICTS.index)
	reasons = [x for r in results if VERDICTS.index(r.verdict) <= VERDICTS.index(verdict) for x in r.reasons]
	if verdict == LIMIT:
		reasons += [x for r in results if r.verdict in (NEEDS_TX, NEEDS_TXF) for x in r.reasons]
	edits = [r.edit for r in results if r.edit]
	return Result(verdict, reasons, edits[0] if edits else '')


def readme(key):
	return 'README: "%s"' % README[key]


# -------------------------------------------------------------------------------------------
# SPL text

def _walk(text, on_char):
	"""Calls on_char(i, c, depth) for every character outside double quotes and backtick macro calls; depth counts
	square brackets and parentheses."""
	i, n, depth, quoted, tick = 0, len(text), 0, False, False
	while i < n:
		c = text[i]
		if quoted:
			if c == '\\':
				i += 2
				continue
			if c == '"':
				quoted = False
		elif tick:
			if c == '`':
				tick = False
		elif c == '"':
			quoted = True
		elif c == '`':
			tick = True
		else:
			if c in '[(':
				depth += 1
			elif c in '])':
				depth -= 1
			on_char(i, c, depth)
		i += 1


def strip_comments(text):
	"""The search without its comments (text between two runs of three backticks, outside quotes)."""
	out, i, n, quoted = [], 0, len(text), False
	while i < n:
		c = text[i]
		if quoted:
			out.append(c)
			if c == '\\' and i + 1 < n:
				out.append(text[i + 1])
				i += 2
				continue
			quoted = c != '"'
			i += 1
			continue
		if c == '"':
			quoted = True
		elif text.startswith('```', i):
			j = text.find('```', i + 3)
			i = n if j < 0 else j + 3
			out.append(' ')
			continue
		out.append(c)
		i += 1
	return ''.join(out)


def split_commands(text):
	"""The commands of a search: its text cut at the pipes outside quotes, subsearches, parentheses and macro calls."""
	cuts = []
	_walk(text, lambda i, c, d: cuts.append(i) if c == '|' and d == 0 else None)
	parts, start = [], 0
	for i in cuts + [len(text)]:
		parts.append(text[start:i].strip())
		start = i + 1
	return parts


def subsearches(text):
	"""The text of each top-level [subsearch] of `text`."""
	found, i, n, quoted, depth, start = [], 0, len(text), False, 0, 0
	while i < n:
		c = text[i]
		if quoted:
			if c == '\\':
				i += 2
				continue
			if c == '"':
				quoted = False
		elif c == '"':
			quoted = True
		elif c == '[':
			if depth == 0:
				start = i + 1
			depth += 1
		elif c == ']' and depth > 0:
			depth -= 1
			if depth == 0:
				found.append(text[start:i].strip())
		i += 1
	return found


def command_name(segment):
	m = re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)', segment)
	return m.group(1).lower() if m else ''


def command_args(segment):
	m = re.match(r'\s*[A-Za-z_][A-Za-z0-9_]*', segment)
	return segment[m.end():].strip() if m else segment.strip()


def without_quotes(text):
	return re.sub(r'"(?:\\.|[^"\\])*"', ' ', text)


def identifiers(text):
	"""The names a stretch of SPL uses: identifiers outside quotes, not called as functions."""
	plain = without_quotes(text)
	return [m.group(0) for m in IDENT.finditer(plain) if plain[m.end():m.end() + 1] != '(']


def option(args, name):
	m = re.search(r'(?<![A-Za-z0-9_])%s\s*=\s*("(?:\\.|[^"\\])*"|\S+)' % re.escape(name), args)
	return pp.unquote(m.group(1)) if m else None


def parse_terms(text):
	"""(leaves, Parser) of a search command's terms; each leaf is (negated, node). Raises pp.Unparsed."""
	parser = pp.Parser(pp.tokenize(text))
	tree, out = parser.parse(), []

	def walk(n, negated):
		if n[0] in ('and', 'or'):
			for child in n[1]:
				walk(child, negated)
		elif n[0] == 'not':
			walk(n[1], not negated)
		elif n[0] != 'true':
			out.append((negated, n))
	walk(tree, False)
	return out, parser


def named(leaves, field):
	"""The values the terms select for `field` (=, ::, IN), not under NOT."""
	found = []
	for negated, n in leaves:
		if negated or n[0] not in ('field', 'in') or n[1].lower() != field:
			continue
		if n[0] == 'field' and n[2] in ('=', '::'):
			found.append(n[3])
		elif n[0] == 'in':
			found.extend(v for v in n[2] if v)
	return [v for v in dict.fromkeys(found) if v]


# Splunk's default breakers (segmenters.conf [indexing]), as the app's prefilter reads them.
MAJOR_CHARS = "[]<>(){}|!;,'\"\n\r \t&?+"
MAJOR_SEQUENCES = ("%2526", "%2520", "%21", "%26", "%3B", "%7C", "%20", "%2B", "%3D", "--", "%5D", "%5B", "%3A",
	"%0A", "%2C", "%28", "%29")
MINOR_CHARS = "/:=@.-$#%\\_"


def midword_wildcard(word):
	"""A word Splunk matches as its prefix after a pipe: a `*` after its first character and before its last, and no
	breaker of its own (Se*Privilege; not *Privilege, Se*, 10.0*14)."""
	if not word or word[0] == '*' or '*' not in word.rstrip('*'):
		return False
	return not any(c in MAJOR_CHARS or c in MINOR_CHARS or c.isspace() for c in word)


def term_text(node):
	"""The text inside TERM(...) of a parse node, or None."""
	m = re.match(r'^TERM\((.*)\)$', node[1], re.S | re.I) if node[0] == 'unknown' else None
	return m.group(1) if m else None


def major_breaker(text):
	return any(c in MAJOR_CHARS or c.isspace() for c in text) or any(q in text for q in MAJOR_SEQUENCES)


def minor_breaker(text):
	return any(c in MINOR_CHARS for c in text)


def word_limits(leaves, pipe_tx=False):
	"""The README's limits of the words a search gives `tx` or `txf` (`| tx` with pipe_tx): Results."""
	found = []
	for negated, n in leaves:
		term = term_text(n)
		if term is not None and major_breaker(term):
			found.append(Result(LIMIT, [readme('major_term')]))
		elif negated and n[0] == 'unknown' and re.match(r'^CASE\(', n[1], re.I):
			found.append(Result(LIMIT, [readme('major_term')]))
		elif negated and ((n[0] == 'text' and midword_wildcard(n[1])) or (term is not None and minor_breaker(term))):
			found.append(Result(LIMIT, [readme('not_words')]))
			if pipe_tx:
				found.append(Result(LIMIT, [readme('pipe_not')]))
	return found


# -------------------------------------------------------------------------------------------
# The edit

def chunks(base):
	"""The top-level terms of a base search as written; a comparison written with spaces is one term."""
	out, buf, i, n, quoted, tick, depth = [], [], 0, len(base), False, False, 0
	while i < n:
		c = base[i]
		if quoted:
			buf.append(c)
			if c == '\\' and i + 1 < n:
				buf.append(base[i + 1])
				i += 2
				continue
			if c == '"':
				quoted = False
		elif tick:
			buf.append(c)
			if c == '`':
				tick = False
		elif c == '"':
			quoted = True
			buf.append(c)
		elif c == '`':
			tick = True
			buf.append(c)
		elif c in '([':
			depth += 1
			buf.append(c)
		elif c in ')]':
			depth -= 1
			buf.append(c)
		elif c.isspace() and depth <= 0:
			if buf:
				out.append(''.join(buf))
				buf = []
		else:
			buf.append(c)
		i += 1
	if buf:
		out.append(''.join(buf))
	merged = []
	for piece in out:
		if merged and merged[-1] not in ('AND', 'OR', 'NOT') and (OPERATOR_START.match(piece) or
				OPERATOR_END.search(merged[-1])):
			merged[-1] += ' ' + piece
		else:
			merged.append(piece)
	return merged


def _goes_before(term):
	m = re.match(r'^([A-Za-z_]+)\s*(?:=|::)\s*\S', term)
	return bool(m) and m.group(1).lower() in BEFORE_MACRO and '`' not in term


def edit_with_macro(search, macro):
	"""
	`search` with `macro` written in front of its search terms: the top-level index, host, source and time terms
	before it, every other term after it, in their order. None when the search starts with a generating command.
	"""
	text = (search or '').strip()
	if not text or text.startswith('|'):
		return None
	parts = split_commands(text)
	first, lead = parts[0], ''
	m = re.match(r'^search\s+', first)
	if m:
		lead, first = first[:m.end()], first[m.end():]
	items = chunks(first)
	before, after = [], []
	for k, t in enumerate(items):
		joined = (k > 0 and items[k - 1] in ('OR', 'NOT')) or (k + 1 < len(items) and items[k + 1] == 'OR')
		(before if _goes_before(t) and not joined else after).append(t)
	body = ' '.join(before + ['`%s`' % macro] + after)
	return lead + body + ''.join(' | ' + p for p in parts[1:])


# -------------------------------------------------------------------------------------------
# One search

def classify(search, move, kind='report', expanded=None):
	"""
	The verdict for one search. `search` is the search as written; `expanded` the same with its macros expanded,
	None when it holds none, or a reason starting with "!" when they could not be expanded.
	"""
	search = strip_comments(search or '').strip()
	if expanded is not None and expanded.startswith('!'):
		return Result(NOT_CLASSIFIED, [expanded[1:]])
	text = strip_comments(expanded if expanded is not None else search).strip()
	if not text:
		return Result(NOT_AFFECTED, ['The search is empty.'])
	first_written = [p for p in split_commands(search) if p][:1]
	if MACROS_OF_THE_APP.search(search) or (first_written and command_name(first_written[0]) in APP_COMMANDS):
		return _already_compact(search, first_written[0] if first_written else '')
	parts = split_commands(text)
	generating = not parts[0]
	if generating:
		parts = parts[1:]
	names = [command_name(p) for p in parts]
	if 'map' in names:
		return Result(NOT_CLASSIFIED, ['It runs `map`, whose searches are built from results.'])
	for sub in subsearches(text):
		inner = classify(sub if sub.startswith('|') or command_name(sub) not in GENERATING else '| ' + sub, move, kind)
		if inner.verdict == NOT_CLASSIFIED:
			return Result(NOT_CLASSIFIED, ['A subsearch could not be classified (%s): [%s]' % (inner.reason.rstrip('.'),
				sub[:120])])
		if inner.verdict != NOT_AFFECTED:
			return Result(NOT_CLASSIFIED, ['A subsearch reads data that moves: [%s]' % sub[:120]])
	first = parts[0]
	if generating and names[0] != 'search':
		return _generating(names[0], command_args(first), parts[1:], move, kind)
	base = command_args(first) if names[0] == 'search' and re.match(r'^search\b', first) else first
	return _search(base, parts[1:], move, kind, search, expanded is not None)


def _already_compact(search, first):
	"""A search written for compact events: unchanged, or a limit the README states for the words it gives the app."""
	found = [Result(UNCHANGED, ['It already searches compact events with the app\'s macros or commands.'])]
	words = pp.text_after_macro(search)
	pipe_tx = words is None and command_name(first) == 'tx'
	if pipe_tx:
		words = command_args(first)
	if words is not None:
		try:
			found += word_limits(parse_terms(words)[0], pipe_tx)
		except pp.Unparsed:
			pass
	return worst(found)


def _generating(name, args, rest, move, kind):
	if name in NO_EVENTS:
		return Result(NOT_AFFECTED, ['`%s` reads no indexed events.' % name])
	if name in OTHER_SEARCH:
		return Result(NOT_CLASSIFIED, ['It runs another saved search or job (`%s`).' % name])
	if name in SUBSEARCH_ONLY:
		return Result(NOT_AFFECTED, ['Its subsearches read none of the moved data.'])
	if name in INDEX_METADATA:
		reads, why = move.reads(pp._specifiers(args, 'sourcetype'), pp._specifiers(args, 'index'))
		if not reads:
			return Result(NOT_AFFECTED, [why])
		return Result(NOT_CLASSIFIED, ['`%s` reads what the moved indexes hold: not measured.' % name])
	if (name in DATA_MODEL_COMMANDS or (name == 'from' and re.match(r'datamodel\b', args, re.I))
			or (name == 'tstats' and re.search(r'(?<![A-Za-z0-9_])datamodel\s*=', args, re.I))):
		if not move.is_mapped([]):
			return Result(NEEDS_MAP, [readme('data_models')])
		pipeline = _pipeline(rest)
		found = [Result(UNCHANGED, ['It reads a data model: the field map writes the fields data models read (data '
			'models measured equal to raw).'])]
		found += _map_limits(args + ' | ' + ' | '.join(rest), [])
		if pipeline['reads_text'] or (name == 'datamodel' and pipeline['returns_events'] and kind != 'alert'):
			found.append(Result(NEEDS_TXF, ['A later command reads the events\' text, which on mapped events is the '
				'compact text.']))
		return worst(found)
	if name == 'tstats':
		return _tstats(args, move)
	return Result(NOT_CLASSIFIED, ['Its first command, `%s`, is not one this tool reads.' % name])


def _tstats(args, move):
	args = TSTATS_OPTIONS.sub(' ', args)
	m = re.search(r'(?<![A-Za-z0-9_])where(?![A-Za-z0-9_])', args)
	head, where = (args[:m.start()], args[m.end():]) if m else (args, '')
	b = re.search(r'(?<![A-Za-z0-9_])by(?![A-Za-z0-9_])', where or head)
	if where:
		where, by = (where[:b.start()], where[b.end():]) if b else (where, '')
	else:
		head, by = (head[:b.start()], head[b.end():]) if b else (head, '')
	try:
		leaves, _ = parse_terms(where)
	except pp.Unparsed as e:
		return Result(NOT_CLASSIFIED, ['Its `where` clause could not be read (%s).' % e])
	sts, idxs = named(leaves, 'sourcetype'), named(leaves, 'index')
	reads, why = move.reads(sts, idxs)
	if not reads:
		return Result(NOT_AFFECTED, [why])
	fields = set(n[1] for _, n in leaves if n[0] in ('field', 'in'))
	fields |= set(identifiers(re.sub(r'(?i)\b(?:as|span)\s*=?\s*\S+', ' ', by)))
	fields |= set(identifiers(re.sub(r'(?i)\bas\s+\S+', ' ', head))) - {'count'}
	fields = {f for f in fields if f.lower() not in ('as', 'span', 'count')}
	if any(n[0] in ('text', 'unknown') for _, n in leaves):
		return Result(NOT_CLASSIFIED, ['Its `where` clause holds words: not measured.'])
	if 'sourcetype' in fields:
		if move.is_mapped(sts):
			return Result(LIMIT, [readme('tstats_sourcetype')])
		return Result(LIMIT, [readme('sourcetype'), 'Write where (sourcetype=<original> OR tenx_sourcetype=<original>) '
			'(measured equal to raw).'])
	if fields & {'punct', 'linecount'}:
		return Result(LIMIT, [readme('punct')])
	if fields <= SAME_ON_COMPACT:
		return Result(UNCHANGED, ['`tstats` by index, host and source counts compact events as raw ones (measured '
			'equal).'])
	return Result(NOT_CLASSIFIED, ['`tstats` on fields other than index, host, source and sourcetype (%s): not '
		'measured.' % ', '.join(sorted(fields - SAME_ON_COMPACT))])


def _pipeline(rest):
	"""What the commands after the first one read and return."""
	reads_text, transforming, keeps_raw, tx_safe = False, False, True, True
	names, produced = [], set()
	for seg in rest:
		name, args = command_name(seg), command_args(seg)
		if not name:
			continue
		tx_safe = tx_safe and name in TX_SAFE_COMMANDS
		listed = args.replace(',', ' ').split()
		if name in ('table', 'fields'):
			if '_raw' in listed and not args.startswith('-'):
				reads_text = True
		elif '_raw' in without_quotes(seg):
			reads_text = True
		if name in TEXT_READERS:
			target = option(args, TEXT_READERS[name]) if TEXT_READERS[name] else None
			if name == 'regex':
				m = re.match(r'\s*([A-Za-z_][A-Za-z0-9_.]*)\s*!?=', args)
				target = m.group(1) if m else None
			if target in (None, '_raw'):
				reads_text = True
		if name == 'search':
			try:
				leaves, _ = parse_terms(args)
				if any(n[0] in ('text', 'unknown') and n[1].strip('*') for _, n in leaves):
					reads_text = True
			except pp.Unparsed:
				reads_text = True
		if name == 'where' and re.search(r'searchmatch\s*\(', args):
			reads_text = True
		if name == 'transaction' and re.search(r'(?:startswith|endswith)\s*=\s*(?!eval\s*\()', args):
			reads_text = True
		if name in TRANSFORMING:
			transforming = True
		if name == 'table' or (name == 'fields' and not args.startswith('-') and not args.startswith('+ ')):
			keeps_raw = '_raw' in listed or '*' in listed
		elif name == 'fields' and args.startswith('-') and '_raw' in listed:
			keeps_raw = False
		produced.update(re.findall(r'\?<([A-Za-z_][A-Za-z0-9_]*)>', seg))
		produced.update(re.findall(r'(?i)\bas\s+"?([A-Za-z_][A-Za-z0-9_.]*)', seg))
		if name == 'eval':
			produced.update(re.findall(r'(?:^|,)\s*"?([A-Za-z_][A-Za-z0-9_.]*)"?\s*=(?!=)', args))
		if name == 'rename':
			produced.update(re.findall(r'(?i)\bas\s+"?([A-Za-z_][A-Za-z0-9_.]*)', args))
		names.extend(identifiers(args))
	return {'reads_text': reads_text, 'returns_events': not transforming and keeps_raw, 'names': names,
		'produced': produced, 'tx_safe': tx_safe}


def _limit_keys(names):
	found = set()
	for n in names:
		for pattern, key in LIMIT_FIELDS:
			if pattern.match(n):
				found.add(key)
	return found


def _map_limits(text, leaves):
	"""The README's limits of the field map that a search's text touches."""
	names = set(identifiers(text)) | set(n[1] for _, n in leaves if n[0] in ('field', 'in'))
	keys, results = _limit_keys(names), []
	for key, quote in (('date', 'date_fields'), ('punct', 'punct'), ('xml_blocks', 'xml_blocks'),
			('privilege', 'privilege_dash'), ('session_token', 'session_token'), ('long_value', 'long_value')):
		if key in keys:
			results.append(Result(LIMIT, [readme(quote)]))
	if set(named(leaves, 'eventtype')) & EVENTTYPE_WORDS:
		results.append(Result(LIMIT, [readme('eventtype_words')]))
	if names & DEST_FIELDS and DEST_EVENTS.search(text):
		results.append(Result(LIMIT, [readme('dest_4798')]))
	return results


def _search(base, rest, move, kind, written, expanded):
	try:
		leaves, parser = parse_terms(base)
	except pp.Unparsed as e:
		return Result(NOT_CLASSIFIED, ['Its search terms could not be read (%s).' % e])
	sts, idxs = named(leaves, 'sourcetype'), named(leaves, 'index')
	reads, why = move.reads(sts, idxs)
	if not reads:
		return Result(NOT_AFFECTED, [why])
	if subsearches(base):
		return Result(NOT_CLASSIFIED, ['A subsearch writes some of its search terms.'])
	pipeline = _pipeline(rest)
	words = [n for _, n in leaves if n[0] in ('text', 'unknown') and n[1].strip('*')]
	field_names = [n[1].lower() for _, n in leaves if n[0] in ('field', 'in')]
	all_text = base + ' | ' + ' | '.join(rest)
	keys = _limit_keys(set(identifiers(all_text)) | set(field_names))
	findings = []

	def macro_limits():
		found = word_limits(leaves)
		if parser.unquoted_comma:
			found.append(Result(LIMIT, [readme('comma')]))
		if 'punct' in keys:
			found.append(Result(LIMIT, [readme('punct')]))
		return found

	if move.is_mapped(sts):
		if words:
			findings.append(Result(NEEDS_TXF, [readme('words'), 'The field map writes fields, not the words of the text; '
				'`txf` expands mapped events too (measured equal to raw).']))
			findings += macro_limits()
		elif pipeline['reads_text']:
			findings.append(Result(NEEDS_TXF, ['A later command reads the events\' text (`_raw`), which on mapped events '
				'is the compact text; `txf` expands it (measured equal to raw).']))
		elif pipeline['returns_events'] and kind != 'alert':
			findings.append(Result(NEEDS_TXF, ['It returns the events: on mapped events their text is the compact text '
				'and their fields the raw event\'s; `txf` shows the original text.']))
		else:
			why = ['Through the field map, field comparisons and metadata return what they return on raw events, '
				'template-text values included (measured).']
			if pipeline['returns_events']:
				why.append('It fires on the number of events, which is equal; the events in its results show the '
					'compact text.')
			findings.append(Result(UNCHANGED, why))
		findings += _map_limits(all_text, leaves)
	else:
		other = [f for f in field_names if f not in SAME_ON_COMPACT]
		pipe_fields = [n for n in pipeline['names'] if n.lower() not in SPL_WORDS and n not in pipeline['produced']]
		reads_meta_only = (pipeline['tx_safe'] and not pipeline['reads_text']
			and all(n in SAME_ON_COMPACT or n == '_raw' for n in pipe_fields))
		if not words and not other and reads_meta_only and not pipeline['returns_events']:
			findings.append(Result(UNCHANGED, ['It reads only index, host, source and time, which compact events carry '
				'as raw ones do (measured: counts by host and source equal).']))
		elif not other and reads_meta_only:
			findings.append(Result(NEEDS_TX, [readme('words') if words else readme('no_keywords'),
				'It reads only the events\' text and metadata, so `tx` serves it (`txf` too).']))
		else:
			reasons = [readme('words')] if words else ([] if field_names else [readme('no_keywords')])
			reasons.append(readme('txf') + '.')
			if 'sourcetype' in field_names:
				reasons.append(readme('sourcetype'))
			findings.append(Result(NEEDS_TXF, reasons))
		findings += macro_limits()
		if 'xmlns' in keys or 'privilege' in keys:
			findings.append(Result(LIMIT, [readme('xml_profile')]))
		if 'date' in keys:
			findings.append(Result(NOT_CLASSIFIED, ['It reads `date_*` fields: through `txf`, not measured.']))
	result = worst(findings)
	if any(f.verdict in (NEEDS_TX, NEEDS_TXF) for f in findings):
		macro = 'txf' if any(f.verdict == NEEDS_TXF for f in findings) else 'tx'
		source = written
		if expanded and _time_in_macro(written, base):
			source = 'search ' + base.strip() + ''.join(' | ' + p for p in rest)
		result.edit = edit_with_macro(source, macro) or ''
	return result


def _time_in_macro(written, base):
	"""Whether the expanded search terms hold a time term the written ones do not show (a macro's)."""
	first = split_commands(written)[0] if written else ''
	for field in TIME_FIELDS:
		pattern = r'(?<![A-Za-z0-9_])%s\s*=' % field
		if re.search(pattern, base) and not re.search(pattern, first):
			return True
	return False


# -------------------------------------------------------------------------------------------
# Macros, conf files, dashboards

def read_conf_text(text):
	"""Stanzas of a .conf file: name -> {key: value}; a line ending in a backslash continues on the next."""
	stanzas, current, lines, i = {}, None, text.splitlines(), 0
	while i < len(lines):
		line = lines[i]
		i += 1
		stripped = line.strip()
		if not stripped or stripped.startswith('#'):
			continue
		if stripped.startswith('[') and stripped.endswith(']'):
			current = stripped[1:-1]
			stanzas.setdefault(current, {})
			continue
		if '=' not in line or current is None:
			continue
		key, value = line.split('=', 1)
		value = value.strip()
		while value.endswith('\\') and i < len(lines):
			value = value[:-1] + '\n' + lines[i].strip()
			i += 1
		stanzas[current][key.strip()] = value
	return stanzas


class Macros(object):
	"""Macro definitions from macros.conf files; expand() writes them into a search as Splunk does, text for text."""

	def __init__(self, stanzas=None):
		self.defs = dict(stanzas or {})

	def add(self, stanzas):
		self.defs.update(stanzas)

	def expand(self, text, depth=0):
		"""(expanded text, None) or (None, reason)."""
		if depth > 20:
			return None, 'Its macros nest more than 20 deep.'
		out, i, n, quoted, changed = [], 0, len(text), False, False
		while i < n:
			c = text[i]
			if quoted:
				out.append(c)
				if c == '\\' and i + 1 < n:
					out.append(text[i + 1])
					i += 2
					continue
				quoted = c != '"'
				i += 1
				continue
			if c == '"':
				quoted = True
			elif c == '`':
				j = text.find('`', i + 1)
				if j < 0:
					return None, 'A backtick has no pair.'
				body, why = self._one(text[i + 1:j])
				if body is None:
					return None, why
				out.append(body)
				changed, i = True, j + 1
				continue
			out.append(c)
			i += 1
		result = ''.join(out)
		return self.expand(result, depth + 1) if changed else (result, None)

	def _one(self, call):
		m = re.match(r'^\s*([^(\s]+)\s*(?:\((.*)\))?\s*$', call, re.S)
		if not m:
			return None, 'Macro call `%s` was not read.' % call
		name, arg_text = m.group(1), m.group(2)
		args = _macro_args(arg_text) if arg_text is not None and arg_text.strip() else []
		stanza = self.defs.get('%s(%d)' % (name, len(args)) if args else name)
		if stanza is None:
			return None, 'Macro `%s` has no definition in what was read.' % call
		if str(stanza.get('iseval', '0')).strip().lower() in ('1', 'true', 't', 'yes'):
			return None, 'Macro `%s` is computed with eval (iseval).' % name
		body = stanza.get('definition', '')
		for k, v in zip([a.strip() for a in stanza.get('args', '').split(',') if a.strip()], args):
			body = body.replace('$%s$' % k, v)
		return body, None


def _macro_args(text):
	args, buf, quoted, depth, i = [], [], False, 0, 0
	while i < len(text):
		c = text[i]
		if quoted:
			buf.append(c)
			if c == '\\' and i + 1 < len(text):
				buf.append(text[i + 1])
				i += 2
				continue
			quoted = c != '"'
		elif c == '"':
			quoted = True
			buf.append(c)
		elif c == ',' and depth == 0:
			args.append(''.join(buf).strip())
			buf = []
		else:
			depth += 1 if c == '(' else -1 if c == ')' else 0
			buf.append(c)
		i += 1
	args.append(''.join(buf).strip())
	return [pp.unquote(a) for a in args]


def saved_search_kind(settings):
	"""alert or report, as Splunk Web lists them."""
	def on(key):
		return str(settings.get(key, '')).strip().lower() in ('1', 'true', 't', 'yes')
	scheduled = on('is_scheduled') or on('enableSched')
	alert_type = str(settings.get('alert_type', '') or '').strip().lower()
	actions = str(settings.get('actions', '') or '').strip() or any(
		k.startswith('action.') and k.count('.') == 1 and on(k) for k in settings)
	realtime = str(settings.get('dispatch.earliest_time', '')).startswith('rt')
	condition = alert_type not in ('', 'always') or bool(str(settings.get('counttype', '') or '').strip())
	if scheduled and (condition or on('alert.track') or actions or realtime):
		return 'alert'
	return 'report'


class Item(object):
	"""One object of the report: a saved search, or one search of a dashboard."""

	def __init__(self, name, app, owner, kind, search, ref=None, base_id=None, sid=None):
		self.name, self.app, self.owner, self.kind, self.search = name, app, owner, kind, search
		self.ref, self.base_id, self.sid = ref, base_id, sid
		self.base, self.post, self.result = None, [], None


def dashboard_items(name, app, owner, xml_text):
	"""The searches of one dashboard (Simple XML or Dashboard Studio) as Items, post-processes linked to their bases."""
	try:
		root = ET.fromstring(xml_text.encode('utf-8') if isinstance(xml_text, str) else xml_text)
	except ET.ParseError as e:
		return [Item(name, app, owner, 'panel', None, ref='!The dashboard XML could not be read (%s).' % e)]
	if root.find('definition') is not None:
		try:
			definition = json.loads(root.find('definition').text or '{}')
		except ValueError as e:
			return [Item(name, app, owner, 'panel', None, ref='!The dashboard definition is not JSON (%s).' % e)]
		return studio_items(name, app, owner, definition)
	if root.tag not in ('dashboard', 'form'):
		return []
	defaults = {}
	for inp in root.iter('input'):
		for tag in ('default', 'initialValue'):
			el = inp.find(tag)
			if inp.get('token') and el is not None and el.text is not None:
				defaults.setdefault(inp.get('token'), el.text.strip())
	for setter in root.iter('set'):
		if setter.get('token') and setter.text is not None:
			defaults.setdefault(setter.get('token'), setter.text.strip())
	parents = dict((c, p) for p in root.iter() for c in p)
	items, number = [], 0
	for el in root.iter():
		if el.tag == 'search':
			q = el.find('query')
			query, ref, base_id, sid = (q.text if q is not None else None), el.get('ref'), el.get('base'), el.get('id')
		elif el.tag in ('searchString', 'searchTemplate'):
			query, ref, base_id, sid = el.text, None, None, None
		elif el.tag == 'searchName':
			query, ref, base_id, sid = None, (el.text or '').strip(), None, None
		else:
			continue
		number += 1
		kind, title, p = 'panel', None, parents.get(el)
		while p is not None:
			if p.tag == 'input':
				kind = 'input'
			t = p.find('label' if p.tag == 'input' else 'title')
			if title is None and t is not None and t.text and p.tag not in ('dashboard', 'form'):
				title = t.text.strip()
			p = parents.get(p)
		label = '%s / %s' % (name, title or ('search %s' % sid if sid else 'search %d' % number))
		items.append(Item(label, app, owner, kind, substitute(query, defaults), ref=ref, base_id=base_id, sid=sid))
	return _link_bases(items)


def studio_items(name, app, owner, definition):
	sources, inputs = definition.get('dataSources') or {}, (definition.get('inputs') or {}).values()
	defaults, titles, input_ds = {}, {}, set()
	for inp in inputs:
		opts = inp.get('options') or {}
		if opts.get('token') and 'defaultValue' in opts and not isinstance(opts['defaultValue'], (dict, list)):
			defaults[opts['token']] = str(opts['defaultValue'])
		ds = (inp.get('dataSources') or {}).get('primary')
		if ds:
			input_ds.add(ds)
	for viz in (definition.get('visualizations') or {}).values():
		ds = (viz.get('dataSources') or {}).get('primary')
		if ds and viz.get('title'):
			titles.setdefault(ds, viz['title'])
	items = []
	for ds_id, ds in sources.items():
		opts = ds.get('options') or {}
		label = '%s / %s' % (name, titles.get(ds_id) or ds.get('name') or ds_id)
		kind = 'input' if ds_id in input_ds else 'panel'
		if ds.get('type') == 'ds.search':
			items.append(Item(label, app, owner, kind, substitute(opts.get('query'), defaults), sid=ds_id))
		elif ds.get('type') == 'ds.chain':
			items.append(Item(label, app, owner, kind, substitute(opts.get('query'), defaults), base_id=opts.get('extend'),
				sid=ds_id))
		elif ds.get('type') == 'ds.savedSearch':
			items.append(Item(label, app, owner, kind, None, ref=opts.get('ref'), sid=ds_id))
	return _link_bases(items)


def _link_bases(items):
	by_id = dict((i.sid, i) for i in items if i.sid)
	for item in items:
		if item.base_id:
			item.base = by_id.get(item.base_id)
			if item.base is None:
				item.ref = '!It post-processes base search %s, which the dashboard does not define.' % item.base_id
			else:
				item.base.post.append(item)
	for item in items:
		if item.post and item.base is None:
			item.kind = 'base search'
	return items


def substitute(query, defaults):
	"""A dashboard search with its tokens replaced by their default values. A token without one is replaced by a
	placeholder where it is a field's value, and otherwise makes the text a reason, starting with '!'."""
	if query is None:
		return None
	missing = []

	def one(m):
		if m.group(1) in defaults:
			return defaults[m.group(1)]
		before = query[:m.start()]
		if re.search(r'(?:!=|<=|>=|=|<|>)\s*"?$', before) and not re.search(
				r'(?<![A-Za-z0-9_])(?:index|sourcetype)\s*(?:=|::)\s*"?$', before):
			return TOKEN_VALUE
		missing.append(m.group(1))
		return m.group(0)
	text = TOKEN.sub(one, query)
	return '!Dashboard token $%s$ has no default value.' % missing[0] if missing else text


# -------------------------------------------------------------------------------------------
# Sources: files and REST

def _path_scope(path, root):
	"""(app, owner) of a file under .../apps/<app>/... or .../users/<owner>/<app>/..."""
	parts = os.path.relpath(path, root).split(os.sep)
	for k, p in enumerate(parts[:-1]):
		if p == 'users' and k + 2 < len(parts) - 1:
			return parts[k + 2], parts[k + 1]
		if p == 'apps' and k + 1 < len(parts) - 1:
			return parts[k + 1], 'nobody'
	for k, p in enumerate(parts[:-1]):
		if p in ('default', 'local') and k > 0:
			return parts[k - 1], 'nobody'
	return '-', '-'


def _read(path):
	with open(path, encoding='utf-8', errors='replace') as f:
		return f.read()


class DirSource(object):
	"""savedsearches.conf, macros.conf and dashboard files under a folder (default/ read before local/)."""

	def __init__(self, root, apps=()):
		paths = []
		for dirpath, dirnames, filenames in os.walk(root):
			dirnames.sort()
			paths += [os.path.join(dirpath, f) for f in sorted(filenames)]
		paths.sort(key=lambda p: (os.sep + 'local' + os.sep in p, p))
		self.macros, saved, self.dashboards = Macros(), {}, []
		for path in paths:
			if os.path.basename(path) == 'macros.conf':
				self.macros.add(read_conf_text(_read(path)))
		for path in paths:
			base = os.path.basename(path)
			app, owner = _path_scope(path, root)
			if apps and app not in apps:
				continue
			if base == 'savedsearches.conf':
				for stanza, settings in read_conf_text(_read(path)).items():
					if stanza != 'default':
						saved.setdefault((app, owner, stanza), {}).update(settings)
			elif base.endswith('.xml'):
				text = _read(path)
				if re.search(r'<(?:dashboard|form)\b', text[:4000]):
					self.dashboards += dashboard_items(os.path.splitext(base)[0], app, owner, text)
			elif base.endswith('.json'):
				try:
					definition = json.loads(_read(path))
				except ValueError:
					continue
				if isinstance(definition, dict) and 'dataSources' in definition:
					self.dashboards += studio_items(os.path.splitext(base)[0], app, owner, definition)
		self.saved = [Item(stanza, app, owner, saved_search_kind(s), s.get('search', ''))
			for (app, owner, stanza), s in sorted(saved.items()) if 'search' in s]

	def items(self):
		return self.saved, self.dashboards

	def expand(self, item, text):
		text = strip_comments(text)
		if '`' not in text:
			return None
		expanded, why = self.macros.expand(text)
		return expanded if expanded is not None else '!' + why


class RestSource(object):
	"""Saved searches and views over the management port; macros expanded by Splunk's search parser."""

	def __init__(self, splunkd, apps=()):
		self.splunkd, self.apps = splunkd, set(apps)

	def _entries(self, path):
		res = self.splunkd.call('GET', path, {'count': 0})
		return [e for e in res.get('entry', []) if not self.apps or e.get('acl', {}).get('app') in self.apps]

	def items(self):
		saved, dashboards = [], []
		for e in self._entries('/servicesNS/-/-/saved/searches'):
			c, acl = e.get('content', {}), e.get('acl', {})
			saved.append(Item(e.get('name'), acl.get('app', '-'), acl.get('owner', '-'), saved_search_kind(c),
				c.get('search', '')))
		for e in self._entries('/servicesNS/-/-/data/ui/views'):
			c, acl = e.get('content', {}), e.get('acl', {})
			if str(c.get('isDashboard', '1')).strip().lower() in ('0', 'false'):
				continue
			dashboards += dashboard_items(e.get('name'), acl.get('app', '-'), acl.get('owner', '-'), c.get('eai:data') or '')
		return saved, dashboards

	def expand(self, item, text):
		"""The search with Splunk's own expansion of its macros, None when it has none, or '!<reason>'."""
		text = strip_comments(text)
		if '`' not in text:
			return None
		q = text.strip()
		generating = q.startswith('|')
		if not generating and not re.match(r'^search\b', q):
			q = 'search ' + q
		owner = item.owner if item.owner not in ('-', '', None) else 'nobody'
		app = item.app if item.app not in ('-', '', None) else 'search'
		path = '/servicesNS/%s/%s/search/parser' % (urllib.parse.quote(owner, safe=''), urllib.parse.quote(app, safe=''))
		try:
			res = self.splunkd.call('POST', path, {'q': q, 'parse_only': 'true'})
		except urllib.error.HTTPError as e:
			return '!Splunk\'s search parser refused it (%s).' % _http_message(e)
		commands = res.get('commands') or []
		if not commands:
			return '!Splunk\'s search parser returned no commands.'
		pieces = []
		for k, c in enumerate(commands):
			raw = (c.get('rawargs') or '').strip()
			pieces.append(raw if k == 0 and not generating and c.get('command') == 'search' else
				('%s %s' % (c.get('command'), raw)).strip())
		return ('| ' if generating else '') + ' | '.join(pieces)


def _http_message(e):
	try:
		body = json.loads(e.read().decode('utf-8', 'replace'))
		return '; '.join(m.get('text', '') for m in body.get('messages', [])) or str(e)
	except Exception:
		return str(e)


# -------------------------------------------------------------------------------------------
# The report

def full_search(item, seen=None):
	"""A dashboard search with the base searches it post-processes in front of it."""
	if item.base is None:
		return item.search
	seen = set() if seen is None else seen
	if id(item) in seen:
		return '!Its base searches form a loop.'
	seen.add(id(item))
	base = full_search(item.base, seen)
	if base is not None and base.startswith('!'):
		return '!It post-processes base search %s: %s' % (item.base.sid or item.base.name, base[1:])
	if item.search is not None and item.search.startswith('!'):
		return item.search
	if base is None or item.search is None:
		return '!It post-processes a base search that has no search text.'
	post = item.search.strip()
	post = post[1:].strip() if post.startswith('|') else post
	return base.rstrip() + (' | ' + post if post else '')


POST_PROCESS = 'It post-processes base search %s'
APP = 'tenx-for-splunk'


def classify_item(source, item, move):
	if item.app == APP:
		return Result(UNCHANGED, ['It is a search of this app, written for compact events.'])
	text = full_search(item)
	if text is None:
		return Result(NOT_CLASSIFIED, ['It has no search text.'])
	if text.startswith('!'):
		return Result(NOT_CLASSIFIED, [text[1:]])
	result = classify(text, move, item.kind, source.expand(item, text))
	if item.base is not None:
		where = ('; the edit goes in the base search, and the edit column shows the two together' if result.edit else '')
		result.reasons.insert(0, '%s%s.' % (POST_PROCESS % (item.base.sid or item.base.name), where))
	return result


def run(source, move):
	saved, dashboards = source.items()
	by_name = {}
	for item in saved:
		item.result = classify_item(source, item, move)
		by_name.setdefault(item.name, item)
	for item in dashboards:
		if item.ref is not None:
			if item.ref.startswith('!'):
				item.result = Result(NOT_CLASSIFIED, [item.ref[1:]])
			elif item.ref in by_name:
				r = by_name[item.ref].result
				item.result = Result(r.verdict, ['It runs saved search "%s": %s' % (item.ref, r.reason)], r.edit)
				item.search = by_name[item.ref].search
				if item.post:
					item.result = None
			else:
				item.result = Result(NOT_CLASSIFIED, ['It runs saved search "%s", which was not read.' % item.ref])
	for item in dashboards:
		_base_result(source, item, move)
	return saved + dashboards


def _base_result(source, item, move):
	"""The result of a dashboard search, its post-processes first: a base search takes the worst of theirs."""
	if item.result is not None:
		return item.result
	if not item.post:
		item.result = classify_item(source, item, move)
		return item.result
	item.result = Result(NOT_CLASSIFIED, ['Its post-process searches form a loop.'])
	found = [_base_result(source, p, move) for p in item.post] + ([classify_item(source, item, move)] if item.base else [])
	result = worst(found)
	result.reasons = [x for x in result.reasons if not x.startswith(POST_PROCESS % '')]
	result.reasons.insert(0, 'It is the base search of %d post-process search%s; the verdict is the worst of theirs.' % (
		len(item.post), '' if len(item.post) == 1 else 'es'))
	needs = [p.result.verdict for p in item.post]
	if item.base is None and any(v in (NEEDS_TX, NEEDS_TXF, LIMIT) for v in needs):
		own = classify_item(source, item, move)
		macro = 'txf' if (NEEDS_TXF in needs or own.verdict == NEEDS_TXF or 'txf' in own.edit) else 'tx'
		result.edit = edit_with_macro(item.search, macro) or ''
	elif item.base is not None:
		result.edit = ''
	item.result = result
	return result


def summary(items):
	counts = dict((v, 0) for v in VERDICTS)
	for item in items:
		counts[item.result.verdict] += 1
	return '%d objects: %s' % (len(items), ', '.join('%d %s' % (counts[v], v) for v in SUMMARY_ORDER))


COLUMNS = ('object', 'app', 'owner', 'kind', 'verdict', 'reason')


def rows(items):
	return [(i.name, i.app, i.owner, i.kind, i.result.verdict, i.result.reason, _shown(i), i.result.edit or '')
		for i in items]


def _shown(item):
	text = full_search(item) if item.base is not None else item.search
	return '' if text is None or text.startswith('!') else text


def print_table(items, out):
	data = [r[:6] for r in rows(items)]
	widths = [min(max([len(COLUMNS[k])] + [len(str(r[k])) for r in data]), 60) for k in range(5)]

	def line(r):
		return '  '.join(str(r[k])[:widths[k]].ljust(widths[k]) for k in range(5)) + '  ' + str(r[5])
	out.write(line(COLUMNS) + '\n')
	for r in data:
		out.write(line(r) + '\n')


def write_csv(items, path):
	with open(path, 'w', newline='', encoding='utf-8') as f:
		w = csv.writer(f)
		w.writerow(COLUMNS + ('search', 'edit'))
		w.writerows(rows(items))


def build_parser():
	ap = argparse.ArgumentParser(description='Which saved searches, alerts and dashboard panels change when sources move '
		'to compact events.')
	src = ap.add_mutually_exclusive_group(required=True)
	src.add_argument('--splunkd', help='management URL of the search head, e.g. https://127.0.0.1:8089')
	src.add_argument('--dir', help='a folder holding savedsearches.conf, macros.conf and dashboard XML or JSON files, '
		'read in place of a search head (for example a copy of its etc/apps and etc/users)')
	ap.add_argument('--sourcetype', action='append', default=[],
		help='an original sourcetype that moves to compact events (repeatable; wildcards allowed)')
	ap.add_argument('--index', action='append', default=[],
		help='an index whose events move to compact events (repeatable; wildcards allowed)')
	ap.add_argument('--field-map', action='append', default=[], metavar='SOURCETYPE',
		help='a moved sourcetype that a field map covers (repeatable)')
	ap.add_argument('--app', action='append', default=[], help='report only the objects of this app (repeatable)')
	ap.add_argument('--csv', help='also write the report to this CSV file, with each search and its edit')
	ap.add_argument('--splunkd-auth-env', default='TENX_SPLUNKD_AUTH',
		help='environment variable holding user:password (default TENX_SPLUNKD_AUTH)')
	ap.add_argument('--splunkd-token-env', default='TENX_SPLUNKD_TOKEN',
		help='environment variable holding a Splunk authentication token, used instead of user:password '
			'(default TENX_SPLUNKD_TOKEN)')
	ap.add_argument('--tls-verify', choices=('on', 'off'), default='on',
		help='off: accept the search head\'s certificate without checking it (Splunk\'s default self-signed one)')
	ap.add_argument('--tls-ca-file', help='PEM file of the authority that signed the search head\'s certificate')
	return ap


def main(argv=None, out=None):
	out = out or sys.stdout
	args = build_parser().parse_args(argv)
	try:
		move = Move(args.sourcetype, args.index, args.field_map)
	except ValueError as e:
		sys.stderr.write('tenx_search_report: %s\n' % e)
		return 2
	unknown = [m for m in args.field_map if args.sourcetype and not Move.match(m, args.sourcetype)]
	if unknown:
		sys.stderr.write('tenx_search_report: --field-map %s is not a --sourcetype that moves\n' % ', '.join(unknown))
		return 2
	if args.dir:
		if not os.path.isdir(args.dir):
			sys.stderr.write('tenx_search_report: --dir %s is not a folder\n' % args.dir)
			return 2
		items = run(DirSource(args.dir, args.app), move)
	else:
		import tenx_field_map
		auth, token = os.environ.get(args.splunkd_auth_env), os.environ.get(args.splunkd_token_env)
		if not auth and not token:
			sys.stderr.write('tenx_search_report: set %s or %s\n' % (args.splunkd_token_env, args.splunkd_auth_env))
			return 2
		splunkd = tenx_field_map.Splunkd(args.splunkd, auth=auth, token=token, tls_verify=args.tls_verify == 'on',
			ca_file=args.tls_ca_file)
		try:
			items = run(RestSource(splunkd, args.app), move)
		except tenx_field_map.TlsVerifyError as e:
			sys.stderr.write('tenx_search_report: %s\n' % e)
			return 1
		except urllib.error.URLError as e:
			sys.stderr.write('tenx_search_report: %s: %s\n' % (args.splunkd, getattr(e, 'reason', e)))
			return 1
	print_table(items, out)
	out.write(summary(items) + '\n')
	if args.csv:
		write_csv(items, args.csv)
		out.write('wrote %s\n' % args.csv)
	return 0


if __name__ == '__main__':
	sys.exit(main())
