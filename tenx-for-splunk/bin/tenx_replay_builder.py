"""
Field replay: the search-time rules of a compact event's original sourcetype, written as search steps.

Why
---
A compact event is indexed under sourcetype tenx_encoded, so Splunk runs tenx_encoded's rules on it
when it is read, plus the rules keyed on its source and host. After `tx` expands it, `extract`
re-runs the regex extractions of whatever sourcetype the event carries at that moment, but no
search command re-applies field aliases, calculated fields or automatic lookups to a result set.
So a search such as  index=x `tx` EventCode=4663  finds nothing: EventCode comes from the original
sourcetype's extractions, and the add-on's aliases, calculated fields and lookups never run.

The original sourcetype travels with the compact event as the indexed field tenx_sourcetype, set
by the sender (`fields` in an HEC event, `_meta = tenx_sourcetype::<name>` in inputs.conf). This
module turns the rules that apply to those sourcetypes into the `tenx-replay` macro, which `txf`
runs right after expanding (`tx` runs no replay; `txf(<sourcetype>)` and the search rewrite run
per-sourcetype units instead, see the notes above unit_macro()):

1. tenx_rst is set to the original sourcetype on every event that was expanded and carries one.
   Every later step is guarded on it, so a compact event without an original sourcetype, or one
   that was not expanded, is left exactly as `tx` leaves it.
2. The search-time fields Splunk set on the unexpanded event are cleared (they came from rules
   keyed on the compact text: on Windows Security data, app=win:unknown on 142 of 662 events).
   Splunk's default fields, tenx_* fields and the indexed fields that the compact events of the
   event's original sourcetype carry are kept.
   eval cannot write a field whose name holds a brace (it reads the braces as a field naming the
   target), so the macro must run before anything that makes such fields: spath, or JSON and XML
   extraction. Both callers run it right after tenx-inflate.
3. sourcetype is set to the original, the _kv mark is dropped on these events only, and `extract`
   re-runs that sourcetype's EXTRACT and REPORT rules and its KV_MODE (none, auto, json and xml
   are all applied by `extract` itself; observed for auto, json and none).
4. The rest of Splunk's search-time sequence, as props.conf.spec in Splunk 10.4.3 describes it
   (lines 1415 to 1510) and, where the spec is silent, as measured on a raw index on Splunk
   Enterprise 10.4.3 (marked "measured" below):
   - field aliases: AS replaces the alias, and removes it when the original has no value; ASNEW
     sets it only when it does not exist. Aliases do not see each other's output (measured: an
     alias of an alias stays empty, in either class order).
   - calculated fields: all read the values from before any of them ran (computed into
     temporary names first). A null result removes the field (measured).
   - lookups, in ASCII order of their class names; a later lookup sees an earlier one's output
     (measured). OUTPUT and OUTPUTNEW keep Splunk's own semantics because the real `lookup`
     command runs; a lookup is kept off the events it does not apply to by giving it no input
     values there. With OUTPUTNEW that leaves those events alone; with OUTPUT the command removes
     its output fields on them (measured with CSV and KV store lookups), so those fields are kept
     aside before the lookup and put back after it, as raw Splunk leaves an event without all
     match fields alone (measured).
   - event types and tags: `typer` and `tags`, with the values of events that were not replayed
     put back afterwards.

Which rules apply to an event
-----------------------------
Props stanzas merge per event: [<sourcetype>], every [source::<pattern>] matching the event's
source, every [host::<pattern>] matching its host, and [default]. For one setting defined in
several, source beats host beats sourcetype beats default; inside source (or host) stanzas, the
higher `priority` wins (default 100 for a literal name, 0 for a pattern), then the name that
sorts first in ASCII. Host patterns match case-insensitively unless they say (?-i). Each step
carries the guard of the stanza it came from, and a setting defined by several stanzas takes the
first matching one in that order.

Written: [default], the stanzas of the original sourcetypes the replay covers, and every source::
and host:: stanza with a search-time rule, whatever the lookback saw (see select_stanzas). The
guard tests the pattern on every event, so a stanza never applies to an event it does not match.

Which apps' rules: one macro for every app
-----------------------------------------
The macro is one text, expanded the same way whatever app a search runs from. Splunk applies to a
raw search the props visible in the searching user's app context: rules shared globally, rules
shared only with the app the search runs from, the user's private rules, and, for one setting
defined in several apps, the value of the app the search runs from first. One macro cannot follow
that, and writing a copy into every app would mean writing into other apps. So the replay applies
only rules shared globally (acl sharing global or system: what `export = system` in an app's
metadata gives), with the precedence between apps as the 10x app sees it (shared_globally()
leaves out the rest and tenxreplay logs them). A search through `tx` therefore differs from the
same search on raw events when the app it runs from holds app-only or private rules for the
replayed sourcetypes, sources or hosts, or itself defines a setting another app also defines.
Lookups have the same rule (lookup_problems()).

Which sourcetype's rules: the one Splunk would have searched the raw event under
-------------------------------------------------------------------------------
The sender's tenx_sourcetype is the sourcetype the event arrived under. Two rules of that sourcetype
decide which sourcetype's search-time rules a raw event gets, and the replay follows both
(effective_sourcetypes()):
* index-time rewrites: a TRANSFORMS- transform with DEST_KEY = MetaData:Sourcetype and SOURCE_KEY
  _raw. Splunk applies it while it parses the raw text, which a compact event does not carry, so the
  replay applies its REGEX and FORMAT to the expanded text. The FortiGate add-on routes its input
  sourcetype fgt_log this way, to fortigate_traffic, fortigate_utm, fortigate_event or
  fortigate_anomaly by the event's devid and type.
* `rename = <target>`, then applied to that result: the target's search-time rules run, and the
  event reads as the target (props.conf.spec: renamed data "only uses the search-time configuration
  for the target sourcetype"). The FortiGate add-on renames fgt_traffic to fortigate_traffic.

Not covered (reported as warnings): index-time fields of the original sourcetype
(INDEXED_EXTRACTIONS, TRANSFORMS that write fields), KV_MODE multi, a sourcetype rewrite that reads
a field other than _raw, lookups whose definition this app cannot see.
"""
import math
import re

CARRIER_FIELD = 'tenx_sourcetype'
# Written by every transform of a field map (tenx_field_map.py MARK_FIELD); tenx-mapped-hide keeps
# an event that carries it out of the replay.
MAPPED_FIELD = 'tenx_mapped'
RST = 'tenx_rst'
COMPACT_RAW = 'tenx_compact_raw'

# Kept through the clearing step: Splunk's default fields, the app's own working fields and
# the internal ones. Indexed fields of the compact events are added by the caller.
DEFAULT_KEEP = ('host', 'source', 'sourcetype', 'index', 'splunk_server', 'splunk_server_group',
				'linecount', 'punct', 'timestartpos', 'timeendpos')
KEEP_PATTERNS = ('_.*', 'tenx_.*', 'date_.*')

KIND_RANK = {'source': 0, 'host': 1, 'sourcetype': 2, 'default': 3}

# Set by the search rewrite (dashboard hook, | tx, | tenxsearch, compiled alerts) on every event
# before it calls the macro, never by `tx`. The rewrite runs its own `extract | spath` and
# key=value pass afterwards, exactly as it does with no replay, so the macro's `extract` must
# not touch an event it does not replay there. While this field is present, an event without
# tenx_rst has no text and a sourcetype, source and host no props stanza names during the
# macro's `extract`, and gets them back right after.
HIDE = 'tenx_hide_others'
PLACEHOLDER = 'tenx_hidden'

# Events that arrive whole: the sender passed the line through as it was (log10x-format S4.1: a
# line that does not begin with "~" is not encoded), so tenx-inflate leaves its text as it is and
# Splunk has already read that text under the event's sourcetype. Two cases, by that sourcetype:
# AS_READ   it is the sourcetype a raw event of the original sourcetype is searched under (a
#           field map renames its compact sourcetype to the original, rename = in props.conf):
#           Splunk has applied exactly the original's search-time rules, so the event is left as
#           Splunk read it, and kept out of the replay's `extract`, which would add every field a
#           transform with MV_ADD extracts a second time (Splunk Enterprise 10.4.3, Windows
#           Security XML, 570 whole events of 662: 95 of 183 fields differed from raw, EventID
#           ["4670", "4670"]).
# WHOLE     it is the compact sourcetype (tenx_encoded): Splunk extracted the text with that
#           sourcetype's rules ([default]'s automatic JSON and key=value extraction, cut at
#           limits.conf [kv] maxchars), whose field names come from the data. The event is
#           replayed like an expanded one, and every field it was read with is cleared first,
#           except the kept ones (see whole_clearing_steps()).
AS_READ = 'tenx_gox'
WHOLE = 'tenx_gow'
# The search rewrite runs its own `extract` (and spath and key=value pass) after the macro, on the
# events the macro did not replay. An AS_READ event must be kept from it too, so when the
# rewrite's hide flag is on, the macro leaves this mark on it (AS_READ itself is removed with the
# block flags): tenx_search_builder hides marked events as it hides replayed ones, and removes it.
# Without the hide flag (`txf`) it is never set.
AS_IS = 'tenx_asis'


def extract_steps(as_read=False):
	"""
	`extract`, with the events that are not replayed hidden from it when the caller set HIDE.
	In `txf` (no HIDE) this is the plain `extract` that `tx` runs after `fields - _kv`.

	as_read: also hide the events marked AS_READ (whole events Splunk read under the sourcetype
	whose rules they need) when HIDE is not set; with HIDE they are hidden already, as events
	that are not replayed.
	"""
	held = ('tenx_hk_raw', '_raw'), ('tenx_hk_st', 'sourcetype'), ('tenx_hk_src', 'source'), ('tenx_hk_host', 'host')
	hide = ['eval ' + ', '.join('%s=if(isnull(%s), %s, null())' % (h, RST, f) for h, f in held),
			'eval _raw=if(isnull(%s), "", _raw), ' % RST + ', '.join(
				'%s=if(isnull(%s), "%s", %s)' % (f, RST, PLACEHOLDER, f) for _, f in held[1:])]
	unhide = ['eval ' + ', '.join('%s=coalesce(%s, %s)' % (f, h, f) for h, f in held), 'fields - tenx_hk_*']
	if not as_read:
		return [block(HIDE, hide), 'extract', block(HIDE, unhide)]
	cond = 'isnotnull(%s) AND isnull(%s)' % (AS_READ, HIDE)
	kept = ('tenx_hx_raw', '_raw'), ('tenx_hx_st', 'sourcetype'), ('tenx_hx_src', 'source'), ('tenx_hx_host', 'host')
	hide_read = ['eval ' + ', '.join('%s=if(%s, %s, null())' % (h, cond, f) for h, f in kept),
				 'eval _raw=if(%s, "", _raw), ' % cond + ', '.join(
					 '%s=if(%s, "%s", %s)' % (f, cond, PLACEHOLDER, f) for _, f in kept[1:])]
	unhide_read = ['eval ' + ', '.join('%s=coalesce(%s, %s)' % (f, h, f) for h, f in kept), 'fields - tenx_hx_*']
	return [block(HIDE, hide), block(AS_READ, hide_read), 'extract', block(AS_READ, unhide_read), block(HIDE, unhide)]


ALIAS_KEY = re.compile(r'^FIELDALIAS-(.+)$')
EVAL_KEY = re.compile(r'^EVAL-(.+)$')
LOOKUP_KEY = re.compile(r'^LOOKUP[-_]?(.+)$', re.I)
SIMPLE_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
WILDCARD = re.compile(r'\*|\.\.\.')


class ReplayError(Exception):
	"""A rule that cannot be written as a search step; the caller reports it and skips the rule."""


# A backtick anywhere in a macro definition is read as a macro call, and a control character
# (a newline above all) does not survive being written into a .conf value or stanza name.
UNSAFE_TEXT = re.compile(r'[`\x00-\x1f\x7f]')


def safe_text(text):
	return bool(text) and not UNSAFE_TEXT.search(text)


def usable_sourcetype(name):
	"""
	Whether an original sourcetype (a value of the indexed field tenx_sourcetype, set by the
	sender) may be written into the macro and become a tenx_replay.conf stanza. [default] and
	[tenx:narrowing] are read back as something else, and brackets would end the stanza name.
	"""
	return safe_text(name) and name not in ('default', NARROWING_STANZA, RETIRED_STANZA, NOCARRIER_STANZA) \
		and '[' not in name and ']' not in name


def check_expression(expr):
	"""
	Raise ReplayError unless expr can be pasted as one eval expression: not empty, no backtick
	or control character, parentheses balanced, and no pipe, bracket or comma outside a quoted
	string or a quoted field name. Splunk checks a calculated field on its own; pasted into the
	macro, text that is not one expression would break, or add commands to, every `tx` search.
	"""
	if not expr.strip():
		raise ReplayError('empty expression')
	if UNSAFE_TEXT.search(expr):
		raise ReplayError('expression with a backtick or a control character')
	depth, i, n = 0, 0, len(expr)
	while i < n:
		c = expr[i]
		if c == '"':
			i += 1
			while i < n and expr[i] != '"':
				i += 2 if expr[i] == '\\' else 1
			if i >= n:
				raise ReplayError('unclosed string in expression')
		elif c == "'":
			j = expr.find("'", i + 1)
			if j < 0:
				raise ReplayError('unclosed field name in expression')
			i = j
		elif c == '(':
			depth += 1
		elif c == ')':
			depth -= 1
			if depth < 0:
				raise ReplayError('unbalanced parentheses in expression')
		elif c in '|[],':
			if c != ',' or depth == 0:
				raise ReplayError("'%s' outside a string in expression" % c)
		i += 1
	if depth:
		raise ReplayError('unbalanced parentheses in expression')


def is_search_time_key(key):
	return bool(ALIAS_KEY.match(key) or EVAL_KEY.match(key) or LOOKUP_KEY.match(key))


def spl_string(text):
	"""A double-quoted SPL string literal holding text exactly."""
	return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def field_ref(name):
	"""A field read inside eval."""
	if "'" in name:
		raise ReplayError("field name with a single quote: %s" % name)
	if not safe_text(name):
		raise ReplayError("field name with a backtick or a control character: %r" % name)
	return "'" + name + "'"


def field_lhs(name):
	"""A field assigned by eval."""
	if SIMPLE_NAME.match(name):
		return name
	if '"' in name or '\\' in name:
		raise ReplayError("field name with a double quote or a backslash: %s" % name)
	if not safe_text(name):
		raise ReplayError("field name with a backtick or a control character: %r" % name)
	if '{' in name or '}' in name:
		# eval reads braces on the left as a field whose value names the target (measured:
		# eval "E{@x}"=1 assigns E), so such a field cannot be written by eval.
		raise ReplayError("field name with a brace: %s" % name)
	return '"' + name + '"'


PLAIN_NAME = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.:@-]*$')


def lookup_name(name):
	"""
	A lookup table, column or event field written into a `lookup` command. Only plain names
	(letters, digits and _ . : @ -) are written: the 120 automatic lookups of Splunk_TA_windows,
	Splunk_SA_CIM and a test add-on use nothing else.
	"""
	if not PLAIN_NAME.match(name or ''):
		raise ReplayError("lookup argument that is not a plain name: %r" % name)
	if SIMPLE_NAME.match(name):
		return name
	if '"' in name or '\\' in name or not safe_text(name):
		raise ReplayError("lookup argument with a quote, a backslash, a backtick or a control character: %r" % name)
	return '"' + name + '"'


def tokens(value):
	"""Split a FIELDALIAS or LOOKUP value at spaces and commas; double quotes keep a name whole."""
	out, buf, quoted, i = [], [], False, 0
	while i < len(value):
		c = value[i]
		if quoted:
			if c == '\\' and i + 1 < len(value):
				buf.append(value[i + 1])
				i += 2
				continue
			if c == '"':
				quoted = False
			else:
				buf.append(c)
		elif c == '"':
			quoted = True
		elif c.isspace() or c == ',':
			if buf:
				out.append(''.join(buf))
				buf = []
		else:
			buf.append(c)
		i += 1
	if buf:
		out.append(''.join(buf))
	return out


def parse_aliases(value):
	"""FIELDALIAS value -> [(original, 'AS'|'ASNEW', alias)]."""
	toks, pairs, i = tokens(value), [], 0
	while i < len(toks):
		if i + 3 > len(toks) or toks[i + 1].upper() not in ('AS', 'ASNEW'):
			raise ReplayError("cannot read field alias '%s'" % value)
		pairs.append((toks[i], toks[i + 1].upper(), toks[i + 2]))
		i += 3
	if not pairs:
		raise ReplayError("cannot read field alias '%s'" % value)
	return pairs


def parse_lookup(value):
	"""
	LOOKUP value -> (table, [(lookup field, event field)], mode, [(lookup field, event field)]).
	mode is 'OUTPUT', 'OUTPUTNEW' or None (every column of the table that is not a match field).
	"""
	toks = tokens(value)
	if len(toks) < 2:
		raise ReplayError("cannot read lookup '%s'" % value)
	table, rest = toks[0], toks[1:]
	inputs, outputs, mode, i = [], [], None, 0
	target = inputs
	while i < len(rest):
		t = rest[i]
		if mode is None and t.upper() in ('OUTPUT', 'OUTPUTNEW'):
			mode, target = t.upper(), outputs
			i += 1
			continue
		if i + 2 < len(rest) and rest[i + 1].upper() == 'AS':
			target.append((t, rest[i + 2]))
			i += 3
		else:
			target.append((t, t))
			i += 1
	if not inputs:
		raise ReplayError("lookup '%s' has no match field" % value)
	if mode is not None and not outputs:
		raise ReplayError("lookup '%s' has %s and no field after it" % (value, mode))
	return table, inputs, mode, outputs


def pattern_regex(pattern):
	"""
	A source:: or host:: stanza name as a regular expression matching the whole name, translated
	as props.conf.spec says: '...' is any characters, '*' anything but the path separator, '.' a
	period, '\\\\' a backslash. Other regular expression characters are read as such only in or
	after a path segment holding a wildcard; before it the name is literal.
	"""
	segments = pattern.split('/')
	out, wild = [], False
	for n, seg in enumerate(segments):
		if WILDCARD.search(seg):
			wild = True
		i, part = 0, []
		while i < len(seg):
			if seg.startswith('...', i):
				part.append('.*')
				i += 3
			elif seg[i] == '*':
				part.append('[^/]*')
				i += 1
			elif seg[i] == '.':
				part.append('\\.')
				i += 1
			elif seg[i] == '\\' and i + 1 < len(seg):
				part.append(seg[i:i + 2] if wild else re.escape(seg[i + 1]))
				i += 2
			else:
				part.append(seg[i] if wild else re.escape(seg[i]))
				i += 1
		out.append(''.join(part))
	return '/'.join(out)


class Stanza(object):
	"""One props stanza, holding only its search-time rules."""

	def __init__(self, name, settings, default_settings=None):
		self.name = name
		default_settings = default_settings or {}
		if name == 'default':
			self.kind, self.pattern = 'default', None
		elif name.startswith('source::'):
			self.kind, self.pattern = 'source', name[len('source::'):]
		elif name.startswith('host::'):
			self.kind, self.pattern = 'host', name[len('host::'):]
		else:
			self.kind, self.pattern = 'sourcetype', name
		self.literal = self.kind in ('source', 'host') and not WILDCARD.search(self.pattern)
		priority = str(settings.get('priority', '') or '').strip()
		if priority.lstrip('-').isdigit():
			self.priority = int(priority)
		else:
			self.priority = 100 if self.literal else 0
		# A stanza read over REST carries the [default] stanza's settings as its own; a setting
		# equal to the default one is the default's, which has the lowest precedence.
		self.rules = dict((k, ' '.join(str(v).split('\n')).strip()) for k, v in settings.items()
			if is_search_time_key(k) and (name == 'default' or default_settings.get(k) != v))
		self.settings = settings

	def sort_key(self):
		return (KIND_RANK[self.kind], -self.priority, self.name)

	def regex(self):
		if self.kind in ('source', 'host'):
			return pattern_regex(self.pattern)
		return None

	def matches(self, value):
		"""Whether this source:: or host:: stanza matches value. None when Python cannot tell."""
		if self.literal:
			return value.lower() == self.pattern.lower() if self.kind == 'host' else value == self.pattern
		rx = self.regex()
		flags = 0
		if self.kind == 'host' and '(?-i)' not in rx:
			flags = re.I
		try:
			return re.match('(?:' + rx + r')\Z', value, flags) is not None
		except re.error:
			return None

	def guard(self):
		"""The eval condition for 'this stanza applies to the event being replayed'."""
		if self.kind == 'default':
			return 'isnotnull(%s)' % RST
		if self.kind == 'sourcetype':
			return '%s==%s' % (RST, spl_string(self.pattern))
		field = self.kind
		if self.literal:
			if self.kind == 'host':
				return 'isnotnull(%s) AND lower(%s)==%s' % (RST, field, spl_string(self.pattern.lower()))
			return 'isnotnull(%s) AND %s==%s' % (RST, field, spl_string(self.pattern))
		rx = self.regex()
		prefix = '(?i)' if self.kind == 'host' and '(?-i)' not in rx else ''
		return 'isnotnull(%s) AND match(%s, %s)' % (RST, field, spl_string(prefix + '^(?:' + rx + ')$'))


def seen_match(stanza, seen):
	"""
	Whether a source:: or host:: stanza matches a source or host recorded in `seen` ({'sources':
	set or ALL, 'hosts': set or ALL}, see coverage()). ALL matches every stanza of that kind, and
	so does a pattern Python cannot evaluate.
	"""
	values = seen.get('sources' if stanza.kind == 'source' else 'hosts')
	if values is ALL:
		return True
	return any(stanza.matches(v) is not False for v in (values or ()) if v)


def select_stanzas(stanzas, present, all_shared=True, seen=None):
	"""
	The stanzas whose rules the macro holds: [default], the stanzas of the original sourcetypes
	in `present` ((original sourcetype, source, host) tuples), and every source:: and host::
	stanza with a search-time rule. Each source or host rule is guarded by its pattern on every
	event, so writing one that matches nothing costs a little time and changes no result, and
	it is there for events whose source or host the lookback did not see (older events, a new
	host). With all_shared=False (the fallback when the macro would be too large) only the
	source and host stanzas matching a source or host in `present` are kept, or whose pattern
	Python cannot evaluate. With `seen` (a sourcetype's unit, see build_unit()) only those
	matching a source or host recorded for the sourcetype are kept (seen_match()).
	"""
	sourcetypes = set(p[0] for p in present)
	sources = set(p[1] for p in present)
	hosts = set(p[2] for p in present)
	chosen = []
	for stanza in stanzas:
		if not stanza.rules:
			continue
		if stanza.kind == 'default':
			chosen.append(stanza)
		elif stanza.kind == 'sourcetype':
			if stanza.name in sourcetypes:
				chosen.append(stanza)
		elif seen is not None:
			if seen_match(stanza, seen):
				chosen.append(stanza)
		elif all_shared:
			chosen.append(stanza)
		else:
			values = sources if stanza.kind == 'source' else hosts
			if any(stanza.matches(v) is not False for v in values):
				chosen.append(stanza)
	return sorted(chosen, key=Stanza.sort_key)


def _by_key(stanzas, key_regex):
	"""{rule key: [(stanza, value)] in precedence order} for one kind of rule."""
	found = {}
	for stanza in stanzas:
		for key, value in stanza.rules.items():
			if key_regex.match(key):
				found.setdefault(key, []).append((stanza, value))
	return found


class Replay(object):
	"""The generated macro and what it holds, per original sourcetype."""

	def __init__(self):
		self.steps = []
		self.warnings = []
		self.per_sourcetype = {}
		self.dropped = []
		# Every calculated field and lookup written, with a search that runs it alone
		# (failing_rules() checks them against the running Splunk): dicts with key, stanza, test.
		self.rules = []

	def spl(self):
		return ' | '.join(self.steps)


def block(flag, body):
	"""
	Steps that run only on a chunk of results where some event carries `flag`. foreach over a
	wildcard runs its body once for each matching field and not at all when none matches
	(measured), so a chunk without replayed events skips the whole block. Its own placeholders
	are renamed so that the <<FIELD>> and <<MATCHSTR>> of steps inside the body are left alone.
	"""
	return 'foreach %s* fieldstr="@@TENXF@@" matchstr="@@TENXM@@" [%s]' % (flag, ' | '.join(body))


# The shipped definition of `tenx-replay`, and the macro written when no compact event carries an
# original sourcetype: re-run the event's own extractions on the expanded text (`txf` drops the
# _kv mark before calling it), and do nothing for the search rewrite, which then extracts
# exactly as it does with no replay.
UNCHANGED = tuple(extract_steps())


ANY = 'tenx_go0z'


def _cond(stanza, ids, flags):
	"""
	The eval condition for 'this stanza applies to the event being replayed'. Never null: a
	sourcetype flag is 1 or absent, so it is tested with isnotnull(), and a source or host guard
	is computed as 1 or 0.
	"""
	if stanza.kind == 'default':
		return 'isnotnull(%s)' % RST
	if stanza.kind == 'sourcetype':
		return 'isnotnull(%s)' % flags[stanza.name]
	return 'tenx_rg%d==1' % ids[stanza.name]


def _home(stanza, flags):
	"""The block a step of this stanza's rules runs in: its sourcetype's, or the one of every replayed event."""
	return flags[stanza.name] if stanza.kind == 'sourcetype' else ANY


def _winner(cands, i, cond):
	"""
	Candidate i of a rule (cands in precedence order) applies and no candidate before it does.
	Two sourcetype stanzas never apply to the same event, so they are not tested against each
	other.
	"""
	me = cands[i][0]
	earlier = [cond(c[0]) for c in cands[:i] if not (me.kind == 'sourcetype' and c[0].kind == 'sourcetype')]
	return cond(me) if not earlier else '%s AND NOT (%s)' % (cond(me), ' OR '.join(earlier))


def _placed(items):
	"""
	(home, step) pairs in run order, as blocks. Consecutive steps with the same home share a
	block. Steps of different sourcetypes between two steps of every replayed event touch
	different events, so they are grouped per sourcetype there; nothing moves across a step
	of every replayed event.
	"""
	out, any_steps, pending = [], [], []

	def flush_pending():
		order = []
		for home, _ in pending:
			if home not in order:
				order.append(home)
		for home in order:
			out.append(block(home, [st for h, st in pending if h == home]))
		del pending[:]

	def flush_any():
		if any_steps:
			out.append(block(ANY, list(any_steps)))
			del any_steps[:]

	for home, step in items:
		if home == ANY:
			flush_pending()
			any_steps.append(step)
		else:
			flush_any()
			pending.append((home, step))
	flush_any()
	flush_pending()
	return out


def _rules(chosen, flags, lookup_fields, warnings, stats, rejected=None, bad_lookups=None, rules=None):
	"""
	The aliases, calculated fields and lookups of every chosen stanza, each written once.
	Rules of a sourcetype stanza run in that sourcetype's block; rules of [default] and of
	source:: and host:: stanzas run in the block of every replayed event, guarded by their
	stanza applying. Splunk's order holds across blocks: every alias reads before any alias
	writes, every calculated field reads before any writes, and lookups run in ASCII order of
	their class names. `stats` collects per stanza what was written.

	rejected      {(rule key, stanza name): reason} of rules the running Splunk refused (see
	              failing_rules()); they are left out like a rule that fails the offline checks.
	bad_lookups   {lookup definition: reason} of lookups not every user can run (see
	              lookup_problems()); their rules are left out.
	rules         a list that receives each written calculated field and lookup with its test.
	"""
	rejected, bad_lookups = rejected or {}, bad_lookups or {}
	rules = rules if rules is not None else []
	ids = dict((s.name, n) for n, s in enumerate(x for x in chosen if x.kind in ('source', 'host')))

	def cond(stanza):
		return _cond(stanza, ids, flags)

	def stat(stanza):
		return stats.setdefault(stanza.name, {'aliases': 0, 'calculated': 0, 'lookups': 0,
											  'computed': set(), 'aliased': set()})

	items = []
	shared = [s for s in chosen if s.kind in ('source', 'host')]
	if shared:
		items.append((ANY, 'eval ' + ', '.join('tenx_rg%d=if(%s,1,0)' % (ids[s.name], s.guard()) for s in shared)))
	homes = [ANY] + [flags[st] for st in sorted(flags)]

	# Field aliases: every alias reads the values from before any alias ran.
	aliases = _by_key(chosen, ALIAS_KEY)
	reads, writes, n = dict((h, []) for h in homes), [], 0
	for key in sorted(aliases):
		cands = aliases[key]
		for i, (stanza, value) in enumerate(cands):
			try:
				pairs = parse_aliases(value)
				for orig, mode, alias in pairs:
					field_ref(orig), field_lhs(alias), field_ref(alias)
			except ReplayError as e:
				warnings.append('%s in [%s]: %s' % (key, stanza.name, e))
				continue
			home = _home(stanza, flags)
			reads[home].append('tenx_rw%d=if(%s,1,0)' % (n, _winner(cands, i, cond)))
			for k, (orig, mode, alias) in enumerate(pairs):
				reads[home].append('tenx_ra%d_%d=%s' % (n, k, field_ref(orig)))
				value_expr = 'tenx_ra%d_%d' % (n, k) if mode == 'AS' else 'coalesce(%s, tenx_ra%d_%d)' % (field_ref(alias), n, k)
				writes.append('%s=if(tenx_rw%d==1, %s, %s)' % (field_lhs(alias), n, value_expr, field_ref(alias)))
			stat(stanza)['aliases'] += 1
			stat(stanza)['aliased'].update(p[2] for p in pairs)
			n += 1
	if writes:
		items.extend((h, 'eval ' + ', '.join(reads[h])) for h in homes if reads[h])
		items.append((ANY, 'eval ' + ', '.join(writes)))
		items.append((ANY, 'fields - tenx_rw*, tenx_ra*'))

	# Calculated fields: all computed from the values before any of them ran, then written,
	# each by the first stanza in precedence order that applies.
	evals = _by_key(chosen, EVAL_KEY)
	reads, writes, n = dict((h, []) for h in homes), [], 0
	for key in sorted(evals):
		name = EVAL_KEY.match(key).group(1)
		cands = evals[key]
		try:
			field_lhs(name), field_ref(name)
		except ReplayError as e:
			warnings.append('%s: %s' % (key, e))
			continue
		# A candidate whose expression cannot be pasted is written as "leave the field as it
		# is": it still hides the lower-precedence candidates, as an empty EVAL- in a local
		# props.conf hides the shipped one.
		cases, written = [], 0
		for stanza, expr in cands:
			try:
				check_expression(expr)
				if (key, stanza.name) in rejected:
					raise ReplayError('refused by Splunk: %s' % rejected[(key, stanza.name)])
			except ReplayError as e:
				warnings.append('%s in [%s]: %s' % (key, stanza.name, e))
				cases.append('%s, %s' % (cond(stanza), field_ref(name)))
				continue
			reads[_home(stanza, flags)].append('tenx_rc%d=if(%s, (%s), null())' % (n, cond(stanza), expr))
			rules.append({'key': key, 'stanza': stanza.name, 'test': 'eval tenx_dry_run=(%s)' % expr})
			cases.append('%s, tenx_rc%d' % (cond(stanza), n))
			stat(stanza)['calculated'] += 1
			stat(stanza)['computed'].add(name)
			written += 1
			n += 1
		if written:
			writes.append('%s=case(%s, true(), %s)' % (field_lhs(name), ', '.join(cases), field_ref(name)))
	if writes:
		items.extend((h, 'eval ' + ', '.join(reads[h])) for h in homes if reads[h])
		items.append((ANY, 'eval ' + ', '.join(writes)))
		items.append((ANY, 'fields - tenx_rc*'))

	# Lookups, in ASCII order of their keys; each runs the real lookup command, with input values
	# only on the events the rule applies to.
	lookups = _by_key(chosen, LOOKUP_KEY)
	n, used = 0, False
	for key in sorted(lookups):
		cands = lookups[key]
		for i, (stanza, value) in enumerate(cands):
			try:
				table, inputs, mode, outputs = parse_lookup(value)
				if lookup_fields is not None and table not in lookup_fields:
					raise ReplayError("lookup definition '%s' is not visible to this app" % table)
				if table in bad_lookups:
					raise ReplayError("lookup definition '%s': %s" % (table, bad_lookups[table]))
				if (key, stanza.name) in rejected:
					raise ReplayError('refused by Splunk: %s' % rejected[(key, stanza.name)])
				lookup_name(table)
				for _, evt in inputs:
					field_ref(evt)
				args = ' '.join('%s AS tenx_ri%d_%d' % (lookup_name(col), n, k) for k, (col, _) in enumerate(inputs))
				out = ''
				if mode:
					out = ' %s %s' % (mode, ', '.join(
						lookup_name(col) if col == evt else '%s AS %s' % (lookup_name(col), lookup_name(evt))
						for col, evt in outputs))
				if mode:
					produced = [evt for _, evt in outputs]
				elif (lookup_fields or {}).get(table) is None:
					raise ReplayError("lookup '%s' has no OUTPUT and its columns are unknown" % table)
				else:
					produced = [c for c in lookup_fields[table] if c not in set(col for col, _ in inputs)]
				for f in produced:
					field_lhs(f), field_ref(f)
			except ReplayError as e:
				warnings.append('%s in [%s]: %s' % (key, stanza.name, e))
				continue
			home, w = _home(stanza, flags), _winner(cands, i, cond)
			inputs_set = ['tenx_ri%d_%d=if(%s, %s, null())' % (n, k, w, field_ref(evt)) for k, (_, evt) in enumerate(inputs)]
			if mode == 'OUTPUTNEW':
				items.append((home, 'eval ' + ', '.join(inputs_set)))
				items.append((home, 'lookup %s %s%s' % (lookup_name(table), args, out)))
			else:
				# The lookup command removes its OUTPUT fields on an event whose input is null
				# (measured on Splunk 10.4.3, CSV and KV store lookups; OUTPUTNEW does not), and a
				# null input is how the replay keeps a lookup off the events it does not apply to.
				# Raw Splunk leaves such an event alone, so its output fields are kept aside and
				# put back.
				off = ' OR '.join('isnull(tenx_ri%d_%d)' % (n, k) for k in range(len(inputs)))
				keep = ['tenx_rl%d=if(%s, 1, 0)' % (n, off)] + [
					'tenx_ro%d_%d=if(tenx_rl%d==1, %s, null())' % (n, j, n, field_ref(f)) for j, f in enumerate(produced)]
				items.append((home, 'eval ' + ', '.join(inputs_set + keep)))
				items.append((home, 'lookup %s %s%s' % (lookup_name(table), args, out)))
				if produced:
					items.append((home, 'eval ' + ', '.join('%s=if(tenx_rl%d==1, tenx_ro%d_%d, %s)' % (
						field_lhs(f), n, n, j, field_ref(f)) for j, f in enumerate(produced))))
			rules.append({'key': key, 'stanza': stanza.name, 'test': 'eval %s | lookup %s %s%s' % (
				', '.join('tenx_ri%d_%d="tenx_dry_run"' % (n, k) for k in range(len(inputs))), lookup_name(table), args, out)})
			stat(stanza)['lookups'] += 1
			stat(stanza)['computed'].update(produced)
			n += 1
			used = True
	if used:
		items.append((ANY, 'fields - tenx_ri*, tenx_ro*, tenx_rl*'))
	if shared:
		items.append((ANY, 'fields - tenx_rg*'))
	return _placed(items)




def read_time_names(stanzas, transforms=None, lookup_fields=None):
	"""
	(the fields Splunk can set on a compact event when it reads it, True when some of them cannot
	be listed). The rules that apply then are those of [default], of the compact sourcetype
	(tenx_encoded, or any stanza carrying the app's REPORT-tenx) and of every source:: and host::
	stanza: their extractions (named groups, a transform's FORMAT and FIELDS), aliases,
	calculated fields and lookup outputs, plus eventtype and tag. A name taken from the data
	($1::$2, _KEY_n, DELIMS without FIELDS, a lookup whose columns are unknown) cannot be listed.
	"""
	transforms = transforms or {}
	names, dynamic = set(['eventtype', 'tag']), False
	for stanza in stanzas:
		compact = stanza.kind == 'sourcetype' and (stanza.name == 'tenx_encoded' or
			str(stanza.settings.get('REPORT-tenx', '')).strip() == 'tenx-hash-vars-extraction')
		if stanza.kind == 'sourcetype' and not compact:
			continue
		for key, value in stanza.settings.items():
			value = str(value or '')
			if key.startswith('EXTRACT-'):
				m = EXTRACT_IN.match(value)
				groups = NAMED_GROUP.findall(m.group(1) if m else value)
				names.update(g for g in groups if not g.startswith(('_KEY_', '_VAL_')))
				dynamic = dynamic or any(g.startswith(('_KEY_', '_VAL_')) for g in groups)
			elif key.startswith('REPORT-'):
				for t in [n.strip() for n in value.split(',') if n.strip()]:
					transform = transforms.get(t) or {}
					out = transform_outputs(transform)
					if '*' in out or any(n.startswith(('_KEY_', '_VAL_')) for n in out) or (
							transform.get('DELIMS') and not transform.get('FIELDS')) or not transform:
						dynamic = True
					names.update(n for n in out if n != '*' and not n.startswith(('_KEY_', '_VAL_')))
		for key, value in stanza.rules.items():
			if ALIAS_KEY.match(key):
				try:
					names.update(p[2] for p in parse_aliases(value))
				except ReplayError:
					pass
			elif EVAL_KEY.match(key):
				names.add(EVAL_KEY.match(key).group(1))
			elif LOOKUP_KEY.match(key):
				try:
					table, inputs, mode, outputs = parse_lookup(value)
				except ReplayError:
					continue
				if mode:
					names.update(evt for _, evt in outputs)
				elif (lookup_fields or {}).get(table) is None:
					dynamic = True
				else:
					names.update(c for c in lookup_fields[table] if c not in set(col for col, _ in inputs))
	return names, dynamic


def clearing_steps(names, keep_rx, warnings, compact=False, cleared_on=None):
	"""
	The steps that remove from a replayed event the fields Splunk set when it read the compact
	text, leaving every other event as it is. Each name is written out (no `foreach *`, which
	would evaluate every field name the event carries, indexed fields named by the sender
	included, and a quote or a brace in one breaks the search or writes another field); a name
	that cannot be written into eval is not cleared, and said so.

	compact (units): the plain names (letters, digits and _ . : @ -, see PLAIN_NAME) are listed
	once in one `foreach <name> <name> ... [eval "<<FIELD>>"=...]` instead of one eval assignment
	each, a third of the characters. foreach takes each listed name as a pattern without a
	wildcard, so it evaluates only those fields; the other names keep the eval form.

	cleared_on: {name: [original sourcetypes]} for a name that the compact events of some original
	sourcetypes carry as an indexed field and those of others do not. It is cleared only on the
	replayed events of the listed sourcetypes (their first tenx_sourcetype value), and kept on
	every other event.
	"""
	keep = re.compile(keep_rx)
	cleared_on = cleared_on or {}
	parts, listed = [], []
	for name in sorted(names):
		if keep.match(name):
			continue
		try:
			lhs, ref = field_lhs(name), field_ref(name)
		except ReplayError as e:
			warnings.append('a field set when compact events are read is not cleared on replayed events: %s' % e)
			continue
		only = cleared_on.get(name)
		if only:
			parts.append('%s=if(isnotnull(%s) AND (%s), null(), %s)' % (lhs, RST, ' OR '.join(
				'mvindex(%s,0)==%s' % (CARRIER_FIELD, spl_string(st)) for st in sorted(only)), ref))
		elif compact and PLAIN_NAME.match(name):
			listed.append(name)
		else:
			parts.append('%s=if(isnotnull(%s), null(), %s)' % (lhs, RST, ref))
	steps = ['eval ' + ', '.join(parts)] if parts else []
	if listed:
		steps.append('foreach %s [eval "<<FIELD>>"=if(isnotnull(%s), null(), \'<<FIELD>>\')]' % (' '.join(listed), RST))
	steps.append('foreach tag::* [eval "<<FIELD>>"=if(isnotnull(%s), null(), \'<<FIELD>>\')]' % RST)
	return steps


def whole_clearing_steps(keep_rx, cleared_on, originals):
	"""
	The step that clears, on the events marked WHOLE only, every field Splunk set when it read
	their text under the compact sourcetype, whatever its name: the read fields of such an event
	take their names from the data (JSON paths such as findings{}.name), so they cannot be listed,
	and eval cannot write a name holding a brace (see field_lhs()). For each field name of the chunk
	the field is renamed to a working name, cleared there on WHOLE events, and renamed back (rename
	takes a name as written, braces included), so every other event keeps it unchanged. The kept
	fields are those of clearing_steps(): `keep_rx`, and a name of `cleared_on` on the events of
	the original sourcetypes whose compact events carry it as an indexed field (every sourcetype not
	listed for it, and one the macro does not cover).

	Measured on Splunk Enterprise 10.4.3: a field named with a double quote cannot be put into the
	body (foreach reports "Failed to parse templatized search for field" and the search goes on
	with that field as it was).
	"""
	kept = ['match("<<FIELD>>", %s)' % spl_string(keep_rx)]
	extra = {}
	for name, only in sorted(cleared_on.items()):
		for st in originals:
			if st not in only:
				extra.setdefault(st, []).append(name)
	orig = 'mvindex(%s,0)' % CARRIER_FIELD
	for st, names in sorted(extra.items()):
		kept.append('(%s==%s AND match("<<FIELD>>", %s))' % (orig, spl_string(st), spl_string(
			'^(%s)$' % '|'.join(re.escape(n) for n in names))))
	if cleared_on:
		kept.append('(NOT (%s) AND match("<<FIELD>>", %s))' % (' OR '.join('%s==%s' % (orig, spl_string(st))
			for st in originals), spl_string('^(%s)$' % '|'.join(re.escape(n) for n in sorted(cleared_on)))))
	return [block(WHOLE, ['foreach * [rename "<<FIELD>>" AS tenx_wf | eval tenx_wf=if(isnotnull(%s) AND NOT (%s), '
						  'null(), tenx_wf) | rename tenx_wf AS "<<FIELD>>"]' % (WHOLE, ' OR '.join(kept))])]


def masking_rules(stanzas, transforms=None):
	"""
	The index-time rules among `stanzas` that change an event's text: every SEDCMD- key, and every
	TRANSFORMS- class naming a transform with DEST_KEY = _raw. Splunk runs them while it parses an
	event under its original sourcetype, source and host. A compact event is parsed as the compact
	sourcetype, so its values are stored as the sender wrote them and `tx` shows them unmasked.
	Returns sorted 'SEDCMD-x in [stanza]' and 'TRANSFORMS-x (name) in [stanza]' strings.
	"""
	transforms = transforms or {}
	found = set()
	for s in stanzas:
		for key, value in sorted(s.settings.items()):
			if key.startswith('SEDCMD-'):
				found.add('%s in [%s]' % (key, s.name))
			elif key.startswith('TRANSFORMS-'):
				for name in (n.strip() for n in str(value or '').split(',') if n.strip()):
					if str((transforms.get(name) or {}).get('DEST_KEY', '')).strip() == '_raw':
						found.add('%s (%s) in [%s]' % (key, name, s.name))
	return sorted(found)


SOURCETYPE_DEST = 'MetaData:Sourcetype'
RST0 = 'tenx_rst0'


def sourcetype_rewrites(stanza, transforms):
	"""
	[(regex, format value)] of the index-time transforms of a sourcetype stanza that set the
	sourcetype from the raw text (DEST_KEY = MetaData:Sourcetype, SOURCE_KEY _raw), in the order
	Splunk runs them: TRANSFORMS- classes in ASCII order, the names of a class in the order listed.
	A rewrite that reads another key is returned as (None, name), for a warning.
	"""
	out = []
	for key in sorted(k for k in stanza.settings if k.startswith('TRANSFORMS-')):
		for name in (n.strip() for n in str(stanza.settings[key] or '').split(',') if n.strip()):
			t = (transforms or {}).get(name) or {}
			if str(t.get('DEST_KEY', '')).strip() != SOURCETYPE_DEST:
				continue
			fmt = str(t.get('FORMAT', '')).strip()
			regex = str(t.get('REGEX', '') or '')
			if str(t.get('SOURCE_KEY', '_raw') or '_raw').strip() != '_raw' or not regex or not fmt.startswith('sourcetype::'):
				out.append((None, name))
				continue
			out.append((regex, fmt[len('sourcetype::'):]))
	return out


def _format_targets(value, names):
	"""The sourcetype names a rewrite's FORMAT value can produce: itself, or the stanza names its pattern matches."""
	if '$' not in value:
		return [value]
	rx = re.compile('^' + ''.join('.+' if re.fullmatch(r'\$\d+', part) else re.escape(part)
									  for part in re.split(r'(\$\d+)', value) if part) + '$')
	return sorted(n for n in names if rx.match(n))


def _format_expr(regex, value):
	"""The eval expression for a rewrite's new sourcetype: FORMAT's $<n> read from the first match of REGEX."""
	if '$' not in value:
		return spl_string(value)
	replacement = re.sub(r'\$(\d+)', r'\\\1', value.replace('\\', '\\\\'))
	return 'replace(_raw, %s, %s)' % (spl_string('(?s)^.*?(?:' + regex + ').*$'), spl_string(replacement))


def effective_sourcetypes(stanzas, transforms, sourcetypes):
	"""
	(eval steps, {original sourcetype: [effective sourcetypes]}, warnings): the steps turn tenx_rst
	from the sourcetype an event arrived under into the one whose search-time rules a raw event gets
	(see "Which sourcetype's rules" above). Without rewrites or renames, no step and each sourcetype
	is its own.
	"""
	by_name = dict((s.name, s) for s in stanzas if s.kind == 'sourcetype')
	steps, effective, warnings = [], {}, []
	renames = {}
	for st in sourcetypes:
		own = by_name.get(st)
		cands = [st]
		for regex, value in (sourcetype_rewrites(own, transforms) if own is not None else []):
			if regex is None:
				warnings.append('the sourcetype rewrite %s of %s does not read _raw and is not replayed' % (value, st))
				continue
			if RST0 not in ''.join(steps):
				steps.append('eval %s=%s' % (RST0, RST))
			steps.append('eval %s=if(%s==%s AND match(_raw, %s), %s, %s)' % (
				RST, RST0, spl_string(st), spl_string(regex), _format_expr(regex, value), RST))
			cands += _format_targets(value, by_name)
		final = []
		for c in cands:
			target = str((by_name[c].settings.get('rename', '') if c in by_name else '') or '').strip()
			if target and usable_sourcetype(target):
				renames[c] = target
				final.append(target)
			else:
				final.append(c)
		effective[st] = sorted(set(final))
	if renames:
		steps.append('eval %s=case(%s, true(), %s)' % (RST, ', '.join('%s==%s, %s' % (RST, spl_string(a), spl_string(b))
			for a, b in sorted(renames.items())), RST))
	if any(step.startswith('eval %s=' % RST0) for step in steps):
		steps.append('fields - %s' % RST0)
	return steps, effective, warnings


def build(stanzas, present, lookup_fields=None, keep_fields=(), all_shared=True, rejected=None, bad_lookups=None,
		  transforms=None, only=False, seen=None, with_tags=True, keep_by_sourcetype=None):
	"""
	Build the replay pipeline.

	stanzas        Stanza objects for every props stanza the search can see.
	present        [(original sourcetype, source, host)] seen in the compact events.
	lookup_fields  {lookup definition name: [its fields]} for the lookups this app can see; a
	               lookup missing from it is skipped with a warning. None skips the check.
	keep_fields    indexed fields kept through the clearing step on every replayed event. Without
	               keep_by_sourcetype: the indexed fields of all compact events.
	keep_by_sourcetype
	               {original sourcetype: the indexed fields its compact events carry}. A name is
	               kept on the events of the sourcetypes whose compact events carry it, and cleared
	               on the events of the others present (see clearing_steps()); a sourcetype missing
	               from it keeps every name listed for any. Indexed fields are
	               set per event by whoever sent it, so one sourcetype's (a field map writing app
	               as an indexed field on FortiGate events) say nothing about another's (app set
	               when a Windows compact event is read).
	only           replay only the events whose original sourcetype is in `present`; every other
	               event is left as `tx` leaves it (a unit, see build_unit()).
	seen           {'sources': ..., 'hosts': ...} recorded for the sourcetype (see coverage()):
	               source:: and host:: stanzas are limited to those matching them, for the rules
	               and for the fields cleared (a unit).
	with_tags      end with event types and tags (tags_block()); a unit leaves them to the
	               `tenx-replay-tags` macro, which runs once after every unit of a search.

	Cost: every step that only replayed events need sits in a block (see block()) keyed on a
	flag that only those events carry: tenx_go0z on every replayed event, and one flag per
	original sourcetype. A chunk of results with no replayed event runs none of them, and a chunk
	runs the rules of the sourcetypes it holds and no others. Measured on Splunk Enterprise
	10.4.3 over 7,649 events without tenx_sourcetype: the unblocked macro took 2.36 s against
	1.25 s for the shipped `tx` text, most of it typer and tags.
	"""
	replay = Replay()
	refused = sorted(set(p[0] for p in present if not usable_sourcetype(p[0])))
	replay.warnings.extend('original sourcetype %r is not written into the macro' % st for st in refused)
	present = [p for p in present if usable_sourcetype(p[0])]
	if not present:
		# Nothing to replay: the macro is the plain `extract` that `tx` runs. A unit also
		# drops tenx_rst, so in the search rewrite, after an earlier unit, its extract skips the
		# events that unit replayed (see compose_units()).
		if only:
			replay.steps.append('eval %s=null()' % RST)
		replay.steps.extend(UNCHANGED)
		return replay
	originals = sorted(set(p[0] for p in present))
	eff_steps, effective, eff_warnings = effective_sourcetypes(stanzas, transforms, originals)
	replay.warnings.extend(eff_warnings)
	eff_present = []
	for p in present:
		for e in effective[p[0]]:
			if (e,) + tuple(p[1:]) not in eff_present:
				eff_present.append((e,) + tuple(p[1:]))
	chosen = []
	for s in select_stanzas(stanzas, eff_present, all_shared, seen):
		if safe_text(s.name):
			chosen.append(s)
		else:
			replay.warnings.append('props stanza %r is not written into the macro' % s.name)
	sourcetypes = sorted(set(p[0] for p in eff_present))
	flags = dict((st, 'tenx_go%dz' % (n + 1)) for n, st in enumerate(sourcetypes))

	keep_fields = [f for f in keep_fields if safe_text(f)]
	names = list(DEFAULT_KEEP) + [f for f in keep_fields if f not in DEFAULT_KEEP]
	cleared_on = {}
	if keep_by_sourcetype is not None:
		# A sourcetype with no entry was not counted (no compact event of it in the time range the
		# caller looked at): it keeps every name that any counted sourcetype keeps, as when one
		# list served every sourcetype.
		known = dict((st, set(f for f in keep_by_sourcetype[st] if safe_text(f)))
					 for st in originals if keep_by_sourcetype.get(st) is not None)
		union = set().union(*known.values()) if known else set()
		by_st = dict((st, known.get(st, union)) for st in originals)
		everywhere = set.intersection(*by_st.values()) if by_st else set()
		names += sorted(everywhere - set(names))
		for name in set().union(*by_st.values()) - everywhere:
			cleared_on[name] = sorted(st for st in originals if name not in by_st[st])
	keep_rx = '^(%s)$' % '|'.join(list(KEEP_PATTERNS) + [re.escape(f) for f in names])

	steps = replay.steps
	which = ''
	if only:
		which = ' AND (%s)' % ' OR '.join('mvindex(%s,0)==%s' % (CARRIER_FIELD, spl_string(st)) for st in originals)
	# Expanded events, and events that arrived whole (text that does not begin with "~"). A compact
	# event whose template could not be applied keeps its compact text and is not replayed.
	steps.append('eval %s=if(isnotnull(%s) AND coalesce(tenx_expand_refused,"")=="" AND '
		'(isnull(%s) OR _raw!=%s OR substr(%s,1,1)!="~")%s, mvindex(%s,0), null())' % (
			RST, CARRIER_FIELD, COMPACT_RAW, COMPACT_RAW, COMPACT_RAW, which, CARRIER_FIELD))
	steps.extend(eff_steps)
	# A whole event read under the sourcetype whose rules it needs is left as read (AS_READ); one
	# read under another sourcetype is replayed with every field it was read with cleared (WHOLE).
	steps.append('eval %s=if(isnotnull(%s) AND _raw==%s AND sourcetype==%s, 1, null()), %s=if(isnotnull(%s) AND '
				 '_raw==%s AND sourcetype!=%s, 1, null())' % (AS_READ, RST, COMPACT_RAW, RST, WHOLE, RST, COMPACT_RAW, RST))
	steps.append('eval %s=if(isnotnull(%s), null(), %s)' % (RST, AS_READ, RST))
	steps.append('eval %s=if(isnotnull(%s),1,null()), ' % (ANY, RST) + ', '.join(
		'%s=if(%s==%s,1,null())' % (flags[st], RST, spl_string(st)) for st in sourcetypes))
	# Clear what Splunk set on the unexpanded text, re-type, and drop the _kv mark on these events
	# only, so the extract that follows runs the original sourcetype's extractions and KV_MODE.
	# A unit clears what the stanzas it can apply set: [default], the compact sourcetype's and the
	# source:: and host:: stanzas matching what was recorded for its sourcetype, rules or not.
	read_from = stanzas
	if seen is not None:
		read_from = [s for s in stanzas if s.kind in ('default', 'sourcetype') or seen_match(s, seen)]
	names, dynamic = read_time_names(read_from, transforms, lookup_fields)
	if dynamic:
		replay.warnings.append('some fields set when compact events are read take their names from the data '
							   'and are not cleared on replayed events')
	steps.extend(whole_clearing_steps(keep_rx, cleared_on, originals))
	steps.append(block(ANY, clearing_steps(names, keep_rx, replay.warnings, compact=seen is not None,
											cleared_on=cleared_on) + [
		'eval sourcetype=coalesce(%s, sourcetype)' % RST,
		'eval _kv=if(isnotnull(%s), null(), _kv)' % RST]))
	steps.extend(extract_steps(as_read=True))

	stats = {}
	steps.extend(_rules(chosen, flags, lookup_fields, replay.warnings, stats, rejected, bad_lookups, replay.rules))

	info = replay.per_sourcetype
	for st in originals:
		effs = effective[st]
		srcs = set(p[1] for p in present if p[0] == st)
		hsts = set(p[2] for p in present if p[0] == st)
		applies = [s for s in chosen if s.kind == 'default' or (s.kind == 'sourcetype' and s.name in effs)
				   or (seen is not None and s.kind in ('source', 'host'))
				   or (s.kind == 'source' and any(s.matches(v) is not False for v in srcs))
				   or (s.kind == 'host' and any(s.matches(v) is not False for v in hsts))]
		counts = {'aliases': 0, 'calculated': 0, 'lookups': 0, 'computed': set(), 'aliased': set()}
		for s in applies:
			got = stats.get(s.name)
			if got:
				for k in ('aliases', 'calculated', 'lookups'):
					counts[k] += got[k]
				counts['computed'] |= got['computed']
				counts['aliased'] |= got['aliased']
		info[st] = {'stanzas': [s.name for s in applies], 'aliases': counts['aliases'],
					'calculated': counts['calculated'], 'lookups': counts['lookups'],
					'computed': sorted(counts['computed']), 'aliased': sorted(counts['aliased']),
					'warnings': [], 'sources': sorted(srcs), 'flag': ','.join(flags[e] for e in effs)}
		if effs != [st]:
			info[st]['replayed_as'] = effs
		own = next((s for s in stanzas if s.kind == 'sourcetype' and s.name == st), None)
		if own is None:
			info[st]['warnings'].append('no props stanza for this sourcetype')
		for e in effs:
			eff = next((s for s in stanzas if s.kind == 'sourcetype' and s.name == e), None)
			settings = eff.settings if eff is not None else {}
			kv = str(settings.get('KV_MODE', 'auto')).strip().lower()
			if kv.startswith('multi'):
				info[st]['warnings'].append('KV_MODE %s is not replayed' % kv)
		settings = own.settings if own is not None else {}
		if str(settings.get('INDEXED_EXTRACTIONS', '') or '').strip():
			info[st]['warnings'].append('INDEXED_EXTRACTIONS fields are index-time and are not replayed')
		# Index-time rules: every stanza that matches the sourcetype, a recorded source or host,
		# whether or not it has a search-time rule the replay chose.
		info[st]['masking'] = masking_rules([s for s in stanzas if (s.kind == 'sourcetype' and s.name == st)
											 or (s.kind == 'source' and any(s.matches(v) is not False for v in srcs))
											 or (s.kind == 'host' and any(s.matches(v) is not False for v in hsts))],
											transforms)
		if info[st]['masking']:
			info[st]['warnings'].append('masked at index time for this sourcetype: %s; compact events of it hold '
										'those values as sent, unmasked (mask them before compaction)'
										% ', '.join(info[st]['masking']))
	replay.warnings[:] = sorted(set(replay.warnings))

	if with_tags:
		steps.append(tags_block())
	steps.append(block(AS_READ, ['eval %s=if(isnotnull(%s) AND isnotnull(%s), 1, %s)' % (AS_IS, HIDE, AS_READ, AS_IS)]))
	# tenx_rst and AS_IS stay: the search rewrite reads them after the macro. Callers remove them.
	steps.append('fields - tenx_go*')
	return replay


def tags_block():
	"""
	Event types and tags, recomputed on the replayed events (tenx_rst set); in a chunk that also
	holds events that were not replayed, those get back what they had. Runs only on a chunk
	with a replayed event (the block of tenx_go0z).
	"""
	return block(ANY, [
		'eval tenx_rk_et=if(isnull(%s), eventtype, null()), tenx_rk_tag=if(isnull(%s), tag, null())' % (RST, RST),
		'foreach tag::* [eval "tenx_rk_<<FIELD>>"=if(isnull(%s), \'<<FIELD>>\', null())]' % RST,
		'typer',
		'tags',
		# Inside a foreach body, tags writes each tag::<field> but not the combined tag field
		# (measured: 0 events had tag inside the block, 786 with the same steps outside it), so
		# tag is built here as the union of the tag::<field> values.
		'foreach tag::* [eval tenx_rk_all=mvappend(tenx_rk_all, \'<<FIELD>>\')]',
		'eval eventtype=if(isnull(%s), tenx_rk_et, eventtype), tag=if(isnull(%s), tenx_rk_tag, mvsort(mvdedup(tenx_rk_all)))' % (RST, RST),
		'foreach tag::* [eval "<<FIELD>>"=if(isnull(%s), null(), \'<<FIELD>>\')]' % RST,
		'foreach tenx_rk_tag::* [eval "tag::<<MATCHSTR>>"=if(isnull(%s), \'<<FIELD>>\', \'tag::<<MATCHSTR>>\')]' % RST,
		'fields - tenx_rk_*'])


# The shipped `tenx-replay-tags` macro (default/macros.conf; a test keeps the two equal): event
# types and tags of every replayed event, once, after the units of a search (txf(<sourcetype>),
# the search rewrite). It does nothing on a chunk without a replayed event.
TAGS_MACRO = 'tenx-replay-tags'
TAGS_STEPS = ('eval %s=if(isnotnull(%s),1,null())' % (ANY, RST), tags_block(), 'fields - %s' % ANY)


NARROWING_STANZA = 'tenx:narrowing'
# tenx_replay.conf stanza: <unit macro name> = <start of the UTC day it became the no-op unit>.
RETIRED_STANZA = 'tenx:retired'
# tenx_replay.conf stanza: indexes = the compact indexes the last rebuild saw with no event
# carrying tenx_sourcetype (the negative record), at most MAX_NOCARRIER, busiest first.
NOCARRIER_STANZA = 'tenx:nocarrier'
MAX_NOCARRIER = 200


def nocarrier_value(compact_counts, carrier_indexes):
	"""
	The negative record: the indexes of `compact_counts` ({index: compact events}) not in
	`carrier_indexes` (or ALL), busiest first, held to MAX_NOCARRIER and returned as a sorted
	comma list. An index left out past the cap, or with a name that cannot be listed, is simply
	unknown to the rewrite, which then runs the full replay: never too little.
	"""
	if carrier_indexes is ALL:
		carrier_indexes = set()
	carriers = set(i.lower() for i in carrier_indexes)
	kept = [ix for ix, _ in sorted(compact_counts.items(), key=lambda kv: (-kv[1], kv[0]))
			if ix and ix.lower() not in carriers and ',' not in ix and safe_text(ix)][:MAX_NOCARRIER]
	return ','.join(sorted(kept))
METADATA_FIELDS = frozenset(('host', 'source', 'sourcetype', 'index', 'splunk_server', '_time', 'timestamp'))
NAMED_GROUP = re.compile(r'\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>')
FORMAT_NAME = re.compile(r'(?:^|\s)([^\s$:]+)::')
EXTRACT_IN = re.compile(r'^(.*)\s+in\s+([A-Za-z0-9_]+)\s*$', re.S)


def transform_outputs(transform):
	"""
	The field names a search-time transform writes: its REGEX's named groups, the static names of
	its FORMAT, its FIELDS. '*' when a name comes from the data ($1::...), which cannot be listed.
	"""
	names = set(NAMED_GROUP.findall(str(transform.get('REGEX', '') or '')))
	fmt = str(transform.get('FORMAT', '') or '')
	names.update(n for n in FORMAT_NAME.findall(fmt))
	if re.search(r'(?:^|\s)\$\d+::', fmt):
		names.add('*')
	names.update(f.strip().strip('"') for f in str(transform.get('FIELDS', '') or '').split(',') if f.strip())
	return names


def fields_not_in_text(stanzas, transforms=None, lookup_fields=None, keep_fields=(), indexed_value_false=()):
	"""
	Every field some props stanza can give a value that is not text of the event: calculated
	fields, lookup outputs, extractions from metadata or from such a field, and aliases of any of
	those, plus the indexed fields of the compact events, plus the fields fields.conf marks with
	INDEXED_VALUE other than true (`indexed_value_false`: Splunk itself does not look their value
	up in the raw text). Taken over every stanza the app can see,
	not only the replayed ones, because a compact event without tenx_sourcetype gets the rules of
	its source and host stanzas when it is read. A '*' in the result means a name could not be
	listed, and no field comparison may restrict.
	"""
	transforms = transforms or {}
	out = set(keep_fields) | set(indexed_value_false)
	meta = set(METADATA_FIELDS) | set(keep_fields)
	for stanza in stanzas:
		for key, value in stanza.settings.items():
			value = str(value or '')
			if key.startswith('REPORT-'):
				for name in [n.strip() for n in value.split(',') if n.strip()]:
					t = transforms.get(name) or {}
					source_key = str(t.get('SOURCE_KEY', '_raw') or '_raw').strip()
					if source_key.startswith('MetaData:') or source_key in meta:
						out |= transform_outputs(t)
			elif key.startswith('EXTRACT-'):
				m = EXTRACT_IN.match(value)
				if m and m.group(2) in meta:
					out |= set(NAMED_GROUP.findall(m.group(1)))
		for key, value in stanza.rules.items():
			if EVAL_KEY.match(key):
				out.add(EVAL_KEY.match(key).group(1))
			elif LOOKUP_KEY.match(key):
				try:
					table, inputs, mode, outputs = parse_lookup(value)
				except ReplayError:
					continue
				if mode:
					out.update(evt for _, evt in outputs)
				else:
					cols = (lookup_fields or {}).get(table)
					if cols is None:
						out.add('*')
					else:
						out.update(c for c in cols if c not in set(col for col, _ in inputs))
	# Aliases do not see each other's output, so one pass over them is enough.
	for stanza in stanzas:
		for key, value in stanza.rules.items():
			if ALIAS_KEY.match(key):
				try:
					pairs = parse_aliases(value)
				except ReplayError:
					continue
				out.update(alias for orig, _, alias in pairs if orig in out or orig in METADATA_FIELDS
						   or orig.startswith('_') or orig.startswith('date_'))
	return sorted(out)


def narrowing_wanted(config, replay):
	"""
	Whether tenxreplay keeps the [tenx:narrowing] stanza the prefilter narrows field comparisons
	with: only when tenx_config.conf [config] has field_narrowing = true and some compact event
	carries tenx_sourcetype. Otherwise an existing stanza is removed.
	"""
	on = str((config or {}).get('field_narrowing', '') or '').strip().lower() in ('1', 'true', 't', 'yes', 'y')
	return bool(on and replay.per_sourcetype)


MAX_LISTED_SOURCES = 200


def sources_value(sources):
	"""
	The `sources` setting of a tenx_replay.conf stanza: the sources covered, or * past the cap
	or when a source name cannot be listed (a comma would split it when read back, and a
	control character does not survive the .conf file).
	"""
	if len(sources) > MAX_LISTED_SOURCES or any(',' in s or not safe_text(s) for s in sources if s):
		return '*'
	return ','.join(sources)


def uncovered(seen, covered):
	"""
	The (original sourcetype, source) pairs in `seen` that the written replay does not cover.
	`covered` maps a sourcetype to its `sources` setting as read back from tenx_replay.conf.
	A sourcetype the macro never takes (see usable_sourcetype) is never reported, so it cannot
	start a rebuild.
	"""
	out = []
	for st, source in seen:
		if not usable_sourcetype(st):
			continue
		if st not in covered:
			out.append((st, source))
			continue
		listed = covered_sources(covered[st])
		if listed.strip() != '*' and source not in set(x for x in listed.split(',') if x):
			out.append((st, source))
	return out


def keep_covered(present, covered):
	"""
	`present` plus every original sourcetype and source the written replay already covers.
	A rebuild looks back a limited time (7 days in the saved searches); without this, a
	sourcetype that stopped sending for longer would lose its replay for searches over its older
	events (on a test install whose sample events were older than 7 days, the hourly rebuild
	dropped two of five sourcetypes). A sourcetype covered with sources = * keeps its
	sourcetype stanza and [default]; its source stanzas come from what the lookback sees.
	"""
	seen = set((p[0], p[1]) for p in present)
	sourcetypes = set(p[0] for p in present)
	out = list(present)
	for st, listed in sorted(covered.items()):
		if not usable_sourcetype(st):
			continue
		listed = covered_sources(listed).strip()
		if listed == '*':
			if st not in sourcetypes:
				out.append((st, '', '') + tuple([0] * (len(present[0]) - 3) if present else ()))
			continue
		for source in [x for x in listed.split(',') if x]:
			if (st, source) not in seen:
				out.append((st, source, '') + tuple([0] * (len(present[0]) - 3) if present else ()))
	return out


def covered_sources(value):
	"""The `sources` of a covered sourcetype: `value` is the setting itself or the whole stanza."""
	return str((value.get('sources', '') if isinstance(value, dict) else value) or '')


# Units: one macro per original sourcetype, for searches that need only some of them
# ---------------------------------------------------------------------------------
# Splunk parses a macro's whole expanded text on every search that uses it, whether or not any
# event is replayed (observed on Splunk Enterprise 10.4.3: about 0.012 s per 1,000 characters,
# the same on zero events). So `tx` runs no replay at all, and a search that wants the replay
# runs only the text it needs:
#
#   `txf`                  the `tenx-replay` macro above: every covered sourcetype, every
#                          source:: and host:: stanza (build_capped()).
#   `txf(<sourcetype>)`    that sourcetype's unit and `tenx-replay-tags` (the macros.conf
#                          stanza `txf(1)` computes the unit's name, unit_macro(), with md5() in
#                          eval; Splunk refuses a colon in a macro name).
#   the search rewrite     the units of the sourcetypes recorded for the indexes the search
#                          names, composed (compose_units()), or `tenx-replay` when it names
#                          none, or nothing at all when none is recorded (rewrite_replay()).
#
# A unit (build_unit()) is build() with only=True, with_tags=False and the sources and hosts
# recorded for its sourcetype: it replays the events of that sourcetype and no other, applies
# the [default] rules, its own stanza's, and those of the source:: and host:: stanzas matching a
# source or host recorded with the sourcetype, and clears the fields those stanzas set when the
# compact event was read. A source or host recorded with the sourcetype stays recorded until the
# sourcetype expires (past 200 values the list becomes *, every stanza), and a sourcetype seen for
# the first time has its sources and hosts read over all time (tenxreplay). So the one difference
# from `tenx-replay` is an event whose source or host the replay has not recorded yet: a new one,
# until the next "When New" rebuild (5 minutes) records it.

ALL = '*'
UNIT_PREFIX = 'tenx-replay-u'
ALIAS_PREFIX = 'tenx-replay-st-'
FULL = '`tenx-replay`'
# The sourcetype names that also get the alias `tenx-replay-st-<name>`: those that are a valid
# macro name (Splunk Enterprise 10.4.3 refuses others: "Macro and argument names might only
# include alphanumerics, '_' and '-'"). `txf(<name>)` does not need it: it computes the unit's
# name with md5() in eval (macros.conf [txf(1)], iseval).
ALIAS_NAME = re.compile(r'^[A-Za-z0-9_-]+$')
MAX_LISTED = MAX_LISTED_SOURCES


# `txf(<sourcetype>)` (macros.conf [txf(1)]) computes the name of that sourcetype's unit in eval. Its
# validation, checked while Splunk parses the search, also requires that a unit is written for the
# sourcetype, so txf(<sourcetype>) without one stops with TXF_ONE_ERROR instead of Splunk's "macro
# cannot be found". A check there reaches every client, the REST export endpoint included (Splunk
# Enterprise 10.4.3: HTTP 400 with the message in json, csv and xml), where a command that fails
# while the search runs gives export in json or csv an empty body. tenxreplay rewrites the
# validation with the units it has written (txf_one_validation()); the shipped one names none.
# Before the final search of `tx`, `txf` and txf(<sourcetype>): the step that matches a wildcard inside a
# word, TERM() and CASE() as a base search on the index matches them (macros.conf [tenx-wild]).
WILD_STEP = ' | `tenx-wild`'
# What `tx`, `txf` and txf(<sourcetype>) read (macros.conf [tenx-raw-events]): the compact events, and
# the raw events of the same sources that the deployment names there, which are returned as they are.
EVENTS = '((`tenx-events`) OR (`tenx-raw-events`))'
TXF_ONE_UNIT = ('"' + EVENTS + ' [| tenxprefilter] | eval tenx_compact_raw=_raw, tenx_passed=if(match(_raw, \\"^~\\") OR '
				'isnotnull(tenx_sourcetype), null(), 1) | `tenx-inflate` | fields - _kv | '
				'`tenx-mapped-hide` | `tenx-whole-hide` | `tenx-replay-u" . substr(md5("$st$"), 1, 12) . "` | `tenx-replay-tags` | '
				'`tenx-whole-restore` | `tenx-mapped-restore` | fields - tenx_compact_raw, tenx_rst, tenx_hash, tenx_var_0, tenx_vars | '
				'eval tenx_expand_refused=if(len(tenx_expand_refused)>0, tenx_expand_refused, null())' + WILD_STEP + ' | search *"')
TXF_ONE = 'txf(1)'
TXF_ONE_NAME = 'match(st, "^[A-Za-z0-9_.:/-]+$")'
# Splunk prints it after "Encountered the following error while validating macro 'txf(<st>)': " and
# adds the final period.
TXF_ONE_ERROR = ('no field replay is written yet for this sourcetype, so the search was not run. Rebuild Field '
				 'Replay When New writes one within five minutes of the sourcetype\'s first compact event being '
				 'indexed; to write it now, run | tenxreplay over All time. txf takes one original sourcetype, without '
				 'quotes (letters, digits and _ . : / -)')


def txf_one_validation(unit_names):
	"""The [txf(1)] validation for the units `unit_names` (tenx-replay-u<12 hex digits> names)."""
	hashes = sorted(n[len(UNIT_PREFIX):] for n in unit_names if n.startswith(UNIT_PREFIX))
	return '%s AND like("|%s|", "%%|" . substr(md5(st), 1, 12) . "|%%")' % (TXF_ONE_NAME, "|".join(hashes))


def unit_macro(sourcetype):
	"""The name of a sourcetype's unit: letters, digits and dashes whatever the sourcetype is called."""
	import hashlib
	return UNIT_PREFIX + hashlib.md5(sourcetype.encode('utf-8')).hexdigest()[:12]


def alias_macro(sourcetype):
	"""The alias `tenx-replay-st-<sourcetype>` (a direct name for the unit), or None when that is not a valid macro name."""
	return ALIAS_PREFIX + sourcetype if ALIAS_NAME.match(sourcetype or '') else None


def listed_value(values):
	"""A tenx_replay.conf list (sources, hosts, indexes): * past the cap or for a name that cannot be listed."""
	if values is ALL:
		return ALL
	values = sorted(v for v in values if v)
	if len(values) > MAX_LISTED or any(',' in v or not safe_text(v) or v == ALL for v in values):
		return ALL
	return ','.join(values)


def parse_listed(value):
	"""The set a tenx_replay.conf list holds, or ALL for *."""
	value = str(value or '').strip()
	if value == ALL:
		return ALL
	return set(v for v in value.split(',') if v)


def _merge(a, b):
	if a is ALL or b is ALL:
		return ALL
	out = set(a) | set(b)
	return ALL if len(out) > MAX_LISTED else out


def coverage(rows, covered=None):
	"""
	{original sourcetype: {'sources', 'hosts', 'indexes'}}, each a set or ALL: what the compact
	events in `rows` ((sourcetype, source, host, count, index) as tenxreplay's tstats returns
	them) carry, plus what tenx_replay.conf already lists for the sourcetype (`covered`, its
	stanzas as read back). A list stays ALL once it is: past 200 values, or a value that cannot
	be listed (listed_value()).
	"""
	out = {}

	def entry(st):
		return out.setdefault(st, {'sources': set(), 'hosts': set(), 'indexes': set()})

	for st, value in sorted((covered or {}).items()):
		if not usable_sourcetype(st):
			continue
		value = value if isinstance(value, dict) else {'sources': value}
		e = entry(st)
		for key in ('sources', 'hosts', 'indexes'):
			e[key] = _merge(e[key], parse_listed(value.get(key, '')))
	for row in rows:
		st = row[0]
		if not usable_sourcetype(st):
			continue
		e = entry(st)
		for key, value in (('sources', row[1]), ('hosts', row[2]), ('indexes', row[4] if len(row) > 4 else '')):
			if value:
				e[key] = _merge(e[key], ALL if (',' in value or not safe_text(value) or value == ALL) else set([value]))
	return out


def uncovered_values(rows, covered):
	"""
	The (sourcetype, kind, value) of `rows` (as for coverage()) that tenx_replay.conf does not
	list yet: a new host or index of a covered sourcetype (a new sourcetype or source is
	uncovered()'s). A list that is * covers everything.
	"""
	out = []
	for row in rows:
		st = row[0]
		if not usable_sourcetype(st) or st not in covered:
			continue
		value = covered[st] if isinstance(covered[st], dict) else {}
		for key, got in (('hosts', row[2]), ('indexes', row[4] if len(row) > 4 else '')):
			listed = parse_listed(value.get(key, ''))
			if got and listed is not ALL and got not in listed:
				out.append((st, key, got))
	return out


# Splunk refuses a search whose pipeline holds more than 1,000 commands ("The pipeline size for this search
# exceeds a search command limit : 1000"), counted at the top level: a foreach block counts once whatever it
# holds, and a subsearch is a search of its own (Splunk Enterprise 10.4.3 and 9.4.15: 1,000 top-level commands
# ran, 1,010 were refused; 600 with a foreach of 500 commands inside ran). It sets no limit on the length of a
# macro or of the search a macro expands to: a macro of 400,152 characters, written through REST and read back
# after a restart, and three chained macros of 454,221 characters together ran, on a search head over two
# indexers as well. txf holds about 40 top-level commands of its own around the replay, so the replay keeps to
# this many, which leaves room for the commands a search adds after txf.
REPLAY_MAX_COMMANDS = 900


def top_level_commands(text):
	"""The commands of a search text at its top level: one more than its pipes outside brackets and quotes."""
	depth, n, quoted, i = 0, 1, False, 0
	while i < len(text):
		ch = text[i]
		if quoted:
			if ch == '\\':
				i += 1
			elif ch == '"':
				quoted = False
		elif ch == '"':
			quoted = True
		elif ch == '[':
			depth += 1
		elif ch == ']':
			depth = max(depth - 1, 0)
		elif ch == '|' and depth == 0:
			n += 1
		i += 1
	return n


def over_limits(replay, limit):
	"""Whether a replay is longer than `limit` characters (replay_max_macro_chars; 0: no limit) or holds more
	top-level commands than REPLAY_MAX_COMMANDS."""
	text = replay.spl()
	return bool(limit and len(text) > limit) or top_level_commands(text) > REPLAY_MAX_COMMANDS


def _size(replay, limit):
	text = replay.spl()
	return '%d characters, %d commands; limits: replay_max_macro_chars = %s, %d commands' % (
		len(text), top_level_commands(text), limit or 'none', REPLAY_MAX_COMMANDS)


def build_unit(stanzas, sourcetype, seen, lookup_fields=None, keep_fields=(), rejected=None, bad_lookups=None,
			   transforms=None, limit=0, keep_by_sourcetype=None):
	"""
	The unit of one original sourcetype (see the notes above unit_macro()). `seen` is its entry of
	coverage(). Past `limit` characters (replay_max_macro_chars, 0 for none) or REPLAY_MAX_COMMANDS the
	unit replays nothing, with a warning: then its events are handled as `tx` handles them.
	keep_by_sourcetype as in build(): the unit keeps `keep_fields` and the indexed fields of this
	sourcetype's compact events.
	"""
	unit = build(stanzas, [(sourcetype, '', '')], lookup_fields, keep_fields, False, rejected, bad_lookups, transforms,
				 only=True, seen=seen, with_tags=False, keep_by_sourcetype=keep_by_sourcetype)
	if over_limits(unit, limit):
		cut = build(stanzas, [], only=True)
		cut.warnings.append('the unit of %r is over its limits (%s) and replays nothing' % (sourcetype, _size(unit, limit)))
		# What the sourcetype's stanza records still holds; LEFT_OUT_KEY says the unit replays nothing.
		cut.per_sourcetype = unit.per_sourcetype
		cut.replays_nothing = True
		return cut
	return unit


# The tenx_replay.conf key that says what leaves a sourcetype's events without its rules, for the
# warning the prefilter shows on `txf` and txf(<sourcetype>) (tenx_prefilter_parser.replay_left_out):
# 'txf' when the `tenx-replay` macro leaves it out (past replay_max_macro_chars, when set, or
# REPLAY_MAX_COMMANDS it keeps the busiest sourcetypes), 'unit' when its own unit is over those limits and
# replays nothing. Empty: neither.
LEFT_OUT_KEY = 'left_out'

# The tenx_replay.conf key that holds the top-level commands of a sourcetype's unit, for rewrite_replay() to
# keep a chain of units within REPLAY_MAX_COMMANDS.
COMMANDS_KEY = 'commands'


def left_out_value(in_macro, replays_nothing):
	"""The LEFT_OUT_KEY value of a sourcetype."""
	return ','.join(w for w, on in (('txf', not in_macro), ('unit', replays_nothing)) if on)


def unit_sourcetypes(present, last_seen=None, settings=None):
	"""
	The original sourcetypes that get a unit and a tenx_replay.conf stanza: every usable one of
	`present`, the busiest first, held to replay_max_sourcetypes: the same sourcetypes the `tenx-replay`
	macro holds unless its size limits leave some out (build_capped()). Each unit has its own limit
	(build_unit()), and a sourcetype the macro leaves out keeps its unit, so txf(<sourcetype>) and the
	search rewrite still give its events their fields.
	"""
	settings = settings or DEFAULT_SETTINGS
	ranked = ranked_sourcetypes(present, last_seen)
	cap = settings['replay_max_sourcetypes']
	return ranked[:cap] if cap else ranked


def build_units(stanzas, cov, sourcetypes, lookup_fields=None, keep_fields=(), settings=None, rejected=None,
				bad_lookups=None, transforms=None, keep_by_sourcetype=None):
	"""{original sourcetype: its unit} for each of `sourcetypes` (those the `tenx-replay` macro covers)."""
	settings = settings or DEFAULT_SETTINGS
	return dict((st, build_unit(stanzas, st, cov.get(st) or {'sources': set(), 'hosts': set(), 'indexes': set()},
								lookup_fields, keep_fields, rejected, bad_lookups, transforms,
								settings['replay_max_macro_chars'], keep_by_sourcetype)) for st in sorted(sourcetypes))


def all_rules(replay, units):
	"""Every rule written into the macro or a unit, once, for failing_rules()."""
	out, seen = [], set()
	for r in [replay] + [units[st] for st in sorted(units)]:
		for rule in r.rules:
			if (rule['key'], rule['stanza']) not in seen:
				seen.add((rule['key'], rule['stanza']))
				out.append(rule)
	return out


def retire_units(no_op, retired, now, grace_days, cap):
	"""
	(the no-op units to keep {name: day retired}, the names to delete). `no_op` are the unit
	names that are the no-op unit after this rebuild, `retired` what tenx_replay.conf
	[tenx:retired] says about them. A unit never seen retired is retired today. Past `grace_days`
	(0: never) a unit is deleted; past `cap` kept (0: no cap) the oldest are deleted first.
	"""
	today = day_of(now)
	kept = {}
	for name in sorted(no_op):
		try:
			kept[name] = int(str(retired.get(name, '')).strip())
		except ValueError:
			kept[name] = today
	delete = []
	if grace_days:
		delete = sorted(n for n, day in kept.items() if now - day > grace_days * DAY)
		for name in delete:
			del kept[name]
	if cap and len(kept) > cap:
		oldest = sorted(kept, key=lambda n: (kept[n], n))[:len(kept) - cap]
		for name in oldest:
			del kept[name]
		delete = sorted(delete + oldest)
	return kept, delete


def no_op_unit():
	"""The unit written for a sourcetype the replay no longer covers: its events are left as `tx` leaves them."""
	return build([], [], only=True)


def compose_units(sourcetypes):
	"""
	The search rewrite's replay for some original sourcetypes: their units in turn, then
	`tenx-replay-tags`. A unit sets tenx_rst on its own events and clears it on every other, so
	the value an earlier unit set is kept in tenx_rprev across the next and put back after it;
	while tenx_rst is clear, an event is left alone by every step of a unit, and is hidden from
	its extract by tenx_hide_others (which only the rewrite sets).
	"""
	sts = sorted(sourcetypes)
	parts = ['`%s`' % unit_macro(sts[0])]
	for st in sts[1:]:
		parts += ['eval tenx_rprev=%s' % RST, '`%s`' % unit_macro(st), 'eval %s=coalesce(%s, tenx_rprev)' % (RST, RST)]
	if len(sts) > 1:
		parts.append('fields - tenx_rprev')
	parts.append('`%s`' % TAGS_MACRO)
	return ' | '.join(parts)


def chained_commands(counts):
	"""The top-level commands of compose_units() over units of `counts` commands each, `tenx-replay-tags` included."""
	k = len(counts)
	return sum(counts) + 2 * (k - 1) + (1 if k > 1 else 0) + top_level_commands(' | '.join(TAGS_STEPS))


def _recorded_commands(value):
	"""A stanza's COMMANDS_KEY as a number, or None when it holds none."""
	try:
		n = int(str(value.get(COMMANDS_KEY, '') or '').strip())
	except ValueError:
		return None
	return n if n > 0 else None


def _index_regex(pattern):
	return re.compile('^' + '.*'.join(re.escape(p) for p in pattern.lower().split('*')) + '$')


def rewrite_replay(covered, indexes):
	"""
	The replay steps for the search rewrite, or None for none, which leaves the rewrite without
	any replay step.

	covered   {original sourcetype: its tenx_replay.conf stanza (only 'indexes' is read)}, or None
	          when tenx_replay.conf could not be read.
	indexes   the index values the search names (TenxSearchAstNode.get_passing_specifiers():
	          [] for none, None when it cannot tell, wildcards allowed).

	Unreadable: `tenx-replay`, which replays whatever the install has (and is the shipped
	extract alone where nothing carries tenx_sourcetype). No covered sourcetype: none. No index
	named, an index named that no stanza records, a wildcard, or every covered sourcetype
	recorded for the indexes named, none of them left out of `tenx-replay` (LEFT_OUT_KEY):
	`tenx-replay`. Otherwise the units of the sourcetypes recorded for those indexes, or
	`tenx-replay` when one of them has no working unit (its stanza says `unit =`), when their
	chain would hold more than REPLAY_MAX_COMMANDS top-level commands, or when a stanza does not
	say how many its unit holds (COMMANDS_KEY).

	Correct results first: the record of indexes lags the data (the next "When New" rebuild,
	5 minutes; longer while a rebuild fails), and an index it does not know may hold events of
	any covered sourcetype. Only the full macro cannot miss them; the units, and the text with
	no replay, can. So an index the record does not know never gets less than `tenx-replay`, on an
	install where any compact event carries tenx_sourcetype.
	"""
	if covered is None:
		return FULL
	sts = sorted(st for st in covered if usable_sourcetype(st))
	if not sts:
		return None
	if not indexes:
		return FULL
	names = [str(i).lower() for i in indexes if str(i)]
	known = set()
	for st in sts:
		value = covered[st] if isinstance(covered[st], dict) else {}
		listed = parse_listed(value.get('indexes', ''))
		if listed is not ALL:
			known.update(ix.lower() for ix in listed)
	# The negative record ([tenx:nocarrier]): compact indexes with no carrier at the last rebuild.
	none = parse_listed((covered.get(NOCARRIER_STANZA) or {}).get('indexes', '') if isinstance(
		covered.get(NOCARRIER_STANZA), dict) else '')
	none = set() if none is ALL else set(ix.lower() for ix in none) - known
	if not names:
		return FULL
	for n in names:
		if '*' in n:
			# resolved against both lists; matching neither is unknown
			r = _index_regex(n)
			if not any(r.match(k) for k in known) and not any(r.match(k) for k in none):
				return FULL
		elif n not in known and n not in none:
			return FULL
	rx = [_index_regex(n) for n in names]
	chosen = []
	for st in sts:
		value = covered[st] if isinstance(covered[st], dict) else {}
		listed = parse_listed(value.get('indexes', ''))
		if listed is ALL or not listed or any(r.match(ix.lower()) for ix in listed for r in rx):
			if 'unit' in value and str(value.get('unit') or '') != unit_macro(st):
				return FULL
			chosen.append(st)
	if not chosen:
		return None
	# `tenx-replay` leaves out the sourcetypes past its size limits; their units replay them.
	left_out = any('txf' in str((covered[st] if isinstance(covered[st], dict) else {}).get(LEFT_OUT_KEY) or '').split(',')
				   for st in chosen)
	if len(chosen) == len(sts) and not left_out:
		return FULL
	# Splunk refuses a search past its command limit, and a chain of units has none of its own: a chain past
	# REPLAY_MAX_COMMANDS, or of a unit whose size the record does not hold, is `tenx-replay`, which keeps to it.
	counts = [_recorded_commands(covered[st] if isinstance(covered[st], dict) else {}) for st in chosen]
	if None in counts or chained_commands(counts) > REPLAY_MAX_COMMANDS:
		return FULL
	return compose_units(chosen)


# Settings of the field replay in tenx_config.conf [config]; see README/tenx_config.conf.spec.
DEFAULT_SETTINGS = {
	# More distinct original sourcetypes than this are not replayed (the busiest are kept).
	'replay_max_sourcetypes': 200,
	# The macro is cut down until its definition is at most this many characters; 0, no limit. Splunk sets
	# no limit on a macro's length (see REPLAY_MAX_COMMANDS), so by default the macro holds every sourcetype
	# that has a unit, held to REPLAY_MAX_COMMANDS.
	'replay_max_macro_chars': 0,
	# A sourcetype no compact event has carried for this many days loses its replay; 0 never.
	'replay_expire_days': 400,
	# A unit that has been the no-op unit for this many days is deleted, with its alias; 0 never.
	# (A saved search naming txf(<sourcetype>) runs as `tx` until then, and "macro cannot be
	# found" after.) The no-op units kept are also held to replay_max_sourcetypes, the oldest
	# deleted first. 90 days: a unit only becomes the no-op after replay_expire_days without data
	# or when replay_max_sourcetypes pushes its sourcetype out; a quarter covers a sourcetype that
	# comes back after a seasonal gap or a migration, and its unit is then rewritten in place.
	'replay_unit_grace_days': 90,
}
DAY = 86400


def replay_settings(content):
	"""The replay settings from the [config] stanza's content, defaults for anything unreadable."""
	out = dict(DEFAULT_SETTINGS)
	for key, default in DEFAULT_SETTINGS.items():
		try:
			out[key] = max(int(str((content or {}).get(key, default)).strip()), 0)
		except ValueError:
			out[key] = default
	return out


def day_of(epoch):
	"""The start of the UTC day holding `epoch`: last_seen is kept per day so the stanza changes at most daily."""
	return int(epoch) // DAY * DAY


def keep_present(recorded, covered, expired, counts, now):
	"""
	(covered, expired) after the check that the expired sourcetypes have no compact event left:
	`counts` {sourcetype: compact events of any date}. One that still has some is covered again,
	its last_seen today, so its replay and its unit stay while its events do; the rest expire.
	"""
	covered, gone = dict(covered), []
	for st in expired:
		if int(counts.get(st, 0) or 0) > 0:
			value = dict(recorded.get(st) or {})
			value['last_seen'] = str(day_of(now))
			covered[st] = value
		else:
			gone.append(st)
	return covered, gone


def index_time_terms(earliest, latest):
	"""
	The search terms for an index-time range: _index_earliest (and _index_latest unless the range
	has no end). An epoch (as the search's time range gives it) is written as whole seconds,
	widened to hold the whole range; a relative time (-7d, -10m@m) as it is.
	"""
	def value(v, widen):
		v = str(v).strip()
		try:
			f = float(v)
		except ValueError:
			if not re.match(r'^[-+@A-Za-z0-9]+$', v):
				raise ValueError('not a time: %r' % v)
			return v
		return str(int(math.ceil(f) if widen else math.floor(f)))
	terms = '_index_earliest=%s' % value(earliest, False)
	if latest not in (None, '', 'now'):
		terms += ' _index_latest=%s' % value(latest, True)
	return terms


def expire_covered(covered, now, days):
	"""
	(covered without the expired sourcetypes, the expired ones). A sourcetype expires when its
	stanza's last_seen is more than `days` days before `now`. A stanza without last_seen (one
	written by hand, for example) does not expire; the next write gives it one.
	"""
	if not days:
		return dict(covered), []
	kept, expired = {}, []
	for st, value in covered.items():
		last = value.get('last_seen') if isinstance(value, dict) else None
		try:
			last = int(str(last).strip()) if last not in (None, '') else None
		except ValueError:
			last = None
		if last is not None and now - last > days * DAY:
			expired.append(st)
		else:
			kept[st] = value
	return kept, sorted(expired)


def last_seen_of(present, covered, now):
	"""
	{original sourcetype: the day it was last seen} for the stanzas to write: today for one with
	events in this lookback (count > 0), else what its stanza holds, else today.
	"""
	today, out = day_of(now), {}
	for p in present:
		st, count = p[0], (p[3] if len(p) > 3 else 0)
		stored = covered.get(st, {}).get('last_seen') if isinstance(covered.get(st), dict) else None
		if count:
			out[st] = today
		elif st not in out:
			out[st] = int(stored) if str(stored or '').strip().isdigit() else today
	return out


def ranked_sourcetypes(present, last_seen=None):
	"""
	The original sourcetypes of `present` ((sourcetype, source, host, count) tuples), the ones
	worth keeping first: those with events in the lookback by event count, then those kept from
	earlier rebuilds by last_seen, newest first, then by name.
	"""
	counts = {}
	for p in present:
		if usable_sourcetype(p[0]):
			counts[p[0]] = counts.get(p[0], 0) + (int(p[3]) if len(p) > 3 and p[3] else 0)
	last_seen = last_seen or {}
	return sorted(counts, key=lambda st: (-counts[st], -int(last_seen.get(st) or 0), st))


def _listed(names, n=20):
	return ', '.join(names[:n]) + (' and %d more' % (len(names) - n) if len(names) > n else '')


def build_capped(stanzas, present, lookup_fields=None, keep_fields=(), settings=None, last_seen=None,
				 rejected=None, bad_lookups=None, transforms=None, keep_by_sourcetype=None):
	"""
	build(), held to replay_max_sourcetypes, to replay_max_macro_chars when it is set, and to
	REPLAY_MAX_COMMANDS. Past the sourcetype cap the least busy sourcetypes are left out. Past a size
	limit, first the source and host stanzas are limited to those matching a source or host seen
	(select_stanzas all_shared=False), then sourcetypes are left out, least busy first; if even the
	shared rules alone do not fit, the macro is the shipped one. Every step is a warning on the result,
	and `dropped` lists the sourcetypes left out.
	"""
	settings = settings or DEFAULT_SETTINGS
	ranked = ranked_sourcetypes(present, last_seen)
	notes, dropped = [], []
	notes.extend('original sourcetype %r is not written into the macro' % st
				 for st in sorted(set(p[0] for p in present if not usable_sourcetype(p[0]))))
	cap = settings['replay_max_sourcetypes']
	if cap and len(ranked) > cap:
		dropped = ranked[cap:]
		ranked = ranked[:cap]
		notes.append('%d original sourcetypes over replay_max_sourcetypes = %d are not replayed: %s'
					 % (len(dropped), cap, _listed(dropped)))

	def attempt(names, all_shared):
		keep = set(names)
		return build(stanzas, [p for p in present if p[0] in keep], lookup_fields, keep_fields, all_shared,
					 rejected, bad_lookups, transforms, keep_by_sourcetype=keep_by_sourcetype)

	replay = attempt(ranked, True)
	limit = settings['replay_max_macro_chars']
	if over_limits(replay, limit):
		notes.append('the macro is over its limits (%s): source and host stanzas are limited to those matching a '
					 'source or host seen in the lookback' % _size(replay, limit))
		replay = attempt(ranked, False)
		cut = []
		while over_limits(replay, limit) and ranked:
			cut.append(ranked.pop())
			replay = attempt(ranked, False)
		if cut:
			dropped += cut
			notes.append('%d more original sourcetypes are not replayed to stay within the macro\'s limits: %s'
						 % (len(cut), _listed(cut)))
		if over_limits(replay, limit):
			notes.append('the rules of [default], source:: and host:: stanzas alone are over the macro\'s limits; '
						 'the shipped macro is written and nothing is replayed')
			dropped = ranked_sourcetypes(present, last_seen)
			replay = build(stanzas, [], lookup_fields, keep_fields, transforms=transforms,
						   keep_by_sourcetype=keep_by_sourcetype)
	replay.warnings[:0] = notes
	replay.dropped = dropped
	return replay


# Checks against the running Splunk. tenxreplay supplies `run`, a function that runs one search
# (a oneshot job over REST) and returns None when it ran cleanly or the error Splunk reported
# (see dry_run_error()); everything here is pure so it can be tested with a fake reply.


def dry_run_error(status, body):
	"""
	None when a oneshot search job ran cleanly, else the error text. `status` is the HTTP status
	of the POST to search/jobs and `body` its JSON reply (text or parsed). Observed on Splunk
	Enterprise 10.4.3: an unparseable search, an unknown eval function, wrong arguments,
	and a lookup whose definition or file is missing all come back as HTTP 200 with a message of
	type FATAL, e.g. {"messages":[{"type":"FATAL","text":"Error in 'EvalCommand': The
	'nosuchfunction' function is unsupported or undefined."}]}. A 4xx or 5xx status, or an
	ERROR message, is read as a failure too.
	"""
	import json
	if isinstance(body, (bytes, str)):
		try:
			body = json.loads(body or '{}')
		except ValueError:
			body = {}
	body = body or {}
	texts = [str(m.get('text', '')) for m in body.get('messages', []) or []
			 if str(m.get('type', '')).upper() in ('FATAL', 'ERROR')]
	if status >= 400:
		return '; '.join(texts) or 'HTTP %d' % status
	return '; '.join(texts) or None


def failing_rules(rules, run):
	"""
	{(rule key, stanza name): error} of the rules whose test search fails. All tests run in one
	search; when it fails, the set is split in two until each failing rule is found alone, so
	k bad rules among n cost about k log2(n) searches.
	"""
	bad = {}

	def check(chunk):
		if not chunk:
			return
		error = run('| makeresults | ' + ' | '.join(r['test'] for r in chunk))
		if error is None:
			return
		if len(chunk) == 1:
			bad[(chunk[0]['key'], chunk[0]['stanza'])] = error
			return
		check(chunk[:len(chunk) // 2])
		check(chunk[len(chunk) // 2:])

	check(list(rules))
	return bad


def _readable_by_everyone(entry):
	acl = entry.get('acl') or {}
	if str(acl.get('sharing', 'global')) not in ('global', 'system'):
		return False
	read = (acl.get('perms') or {}).get('read')
	return read is None or '*' in read


def lookup_problems(definitions, table_files, collections):
	"""
	{lookup definition: reason} for the lookups a search through `tx` may not be able to run.
	The replay runs each automatic lookup as an explicit `lookup` command in every user's
	search; where raw Splunk skips an automatic lookup it cannot run (with a warning), the
	command fails the search. So a lookup is written only when its definition is shared with
	every app and readable by every role, and its table exists: the CSV file for a file lookup
	(also readable by every role), the collection for a KV store lookup.

	definitions   REST entries of data/transforms/lookups (name, content, acl)
	table_files   REST entries of data/lookup-table-files, all apps
	collections   REST entries of storage/collections/config, all apps
	"""
	files = dict((e.get('name'), e) for e in table_files)
	stores = set(e.get('name') for e in collections)
	out = {}
	for entry in definitions:
		name, content = entry.get('name'), entry.get('content') or {}
		if not _readable_by_everyone(entry):
			out[name] = 'the definition is not shared with every app and readable by every role'
		elif content.get('filename'):
			table = files.get(content.get('filename'))
			if table is None:
				out[name] = 'its file %s does not exist' % content.get('filename')
			elif not _readable_by_everyone(table):
				out[name] = 'its file %s is not readable by every role' % content.get('filename')
		elif str(content.get('external_type', '')).lower() == 'kvstore' or content.get('collection'):
			if content.get('collection') not in stores:
				out[name] = 'its KV store collection %s does not exist' % content.get('collection')
	return out


def _dry_events(sts):
	"""
	The made-up events of a dry run: one expanded event per original sourcetype in `sts`, one
	without tenx_sourcetype, and, when there is a sourcetype, two events of the first that arrived
	whole, one read under the compact sourcetype and one under that sourcetype itself, so the
	blocks for whole events run too. The rewrite's hide flag is on.
	"""
	n = len(sts) + 1
	which = ', '.join('tenx_n==%d, %s' % (i + 1, spl_string(st)) for i, st in enumerate(sts))
	head = ('| makeresults count=%d | streamstats count AS tenx_n | eval tenx_sourcetype=case(%s, true(), null()), '
			'tenx_compact_raw="tenx dry run compact", _raw="tenx dry run", sourcetype="tenx_encoded", '
			'source="tenx_dry_run", host="tenx_dry_run", %s=1' % (n + 2 if sts else n, which or 'false(), null()', HIDE))
	if sts:
		head += (' | eval tenx_sourcetype=if(tenx_n>%d, %s, tenx_sourcetype), tenx_compact_raw=if(tenx_n>%d, '
				 '"tenx dry run whole", tenx_compact_raw), _raw=if(tenx_n>%d, "tenx dry run whole", _raw), '
				 'sourcetype=if(tenx_n==%d, %s, sourcetype)' % (n, spl_string(sts[0]), n, n, n + 2, spl_string(sts[0])))
	return head


def macro_dry_run(replay):
	"""
	A search that runs the whole generated definition on the made-up events of _dry_events(), so
	every block of the macro runs. tenxreplay writes the macro only when this runs cleanly.
	"""
	return '%s | %s | stats count' % (_dry_events(sorted(replay.per_sourcetype)), replay.spl())


def units_dry_run(units):
	"""
	A search that runs the given units ({sourcetype: Replay}) composed as the search rewrite
	composes them (compose_units(), with the rewrite's hide flag on), then `tenx-replay-tags`, on
	the made-up events of _dry_events(), so every block of every unit runs.
	"""
	sts = sorted(units)
	parts = [units[sts[0]].spl()]
	for st in sts[1:]:
		parts += ['eval tenx_rprev=%s' % RST, units[st].spl(), 'eval %s=coalesce(%s, tenx_rprev)' % (RST, RST)]
	parts += ['fields - tenx_rprev'] + list(TAGS_STEPS)
	return '%s | %s | stats count' % (_dry_events(sts), ' | '.join(parts))


def failing_units(units, run, limit=262144):
	"""
	{sourcetype: error} of the units whose dry run fails. Units are run together in searches of
	at most about `limit` characters and REPLAY_MAX_COMMANDS top-level commands; a failing search is
	split in two until each failing unit is found alone.
	"""
	bad = {}

	def check(sts):
		if not sts:
			return
		error = run(units_dry_run(dict((st, units[st]) for st in sts)))
		if error is None:
			return
		if len(sts) == 1:
			bad[sts[0]] = error
			return
		check(sts[:len(sts) // 2])
		check(sts[len(sts) // 2:])

	batch, size, commands = [], 0, 0
	for st in sorted(units):
		n, c = len(units[st].spl()), top_level_commands(units[st].spl()) + 3
		if batch and (size + n > limit or commands + c > REPLAY_MAX_COMMANDS):
			check(batch)
			batch, size, commands = [], 0, 0
		batch.append(st)
		size += n
		commands += c
	check(batch)
	return bad


def shared_globally(entries):
	"""
	(the REST entries of props stanzas shared with every app, the names of those that are not).
	An entry without an acl (the [default] stanza read through properties/) is kept.
	"""
	kept, skipped = [], []
	for entry in entries:
		sharing = str((entry.get('acl') or {}).get('sharing', 'global'))
		(kept if sharing in ('global', 'system') else skipped).append(entry)
	return kept, sorted(e.get('name', '') for e in skipped)
