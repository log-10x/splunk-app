"""
Replaying only the rules a `txf` search reads.

`txf` runs the field replay (the `tenx-replay` macro, tenx_replay_builder.py) on every event it
expands: the original sourcetype's field aliases, calculated fields, lookups, event types and tags.
Splunk's optimizer does not drop replay steps a search never reads (measured on Splunk Enterprise
10.4.3: `txf` cost the same with the replay's guards removed), so a search such as
	index=fw `txf` dstip=10.1.2.3 | stats count
paid for every alias, calculated field and lookup of the FortiGate add-on while it read one field
that the add-on's extraction sets.

How a search gets less: tenxreplay writes, beside the macro, the table of its rules ([tenx:plan] in
tenx_replay.conf: each rule's id, the fields it writes, the fields it reads, and whether it needs the
source:: and host:: stanza tests). Every rule in the macro runs inside a guard that passes when the
field tenx_ndall exists or when the search's plan names the rule (guard()). tenxprefilter reads the
search, works out the fields it reads after the macro (needed_fields()), closes them over the table
(closure()), and stores the rules to run on the running job (custom.tenx_replay_plan). `txf` reads that
back in one subsearch and puts the plan's fields on its events (fillnull), right before the replay.
The macro starts by setting tenx_ndall unless the plan's marker for this very macro (its generation)
is there, so the whole replay runs whenever no plan was stored, the plan cannot be read, it was made
for another version of the macro, or the macro is run by anything other than `txf` (the search
rewrite, compiled alerts).

The rest of the search decides. Every one of these runs the whole replay (needed_fields() returns
None):
- the search returns events (no transforming command, and no `fields` or `table` naming what it
  keeps): every field the events carry is part of the result;
- a field name with a wildcard (`table *`, `fields dest*`, `values(*)`), eventtype or tag (event
  types read any field), a command this module does not read, a subsearch, a macro other than the
  one `txf`, a second `tx` or `txf`, anything before `txf` that is not plain search terms;
- a search Splunk keeps the events of (statusBuckets above 0, verbose mode: the events tab shows
  every field), checked by tenxprefilter on the job;
- the macro is not plain `txf` (txf(<sourcetype>) runs its own unit), or it is not in the search's
  text at all (a saved search, a data model, a dashboard panel that only references one).
Reading more fields than a search needs only replays more; never fewer is the requirement, and a field
any command mentions is taken as read.
"""
import json
import re

# The fields the plan puts on each event and the guards test (tenx_replay_builder.guard()).
PREFIX = "tenx_nd"
ALL = "tenx_ndall"
MARK = "tenx_ndm"
# The id of the source:: and host:: stanza tests: no field of its own; needed by any rule whose
# stanza is one of those, or whose precedence over another stanza tests one.
SHARED = 0

TXF = "`txf`"
# Field names Splunk computes from every other field (event types, their tags).
EVERY_FIELD = re.compile(r"^(eventtype|tag|tag::.*)$", re.I)
NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:@-]*$")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class Unknown(Exception):
	"""What a search reads cannot be told: the whole replay runs."""


def _split(text, sep, single=True):
	"""`text` cut at `sep` outside double quotes, single quotes (unless `single` is False), parentheses and brackets."""
	out, buf, depth, i, n, quote = [], [], 0, 0, len(text), None
	while i < n:
		c = text[i]
		if quote:
			buf.append(c)
			if c == "\\" and quote == '"' and i + 1 < n:
				buf.append(text[i + 1])
				i += 2
				continue
			if c == quote:
				quote = None
		elif c == '"' or (c == "'" and single):
			quote = c
			buf.append(c)
		elif c in "([":
			depth += 1
			buf.append(c)
		elif c in ")]":
			depth -= 1
			buf.append(c)
		elif c == sep and depth == 0:
			out.append("".join(buf))
			buf = []
		else:
			buf.append(c)
		i += 1
	if quote or depth:
		raise Unknown("unbalanced quotes or parentheses")
	out.append("".join(buf))
	return out


def _outside_quotes(text):
	"""`text` with every double-quoted string replaced by a space (an unclosed quote: Unknown)."""
	out, i, n = [], 0, len(text)
	while i < n:
		c = text[i]
		if c == '"':
			j = i + 1
			while j < n and text[j] != '"':
				j += 2 if text[j] == "\\" else 1
			if j >= n:
				raise Unknown("unclosed quote")
			out.append(" ")
			i = j + 1
			continue
		out.append(c)
		i += 1
	return "".join(out)


def expression_fields(expr):
	"""
	Every field an eval expression can read, taken widely: each name outside double-quoted strings
	(function names and keywords included, which only widens it) and each 'single-quoted' name. Unknown
	for searchmatch(), which reads fields named inside a string, and for braces (a field named by a value).
	"""
	text = str(expr or "")
	if re.search(r"searchmatch\s*\(", text, re.I):
		raise Unknown("searchmatch")
	bare = _outside_quotes(text)
	if "{" in bare or "}" in bare:
		raise Unknown("a field named by a value")
	found = set(re.findall(r"'([^']*)'", bare))
	bare = re.sub(r"'[^']*'", " ", bare)
	found.update(IDENT.findall(bare))
	return found


def _name(word):
	"""A field name as written (quotes removed); Unknown for a wildcard or anything that is not a plain name."""
	word = word.strip()
	if len(word) >= 2 and word[0] == word[-1] and word[0] in "\"'":
		word = word[1:-1]
	if not word or "*" in word or not NAME.match(word):
		raise Unknown("field name %r" % word)
	return word


def _words(args):
	"""The arguments of a command as words: split at white space and commas outside quotes and parentheses."""
	out = []
	for part in _split(args, ","):
		out.extend(w for w in _split_space(part) if w)
	return out


def _split_space(text):
	out, buf, depth, quote = [], [], 0, None
	for c in text:
		if quote:
			buf.append(c)
			if c == quote:
				quote = None
			continue
		if c in "\"'":
			quote = c
		elif c == "(":
			depth += 1
		elif c == ")":
			depth -= 1
		if c.isspace() and depth == 0:
			out.append("".join(buf))
			buf = []
		else:
			buf.append(c)
	out.append("".join(buf))
	return out


OPTION = re.compile(r"^([A-Za-z_]+)=(.*)$", re.S)


def _options(words, allowed):
	"""(the leading key=value words whose key is in `allowed`, as a dict, the words after them)."""
	opts, i = {}, 0
	while i < len(words):
		m = OPTION.match(words[i])
		if not m or m.group(1).lower() not in allowed:
			break
		opts[m.group(1).lower()] = m.group(2)
		i += 1
	return opts, words[i:]


AGGREGATE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)$", re.S)
NO_ARGUMENT = ("count", "c", "dc", "distinct_count", "per_second", "per_minute", "per_hour", "per_day")


def _aggregate(word, reads):
	"""The fields an aggregation reads: count, count(x), dc(x), avg(eval(...)), sparkline(count(x), 1h)."""
	m = AGGREGATE.match(word)
	if not m:
		if word.lower() in NO_ARGUMENT:
			return
		raise Unknown("aggregation %r" % word)
	inner = m.group(2).strip()
	if m.group(1).lower() == "eval":
		reads.update(expression_fields(inner))
		return
	if not inner:
		return
	for arg in _split(inner, ","):
		arg = arg.strip()
		if AGGREGATE.match(arg):
			_aggregate(arg, reads)
		elif re.match(r"^\d+[a-z]*$", arg, re.I) and m.group(1).lower() == "sparkline":
			continue
		else:
			reads.add(_name(arg))


STATS_OPTIONS = ("allnum", "delim", "partitions", "dedup_splitvals", "global", "window", "current", "time_window",
				 "reset_on_change", "instance_limit", "span", "bins", "minspan", "start", "end", "aligntime", "limit",
				 "useother", "usenull", "otherstr", "nullstr", "partial", "fixedrange", "cont", "format", "sep",
				 "agg", "keepempty")


def _stats(args, kind):
	"""The fields read by stats, eventstats, streamstats, chart and timechart."""
	reads = set()
	words = _words(args)
	opts, words = _options(words, STATS_OPTIONS)
	i, grouping = 0, False
	while i < len(words):
		w = words[i]
		low = w.lower()
		m = OPTION.match(w)
		if m and m.group(1).lower() in STATS_OPTIONS:
			i += 1
			continue
		if m or low.startswith("reset_") or low == "where":
			raise Unknown("%s clause %r" % (kind, w))
		if low in ("by", "over"):
			grouping = True
			i += 1
			continue
		if low == "as":
			if grouping or i + 1 >= len(words):
				raise Unknown("as")
			i += 2
			continue
		if grouping:
			reads.add(_name(w))
		else:
			_aggregate(w, reads)
		i += 1
	return reads


def _top(args):
	words = _words(args)
	opts, words = _options(words, ("limit", "countfield", "percentfield", "showcount", "showperc", "useother",
								   "otherstr"))
	reads = set()
	for w in words:
		if w.lower() == "by":
			continue
		if OPTION.match(w):
			raise Unknown("top option %r" % w)
		reads.add(_name(w))
	return reads


def _search_words(text, parser):
	"""The fields a search's words compare (field=value, field IN (...)); a word alone is matched on _raw."""
	reader = parser.Parser(parser.tokenize(text))
	try:
		tree = reader.parse()
	except parser.Unparsed as e:
		raise Unknown(str(e))
	reads = set()

	def walk(node):
		kind = node[0]
		if kind in ("and", "or"):
			for child in node[1]:
				walk(child)
		elif kind == "not":
			walk(node[1])
		elif kind in ("field", "in"):
			reads.add(_name(node[1]))
		elif kind in ("text", "true"):
			return
		elif kind == "unknown" and re.match(r"^(TERM|CASE)\(", str(node[1])):
			# TERM() and CASE() match the event's text
			return
		else:
			raise Unknown("search term %r" % (node,))
	if any(kind == "subsearch" for kind, _ in parser.tokenize(text)):
		raise Unknown("subsearch")
	walk(tree)
	return reads


def _lookup(args):
	words = _words(args)
	opts, words = _options(words, ("local", "update", "event_time_field"))
	if not words:
		raise Unknown("lookup without a table")
	upper = [w.upper() for w in words]
	if "OUTPUT" not in upper and "OUTPUTNEW" not in upper:
		raise Unknown("lookup without OUTPUT")
	reads, i = set(), 1
	while i < len(words):
		w = words[i]
		if w.upper() in ("OUTPUT", "OUTPUTNEW"):
			i += 1
			continue
		if i + 2 < len(words) and words[i + 1].upper() == "AS":
			reads.add(_name(words[i + 2]))
			i += 3
			continue
		reads.add(_name(w))
		i += 1
	return reads


def _anywhere(words, allowed):
	"""(the key=value words whose key is in `allowed`, wherever they are written, as a dict, the other words)."""
	opts, rest = {}, []
	for w in words:
		m = OPTION.match(w)
		if m and m.group(1).lower() in allowed:
			opts[m.group(1).lower()] = m.group(2)
		else:
			rest.append(w)
	return opts, rest


def _single_field(args, allowed, default=None):
	opts, words = _anywhere(_words(args), allowed)
	if len(words) > 1 and words[1].lower() == "as":
		words = words[:1] + words[3:]
	if len(words) != 1:
		if not words and default:
			return set([default])
		raise Unknown("expected one field: %r" % args)
	return set([_name(words[0])])


def _command(name, args, parser):
	"""(fields read, ends: the command's output holds only what it names or computes). Unknown otherwise."""
	if name in ("stats", "chart", "timechart"):
		return _stats(args, name), True
	if name in ("eventstats", "streamstats"):
		return _stats(args, name), False
	if name in ("top", "rare"):
		return _top(args), True
	if name == "search":
		return _search_words(args, parser), False
	if name == "where":
		return expression_fields(args), False
	if name == "eval":
		reads = set()
		for part in _split(args, ","):
			m = re.match(r"^\s*(\"[^\"]*\"|'[^']*'|[^=\s]+)\s*=(?!=)(.*)$", part, re.S)
			if not m:
				raise Unknown("eval %r" % part)
			_name(m.group(1))
			reads.update(expression_fields(m.group(2)))
		return reads, False
	if name in ("fields", "table"):
		text = args.strip()
		if name == "fields" and text.startswith("-"):
			for w in _words(text[1:]):
				_name(w)
			return set(), False
		if name == "fields" and text.startswith("+"):
			text = text[1:]
		names = set(_name(w) for w in _words(text))
		if not names:
			raise Unknown("%s with no field" % name)
		return names, True
	if name == "rename":
		reads, words = set(), _words(args)
		if len(words) % 3:
			raise Unknown("rename")
		for k in range(0, len(words), 3):
			if words[k + 1].lower() != "as":
				raise Unknown("rename")
			reads.add(_name(words[k]))
			_name(words[k + 2])
		return reads, False
	if name == "dedup":
		words = _words(args)
		opts, words = _options(words, ("keepevents", "keepempty", "consecutive"))
		reads = set()
		if words and re.match(r"^\d+$", words[0]):
			words = words[1:]
		sortby = False
		for w in words:
			if w.lower() == "sortby":
				sortby = True
				continue
			if sortby:
				w = w.lstrip("+-")
				m = AGGREGATE.match(w)
				if m and m.group(1).lower() in ("auto", "str", "ip", "num"):
					w = m.group(2)
			reads.add(_name(w))
		if not reads:
			raise Unknown("dedup with no field")
		return reads, False
	if name == "sort":
		words = _words(args)
		opts, words = _options(words, ("limit",))
		if words and re.match(r"^\d+$", words[0]):
			words = words[1:]
		if words and words[-1].lower() in ("d", "desc"):
			words = words[:-1]
		reads = set()
		for w in words:
			if w in ("+", "-"):
				continue
			w = w.lstrip("+-")
			m = AGGREGATE.match(w)
			if m and m.group(1).lower() in ("auto", "str", "ip", "num"):
				w = m.group(2)
			reads.add(_name(w))
		return reads, False
	if name in ("head", "tail"):
		words = _words(args)
		opts, words = _options(words, ("limit", "null", "keeplast"))
		if not words or (len(words) == 1 and re.match(r"^\d+$", words[0])):
			return set(), False
		if name == "head":
			return expression_fields(args), False
		raise Unknown("tail %r" % args)
	if name in ("reverse", "addinfo"):
		if args.strip():
			raise Unknown(name)
		return set(), False
	if name == "noop":
		return set(), False
	if name == "rex":
		opts, words = _anywhere(_words(args), ("field", "mode", "max_match", "offset_field"))
		return set([_name(opts.get("field", "_raw"))]), False
	if name == "spath":
		opts, words = _anywhere(_words(args), ("input", "output", "path"))
		return set([_name(opts.get("input", "_raw"))]), False
	if name == "lookup":
		return _lookup(args), False
	if name == "fillnull":
		words = _words(args)
		opts, words = _options(words, ("value",))
		if not words:
			raise Unknown("fillnull of every field")
		return set(_name(w) for w in words), False
	if name in ("makemv", "mvexpand", "nomv"):
		return _single_field(args, ("delim", "tokenizer", "allowempty", "setsv", "limit")), False
	if name in ("bin", "bucket"):
		return _single_field(args, ("span", "bins", "minspan", "start", "end", "aligntime")), False
	raise Unknown("command %r" % name)


def _pipes(text):
	"""
	The commands of a search text: cut at pipes outside quotes and brackets. A single quote names a field in
	eval and where and is a plain character in search words; where reading it either way cuts the text
	differently (user=o'brien | eval x='a b'), the commands are not known.
	"""
	cut = _split(text, "|")
	if cut != _split(text, "|", single=False):
		raise Unknown("a single quote changes where the commands end")
	return cut


def needed_fields(search, parser):
	"""
	The fields a search that runs plain `txf` once reads after it (a set of names), or None when that
	cannot be told and the whole replay must run. `parser` is tenx_prefilter_parser (tokenize, Parser,
	macro_call, macro_calls).
	"""
	try:
		return _needed(search or "", parser)
	except Unknown:
		return None


def _needed(search, parser):
	call = parser.macro_call(search)
	if call is None or call[1] != TXF or parser.macro_calls(search) != 1:
		raise Unknown("not one plain txf")
	before, rest = call[0], search[len(call[0]) + len(call[1]):]
	plain = _outside_quotes(before)
	if any(c in plain for c in "|[]`") or "`" in _outside_quotes(rest):
		raise Unknown("before txf, or a macro after it")
	commands = _pipes(rest)
	if any("[" in _outside_quotes(c) for c in commands):
		raise Unknown("subsearch")
	reads = _search_words(commands[0], parser)
	ends = False
	for text in commands[1:]:
		text = text.strip()
		if not text:
			raise Unknown("empty command")
		name = text.split(None, 1)[0].lower()
		got, ends = _command(name, text[len(name):].strip(), parser)
		reads |= got
		if ends:
			break
	if not ends:
		raise Unknown("the search returns its events")
	if any(EVERY_FIELD.match(f) for f in reads):
		raise Unknown("event types or tags")
	return reads


def closure(rules, needed):
	"""
	The ids of the rules to run for `needed` (field names): every rule that writes a needed field, and,
	again, every rule that writes a field those rules read, until nothing is added; SHARED when one of
	them needs the source:: and host:: stanza tests. Names compare without case (only widening). None
	when a rule to run reads fields that cannot be listed ('*'). `rules`: [[id, writes, reads, shared]].
	"""
	need = set(f.lower() for f in needed)
	chosen = set()
	changed = True
	while changed:
		changed = False
		for rid, writes, reads, shared in rules:
			if rid in chosen or not any(w.lower() in need for w in writes):
				continue
			if "*" in reads:
				return None
			chosen.add(rid)
			need.update(r.lower() for r in reads)
			if shared:
				chosen.add(SHARED)
			changed = True
	return chosen


def flags(generation, ids):
	"""The fields the plan puts on every event: the marker of the macro it was made for, and one field
	naming the ids, which each guard of those rules matches (tenx_nd<generation>_<id>_..._)."""
	return "%s%s %s%s_%s" % (MARK, generation, PREFIX, generation, "".join("%d_" % i for i in sorted(ids)))


GENERATION = re.compile(r"^[0-9a-f]{8}$")


def read_table(entry):
	"""(generation, rules) from the [tenx:plan] stanza's keys, or None when it is missing or not readable."""
	try:
		generation = str(entry.get("generation", "")).strip()
		rules = json.loads(entry.get("rules", ""))
		if not GENERATION.match(generation) or not isinstance(rules, list):
			return None
		out = []
		for r in rules:
			rid, writes, reads, shared = r
			if not isinstance(rid, int) or not all(isinstance(x, str) for x in list(writes) + list(reads)):
				return None
			out.append((rid, list(writes), list(reads), bool(shared)))
		return generation, out
	except (ValueError, TypeError, AttributeError):
		return None


# The most rules a plan names: past it the plan field's name grows long and the saving is small, so
# the whole replay runs instead.
MAX_SHARE = 0.6


def plan_value(table, needed):
	"""The value stored on the job (custom.tenx_replay_plan), or None for the whole replay."""
	if table is None or needed is None:
		return None
	generation, rules = table
	ids = closure(rules, needed)
	if ids is None or len([i for i in ids if i != SHARED]) > MAX_SHARE * max(len(rules), 1):
		return None
	return flags(generation, ids)
