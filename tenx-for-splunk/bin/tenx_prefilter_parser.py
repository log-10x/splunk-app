"""
The words after the `tx` macro, read as a search, and the prefilter built from them.

`tx` is written in front of an ordinary search: index=app_logs `tx` error "payment failed".
Its subsearch runs the tenxprefilter command once per search. The command reads the job's
own search text, and this module

1. takes the text after the first `tx` that is outside quotes, up to the first pipe that is
   outside quotes and brackets (`txf` and `txf(<sourcetype>)`, the same search with the
   original sourcetype's fields replayed, are read the same way);
2. parses it as Splunk search terms: quoted phrases (with backslash escapes), parentheses,
   NOT, OR and AND with Splunk's precedence (NOT, then OR, then the implied AND), field
   comparisons (a quoted or unquoted name, spaces or none around the operator), field IN (...),
   indexed field terms (host::x), TERM() and CASE(), subsearches. A word or phrase is a required
   search term only when the parser recognises it as one: a plain word (no operator, quote,
   bracket, backslash or backtick in it) or a phrase. Every other token sequence places no
   restriction, and where the shape of the whole search is in doubt (a macro, AND, OR or IN where
   a term should be, IN without its parentheses) the search is not narrowed at all (Unparsed).
   TERM() and CASE() place no restriction: `tx` applies the user's words after a pipe, where
   Splunk tests them against the event's text, and for some arguments that differs from the same
   search on an index;
3. builds the prefilter. A word or phrase is cut into pieces at the characters Splunk breaks
   indexed text at (SEGMENT_BREAKERS, the same set the search rewrite uses) and at white space;
   each piece must appear in the compact event as a value (TERM(piece)) or be carried by the
   event's template (TERM(<token of the template's hash>)). A piece is not used when a rendered
   timestamp could print text it matches (any run of digits, month and day names, 14t10, and any
   wildcard that can match such text: 2026*, nov*, *t10; see timestamp_could_print()), when it
   holds a character outside a-z and 0-9, when a wildcard sits between two of its characters
   (Splunk matches that across a minor breaker the compact text does not keep), or when more than
   MAX_TEMPLATES templates carry it. A character that is neither a letter, a digit nor a breaker
   stays in its piece, so the piece is not used: Splunk indexes PROGRA~1 (a short name in a
   Windows path) as one term, and TERM(progra) would miss it. Inside a phrase a backslash
   escapes only a quote or a backslash; any other backslash is kept and breaks the phrase into
   pieces there, so "C:\\Program Files\\Google" gives c, program, files and google. A NOT, a
   subsearch, and a field compared with anything but = place no restriction. An OR with any
   unrestricted branch places none.
   "When a rendered timestamp could print it" is read two ways: the piece alone looks like
   timestamp text (TIMESTAMP_PIECE: one or two digits, a year, an epoch, a month name ...), or
   the piece sits inside a written date or time in the searched text (TIME_FORMS: 20:11:45.936,
   2025-11-12, 20251112, a zone offset +0000). The engine stores a timestamp as an epoch and
   tx-inflate prints it again, so no digit of such a form is a term of the compact event: the
   936 of "20:11:45.936" is three digits, which the first test alone kept, and the search found
   none of the events that hold it.
   A run of digits (4625, 54849625) is the one exception the stored templates can settle: a token
   that starts with a digit is always a value of the compact event (FORMAT_SPEC S3.2), so the
   timestamp is the only text that prints digits the compact event does not hold. tenxprefilter
   reads the timestamp formats of the stored templates (FORMAT_KEY_STEPS, in the same read of the
   KV store as the template dictionary), and a run of digits that
   none of them can print (timestamp_prints()) is used like any other piece; one that some format
   can print (a year, the two digits of a minute, a fraction of the same length) is not. When the
   formats cannot be read, no run of digits is used.

   Field narrowing is off unless tenx_config.conf [config] says field_narrowing = true, and
   then only once tenxreplay has written the list it needs; off, field comparisons place no
   restriction (tests/test_prefilter_narrowing_opt_in.py compares this with a copy of the parser
   without narrowing). On:
   field=value and field IN (...) restrict like their value written as a word, but only when
   the caller says the field's value is read from the event's text (`text_field`): not
   Splunk's default or indexed fields, not event types or tags, not a field fields.conf marks
   INDEXED_VALUE = false, and not a field that any props stanza produces with a calculated
   field, a lookup, an extraction from metadata, or an alias of one of those. The tenxreplay
   command writes that list (tenx_replay.conf, [tenx:narrowing]). This is the same assumption
   Splunk makes for field=value on an ordinary index, where the value is looked up as a term
   of the raw text unless fields.conf says INDEXED_VALUE = false. Also on: a piece that the
   compact event stores in another written form is not used (see form_spans()).

4. reads an IPv4 address in a word, phrase or text field value as a whole. Every part of the
   address, one- and two-digit parts included, must be a term of the compact event:
   (TERM(<part>) OR TERM(<address>)). Where the engine stored the address cut, each part is a
   value of its own, so TERM(<part>) holds. Where it stored the address as one value (its
   ipv4SingleToken option), TERM(<address>) holds, and so does TERM(<part>), because Splunk
   indexes the pieces between minor breakers too (observed on Splunk Enterprise 10.4.3). An
   index holding both forms is therefore searched correctly, and no template lookup is needed.
   A prefix of three whole parts and a wildcard, 10.0.1.*, requires those parts the same way,
   TERM(<part>) each.
   Two exceptions, both from the format: a first part of 1 is not required, because "-1"
   before a dot stays template text (FORMAT_SPEC S2.2); and an address printed by a timestamp
   slot whose format has dots is not covered, the same limit the piece rule above has for a
   three-digit piece. This rule applies with field narrowing off and on.

Anything the prefilter leaves unrestricted is still applied, exactly, by the search that
follows `tx` on the expanded text. The prefilter only selects which compact events to expand,
so it may select more than the search keeps, never fewer.
"""
import fnmatch
import re
import time
import urllib.parse

MACRO = "`tx`"
# The macros whose subsearch runs tenxprefilter: `tx`, `txf` and `txf(<sourcetype>)`.
MACRO_CALL = re.compile(r"`(?:tx|txf|txf\([^`()]*\))`")
MAX_TEMPLATES = 5000
TIME_FIELDS = frozenset(("earliest", "latest", "earliest_time", "latest_time", "starttime", "endtime",
                         "starttimeu", "endtimeu"))
# A piece a rendered timestamp could print: one or two digits, a year, an epoch, 12t08, 153z, a
# kube-apiserver I1012, month and day names, am/pm, utc/gmt.
TIMESTAMP_PIECE = re.compile(
	r"^(?:[0-9]{1,2}|(?:19|20)[0-9]{2}|[0-9]{10}|[0-9]{13}|[0-9]{1,2}t[0-9]{0,2}|[0-9]+z|[iwef][0-9]{4}|"
	r"jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|january|february|march|april|june|july|august|"
	r"september|october|november|december|mon|tue|wed|thu|fri|sat|sun|monday|tuesday|wednesday|"
	r"thursday|friday|saturday|sunday|am|pm|utc|gmt)$")
# Splunk's default segment breakers, major and minor, as single characters; '*' is left out, as a
# wildcard of the search it stays in its piece. The same set as tenx_search_builder.SEGMENT_BREAKERS.
SEGMENT_BREAKERS = frozenset("[]<>(){}|!;,'\"\n\r\t &?+/:=@.-$#%\\_")
# A field name as a search writes it unquoted: Splunk takes the text before the operator, and an
# extracted field's name can hold almost anything its source wrote (a Kubernetes label key from
# JSON, kubernetes.labels.app.kubernetes.io/name, holds dots and a slash). Everything but white
# space, quotes, brackets, parentheses, a pipe, a backtick, a backslash, a comma and the operator
# characters.
NAME_CHARS = r"[^\s\"'()\[\]|`\\,=<>!]"
FIELD_TERM = re.compile(r"^(" + NAME_CHARS + r"+)(!=|<=|>=|=|<|>)(.*)$", re.S)
# Written forms of a date or a time in searched text (see the module docstring). A piece that
# overlaps one is not used. Matching more than a timestamp prints only leaves a piece unused,
# which expands more compact events and never drops one the search after `tx` would keep.
TIME_FORMS = (
	# times: 08:00, 8:00:00, 08:00:00.123456, 08:00:00,123, 20:11:46:346 (not 10.0.1.14:8443)
	re.compile(r"(?<![0-9])(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?(?:[.,:]\d{1,9})?(?![0-9])"),
	# dates: 2024-03-15, 2024/03/15, 15.03.2024, 03/15/24 (not inside 192.168.33.161)
	re.compile(r"(?<![0-9.])(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})(?![0-9]|\.[0-9])"),
	# an epoch with a fraction: 1763020800.123, 1763020800123.456
	re.compile(r"(?<![0-9])(?:\d{10}|\d{13})[.,]\d{1,9}(?![0-9])"),
	# dates and times without separators: 20240315, 20240315080000, 080000, 080000123
	re.compile(r"(?<![0-9])(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d*(?![0-9])"),
	re.compile(r"(?<![0-9])(?:[01]\d|2[0-3])[0-5]\d[0-5]\d\d*(?![0-9])"),
	# epochs in microseconds and nanoseconds (10 and 13 digits are TIMESTAMP_PIECE already)
	re.compile(r"(?<![0-9])(?:\d{16}|\d{19})(?![0-9])"),
	# zone offsets: +0000, -04:00
	re.compile(r"[-+](?:[01]\d|2[0-3]):?[0-5]\d(?![0-9])"),
)
FIELD_NAME = re.compile(r"^" + NAME_CHARS + r"+$")
OPERATOR = re.compile(r"^(?:!=|<=|>=|=|<|>)")
# A word that is a search term and nothing else: no comparison operator, quote, bracket, backslash
# or backtick in it (each of those is syntax, or an escape Splunk resolves before it matches).
PLAIN_WORD = re.compile(r'^[^=<>"\[\]\\`]+$')
INDEXED_TERM = re.compile(r"^([A-Za-z0-9_.@{}\-]+)::(.*)$", re.S)
# An IPv4 address in a search word, cut the way the engine's ipv4SingleToken option cuts it: four
# parts of 1 to 3 digits joined by single dots, the first not right after a letter or digit or
# after a digit and a dot, the last not followed by a letter or digit or by a dot and a digit.
# Each part must also be 255 or less (checked in addresses_of). A wildcard next to the first or
# the last part makes that part a fragment of a longer number (*10.0.1.14 matches 110.0.1.14,
# 10.0.2.1* matches 10.0.2.14), so neither is read as an address.
ADDRESS = re.compile(r"(?<![0-9A-Za-z*])(?<![0-9]\.)([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})"
					 r"(?![0-9A-Za-z*])(?!\.[0-9])")
# Three whole parts of an address and a wildcard for the fourth: 10.0.1.* or 10.0.1.1*. Shorter
# prefixes (10.0.*) are left to the piece rule: two dotted numbers are as likely a date or a time.
ADDRESS_PREFIX = re.compile(r"(?<![0-9A-Za-z*])(?<![0-9]\.)((?:[0-9]{1,3}\.){3})[0-9]{0,2}\*")


class Unparsed(Exception):
	"""The text after `tx` is not a search this module can read; the caller reads every event."""


def text_after_macro(search):
	"""The text after the first `tx` (or `txf`, `txf(...)`) outside quotes, up to the first top-level pipe; None if absent."""
	i, n, quoted, start = 0, len(search), False, -1
	while i < n:
		c = search[i]
		if quoted:
			if c == "\\":
				i += 2
				continue
			if c == '"':
				quoted = False
		elif c == '"':
			quoted = True
		elif c == "`" and MACRO_CALL.match(search, i):
			start = MACRO_CALL.match(search, i).end()
			break
		i += 1
	if start < 0:
		return None
	i, quoted, depth = start, False, 0
	while i < n:
		c = search[i]
		if quoted:
			if c == "\\":
				i += 2
				continue
			if c == '"':
				quoted = False
		elif c == '"':
			quoted = True
		elif c == "[":
			depth += 1
		elif c == "]":
			depth -= 1
		elif c == "|" and depth <= 0:
			return search[start:i]
		i += 1
	return search[start:]


class Tokens(list):
	"""The tokens of tokenize(); `glued` holds the positions of the tokens written right after the one
	before them, with no white space between (`"abc"def` is a phrase and a glued word)."""

	def __init__(self):
		list.__init__(self)
		self.glued = set()
		# (start, end) of each token in the text it was read from
		self.spans = []


def macro_call(search):
	"""(the text before the first `tx`, `txf` or `txf(...)` outside quotes, the macro call written), or None."""
	i, n, quoted = 0, len(search), False
	while i < n:
		c = search[i]
		if quoted:
			if c == "\\":
				i += 2
				continue
			if c == '"':
				quoted = False
		elif c == '"':
			quoted = True
		elif c == "`" and MACRO_CALL.match(search, i):
			return search[:i], MACRO_CALL.match(search, i).group(0)
		i += 1
	return None


def macro_calls(search):
	"""How many `tx`, `txf` or `txf(...)` calls `search` holds outside quotes."""
	i, n, quoted, count = 0, len(search), False, 0
	while i < n:
		c = search[i]
		if quoted:
			if c == "\\":
				i += 2
				continue
			if c == '"':
				quoted = False
		elif c == '"':
			quoted = True
		elif c == "`" and MACRO_CALL.match(search, i):
			count += 1
			i = MACRO_CALL.match(search, i).end()
			continue
		i += 1
	return count


def _specifiers(before, name):
	"""The values of `name`=x and `name`::x written as search terms in `before` (quoted values
	unquoted; a phrase, or a value inside another field's quotes, is not a term; a term under NOT,
	or inside parentheses after NOT, is left out)."""
	found, tokens = [], list(tokenize(before or ""))
	negated, depth, i = [], 0, 0
	while i < len(tokens):
		kind, value = tokens[i]
		if kind == "(":
			depth += 1
		elif kind == ")":
			depth -= 1
			while negated and negated[-1] > depth:
				negated.pop()
		elif kind == "word" and value == "NOT":
			if i + 1 < len(tokens) and tokens[i + 1][0] == "(":
				negated.append(depth + 1)
			else:
				i += 2
				continue
		elif kind == "word" and not negated:
			m = FIELD_TERM.match(value)
			if m and m.group(1).lower() == name and m.group(2) == "=":
				found.append(unquote(m.group(3)))
			else:
				m = INDEXED_TERM.match(value)
				if m and m.group(1).lower() == name:
					found.append(unquote(m.group(2)))
		i += 1
	return [v for v in dict.fromkeys(found) if v]


def named_sourcetypes(before, tree, after_counts):
	"""
	The sourcetypes a `tx` search names: written before the macro (sourcetype=x, sourcetype::x),
	and, when `after_counts`, compared after it (sourcetype=x, sourcetype IN (...)), not under NOT.
	A compact event is indexed as the compact sourcetype, and `tx` leaves that on the expanded
	event (`txf` gives it its original sourcetype), so a search that names the ORIGINAL sourcetype
	in those places matches none of its compact events. Wildcards are kept: the probe tells a
	value that selects the compact sourcetype itself (tenx*, *) from one that does not (fr:*).
	"""
	found = _specifiers(before, "sourcetype")

	def walk(node):
		if node[0] == "field" and node[1].lower() == "sourcetype" and node[2] in ("=", "::"):
			found.append(node[3])
		elif node[0] == "in" and node[1].lower() == "sourcetype":
			found.extend(v for v in node[2] if v)
		elif node[0] in ("and", "or"):
			for child in node[1]:
				walk(child)
	if after_counts and tree is not None:
		walk(tree)
	return [v for v in dict.fromkeys(found) if v and v.strip("*")]


def named_indexes(before):
	"""The index values written before the macro."""
	return _specifiers(before, "index")


def original_sourcetype_probe(sourcetypes, indexes):
	"""
	The tstats that finds compact events (not field-mapped) whose original sourcetype
	(tenx_sourcetype) is one of `sourcetypes` while their indexed sourcetype is none of them, in
	`indexes` (all the user searches when none), or None. Those are the events such a search
	misses; a value that also selects the compact sourcetype (tenx_encoded, tenx*) finds none.
	"""
	if not sourcetypes:
		return None
	quote = lambda v: '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
	where = "(%s) " % " OR ".join("index=%s" % quote(i) for i in sorted(indexes)) if indexes else ""
	return "| tstats count where %s`tenx-events` NOT tenx_mapped=* (%s) NOT (%s) by tenx_sourcetype" % (
		where, " OR ".join("tenx_sourcetype=%s" % quote(v) for v in sorted(sourcetypes)),
		" OR ".join("sourcetype=%s" % quote(v) for v in sorted(sourcetypes)))


def original_sourcetype_message(rows, macro):
	"""
	The message that stops a `tx` or `txf` search naming the original sourcetype of compact events (`rows` of the
	probe). Splunk keeps the first 256 characters of a search command's message, so the message says what to write
	first and stays within that length for sourcetype names of common length.
	"""
	sts = sorted(set(r.get("tenx_sourcetype", "") for r in rows if r.get("tenx_sourcetype"))) or ["<sourcetype>"]
	name = macro.strip("`").split("(")[0]
	named = " and ".join("sourcetype=%s" % st for st in sts)
	write = " OR ".join("tenx_sourcetype=%s" % st for st in sts)
	write = write if len(sts) == 1 else "(%s)" % write
	if name == "tx":
		# `txf` first: `tx` gives only the fields in an event's text, so a field an add-on defines matches
		# nothing after `tx` (tenx_sourcetype=XmlWinEventLog `tx` EventCode=4624: 0 events, raw 21).
		original = " OR ".join("sourcetype=%s" % st for st in sts)
		original = original if len(sts) == 1 else "(%s)" % original
		return ("tx: the search was not run. Write %s after `txf` for the %s fields; %s before `tx` gives only the "
				"fields in their text. %s %s no compact event."
				% (original, "add-on's" if len(sts) == 1 else "add-ons'", write, named, "matches" if len(sts) == 1 else "match"))
	do = "Write %s before `%s`, or the sourcetype after it: `txf` gives each event its original sourcetype." % (write, name)
	if len(sts) == 1:
		why = "%s selects no compact events: they carry it in tenx_sourcetype." % named
	else:
		why = "%s select no compact events: they carry them in tenx_sourcetype." % named
	return "%s: the search was not run. %s %s" % (name, do, why)


def tokenize(text):
	tokens, i, n = Tokens(), 0, len(text)
	space = True
	while i < n:
		c = text[i]
		if c.isspace():
			i += 1
			space = True
			continue
		if not space and tokens:
			tokens.glued.add(len(tokens))
		space = False
		if c == '"':
			j, buf = i + 1, []
			while j < n:
				if text[j] == "\\" and j + 1 < n:
					# \" and \\ stand for the character; any other backslash is text
					if text[j + 1] not in '"\\':
						buf.append(text[j])
					buf.append(text[j + 1])
					j += 2
					continue
				if text[j] == '"':
					j += 1
					break
				buf.append(text[j])
				j += 1
			tokens.append(("phrase", "".join(buf)))
			tokens.spans.append((i, j))
			i = j
			continue
		if c in "()":
			tokens.append((c, c))
			tokens.spans.append((i, i + 1))
			i += 1
			continue
		if c == "[":
			depth, j = 0, i
			while j < n:
				if text[j] == '"':
					j += 1
					while j < n and text[j] != '"':
						j += 2 if text[j] == "\\" else 1
				elif text[j] == "[":
					depth += 1
				elif text[j] == "]":
					depth -= 1
					if depth == 0:
						j += 1
						break
				j += 1
			tokens.append(("subsearch", ""))
			tokens.spans.append((i, j))
			i = j
			continue
		j, buf = i, []
		while j < n and not text[j].isspace() and text[j] not in "()[":
			if text[j] == '"':
				k = j + 1
				while k < n:
					if text[k] == "\\" and k + 1 < n:
						k += 2
						continue
					if text[k] == '"':
						k += 1
						break
					k += 1
				buf.append(text[j:k])
				j = k
				continue
			buf.append(text[j])
			j += 1
		tokens.append(("word", "".join(buf)))
		tokens.spans.append((i, j))
		i = j
	return tokens


class Parser(object):
	"""NOT binds tightest, then OR, then AND (written or implied), as in Splunk's search language."""

	def __init__(self, tokens):
		self.tokens, self.i = tokens, 0
		self.time_modifier = False
		self.unquoted_comma = False
		# id() of each ("text", ...) node made from one word or phrase token -> that token's index
		self.text_at = {}
		# id() of each TERM() or CASE() node -> (TERM or CASE, its one word or None, first token, last token)
		self.call_at = {}

	def _peek(self, k=0):
		return self.tokens[self.i + k] if self.i + k < len(self.tokens) else (None, None)

	def _take(self):
		token = self._peek()
		self.i += 1
		return token

	def parse(self):
		if not self.tokens:
			return ("true",)
		if any(kind == "word" and "`" in value for kind, value in self.tokens):
			# A macro after tx expands to search text this module never sees, operators included.
			raise Unparsed("a macro after tx")
		node = self._and()
		if self.i < len(self.tokens):
			raise Unparsed("unbalanced parentheses")
		return node

	def _and(self):
		nodes = [self._or()]
		while self._peek()[0] not in (None, ")"):
			if self._peek() == ("word", "AND"):
				self._take()
			nodes.append(self._or())
		return ("and", nodes) if len(nodes) > 1 else nodes[0]

	def _or(self):
		nodes = [self._not()]
		while self._peek() == ("word", "OR"):
			self._take()
			nodes.append(self._not())
		return ("or", nodes) if len(nodes) > 1 else nodes[0]

	def _not(self):
		if self._peek() == ("word", "NOT"):
			self._take()
			return ("not", self._not())
		return self._primary()

	def _glued(self):
		"""Whether the next token is written right after the one just taken, with no space."""
		return self.i in getattr(self.tokens, "glued", ())

	def _in_values(self, field):
		"""After `<field> IN`: the values up to the closing parenthesis, as ("in", field, values)."""
		self._take()
		values = []
		while self._peek()[0] not in (")", None):
			kind_, item = self._take()
			if kind_ == "phrase":
				values.append(item)
			elif kind_ == "word":
				values.extend(unquote(v) for v in item.split(",") if v)
			else:
				values.append(None)
		if self._take()[0] != ")":
			raise Unparsed("IN without its closing parenthesis")
		return ("in", field, values)

	def _primary(self):
		kind, value = self._take()
		if kind is None:
			raise Unparsed("an operator with nothing after it")
		if kind == "(":
			node = self._and()
			if self._take()[0] != ")":
				raise Unparsed("unbalanced parentheses")
			return node
		if kind == "subsearch":
			return ("true",)
		if kind == "phrase":
			following = self._peek()
			if following[0] == "word" and OPERATOR.match(following[1]):
				# A quoted field name compared: `"requestParameters.VersioningConfiguration.Status"=Suspended`,
				# `"usr" != root`. Read as text, the name and the value were required words, and for != the
				# value is what the search excludes. The value is read as for an unquoted name; anything else
				# after the operator is not read with certainty, and the search is not narrowed at all.
				self._take()
				op = OPERATOR.match(following[1])
				rest = following[1][op.end():]
				if not rest:
					kind_, rest = self._peek()
					if kind_ == "phrase":
						self._take()
						rest = '"' + rest.replace('\\', '\\\\').replace('"', '\\"') + '"'
					elif kind_ == "word" and rest not in ("AND", "OR", "NOT") and not OPERATOR.match(rest):
						self._take()
					else:
						raise Unparsed("a comparison whose value is not a word or a phrase: " + value)
				return ("field", value, op.group(0), unquote(rest))
			if following == ("word", "IN"):
				# A quoted field name before IN: `"user" IN (alice, bob)`. Read as text, the name, the
				# keyword and each value were required words.
				self._take()
				if self._peek()[0] != "(":
					raise Unparsed("IN without a parenthesis after it")
				return self._in_values(value)
			if following[0] in ("word", "phrase") and self._glued():
				# A phrase with a word written right after it (`"abc"def`): not a form this module reads
				# with certainty, so it places no restriction.
				self._take()
				return ("unknown", value)
			node = ("text", value)
			self.text_at[id(node)] = self.i - 1
			return node
		if kind != "word":
			raise Unparsed("unexpected %s" % kind)
		if value in ("AND", "OR", "IN"):
			raise Unparsed("%s where a search term should be" % value)
		following = self._peek()
		if value in ("TERM", "CASE") and following[0] == "(":
			first = self.i - 1
			self._take()
			inner, kinds = [], []
			while self._peek()[0] not in (")", None):
				kind_, item = self._take()
				if kind_ not in ("word", "phrase"):
					raise Unparsed("%s() holding %s" % (value, kind_))
				inner.append(item)
				kinds.append(kind_)
			if self._take()[0] != ")":
				raise Unparsed("%s( without its closing parenthesis" % value)
			# `tx` applies the user's words after a pipe, where Splunk tests TERM() and CASE() against
			# the event's text, which for some arguments differs from the same search on an index
			# (TERM(pattern=*.log): 0 events on the index, 1,025 after a pipe, Splunk Enterprise 10.4.3).
			# Which words every such event holds is not certain, so they place no restriction on the
			# prefilter. wild_plan() matches some of them as the index does before the final search.
			node = ("unknown", "%s(%s)" % (value, " ".join(inner)))
			self.call_at[id(node)] = (value, inner[0] if kinds == ["word"] else None, first, self.i - 1)
			return node
		if following == ("word", "IN"):
			self._take()
			if self._peek()[0] != "(":
				raise Unparsed("IN without a parenthesis after it")
			return self._in_values(value)
		if FIELD_NAME.match(value) and following[0] == "word" and value not in ("AND", "OR", "NOT"):
			# A comparison written with spaces: `eventName = DeleteTrail`, `userAgent !=console.amazonaws.com`,
			# `src_ip != "x"`. Splunk reads these as field comparisons; read as words, the field name would be
			# required in the compact event, where it is template text.
			op = OPERATOR.match(following[1])
			if op:
				self._take()
				rest = following[1][op.end():]
				if not rest and self._peek()[0] in ("word", "phrase"):
					kind_, rest = self._take()
					if kind_ == "phrase":
						rest = '"' + rest.replace('\\', '\\\\').replace('"', '\\"') + '"'
				value = value + op.group(0) + rest
		match = FIELD_TERM.match(value)
		if match and match.group(1) and not match.group(3) and self._peek()[0] is not None:
			# The operator ends the word and the value follows after a space: `SignatureStatus!= Valid`,
			# `count>= 5`, `user= "a b"`. Read as a comparison with no value, the next word was required
			# text, and for != that is the value the search excludes (Splunk Enterprise 10.4.3, Sysmon,
			# `SignatureStatus!= Valid`: 108 events through `txf` against 259). The next word or phrase is
			# the value. Anything else after the operator is not read with certainty, so the search is not
			# narrowed at all (Unparsed: every compact event in range is expanded).
			kind_, rest = self._peek()
			if kind_ == "phrase":
				self._take()
				rest = '"' + rest.replace('\\', '\\\\').replace('"', '\\"') + '"'
			elif kind_ == "word" and rest not in ("AND", "OR", "NOT") and not OPERATOR.match(rest):
				self._take()
			else:
				raise Unparsed("a comparison whose value is not a word or a phrase: %s" % value)
			match = FIELD_TERM.match(value + rest)
		if match and match.group(1):
			if match.group(1).lower() in TIME_FIELDS:
				self.time_modifier = True
			return ("field", match.group(1), match.group(2), unquote(match.group(3)))
		indexed = INDEXED_TERM.match(value)
		if indexed:
			# An indexed field term, `host::web-01`, `sourcetype::tenx_encoded`: matched against the
			# event's indexed fields, never its text.
			return ("field", indexed.group(1), "::", indexed.group(2))
		if self._peek()[0] == "word" and OPERATOR.match(self._peek()[1]):
			# A word, then an operator word: a comparison whose name this module does not read (the
			# name rule above took every name it can). The name, the operator and the value place no
			# restriction.
			self._take()
			if OPERATOR.fullmatch(self._peek(-1)[1]) and self._peek()[0] in ("word", "phrase") \
					and self._peek() not in (("word", "AND"), ("word", "OR"), ("word", "NOT")):
				self._take()
			return ("unknown", value)
		if not PLAIN_WORD.match(value) or value in ("TERM", "CASE"):
			# Not a search word this module recognises (an operator outside a comparison it reads, a
			# quote or a bracket inside a word, a backslash, whose escape Splunk applies before it
			# matches): it places no restriction.
			return ("unknown", value)
		if "," in value:
			self.unquoted_comma = True
		node = ("text", value)
		self.text_at[id(node)] = self.i - 1
		return node


def unquote(value):
	"""A field value as the search compares it: surrounding double quotes and their escapes removed."""
	if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
		return re.sub(r'\\(.)', r'\1', value[1:-1])
	return value


# Fields whose value is never read from the event's text, whatever the props say.
NOT_IN_TEXT = frozenset(("host", "source", "sourcetype", "index", "splunk_server", "splunk_server_group",
						 "linecount", "punct", "timestartpos", "timeendpos", "timestamp", "eventtype", "tag"))
NOT_IN_TEXT_PATTERNS = ("_*", "tenx_*", "date_*", "tag::*")


def text_field_predicate(not_in_text):
	"""
	The text_field test for prefilter(): True for a field whose value is read from the event's
	text. `not_in_text` lists the fields (fnmatch patterns allowed) that are not; a lone "*"
	means no field is.
	"""
	names = set(not_in_text) | NOT_IN_TEXT
	patterns = [n for n in names if "*" in n] + list(NOT_IN_TEXT_PATTERNS)
	if "*" in names:
		return lambda name: False

	def text_field(name):
		return bool(name) and "*" not in name and name not in names and not any(
			fnmatch.fnmatchcase(name, p) for p in patterns)
	return text_field


def as_text(node, text_field):
	"""A field comparison the prefilter may read as its value written as words, or None."""
	if text_field is None:
		return None
	if node[0] == "field" and node[2] == "=" and text_field(node[1]):
		return ("text", node[3])
	if node[0] == "in" and text_field(node[1]) and node[2] and None not in node[2]:
		return ("or", [("text", v) for v in node[2]])
	return None


def narrowing_matters(node):
	"""
	Whether field narrowing can change the prefilter of a parsed search: it has a field compared
	with = or IN (as_text()), or a text whose pieces_kept() differ from its pieces_of(). When it
	cannot, tenxprefilter does not read the setting, so a search without such a term makes no
	REST call for it.
	"""
	kind = node[0]
	if kind == "field":
		return node[2] == "="
	if kind == "in":
		return True
	if kind == "text":
		return pieces_kept(node[1]) != pieces_of(node[1])
	if kind in ("and", "or"):
		return any(narrowing_matters(child) for child in node[1])
	return False


def conf_setting(paths, stanza, key):
	"""
	The value of `key` in `[stanza]` of the .conf files `paths`, a later file overriding an
	earlier one (default/ then local/), read from disk with no REST call; None when no file sets
	it or none can be read. Lines are `key = value`; `#` starts a comment line.
	"""
	value = None
	for path in paths:
		try:
			with open(path, encoding="utf-8") as f:
				lines = f.read().splitlines()
		except (OSError, UnicodeDecodeError):
			continue
		current = None
		for line in lines:
			text = line.strip()
			if not text or text.startswith("#"):
				continue
			if text.startswith("[") and text.endswith("]"):
				current = text[1:-1].strip()
			elif current == stanza and "=" in text:
				k, v = text.split("=", 1)
				if k.strip() == key:
					value = v.strip()
	return value


def narrowing_on_disk(apphome):
	"""
	Whether field narrowing is on, from the app's own tenx_config.conf on disk (default, then
	local). Missing or unreadable: off. tenxprefilter reads this first, so with narrowing off (the
	default) it makes no REST call for field narrowing.
	"""
	import os
	paths = [os.path.join(apphome, d, "tenx_config.conf") for d in ("default", "local")]
	return narrowing_on({"field_narrowing": conf_setting(paths, "config", "field_narrowing")})


def narrowing_on(config):
	"""Whether tenx_config.conf [config] (its REST content) switches field narrowing on."""
	return str((config or {}).get("field_narrowing", "") or "").strip().lower() in ("1", "true", "t", "yes", "y")


# Field narrowing from Splunk's own index terms (tenx_config.conf field_narrowing = splunk; off by default).
#
# A field comparison on raw events reads only the events that hold the index terms Splunk derives
# for it: Splunk expands the field's aliases, event types and tags, and leaves out a value it cannot
# expect in the text. It writes those terms in the job's search.log as its "base lispy". The
# prefilter asks for them with a probe: the words after the macro as a search of their own, over a
# time range that holds no event, and requires the same terms of the compact events the way it
# requires a word (pieces, template dictionary). Every raw event the search returns holds each of
# those terms; its compact event expands to the same text, so it holds each piece as a value or
# through its template, and it is selected. A term the prefilter cannot read as a word, an indexed
# term (name::value) other than as an OR's alternative to terms it reads (lispy_tree), a NOT, an OR
# with any of those, or no answer at all, place no restriction.
SPLUNK_MODE = "splunk"
LISPY_LINE = re.compile(r"base lispy: (\[.*\])\s*$")
LISPY_WORD = re.compile(r"^[^\s\"'\\()\[\]`]+$")
TRUE = ("true",)


def narrowing_mode(config):
	"""
	How field comparisons narrow, from tenx_config.conf [config] field_narrowing: "splunk" (Splunk's
	own index terms for the comparison, read with a probe), "list" (true: the field's value as a word,
	unless tenxreplay's list names the field), or "off" (false, missing or unreadable).
	"""
	value = str((config or {}).get("field_narrowing", "") or "").strip().lower()
	if value == SPLUNK_MODE:
		return SPLUNK_MODE
	return "list" if narrowing_on(config) else "off"


def narrowing_mode_on_disk(apphome):
	"""narrowing_mode() from the app's tenx_config.conf on disk (default, then local); no REST call."""
	import os
	paths = [os.path.join(apphome, d, "tenx_config.conf") for d in ("default", "local")]
	return narrowing_mode({"field_narrowing": conf_setting(paths, "config", "field_narrowing")})


def compares_fields(node):
	"""Whether a parsed search compares a field with = or IN (an indexed term name::value does not count)."""
	kind = node[0]
	if kind == "field":
		return node[2] == "="
	if kind == "in":
		return True
	if kind in ("and", "or"):
		return any(compares_fields(child) for child in node[1])
	if kind == "not":
		return compares_fields(node[1])
	return False


def lispy_probe(text, macro):
	"""
	The probe whose search.log holds Splunk's index terms for `text` (the words after the macro):
	the words as a search of their own, with sourcetype="<st>" for txf(<st>), which says which
	sourcetype's aliases and rules apply. Its caller runs it over a time range that holds no event.
	None when the words hold a subsearch, which the probe would run.
	"""
	if any(kind == "subsearch" for kind, _ in tokenize(text or "")):
		return None
	clause = ""
	m = re.match(r"^`txf\((.*)\)`$", macro or "")
	if m and m.group(1).strip():
		clause = 'sourcetype="%s" ' % m.group(1).strip().replace("\\", "\\\\").replace('"', '\\"')
	return "search %s%s | head 1" % (clause, (text or "").strip())


def lispy_from_log(log):
	"""
	The base lispy a search.log text holds, or None: none at all, or lines that do not all say the
	same, are not read (which one is the search's own is not known, so nothing is narrowed).
	"""
	found = set()
	for line in (log or "").splitlines():
		m = LISPY_LINE.search(line)
		if m:
			found.add(m.group(1))
	return found.pop() if len(found) == 1 else None


# The warning of a search whose field comparisons could have narrowed with field_narrowing = splunk, when
# Splunk's index terms for them could not be read (no probe, no base lispy in its log, or one this does not
# read): the comparisons then narrow nothing, as with field_narrowing = false.
SPLUNK_TERMS_UNREAD = ("tx: field_narrowing = splunk, but Splunk's index terms for the field comparisons could not be "
					   "read, so they do not narrow which compact events are read.")


# An indexed term of the base lispy (name::value) whose field the compact events can carry as Splunk's raw
# events do: not a default field (a compact event has its own sourcetype, source, host and index).
LISPY_INDEXED = re.compile(r"^([A-Za-z0-9_.@-]+)::([^\s\"'\\()\[\]`]+)$")


def _indexed_term(token):
	"""("indexed", token) for a name::value term the prefilter may keep as an alternative, or None."""
	m = LISPY_INDEXED.match(token)
	if not m:
		return None
	name = m.group(1).lower()
	if name in NOT_IN_TEXT or any(fnmatch.fnmatchcase(name, p) for p in NOT_IN_TEXT_PATTERNS):
		return None
	return ("indexed", token)


def lispy_tree(lispy):
	"""
	A base lispy ("[ AND 4625 index::main [ OR alice bob ] ]") as a parsed search the prefilter reads:
	("text", term), ("indexed", name::value), ("and", [...]), ("or", [...]) or ("true",). Brackets are
	tokens of their own. A term with a quote, a backslash, a parenthesis or a bracket inside it, a NOT, and
	an OR with any such branch place no restriction.

	An indexed term (name::value) restricts only as a branch of an OR beside a branch that does: Splunk
	writes [ OR dstip::10.1.2.3 [ AND 10 1 2 3 ] ] for dstip=10.1.2.3 by default (limits.conf
	always_include_indexedfield_lispy = true), and a raw event it returns holds either the indexed field or
	the terms; its compact event holds the same terms, or carries the same indexed field (a field map, fields
	sent with the event). Required on its own, or in an OR of indexed terms only, it places no restriction (a
	compact event can get the field at search time instead), nor does one on a default field (sourcetype,
	source, host, index: a compact event has its own). None when the text is not a lispy this reads (then no
	narrowing at all).
	"""
	if not lispy:
		return None
	tokens = lispy.split()
	pos = [0]

	def term(token):
		if "::" in token:
			return _indexed_term(token) or TRUE
		if not LISPY_WORD.match(token) or token.upper() in ("AND", "OR", "NOT"):
			return TRUE
		return ("text", token)

	def node():
		if pos[0] >= len(tokens):
			raise Unparsed("lispy ended early")
		token = tokens[pos[0]]
		pos[0] += 1
		if token == "]":
			raise Unparsed("lispy: ] where a term should be")
		if token != "[":
			return term(token)
		if pos[0] >= len(tokens):
			raise Unparsed("lispy ended early")
		op = tokens[pos[0]].upper()
		pos[0] += 1
		children = []
		while True:
			if pos[0] >= len(tokens):
				raise Unparsed("lispy: unbalanced brackets")
			if tokens[pos[0]] == "]":
				pos[0] += 1
				break
			children.append(node())
		if op == "AND":
			kept = [c for c in children if c != TRUE and c[0] != "indexed"]
			return TRUE if not kept else kept[0] if len(kept) == 1 else ("and", kept)
		if op == "OR":
			if not children or TRUE in children or all(c[0] == "indexed" for c in children):
				return TRUE
			return children[0] if len(children) == 1 else ("or", children)
		if op == "NOT":
			return TRUE
		raise Unparsed("lispy: operator %s" % op)

	try:
		tree = node()
		if pos[0] != len(tokens):
			raise Unparsed("lispy: text after the expression")
	except Unparsed:
		return None
	return TRUE if tree[0] == "indexed" else tree


# Written forms the compact event does not keep (FORMAT_SPEC.md S2.2 and S4.4, log10x-format):
# a timestamp is stored as an epoch and printed again by tenx-inflate, so none of its digits is a
# term of the compact event; and the sign rule stores a '-' with the digits after it ("-4320"),
# which a zone offset ("+0000", "-0400") also looks like. A piece that overlaps one of these
# spans of the searched text is not used for narrowing. Over-matching only narrows less.
FORM_SPANS = (
	# times: 08:00, 08:00:00, 08:00:00.123456, 20:11:46:346
	re.compile(r"\d{1,2}:\d{2}(?::\d{2})?(?:[.,:]\d{1,9})?"),
	# dates: 2024-03-15, 2024/03/15, 15.03.2024, 03/15/24
	re.compile(r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}"),
	# an epoch with a fraction: 1763020800.123, 1763020800123.456
	re.compile(r"(?<![0-9])(?:\d{10}|\d{13})[.,]\d{1,9}(?![0-9])"),
	# dates and times without separators: 20240315, 20240315080000, 080000, 080000123
	re.compile(r"(?<![0-9])(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d*(?![0-9])"),
	re.compile(r"(?<![0-9])(?:[01]\d|2[0-3])[0-5]\d[0-5]\d\d*(?![0-9])"),
	# epochs in microseconds and nanoseconds (10 and 13 digits are TIMESTAMP_PIECE already)
	re.compile(r"(?<![0-9])(?:\d{16}|\d{19})(?![0-9])"),
	# the sign rule, and zone offsets
	re.compile(r"[-+]\d+"),
)


def form_spans(text):
	"""The positions of `text` inside a written form the compact event does not keep."""
	covered = set()
	for rx in FORM_SPANS:
		for m in rx.finditer(text):
			covered.update(range(m.start(), m.end()))
	return covered


def pieces_kept(text):
	"""pieces_of(text) without the pieces that overlap a form_spans() position."""
	covered = form_spans(text.lower())
	pieces, buf, start = [], [], 0
	low = text.lower()
	for i, ch in enumerate(low):
		if ch not in SEGMENT_BREAKERS and not ch.isspace():
			if not buf:
				start = i
			buf.append(ch)
		elif buf:
			if not covered.intersection(range(start, i)):
				pieces.append("".join(buf))
			buf = []
	if buf and not covered.intersection(range(start, len(low))):
		pieces.append("".join(buf))
	return pieces


def pieces_of(text):
	"""The pieces of a word or phrase, lowercased: the runs between Splunk's segment breakers and
	white space. A run that holds another character than a letter, a digit or '*' (PROGRA~1) is one
	term to Splunk and stays one piece, which usable() then rejects."""
	pieces, buf = [], []
	for ch in text.lower():
		if ch not in SEGMENT_BREAKERS and not ch.isspace():
			buf.append(ch)
		elif buf:
			pieces.append("".join(buf))
			buf = []
	if buf:
		pieces.append("".join(buf))
	return pieces


def time_spans(text):
	"""The positions of `text` inside a written date or time (TIME_FORMS)."""
	covered = set()
	for rx in TIME_FORMS:
		for m in rx.finditer(text):
			covered.update(range(m.start(), m.end()))
	return covered


def pieces_outside_times(text):
	"""pieces_of(text) without the pieces that overlap a written date or time."""
	low = text.lower()
	covered = time_spans(low)
	pieces, buf, start = [], [], 0
	for i, ch in enumerate(low):
		if ch not in SEGMENT_BREAKERS and not ch.isspace():
			if not buf:
				start = i
			buf.append(ch)
		elif buf:
			if not covered.intersection(range(start, i)):
				pieces.append("".join(buf))
			buf = []
	if buf and not covered.intersection(range(start, len(low))):
		pieces.append("".join(buf))
	return pieces


# What a rendered timestamp prints, as runs between Splunk's breakers. The engine stores a
# timestamp as an epoch and tenx-inflate prints it at search time with the template's format, so
# none of this text is in the compact event. The formats are the engine's timestamp patterns
# (pipelines/run/transform/timestamp config.yaml): digits; month and day names (MMM, EEE; Splunk's
# strftime prints them in English); AM and PM; the zone as UTC or GMT; and the literal letters T,
# Z, I, W, E, F and the literal '*' those patterns write. Where no breaker separates them they print
# as one run: 2026-11-14T10 gives the run 14t10, 15.162Z gives 162z, 14Nov2026 would give 14nov2026.
TIMESTAMP_NAMES = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec",
				   "january", "february", "march", "april", "june", "july", "august", "september", "october",
				   "november", "december", "mon", "tue", "wed", "thu", "fri", "sat", "sun", "monday", "tuesday",
				   "wednesday", "thursday", "friday", "saturday", "sunday", "am", "pm", "utc", "gmt",
				   "t", "z", "i", "w", "e", "f", "*")


def timestamp_could_print(piece):
	"""
	Whether some run a rendered timestamp prints could be matched by `piece`, a run of the search
	with '*' as a wildcard: runs of digits and TIMESTAMP_NAMES joined in any order. Decided with a
	small automaton over those runs; the wildcard stands for any text.
	"""
	start, done, digits = ("start",), ("done",), ("digits",)

	def step(states, ch):
		out = set()
		for state in states:
			if state == digits:
				if ch.isdigit():
					out.add(digits)
				state = done
			if state in (start, done):
				if ch.isdigit():
					out.add(digits)
				for name in TIMESTAMP_NAMES:
					if name[0] == ch:
						out.add(done if len(name) == 1 else ("name", name, 1))
			elif state[0] == "name":
				name, k = state[1], state[2]
				if name[k] == ch:
					out.add(done if k + 1 == len(name) else ("name", name, k + 1))
		return out

	states = {start}
	for ch in piece:
		if ch == "*":
			# any text: every state reachable from a live one
			states = states | {done, digits} | set(("name", n, k) for n in TIMESTAMP_NAMES for k in range(1, len(n)))
		else:
			states = step(states, ch)
		if not states:
			return False
	return bool(states & {done, digits})


def usable(piece):
	"""
	Whether a piece of the search may narrow: a run of letters and digits (with '*' at its start or
	end only) that every matching event's compact text holds. Not when a rendered timestamp could
	print text it matches (TIMESTAMP_PIECE, timestamp_could_print(): `2026*`, `nov*`, `*t10`, any run
	of digits), and not with a '*' between two characters: Splunk's wildcard there also matches a run
	that holds a minor breaker (fo*ar matches fo-x-ar), which the compact event, cut at those breakers,
	does not hold as one term.
	"""
	return (bool(re.fullmatch(r"[a-z0-9*]+", piece)) and piece.strip("*") != "" and "*" not in piece.strip("*")
			and not TIMESTAMP_PIECE.match(piece) and not timestamp_could_print(piece))


# A run of digits the search holds: a piece that usable() refuses only because a rendered timestamp
# prints runs of digits. Every other run of digits of an event is a value of its compact event: a
# token that starts with a digit is never template text (FORMAT_SPEC.md S3.2, rule 2), except "-1"
# (S2.2), which the template dictionary finds in the template's text. So such a piece narrows once no
# timestamp format of the stored templates can print it (digit_pieces_cleared()).
DIGIT_PIECE = re.compile(r"[0-9]+")
# The directives a stored timestamp_format holds (tenx_dml_builder.to_splunk_time_format), as
# tenx-inflate prints them: (fewest digits, most digits, lowest value, highest value, zero-padded).
# The year is printed from the first 10 digits of the epoch (tenx-inflate tenx_ts_sec), so it is
# between 1969 and 2286; 1900 to 2299 is used. A seconds field is the epoch's second of the minute.
TS_NUMBER = {
	"Y": (4, 4, 1900, 2299, True), "y": (2, 2, 0, 99, True),
	"m": (2, 2, 1, 12, True), "-m": (1, 2, 1, 12, False),
	"d": (2, 2, 1, 31, True), "-d": (1, 2, 1, 31, False),
	"j": (3, 3, 1, 366, True), "-j": (1, 3, 1, 366, False), "V": (2, 2, 1, 53, True),
	"H": (2, 2, 0, 23, True), "-H": (1, 2, 0, 23, False),
	"I": (2, 2, 1, 12, True), "-I": (1, 2, 1, 12, False),
	"M": (2, 2, 0, 59, True), "-M": (1, 2, 0, 59, False),
	"S": (2, 2, 0, 59, True), "-S": (1, 2, 0, 59, False),
}
# Directives that print letters only (AM/PM, month and day names, UTC), and the zone offsets, which
# tenx-inflate prints as these literal characters.
TS_LETTERS = frozenset(("p", "b", "B", "a", "A", "Z"))
TS_ZONES = {"z": "+0000", ":z": "+00:00", ":::z": "+00"}
TS_DIRECTIVE = re.compile(r"%(-?)(:*)([0-9]*)([A-Za-z%])")
EPOCH_PASSTHROUGH = "__TENX_EPOCH__"
# Per stored record: its timestamp_format and whether a digit can stand right before (lg) or right
# after (rg) the rendered timestamp, so that Splunk reads them as one run with it. A digit of the
# template text, or a value (the placeholder at the start or the end of a part): counted as one. The
# placeholder is the literal tenx-inflate replaces. dictionary_search(formats=True) returns the
# distinct "<lg><rg>|<timestamp_format>" of every record that has a timestamp, in tenx_formats. mvfilter() takes
# one field (Splunk 10.4.3 refuses mvfilter(match(mvappend(...), ...)) as invalid arguments), hence two evals.
FORMAT_KEY_STEPS = (
	' | eval tenx_tp=mvappend(part_0, pattern_parts, pattern_terminator)'
	' | eval tenx_tp=mvfilter(match(tenx_tp, "__TENX_TS__"))'
	' | eval tenx_fk=if(isnull(tenx_tp), null(), if(isnotnull(mvfind(tenx_tp, "(^|[0-9])__TENX_TS__")), "1", "0")'
	' . if(isnotnull(mvfind(tenx_tp, "__TENX_TS__([0-9]|$)")), "1", "0") . "|" . coalesce(timestamp_format, ""))'
)


def timestamp_elements(fmt):
	"""
	What a stored timestamp_format prints, in order: ("lit", character), ("num", *TS_NUMBER entry),
	("any", fewest, most or None) for digits of any value, ("letters",). A directive this does not
	know prints any digits, which can only make a piece unusable.
	"""
	out, i = [], 0
	qs = len(re.findall(r"%[0-9]+Q", fmt))
	while i < len(fmt):
		if fmt[i] != "%":
			out.append(("lit", fmt[i]))
			i += 1
			continue
		m = TS_DIRECTIVE.match(fmt, i)
		if not m:
			out.append(("any", 1, None))
			i += 1
			continue
		dash, colons, width, letter = m.groups()
		i = m.end()
		key = dash + colons + letter
		if letter == "%" and not (dash or colons or width):
			out.append(("lit", "%"))
		elif letter == "Q" and width and not (dash or colons):
			# tenx-inflate prints every %<n>Q with the digit count of the last one; one is exact
			n = int(width)
			out.append(("any", n, n) if qs == 1 and 1 <= n <= 9 else ("any", 1, None))
		elif width:
			out.append(("any", 1, None))
		elif key in TS_NUMBER:
			out.append(("num",) + TS_NUMBER[key])
		elif key in TS_ZONES:
			out.extend(("lit", c) for c in TS_ZONES[key])
		elif key in TS_LETTERS:
			out.append(("letters",))
		else:
			out.append(("any", 1, None))
	return out


def timestamp_prints(piece, fmt, glued_left=True, glued_right=True):
	"""
	Whether a timestamp rendered with the stored timestamp_format `fmt` can print a run between
	Splunk's breakers equal to `piece`, a run of digits. Every character that is not a letter or a
	digit is taken as a breaker (more runs than Splunk sees, so more pieces refused, never fewer).
	`glued_left`/`glued_right`: digits may stand right before or after the timestamp (FORMAT_KEY_STEPS),
	so the first or last run may carry any digits before or after what the format prints. A format
	that writes the epoch back as it is (EPOCH_PASSTHROUGH) prints the compact event's own value, so
	it can print a piece the compact event does not hold only when glued to digits.
	"""
	if not DIGIT_PIECE.fullmatch(piece):
		return True
	if fmt == EPOCH_PASSTHROUGH:
		return glued_left or glued_right
	elements = timestamp_elements(fmt)
	n = len(piece)
	runs, start = [], 0
	for k, e in enumerate(elements + [("lit", " ")]):
		if e[0] == "lit" and not e[1].isalnum():
			if k > start:
				runs.append((start, k))
			start = k + 1

	def prints(run, left, right):
		memo = {}

		def go(i, k):
			if (i, k) in memo:
				return memo[(i, k)]
			if k == len(run):
				ok = i == n or right
			else:
				e = run[k]
				ok = False
				if e[0] == "lit":
					ok = i < n and piece[i] == e[1] and go(i + 1, k + 1)
				elif e[0] == "any":
					most = n - i if e[2] is None else min(e[2], n - i)
					ok = any(go(i + w, k + 1) for w in range(e[1], most + 1))
				elif e[0] == "num":
					_, fewest, most, low, high, padded = e
					for w in range(fewest, min(most, n - i) + 1):
						s = piece[i:i + w]
						if low <= int(s) <= high and (padded or s == str(int(s))) and go(i + w, k + 1):
							ok = True
							break
			memo[(i, k)] = ok
			return ok
		return any(go(i, 0) for i in (range(n) if left else (0,)))

	for a, b in runs:
		run = elements[a:b]
		if any(e[0] == "letters" or (e[0] == "lit" and not e[1].isdigit()) for e in run):
			continue
		if prints(run, glued_left and a == 0, glued_right and b == len(elements)):
			return True
	return False


def formats_from_rows(rows):
	"""
	The (timestamp_format, glued_left, glued_right) of every stored template with a timestamp, from the
	tenx_formats of dictionary_search(formats=True). None when the answer carries no tenx_formats.
	"""
	found = None
	for row in rows:
		keys = row.get("tenx_formats")
		if keys is None:
			continue
		found = found or []
		for key in ([keys] if isinstance(keys, str) else keys):
			key = str(key)
			if len(key) >= 3 and key[2] == "|":
				found.append((key[3:], key[0] != "0", key[1] != "0"))
	return found


def digit_candidates(node, text_field=None):
	"""The runs of digits the prefilter would use if no rendered timestamp could print them."""
	found = set()
	node = as_text(node, text_field) or node
	if node[0] == "text":
		in_address = {p for a in addresses_of(node[1]) for p in pieces_of(a)} | set(prefix_parts(node[1]))
		found.update(p for p in (pieces_outside_times(node[1]) if text_field is None else pieces_kept(node[1]))
					 if DIGIT_PIECE.fullmatch(p) and not usable(p) and p not in in_address)
	elif node[0] in ("and", "or"):
		for child in node[1]:
			found |= digit_candidates(child, text_field)
	return found


def digit_pieces_cleared(candidates, formats):
	"""
	The candidates (digit_candidates()) no stored timestamp format can print (timestamp_prints()):
	those narrow like any other piece. `formats` is formats_from_rows() of every template that has a
	timestamp. No formats is taken as not known (the read failed or found no template), and then no
	run of digits narrows.
	"""
	if not formats:
		return frozenset()
	return frozenset(p for p in candidates if not any(timestamp_prints(p, f, lg, rg) for f, lg, rg in formats))


def addresses_of(text):
	"""The IPv4 addresses written in a word or phrase, in order, without repeats."""
	found = []
	for match in ADDRESS.finditer(text):
		if all(int(part) <= 255 for part in match.groups()) and match.group(0) not in found:
			found.append(match.group(0))
	return found


def address_parts(address):
	"""The parts of an address that must be terms of the event, in order, without repeats. A first
	part of 1 is left out: after a "-" it is the literal -1 of the template (FORMAT_SPEC S2.2)."""
	parts = address.lower().split(".")
	return list(dict.fromkeys(p for i, p in enumerate(parts) if not (i == 0 and p == "1")))


def prefix_parts(text):
	"""The whole parts of each address prefix written with a wildcard (10.0.1.*), in order, without
	repeats, as address_parts gives them. Text that is a whole address has none."""
	found = []
	for match in ADDRESS_PREFIX.finditer(text):
		parts = match.group(1).rstrip(".").split(".")
		if all(int(part) <= 255 for part in parts):
			for part in address_parts(".".join(parts)):
				if part not in found:
					found.append(part)
	return found


def lookup_pieces(node, found=None, text_field=None, digits=frozenset()):
	"""Every usable piece the prefilter would look up in the template dictionary. The parts of an
	address are not looked up: a part is digits only, so never template text (FORMAT_SPEC S3.2).
	`digits`: runs of digits no stored timestamp format prints (digit_pieces_cleared()); they are
	looked up, because "-1" is template text (S2.2)."""
	found = set() if found is None else found
	node = as_text(node, text_field) or node
	if node[0] == "text":
		in_address = {p for a in addresses_of(node[1]) for p in pieces_of(a)} | set(prefix_parts(node[1]))
		found.update(p for p in (pieces_outside_times(node[1]) if text_field is None else pieces_kept(node[1]))
					 if (usable(p) or p in digits) and p not in in_address)
	elif node[0] in ("and", "or"):
		for child in node[1]:
			lookup_pieces(child, found, text_field, digits)
	return found


def prefilter(node, dictionary, text_field=None, digits=frozenset()):
	"""
	The prefilter for a parsed search, or None for no restriction. `dictionary` maps a piece to
	(number of templates carrying it, [TERM(...) clauses for those templates]). `text_field`
	(see text_field_predicate) decides which field comparisons may restrict; None: none do.
	`digits`: runs of digits that narrow because no stored timestamp format prints them
	(digit_pieces_cleared()); empty, no run of digits narrows.
	"""
	node = as_text(node, text_field) or node
	kind = node[0]
	if kind == "text":
		clauses = []
		addresses = addresses_of(node[1])
		prefixed = [p for p in prefix_parts(node[1]) if p not in {q for a in addresses for q in address_parts(a)}]
		in_address = {p for a in addresses for p in pieces_of(a)} | set(prefixed)
		for piece in (pieces_outside_times(node[1]) if text_field is None else pieces_kept(node[1])):
			if not (usable(piece) or piece in digits) or piece in in_address:
				continue
			count, terms = dictionary.get(piece, (0, []))
			if count > MAX_TEMPLATES:
				continue
			clauses.append("(TERM(%s) OR %s)" % (piece, " OR ".join(terms)) if terms else "TERM(%s)" % piece)
		for address in addresses:
			clauses.extend("(TERM(%s) OR TERM(%s))" % (part, address) for part in address_parts(address))
		clauses.extend("TERM(%s)" % part for part in prefixed)
		return "(" + " AND ".join(clauses) + ")" if clauses else None
	if kind == "and":
		clauses = [c for c in (prefilter(child, dictionary, text_field, digits) for child in node[1]) if c is not None]
		return "(" + " AND ".join(clauses) + ")" if clauses else None
	if kind == "or":
		clauses = [prefilter(child, dictionary, text_field, digits) for child in node[1]]
		return None if any(c is None for c in clauses) else "(" + " OR ".join(clauses) + ")"
	if kind == "indexed":
		# a name::value alternative of Splunk's base lispy (lispy_tree), matched on the indexed fields
		return node[1]
	return None


# The runs of a compact event's '~<hash>' between Splunk's index-time major breakers
# (etc/system/default/segmenters.conf). Of the hash alphabet (log10x format spec S5.5), space
# ! & * + ; < > ? [ ] { | } are major breakers; '~' is not one, so it is part of the first run.
HASH_SEGMENT = re.compile(r"[^ !;<>{}|&?+\[\]*,()'\"]+")


def hash_term(dml_hash):
	"""
	The term that selects the compact events of a template, as TERM(<term>): one run of
	'~<hash>' between major breakers, which Splunk indexes as a term of every event of the
	template. A run with '*' directly before and after it is not used: TERM() finds it from the
	index alone, but not when the search also compares a field such as host= or sourcetype=,
	which is how `tx` is written (measured on Splunk 10.4.3 over every pair of neighbouring
	characters and 5,550 hashes; every other run was found both ways). Of the runs left, the
	longest of at least two characters holding a letter or a digit; when there is none, the
	first run, which begins with '~' and has nothing before it.
	"""
	text = "~" + dml_hash
	runs = [(m.group(0), m.start(), m.end()) for m in HASH_SEGMENT.finditer(text)]
	usable = [run for run, start, end in runs
			  if not (text[start - 1:start] == "*" and text[end:end + 1] == "*")
			  and len(run) >= 2 and re.search(r"[A-Za-z0-9]", run)]
	if usable:
		return max(usable, key=lambda run: "%03d" % len(run) + run)
	return runs[0][0]


# The word boundary of the template dictionary's matching: a letter or a digit may not touch a piece.
NOT_WORD = "[^\\p{L}\\p{N}]"


def piece_regex(piece):
	"""The SPL regex that finds `piece` (a usable piece: a-z, 0-9, '*' at its ends) in lowered template text."""
	return "(^|%s)%s(%s|$)" % (NOT_WORD, piece.replace("*", "[\\p{L}\\p{N}]*"), NOT_WORD)


def dictionary_search(pieces, formats=False, hours=None):
	"""
	The search that answers, for each piece, which templates carry it in their text, as the
	TERM() clause of each template's hash_term.

	It reads the templates from the KV store (tenx-dml-lookup), the store tenx-inflate expands
	from, so every template that can expand an event is asked about. The searchable copy in the
	template index (`tenx-templates`) is written later, by the Consume KV alert action, and a
	template whose copy is not written yet expands its events but is not in that index: read from
	there, a word in its text selected none of its events (Splunk Enterprise 10.4.3, 175,480
	templates in the KV store with their copies pending: `tx` jsmith 0 events, raw 905; copies
	written: 905). The text is the record's pattern_search, the same text the copy holds (or its
	pattern with the value separators removed, for a record stored before that field).

	The term is computed in SPL from the hash as the engine wrote it (pattern_hash; the record
	key is trimmed): the runs with '*' on both sides are blanked, the text is split at the major
	breakers, and the longest run of at least two characters with a letter or a digit is taken,
	else the first run. One row comes back, n<i> and hs<i> for the i-th piece of sorted(pieces);
	no command in it caps the rows it passes on (no mvexpand, head or subsearch).

	formats: also return, in tenx_formats, the timestamp format of every stored template with its
	glue (FORMAT_KEY_STEPS), for the runs of digits (digit_pieces_cleared()). Every record then reaches
	the stats; the term is computed only on records that hold some piece.

	hours: read only the records Consume KV wrote in these hours (stored_hour, an indexed field of the
	collection), to complete an earlier answer (cache_hours()); None reads every record.
	"""
	plist = sorted(pieces)
	marks = ", ".join('m%d=if(match(tenx_t, "%s"), 1, null())' % (i, piece_regex(piece)) for i, piece in enumerate(plist))
	counts = ", ".join('values(eval(if(m%d=1, h, null()))) as hs%d, count(m%d) as n%d' % (i, i, i, i)
					   for i in range(len(plist)))
	prune = 'match(tenx_t, "(^|' + NOT_WORD + ')(' + "|".join(p.replace("*", "[\\p{L}\\p{N}]*") for p in plist) + ')(' + NOT_WORD + '|$)")'
	if formats:
		head = (' | eval tenx_any=if(' + prune + ', 1, null())' + FORMAT_KEY_STEPS +
				' | eval dml_hash=if(isnotnull(tenx_any), coalesce(pattern_hash, _key), null())')
	else:
		head = ' | where ' + prune + ' | eval dml_hash=coalesce(pattern_hash, _key)'
	where = (' where (' + ' OR '.join('%s="%s"' % (STORED_HOUR, h) for h in hours) + ')') if hours else ''
	return (
		'| inputlookup tenx-dml-lookup' + where + ' | fields _key, pattern_hash, pattern_search, pattern'
		+ (', timestamp_format, part_0, pattern_parts, pattern_terminator' if formats else '') +
		' | eval tenx_t=lower(coalesce(pattern_search, replace(pattern, "[$]", "")))'
		+ head +
		' | eval ' + marks +
		' | eval segs=split(replace(replace(replace("~" . dml_hash, "--|%[0-9A-Fa-f]{2}", " "),'
		' "(?<=\\*)[^ !;<>{}|&?+\\[\\]*,()\'\\"]+(?=\\*)", " "), "[ !;<>{}|&?+\\[\\]*,()\'\\"]", " "), " ")'
		' | eval cand=mvfilter(len(segs) >= 2 AND match(segs, "[\\p{L}\\p{N}]"))'
		' | eval best=substr(mvindex(mvsort(mvmap(cand, printf("%03d", len(cand)) . cand)), -1), 4)'
		' | eval h="TERM(" . coalesce(best, mvindex(segs, 0)) . ")"'
		' | stats ' + counts + (', values(tenx_fk) as tenx_formats' if formats else '')
	)


def dictionary_from_rows(rows, pieces=None):
	"""
	The dictionary of dictionary_search()'s answer: piece -> (templates carrying it, [TERM() of
	each]). `pieces` are the pieces the search was built for; rows in the earlier form (one row a
	piece, with piece, n and hs) are read as well.
	"""
	dictionary = {}
	for row in rows:
		if "piece" in row:
			terms = row.get("hs") or []
			dictionary[row["piece"]] = (int(row.get("n") or 0), [terms] if isinstance(terms, str) else list(terms))
			continue
		for i, piece in enumerate(sorted(pieces or ())):
			terms = row.get("hs%d" % i) or []
			dictionary[piece] = (int(row.get("n%d" % i) or 0), [terms] if isinstance(terms, str) else list(terms))
	return dictionary


# The template dictionary read in part. Reading every record of the KV store for each search costs
# seconds of search head CPU per search at hundreds of thousands of templates. The prefilter keeps its
# answer for each piece in the collection tenx_dict_cache, and a later search for the same pieces reads
# only the records Consume KV wrote in the hours since (stored_hour, an indexed field), adding them to
# the kept answer. Why that is every template: a full read that starts at time S sees every record
# readable at S; a record that became readable later was stamped with its hour before it was saved,
# at most CACHE_LAG_SECONDS before it became readable, so its stored_hour is at least the hour of
# S - CACHE_LAG_SECONDS, which is the first hour a later search reads again (through_hour). A record
# written again (refreshed, replaced, marked hash-conflict) gets a new hour and is read again; a
# template removed from the store stays in the kept answer, which can only select more events. A
# record counted twice can only raise n past MAX_TEMPLATES, which narrows less. Every
# CACHE_FULL_SECONDS, or when a piece has no kept answer, every record is read again, and so it is after
# an install or an upgrade and after a load from the start of the index (cache_valid_from): records
# restored into the store come back with the hours they had. The margin CACHE_LAG_SECONDS covers the
# save of one chunk, the KV store's copy to the other members of a search head cluster and the
# difference of their clocks together; a record that takes longer to become readable on a member is
# missed there by the partial reads until the next full read.
CACHE_PATH = "/servicesNS/nobody/tenx-for-splunk/storage/collections/data/tenx_dict_cache"
STORED_HOUR = "stored_hour"
# Longer than the Consume KV alert action may run (alert_actions.conf maxtime 10m), with what the clocks
# of search heads in one cluster may differ added.
CACHE_LAG_SECONDS = 900
CACHE_FULL_SECONDS = 86400
FORMATS_KEY = "formats"


def hour_of(t):
	return int(t) // 3600


def cache_key(piece):
	"""The tenx_dict_cache key of a piece (a-z, 0-9 and '*', so '*' -> '-' is one to one)."""
	return "p_" + piece.replace("*", "-")


def cache_keys(pieces, formats=False):
	return sorted(cache_key(p) for p in pieces) + ([FORMATS_KEY] if formats else [])


def cache_valid_from(state):
	"""
	The time before which no kept answer is used, from the Consume KV record `state`: the start of
	this version's first run (version_since: an install or an upgrade, which may read templates
	differently) or of the last load from the start of the index (dict_reset: the documented step after
	the template store was emptied or restored, whose records come back with the hours they had).
	None when there is no record or it cannot be read: then every record is read.
	"""
	if not isinstance(state, dict) or not state:
		return None
	times = []
	for key in ("version_since", "dict_reset"):
		try:
			times.append(float(state.get(key) or 0))
		except (TypeError, ValueError):
			return None
	return max(times)


def cache_hours(entries, pieces, formats, now, valid_from=None):
	"""
	The stored_hour values a search reads to complete the kept answers `entries` ({key: record}) for
	`pieces` (and the timestamp formats when `formats`): every hour from the earliest through_hour
	among them to the hour of `now` + CACHE_LAG_SECONDS (a record stamped by a clock ahead of this
	one). None, read every record, when one is missing or unreadable, was last read in full more than
	CACHE_FULL_SECONDS ago or before `valid_from` (cache_valid_from(); None: no kept answer is
	used), or carries a time after `now`.
	"""
	if valid_from is None:
		return None
	starts = []
	for key in cache_keys(pieces, formats):
		entry = (entries or {}).get(key)
		try:
			full_at, through = float(entry["full_at"]), int(float(entry["through_hour"]))
		except (KeyError, TypeError, ValueError):
			return None
		if not 0 <= now - full_at <= CACHE_FULL_SECONDS or full_at < valid_from or through > hour_of(now):
			return None
		starts.append(through)
	if not starts:
		return None
	return [str(h) for h in range(min(starts), hour_of(now + CACHE_LAG_SECONDS) + 1)]


def format_keys_from_rows(rows):
	"""The tenx_formats keys ("<lg><rg>|<timestamp_format>") of dictionary_search(formats=True)'s answer."""
	keys = set()
	for row in rows or []:
		value = row.get("tenx_formats")
		if value is not None:
			keys.update(str(k) for k in ([value] if isinstance(value, str) else value))
	return keys


def _values(value):
	"""A KV field read back as a list of strings (a multivalue, one string, or nothing)."""
	return [] if value is None else [str(value)] if isinstance(value, str) else [str(v) for v in value]


def cache_merge(entries, fresh, fresh_format_keys, pieces, formats):
	"""
	(dictionary, formats) from the kept answers `entries` and the answer `fresh` of the records read
	since (dictionary_from_rows, format_keys_from_rows): the templates of both for each piece, the
	formats of both. formats is None when not asked for.
	"""
	dictionary = {}
	for piece in pieces:
		entry = entries[cache_key(piece)]
		n, terms = fresh.get(piece, (0, []))
		dictionary[piece] = (int(float(entry.get("n") or 0)) + n, sorted(set(_values(entry.get("hs"))) | set(terms)))
	if not formats:
		return dictionary, None
	keys = set(_values(entries[FORMATS_KEY].get("formats"))) | set(fresh_format_keys or ())
	return dictionary, formats_from_rows([{"tenx_formats": sorted(keys)}])


def cache_records(dictionary, format_keys, pieces, formats, started):
	"""
	The tenx_dict_cache records of a full read that started at `started`: through_hour is the hour of
	started - CACHE_LAG_SECONDS. A piece carried by more than MAX_TEMPLATES templates keeps its count
	alone, which is enough to leave it out.
	"""
	through, records = hour_of(started - CACHE_LAG_SECONDS), []
	for piece in sorted(pieces):
		n, terms = dictionary.get(piece, (0, []))
		records.append({"_key": cache_key(piece), "n": n, "hs": sorted(terms) if n <= MAX_TEMPLATES else [],
						"full_at": int(started), "through_hour": through})
	if formats:
		records.append({"_key": FORMATS_KEY, "formats": sorted(format_keys or ()), "full_at": int(started), "through_hour": through})
	return records


# A wildcard inside a word, TERM() and CASE() after `tx` (Splunk Enterprise 10.4.3). `tx` applies the
# words after it in a `search` after a pipe that Splunk cannot fold into the base search, and there
# some of them match other events than the same search on the index:
# - a word with a `*` after its first character (Se*Privilege, le*FO, S*P*e) is matched as its prefix
#   alone: any term starting with "se" (Windows 662 sample: 662 events, the base search on the raw
#   events 3; Se*Zzz also 662). On the index the whole word is matched against the event's terms,
#   case-insensitively, `*` standing for any characters: a major segment (the text between two major
#   breakers) or a minor piece (between any two breakers). A word starting with `*`, or ending with its
#   only `*`, or holding a breaker of its own (10.0*14, foo.*.com), matched after the pipe as on the
#   index on every case measured, so it is left alone.
# - TERM(x) on the index is a term of the event that is x (`*` as above): a major segment, or, when x
#   holds no minor breaker, a minor piece. After the pipe x is found inside a longer term too
#   (TERM(10.2.236.94) in client_ip=10.2.236.94: 0 on the index, 1 after the pipe). TERM() of a plain
#   word matched alike both ways and is left alone. When x holds a major breaker, the index matched no
#   event on default segmentation (TERM(+0000): 0) but did match on Windows events indexed under the
#   Windows add-on (TERM(Name='SubjectLogonId'>0x331dbb</Data><Data): 18), so where such a TERM()
#   selects events it is left to the final search; under NOT it is taken as matching nothing, which
#   can only keep more events than the final search would.
# - CASE(x) matched alike both ways except when x has a wildcard inside it: after the pipe, a term
#   starting with x's prefix in its letter case; on the index, an event that holds x as the word above
#   (any letter case) and also matches CASE(x) as after the pipe (CASE(Se*Privilege) matches
#   "sexprivilege Seattle" and "SeQPRIVILEGE", not "SEXPRIVILEGE").
# The breakers of segmenters.conf [indexing] (btool on 10.4.3), the default for every sourcetype here.
MAJOR_CHARS = "[]<>(){}|!;,'\"*\n\r \t&?+"
MAJOR_SEQUENCES = ("%2526", "%2520", "%21", "%26", "%3B", "%7C", "%20", "%2B", "%3D", "--", "%5D", "%5B", "%3A",
				   "%0A", "%2C", "%28", "%29")
MINOR_CHARS = "/:=@.-$#%\\_"
# The fields wild_plan() sets on each event: tenx_w0, tenx_w1, ... (the search rewrite); the tx macros set one
# field, tenx_w, to the numbers of the marks the event matches (wild_marks).
WILD_FIELD = "tenx_w"


def mid_wildcard(word):
	"""Whether `word` is a word Splunk matches differently after a pipe than on the index (see above)."""
	if not word or word[0] == "*" or "*" not in word.rstrip("*"):
		return False
	return not any(c in MAJOR_CHARS.replace("*", "") or c in MINOR_CHARS or c.isspace() for c in word)


def _major_breaker(text):
	return any(c in MAJOR_CHARS.replace("*", "") or c.isspace() for c in text) or any(s in text for s in MAJOR_SEQUENCES)


def _class(chars):
	return "[" + "".join("\\" + c if c in "]\\^-[" else c for c in chars).replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "]"


def term_regex(word, case=False, major_only=False):
	"""
	A regular expression (PCRE, as Splunk's match() reads it, and Python's re alike) that finds `word`
	in an event's text as a base search on the index finds it: some major segment or minor piece of
	the text is the word, case-insensitively, each `*` standing for any characters of that term (as
	the index places the parts, see pattern()).
	`case`: the letter case kept. `major_only`: a major segment only (TERM() of a word with a minor
	breaker in it, which no minor piece can be).
	"""
	major = _class(MAJOR_CHARS.replace("*", "") + "*")
	seq = "|".join(re.escape(s) for s in MAJOR_SEQUENCES)
	brk = "(?:%s|%s)" % (major, seq)
	in_major = "(?:(?!%s)[^%s])" % (seq, _class(MAJOR_CHARS.replace("*", "") + "*")[1:-1])
	minor = _class(MINOR_CHARS)
	in_minor = "[^%s%s]" % (_class(MAJOR_CHARS.replace("*", "") + "*")[1:-1], minor[1:-1])
	parts = word.split("*")
	tail = parts[-1] != ""

	def pattern(start, inner, end):
		# The index takes each part after a `*` at its first place in the rest of the term, and the last
		# part, when the word does not end with `*`, again only after the end of each place it found
		# that does not end the term: 19*44 matches 19.2.3.4.44 and 198/544 but not 19.2.3.444 or
		# 198/55444 (the second 44 overlaps the first), x*ab matches xabab (Splunk Enterprise 10.4.3).
		text = re.escape(parts[0])
		for k, p in enumerate(parts[1:], 1):
			if not p:
				text += inner + "*?"
				continue
			first = "(?:(?!%s)%s)*%s" % (re.escape(p), inner, re.escape(p))
			text += "(?:%s)+" % first if tail and k == len(parts) - 1 else first
		return start + text + (end if tail else "")
	whole = pattern("(?:^|%s)" % brk, in_major, "(?=%s|$)" % brk)
	piece = pattern("(?:^|%s|%s)" % (brk, minor), in_minor, "(?=%s|%s|$)" % (brk, minor))
	return ("" if case else "(?i)") + "(?:%s)" % (whole if major_only else whole + "|" + piece)


def _eval_string(text):
	return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


# The regular expression that stands for false() in the marks the tx macros read (wild_marks): it matches nothing.
NEVER = "(?!)"


def _atom_regex(name, word, positive=True):
	"""
	The regular expression that finds the atom in an event's text as a base search on the index does
	(see above), NEVER where the atom is taken as matching nothing, or None when it matches alike after
	the pipe or is not read with certainty: name is None for a word or a quoted word, TERM or CASE;
	positive is False where the atom stands under NOT.
	"""
	if not word:
		return None
	if name is None or name == "CASE":
		return term_regex(word) if mid_wildcard(word) else None
	if "\\" in word:
		# Splunk applies the escape first (TERM(\resource) matched what TERM(resource) matches, 1,161 events)
		return None
	if _major_breaker(word):
		return None if positive else NEVER
	minor = any(c in MINOR_CHARS for c in word)
	if not minor and not mid_wildcard(word):
		return None
	return term_regex(word, major_only=minor)


def _atom_test(name, word, positive=True):
	"""
	The eval condition that matches the atom as a base search on the index (see above), or None
	when it matches alike after the pipe or is not read with certainty (_atom_regex).
	"""
	rx = _atom_regex(name, word, positive)
	if rx is None:
		return None
	return "false()" if rx == NEVER else "match(_raw, %s)" % _eval_string(rx)


def _wild_atoms(text):
	"""
	The words after `tx` (`text`) that match other events after a pipe than on the index (see above),
	as (regexes, edits): `regexes` holds one regular expression per distinct test, in order (the mark
	of the n-th is n), and `edits` holds (start, end, n, CASE or not) for each place in `text` that
	such a word takes. None when no word needs it, or when the text is not read with certainty (a
	subsearch, a macro, parentheses that do not close). A word written right against another word or
	phrase (no space) is left as it is.
	"""
	tokens = tokenize(text)
	if any(kind == "subsearch" for kind, _ in tokens):
		return None
	reader = Parser(tokens)
	try:
		tree = reader.parse()
	except Unparsed:
		return None
	marks, regexes, edits = {}, [], []

	def glued_to_text(first, last):
		before = first in tokens.glued and tokens[first - 1][0] in ("word", "phrase")
		after = (last + 1) in tokens.glued and tokens[last + 1][0] in ("word", "phrase")
		return before or after

	def visit(node, positive=True):
		kind = node[0]
		if kind in ("and", "or"):
			for child in node[1]:
				visit(child, positive)
			return
		if kind == "not":
			visit(node[1], not positive)
			return
		if kind == "text" and id(node) in reader.text_at:
			index = reader.text_at[id(node)]
			name, word, first, last = None, node[1], index, index
			if tokens[index][0] == "phrase" and (not word or any(c.isspace() for c in word)):
				return
		elif kind == "unknown" and id(node) in reader.call_at:
			name, word, first, last = reader.call_at[id(node)]
		else:
			return
		rx = _atom_regex(name, word, positive)
		if rx is None or glued_to_text(first, last):
			return
		if rx not in marks:
			marks[rx] = len(regexes)
			regexes.append(rx)
		edits.append((tokens.spans[first][0], tokens.spans[last][1], marks[rx], name == "CASE"))

	visit(tree)
	return (regexes, edits) if edits else None


def _wild_search(text, edits, mark):
	"""`text` with each place in `edits` replaced by mark(n), CASE(x) by (mark(n) CASE(x))."""
	search = text
	for start, end, n, case in sorted(edits, reverse=True):
		search = search[:start] + ("(%s %s)" % (mark(n), text[start:end]) if case else mark(n)) + search[end:]
	return search.strip()


def wild_plan(text):
	"""
	The words after `tx` (`text`) with every word that matches other events after a pipe than on
	the index (see above) put as a field the step before computes: (eval, search), where `eval` sets
	tenx_w0, tenx_w1, ... to 1 on the events whose text holds that word as the index does, and
	`search` is `text` with each such word replaced by tenx_wN=1 (CASE(x) by (tenx_wN=1 CASE(x)), see
	above). `| eval <eval> | search <search>` then keeps the events the base search on the index would
	keep for those words, under AND, OR and NOT alike (on the index, NOT CASE() ignores the letter
	case, so it is not the opposite of CASE(); this gives the opposite), and every other word as
	`search` after a pipe keeps them. None when no word needs it, or when the text is not read with
	certainty (a subsearch, a macro, parentheses that do not close). The search rewrite writes this
	eval into the search it runs; the tx macros take the same marks through wild_marks().

	A word written right against another word or phrase (no space) is left as it is.
	"""
	atoms = _wild_atoms(text)
	if atoms is None:
		return None
	regexes, edits = atoms
	steps = ["%s%d=%s" % (WILD_FIELD, n, "0" if rx == NEVER else "if(match(_raw, %s), 1, 0)" % _eval_string(rx))
			 for n, rx in enumerate(regexes)]
	return ", ".join(steps), _wild_search(text, edits, lambda n: "%s%d=1" % (WILD_FIELD, n))


def wild_marks(text):
	"""
	The same marks as wild_plan() in the form the tx macros read back from the job (macros.conf
	[tenx-wild]): (marks, search). `marks` is "0:<regex>,1:<regex>,..." with each regular expression
	percent-encoded (letters, digits and _.-~ kept), so it holds no quote, comma, colon or backslash
	and goes into the search text as one quoted value; the macro step sets the field tenx_w to the
	numbers of the expressions the event's text matches (urldecode, match). `search` is `text` with
	each such word replaced by tenx_w=N (CASE(x) by (tenx_w=N CASE(x))). The step carries no
	subsearch inside eval, which Splunk's union refuses in its datasets ("The expression is
	malformed", Splunk Enterprise 10.4.3). None when wild_plan() is None.
	"""
	atoms = _wild_atoms(text)
	if atoms is None:
		return None
	regexes, edits = atoms
	marks = ",".join("%d:%s" % (n, urllib.parse.quote(rx, safe="")) for n, rx in enumerate(regexes))
	return marks, _wild_search(text, edits, lambda n: "%s=%d" % (WILD_FIELD, n))


# The record the Consume KV alert action keeps of how far it has stored template records
# (collections.conf [tenx_kv_state], tenx_dml_to_kv.py). It runs every five minutes.
STORE_STATE_PATH = "/servicesNS/nobody/tenx-for-splunk/storage/collections/data/tenx_kv_state/consume_kv?output_mode=json"
STORE_STALE_SECONDS = 900


def store_warning(state, now):
	"""
	The warning `tx` and `txf` show when the template store can lack templates their events
	need, from the Consume KV record, or None. Events whose template is not stored stay compact.
	"""
	if not isinstance(state, dict) or not state:
		return None
	try:
		updated = float(state.get("updated"))
		through = float(state.get("loaded_through") or 0)
	except (TypeError, ValueError):
		return None
	after = (" indexed after %s" % time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(through))) if through > 0 else ""
	status = state.get("status")
	if status == "failed":
		return ("tx: Consume KV stopped with an error (%s), so templates%s may not be stored; events that use them stay "
				"compact. See the Diagnostics dashboard." % (str(state.get("detail") or "see tenx_dml_to_kv.log")[:200], after))
	if now - updated > STORE_STALE_SECONDS:
		return ("tx: Consume KV has not run since %s, so templates indexed since then are not stored; events that use "
				"them stay compact." % time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(updated)))
	if status == "loading":
		return ("tx: Consume KV is still storing templates%s; events that use them stay compact until it has." % after)
	return None


# The record tenxreplay keeps of the original sourcetypes (tenx_replay.conf: one stanza per original
# sourcetype, with the indexes its compact events were seen in, and LEFT_OUT_KEY), read from the
# app's own conf files on disk, so the checks below make no REST call to read it.
RECORD_KEYS = ("indexes", "left_out")
RAW_EVENTS_MACRO = "`tenx-raw-events`"
SAFE_TIME = re.compile(r"^[-+@0-9A-Za-z:/.]+$")


def conf_stanzas(paths):
	"""{stanza: {key: value}} of the .conf files `paths`, a later file overriding an earlier one, read from
	disk; {} when none can be read. Lines are `key = value`; `#` starts a comment line."""
	out = {}
	for path in paths:
		try:
			with open(path, encoding="utf-8") as f:
				lines = f.read().splitlines()
		except (OSError, UnicodeDecodeError):
			continue
		current = None
		for line in lines:
			text = line.strip()
			if not text or text.startswith("#"):
				continue
			if text.startswith("[") and text.endswith("]"):
				current = text[1:-1].strip()
				out.setdefault(current, {})
			elif current is not None and "=" in text:
				k, v = text.split("=", 1)
				out[current][k.strip()] = v.strip()
	return out


def replay_record_on_disk(apphome):
	"""
	{original sourcetype: {'indexes': ..., 'left_out': ...}} from tenx_replay.conf on disk (default, then
	local), without [default] and the tenx:* stanzas. Empty when nothing is recorded: then no compact
	event carries tenx_sourcetype (or tenxreplay has not run), and the checks below have nothing to go on.
	"""
	import os
	stanzas = conf_stanzas([os.path.join(apphome, d, "tenx_replay.conf") for d in ("default", "local")])
	return dict((st, dict((k, kv.get(k, "")) for k in RECORD_KEYS)) for st, kv in stanzas.items()
				if st and st != "default" and not st.startswith("tenx:"))


def _listed(value):
	"""The indexes a record lists: a set of lower-case names, or None for * (any index)."""
	value = str(value or "").strip()
	if value == "*":
		return None
	return set(v.strip().lower() for v in value.split(",") if v.strip())


def _in_indexes(listed, named):
	"""Whether an index the record lists (`listed`, see _listed) can be one the search names (`named`,
	wildcards allowed; none named: every index)."""
	if not named or listed is None:
		return True
	return any(fnmatch.fnmatchcase(ix, n.lower()) for ix in listed for n in named)


def _names(values, n=3):
	values = sorted(values)
	if len(values) <= n:
		return values[0] if len(values) == 1 else ", ".join(values[:-1]) + " and " + values[-1]
	return ", ".join(values[:n]) + " and %d more" % (len(values) - n)


def replay_left_out(record, macro, indexes):
	"""
	The warning of `txf` or txf(<sourcetype>) whose field replay leaves events of a covered sourcetype
	without its rules, or None. `txf`: the `tenx-replay` macro holds the busiest sourcetypes that fit in
	its limits (replay_max_macro_chars when set, and the commands of one search), and the record marks the
	others left_out=txf; only those recorded in the indexes the search names count. txf(<sourcetype>): that
	sourcetype's unit is over the same limits and replays nothing (left_out has unit). Either way such
	events get only the fields in their text.
	"""
	name = (macro or "").strip("`")
	if name == "txf":
		left = [st for st, kv in record.items() if "txf" in str(kv.get("left_out") or "").split(",")
				and _in_indexes(_listed(kv.get("indexes")), indexes)]
		if left:
			return ("txf: the field replay of txf leaves out %s (over its size limits), so %s events get only "
					"the fields in their text; txf(<sourcetype>) gives them all their fields."
					% (_names(left), "their" if len(left) > 1 else "its"))
	elif name.startswith("txf(") and name.endswith(")"):
		st = name[4:-1].strip()
		if "unit" in str((record.get(st) or {}).get("left_out") or "").split(","):
			return ("txf(%s): this sourcetype's field replay is over its size limits and replays nothing, so its "
					"events get only the fields in their text." % st)
	return None


def raw_history_probe(record, before):
	"""
	The tstats that counts, by index and sourcetype, the events of the original sourcetypes in `record`
	that are not compact, in the indexes their compact events were seen in and those written before the
	macro (`before`), over the search's time range (with the earliest= and latest= written there), that
	the tenx-raw-events macro does not name: raw events of the same sources, typically indexed before the
	Receiver was installed, which `tx` and `txf` would leave out. None when there is nothing to count, or
	when the search names a sourcetype before the macro (it chose the events it reads).
	"""
	if not record or _specifiers(before, "sourcetype"):
		return None
	quote = lambda v: '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
	named = named_indexes(before)
	pairs = []
	for st, kv in sorted(record.items()):
		listed = _listed(kv.get("indexes"))
		if not _in_indexes(listed, named):
			continue
		ixs = sorted(listed or [])
		pairs.append("(sourcetype=%s%s)" % (quote(st), (" (%s)" % " OR ".join("index=%s" % quote(i) for i in ixs)) if ixs else ""))
	if not pairs:
		return None
	times = " ".join("%s=%s" % (k, v) for k in ("earliest", "latest") for v in _specifiers(before, k)[:1] if SAFE_TIME.match(v))
	where = "(%s) " % " OR ".join("index=%s" % quote(i) for i in sorted(named)) if named else ""
	return "| tstats count where %s%s(%s) NOT tenx_sourcetype=* NOT tenx_mapped=* NOT (%s) by index, sourcetype" % (
		times + " " if times else "", where, " OR ".join(pairs), RAW_EVENTS_MACRO)


def word_index_probe(before):
	"""
	The tstats that finds, by index, host and source, compact events (`tenx-events`) in the search's range
	that hold no word term. Every compact event starts with ~ and its template hash, which segmentation
	indexes as a term starting with ~; a group with more events than events holding such a term was
	indexed without words (SEGMENTATION = none on the compact sourcetype, its source or host), so a word
	prefilter cannot find its events. Restricted to the indexes written before the macro (`before`).
	"""
	quote = lambda v: '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
	named = named_indexes(before)
	where = "(%s) " % " OR ".join("index=%s" % quote(i) for i in sorted(named)) if named else ""
	return ("| tstats count where %s`tenx-events` by index, host, source | eval tenx_w=0 | append [| tstats count "
			"where %s`tenx-events` TERM(~*) by index, host, source | eval tenx_w=1] | stats sum(eval(if(tenx_w==0, "
			"count, 0))) as tenx_all, sum(eval(if(tenx_w==1, count, 0))) as tenx_words by index, host, source "
			"| where tenx_all > tenx_words" % (where, where))


def word_index_branch(rows, most=200):
	"""The OR branch that reads every compact event of the groups word_index_probe found (by index alone past `most`)."""
	quote = lambda v: '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'
	if len(rows) > most:
		return " OR ".join("index=%s" % quote(i) for i in sorted(set(r.get("index", "") for r in rows)))
	return " OR ".join("(index=%s host=%s source=%s)" % (quote(r.get("index", "")), quote(r.get("host", "")),
														   quote(r.get("source", ""))) for r in rows)


def raw_history_message(rows, macro):
	"""
	The warning of a `tx` or `txf` search whose indexes hold, in its time range, events of the original
	sourcetypes of its compact events that are not compact (`rows` of raw_history_probe). Splunk keeps the
	first 256 characters of a search command's message.
	"""
	name = (macro or "`tx`").strip("`").split("(")[0]
	sts = set(r.get("sourcetype", "") for r in rows if r.get("sourcetype"))
	ixs = set(r.get("index", "") for r in rows if r.get("index"))
	return ("%s: %s %s also %s events of %s that are not compact, and this search leaves them out. To return them too, "
			"name them in the tenx-raw-events macro." % (name, "index" if len(ixs) == 1 else "indexes", _names(ixs, 2),
														 "holds" if len(ixs) == 1 else "hold", _names(sts)))


# The minutes after an install or an upgrade. On a search head with separate indexers the app's template
# lookup reaches them with the next knowledge bundle; until it has, every `tx` search failed there
# (Splunk Enterprise 10.4.3, a fresh search head over two indexers: "Error in 'lookup' command: Could not
# construct lookup 'tenx-dml-lookup' ... does not exist or is not available", no rows, for about a minute
# after the install). On another fresh search head over the same indexers the search process on each
# indexer exited instead (splunkd.log: "caught exception", exit code 111), and the search head said only
# "Search results might be incomplete: the search process on the peer:[...] ended prematurely", no rows,
# for about a minute. For these minutes tenxprefilter runs LOOKUP_PROBE first, and when it fails on the
# indexers either way it keeps the search on the search head (ON_SEARCH_HEAD) and warns instead.
NEW_VERSION_SECONDS = 900
PEERS_PATH = "/services/search/distributed/peers?output_mode=json&count=0"
LOOKUP_PROBE = ("search ((`tenx-events`) OR (`tenx-raw-events`)) | lookup tenx-dml-lookup _key AS tenx_hash OUTPUT _key AS "
				"tenx_probe | head 1 | fields tenx_probe")
ON_SEARCH_HEAD = "splunk_server=local"
NOT_ON_INDEXERS = ("tx: the app's template lookup has not reached the indexers yet; Splunk sends it with the next "
				   "knowledge bundle, about a minute after the app is installed or upgraded. No event was read: retry "
				   "in a minute.")


def new_version(state, version, now):
	"""
	Whether the app may still be on its way to the indexers: the Consume KV record (`state`, None when
	there is none yet) is absent, was written by another version than `version` (this one, from
	app.conf), or says this version's first run started less than NEW_VERSION_SECONDS ago.
	"""
	if not isinstance(state, dict) or not state:
		return True
	if version and str(state.get("version") or "") != version:
		return True
	try:
		return now - float(state.get("version_since")) < NEW_VERSION_SECONDS
	except (TypeError, ValueError):
		return False


# What says the template lookup is not on the indexers: one of the two answers measured above. Splunk's error
# naming tenx-dml-lookup as a lookup it cannot construct or find, or its message that the search process on a peer
# ended prematurely. Any other error of the probe is not this one: an add-on's automatic lookup that fails on the
# probe's events, or the KV store starting on the search head. The search then runs as it would and shows its own
# error.
LOOKUP_NAME = "tenx-dml-lookup"
LOOKUP_MISSING = ("could not construct lookup", "does not exist or is not available")
PEER_PROCESS = "search process on the peer"
PEER_ENDED = "ended prematurely"


def lookup_failed(result):
	"""The text of an error of LOOKUP_PROBE's answer that says the template lookup cannot run on the indexers
	(LOOKUP_NAME with one of LOOKUP_MISSING, or PEER_PROCESS with PEER_ENDED), or None."""
	for message in (result or {}).get("messages", []) or []:
		kind, text = str(message.get("type", "")).upper(), str(message.get("text", ""))
		low = text.lower()
		if kind in ("ERROR", "FATAL") and ((LOOKUP_NAME in low and any(m in low for m in LOOKUP_MISSING))
										   or (PEER_PROCESS in low and PEER_ENDED in low)):
			return text[:300]
	return None


# Right after Splunk starts, until its KV store is ready, the read of the Consume KV record answers HTTP 503 "KV Store
# is initializing", and the template lookup of every `tx` search fails on the search head ("Could not create KvStore
# External command based lookup 'tenx-dml-lookup' ... KV Store initializing", FATAL; Splunk Enterprise 10.4.3, a few
# seconds after a restart). The search still fails; this says why.
KV_STARTING = "KV Store is initializing"
KV_NOT_READY = "tx: the KV store is still starting, so the template lookup cannot run yet; retry in a moment."
