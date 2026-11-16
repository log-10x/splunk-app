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
			self._take()
			inner = []
			while self._peek()[0] not in (")", None):
				kind_, item = self._take()
				if kind_ not in ("word", "phrase"):
					raise Unparsed("%s() holding %s" % (value, kind_))
				inner.append(item)
			if self._take()[0] != ")":
				raise Unparsed("%s( without its closing parenthesis" % value)
			# `tx` applies the user's words after a pipe, where Splunk tests TERM() and CASE() against
			# the event's text, which for some arguments differs from the same search on an index
			# (TERM(pattern=*.log): 0 events on the index, 1,025 after a pipe, Splunk Enterprise 10.4.3).
			# Which words every such event holds is not certain, so they place no restriction.
			return ("unknown", "%s(%s)" % (value, " ".join(inner)))
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


def lookup_pieces(node, found=None, text_field=None):
	"""Every usable piece the prefilter would look up in the template dictionary. The parts of an
	address are not looked up: a part is digits only, so never template text (FORMAT_SPEC S3.2)."""
	found = set() if found is None else found
	node = as_text(node, text_field) or node
	if node[0] == "text":
		in_address = {p for a in addresses_of(node[1]) for p in pieces_of(a)} | set(prefix_parts(node[1]))
		found.update(p for p in (pieces_outside_times(node[1]) if text_field is None else pieces_kept(node[1]))
					 if usable(p) and p not in in_address)
	elif node[0] in ("and", "or"):
		for child in node[1]:
			lookup_pieces(child, found, text_field)
	return found


def prefilter(node, dictionary, text_field=None):
	"""
	The prefilter for a parsed search, or None for no restriction. `dictionary` maps a piece to
	(number of templates carrying it, [TERM(...) clauses for those templates]). `text_field`
	(see text_field_predicate) decides which field comparisons may restrict; None: none do.
	"""
	node = as_text(node, text_field) or node
	kind = node[0]
	if kind == "text":
		clauses = []
		addresses = addresses_of(node[1])
		prefixed = [p for p in prefix_parts(node[1]) if p not in {q for a in addresses for q in address_parts(a)}]
		in_address = {p for a in addresses for p in pieces_of(a)} | set(prefixed)
		for piece in (pieces_outside_times(node[1]) if text_field is None else pieces_kept(node[1])):
			if not usable(piece) or piece in in_address:
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
		clauses = [c for c in (prefilter(child, dictionary, text_field) for child in node[1]) if c is not None]
		return "(" + " AND ".join(clauses) + ")" if clauses else None
	if kind == "or":
		clauses = [prefilter(child, dictionary, text_field) for child in node[1]]
		return None if any(c is None for c in clauses) else "(" + " OR ".join(clauses) + ")"
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


def dictionary_search(pieces):
	"""
	The search that answers, for each piece, which templates carry it, as the TERM() clause of
	each template's hash_term, computed in SPL: the runs with '*' on both sides are blanked, the
	text is split at the major breakers, and the longest run of at least two characters with a
	letter or a digit is taken, else the first run.
	"""
	plist = sorted(pieces)
	return (
		'search `tenx-templates` earliest=0 latest=now ("%s") | fields dml_hash, _raw'
		' | eval piece=split("%s", " ") | mvexpand piece'
		' | where match(lower(_raw), "(^|[^\\p{L}\\p{N}])" . replace(piece, "\\*", "[\\p{L}\\p{N}]*") . "([^\\p{L}\\p{N}]|$)")'
		' | stats count by piece, dml_hash'
		' | eval segs=split(replace(replace(replace("~" . dml_hash, "--|%%[0-9A-Fa-f]{2}", " "),'
		' "(?<=\\*)[^ !;<>{}|&?+\\[\\]*,()\'\\"]+(?=\\*)", " "), "[ !;<>{}|&?+\\[\\]*,()\'\\"]", " "), " ")'
		' | eval cand=mvfilter(len(segs) >= 2 AND match(segs, "[\\p{L}\\p{N}]"))'
		' | eval best=substr(mvindex(mvsort(mvmap(cand, printf("%%03d", len(cand)) . cand)), -1), 4)'
		' | eval h="TERM(" . coalesce(best, mvindex(segs, 0)) . ")"'
		' | stats values(h) as hs count as n by piece'
	) % ('" OR "'.join(plist), " ".join(plist))


def dictionary_from_rows(rows):
	dictionary = {}
	for row in rows:
		terms = row.get("hs") or []
		terms = [terms] if isinstance(terms, str) else list(terms)
		dictionary[row["piece"]] = (int(row.get("n") or 0), terms)
	return dictionary


# A wildcard inside a word after `tx` (Splunk Enterprise 10.4.3). `tx` applies the words after it in
# a `search` after a pipe that Splunk cannot fold into the base search, and there a word with a `*`
# after its first character (Se*Privilege, le*FO, S*P*e) is matched as its prefix alone: any term
# starting with "se" (Windows 662 sample: 662 events, the base search on the raw events 3; Se*Zzz
# also 662). In a base search the same word is matched against the event's terms: the whole word,
# case-insensitively, `*` standing for any characters, against a major segment (the text between
# two major breakers) or a minor piece (between any two breakers). A word starting with `*`, or
# ending with its only `*`, or holding a breaker of its own (10.0*14, foo.*.com), matched after the
# pipe as on the index on every case measured, so it is left alone.
# The breakers of segmenters.conf [indexing] (btool on 10.4.3), the default for every sourcetype here.
MAJOR_CHARS = "[]<>(){}|!;,'\"*\n\r \t&?+"
MAJOR_SEQUENCES = ("%2526", "%2520", "%21", "%26", "%3B", "%7C", "%20", "%2B", "%3D", "--", "%5D", "%5B", "%3A",
				   "%0A", "%2C", "%28", "%29")
MINOR_CHARS = "/:=@.-$#%\\_"
WILD_STEP_FIELD = "tenx_keep"


def mid_wildcard(word):
	"""Whether `word` is a word Splunk matches differently after a pipe than on the index (see above)."""
	if not word or word[0] == "*" or "*" not in word.rstrip("*"):
		return False
	return not any(c in MAJOR_CHARS.replace("*", "") or c in MINOR_CHARS or c.isspace() for c in word)


def _class(chars):
	return "[" + "".join("\\" + c if c in "]\\^-[" else c for c in chars).replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "]"


def term_regex(word):
	"""
	A regular expression (PCRE, as Splunk's match() reads it, and Python's re alike) that finds `word`
	in an event's text as a base search on the index finds it: some major segment or minor piece of
	the text is the word, case-insensitively, each `*` standing for any characters of that term.
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
		text = re.escape(parts[0])
		for p in parts[1:]:
			text += inner + "*?" + re.escape(p)
		return start + text + (end if tail else "")
	return "(?i)(?:%s|%s)" % (
		pattern("(?:^|%s)" % brk, in_major, "(?=%s|$)" % brk),
		pattern("(?:^|%s|%s)" % (brk, minor), in_minor, "(?=%s|%s|$)" % (brk, minor)))


def _eval_string(text):
	return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _plain_term(word):
	"""A word the filter can match as a term itself: no breaker but `*`, not starting with `*`."""
	return bool(word) and word[0] != "*" and not any(
		c in MAJOR_CHARS.replace("*", "") or c in MINOR_CHARS or c.isspace() for c in word)


def wildcard_filter(text):
	"""
	The eval expression the `tx` macro runs before its final search (`eval [| tenxprefilter after=t]`,
	then `search tenx_keep=1`): tenx_keep set on the events whose words with a wildcard inside them
	(mid_wildcard()) match as a base search on the index would match them; None when there is none
	(or the words are not read with certainty), and every event is kept. The final search still
	applies every word, so the filter only has to be right where the final search is too broad:
	- a word with a wildcard inside it that is one of the search's top-level AND terms, alone or
	  quoted, is its term_regex() match;
	- a top-level AND term made only of such words and plain words (no breaker, no leading `*`,
	  under AND, OR and NOT) is evaluated whole, each word by term_regex(); a plain word or a word
	  with a trailing `*` matches after the pipe as on the index, and term_regex() gives the same;
	- any other place (next to a phrase, a field comparison, a word with a breaker or a leading
	  `*`) is left to the final search, as before.
	A word with a wildcard inside it under NOT is left alone: on the Windows 662 sample the base
	search on the index tests its prefix too (NOT Se*Privilege: 0 events on the index, as after the
	pipe), so its NOT is the prefix one (term_regex of the prefix and `*`).
	"""
	tokens = tokenize(text)
	if any(kind == "subsearch" for kind, _ in tokens):
		return None
	reader = Parser(tokens)
	try:
		tree = reader.parse()
	except Unparsed:
		return None
	marks, steps = {}, []

	def mark(word):
		if word not in marks:
			marks[word] = "tenx_w%d" % len(marks)
			steps.append("%s=if(match(_raw, %s), 1, 0)" % (marks[word], _eval_string(term_regex(word))))
		return marks[word] + "=1"

	def selects(node, positive=True):
		"""Whether `node` holds a word with a wildcard inside it where it selects events."""
		if node[0] == "text":
			return positive and id(node) in reader.text_at and mid_wildcard(node[1])
		if node[0] == "not":
			return selects(node[1], not positive)
		if node[0] in ("and", "or"):
			return any(selects(c, positive) for c in node[1])
		return False

	def whole(node, positive=True, build=True):
		"""`node` as an eval condition from term_regex() alone, or None when it holds anything else."""
		kind = node[0]
		if kind == "text":
			index = reader.text_at.get(id(node))
			if index is None or tokens[index][0] != "word" or not _plain_term(node[1]):
				return None
			word = node[1]
			if mid_wildcard(word) and not positive:
				word = word[:word.index("*") + 1]
			return mark(word) if build else word
		if kind == "not":
			inner = whole(node[1], not positive, build)
			return None if inner is None else "NOT (%s)" % inner
		if kind in ("and", "or"):
			parts = [whole(c, positive, build) for c in node[1]]
			if any(p is None for p in parts):
				return None
			return "(%s)" % (" %s " % kind.upper()).join(parts)
		return None

	conditions = []
	for term in (tree[1] if tree[0] == "and" else [tree]):
		if not selects(term):
			continue
		if term[0] == "text":
			conditions.append(mark(term[1]))
			continue
		if whole(term, build=False) is not None:
			conditions.append(whole(term))
	if not conditions:
		return None
	steps.append("%s=if(%s, 1, null())" % (WILD_STEP_FIELD, " AND ".join(conditions)))
	return ", ".join(steps)
