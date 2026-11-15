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
   comparisons, field IN (...), TERM() and CASE(), subsearches;
3. builds the prefilter. A word or phrase is cut into pieces at anything that is not a letter
   or a digit; each piece must appear in the compact event as a value (TERM(piece)) or be
   carried by the event's template (TERM(<token of the template's hash>)). A piece is not
   used when a rendered timestamp could print it, when it holds a character outside a-z and
   0-9, or when more than MAX_TEMPLATES templates carry it. A NOT, a subsearch, and a field
   compared with anything but = place no restriction. An OR with any unrestricted branch
   places none.

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
FIELD_TERM = re.compile(r"^([A-Za-z0-9_.:@{}\-]+)(!=|<=|>=|=|<|>)(.*)$", re.S)
FIELD_NAME = re.compile(r"^[A-Za-z0-9_.:@{}\-]+$")
OPERATOR = re.compile(r"^(?:!=|<=|>=|=|<|>)")
# An IPv4 address in a search word, cut the way the engine's ipv4SingleToken option cuts it: four
# parts of 1 to 3 digits joined by single dots, the first not right after a letter or digit or
# after a digit and a dot, the last not followed by a letter or digit or by a dot and a digit.
# Each part must also be 255 or less (checked in addresses_of).
ADDRESS = re.compile(r"(?<![0-9A-Za-z])(?<![0-9]\.)([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})"
					 r"(?![0-9A-Za-z])(?!\.[0-9])")


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


def tokenize(text):
	tokens, i, n = [], 0, len(text)
	while i < n:
		c = text[i]
		if c.isspace():
			i += 1
			continue
		if c == '"':
			j, buf = i + 1, []
			while j < n:
				if text[j] == "\\" and j + 1 < n:
					buf.append(text[j + 1])
					j += 2
					continue
				if text[j] == '"':
					j += 1
					break
				buf.append(text[j])
				j += 1
			tokens.append(("phrase", "".join(buf)))
			i = j
			continue
		if c in "()":
			tokens.append((c, c))
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
		i = j
	return tokens


class Parser(object):
	"""NOT binds tightest, then OR, then AND (written or implied), as in Splunk's search language."""

	def __init__(self, tokens):
		self.tokens, self.i = tokens, 0
		self.time_modifier = False
		self.unquoted_comma = False

	def _peek(self, k=0):
		return self.tokens[self.i + k] if self.i + k < len(self.tokens) else (None, None)

	def _take(self):
		token = self._peek()
		self.i += 1
		return token

	def parse(self):
		if not self.tokens:
			return ("true",)
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
			return ("text", value)
		if kind != "word":
			raise Unparsed("unexpected %s" % kind)
		following = self._peek()
		if value in ("TERM", "CASE") and following[0] == "(":
			self._take()
			inner = []
			while self._peek()[0] not in (")", None):
				inner.append(self._take()[1])
			self._take()
			return ("text", " ".join(inner))
		if following == ("word", "IN") and self._peek(1)[0] == "(":
			self._take()
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
			self._take()
			return ("in", value, values)
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
		if match and match.group(1):
			if match.group(1).lower() in TIME_FIELDS:
				self.time_modifier = True
			return ("field", match.group(1), match.group(2), unquote(match.group(3)))
		if "," in value:
			self.unquoted_comma = True
		return ("text", value)


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
		if ch.isalnum() or ch == "*":
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
	pieces, buf = [], []
	for ch in text.lower():
		if ch.isalnum() or ch == "*":
			buf.append(ch)
		elif buf:
			pieces.append("".join(buf))
			buf = []
	if buf:
		pieces.append("".join(buf))
	return pieces


def usable(piece):
	return bool(re.fullmatch(r"[a-z0-9*]+", piece)) and piece.strip("*") != "" and not TIMESTAMP_PIECE.match(piece)


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


def lookup_pieces(node, found=None, text_field=None):
	"""Every usable piece the prefilter would look up in the template dictionary. The parts of an
	address are not looked up: a part is digits only, so never template text (FORMAT_SPEC S3.2)."""
	found = set() if found is None else found
	node = as_text(node, text_field) or node
	if node[0] == "text":
		in_address = {p for a in addresses_of(node[1]) for p in pieces_of(a)}
		found.update(p for p in (pieces_of(node[1]) if text_field is None else pieces_kept(node[1]))
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
		in_address = {p for a in addresses for p in pieces_of(a)}
		for piece in (pieces_of(node[1]) if text_field is None else pieces_kept(node[1])):
			if not usable(piece) or piece in in_address:
				continue
			count, terms = dictionary.get(piece, (0, []))
			if count > MAX_TEMPLATES:
				continue
			clauses.append("(TERM(%s) OR %s)" % (piece, " OR ".join(terms)) if terms else "TERM(%s)" % piece)
		for address in addresses:
			clauses.extend("(TERM(%s) OR TERM(%s))" % (part, address) for part in address_parts(address))
		return "(" + " AND ".join(clauses) + ")" if clauses else None
	if kind == "and":
		clauses = [c for c in (prefilter(child, dictionary, text_field) for child in node[1]) if c is not None]
		return "(" + " AND ".join(clauses) + ")" if clauses else None
	if kind == "or":
		clauses = [prefilter(child, dictionary, text_field) for child in node[1]]
		return None if any(c is None for c in clauses) else "(" + " OR ".join(clauses) + ")"
	return None


def dictionary_search(pieces):
	"""
	The search that answers, for each piece, which templates carry it, as the TERM() clause of
	the longest token of each template's hash between Splunk's major breakers (a leading ~ stays
	attached to a letter or digit, so it is part of the token).
	"""
	plist = sorted(pieces)
	return (
		'search `tenx-templates` earliest=0 latest=now ("%s") | fields dml_hash, _raw'
		' | eval piece=split("%s", " ") | mvexpand piece'
		' | where match(lower(_raw), "(^|[^\\p{L}\\p{N}])" . replace(piece, "\\*", "[\\p{L}\\p{N}]*") . "([^\\p{L}\\p{N}]|$)")'
		' | stats count by piece, dml_hash'
		' | eval segs=split(replace(replace("~" . dml_hash, "--|%%[0-9A-Fa-f]{2}", " "), "[ !;<>{}|&?+\\[\\]*,()\'\\"]", " "), " ")'
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
