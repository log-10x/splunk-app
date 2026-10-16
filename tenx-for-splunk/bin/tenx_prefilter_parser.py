"""
The words after the `tx` macro, read as a search, and the prefilter built from them.

`tx` is written in front of an ordinary search: index=app_logs `tx` error "payment failed".
Its subsearch runs the tenxprefilter command once per search. The command reads the job's
own search text, and this module

1. takes the text after the first `tx` that is outside quotes, up to the first pipe that is
   outside quotes and brackets;
2. parses it as Splunk search terms: quoted phrases (with backslash escapes), parentheses,
   NOT, OR and AND with Splunk's precedence (NOT, then OR, then the implied AND), field
   comparisons, field IN (...), TERM() and CASE(), subsearches;
3. builds the prefilter. A word or phrase is cut into pieces at anything that is not a letter
   or a digit; each piece must appear in the compact event as a value (TERM(piece)) or be
   carried by the event's template (TERM(<token of the template's hash>)). A piece is not
   used when a rendered timestamp could print it, when it holds a character outside a-z and
   0-9, or when more than MAX_TEMPLATES templates carry it. A field comparison, a NOT and a
   subsearch place no restriction. An OR with any unrestricted branch places none.

Anything the prefilter leaves unrestricted is still applied, exactly, by the search that
follows `tx` on the expanded text. The prefilter only selects which compact events to expand,
so it may select more than the search keeps, never fewer.
"""
import re

MACRO = "`tx`"
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


class Unparsed(Exception):
	"""The text after `tx` is not a search this module can read; the caller reads every event."""


def text_after_macro(search):
	"""The text after the first `tx` outside quotes, up to the first top-level pipe; None if absent."""
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
		elif search.startswith(MACRO, i):
			start = i + len(MACRO)
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
			while self._peek()[0] not in (")", None):
				self._take()
			self._take()
			return ("field", value)
		match = FIELD_TERM.match(value)
		if match and match.group(1):
			if match.group(1).lower() in TIME_FIELDS:
				self.time_modifier = True
			return ("field", match.group(1))
		if "," in value:
			self.unquoted_comma = True
		return ("text", value)


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


def lookup_pieces(node, found=None):
	"""Every usable piece the prefilter would look up in the template dictionary."""
	found = set() if found is None else found
	if node[0] == "text":
		found.update(p for p in pieces_of(node[1]) if usable(p))
	elif node[0] in ("and", "or"):
		for child in node[1]:
			lookup_pieces(child, found)
	return found


def prefilter(node, dictionary):
	"""
	The prefilter for a parsed search, or None for no restriction. `dictionary` maps a piece to
	(number of templates carrying it, [TERM(...) clauses for those templates]).
	"""
	kind = node[0]
	if kind == "text":
		clauses = []
		for piece in pieces_of(node[1]):
			if not usable(piece):
				continue
			count, terms = dictionary.get(piece, (0, []))
			if count > MAX_TEMPLATES:
				continue
			clauses.append("(TERM(%s) OR %s)" % (piece, " OR ".join(terms)) if terms else "TERM(%s)" % piece)
		return "(" + " AND ".join(clauses) + ")" if clauses else None
	if kind == "and":
		clauses = [c for c in (prefilter(child, dictionary) for child in node[1]) if c is not None]
		return "(" + " AND ".join(clauses) + ")" if clauses else None
	if kind == "or":
		clauses = [prefilter(child, dictionary) for child in node[1]]
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
