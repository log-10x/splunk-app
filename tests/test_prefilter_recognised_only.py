"""
The prefilter requires a word of a compact event only when the parser has recognised the search term
and every event the search keeps is certain to hold that word in its compact text. A token sequence
it does not recognise places no restriction (an "unknown" node; an OR holding one places none), and
where the structure of the whole search is in doubt (a macro, AND or OR where a term should be, IN
without its parentheses) nothing is narrowed at all. Two kinds of text an expanded event holds that
its compact text does not: the rendered timestamp (stored as an epoch), and, for a wildcard between
two characters, a run Splunk matches across a minor breaker. Template text is found through the
template lookup (the dictionary), exact words and wildcards alike.

Each example below was measured on Splunk Enterprise 10.4.3, raw against `tx`, with the parser
before this change (selecting too few) and with it (equal), on 900 key=value, syslog and access-log
lines written for the test, compact under five templates, three of them with a timestamp slot.
"""
import pytest

import tenx_prefilter_parser as p

D = {"root": (3, ["TERM(~r1)"]), "error": (3, ["TERM(~e1)"]), "user": (2, ["TERM(~u1)"]),
	 "web": (2, ["TERM(~w1)"]), "get": (1, ["TERM(~g1)"])}


def tree(text):
	return p.Parser(p.tokenize(text)).parse()


def pf(text):
	return p.prefilter(tree(text), D)


def unparsed(text):
	try:
		tree(text)
	except p.Unparsed:
		return True
	return False


class TestTimestampText:
	"""A rendered timestamp prints text the compact event does not hold (raw against the parser
	before: `2026*` 400/0, `Nov*` 400/0, `No*` 464/64, `14/Nov/2026*` 200/0, `*T10:1*` 1/0, `*44`
	28/10, `*36*` 47/31, `*1Z` 15/0, `0000` 200/0)."""

	@pytest.mark.parametrize("text", ["2026*", "20*26", "*T10:1*", "Nov*", "14/Nov/2026*", "No*", "*44", "*36*",
									  "*1Z", "0000", "*Z", "nov", "14t10", "162z", "162utc", "t10", "i1012", "Sat*",
									  "*pm", "a*", "2026-11-14T10*", '"Nov 14"', '"2026-11-14T00:00:15.162Z"'])
	def test_places_no_restriction(self, text):
		assert pf(text) is None, text

	def test_timestamp_could_print(self):
		for piece in ("2026*", "nov*", "no*", "*t10", "*44", "*36*", "*1z", "0000", "936", "*z", "14t10", "162utc",
					  "a*", "*", "sept*", "*gmt"):
			assert p.timestamp_could_print(piece), piece
		for piece in ("err*", "*rror", "*shadowcopy*", "firefox*", "spn*", "win32", "pnpentity", "0x1f", "root",
					  "login", "monitor", "info", "fatal", "debug", "warn", "api", "alice", "erin", "*oot", "roo*"):
			assert not p.timestamp_could_print(piece), piece

	def test_other_words_still_narrow(self):
		assert pf("error*") == "(TERM(error*))"
		assert pf("root GET") == "(((TERM(root) OR TERM(~r1))) AND ((TERM(get) OR TERM(~g1))))"
		assert pf("*oot") == "(TERM(*oot))"
		assert pf("10.0.2.*") == "(TERM(10) AND TERM(0) AND TERM(2))"


class TestAWildcardInsideAWord:
	"""Splunk matches a wildcard between two characters across a minor breaker (`le*FO` matches
	`level=INFO`), which the compact event, cut at those breakers, does not hold as one term (DF:
	`le*FO` raw 2,278, tx 0; `am*50` 197, 0)."""

	@pytest.mark.parametrize("text", ["le*FO", "am*50", "to*en", "ER*OR", "ro*t", "a*ce", "us*ot", "Se*Privilege"])
	def test_places_no_restriction(self, text):
		assert pf(text) is None, text

	def test_at_the_ends_it_narrows(self):
		assert pf("roo*") == "(TERM(roo*))" and pf("*oo*") == "(TERM(*oo*))"


class TestEveryConstruct:
	def test_field_comparisons_place_no_restriction(self):
		for op in ("=", "!=", "<", ">", "<=", ">="):
			for name in ("usr", '"usr"', "a.b", '"a.b"', "x{}.y", "ns:key", "user-id", "@ts"):
				for spaced in ("%s%s%s", "%s %s %s", "%s%s %s", "%s %s%s"):
					text = spaced % (name, op, "root")
					assert pf(text) is None, text
		for text in ("usr=*", "usr!=*", "nofield=*", 'msg="user root did login"', 'msg="a = b"', "usr=act",
					 "index=main", "sourcetype=tenx_encoded", "eventtype=x", "tag=authentication"):
			assert pf(text) is None, text

	def test_in(self):
		for text in ("usr IN (root)", '"usr" IN (root)', "usr IN (root, alice)", '"usr" IN ("root" alice)',
					 "NOT usr IN (root)", 'NOT "usr" IN (root)', '"source" IN (/var/log/app/app.log)',
					 'NOT "status" IN ("502" 500)', 'NOT "event" IN (login)'):
			assert pf(text) is None, text

	def test_indexed_field_terms(self):
		# host::fr-spl root: raw 227, the parser before 0 (it required fr and spl as words)
		assert tree("host::fr-spl") == ("field", "host", "::", "fr-spl")
		assert pf("host::fr-spl root") == "(((TERM(root) OR TERM(~r1))))"

	def test_term_and_case(self):
		for text in ("TERM(root)", "TERM(usr=root)", "TERM(10.0.2.209)", "CASE(root)", "NOT TERM(root)",
					 "NOT CASE(root)", "TERM(pattern=*.log)", "TERM(91%)"):
			assert pf(text) is None, text
		assert unparsed("TERM(a [search x])") and unparsed("TERM(a")

	def test_not(self):
		for text in ("NOT root", "NOT usr=root", 'NOT "user root did login"', "NOT Nov*", "NOT TERM(x)", "NOT host::a"):
			assert pf(text) is None, text
		assert pf("error NOT root") == "(((TERM(error) OR TERM(~e1))))"

	def test_an_or_with_a_member_not_recognised(self):
		for text in ("root OR a/b=c", 'root OR "abc"def', "root OR =x", "root OR TERM(x)", "root OR x\\y"):
			assert pf(text) is None, text
		assert pf("root OR error") == "(((TERM(root) OR TERM(~r1))) OR ((TERM(error) OR TERM(~e1))))"

	def test_words_not_recognised(self):
		for text in ("a/b=c", "=x", "<5", 'a"b"c', "a]b", "x\\y", "C:\\Windows\\explorer.exe", "TERM", "CASE", '"abc"def'):
			assert pf(text) is None, text
		assert tree("error a/b=c") == ("and", [("text", "error"), ("unknown", "a/b=c")])

	def test_subsearches_macros_and_misplaced_operators(self):
		assert pf("[| makeresults | eval search=\"root\" | fields search]") is None
		assert pf("root [search x]") == "(((TERM(root) OR TERM(~r1))))"
		for text in ("error `my_macro`", "`m`", "OR x", "AND x", "x AND", "x OR", "IN (a)", "x IN y", '"x" IN y',
					 "(x", "x)", "NOT"):
			assert unparsed(text), text

	def test_time_modifiers_are_seen(self):
		reader = p.Parser(p.tokenize("earliest=-1h root"))
		reader.parse()
		assert reader.time_modifier

	def test_lowercase_keywords_are_words(self):
		# Splunk Enterprise 10.4.3: `usr in (root)`, `root or alice`, `root and alice`, `root not alice`
		# each 0 events on the raw lines, as words
		assert tree("root or alice") == ("and", [("text", "root"), ("text", "or"), ("text", "alice")])

	def test_a_pipe_ends_the_text(self):
		assert p.text_after_macro('index=x `tx` root | where usr="a|b" | stats count') == " root "
		assert p.text_after_macro('index=x `tx` "a | b" root | head 1') == ' "a | b" root '

	def test_a_glued_phrase(self):
		# "user"root: Splunk Enterprise 10.4.3, 178 raw, 178 through tx either way; not a form read
		# with certainty, so it places no restriction
		assert pf('"user"root') is None
		assert pf('"user" root') == "(((TERM(user) OR TERM(~u1))) AND ((TERM(root) OR TERM(~r1))))"
