"""
The prefilter of the `tx` macro: which compact events a search expands.

The rule every case here checks is the one that keeps `tx` correct: the prefilter may select
more compact events than the search after `tx` keeps, never fewer. A clause is therefore
required only where a word must be present in every match; anything negated, compared as a
field, or ORed with something unrestricted places no restriction.
"""
import pytest

import tenx_prefilter_parser as p

# A stand-in dictionary: piece -> (templates carrying it, their TERM() clauses).
D = {
	"error": (10, ["TERM(~e1)"]),
	"warn": (5, ["TERM(~w1)"]),
	"kafka": (3, ["TERM(~k1)"]),
	"valkeycartstore": (2, ["TERM(~v1)"]),
	"migration": (4, ["TERM(~m1)"]),
	"successfully": (9, ["TERM(~s1)"]),
	"executed": (9, ["TERM(~x1)"]),
	"info": (6000, ["TERM(~i1)"]),
}


def plan(text):
	reader = p.Parser(p.tokenize(text))
	tree = reader.parse()
	return p.prefilter(tree, D), reader


class TestTextAfterMacro:

	def test_up_to_the_first_pipe(self):
		assert p.text_after_macro('search index=a `tx` error "x" | stats count') == ' error "x" '

	def test_a_pipe_inside_quotes_is_part_of_the_words(self):
		assert p.text_after_macro('search index=a `tx` "a | b" | head 1') == ' "a | b" '

	def test_a_pipe_inside_a_subsearch_is_part_of_the_words(self):
		assert p.text_after_macro('search `tx` x [search y | head 1] | stats count') == ' x [search y | head 1] '

	def test_an_escaped_quote_does_not_end_the_phrase(self):
		assert p.text_after_macro('search `tx` "a \\" | b" | x') == ' "a \\" | b" '

	def test_the_macro_inside_quotes_is_not_the_macro(self):
		assert p.text_after_macro('search "`tx` no" `tx` warn | x') == ' warn '

	def test_no_macro(self):
		assert p.text_after_macro('search index=a error') is None

	def test_nothing_after_the_macro(self):
		assert p.text_after_macro('search index=a `tx`') == ''


class TestPrefilter:

	def test_a_word(self):
		assert plan("ValkeyCartStore")[0] == "((TERM(valkeycartstore) OR TERM(~v1)))"

	def test_a_phrase_requires_each_of_its_words(self):
		pf = plan('"successfully executed"')[0]
		assert "TERM(successfully)" in pf and "TERM(executed)" in pf and " AND " in pf

	def test_or(self):
		pf = plan("error OR warn")[0]
		assert pf.startswith("(") and " OR " in pf and "TERM(~e1)" in pf and "TERM(~w1)" in pf

	def test_not_places_no_restriction(self):
		assert plan("error NOT kafka")[0] == "(((TERM(error) OR TERM(~e1))))"

	def test_or_with_a_negated_branch_reads_every_event(self):
		assert plan("error OR NOT kafka")[0] is None

	def test_or_with_a_timestamp_piece_reads_every_event(self):
		assert plan("error OR 2026")[0] is None

	def test_or_with_a_field_reads_every_event(self):
		assert plan("ValkeyCartStore OR kubernetes.container_name=grafana")[0] is None

	def test_or_binds_tighter_than_the_implied_and(self):
		pf = plan("error OR warn kafka")[0]
		assert pf.endswith("AND ((TERM(kafka) OR TERM(~k1))))")

	def test_a_parenthesised_group_then_not(self):
		pf = plan("(error OR warn) NOT kafka")[0]
		assert "kafka" not in pf and "TERM(~e1)" in pf and "TERM(~w1)" in pf

	def test_field_in_places_no_restriction(self):
		assert plan('kubernetes.container_name IN ("cart", "frontend")')[0] is None
		assert plan("kubernetes.container_name IN (cart, frontend)")[0] is None

	def test_field_in_beside_a_word_keeps_the_word(self):
		assert plan('ValkeyCartStore kubernetes.container_name IN ("cart", "frontend")')[0] == "(((TERM(valkeycartstore) OR TERM(~v1))))"

	def test_term_and_case_are_read_as_their_word(self):
		assert plan("TERM(ValkeyCartStore)")[0] == "((TERM(valkeycartstore) OR TERM(~v1)))"
		assert plan("CASE(ValkeyCartStore)")[0] == "((TERM(valkeycartstore) OR TERM(~v1)))"

	def test_an_escaped_quote_inside_a_phrase(self):
		pf = plan('"\\"stream\\": \\"stdout\\""')[0]
		assert pf == "(TERM(stream) AND TERM(stdout))"

	def test_a_subsearch_places_no_restriction(self):
		assert plan("ValkeyCartStore [search x | head 1]")[0] == "(((TERM(valkeycartstore) OR TERM(~v1))))"

	def test_nothing_or_a_star_reads_every_event(self):
		assert plan("")[0] is None
		assert plan("*")[0] is None

	def test_a_wildcard_piece_is_looked_up(self):
		reader = p.Parser(p.tokenize("Valkey*"))
		assert p.lookup_pieces(reader.parse()) == {"valkey*"}

	def test_non_ascii_pieces_are_not_used(self):
		assert plan("zürich")[0] is None
		assert p.lookup_pieces(p.Parser(p.tokenize("error zürich")).parse()) == {"error"}

	def test_a_piece_in_too_many_templates_is_not_used(self):
		assert plan("info ValkeyCartStore")[0] == "(((TERM(valkeycartstore) OR TERM(~v1))))"

	def test_a_value_no_template_carries(self):
		assert plan("a05b2981")[0] == "(TERM(a05b2981))"

	def test_an_ip_is_its_pieces(self):
		reader = p.Parser(p.tokenize("10.100.153.189"))
		assert p.lookup_pieces(reader.parse()) == {"100", "153", "189"}

	def test_lowercase_or_is_a_word(self):
		pf = plan("error or warn")[0]
		assert "TERM(or)" in pf and " OR TERM(~w1)" in pf


class TestStops:

	def test_time_modifier_after_tx(self):
		assert plan("error earliest=-1h")[1].time_modifier
		assert plan("error latest=now")[1].time_modifier
		assert not plan("error")[1].time_modifier

	def test_unquoted_comma(self):
		assert plan("info, ValkeyCartStore")[1].unquoted_comma
		assert not plan('"info, ValkeyCartStore"')[1].unquoted_comma
		assert not plan("status IN (500, 503)")[1].unquoted_comma

	def test_unbalanced_parentheses_are_unparsed(self):
		with pytest.raises(p.Unparsed):
			p.Parser(p.tokenize("(error OR warn")).parse()
		with pytest.raises(p.Unparsed):
			p.Parser(p.tokenize("error OR")).parse()


class TestDictionary:

	def test_the_dictionary_search_names_each_piece(self):
		s = p.dictionary_search({"error", "warn"})
		assert '("error" OR "warn")' in s and 'split("error warn", " ")' in s and s.startswith("search `tenx-templates`")

	def test_rows_with_one_or_many_terms(self):
		d = p.dictionary_from_rows([{"piece": "a", "n": "1", "hs": "TERM(~a)"}, {"piece": "b", "n": "2", "hs": ["TERM(~b)", "TERM(~c)"]}])
		assert d == {"a": (1, ["TERM(~a)"]), "b": (2, ["TERM(~b)", "TERM(~c)"])}


class TestHashTerm:
	"""
	The term that selects a template's compact events. Measured on Splunk 10.4.3: every run of
	'~<hash>' between major breakers is found by TERM(), from the index alone and with a field
	comparison in the same search, except a run with '*' on both sides, which only the index
	alone finds (-*Hf8l*8.5}: TERM(Hf8l) 4 events, sourcetype=tenx_encoded TERM(Hf8l) 0).
	"""

	def test_the_longest_run(self):
		assert p.hash_term("KC 2c#eEev") == "2c#eEev"
		assert p.hash_term("H*ly1wX1N{") == "ly1wX1N"
		assert p.hash_term("-K<dSy@u*az") == "dSy@u"

	def test_a_run_between_two_stars_is_never_used(self):
		assert p.hash_term("-*Hf8l*8.5}") == "8.5"
		assert p.hash_term("-M;*DEsWy*;") == "~-M"
		assert p.hash_term("Nss*tLW2r*") == "~Nss"
		for dml_hash in ("-*Hf8l*8.5}", "-M;*DEsWy*;", "Nss*tLW2r*", "*ab*cd*", "a*bcdefg*h"):
			text = "~" + dml_hash
			term = p.hash_term(dml_hash)
			i = text.index(term)
			assert not (text[i - 1:i] == "*" and text[i + len(term):i + len(term) + 1] == "*"), dml_hash

	def test_the_first_run_when_nothing_else_qualifies(self):
		# The first run begins with '~' and nothing precedes it, so it is never between two stars.
		assert p.hash_term("*abc*") == "~"
		assert p.hash_term("-*") == "~-"
		assert p.hash_term("**") == "~"
		assert p.hash_term("-.*") == "~-."

	def test_a_leading_tilde_stays_attached(self):
		assert p.hash_term("0PIlry*uDJ") == "~0PIlry"
		assert p.hash_term("-JEmd{tpmg*") == "~-JEmd"

	def test_the_term_is_a_whole_run_of_the_hash(self):
		import random
		alphabet = " !#$&*+./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}"
		rnd = random.Random(84)
		for _ in range(5000):
			dml_hash = ("-" if rnd.random() < 0.5 else "") + "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 10)))
			runs = p.HASH_SEGMENT.findall("~" + dml_hash)
			assert p.hash_term(dml_hash) in runs, dml_hash

	def test_the_dictionary_search_computes_the_same_term(self):
		# The prefilter's search computes the term in SPL. Run its three replace() patterns, split,
		# filter and pick in Python, with SPL's string escapes read back, and compare.
		import random
		import re
		s = p.dictionary_search({"x"})
		chain = re.search(r'eval segs=split\(replace\(replace\(replace\("~" \. dml_hash, "(.*?)", " "\), "(.*?)", " "\), "(.*?)", " "\), " "\)', s)
		assert chain, s
		pats = [re.compile(g.replace('\\"', '"')) for g in chain.groups()]

		def spl(dml_hash):
			text = "~" + dml_hash
			for pat in pats:
				text = pat.sub(" ", text)
			segs = text.split(" ")
			cand = [x for x in segs if len(x) >= 2 and re.search(r"[A-Za-z0-9]", x)]
			return max(cand, key=lambda x: "%03d" % len(x) + x) if cand else segs[0]

		alphabet = " !#$&*+./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}"
		rnd = random.Random(10)
		hashes = ["-*Hf8l*8.5}", "*abc*", "a*bc", "-M;*DEsWy*;", "**", "-*", "*a*b*c*d"]
		hashes += [("-" if rnd.random() < 0.5 else "") + "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 10)))
				   for _ in range(5000)]
		for dml_hash in hashes:
			assert spl(dml_hash) == p.hash_term(dml_hash), dml_hash
		# and the shipped split alone would pick the run between the stars
		assert "(?<=\\*)" in chain.group(2) and "(?=\\*)" in chain.group(2)
