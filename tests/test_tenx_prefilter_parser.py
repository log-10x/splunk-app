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

	def test_an_ip_is_not_looked_up_in_the_dictionary(self):
		# Its parts are digits only, so never template text; TestWholeAddress has the clause.
		reader = p.Parser(p.tokenize("10.100.153.189"))
		assert p.lookup_pieces(reader.parse()) == set()

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


class TestFieldNarrowing:
	"""
	field=value restricts like its value written as a word, but only for a field whose value is
	text of the event (text_field). Compared on Splunk Enterprise 10.4.3 against the same
	searches on raw events.
	"""
	TEXT = staticmethod(p.text_field_predicate(["action", "signature_id", "dvc_ip"]))

	def narrowed(self, text):
		reader = p.Parser(p.tokenize(text))
		return p.prefilter(reader.parse(), D, self.TEXT)

	def test_without_the_list_no_field_restricts(self):
		assert plan("user=kafka")[0] is None

	def test_a_text_field_restricts_like_its_value(self):
		assert self.narrowed("user=kafka") == plan("kafka")[0]

	def test_a_quoted_value_restricts_like_the_phrase(self):
		assert self.narrowed('msg="migration successfully executed"') == plan('"migration successfully executed"')[0]

	def test_a_computed_field_does_not_restrict(self):
		assert self.narrowed("action=kafka") is None
		assert self.narrowed("signature_id=4648") is None

	def test_default_and_indexed_fields_do_not_restrict(self):
		for field in ("host", "source", "sourcetype", "index", "eventtype", "tag", "tag::action", "date_hour",
					  "tenx_sourcetype", "_time", "timestamp"):
			assert self.narrowed("%s=kafka" % field) is None, field

	def test_only_equality_restricts(self):
		for op in ("!=", ">", "<", ">=", "<="):
			assert self.narrowed("user%skafka" % op) is None, op
		assert self.narrowed("NOT user=kafka") is None

	def test_in_is_an_or_of_its_values(self):
		assert self.narrowed("user IN (kafka, error)") == plan("(kafka OR error)")[0]
		assert self.narrowed('user IN (kafka, "migration successfully")') == plan('(kafka OR "migration successfully")')[0]

	def test_in_with_a_value_that_places_no_restriction_places_none(self):
		assert self.narrowed("user IN (kafka, *)") is None
		assert self.narrowed("action IN (kafka, error)") is None

	def test_a_wildcard_field_name_is_never_a_text_field(self):
		# (The parser reads us*=kafka as a word, not as a field comparison.)
		assert self.TEXT("us*") is False and self.TEXT("user") is True

	def test_a_star_in_the_list_turns_narrowing_off(self):
		reader = p.Parser(p.tokenize("user=kafka"))
		assert p.prefilter(reader.parse(), D, p.text_field_predicate(["*"])) is None

	def test_pieces_of_field_values_are_looked_up(self):
		reader = p.Parser(p.tokenize('user=kafka action=warn msg="error x"'))
		assert p.lookup_pieces(reader.parse(), text_field=self.TEXT) == {"kafka", "error", "x"}
		reader = p.Parser(p.tokenize('user=kafka'))
		assert p.lookup_pieces(reader.parse()) == set()

	def test_a_value_with_dots_and_dashes_is_its_pieces(self):
		assert self.narrowed("dest=web-01.kafka.internal") == plan("web-01.kafka.internal")[0]


class TestWholeAddress:
	"""
	An IPv4 address requires each of its parts as a term, or the whole address as one term. Cut
	(four values) or whole (one value, ipv4SingleToken), the event holds those terms, so an index
	holding both forms is searched correctly. Compared on Splunk Enterprise 10.4.3 against the
	same searches on raw events, on indexes holding the cut form, the one-value form and both.
	"""

	def test_short_parts_narrow(self):
		# Every piece of 10.0.1.14 has one or two digits, which the piece rule alone leaves unused.
		assert plan("10.0.1.14")[0] == (
			"((TERM(10) OR TERM(10.0.1.14)) AND (TERM(0) OR TERM(10.0.1.14))"
			" AND (TERM(1) OR TERM(10.0.1.14)) AND (TERM(14) OR TERM(10.0.1.14)))")

	def test_term_quotes_and_a_text_field_read_as_the_address(self):
		want = plan("10.0.1.14")[0]
		assert plan("TERM(10.0.1.14)")[0] == want and plan('"10.0.1.14"')[0] == want
		reader = p.Parser(p.tokenize("IpAddress=10.0.1.14"))
		assert p.prefilter(reader.parse(), D, p.text_field_predicate([])) == want
		reader = p.Parser(p.tokenize("IpAddress=10.0.1.14"))
		assert p.prefilter(reader.parse(), D) is None

	def test_three_digit_parts_need_no_dictionary(self):
		assert plan("192.168.33.161")[0] == (
			"((TERM(192) OR TERM(192.168.33.161)) AND (TERM(168) OR TERM(192.168.33.161))"
			" AND (TERM(33) OR TERM(192.168.33.161)) AND (TERM(161) OR TERM(192.168.33.161)))")

	def test_a_port_is_a_piece_of_its_own(self):
		pf = plan("10.0.1.14:8443")[0]
		assert pf.startswith("(TERM(8443) AND (TERM(10) OR TERM(10.0.1.14))")
		reader = p.Parser(p.tokenize("10.0.1.14:8443"))
		assert p.lookup_pieces(reader.parse()) == {"8443"}

	def test_repeated_parts_once(self):
		assert plan("0.0.0.0")[0] == "((TERM(0) OR TERM(0.0.0.0)))"
		assert plan("10.0.0.1")[0] == "((TERM(10) OR TERM(10.0.0.1)) AND (TERM(0) OR TERM(10.0.0.1)) AND (TERM(1) OR TERM(10.0.0.1)))"

	def test_a_first_part_of_one_is_not_required(self):
		# After a "-", the engine keeps "-1" as template text (FORMAT_SPEC S2.2).
		assert p.address_parts("1.2.3.4") == ["2", "3", "4"]
		assert p.address_parts("1.1.1.1") == ["1"]
		assert p.address_parts("10.1.1.1") == ["10", "1"]

	def test_what_the_engine_keeps_cut_is_not_an_address(self):
		for text in ("1.2.3.4.5", "5.1.2.3.4x", "256.1.1.1", "1.2.3.1234", "10.0.1.14abc", "v1.2.3.4", "3.14", "1.2.3"):
			assert p.addresses_of(text) == [], text
		assert plan("1.2.3.4.5")[0] is None

	def test_addresses_the_engine_takes_whole(self):
		assert p.addresses_of("x.1.2.3.4") == ["1.2.3.4"]
		assert p.addresses_of("10.0.0.0/8 to 010.000.1.1, 10.0.0.0/8") == ["10.0.0.0", "010.000.1.1"]
		assert p.addresses_of("range 10.0.0.1-10.0.0.255.") == ["10.0.0.1", "10.0.0.255"]

	def test_a_partial_address_keeps_the_piece_rules(self):
		assert plan("192.168.*")[0] == "(TERM(192) AND TERM(168))"

	def test_negated_or_ored_with_nothing(self):
		assert plan("NOT 10.0.1.14")[0] is None
		assert plan("10.0.1.14 OR NOT x")[0] is None
		assert plan("10.0.1.14 OR 0.0.0.0")[0] == (
			"(((TERM(10) OR TERM(10.0.1.14)) AND (TERM(0) OR TERM(10.0.1.14)) AND (TERM(1) OR TERM(10.0.1.14))"
			" AND (TERM(14) OR TERM(10.0.1.14))) OR ((TERM(0) OR TERM(0.0.0.0))))")

	def test_other_words_keep_their_dictionary_clause(self):
		assert plan("kafka 10.0.1.14")[0].startswith("(((TERM(kafka) OR TERM(~k1))) AND ((TERM(10) OR TERM(10.0.1.14))")
