"""
Unit tests for tenx_search_builder: the compile of a user search into a search over
compact events.

These pin the four defects measured on a live Splunk 10.4.3 against the E21 capture
(20,000 compact events, 2,991 templates) and the three design points that were right and
must stay:

- D1  the hash clause is a phrase "~<hash>", never tenx_hash IN (...): the tilde is not a
      breaker so the indexed token is "~KC", and '*' is a wildcard even inside quotes.
- D2  NOT is kept, contributes nothing to the prefilter, and is applied after expansion.
- D3  a term is cut into pieces at Splunk's breakers, so an IP address or a hostname is
      matched piece by piece; a piece no template contains is required in the raw.
- Guard: a conjunction split between template text and a variable value ("cartstore
  a05b2981") must not be compiled as a single dictionary probe.

The template store is the offline double from tests/support, whose matching is whole-token,
like Splunk's. Each expectation quotes the live measurement it stands for.
"""
import pytest

import tenx_search_builder
from tenx_search_builder import (
	ResolvedState,
	split_pieces,
	hash_predicate,
	hash_clause,
	conjoin,
	is_wrapped,
)

from support.local_search_manager import LocalSearchManager, CsvTemplateStore


# Hashes shaped like the real ones: an interior space, a '*' after a usable prefix, a '*'
# too early for a prefix, and plain. The words are the non-'$' tokens of each pattern.
TEMPLATES = [
	('KC 2c#eEev', 'cartstore called with $ for $'),
	('0PIlry*uDJ', 'cart bootstrap $ items'),
	('a*bc', 'node ip$$$$.ec2.internal region us-west$'),
	('h_err', 'ERROR $ while processing request $'),
	('h_err2', 'error reading $ from cartstore'),
	('h_pay', 'payment $ failed for user $'),
	('h_pay2', 'payment declined for account $'),
	('h_login', 'User $ logged in from $'),
]


def make_config():
	return {
		'tenx_source_types': ['tenx_encoded'],
		'tenx_sources': [],
		'dml_source_type': 'tenx_dml_pure',
		'timestamp_placeholder': '__TENX_TS__',
		'variable_separator': '$',
		'tenx_extraction_name': 'REPORT-tenx',
		'tenx_extraction': 'tenx-hash-vars-extraction',
	}


class CountingManager(LocalSearchManager):
	"""Records every dictionary probe the builder makes."""
	def __init__(self, *args, **kwargs):
		LocalSearchManager.__init__(self, *args, **kwargs)
		self.probes = []

	def run_dml_search(self, dml_search, max_time_ms=2000, poll_interval_ms=50):
		self.probes.append(dml_search)
		return LocalSearchManager.run_dml_search(self, dml_search, max_time_ms, poll_interval_ms)


def make_builder(templates=TEMPLATES, **manager_kwargs):
	manager = CountingManager(CsvTemplateStore(templates), **manager_kwargs)
	builder = tenx_search_builder.TenxSearchBuilder(
		server_connection=None, tenx_config=make_config(), search_manager=manager)
	return builder, manager


def compile_search(search, **manager_kwargs):
	builder, manager = make_builder(**manager_kwargs)
	result = builder.build(search)
	return result, manager


def prefilter(compiled):
	"""The text between the modifiers and the inflate macro: the compact-event prefilter."""
	head = compiled.split('| `tenx-inflate`')[0]
	return head.replace('| search sourcetype=tenx_encoded', '', 1).strip()


# ---------------------------------------------------------------------------
# Pieces: a term is cut where Splunk cuts it
# ---------------------------------------------------------------------------

class TestSplitPieces:
	def test_ip_address_is_four_octets(self):
		assert split_pieces('192.168.45.200') == ['192', '168', '45', '200']

	def test_hostname_cuts_at_dash_and_dot(self):
		assert split_pieces('ip-192-168-42-205.ec2.internal') == ['ip', '192', '168', '42', '205', 'ec2', 'internal']

	def test_region(self):
		assert split_pieces('us-west-2') == ['us', 'west', '2']

	def test_plain_word_is_itself(self):
		assert split_pieces('bootstrap') == ['bootstrap']

	def test_wildcard_stays_attached(self):
		assert split_pieces('err*') == ['err*']

	def test_bare_wildcard_is_nothing(self):
		assert split_pieces('*') == []
		assert split_pieces('**') == []

	def test_underscore_and_colon_are_breakers(self):
		assert split_pieces('kube_system:pod') == ['kube', 'system', 'pod']

	def test_leading_and_repeated_breakers(self):
		assert split_pieces('--2..x') == ['2', 'x']


# ---------------------------------------------------------------------------
# D1: how one template is selected
# ---------------------------------------------------------------------------

class TestHashPredicate:
	def test_plain_hash_is_tilde_phrase(self):
		assert hash_predicate('h_err') == '"~h_err"'

	def test_hash_with_interior_space_is_still_one_phrase(self):
		# 305 of 2,991 real hashes contain a space; tenx_hash="KC 2c#eEev" found nothing.
		assert hash_predicate('KC 2c#eEev') == '"~KC 2c#eEev"'

	def test_star_hash_uses_prefix_before_star(self):
		# tenx_hash="0PIlry*uDJ" gave 0 of 39 events; the phrase "~0PIlry" gave 39.
		assert hash_predicate('0PIlry*uDJ') == '"~0PIlry"'

	def test_star_too_early_falls_back_to_field_predicate(self):
		# "~a" would be no filter at all ("~-" matched 12,648 of 20,000 events).
		assert hash_predicate('a*bc') == 'tenx_hash="a*bc"'
		assert hash_predicate('*abc') == 'tenx_hash="*abc"'

	def test_quotes_and_backslashes_are_escaped(self):
		assert hash_predicate('a"b\\c') == '"~a\\"b\\\\c"'

	def test_never_uses_in_list(self):
		for dml_hash in ('h_err', 'KC 2c#eEev', '0PIlry*uDJ', 'a*bc'):
			assert 'IN (' not in hash_predicate(dml_hash)


class TestHashClause:
	def test_sorted_and_deduplicated(self):
		# two hashes sharing a prefix before '*' collapse to one predicate
		assert hash_clause(['zz*1', 'h_b', 'zz*2', 'h_a']) == '("~h_a" OR "~h_b" OR "~zz")'

	def test_same_set_same_text(self):
		assert hash_clause(['h_b', 'h_a']) == hash_clause(['h_a', 'h_b'])


class TestConjoin:
	def test_none_is_unrestricted(self):
		assert conjoin([None, None]) is None
		assert conjoin([]) is None

	def test_single_part_unchanged(self):
		assert conjoin([None, '"a"']) == '"a"'

	def test_parts_are_parenthesised_once(self):
		assert conjoin(['"a" OR "b"', '("c")']) == '("a" OR "b") AND ("c")'

	def test_is_wrapped(self):
		assert is_wrapped('("a" OR "b")')
		assert not is_wrapped('("a") OR ("b")')
		assert not is_wrapped('"a"')


# ---------------------------------------------------------------------------
# D1 end to end: the compiled prefilter
# ---------------------------------------------------------------------------

class TestCompiledPrefilter:
	def test_single_word_in_templates(self):
		# live: `error` returned 159 of 438 with the IN list, 438 with the phrases
		result, manager = compile_search('sourcetype=tenx_encoded error')

		assert result.state == ResolvedState.SUCCESS
		assert prefilter(result.resolved) == '("error" OR ("~h_err" OR "~h_err2"))'
		assert result.resolved.endswith('| `tenx-inflate` | extract | spath | fields - tenx_hash, tenx_var_0, tenx_vars | search error')
		assert manager.probes == ['"error"']

	def test_space_and_star_hashes_are_selectable(self):
		# live: `bootstrap` 6 of 8 (two hashes unreachable), `cartstore` 1,075 of 1,974
		result, _ = compile_search('sourcetype=tenx_encoded bootstrap')
		assert prefilter(result.resolved) == '("bootstrap" OR ("~0PIlry"))'

		result, _ = compile_search('sourcetype=tenx_encoded cartstore')
		assert prefilter(result.resolved) == '("cartstore" OR ("~KC 2c#eEev" OR "~h_err2"))'

	def test_word_in_no_template_is_required_in_raw(self):
		# live row 6: `zzzqqq` returns 0, no error
		result, _ = compile_search('sourcetype=tenx_encoded zzzqqq')

		assert result.state == ResolvedState.SUCCESS
		assert prefilter(result.resolved) == '"zzzqqq"'
		assert result.no_dml_results

	def test_two_words_are_conjoined_per_word(self):
		# live row 8: `cartstore called`, truth 1,973
		result, _ = compile_search('sourcetype=tenx_encoded cartstore called')

		assert prefilter(result.resolved) == (
			'("cartstore" OR ("~KC 2c#eEev" OR "~h_err2")) AND ("called" OR ("~KC 2c#eEev"))')
		assert result.resolved.endswith('| search cartstore called')

	def test_conjunction_split_between_template_and_variable(self):
		# live rows 9 and 10: `cartstore a05b2981` truth 1,974. A single AND probe of both
		# words finds no template and loses every event; this is the regression guard.
		result, manager = compile_search('sourcetype=tenx_encoded cartstore a05b2981')

		assert prefilter(result.resolved) == '("cartstore" OR ("~KC 2c#eEev" OR "~h_err2")) AND ("a05b2981")'
		assert '"cartstore a05b2981"' not in manager.probes
		assert not result.no_dml_results

	def test_quoted_phrase_is_conjoined_and_reapplied_as_phrase(self):
		result, _ = compile_search('sourcetype=tenx_encoded "payment failed"')

		assert prefilter(result.resolved) == (
			'("payment" OR ("~h_pay" OR "~h_pay2")) AND ("failed" OR ("~h_pay"))')
		assert result.resolved.endswith('| search "payment failed"')

	def test_or_of_two_words(self):
		result, _ = compile_search('sourcetype=tenx_encoded payment OR login')
		assert prefilter(result.resolved) == (
			'("payment" OR ("~h_pay" OR "~h_pay2")) OR ("login" OR ("~h_login"))')

	def test_or_binds_tighter_than_the_implicit_and(self):
		# Splunk reads `a OR b c` as `(a OR b) AND c`; the compiled text must too.
		result, _ = compile_search('sourcetype=tenx_encoded payment OR login zzz')
		assert prefilter(result.resolved) == (
			'(("payment" OR ("~h_pay" OR "~h_pay2")) OR ("login" OR ("~h_login"))) AND ("zzz")')

	def test_parenthesised_group_keeps_its_boundary(self):
		result, _ = compile_search('sourcetype=tenx_encoded zzz OR (payment failed)')
		assert prefilter(result.resolved) == (
			'("zzz") OR (("payment" OR ("~h_pay" OR "~h_pay2")) AND ("failed" OR ("~h_pay")))')

	def test_wildcard_term(self):
		result, _ = compile_search('sourcetype=tenx_encoded err*')
		assert prefilter(result.resolved) == '("err*" OR ("~h_err" OR "~h_err2"))'

	def test_expansion_suffix_drops_the_re_extracted_compact_fields(self):
		# `| extract` re-runs the compact-format extraction on the expanded line, whose regex
		# matches any line with a comma; without this the sidebar shows a tenx_hash of
		# '{"stream":"stdout"' on every expanded event. tenx_expand_refused stays.
		result, _ = compile_search('sourcetype=tenx_encoded payment')
		assert '| spath | fields - tenx_hash, tenx_var_0, tenx_vars |' in result.resolved
		assert 'tenx_expand_refused' not in result.resolved

	def test_original_terms_are_always_reapplied(self):
		# the prefilter is a superset (the prefix branch over-selects), so even a single
		# word gets the post-expansion search
		result, _ = compile_search('sourcetype=tenx_encoded payment')
		assert result.resolved.endswith('| search payment')

	def test_field_only_search_has_no_prefilter_and_no_probe(self):
		result, manager = compile_search('sourcetype=tenx_encoded status=500')

		assert prefilter(result.resolved) == ''
		assert manager.probes == []
		assert result.resolved.endswith('| extract kvdelim="=" pairdelim=" " | search status=500')
		assert not result.no_prefilter   # no keywords at all is has_search_terms=False, not this

	def test_downstream_pipeline_is_preserved(self):
		result, _ = compile_search('sourcetype=tenx_encoded bootstrap | stats count')
		assert result.resolved.endswith('| search bootstrap | stats count')

	def test_same_search_compiles_identically(self):
		a, _ = compile_search('sourcetype=tenx_encoded payment')
		b, _ = compile_search('sourcetype=tenx_encoded payment')
		assert a.resolved == b.resolved


# ---------------------------------------------------------------------------
# Grammar: the shapes people actually type, with Splunk's precedence
# ---------------------------------------------------------------------------

class TestGrammarShapes:
	def test_group_followed_by_terms(self):
		# `(error OR warn) kubernetes` on a real dashboard panel showed 0 against a truth of
		# 468: the old grammar could not parse a group followed by more terms, and the
		# unparsed search ran as typed.
		result, _ = compile_search('sourcetype=tenx_encoded (payment OR login) zzz')

		assert result.state == ResolvedState.SUCCESS and result.engaged
		assert prefilter(result.resolved) == (
			'(("payment" OR ("~h_pay" OR "~h_pay2")) OR ("login" OR ("~h_login"))) AND ("zzz")')
		assert result.resolved.endswith('| search (payment OR login) zzz')

	def test_two_groups_with_explicit_and(self):
		result, _ = compile_search('sourcetype=tenx_encoded (payment OR login) AND (zzz OR failed)')
		assert prefilter(result.resolved) == (
			'(("payment" OR ("~h_pay" OR "~h_pay2")) OR ("login" OR ("~h_login"))) AND '
			'(("zzz") OR ("failed" OR ("~h_pay")))')

	def test_or_binds_tighter_than_explicit_and(self):
		# Splunk: `a OR b AND c` is `(a OR b) AND c`
		result, _ = compile_search('sourcetype=tenx_encoded payment OR login AND zzz')
		assert prefilter(result.resolved) == (
			'(("payment" OR ("~h_pay" OR "~h_pay2")) OR ("login" OR ("~h_login"))) AND ("zzz")')

	def test_not_binds_tighter_than_or(self):
		# Splunk: `NOT a OR b` is `(NOT a) OR b`, which is unrestricted, and NOT a b is (NOT a) AND b
		result, _ = compile_search('sourcetype=tenx_encoded NOT payment OR login')
		assert prefilter(result.resolved) == ''
		assert result.resolved.endswith('| search NOT payment OR login')

		result, _ = compile_search('sourcetype=tenx_encoded NOT payment login')
		assert prefilter(result.resolved) == '("login" OR ("~h_login"))'

	def test_inline_time_modifier_is_a_modifier(self):
		# `earliest=-24h error` on a dashboard panel showed 0 against 438: the old grammar
		# read -24h as a number and failed on the h
		result, _ = compile_search('sourcetype=tenx_encoded earliest=-24h latest=now payment')

		assert result.engaged
		assert result.resolved.startswith(' | search sourcetype=tenx_encoded earliest=-24h latest=now ("payment"')
		assert '| search payment' in result.resolved and 'earliest' not in result.resolved.split('| `tenx-inflate`')[1]

	def test_in_list_is_a_field_condition(self):
		result, _ = compile_search('sourcetype=tenx_encoded status IN (500, 502) payment')

		assert result.field_terms == ['status IN (500, 502)']
		assert prefilter(result.resolved) == '("payment" OR ("~h_pay" OR "~h_pay2"))'

	def test_negative_field_value(self):
		result, _ = compile_search('sourcetype=tenx_encoded delta=-1 payment')
		assert result.field_terms == ['delta=-1']

	def test_sourcetype_group_is_still_targeted(self):
		result, manager = compile_search('(sourcetype=tenx_encoded OR sourcetype=other) payment')

		assert result.engaged
		assert result.resolved.startswith(' | search (sourcetype=tenx_encoded OR sourcetype=other) ("payment"')


# ---------------------------------------------------------------------------
# D2: negation
# ---------------------------------------------------------------------------

class TestNegation:
	def test_not_alone_scans_and_excludes_after_expansion(self):
		# live row 5: `NOT bootstrap` returned 6 (the complement) against a truth of 19,992
		result, manager = compile_search('sourcetype=tenx_encoded NOT bootstrap')

		assert result.state == ResolvedState.SUCCESS
		assert prefilter(result.resolved) == ''
		assert result.resolved.endswith('| `tenx-inflate` | extract | spath | fields - tenx_hash, tenx_var_0, tenx_vars | search NOT bootstrap')
		assert result.no_prefilter
		assert result.has_search_terms
		# the negated word is never sent to the dictionary
		assert manager.probes == []

	def test_positive_term_prefilters_negated_term_does_not(self):
		result, manager = compile_search('sourcetype=tenx_encoded error NOT healthcheck')

		assert prefilter(result.resolved) == '("error" OR ("~h_err" OR "~h_err2"))'
		assert result.resolved.endswith('| search error NOT healthcheck')
		assert manager.probes == ['"error"']
		assert not result.no_prefilter

	def test_negated_group(self):
		result, _ = compile_search('sourcetype=tenx_encoded NOT (payment OR login)')

		assert prefilter(result.resolved) == ''
		assert result.resolved.endswith('| search NOT (payment OR login)')

	def test_negated_field_condition_is_kept(self):
		result, _ = compile_search('sourcetype=tenx_encoded payment NOT status=500')

		assert prefilter(result.resolved) == '("payment" OR ("~h_pay" OR "~h_pay2"))'
		assert '| search NOT status=500' in result.resolved
		assert result.field_terms == ['NOT status=500']

	def test_negated_compact_sourcetype_is_not_rewritten(self):
		# excluding the compact sourcetype means the search does not target it
		result, manager = compile_search('NOT sourcetype=tenx_encoded error')

		assert result.resolved == ' | search NOT sourcetype=tenx_encoded error'
		assert not result.engaged
		assert manager.probes == []


# ---------------------------------------------------------------------------
# D3: sub-token values
# ---------------------------------------------------------------------------

class TestSubTokenValues:
	def test_ip_address_requires_every_octet_in_raw(self):
		# live row 13: `192.168.45.200` returned 0 against 1,981; the four required pieces
		# ANDed on the compact raw returned exactly 1,981
		result, manager = compile_search('sourcetype=tenx_encoded 192.168.45.200')

		assert prefilter(result.resolved) == '("192") AND ("168") AND ("45") AND ("200")'
		assert result.resolved.endswith('| search 192.168.45.200')
		assert manager.probes == ['"192"', '"168"', '"45"', '"200"']

	def test_hostname_mixes_required_and_template_pieces(self):
		# live row 14: `ip-192-168-42-205.ec2.internal` returned 0 against 20,000. "ip",
		# "ec2" and "internal" are template text, so each is (piece OR its templates); the
		# numbers are in no template, so each must be in the raw.
		result, _ = compile_search('sourcetype=tenx_encoded ip-192-168-42-205.ec2.internal')

		assert prefilter(result.resolved) == (
			'("ip" OR (tenx_hash="a*bc")) AND ("192") AND ("168") AND ("42") AND ("205") '
			'AND ("ec2" OR (tenx_hash="a*bc")) AND ("internal" OR (tenx_hash="a*bc"))')
		assert result.resolved.endswith('| search ip-192-168-42-205.ec2.internal')

	def test_region(self):
		# live row 15: `us-west-2`, truth 5; the engine stores it as `us-west$` + `-2`
		result, _ = compile_search('sourcetype=tenx_encoded us-west-2')

		assert prefilter(result.resolved) == (
			'("us" OR (tenx_hash="a*bc")) AND ("west" OR (tenx_hash="a*bc")) AND ("2")')
		assert result.resolved.endswith('| search us-west-2')

	def test_repeated_piece_is_probed_once(self):
		result, manager = compile_search('sourcetype=tenx_encoded 10.0.0.1')

		assert prefilter(result.resolved) == '("10") AND ("0") AND ("1")'
		assert manager.probes == ['"10"', '"0"', '"1"']

	def test_pieces_matching_many_templates_share_one_clause(self):
		# a piece present in more templates than PER_PIECE_HASH_LIMIT does not repeat the
		# whole hash list; such pieces are grouped as ((p1 OR p2) OR <templates with both>)
		many = [('h%d' % index, 'kubernetes container %d $' % index) for index in range(600)]
		result, _ = compile_search('sourcetype=tenx_encoded kubernetes.container', templates=many)

		text = prefilter(result.resolved)
		assert text.startswith('(("kubernetes" OR "container") OR (')
		assert text.count('"~h') == 600


# ---------------------------------------------------------------------------
# Probe failures: never a guess
# ---------------------------------------------------------------------------

class TestProbeOutcomes:
	def test_failed_probe_is_a_retryable_failure_not_a_bare_search(self):
		result, _ = compile_search('sourcetype=tenx_encoded payment', fail_dml=True)

		assert result.state == ResolvedState.FAILURE
		assert result.retryable
		assert '`tenx-inflate`' not in result.resolved

	def test_truncated_probe_leaves_the_piece_unrestricted(self):
		# a cut hash list can be relied on neither as "required in raw" nor as a template set
		result, _ = compile_search('sourcetype=tenx_encoded payment', truncate_dml=True)

		assert result.state == ResolvedState.SUCCESS
		assert result.dml_truncated
		assert prefilter(result.resolved) == ''
		assert result.resolved.endswith('| search payment')

	def test_non_compact_search_is_untouched(self):
		result, manager = compile_search('index=main error')

		assert result.resolved == ' | search index=main error'
		assert manager.probes == []
