"""
Unit tests for tenx_alert_compiler.

These exercise the save-time compiler end to end against a local template store, so no
Splunk instance is needed (see tests/support/local_search_manager.py and conftest.py for
the offline doubles). ResolvedState.COMPLEX -> REJECTED is driven with an injected stub
builder, since that state is awkward to trigger through the grammar and dependency
injection is the more robust way to pin the mapping.
"""
import os

import pytest

import tenx_search_builder
from tenx_search_builder import ResolvedState, BuildResult
from tenx_alert_compiler import (
	TenxAlertCompiler,
	AlertStrategy,
	AlertCompileResult,
	_normalize_native,
	_referenced_tenx_sources,
	_specifier_values,
	_has_negation,
	_stringy_field_terms,
)

from support.local_search_manager import LocalSearchManager, CsvTemplateStore
from conftest import DEMO_TEMPLATES_CSV


# A small, deterministic template set. build_pure_dml_line prepends the hash and strips '$',
# so the searchable words are the non-$ tokens of each pattern. The DML probe now uses AND
# semantics (matching the real base_user_terms fix), so h_pay and h_pay2 deliberately share
# "payment" but differ on "failed"/"declined", to exercise that precision.
CONTROLLED_TEMPLATES = [
	('h_pay', 'payment $ failed for user $'),
	('h_pay2', 'payment declined for account $'),
	('h_login', 'User $ logged in from $'),
	('h_err', 'ERROR $ while processing request $'),
]


def make_config(source_types=('tenx_encoded',), sources=()):
	return {
		'tenx_source_types': list(source_types),
		'tenx_sources': list(sources),
		'dml_source_type': 'tenx_dml_pure',
		'timestamp_placeholder': '__TENX_TS__',
		'variable_separator': '$',
		'tenx_extraction_name': 'REPORT-tenx',
		'tenx_extraction': 'tenx-hash-vars-extraction',
	}


def make_compiler(templates=CONTROLLED_TEMPLATES, config=None, fail_dml=False, truncate_dml=False):
	store = CsvTemplateStore(templates)
	manager = LocalSearchManager(store, fail_dml=fail_dml, truncate_dml=truncate_dml)
	builder = tenx_search_builder.TenxSearchBuilder(
		server_connection=None,
		tenx_config=config or make_config(),
		search_manager=manager)
	return TenxAlertCompiler(builder)


class StubBuilder:
	"""A builder whose build() returns a fixed BuildResult - for pinning compiler policy."""
	def __init__(self, state, resolved, engaged=False, field_terms=None, retryable=False,
				has_search_terms=True, no_dml_results=False, dml_truncated=False,
				tenx_config=None, raises=None):
		self._result = BuildResult(state, resolved, engaged=engaged,
									field_terms=field_terms, retryable=retryable,
									has_search_terms=has_search_terms,
									no_dml_results=no_dml_results,
									dml_truncated=dml_truncated)
		self.tenx_config = tenx_config or make_config()
		self._raises = raises

	def build(self, base_search):
		if self._raises is not None:
			raise self._raises
		return self._result


# ---------------------------------------------------------------------------
# NATIVE: searches on compact data compile to a hash-prefilter + inflate pipeline
# ---------------------------------------------------------------------------

class TestNativeCompile:
	def test_message_type_alert_compiles_to_hash_prefilter(self):
		# "payment failed" probes the DML with AND semantics: only h_pay contains BOTH
		# words (h_pay2 lacks "failed"), so the prefilter is precise, not "every template
		# mentioning payment".
		result = make_compiler().compile('index=main sourcetype=tenx_encoded payment failed')

		assert result.strategy == AlertStrategy.NATIVE
		assert result.storable
		assert not result.needs_review
		# hash prefilter over just h_pay, quoted (real hashes are punctuation-heavy and
		# would otherwise corrupt or break the generated SPL)
		assert 'tenx_hash IN ("h_pay")' in result.compiled_search
		assert '(payment OR failed)' in result.compiled_search
		# expansion is applied and results are re-narrowed to true matches
		assert '`tenx-inflate`' in result.compiled_search
		assert result.compiled_search.endswith('| search payment failed')

	def test_native_output_is_idiomatic_no_leading_pipe(self):
		result = make_compiler().compile('sourcetype=tenx_encoded payment')

		assert result.strategy == AlertStrategy.NATIVE
		# stored form starts with the bare 'search' command, not '| search'
		assert result.compiled_search.startswith('search ')
		assert not result.compiled_search.startswith('| ')

	def test_original_is_preserved_for_recompile(self):
		original = 'sourcetype=tenx_encoded payment failed'
		result = make_compiler().compile(original)

		assert result.original_search == original
		assert result.compiled_search != original

	def test_field_condition_becomes_where_clause(self):
		result = make_compiler().compile('sourcetype=tenx_encoded status=500 payment')

		assert result.strategy == AlertStrategy.NATIVE
		assert '| where status=500' in result.compiled_search

	def test_trailing_pipeline_is_preserved(self):
		result = make_compiler().compile('sourcetype=tenx_encoded payment | stats count')

		assert result.strategy == AlertStrategy.NATIVE
		assert result.compiled_search.rstrip().endswith('| stats count')
		assert '`tenx-inflate`' in result.compiled_search
		# inflate happens before the user's downstream stats
		assert result.compiled_search.index('`tenx-inflate`') < result.compiled_search.index('| stats count')

	def test_quoted_phrase_alert(self):
		result = make_compiler().compile('sourcetype=tenx_encoded "payment failed"')

		assert result.strategy == AlertStrategy.NATIVE
		assert 'tenx_hash IN ("h_pay")' in result.compiled_search

	def test_multi_word_matches_only_templates_with_all_words(self):
		# "payment declined" should resolve to h_pay2 only, not h_pay (which lacks "declined").
		result = make_compiler().compile('sourcetype=tenx_encoded payment declined')

		assert result.strategy == AlertStrategy.NATIVE
		assert 'tenx_hash IN ("h_pay2")' in result.compiled_search


# ---------------------------------------------------------------------------
# B6: a search with no keyword terms at all has no hash prefilter -> full scan
# ---------------------------------------------------------------------------

class TestFieldOnlyFullScanGuard:
	def test_encoded_sourcetype_with_no_terms_is_flagged(self):
		result = make_compiler().compile('sourcetype=tenx_encoded')

		assert result.strategy == AlertStrategy.NATIVE
		assert '`tenx-inflate`' in result.compiled_search
		assert 'tenx_hash IN' not in result.compiled_search  # nothing to prefilter on
		assert result.storable
		assert result.needs_review
		assert 'no keyword search terms' in result.reason

	def test_field_only_alert_is_flagged(self):
		# status=500 alone: a field condition but no keyword term, so no DML probe ever
		# runs and the compiled search scans the whole compact sourcetype every run.
		result = make_compiler().compile('sourcetype=tenx_encoded status=500')

		assert result.strategy == AlertStrategy.NATIVE
		assert 'tenx_hash IN' not in result.compiled_search
		assert result.needs_review
		assert 'no keyword search terms' in result.reason

	def test_keyword_plus_field_is_not_flagged_for_this_reason(self):
		# a search WITH a keyword term still gets a prefilter, so this guard doesn't fire
		# (the string-field-value guard is a separate, unrelated check - see TestFieldValueGuard)
		result = make_compiler().compile('sourcetype=tenx_encoded status=500 payment')

		assert result.strategy == AlertStrategy.NATIVE
		assert not result.needs_review


# ---------------------------------------------------------------------------
# B3: an empty or truncated hash set must not be certified as fully clean
# ---------------------------------------------------------------------------

class TestHashSetIntegrityGuard:
	def test_term_matching_no_template_is_flagged(self):
		# "zzzznomatch" is in no template: no hash clause, but it still runs on compact
		# data so it must be inflated. Since the DML genuinely found nothing, flag it -
		# the alert will only fire on a variable-value match, which may not be the intent.
		result = make_compiler().compile('sourcetype=tenx_encoded zzzznomatch')

		assert result.strategy == AlertStrategy.NATIVE
		assert '`tenx-inflate`' in result.compiled_search
		assert 'tenx_hash IN' not in result.compiled_search
		assert result.storable
		assert result.needs_review
		assert 'no message type currently matches' in result.reason

	def test_truncated_dml_probe_is_flagged(self):
		result = make_compiler(truncate_dml=True).compile('sourcetype=tenx_encoded payment')

		assert result.strategy == AlertStrategy.NATIVE
		assert 'tenx_hash IN' in result.compiled_search  # some hashes were still found
		assert result.storable
		assert result.needs_review
		assert 'more message types than could be fetched' in result.reason

	def test_healthy_match_is_not_flagged(self):
		result = make_compiler().compile('sourcetype=tenx_encoded payment failed')

		assert result.strategy == AlertStrategy.NATIVE
		assert not result.needs_review

	def test_truncated_and_no_results_together_gives_one_coherent_reason(self):
		# no_dml_results and dml_truncated are independent flags and can both be true (the
		# probe can be truncated before it happens to reach a matching row). The two review
		# reasons must not just be concatenated - that reads as "nothing matched" and "too
		# much matched" at once, which is self-contradictory.
		result = make_compiler(truncate_dml=True).compile('sourcetype=tenx_encoded zzzznomatch')

		assert result.strategy == AlertStrategy.NATIVE
		assert 'tenx_hash IN' not in result.compiled_search
		assert result.needs_review
		assert 'no message type currently matches' not in result.reason
		assert 'more message types than could be fetched' not in result.reason
		assert 'truncated before finishing' in result.reason


# ---------------------------------------------------------------------------
# PASSTHROUGH: searches that don't touch compact data are stored unchanged
# ---------------------------------------------------------------------------

class TestPassthrough:
	def test_non_encoded_search_unchanged(self):
		result = make_compiler().compile('index=main error')

		assert result.strategy == AlertStrategy.PASSTHROUGH
		assert result.storable
		assert not result.needs_review
		assert result.compiled_search == 'index=main error'

	def test_bare_term_unchanged(self):
		result = make_compiler().compile('error')

		assert result.strategy == AlertStrategy.PASSTHROUGH
		assert result.compiled_search == 'error'

	def test_passthrough_never_gets_builder_pipe_prefix(self):
		# The builder would munge a passthrough-via-search into '| search ...'; the compiler
		# must store the clean original instead.
		result = make_compiler().compile('sourcetype=web_access error OR warn')

		assert result.strategy == AlertStrategy.PASSTHROUGH
		assert result.compiled_search == 'sourcetype=web_access error OR warn'
		assert not result.compiled_search.startswith('|')


# ---------------------------------------------------------------------------
# Safety net: a passthrough that still names a compact sourcetype is flagged
# ---------------------------------------------------------------------------

class TestPassthroughSafetyNet:
	def test_ambiguous_encoded_search_is_flagged_for_review(self):
		# Mixed sourcetypes defeat the builder's detection -> it passes through unchanged,
		# but the search names tenx_encoded, so it must not be stored blind.
		result = make_compiler().compile('sourcetype=tenx_encoded error OR sourcetype=other')

		assert result.strategy == AlertStrategy.PASSTHROUGH
		assert result.needs_review
		assert 'tenx_encoded' in result.reason

	def test_flags_configured_source_too(self):
		config = make_config(source_types=(), sources=('/var/log/app.log',))
		compiler = make_compiler(config=config)
		# unparseable-for-the-grammar shape degrades to passthrough; it names the source
		result = compiler.compile('source=/var/log/app.log (payment OR host=web1)')

		assert result.strategy == AlertStrategy.PASSTHROUGH
		assert result.needs_review

	def test_clean_non_encoded_passthrough_not_flagged(self):
		result = make_compiler().compile('index=main sourcetype=web_access error')

		assert result.strategy == AlertStrategy.PASSTHROUGH
		assert not result.needs_review


# ---------------------------------------------------------------------------
# COMPLEX -> REJECTED: too-complex searches are not auto-scheduled via a broken fallback
# ---------------------------------------------------------------------------

class TestComplexIsRejected:
	def test_complex_state_is_rejected_not_auto_scheduled(self):
		# ESCAPE_HATCH (auto-generating `| tenxsearch ...`) was retired: tenxsearch re-runs
		# the same builder logic, so a search too complex for this compiler is generally too
		# complex for that command too, and it carries its own cost (a nested proxied job).
		builder = StubBuilder(ResolvedState.COMPLEX, 'irrelevant')
		result = TenxAlertCompiler(builder).compile('sourcetype=tenx_encoded weird OR stuff')

		assert result.strategy == AlertStrategy.REJECTED
		assert not result.storable
		assert result.compiled_search is None
		assert 'tenxsearch' in result.reason  # still named as a manual, human-chosen option

	def test_ambiguous_mixed_sourcetype_via_real_builder_is_passthrough_not_complex(self):
		# The real builder does NOT emit ResolvedState.COMPLEX for this shape; it passes the
		# search through (state SUCCESS, not engaged), and the safety net flags it instead.
		# COMPLEX->REJECTED is a defensive path reachable only if build() ever returns COMPLEX.
		result = make_compiler().compile('sourcetype=tenx_encoded a OR sourcetype=other')

		assert result.strategy == AlertStrategy.PASSTHROUGH
		assert result.state == ResolvedState.SUCCESS
		assert result.needs_review


# ---------------------------------------------------------------------------
# REJECTED: unresolvable searches are never stored
# ---------------------------------------------------------------------------

class TestRejected:
	def test_empty_search_rejected(self):
		result = make_compiler().compile('   ')

		assert result.strategy == AlertStrategy.REJECTED
		assert not result.storable
		assert result.compiled_search is None

	def test_none_search_rejected(self):
		result = make_compiler().compile(None)

		assert result.strategy == AlertStrategy.REJECTED
		assert result.compiled_search is None

	def test_builder_exception_is_contained(self):
		builder = StubBuilder(ResolvedState.SUCCESS, 'x', raises=RuntimeError('boom'))
		result = TenxAlertCompiler(builder).compile('anything')

		assert result.strategy == AlertStrategy.REJECTED
		assert 'boom' in result.reason


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

class TestNormalizeNative:
	def test_strips_leading_search_pipe(self):
		assert _normalize_native(' | search foo | `tenx-inflate`') == 'search foo | `tenx-inflate`'

	def test_leaves_inner_search_pipes(self):
		out = _normalize_native('| search a | `tenx-inflate` | extract | search a')
		assert out == 'search a | `tenx-inflate` | extract | search a'
		assert out.count('| search') == 1  # only the trailing re-narrow remains piped

	def test_does_not_unwrap_generating_command(self):
		# a genuine leading-pipe generating command must be preserved
		assert _normalize_native('| tstats count') == '| tstats count'

	def test_does_not_unwrap_search_prefixed_command(self):
		# a command whose name merely starts with 'search' (e.g. searchtxn) must be preserved
		assert _normalize_native('| searchtxn foo | `tenx-inflate`') == '| searchtxn foo | `tenx-inflate`'
		assert _normalize_native('| searchmatch(x)') == '| searchmatch(x)'


class TestReferencedTenxSources:
	def test_detects_sourcetype_token(self):
		cfg = make_config(source_types=('tenx_encoded',))
		assert _referenced_tenx_sources('sourcetype=tenx_encoded error', cfg) == ['tenx_encoded']

	def test_no_false_positive_on_substring(self):
		cfg = make_config(source_types=('enc',))
		# 'enc' must not match inside 'tenx_encoded'
		assert _referenced_tenx_sources('sourcetype=tenx_encoded error', cfg) == []

	def test_empty_config(self):
		assert _referenced_tenx_sources('sourcetype=tenx_encoded error', None) == []


# ---------------------------------------------------------------------------
# Negation guard: NOT on compact data would be silently dropped -> refuse it
# ---------------------------------------------------------------------------

class TestNegationGuard:
	def test_not_on_compact_search_is_rejected(self):
		# The builder's parser prunes NOT, so `sourcetype=tenx_encoded NOT payment` would
		# otherwise compile to the same thing as the positive search (inverted alert).
		result = make_compiler().compile('sourcetype=tenx_encoded NOT payment')

		assert result.strategy == AlertStrategy.REJECTED
		assert not result.storable
		assert 'NOT' in result.reason

	def test_excluding_term_on_compact_is_rejected(self):
		result = make_compiler().compile('sourcetype=tenx_encoded error NOT healthcheck')
		assert result.strategy == AlertStrategy.REJECTED

	def test_not_sourcetype_form_is_rejected(self):
		# would otherwise inflate the very sourcetype the user asked to exclude
		result = make_compiler().compile('NOT sourcetype=tenx_encoded error')
		assert result.strategy == AlertStrategy.REJECTED

	def test_not_on_non_compact_search_is_fine(self):
		# Splunk handles NOT natively off compact data; don't over-reject.
		result = make_compiler().compile('index=main error NOT healthcheck')
		assert result.strategy == AlertStrategy.PASSTHROUGH
		assert result.compiled_search == 'index=main error NOT healthcheck'

	def test_literal_not_in_quotes_is_not_negation(self):
		assert _has_negation('sourcetype=tenx_encoded "404 NOT FOUND"') is False
		assert _has_negation('sourcetype=tenx_encoded NOT payment') is True
		assert _has_negation('sourcetype=tenx_encoded not_a_field=1') is False


# ---------------------------------------------------------------------------
# Field-value guard: a string-valued field condition -> `| where` matches nothing
# ---------------------------------------------------------------------------

class TestFieldValueGuard:
	def test_string_field_value_flagged_for_review(self):
		result = make_compiler().compile('sourcetype=tenx_encoded payment level=error')

		assert result.strategy == AlertStrategy.NATIVE
		assert result.needs_review
		assert 'level=error' in result.reason

	def test_numeric_field_value_not_flagged(self):
		result = make_compiler().compile('sourcetype=tenx_encoded payment status=500')

		assert result.strategy == AlertStrategy.NATIVE
		assert not result.needs_review

	def test_quoted_field_value_not_flagged(self):
		result = make_compiler().compile('sourcetype=tenx_encoded payment level="error"')

		assert result.strategy == AlertStrategy.NATIVE
		assert not result.needs_review

	def test_helper_classifies_values(self):
		assert _stringy_field_terms(['status=500']) == []
		assert _stringy_field_terms(['level="error"']) == []
		assert _stringy_field_terms(['level=error']) == ['level=error']
		assert _stringy_field_terms(['code>=400']) == []
		assert _stringy_field_terms(['host IN (web1,web2)']) == ['host IN (web1,web2)']


# ---------------------------------------------------------------------------
# RETRYABLE: a transient DML lookup failure must not drop a live alert
# ---------------------------------------------------------------------------

class TestRetryable:
	def test_transient_dml_failure_is_retryable_not_rejected(self):
		result = make_compiler(fail_dml=True).compile('sourcetype=tenx_encoded payment failed')

		assert result.strategy == AlertStrategy.RETRYABLE
		assert not result.storable          # don't overwrite a live alert with a broken one
		assert result.compiled_search is None
		assert result.state == ResolvedState.FAILURE
		assert 'retry' in result.reason.lower()

	def test_permanent_failure_is_rejected_via_stub(self):
		# an unparseable search (build returns FAILURE, retryable False) is REJECTED, not retried
		builder = StubBuilder(ResolvedState.FAILURE, 'x', retryable=False)
		result = TenxAlertCompiler(builder).compile('anything')
		assert result.strategy == AlertStrategy.REJECTED


# ---------------------------------------------------------------------------
# Glob-aware safety net: sourcetype=tenx_* must still be caught
# ---------------------------------------------------------------------------

class TestGlobAwareSafetyNet:
	def test_wildcard_sourcetype_is_flagged(self):
		# 'tenx_*' evades the builder's exact-match detection -> passthrough; the net must
		# still recognise that it selects the compact sourcetype.
		result = make_compiler().compile('sourcetype=tenx_* payment')

		assert result.strategy == AlertStrategy.PASSTHROUGH
		assert result.needs_review

	def test_specifier_extraction(self):
		assert _specifier_values('sourcetype=tenx_encoded error') == ['tenx_encoded']
		assert _specifier_values('sourcetype="tenx encoded" x') == ['tenx encoded']
		assert _specifier_values('source=/var/log/a.log y') == ['/var/log/a.log']
		# exclusion is not a target
		assert _specifier_values('sourcetype!=tenx_encoded error') == []

	def test_glob_matches_configured_name(self):
		cfg = make_config(source_types=('tenx_encoded',))
		assert _referenced_tenx_sources('sourcetype=tenx_* x', cfg) == ['tenx_encoded']
		assert _referenced_tenx_sources('sourcetype=web_* x', cfg) == []


# ---------------------------------------------------------------------------
# The DML double approximates Splunk segmentation (whole tokens, AND semantics)
# ---------------------------------------------------------------------------

class TestDmlDoubleTokenMatching:
	def test_substring_does_not_match_token(self):
		# "count" must not resolve the "account" template (a substring but not a token).
		templates = [('h_acct', 'account $ created'), ('h_pay', 'payment $ failed')]
		store = CsvTemplateStore(templates)
		assert store.matching_hashes('count') == []
		assert store.matching_hashes('account') == ['h_acct']

	def test_trailing_wildcard_matches_prefix(self):
		store = CsvTemplateStore([('h_pay', 'payment $ failed')])
		assert store.matching_hashes('pay*') == ['h_pay']
		assert store.matching_hashes('zzz*') == []

	def test_and_semantics_require_all_words(self):
		store = CsvTemplateStore(CONTROLLED_TEMPLATES)
		# both words present only in h_pay
		assert store.matching_hashes('payment failed') == ['h_pay']
		# both words present only in h_pay2
		assert store.matching_hashes('payment declined') == ['h_pay2']
		# "payment" alone matches both
		assert store.matching_hashes('payment') == ['h_pay', 'h_pay2']


# ---------------------------------------------------------------------------
# resolve() still behaves as before now that it delegates to build()
# ---------------------------------------------------------------------------

class TestBuilderResolveContract:
	def _builder(self, fail_dml=False):
		store = CsvTemplateStore(CONTROLLED_TEMPLATES)
		manager = LocalSearchManager(store, fail_dml=fail_dml)
		return tenx_search_builder.TenxSearchBuilder(
			server_connection=None, tenx_config=make_config(), search_manager=manager)

	def test_resolve_matches_build_output(self):
		builder = self._builder()
		search = 'sourcetype=tenx_encoded payment failed'
		built = builder.build(search)
		assert builder.resolve(search) == built.resolved

	def test_resolve_swallows_errors_to_message_macro(self):
		# build() surfaces exceptions; resolve() keeps its historical catch-all.
		builder = self._builder()

		def boom(_):
			raise RuntimeError('kaboom')

		builder.build = boom
		out = builder.resolve('anything')
		assert out == '`tenx-message(Failed building tenx search)`'

	def test_build_returns_failure_state_on_dml_error(self):
		builder = self._builder(fail_dml=True)
		result = builder.build('sourcetype=tenx_encoded payment failed')
		assert result.state == ResolvedState.FAILURE
		assert result.retryable is True

	def test_build_engaged_and_field_terms_exposed(self):
		builder = self._builder()
		engaged = builder.build('sourcetype=tenx_encoded status=500 payment')
		assert engaged.engaged is True
		assert 'status=500' in engaged.field_terms
		assert engaged.has_search_terms is True

		plain = builder.build('index=main error')
		assert plain.engaged is False
		assert plain.field_terms == []

	def test_build_exposes_no_dml_results_and_has_search_terms(self):
		builder = self._builder()

		no_match = builder.build('sourcetype=tenx_encoded zzzznomatch')
		assert no_match.no_dml_results is True
		assert no_match.has_search_terms is True

		field_only = builder.build('sourcetype=tenx_encoded status=500')
		assert field_only.has_search_terms is False

	def test_build_exposes_dml_truncated(self):
		store = CsvTemplateStore(CONTROLLED_TEMPLATES)
		manager = LocalSearchManager(store, truncate_dml=True)
		builder = tenx_search_builder.TenxSearchBuilder(
			server_connection=None, tenx_config=make_config(), search_manager=manager)

		result = builder.build('sourcetype=tenx_encoded payment')
		assert result.dml_truncated is True


# ---------------------------------------------------------------------------
# Integration: compile against the real demo template CSV
# ---------------------------------------------------------------------------

class TestDemoCsvIntegration:
	@pytest.fixture
	def compiler(self):
		assert os.path.exists(DEMO_TEMPLATES_CSV), "demo template CSV missing"
		store = CsvTemplateStore.from_csv(DEMO_TEMPLATES_CSV)
		manager = LocalSearchManager(store)
		builder = tenx_search_builder.TenxSearchBuilder(
			server_connection=None, tenx_config=make_config(), search_manager=manager)
		return TenxAlertCompiler(builder)

	def test_known_demo_word_compiles_native_with_hashes(self, compiler):
		# "binding" appears in several SLF4J demo templates.
		result = compiler.compile('sourcetype=tenx_encoded binding')

		assert result.strategy == AlertStrategy.NATIVE
		assert 'tenx_hash IN (' in result.compiled_search
		assert '`tenx-inflate`' in result.compiled_search

	def test_absent_word_compiles_native_flagged(self, compiler):
		result = compiler.compile('sourcetype=tenx_encoded zzz_not_in_any_template_zzz')

		assert result.strategy == AlertStrategy.NATIVE
		assert 'tenx_hash IN' not in result.compiled_search
		assert '`tenx-inflate`' in result.compiled_search
		assert result.needs_review
