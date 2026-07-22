"""
Unit tests for tenx_alert_persist - the offline decision + payload logic behind the
/tenx-alert handler. No Splunk connection is exercised; the handler's actual saved/searches
write is verified live (see SAVE_TIME_ALERTS.md), not here.
"""
import tenx_alert_persist
from tenx_alert_compiler import AlertStrategy, AlertCompileResult


def _result(strategy, compiled='compiled spl', original='human spl', needs_review=False, reason=None):
	return AlertCompileResult(
		strategy=strategy,
		compiled_search=compiled,
		original_search=original,
		needs_review=needs_review,
		reason=reason)


class TestDecide:
	def test_rejected_is_not_applied(self):
		decision = tenx_alert_persist.decide(_result(AlertStrategy.REJECTED, compiled=None, reason='NOT on compact data'))

		assert decision.action == tenx_alert_persist.REJECT
		assert decision.status == 422
		assert decision.applied is False
		assert decision.payload['applied'] is False
		assert decision.payload['strategy'] == 'REJECTED'
		assert decision.payload['reason'] == 'NOT on compact data'

	def test_retryable_is_not_applied(self):
		decision = tenx_alert_persist.decide(_result(AlertStrategy.RETRYABLE, reason='DML lookup timed out'))

		assert decision.action == tenx_alert_persist.RETRY
		assert decision.status == 503
		assert decision.applied is False
		assert decision.payload['applied'] is False

	def test_clean_native_is_applied(self):
		decision = tenx_alert_persist.decide(_result(AlertStrategy.NATIVE))

		assert decision.action == tenx_alert_persist.APPLY
		assert decision.status == 200
		assert decision.applied is True
		assert decision.payload['applied'] is True
		assert decision.payload['compiled_search'] == 'compiled spl'

	def test_clean_passthrough_is_applied(self):
		decision = tenx_alert_persist.decide(_result(AlertStrategy.PASSTHROUGH))

		assert decision.action == tenx_alert_persist.APPLY
		assert decision.applied is True

	def test_needs_review_without_confirm_is_held(self):
		decision = tenx_alert_persist.decide(
			_result(AlertStrategy.NATIVE, needs_review=True, reason='full sourcetype scan'),
			confirm=False)

		assert decision.action == tenx_alert_persist.REVIEW
		assert decision.status == 200
		assert decision.applied is False
		assert decision.payload['applied'] is False
		assert decision.payload['needs_review'] is True
		assert decision.payload['reason'] == 'full sourcetype scan'
		# the candidate is still returned so a human can inspect it
		assert decision.payload['compiled_search'] == 'compiled spl'

	def test_needs_review_with_confirm_is_applied(self):
		decision = tenx_alert_persist.decide(
			_result(AlertStrategy.NATIVE, needs_review=True, reason='full sourcetype scan'),
			confirm=True)

		assert decision.action == tenx_alert_persist.APPLY
		assert decision.applied is True
		assert decision.payload['applied'] is True

	def test_confirm_does_not_apply_a_rejected_result(self):
		# confirm only overrides needs_review; it must never turn a REJECTED into an apply
		decision = tenx_alert_persist.decide(_result(AlertStrategy.REJECTED, compiled=None), confirm=True)

		assert decision.action == tenx_alert_persist.REJECT
		assert decision.applied is False

	def test_confirm_does_not_apply_a_retryable_result(self):
		decision = tenx_alert_persist.decide(_result(AlertStrategy.RETRYABLE), confirm=True)

		assert decision.action == tenx_alert_persist.RETRY
		assert decision.applied is False


class TestBuildSavedSearchData:
	def test_replaces_search_with_compiled_and_forwards_attrs(self):
		form = {
			'search': 'sourcetype=tenx_encoded payment failed',
			'name': 'Payment failures',
			'confirm': 'true',
			'method': 'POST',
			'cron_schedule': '*/5 * * * *',
			'alert_type': 'number of events',
		}
		result = _result(AlertStrategy.NATIVE, compiled='COMPILED', original='sourcetype=tenx_encoded payment failed')

		data = tenx_alert_persist.build_saved_search_data(form, result)

		# compiled SPL replaces the human search
		assert data['search'] == 'COMPILED'
		# alert attributes are forwarded verbatim
		assert data['cron_schedule'] == '*/5 * * * *'
		assert data['alert_type'] == 'number of events'

	def test_original_is_not_a_saved_search_attribute(self):
		# the saved/searches EAI endpoint rejects unknown args, so the human original must NOT
		# ride along in this payload - it is written separately via configs/conf-savedsearches
		form = {'search': 'human', 'name': 'A'}
		result = _result(AlertStrategy.NATIVE, compiled='C', original='human')

		data = tenx_alert_persist.build_saved_search_data(form, result)

		assert tenx_alert_persist.ORIGINAL_SEARCH_KEY not in data

	def test_control_keys_are_not_forwarded_as_attributes(self):
		form = {'search': 'x', 'name': 'A', 'confirm': 'true', 'method': 'POST', 'output_mode': 'json'}
		result = _result(AlertStrategy.NATIVE, compiled='C', original='x')

		data = tenx_alert_persist.build_saved_search_data(form, result)

		# name identifies the stanza (URL for update / added by handler for create) - not an attribute
		assert 'name' not in data
		assert 'confirm' not in data
		assert 'method' not in data
		assert 'output_mode' not in data


class TestBuildTenxMetadata:
	def test_stashes_original_and_fingerprint(self):
		data = tenx_alert_persist.build_tenx_metadata('sourcetype=tenx_encoded payment', 'search ... | `tenx-inflate`')

		assert data == {
			tenx_alert_persist.ORIGINAL_SEARCH_KEY: 'sourcetype=tenx_encoded payment',
			tenx_alert_persist.COMPILED_SEARCH_KEY: 'search ... | `tenx-inflate`',
		}


class TestIsDrifted:
	C = tenx_alert_persist.COMPILED_SEARCH_KEY

	def test_live_search_matches_fingerprint_is_not_drift(self):
		stanza = {'search': 'search X | `tenx-inflate`', self.C: 'search X | `tenx-inflate`'}

		assert tenx_alert_persist.is_drifted(stanza) is False

	def test_live_search_differs_from_fingerprint_is_drift(self):
		# an operator hand-edited a search we previously compiled
		stanza = {'search': 'search X | `tenx-inflate` | head 5', self.C: 'search X | `tenx-inflate`'}

		assert tenx_alert_persist.is_drifted(stanza) is True

	def test_no_fingerprint_is_not_drift(self):
		# a legacy | tenxsearch alert (never compiled) must be migratable, not treated as drift
		stanza = {'search': '| tenxsearch searchstring="x"', self.C: ''}

		assert tenx_alert_persist.is_drifted(stanza) is False


class TestRecompileSource:
	K = tenx_alert_persist.ORIGINAL_SEARCH_KEY

	def test_stored_original_is_the_source(self):
		stanza = {'name': 'a', 'search': 'search ... | `tenx-inflate`', self.K: 'sourcetype=tenx_encoded payment'}

		assert tenx_alert_persist.recompile_source(stanza) == 'sourcetype=tenx_encoded payment'

	def test_legacy_tenxsearch_searchstring_is_the_source(self):
		stanza = {'name': 'a', 'search': '| tenxsearch searchstring="sourcetype=tenx_encoded error"', self.K: ''}

		assert tenx_alert_persist.recompile_source(stanza) == 'sourcetype=tenx_encoded error'

	def test_tenxsearch_searchstring_is_unescaped(self):
		stanza = {'name': 'a', 'search': r'| tenxsearch searchstring="host=\"web1\" AND path=\\x"', self.K: ''}

		assert tenx_alert_persist.recompile_source(stanza) == r'host="web1" AND path=\x'

	def test_stored_original_wins_over_a_tenxsearch_body(self):
		stanza = {'name': 'a', 'search': '| tenxsearch searchstring="something else"', self.K: 'sourcetype=tenx_encoded payment'}

		assert tenx_alert_persist.recompile_source(stanza) == 'sourcetype=tenx_encoded payment'

	def test_unmanaged_saved_search_returns_none(self):
		stanza = {'name': 'a', 'search': 'index=main error | stats count', self.K: ''}

		assert tenx_alert_persist.recompile_source(stanza) is None

	def test_is_legacy_tenxsearch(self):
		legacy = {'name': 'a', 'search': '| tenxsearch searchstring="x"', self.K: ''}
		migrated = {'name': 'a', 'search': 'search x | `tenx-inflate`', self.K: 'x'}
		plain = {'name': 'a', 'search': 'index=main error', self.K: ''}

		assert tenx_alert_persist.is_legacy_tenxsearch(legacy) is True
		assert tenx_alert_persist.is_legacy_tenxsearch(migrated) is False
		assert tenx_alert_persist.is_legacy_tenxsearch(plain) is False
