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
	def test_replaces_search_with_compiled_and_stashes_original(self):
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
		# the human original is stashed for later recompilation
		assert data[tenx_alert_persist.ORIGINAL_SEARCH_KEY] == 'sourcetype=tenx_encoded payment failed'
		# alert attributes are forwarded verbatim
		assert data['cron_schedule'] == '*/5 * * * *'
		assert data['alert_type'] == 'number of events'

	def test_control_keys_are_not_forwarded_as_attributes(self):
		form = {'search': 'x', 'name': 'A', 'confirm': 'true', 'method': 'POST', 'output_mode': 'json'}
		result = _result(AlertStrategy.NATIVE, compiled='C', original='x')

		data = tenx_alert_persist.build_saved_search_data(form, result)

		# name identifies the stanza (URL for update / added by handler for create) - not an attribute
		assert 'name' not in data
		assert 'confirm' not in data
		assert 'method' not in data
		assert 'output_mode' not in data
