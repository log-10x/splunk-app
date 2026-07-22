"""
Offline tests for the /tenx-alert handler's write ORCHESTRATION - specifically the atomicity /
ordering guarantees the adversarial review flagged as HIGH. A mock connection records the exact
sequence of REST calls the handler makes and can inject a failure on a chosen endpoint, which is
what actually determines whether a partial failure loses the human original or misreports the
outcome. (The happy-path behaviour is separately verified live on Splunk.)
"""
import json
import urllib.error

import pytest

import tenx_alert_handler
import tenx_alert_persist
from tenx_alert_compiler import AlertStrategy, AlertCompileResult

CONF = 'configs/conf-savedsearches'   # metadata (original + fingerprint) writes land here
SAVED = 'saved/searches'              # the compiled-search write lands here


class MockConn:
	"""Records every REST call; raises HTTPError 503 on any URL containing `fail_on`."""
	def __init__(self, entries=None, fail_on=None):
		self.user = 'admin'
		self._entries = entries or []
		self.fail_on = fail_on
		self.calls = []  # list of (verb, url[, data])

	def get(self, url, params=None):
		self.calls.append(('GET', url))
		return {'entry': self._entries}

	def post(self, url, data):
		self.calls.append(('POST', url, data))
		if self.fail_on and self.fail_on in url:
			raise urllib.error.HTTPError(url, 503, 'injected failure', {}, None)
		return {}

	def posts_to(self, needle):
		return [c for c in self.calls if c[0] == 'POST' and needle in c[1]]

	def first_post_index(self, needle):
		for i, c in enumerate(self.calls):
			if c[0] == 'POST' and needle in c[1]:
				return i
		return None


class FakeCompiler:
	def __init__(self, result):
		self._result = result

	def compile(self, source):
		return self._result


def _stanza(name, search, original='', compiled=''):
	return {'name': name, 'content': {
		'search': search,
		tenx_alert_persist.ORIGINAL_SEARCH_KEY: original,
		tenx_alert_persist.COMPILED_SEARCH_KEY: compiled,
	}}


def _handler():
	return tenx_alert_handler.TenxAlertHandler(None, None)


# ---------------------------------------------------------------------------
# recompile_all: write-ORDERING + no-data-loss on partial failure
# ---------------------------------------------------------------------------

class TestRecompileOrdering:
	def test_metadata_is_written_before_the_search(self):
		conn = MockConn(entries=[_stanza('a', '| tenxsearch searchstring="sourcetype=tenx_encoded x"')])
		result = AlertCompileResult(AlertStrategy.NATIVE, 'search NATIVE x', 'sourcetype=tenx_encoded x')

		_handler().recompile_all(conn, 'admin', FakeCompiler(result))

		meta_at = conn.first_post_index(CONF)
		search_at = conn.first_post_index(SAVED)
		assert meta_at is not None and search_at is not None
		# the original must be persisted BEFORE the (destructive) search overwrite
		assert meta_at < search_at

	def test_legacy_search_write_failure_preserves_the_original(self):
		# migrating a legacy alert: the original lives only in the | tenxsearch body we overwrite.
		conn = MockConn(
			entries=[_stanza('a', '| tenxsearch searchstring="sourcetype=tenx_encoded x"')],
			fail_on=SAVED)  # the compiled-search write fails
		result = AlertCompileResult(AlertStrategy.NATIVE, 'search NATIVE x', 'sourcetype=tenx_encoded x')

		summary = _handler().recompile_all(conn, 'admin', FakeCompiler(result))

		# the metadata write (with the human original) landed BEFORE the failing search write
		meta_posts = conn.posts_to(CONF)
		assert meta_posts, "the human original was never stashed - it would be lost"
		assert meta_posts[0][2][tenx_alert_persist.ORIGINAL_SEARCH_KEY] == 'sourcetype=tenx_encoded x'
		# the failure is counted, nothing is falsely reported as migrated
		assert summary['errors'] == 1
		assert summary['migrated'] == 0
		assert summary['updated'] == []

	def test_metadata_write_failure_does_not_touch_the_search(self):
		# if the metadata write itself fails, the destructive search write must not run.
		conn = MockConn(
			entries=[_stanza('a', '| tenxsearch searchstring="sourcetype=tenx_encoded x"')],
			fail_on=CONF)
		result = AlertCompileResult(AlertStrategy.NATIVE, 'search NATIVE x', 'sourcetype=tenx_encoded x')

		summary = _handler().recompile_all(conn, 'admin', FakeCompiler(result))

		assert conn.posts_to(SAVED) == []  # legacy body left intact, still functional
		assert summary['errors'] == 1


class TestRecompileDecisions:
	def test_drifted_alert_is_skipped_and_never_written(self):
		# an operator hand-edited a search we compiled -> live != stored fingerprint
		conn = MockConn(entries=[_stanza('a', 'search NATIVE x | head 5', original='sourcetype=tenx_encoded x', compiled='search NATIVE x')])
		result = AlertCompileResult(AlertStrategy.NATIVE, 'search NATIVE x', 'sourcetype=tenx_encoded x')

		summary = _handler().recompile_all(conn, 'admin', FakeCompiler(result))

		assert summary['drifted'] == 1
		assert conn.posts_to(SAVED) == [] and conn.posts_to(CONF) == []

	def test_unchanged_alert_is_a_no_op(self):
		conn = MockConn(entries=[_stanza('a', 'search NATIVE x', original='sourcetype=tenx_encoded x', compiled='search NATIVE x')])
		result = AlertCompileResult(AlertStrategy.NATIVE, 'search NATIVE x', 'sourcetype=tenx_encoded x')

		summary = _handler().recompile_all(conn, 'admin', FakeCompiler(result))

		assert summary['unchanged'] == 1
		assert conn.posts_to(SAVED) == [] and conn.posts_to(CONF) == []

	def test_happy_migration_writes_metadata_then_search(self):
		conn = MockConn(entries=[_stanza('a', '| tenxsearch searchstring="sourcetype=tenx_encoded x"')])
		result = AlertCompileResult(AlertStrategy.NATIVE, 'search NATIVE x', 'sourcetype=tenx_encoded x')

		summary = _handler().recompile_all(conn, 'admin', FakeCompiler(result))

		assert summary['migrated'] == 1 and summary['updated'] == ['a']
		assert conn.first_post_index(CONF) < conn.first_post_index(SAVED)


# ---------------------------------------------------------------------------
# APPLY path: a metadata-only failure is reported honestly (applied=true), not as applied=false
# ---------------------------------------------------------------------------

class TestApplyPartialFailure(object):
	def _in_string(self, form_pairs):
		return json.dumps({
			'method': 'POST',
			'server': {'rest_uri': 'https://localhost:8089'},
			'session': {'authtoken': 't', 'user': 'admin'},
			'form': [list(p) for p in form_pairs],
		})

	def test_metadata_failure_after_search_reports_applied_true_with_warning(self, monkeypatch):
		result = AlertCompileResult(AlertStrategy.PASSTHROUGH, 'index=_internal error', 'index=_internal error')
		monkeypatch.setattr(tenx_alert_compiler_module(), 'TenxAlertCompiler', lambda builder: FakeCompiler(result))
		monkeypatch.setattr(tenx_alert_handler.tenx_util, 'get_tenx_config', lambda **k: {})
		conn = MockConn(fail_on=CONF)  # search write ok, metadata write fails
		monkeypatch.setattr(tenx_alert_handler.tenx_util, 'ServerConnection', lambda **k: conn)

		out = _handler().handle(self._in_string([('search', 'index=_internal error'), ('name', 'n')]))
		payload = out['payload']

		assert out['status'] == 200
		assert payload['applied'] is True         # the alert IS live - do not misreport as false
		assert 'metadata_error' in payload        # the stash failure is surfaced (value is Splunk's message)
		assert payload.get('saved_search') in ('created', 'updated')
		assert conn.posts_to(SAVED)               # the search was actually written


def tenx_alert_compiler_module():
	import tenx_alert_compiler
	return tenx_alert_compiler
