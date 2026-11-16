"""
A search splunkd itself refuses to parse (a macro whose validation fails, such as txf(<sourcetype>)
for a sourcetype without a field replay unit, or an unknown command) reaches the rewrite paths as an
HTTP 400 from the search parser endpoint. Before this, the search manager returned None, the builder
read `'commands' in None`, and the dashboard hook answered HTTP 500 "argument of type 'NoneType' is
not iterable" (Splunk Enterprise 10.4.3): the panel showed that instead of Splunk's own message.
Now splunkd's message is kept and passed on: the hook refuses with it (HTTP 400, the shape of
splunkd's own job rejection), `| tenxsearch` stops with it, and a compiled alert is rejected with it.
"""
import io
import urllib.error

import tenx_search_builder as sb
import tenx_search_manager as sm
from support.local_search_manager import CsvTemplateStore, LocalSearchManager
from tenx_alert_compiler import AlertStrategy, TenxAlertCompiler
from test_tenx_alert_compiler import CONTROLLED_TEMPLATES, make_config

TEXT = ("Error in 'SearchParser': Encountered the following error while validating macro 'txf(fr:none)': txf takes "
		"one original sourcetype, without quotes (letters, digits and _ . : / -), that has a field replay.")


def refused(body=b'{"messages":[{"type":"ERROR","text":"%s","help":""}]}' % TEXT.encode()):
	return urllib.error.HTTPError('https://localhost:8089/servicesNS/admin/search/search/parser', 400, 'Bad Request',
								  {}, io.BytesIO(body))


class RefusingConnection:
	user = 'admin'

	def __init__(self, body=None):
		self.body = body

	def post(self, url, data=None, **kwargs):
		raise refused() if self.body is None else refused(self.body)


class RefusingManager(LocalSearchManager):
	"""splunkd's search parser refusing every search, as the real manager reports it."""

	def parse_search_string(self, search, parse_only=False):
		self.last_parse_error = TEXT
		return None


def test_the_manager_keeps_splunkds_message():
	manager = sm.TenxSearchManager(RefusingConnection(), make_config())
	assert manager.parse_search_string('search index=fr_j `txf(fr:none)`') is None
	assert manager.last_parse_error == TEXT
	# a reply without messages: nothing to pass on
	manager = sm.TenxSearchManager(RefusingConnection(b'not json'), make_config())
	assert manager.parse_search_string('search x') is None and manager.last_parse_error is None


def builder():
	return sb.TenxSearchBuilder(server_connection=None, tenx_config=make_config(),
								search_manager=RefusingManager(CsvTemplateStore(CONTROLLED_TEMPLATES)))


def test_the_builder_passes_it_on():
	got = builder().build('search index=fr_j `txf(fr:none)` | stats count')
	assert got.state == sb.ResolvedState.FAILURE and not got.retryable
	assert got.parse_error == TEXT


def test_a_compiled_alert_is_rejected_with_it():
	got = TenxAlertCompiler(builder()).compile('index=fr_j `txf(fr:none)` | stats count')
	assert got.strategy == AlertStrategy.REJECTED and got.reason == TEXT


def test_a_search_splunkd_parses_has_none():
	manager = LocalSearchManager(CsvTemplateStore(CONTROLLED_TEMPLATES))
	got = sb.TenxSearchBuilder(server_connection=None, tenx_config=make_config(), search_manager=manager).build(
		'search index=main error')
	assert got.parse_error is None
