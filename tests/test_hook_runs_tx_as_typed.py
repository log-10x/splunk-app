"""
The dashboard hook (the tenx-search endpoint dashboard.js routes every panel's search through):
a search that calls `tx` or `txf` is created as typed, so the macro's prefilter reads its own words
and its stops run as they do from the search bar; and when splunkd refuses a job (txf(<sourcetype>)
without a field replay unit fails the macro's validation), the panel gets splunkd's message, not
HTTP 500 "Missing sid in job creation result". Splunk Enterprise 10.4.3, before: `index=x
sourcetype=<original> \\`tx\\`` through the hook ran rewritten and returned 0 events with no message;
`txf(fr:none)` gave HTTP 500 "argument of type 'NoneType' is not iterable".
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

CHILD = r'''
import io, json, os, sys, types, urllib.error
root, home = sys.argv[1], sys.argv[2]
os.makedirs(os.path.join(home, 'var', 'log', 'splunk'), exist_ok=True)
os.environ['SPLUNK_HOME'] = home
splunk = types.ModuleType('splunk'); persist = types.ModuleType('splunk.persistconn')
app = types.ModuleType('splunk.persistconn.application')
class Base(object):
	def __init__(self, *a): pass
app.PersistentServerConnectionApplication = Base
clilib = types.ModuleType('splunk.clilib'); bp = types.ModuleType('splunk.clilib.bundle_paths')
bp.get_base_path = lambda: root; clilib.bundle_paths = bp
sys.modules.update({'splunk': splunk, 'splunk.persistconn': persist, 'splunk.persistconn.application': app,
					'splunk.clilib': clilib, 'splunk.clilib.bundle_paths': bp})
sys.path.insert(0, os.path.join(root, 'tenx-for-splunk', 'lib'))
sys.path.insert(0, os.path.join(root, 'tenx-for-splunk', 'bin'))
sys.path.insert(0, os.path.join(root, 'tests'))
import tenx_util, tenx_search_handler
from test_tenx_alert_compiler import make_config
TEXT = "Error in 'SearchParser': Encountered the following error while validating macro 'txf(fr:none)': no unit."
posted = []
class Conn(object):
	def __init__(self, **kw): self.user = kw.get('user')
	def post(self, url, data=None, **kw):
		posted.append((url, dict(data) if isinstance(data, dict) else data))
		if url.endswith('/search/jobs/') and 'txf(fr:none)' in data['search']:
			raise urllib.error.HTTPError(url, 400, 'Bad Request', {}, io.BytesIO(json.dumps(
				{'messages': [{'type': 'ERROR', 'text': TEXT}]}).encode()))
		if url.endswith('/search/jobs/'):
			return {'sid': 'sid-1'}
		raise AssertionError('unexpected call %s' % url)
tenx_util.ServerConnection = Conn
config = make_config(); config[tenx_util.CONFIG_LOADED] = True
tenx_util.get_tenx_config = lambda **kw: config
def call(search):
	del posted[:]
	req = {'method': 'POST', 'server': {'rest_uri': 'https://127.0.0.1:8089'}, 'session': {'authtoken': 't', 'user': 'admin'},
		   'ns': {'app': 'tenx-for-splunk'}, 'form': [['search', search], ['earliest_time', '0'], ['latest_time', 'now']]}
	out = tenx_search_handler.TenxSearchHandler(None, None).handle(json.dumps(req))
	return {'out': out, 'posted': [(u.rsplit('/', 3)[-3] + '/' + u.rsplit('/', 3)[-2], d.get('search') if isinstance(d, dict) else None) for u, d in posted]}
print(json.dumps({'tx': call('search index=x sourcetype=fr:old `tx` | stats count'),
				  'txf': call('search index=x `txf` error'),
				  'nounit': call('search index=x `txf(fr:none)` | stats count')}))
'''


def test_tx_searches_run_as_typed_and_refusals_carry_splunkds_message():
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', CHILD, ROOT, home], capture_output=True, text=True, timeout=120)
	assert proc.returncode == 0, proc.stderr[-3000:]
	out = json.loads(proc.stdout.strip().splitlines()[-1])
	# no parse, no rewrite: the one job, with the search as typed
	assert out['tx']['out'] == {'payload': {'sid': 'sid-1'}, 'status': 200}
	assert out['tx']['posted'] == [['search/jobs', 'search index=x sourcetype=fr:old `tx` | stats count']]
	assert out['txf']['posted'] == [['search/jobs', 'search index=x `txf` error']]
	assert out['nounit']['out'] == {'payload': {'messages': [{'type': 'FATAL', 'text': (
		"Error in 'SearchParser': Encountered the following error while validating macro 'txf(fr:none)': no unit.")}]},
		'status': 400}
