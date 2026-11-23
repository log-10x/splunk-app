"""
The README's limit sentence for the `tx` and `tenxsearch` commands, the values the live check
(tests/live_tx_command_cr.py) asserts, and the probe it installs must agree. The live check pins
what Splunk does; this pins that the sentence still says the same, and that the probe stays out of
the app package.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROBE = os.path.join(HERE, 'support', 'tx_cr_probe')
sys.path.insert(0, os.path.join(PROBE, 'bin'))

import tenx_cr_cases  # noqa: E402


def readme():
	with open(os.path.join(ROOT, 'tenx-for-splunk', 'README.md')) as f:
		return f.read()


def test_the_readme_states_the_limit_under_the_commands_paragraph():
	text = readme()
	assert tenx_cr_cases.README_SENTENCE in ' '.join(text.split())
	paragraph = text[text.index('**The `tx` and `tenxsearch` commands.**'):]
	paragraph = paragraph[:paragraph.index('\n\n')]
	assert tenx_cr_cases.README_SENTENCE in ' '.join(paragraph.split())


def test_every_measured_value_follows_the_sentence():
	for case, written, read_back in tenx_cr_cases.CASES:
		assert tenx_cr_cases.as_read_back(written) == read_back, case


def test_the_cases_cover_each_clause_of_the_sentence():
	by_case = {case: (written, read_back) for case, written, read_back in tenx_cr_cases.CASES}
	written, read_back = by_case['crlf']
	assert '\r\n' in written and '\r' not in read_back and read_back.count('\n') == written.count('\n')
	written, read_back = by_case['endcr']
	assert written.endswith('\r') and read_back == written
	written, read_back = by_case['lonecr']
	assert read_back == written and '\r' in read_back
	written, read_back = by_case['crcr']
	assert written.count('\r') == 2 and read_back.count('\r') == 1


def test_the_probe_writes_exactly_the_cases_and_is_not_packaged():
	with open(os.path.join(PROBE, 'bin', 'tenxcrprobe.py')) as f:
		source = f.read()
	assert 'from tenx_cr_cases import CASES' in source and 'for case, value, _ in CASES' in source
	assert not os.path.abspath(PROBE).startswith(os.path.join(ROOT, 'tenx-for-splunk') + os.sep)
	with open(os.path.join(PROBE, 'default', 'commands.conf')) as f:
		assert 'chunked = true' in f.read()


# The command run in a child interpreter with the real vendored splunklib (the suite stubs it, see conftest.py),
# its nested search answered here with each case's value as the event text and as a field of two values.
WRITES = r'''
import json, os, sys, types
root, home = sys.argv[1], sys.argv[2]
os.makedirs(os.path.join(home, 'var', 'log', 'splunk'), exist_ok=True)
os.environ['SPLUNK_HOME'] = home
splunk = types.ModuleType('splunk')
clilib = types.ModuleType('splunk.clilib')
bundle_paths = types.ModuleType('splunk.clilib.bundle_paths')
bundle_paths.get_base_path = lambda: root
clilib.bundle_paths = bundle_paths
splunk.clilib = clilib
sys.modules.update({'splunk': splunk, 'splunk.clilib': clilib, 'splunk.clilib.bundle_paths': bundle_paths})
sys.path.insert(0, os.path.join(root, 'tenx-for-splunk', 'lib'))
sys.path.insert(0, os.path.join(root, 'tenx-for-splunk', 'bin'))
sys.path.insert(0, os.path.join(root, 'tests', 'support', 'tx_cr_probe', 'bin'))

import tx, tenx_util, tenx_search_builder, tenx_search_manager
from tenx_cr_cases import CASES

EVENTS = [{'_raw': value, 'Message': [value, 'two'], 'case': case, '_cd': '1:2'} for case, value, _ in CASES]

class Manager:
	def __init__(self, **kw): pass
	def get_search_job_details(self, sid):
		if sid == 'top':
			return {'request': {'earliest_time': '-1h', 'latest_time': 'now'}}
		return {'eventCount': len(EVENTS), 'reportSearch': ''}
	def create_search_job(self, data): return 'nested'
	def poll_for_job_end(self, *a, **kw): return tenx_search_manager.JobState.SUCCESS
	def is_job_live(self, sid): return True
	def cancel_search_job(self, sid): pass
	def run_probe(self, *a): return []
	def get_search_results(self, sid, params, transformed=False):
		return {'results': [dict(e) for e in EVENTS[params['offset']:params['offset'] + params['count']]]}

class Built:
	state = tenx_search_builder.ResolvedState.SUCCESS
	resolved = '| search index=c sourcetype=tenx_encoded | `tenx-inflate`'
	engaged = True
	retryable = False
	parse_error = None

class Builder:
	def __init__(self, **kw): pass
	def build(self, s): return Built()

tenx_util.get_tenx_config = lambda **kw: {}
tenx_util.ServerConnection = lambda **kw: None
tenx_search_manager.TenxSearchManager = Manager
tenx_search_builder.TenxSearchBuilder = Builder
tenx_search_builder.compact_probe = lambda b, c: (None, None)

cmd = tx.TxCommand()
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	raw_args=['index=c', 'sourcetype=tenx_encoded'], args=[], sid='top', username='admin', app='search',
	splunkd_uri='https://127.0.0.1:8089', session_key='key'))
cmd.write_error = lambda m, *a: None
cmd.write_warning = lambda m, *a: None
print(json.dumps(list(cmd.generate())))
'''


def test_the_commands_write_each_value_so_that_it_reads_back_as_the_event_holds_it():
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', WRITES, ROOT, home], capture_output=True, text=True, timeout=120)
	assert proc.returncode == 0, proc.stderr[-3000:]
	rows = json.loads(proc.stdout.strip().splitlines()[-1])
	assert [r['case'] for r in rows] == [case for case, _, _ in tenx_cr_cases.CASES]
	for row, (case, value, _) in zip(rows, tenx_cr_cases.CASES):
		assert tenx_cr_cases.as_read_back(row['_raw']) == value, case
		assert [tenx_cr_cases.as_read_back(v) for v in row['Message']] == [value, 'two'], case
		assert '_cd' not in row
