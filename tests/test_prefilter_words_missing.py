"""
Compact events indexed without words (SEGMENTATION = none on the compact sourcetype, its source or host).

The prefilter of `tx` and `txf` turns words into index terms of the compact text (TERM(<piece>) OR
TERM(<template hash>)). Indexed without words, a compact event holds none of them, and `tx "<ip>"` returned
0 events where the raw search returned 38,204 (Splunk Enterprise 10.4.3, BOTS v1 FortiGate, 100,000 events).
Every compact event starts with ~ and its template hash, which segmentation indexes as a term starting with
~; one tstats per search counts, by index, host and source, the compact events and those holding such a
term, and the groups where they differ are read whole (ORed into the prefilter). The words are then matched
after expansion. When the check cannot run, every compact event in range is read.
"""
import json
import os
import subprocess
import sys
import tempfile

import pytest

import tenx_prefilter_parser as p

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class TestTheCheck:
	def test_counts_every_compact_event_against_those_holding_a_word(self):
		probe = p.word_index_probe('index=fw sourcetype::tenx_encoded ')
		assert probe.startswith('| tstats count where (index="fw") `tenx-events` by index, host, source')
		assert '`tenx-events` TERM(~*) by index, host, source' in probe
		assert probe.endswith('| where tenx_all > tenx_words')

	def test_every_index_when_none_is_named(self):
		assert p.word_index_probe('').startswith('| tstats count where `tenx-events` by index')

	def test_the_groups_found_are_read_whole(self):
		rows = [{'index': 'fw', 'host': 'a', 'source': 's"1'}]
		assert p.word_index_branch(rows) == '(index="fw" host="a" source="s\\"1")'
		many = [{'index': 'ix%d' % (i % 3), 'host': 'h%d' % i, 'source': 's'} for i in range(300)]
		assert p.word_index_branch(many) == 'index="ix0" OR index="ix1" OR index="ix2"'


GENERATE = r"""
import json, os, sys, types
root, home, answer = sys.argv[1:4]
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
import tenx_prefilter
cmd = tenx_prefilter.TenxPrefilterCommand()
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	sid='subsearch_1794937815.59_1794937816.89', username='admin', earliest_time=0, latest_time=0,
	splunkd_uri='https://127.0.0.1:8089', session_key='key'))
checks, warnings = [], []
def rest(path, data=None, answer_=True, method=None):
	if path.startswith('/services/search/jobs/1794937815.59') and not data:
		return {'entry': [{'content': {'search': 'search index=fw `tx` kerberos | stats count'}}]}
	if data and 'TERM(~*)' in data.get('search', ''):
		checks.append(data['search'])
		if answer == 'fail':
			raise OSError('refused')
		return {'results': json.loads(answer)}
	return {'results': []}
cmd._rest = rest
cmd._store_check = lambda: True
cmd._record_checks = lambda macro: None
cmd._original_sourcetype_rows = lambda tree: ([], '`tx`')
cmd._dictionary = lambda pieces, formats: (dict((x, (1, ['TERM(~h_%s)' % x])) for x in pieces), None)
cmd.write_warning = warnings.append
rows = list(cmd.generate())
print(json.dumps({'rows': rows, 'checks': len(checks), 'warnings': warnings}))
"""


def generate(answer):
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', GENERATE, ROOT, home, answer], capture_output=True, text=True,
							  timeout=60)
	assert proc.returncode == 0, proc.stderr[-3000:]
	return json.loads(proc.stdout.strip().splitlines()[-1])


class TestThePrefilter:
	def test_every_group_holds_words(self):
		out = generate('[]')
		assert out['checks'] == 1 and out['warnings'] == []
		assert out['rows'] == [{'search': '((TERM(kerberos) OR TERM(~h_kerberos)))'}]

	def test_a_group_without_words_is_read_whole(self):
		out = generate(json.dumps([{'index': 'fw', 'host': 'a', 'source': 's'}]))
		assert out['rows'] == [{'search': '(((TERM(kerberos) OR TERM(~h_kerberos))) OR (index="fw" host="a" source="s"))'}]

	def test_no_check_means_every_event(self):
		out = generate('fail')
		assert out['rows'] == [{'search': '(*)'}]
		assert out['warnings'] == ['tx: could not check that the compact events hold words; every compact event in range '
								   'is expanded.']
