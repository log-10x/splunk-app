"""
`| tx <search>` takes its search as its arguments, written the way the search is written on
the original data, and hands it to the same rewrite as `| tenxsearch searchstring="..."`.

These tests load the real vendored splunklib, so they run in a child interpreter: the rest of
the suite replaces splunklib with an offline stub (see conftest.py).
"""

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

CHILD = r'''
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

import tx
import tenx_util

def command(raw_args):
	cmd = tx.TxCommand()
	cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
		raw_args=raw_args, args=[a.strip('"') for a in raw_args],
		splunkd_uri='https://127.0.0.1:8089', session_key='key'))
	return cmd

out = {}

out['parsed'] = [tx.TxCommand()._protocol_v2_option_parser(a)
	for a in ['index=app_logs', 'searchstring=x', 'error']]

out['search'] = command(['index=app_logs', 'sourcetype="tenx_encoded"', '"connection refused"',
	'NOT', 'bootstrap', '(error', 'OR', 'warn)']).search_text()

def no_config(*args, **kwargs):
	raise AssertionError('the configuration was read for an empty search')

tenx_util.get_tenx_config = no_config

for name, raw_args in (('empty', []), ('blank', ['  '])):
	cmd = command(raw_args)
	errors = []
	cmd.write_error = lambda message, *args: errors.append(message)
	rows = list(cmd.generate())
	out[name] = {'rows': len(rows), 'errors': errors}

print(json.dumps(out))
'''


def run_child():
	with tempfile.TemporaryDirectory() as home:
		result = subprocess.run([sys.executable, '-c', CHILD, ROOT, home],
			capture_output=True, text=True, timeout=120)

	assert result.returncode == 0, result.stderr
	return json.loads(result.stdout.strip().splitlines()[-1])


RESULT = None


def child():
	global RESULT

	if RESULT is None:
		RESULT = run_child()

	return RESULT


class TestTxCommand:

	def test_name_value_arguments_are_part_of_the_search(self):
		assert child()['parsed'] == [['index=app_logs'], ['searchstring=x'], ['error']]

	def test_the_search_keeps_its_quotes_and_operators(self):
		assert child()['search'] == \
			'index=app_logs sourcetype="tenx_encoded" "connection refused" NOT bootstrap (error OR warn)'

	def test_no_search_is_refused_before_any_lookup(self):
		for name in ('empty', 'blank'):
			assert child()[name]['rows'] == 0
			assert len(child()[name]['errors']) == 1
			assert 'no search was given' in child()[name]['errors'][0]


class TestTxRegistration:

	def conf(self, name):
		import configparser

		parser = configparser.RawConfigParser(strict=False)
		parser.read(os.path.join(ROOT, 'tenx-for-splunk', 'default', name))
		return parser

	def test_tx_runs_like_tenxsearch(self):
		commands = self.conf('commands.conf')

		assert commands.get('tx', 'filename') == 'tx.py'

		for key in ('chunked', 'python.version', 'python.required'):
			assert commands.get('tx', key) == commands.get('tenxsearch', key)

	def test_tx_has_search_help(self):
		assert self.conf('searchbnf.conf').get('tx-command', 'syntax').startswith('tx ')
