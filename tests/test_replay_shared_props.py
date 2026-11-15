"""
Rules of other apps: one macro serves every app, so the replay uses only props shared globally,
and says so (tenx_replay_builder docstring, "Which apps' rules").
"""
import json
import os
import subprocess
import sys
import tempfile

import tenx_replay_builder as b

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def test_only_globally_shared_stanzas_are_kept():
	entries = [{'name': 'XmlWinEventLog', 'acl': {'sharing': 'global', 'app': 'Splunk_TA_windows'}},
			   {'name': 'source::x', 'acl': {'sharing': 'system', 'app': 'system'}},
			   {'name': 'app:only', 'acl': {'sharing': 'app', 'app': 'search'}},
			   {'name': 'mine', 'acl': {'sharing': 'user', 'app': 'search'}},
			   {'name': 'no_acl'}]
	kept, skipped = b.shared_globally(entries)
	assert [e['name'] for e in kept] == ['XmlWinEventLog', 'source::x', 'no_acl']
	assert skipped == ['app:only', 'mine']


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

import tenxreplay
cmd = tenxreplay.TenxReplayCommand()
def rest(path, data=None, method=None):
	if 'properties/props/default' in path:
		return {'entry': []}
	return {'entry': [
		{'name': 'XmlWinEventLog', 'content': {'EVAL-a': '1'}, 'acl': {'sharing': 'global'}},
		{'name': 'XmlWinEventLog:local', 'content': {'EVAL-b': '1'}, 'acl': {'sharing': 'app'}},
		{'name': 'off', 'content': {'EVAL-c': '1', 'disabled': '1'}, 'acl': {'sharing': 'global'}}]}
cmd._rest = rest
print(json.dumps([s.name for s in cmd._stanzas()]))
'''


def test_the_command_reads_only_globally_shared_stanzas():
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', CHILD, ROOT, home], capture_output=True, text=True, timeout=60)
	assert proc.returncode == 0, proc.stderr
	assert json.loads(proc.stdout.strip().splitlines()[-1]) == ['default', 'XmlWinEventLog']


def test_every_custom_conf_has_a_reload_trigger():
	# tenx_replay.conf is a custom conf like tenx_config.conf, which carries one too; without
	# it Splunk may ask for a restart when the app is installed or updated.
	import configparser
	import glob
	app = os.path.join(ROOT, 'tenx-for-splunk')
	conf = configparser.RawConfigParser(strict=False)
	conf.read(os.path.join(app, 'default', 'app.conf'))
	custom = [os.path.basename(p)[:-len('.conf.spec')] for p in glob.glob(os.path.join(app, 'README', '*.conf.spec'))
			  if os.path.basename(p) not in ('alert_actions.conf.spec', 'savedsearches.conf.spec')]
	assert sorted(custom) == ['tenx_config', 'tenx_replay']
	for name in custom:
		assert conf.get('triggers', 'reload.' + name) == 'simple', name
