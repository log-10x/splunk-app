"""
Each generated rule is checked before it is written, and a rule that fails is left out with a
logged reason instead of breaking every search that runs the replay.

Offline: tests/test_replay_builder_edge_cases.py (one eval expression; no pipe, bracket,
backtick or top-level comma) and the plain-name rule for lookup arguments below.
Against the running Splunk: tenxreplay runs each rule's test search and the whole generated
macro as oneshot jobs (TenxReplayCommand._dry_run) and reads the lookup definitions, tables and
collections over REST (_lookup_problems). The decisions are pure functions in
tenx_replay_builder, tested here with fake replies shaped as Splunk's REST returns them; the
command's own REST method is tested in a child interpreter with a faked _rest. Splunk Enterprise
10.4.3 answered the failing searches below with HTTP 200 and a FATAL message; an HTTP 400 reply
is read as a failure too.
"""
import json
import os
import subprocess
import sys
import tempfile

import tenx_replay_builder as b

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def stanza(name, **rules):
	return b.Stanza(name, dict(rules), {})


class TestPlainLookupNames:
	def test_lookup_arguments_must_be_plain_names(self):
		for value in ('users "user name" OUTPUT dept', 'users user OUTPUT "a b"', 'my\\table user', 'users user OUTPUT x{}'):
			r = b.build([stanza('st', **{'LOOKUP-u': value})], [('st', 's', 'h')], None)
			assert 'lookup ' not in r.spl(), value
			assert any('plain name' in w for w in r.warnings), value

	def test_plain_names_with_dots_and_colons_are_written(self):
		r = b.build([stanza('st', **{'LOOKUP-u': 'win:lookup user.name AS user OUTPUT dept-id AS dept'})], [('st', 's', 'h')], None)
		assert 'lookup "win:lookup" "user.name" AS tenx_ri0_0 OUTPUT "dept-id" AS dept' in r.spl()


class TestDryRunReply:
	def test_what_splunk_10_4_3_returned(self):
		# Observed on Splunk Enterprise 10.4.3: oneshot jobs that cannot run come back HTTP 200
		# with a FATAL message.
		for text in ("Error in 'EvalCommand': The 'nosuchfunction' function is unsupported or undefined.",
					 "Error in 'EvalCommand': The arguments to the 'if' function are invalid.",
					 "Error in 'EvalCommand': The expression is malformed. Expected ).",
					 "Error in 'lookup' command: Could not construct lookup 'r_missing_lookup, k, AS, k, OUTPUT, v'. See search.log for more details."):
			assert b.dry_run_error(200, json.dumps({'messages': [{'type': 'FATAL', 'text': text}]})) == text
		clean = '{"preview":false,"init_offset":0,"messages":[],"fields":[{"name":"_time"},{"name":"x","type":"num"}],"results":[{"_time":"2026-11-14T08:32:29.000+00:00","x":"1"}], "highlighted":{}}'
		assert b.dry_run_error(200, clean) is None

	def test_parse_error_is_http_400_with_a_fatal_message(self):
		body = json.dumps({'messages': [{'type': 'FATAL', 'text': "Error in 'eval' command: The expression is malformed."}]})
		assert b.dry_run_error(400, body) == "Error in 'eval' command: The expression is malformed."

	def test_runtime_error_message_on_a_completed_job(self):
		body = {'messages': [{'type': 'INFO', 'text': 'fine'}, {'type': 'ERROR', 'text': "Error in 'lookup' command: no table"}], 'results': []}
		assert b.dry_run_error(200, body) == "Error in 'lookup' command: no table"

	def test_clean_job(self):
		assert b.dry_run_error(200, {'messages': [{'type': 'WARN', 'text': 'w'}], 'results': [{'count': '3'}]}) is None
		assert b.dry_run_error(200, '') is None

	def test_http_error_without_a_body(self):
		assert b.dry_run_error(503, 'not json') == 'HTTP 503'


class TestFailingRules:
	def fake_splunk(self, bad_texts):
		calls = []

		def run(spl):
			calls.append(spl)
			hit = [t for t in bad_texts if t in spl]
			return "Error in 'eval' command: %s" % hit[0] if hit else None
		return run, calls

	def test_each_failing_rule_is_found_and_left_out_with_its_reason(self):
		rules = dict(('EVAL-f%02d' % i, '"v%02d"' % i) for i in range(32))
		rules['EVAL-f07'] = 'nosuchfunction(x)'
		rules['EVAL-f20'] = 'if(a)'
		stanzas = [stanza('st', **rules)]
		first = b.build(stanzas, [('st', 's', 'h')])
		run, calls = self.fake_splunk(['nosuchfunction(x)', 'if(a)'])
		bad = b.failing_rules(first.rules, run)
		assert bad == {('EVAL-f07', 'st'): "Error in 'eval' command: nosuchfunction(x)",
					   ('EVAL-f20', 'st'): "Error in 'eval' command: if(a)"}
		assert len(calls) <= 1 + 2 * 2 * 5 < len(first.rules)   # about 2 k log2(n) searches, not one per rule
		again = b.build(stanzas, [('st', 's', 'h')], rejected=bad)
		assert 'nosuchfunction' not in again.spl() and 'if(a)' not in again.spl() and '"v31"' in again.spl()
		assert any('EVAL-f07' in w and 'refused by Splunk' in w for w in again.warnings)

	def test_a_rejected_lookup_is_left_out(self):
		stanzas = [stanza('st', **{'LOOKUP-a': 'missing user OUTPUT dept', 'LOOKUP-b': 'users user OUTPUT team'})]
		first = b.build(stanzas, [('st', 's', 'h')])
		run, _ = self.fake_splunk(['lookup missing'])
		bad = b.failing_rules(first.rules, run)
		assert list(bad) == [('LOOKUP-a', 'st')]
		again = b.build(stanzas, [('st', 's', 'h')], rejected=bad)
		assert 'lookup missing' not in again.spl() and 'lookup users' in again.spl()

	def test_nothing_to_check_runs_nothing(self):
		run, calls = self.fake_splunk([])
		assert b.failing_rules([], run) == {} and calls == []


def entry(name, sharing='global', read=('*',), **content):
	return {'name': name, 'content': content, 'acl': {'sharing': sharing, 'perms': {'read': list(read), 'write': ['admin']}}}


class TestLookupProblems:
	def test_what_every_user_can_run(self):
		definitions = [
			entry('ok_file', filename='users.csv'),
			entry('ok_kv', external_type='kvstore', collection='assets'),
			entry('app_only', sharing='app', filename='users.csv'),
			entry('admins_only', read=('admin',), filename='users.csv'),
			entry('no_file', filename='gone.csv'),
			entry('private_file', filename='secret.csv'),
			entry('no_collection', external_type='kvstore', collection='nope'),
		]
		files = [entry('users.csv'), entry('secret.csv', read=('admin',))]
		collections = [{'name': 'assets'}]
		got = b.lookup_problems(definitions, files, collections)
		assert sorted(got) == ['admins_only', 'app_only', 'no_collection', 'no_file', 'private_file']
		r = b.build([stanza('st', **{'LOOKUP-a': 'no_file u OUTPUT d', 'LOOKUP-b': 'ok_file u OUTPUT d'})],
					[('st', 's', 'h')], bad_lookups=got)
		assert 'lookup no_file' not in r.spl() and 'lookup ok_file' in r.spl()
		assert any('gone.csv does not exist' in w for w in r.warnings)


class TestMacroDryRun:
	def test_every_block_runs(self):
		r = b.build([stanza('a:st', **{'EVAL-x': '1'}), stanza('b:st', **{'EVAL-y': '2'})],
					[('a:st', 's', 'h'), ('b:st', 's', 'h')])
		spl = b.macro_dry_run(r)
		assert spl.startswith('| makeresults count=3 | streamstats count AS tenx_n | eval tenx_sourcetype=case(')
		assert 'tenx_n==1, "a:st", tenx_n==2, "b:st", true(), null()' in spl
		assert 'tenx_hide_others=1 | ' + r.spl() + ' | stats count' in spl


CHILD = r'''
import json, os, sys, types, io, urllib.error

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
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	username='splunk-system-user', splunkd_uri='https://127.0.0.1:8089', session_key='key'))
seen = []

def replies(*answers):
	answers = list(answers)
	def rest(path, data=None, method=None):
		seen.append((path, data))
		answer = answers.pop(0)
		if isinstance(answer, Exception):
			raise answer
		return answer
	return rest

out = {}
cmd._rest = replies({'results': [{'count': '1'}], 'messages': []})
out['clean'] = cmd._dry_run('| makeresults | eval x=1')
body = json.dumps({'messages': [{'type': 'FATAL', 'text': "Error in 'eval' command: The expression is malformed."}]}).encode()
cmd._rest = replies(urllib.error.HTTPError('u', 400, 'Bad Request', {}, io.BytesIO(body)))
out['parse_error'] = cmd._dry_run('| makeresults | eval x=(')
out['posted'] = [seen[0][0], seen[0][1]['exec_mode'], seen[0][1]['search']]
cmd._rest = replies(
	{'entry': [{'name': 'users', 'content': {'filename': 'users.csv'}, 'acl': {'sharing': 'global', 'perms': {'read': ['*']}}},
			   {'name': 'gone', 'content': {'filename': 'gone.csv'}, 'acl': {'sharing': 'global', 'perms': {'read': ['*']}}}]},
	{'entry': [{'name': 'users.csv', 'acl': {'sharing': 'global', 'perms': {'read': ['*']}}}]},
	{'entry': []})
out['lookups'] = cmd._lookup_problems()
out['lookup_paths'] = [p for p, _ in seen[2:]]
print(json.dumps(out))
'''


def test_the_command_reads_splunks_reply():
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', CHILD, ROOT, home], capture_output=True, text=True, timeout=60)
	assert proc.returncode == 0, proc.stderr
	out = json.loads(proc.stdout.strip().splitlines()[-1])
	assert out['clean'] is None
	assert out['parse_error'] == "Error in 'eval' command: The expression is malformed."
	assert out['posted'] == ['/servicesNS/splunk-system-user/tenx-for-splunk/search/jobs', 'oneshot', '| makeresults | eval x=1']
	assert out['lookups'] == {'gone': 'its file gone.csv does not exist'}
	assert out['lookup_paths'] == ['/servicesNS/nobody/tenx-for-splunk/data/transforms/lookups?count=0',
								   '/servicesNS/nobody/-/data/lookup-table-files?count=0',
								   '/servicesNS/nobody/-/storage/collections/config?count=0']
