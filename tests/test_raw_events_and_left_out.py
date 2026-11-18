"""
Two things a `tx` or `txf` search used to leave out with no message.

1. Raw events of the same sources. A source that sent raw events before the Receiver was installed has
   them in the same indexes as its compact events; `tx` read `tenx-events` alone, so a search over both
   periods returned the compact events only. `tx`, `txf` and txf(<sourcetype>) now read
   ((`tenx-events`) OR (`tenx-raw-events`)), whose shipped definition selects no event, and the
   prefilter warns when the indexes a search reads hold raw events of the original sourcetypes of its
   compact events that the macro does not name (one tstats, from tenxreplay's record).
2. Sourcetypes the field replay macro leaves out. Past replay_max_macro_chars `tenx-replay` holds the
   busiest sourcetypes only; the others lost their unit as well (it became the no-op unit) and their
   record, so txf(<sourcetype>) and the search rewrite gave their events none of the add-on's fields
   either. Every covered sourcetype now keeps its unit and its record, the record marks what the macro
   leaves out (left_out), the rewrite chains their units, and `txf` warns.
"""
import configparser
import json
import os
import subprocess
import sys
import tempfile

import tenx_prefilter_parser as pp
import tenx_replay_builder as b
from test_replay_units import CHILD, ROOT

APP = os.path.join(ROOT, 'tenx-for-splunk')


def macros():
	conf = configparser.RawConfigParser(strict=False)
	conf.read(os.path.join(APP, 'default', 'macros.conf'), encoding='utf-8')
	return conf


class TestTheRawEventsMacro:
	def test_tx_txf_and_txf_of_one_read_both_macros(self):
		conf = macros()
		assert b.EVENTS == '((`tenx-events`) OR (`tenx-raw-events`))'
		for name in ('tx', 'txf'):
			assert conf.get(name, 'definition').startswith(b.EVENTS + ' [| tenxprefilter] | '), name
		assert conf.get('txf(1)', 'definition').startswith('"' + b.EVENTS + ' [| tenxprefilter] | ')
		assert conf.get('txf(1)', 'definition') == b.TXF_ONE_UNIT

	def test_the_shipped_definition_selects_no_event_and_only_tx_reads_it(self):
		conf = macros()
		assert conf.get('tenx-raw-events', 'definition') == 'sourcetype::tenx_no_raw_events'
		readers = [s for s in conf.sections() if '`tenx-raw-events`' in conf.get(s, 'definition', fallback='')]
		assert sorted(readers) == ['tx', 'txf', 'txf(1)']

	def test_raw_events_are_passed_through_as_they_were_read(self):
		# a raw event is not compact text, so tx and txf mark it tenx_passed before the expansion and hide it
		# from the extraction that follows (tenx-whole-hide): it keeps the fields Splunk gave it
		conf = macros()
		assert 'eval tenx_passed=if(match(_raw, "^~"), null(), 1)' in conf.get('tx', 'definition')
		assert 'tenx_passed=if(match(_raw, "^~") OR isnotnull(tenx_sourcetype), null(), 1)' in conf.get('txf', 'definition')


RECORD = {'access_combined': {'indexes': 'web,web_old', 'left_out': ''},
		  'fortigate_utm': {'indexes': 'fw', 'left_out': 'txf'},
		  'fortigate_log': {'indexes': '*', 'left_out': 'txf,unit'}}


class TestTheRecordOnDisk:
	def test_local_overrides_default_and_tenx_stanzas_are_left_out(self):
		with tempfile.TemporaryDirectory() as home:
			for d, text in (('default', '[default]\n[a]\nindexes = x\n'),
							('local', '# note\n[a]\nindexes = y\nleft_out = txf\n[tenx:narrowing]\nfields_not_in_text = q\n[b]\nindexes = *\n')):
				os.makedirs(os.path.join(home, d))
				open(os.path.join(home, d, 'tenx_replay.conf'), 'w').write(text)
			assert pp.replay_record_on_disk(home) == {'a': {'indexes': 'y', 'left_out': 'txf'},
													   'b': {'indexes': '*', 'left_out': ''}}

	def test_nothing_on_disk_is_an_empty_record(self):
		with tempfile.TemporaryDirectory() as home:
			assert pp.replay_record_on_disk(home) == {}


class TestTheLeftOutWarning:
	def test_txf_names_what_its_macro_leaves_out_in_the_indexes_searched(self):
		msg = pp.replay_left_out(RECORD, '`txf`', [])
		assert msg == ('txf: the field replay of txf leaves out fortigate_log and fortigate_utm (over '
					   'replay_max_macro_chars), so their events get only the fields in their text; txf(<sourcetype>) '
					   'gives them all their fields.')
		assert len(msg) <= 256
		# fortigate_utm is recorded in fw only; fortigate_log in every index (*)
		assert 'fortigate_utm' not in pp.replay_left_out(RECORD, '`txf`', ['web'])
		assert 'fortigate_utm' in pp.replay_left_out(RECORD, '`txf`', ['f*'])

	def test_nothing_left_out_is_no_warning(self):
		record = {'access_combined': {'indexes': 'web', 'left_out': ''}}
		assert pp.replay_left_out(record, '`txf`', []) is None
		assert pp.replay_left_out(RECORD, '`tx`', []) is None

	def test_txf_of_one_warns_only_when_its_own_unit_replays_nothing(self):
		assert pp.replay_left_out(RECORD, '`txf(fortigate_utm)`', []) is None
		assert pp.replay_left_out(RECORD, '`txf(fortigate_log)`', []) == (
			"txf(fortigate_log): this sourcetype's field replay is over replay_max_macro_chars and replays nothing, so "
			"its events get only the fields in their text.")


class TestTheRawEventsProbe:
	def test_the_recorded_pairs_in_the_indexes_and_time_written_before_the_macro(self):
		assert pp.raw_history_probe(RECORD, 'index=web earliest=-90d') == (
			'| tstats count where earliest=-90d (index="web") ((sourcetype="access_combined" (index="web" OR '
			'index="web_old")) OR (sourcetype="fortigate_log")) NOT tenx_sourcetype=* NOT tenx_mapped=* NOT '
			'(`tenx-raw-events`) by index, sourcetype')

	def test_no_index_named_is_every_recorded_pair(self):
		probe = pp.raw_history_probe(RECORD, '')
		assert probe.startswith('| tstats count where ((sourcetype="access_combined" ')
		assert '(sourcetype="fortigate_utm" (index="fw"))' in probe and probe.endswith(' by index, sourcetype')

	def test_not_probed(self):
		assert pp.raw_history_probe({}, 'index=web') is None
		# a sourcetype written before the macro chooses the events the search reads
		assert pp.raw_history_probe(RECORD, 'index=web sourcetype=tenx_encoded') is None
		# no recorded pair in the indexes named
		assert pp.raw_history_probe({'a': {'indexes': 'x', 'left_out': ''}}, 'index=y') is None
		# a time value that is not a plain time modifier is not copied into the probe
		assert 'earliest' not in pp.raw_history_probe(RECORD, 'index=web earliest="a b"')

	def test_the_message(self):
		rows = [{'index': 'web_old', 'sourcetype': 'access_combined', 'count': '5'},
				{'index': 'web_old', 'sourcetype': 'fortigate_traffic', 'count': '7'}]
		msg = pp.raw_history_message(rows, '`txf(access_combined)`')
		assert msg == ('txf: index web_old also holds events of access_combined and fortigate_traffic that are not '
					   'compact, and this search leaves them out. To return them too, name them in the tenx-raw-events '
					   'macro.')
		assert len(msg) <= 256
		many = [{'index': 'idx%d' % i, 'sourcetype': 'sourcetype_number_%d' % i, 'count': '1'} for i in range(6)]
		assert len(pp.raw_history_message(many, '`tx`')) <= 256


COMMAND = r'''
import json, os, sys, types, tempfile, shutil

root, home, record, before, macro, rows = sys.argv[1:7]
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

app = tempfile.mkdtemp()
os.makedirs(os.path.join(app, 'local'))
with open(os.path.join(app, 'local', 'tenx_replay.conf'), 'w') as f:
	for st, kv in json.loads(record).items():
		f.write('[%s]\n' % st + ''.join('%s = %s\n' % i for i in kv.items()))
tenx_prefilter.apphome = app
cmd = tenx_prefilter.TenxPrefilterCommand()
cmd.before = (before, macro)
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	username='u', splunkd_uri='https://127.0.0.1:8089', session_key='k', earliest_time='0', latest_time='now'))
searches, warnings = [], []
def rest(path, data=None, answer=True):
	searches.append(data['search'])
	return {'results': json.loads(rows)}
cmd._rest = rest
cmd.write_warning = warnings.append
cmd._record_checks(macro)
shutil.rmtree(app)
print(json.dumps({'searches': searches, 'warnings': warnings}))
'''


class TestTheCommand:
	def run(self, record, before, rows, macro='`tx`'):
		with tempfile.TemporaryDirectory() as home:
			proc = subprocess.run([sys.executable, '-c', COMMAND, ROOT, home, json.dumps(record), before, macro,
								   json.dumps(rows)], capture_output=True, text=True, timeout=60)
		assert proc.returncode == 0, proc.stderr[-3000:]
		return json.loads(proc.stdout.strip().splitlines()[-1])

	def test_raw_events_found_is_a_warning(self):
		out = self.run(RECORD, 'index=web', [{'index': 'web', 'sourcetype': 'access_combined', 'count': '9'}])
		assert out['searches'] == [pp.raw_history_probe(RECORD, 'index=web')]
		assert out['warnings'] == [pp.raw_history_message([{'index': 'web', 'sourcetype': 'access_combined'}], '`tx`')]

	def test_none_found_or_nothing_recorded_is_no_warning(self):
		assert self.run(RECORD, 'index=web', [{'index': 'web', 'sourcetype': 'x', 'count': '0'}])['warnings'] == []
		assert self.run({}, 'index=web', []) == {'searches': [], 'warnings': []}

	def test_txf_also_names_what_its_replay_leaves_out(self):
		out = self.run(RECORD, 'index=fw', [], macro='`txf`')
		assert out['warnings'] == [pp.replay_left_out(RECORD, '`txf`', ['fw'])]


class TestTheRecordAndTheRewrite:
	def test_left_out_values(self):
		assert b.left_out_value(True, False) == ''
		assert b.left_out_value(False, False) == 'txf'
		assert b.left_out_value(False, True) == 'txf,unit'

	def test_units_are_held_to_the_sourcetype_cap_alone(self):
		present = [('a', '', '', 9), ('b', '', '', 5), ('c', '', '', 1)]
		assert b.unit_sourcetypes(present, settings=dict(b.DEFAULT_SETTINGS, replay_max_macro_chars=1)) == ['a', 'b', 'c']
		assert b.unit_sourcetypes(present, settings=dict(b.DEFAULT_SETTINGS, replay_max_sourcetypes=2)) == ['a', 'b']

	def test_the_rewrite_chains_units_where_the_macro_leaves_a_sourcetype_out(self):
		covered = {'a': {'indexes': 'x', 'unit': b.unit_macro('a')}, 'b': {'indexes': 'x', 'unit': b.unit_macro('b')}}
		assert b.rewrite_replay(covered, ['x']) == b.FULL
		covered['b']['left_out'] = 'txf'
		assert b.rewrite_replay(covered, ['x']) == b.compose_units(['a', 'b'])

	def test_a_cut_unit_keeps_what_the_record_needs(self):
		unit = b.build_unit([], 'a', {'sources': set(), 'hosts': set(), 'indexes': set()}, limit=10)
		assert unit.replays_nothing and 'a' in unit.per_sourcetype and unit.spl() == b.build([], [], only=True).spl()


SCENARIO = r'''
class SizedSplunk(FakeSplunk):
	"""replay_max_macro_chars from self.limit."""
	limit = None
	def rest(self, path, data=None, method=None):
		if self.limit and urllib.parse.urlparse(path).path == NS + 'configs/conf-tenx_config/config':
			return {'entry': [{'content': {'replay_max_macro_chars': str(self.limit)}}]}
		return FakeSplunk.rest(self, path, data, method)

ROWS = [('app:kv', '/var/app/a.log', 'web-1', 50, 'app', True),
		('app:json', '/var/other/b.log', 'api-1', 3, 'shared', True)]
fake = SizedSplunk(ROWS)
run(fake)
full = len(fake.macros['tenx-replay'])
out = {'full': full, 'found': None}
# the largest limit under which the macro leaves out app:json (the less busy) while each unit fits
for limit in range(full, 0, -50):
	fake = SizedSplunk(ROWS)
	fake.limit = limit
	rows = run(fake)
	left = dict((r['sourcetype'], r.get('left_out')) for r in rows)
	if left.get('app:json') == 'txf' and left.get('app:kv') == '':
		out['found'] = limit
		break
no_op = tenxreplay.builder.no_op_unit().spl()
out['left'] = left
out['units_no_op'] = sorted(st for st in ('app:kv', 'app:json') if fake.macros.get(tenxreplay.builder.unit_macro(st)) == no_op)
out['units'] = sorted(st for st in ('app:kv', 'app:json') if tenxreplay.builder.unit_macro(st) in fake.macros)
out['conf'] = dict((k, v.get('left_out')) for k, v in fake.conf.items() if not k.startswith('tenx:'))
out['json_in_macro'] = 'EVAL-j' in fake.macros['tenx-replay'] or '"json"' in fake.macros['tenx-replay']
out['json_in_unit'] = '"json"' in fake.macros[tenxreplay.builder.unit_macro('app:json')]
out['rewrite'] = tenxreplay.builder.rewrite_replay(dict(fake.conf), ['shared', 'app'])
out['compose'] = tenxreplay.builder.compose_units(['app:json', 'app:kv'])
out['retired'] = sorted(fake.conf.get(tenxreplay.builder.RETIRED_STANZA, {}))
# a second rebuild with the same limit changes nothing
run(fake)
out['second_writes'] = fake.writes
print(json.dumps(out))
'''


def test_a_sourcetype_the_macro_leaves_out_keeps_its_unit_and_its_record():
	marker = '# (sourcetype, source, host, count, index, in the 7-day lookback)'
	assert marker in CHILD
	child = CHILD.split(marker)[0] + SCENARIO
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', child, ROOT, home], capture_output=True, text=True, timeout=300)
	assert proc.returncode == 0, proc.stderr[-3000:]
	out = json.loads(proc.stdout.strip().splitlines()[-1])
	assert out['found'], out
	assert out['left'] == {'app:kv': '', 'app:json': 'txf'}
	assert not out['json_in_macro'] and out['json_in_unit']
	assert out['units'] == ['app:json', 'app:kv'] and out['units_no_op'] == [] and out['retired'] == []
	assert out['conf'] == {'app:kv': '', 'app:json': 'txf'}
	assert out['rewrite'] == out['compose']
	assert out['second_writes'] == []


class TestSubsecond:
	"""
	tenx-event-time gives a compact event a time with a fraction, so Splunk keeps _subsecond on it (.000 where
	the epoch's fraction digits are zeros); the raw event has it only when its timestamp printed sub-seconds.
	Both inflate macros drop it on an expanded event whose template's timestamp format has no fraction.
	"""
	STEP = ('_subsecond=if(len(tenx_text)>0 AND len(tenx_ts_f)>0 AND tenx_ts_f!="__TENX_EPOCH__" AND '
			'NOT match(tenx_ts_f, "%\\d+Q"), null(), _subsecond)')

	@staticmethod
	def dropped(fmt, expanded=True):
		"""The step's condition, in Python: len(tenx_text)>0, a format, not an epoch written back, no %<n>Q."""
		import re
		return bool(expanded) and len(fmt) > 0 and fmt != '__TENX_EPOCH__' and not re.search(r'%\d+Q', fmt)

	def test_in_both_inflate_macros_in_the_step_that_sets_raw(self):
		conf = macros()
		for name in ('tenx-inflate', 'tenx-inflate-debug'):
			d = conf.get(name, 'definition')
			assert ('_raw=if(len(tenx_text)>0, tenx_text, _raw), ' + self.STEP) in d, name
			# before the fields the step reads are removed
			assert d.index(self.STEP) < (d.index('| fields  - ') if '| fields  - ' in d else len(d))

	def test_which_formats_lose_it(self):
		assert self.dropped('%d/%b/%Y:%H:%M:%S %z')
		assert self.dropped('%Y-%m-%d %H:%M:%S')
		assert not self.dropped('%Y-%m-%dT%H:%M:%S.%3QZ')
		assert not self.dropped('%H:%M:%S,%6Q')
		assert not self.dropped('__TENX_EPOCH__')
		assert not self.dropped('')
		assert not self.dropped('%d/%b/%Y:%H:%M:%S %z', expanded=False)


STORE_CHILD = r'''
import io, json, os, sys, types, urllib.error

root, home, state, peers, probe = sys.argv[1:6]
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
	username='u', splunkd_uri='https://127.0.0.1:8089', session_key='k', earliest_time='0', latest_time='now', sid='x'))
calls, warnings = [], []
def rest(path, data=None, answer=True):
	calls.append(path.split('?')[0] if data is None else data['search'][:14])
	if path == tenx_prefilter.parser.STORE_STATE_PATH:
		if state == 'absent':
			raise urllib.error.HTTPError(path, 404, 'Not Found', {}, io.BytesIO(b'{}'))
		if state == 'starting':
			raise urllib.error.HTTPError(path, 503, 'Service Unavailable', {}, io.BytesIO(
				b'{"messages":[{"type":"ERROR","text":"KV Store is initializing. Please try again later."}]}'))
		return json.loads(state)
	if path == tenx_prefilter.parser.PEERS_PATH:
		return {'entry': [{'name': 'idx1'}] * int(peers)}
	return json.loads(probe)
cmd._rest = rest
cmd.write_warning = warnings.append
out = list(cmd.generate())
print(json.dumps({'calls': calls, 'warnings': warnings, 'out': out}))
'''

FAILED = {'messages': [{'type': 'ERROR', 'text': "Streamed search execute failed because: Error in 'lookup' command: Could "
						"not construct lookup 'tenx-dml-lookup, _key, AS, tenx_hash'"}], 'results': []}


class TestTheLookupOnTheIndexers:
	"""
	For some minutes after an install or an upgrade, on a search head with search peers, the prefilter checks that
	the template lookup runs on the indexers; while it does not, the search reads no indexer and says why, where it
	failed with Splunk's lookup error and no rows.
	"""
	def run(self, state, peers, probe):
		with tempfile.TemporaryDirectory() as home:
			proc = subprocess.run([sys.executable, '-c', STORE_CHILD, ROOT, home, state, str(peers), json.dumps(probe)],
								  capture_output=True, text=True, timeout=60)
		assert proc.returncode == 0, proc.stderr[-3000:]
		return json.loads(proc.stdout.strip().splitlines()[-1])

	def test_new_version(self):
		version = '1.2.5'
		assert pp.new_version(None, version, 1000)
		assert pp.new_version({'version': '1.2.4', 'version_since': 1}, version, 10 ** 9)
		assert pp.new_version({'version': version, 'version_since': 1000}, version, 1000 + pp.NEW_VERSION_SECONDS - 1)
		assert not pp.new_version({'version': version, 'version_since': 1000}, version, 1000 + pp.NEW_VERSION_SECONDS)
		# a record from before the field existed, of this version: not new
		assert not pp.new_version({'version': version}, version, 1000)

	def test_lookup_failed(self):
		assert pp.lookup_failed(FAILED).startswith("Streamed search execute failed")
		assert pp.lookup_failed({'messages': [{'type': 'WARN', 'text': 'lookup slow'}]}) is None
		assert pp.lookup_failed({'results': [{'tenx_probe': 'x'}]}) is None

	def test_while_the_lookup_fails_on_the_indexers_the_search_stays_on_the_search_head(self):
		out = self.run('absent', 2, FAILED)
		assert out['out'] == [{'search': pp.ON_SEARCH_HEAD}] and out['warnings'] == [pp.NOT_ON_INDEXERS]
		assert len(pp.NOT_ON_INDEXERS) <= 256

	def test_once_it_runs_or_without_peers_or_long_after_the_install_nothing_changes(self):
		version = pp.conf_setting([os.path.join(APP, 'default', 'app.conf')], 'launcher', 'version')
		ok = self.run('absent', 2, {'results': [{'tenx_probe': 'a'}], 'messages': []})
		assert ok['out'][0]['search'] != pp.ON_SEARCH_HEAD and pp.NOT_ON_INDEXERS not in ok['warnings']
		alone = self.run('absent', 0, FAILED)
		assert alone['out'][0]['search'] != pp.ON_SEARCH_HEAD and len([c for c in alone['calls'] if c.startswith('search ((')]) == 0
		old = self.run(json.dumps({'version': version, 'version_since': 1, 'updated': 9 * 10 ** 9, 'status': 'current'}), 2, FAILED)
		assert pp.PEERS_PATH.split('?')[0] not in old['calls'] and old['out'][0]['search'] != pp.ON_SEARCH_HEAD

	def test_while_the_kv_store_starts_the_search_says_why(self):
		out = self.run('starting', 2, FAILED)
		assert out['warnings'][:1] == [pp.KV_NOT_READY] and pp.PEERS_PATH.split('?')[0] not in out['calls']


INFOS_SCENARIO = r'''
infos = tenxreplay.TenxReplayCommand._recorded_infos(tenxreplay.builder.Replay(), {}, {'gone:st'})
print(json.dumps(sorted(infos['gone:st'])))
'''


def test_a_failed_unit_left_out_of_the_macro_still_gets_a_row_and_a_record():
	# the rows tenxreplay yields read these keys of every recorded sourcetype
	marker = '# (sourcetype, source, host, count, index, in the 7-day lookback)'
	child = CHILD.split(marker)[0] + INFOS_SCENARIO
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', child, ROOT, home], capture_output=True, text=True, timeout=120)
	assert proc.returncode == 0, proc.stderr[-3000:]
	keys = set(json.loads(proc.stdout.strip().splitlines()[-1]))
	assert {'stanzas', 'aliases', 'calculated', 'lookups', 'computed', 'aliased', 'masking', 'sources', 'warnings'} <= keys
