"""
The hourly rebuild with skip_unchanged: when nothing a rebuild reads has changed since the last rebuild, three searches
decide it and nothing is written; when anything has, the rebuild reads and writes what it does without the option.
"""
import collections

SCENARIO = r'''
import copy, time

MERGED = '| tstats fillnull_value='
SENDERS = '| tstats max(_time) as t where'

class Fake(FakeSplunk):
	"""Answers the state read's tstats and the senders' tstats from the rows, and lists extra props."""
	props = []

	def rest(self, path, data=None, method=None):
		s = (data or {}).get('search', '')
		rows = sorted((r for r in self.rows if r[5]), key=lambda r: (r[4], r[2], r[1]))
		if s.startswith(MERGED) or s.startswith(SENDERS):
			self.searches.append((s, data.get('earliest_time')))
			out = [{'index': r[4], 'host': r[2], 'source': r[1], 'sourcetype': 'tenx_encoded', 'tenx_sourcetype': r[0],
					'count': str(r[3]), 't': '1590998400'} for r in rows]
			return {'results': out if s.startswith(MERGED) else [dict(o, tenx_sourcetype=None) for o in out]}
		if 'dedup index host source sourcetype | fieldsummary' in s:
			self.searches.append((s, data.get('earliest_time')))
			return {'results': [{'field': f} for f in getattr(self, 'sender_fields', ['host'])]}
		reply = FakeSplunk.rest(self, path, data, method)
		if urllib.parse.urlparse(path).path == NS + 'configs/conf-props':
			reply = {'entry': reply['entry'] + self.props}
		return reply

def hourly(fake, skip=True, shift=0):
	cmd = tenxreplay.TenxReplayCommand()
	cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
		username='splunk-system-user', splunkd_uri='https://127.0.0.1:8089', session_key='key',
		earliest_time='-7d', latest_time='now'))
	cmd._apply, cmd._only_new, cmd._lookback, cmd._skip_unchanged = True, False, '-7d', skip
	cmd._rest = fake.rest
	fake.searches, fake.writes = [], []
	real = time.time
	time.time = lambda: real() + shift
	try:
		rows = list(cmd.generate())
	finally:
		time.time = real
	return {'searches': [s for s, _ in fake.searches], 'writes': fake.writes, 'rows': rows}

def both(fake, shift=0):
	other = copy.deepcopy(fake)
	return hourly(fake, True, shift), hourly(other, False, shift)

fake = Fake([('XmlWinEventLog', 'XmlWinEventLog:Security', 'dc1', 5, 'wx', True),
			 ('linux:audit', '/var/log/audit/audit.log', 'h1', 3, 'au', True)])
out = {'settle': [hourly(fake) for _ in range(3)], 'quiet': [hourly(fake), hourly(fake)]}
fake.stored = [{'pattern_hash': 'h new', 'stored_hour': str(int(time.time()) // 3600)}]
out['template'] = both(fake)
fake.stored = []
for _ in range(3):
	hourly(fake)
fake.rows.append(('XmlWinEventLog', 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational', 'dc1', 9, 'sy', True))
out['pair'] = both(fake)
for _ in range(2):
	hourly(fake)
fake.sender_fields = ['host', 'k8s_ns']
out['sender_field'] = both(fake)
for _ in range(2):
	hourly(fake)
fake.props = [{'name': 'linux:audit', 'content': {'EVAL-a': '"audit"'}, 'acl': GLOBAL}]
out['props'] = both(fake)
for _ in range(2):
	hourly(fake)
fake.macros['tenx-extract'] = 'extract | eval edited=1'
out['edited'] = both(fake)
for _ in range(2):
	hourly(fake)
out['day'] = both(fake, shift=86400)
out['quiet_after'] = hourly(fake, shift=86400)

def record(have, outcome):
	cmd = tenxreplay.TenxReplayCommand()
	writes = []
	cmd._sampled_record = lambda: dict(have)
	cmd._state_digest = lambda state: 'digest of %s' % json.dumps(state)
	cmd._rest = lambda path, data=None, method=None: writes.append(data)
	cmd._record_state({'day': 1}, outcome)
	return writes

out['same_outcome'] = record({'outcome': 'A'}, 'A')
out['new_outcome'] = record({'outcome': 'A', 'state': 'old'}, 'B')
conf = {'tenx:sampled': {'pairs': 'wx XmlWinEventLog', 'began': '1'}}
cmd = tenxreplay.TenxReplayCommand()
cmd._rest = lambda path, data=None, method=None: (
	{'entry': [{'name': k, 'content': dict(v)} for k, v in conf.items()]} if 'conf-tenx_replay' in path else
	{'entry': [{'name': 'tenx-extract', 'content': {'definition': 'extract'}, 'acl': {}}]})
digests = [cmd._state_digest({'day': 1})]
conf['tenx:sampled'].update(state='x', outcome='y')
digests.append(cmd._state_digest({'day': 1}))
conf['tenx:sampled']['began'] = '2'
digests.append(cmd._state_digest({'day': 1}))
out['digests'] = digests
print(json.dumps(out))
'''

MERGED = '| tstats fillnull_value=tenx_no_carrier count max(_time) as t where `tenx-events` by index host source sourcetype tenx_sourcetype'
SENDERS = '| tstats max(_time) as t where `tenx-events` by index host source sourcetype'


RAN = {}


def run():
	from test_replay_coverage_record import child_run
	if not RAN:
		RAN.update(child_run(SCENARIO))
	return RAN


class TestTheHourlyRebuild:
	def out(self):
		return run()

	def test_nothing_changed_takes_three_searches_and_writes_nothing(self):
		for quiet in self.out()['quiet'] + [self.out()['quiet_after']]:
			assert quiet['writes'] == []
			# the compact events' groups, each sender's newest event, the indexes' lexicons
			merged, senders, lexicon = quiet['searches']
			assert merged == MERGED and 'dedup index host source sourcetype | fieldsummary' in senders
			assert lexicon.startswith('| walklex type=field index=au ')
			assert quiet['rows'] == [{'sourcetype': '', 'written': 'no change', 'recompile_dispatched': 'no',
									  'warnings': ['nothing a rebuild reads has changed since the last rebuild']}]

	def test_the_first_runs_rebuild_until_the_rules_left_out_repeat(self):
		settle = self.out()['settle']
		assert all(len(r['searches']) > 3 for r in settle)
		recorded = [[w for w in r['writes'] if w == ['conf~', 'tenx:sampled']] for r in settle]
		# never sampled before: nothing to compare with; then the outcome is recorded; then the state
		assert recorded[0] in ([], [['conf~', 'tenx:sampled']]) and recorded[1] and recorded[2]

	def test_anything_new_rebuilds_as_without_the_option(self):
		for case in ('template', 'pair', 'sender_field', 'props', 'edited', 'day'):
			skip, plain = self.out()[case]
			assert skip['rows'] == plain['rows'], case
			assert [w for w in skip['writes'] if w != ['conf~', 'tenx:sampled']] == \
				[w for w in plain['writes'] if w != ['conf~', 'tenx:sampled']], case
			# the same searches, with the state read's tstats in place of the senders' tstats
			a = collections.Counter(skip['searches'])
			b = collections.Counter(plain['searches'])
			assert a[MERGED] == 1 and b[SENDERS] == 1 and SENDERS not in a, case
			del a[MERGED], b[SENDERS]
			assert a == b, case

	def test_what_is_new_is_what_the_rebuild_reads(self):
		out = self.out()
		assert any('"~h new"' in s for s in out['template'][0]['searches'])
		assert any('index=sy tenx_sourcetype::XmlWinEventLog' in s for s in out['pair'][0]['searches'])
		assert ['macro~', 'tenx-extract'] in out['edited'][0]['writes']


class TestTheRecord:
	def test_the_state_is_recorded_when_the_rules_left_out_are_those_of_the_last_rebuild(self):
		assert run()['same_outcome'] == [{'outcome': 'A', 'state': 'digest of {"day": 1}'}]

	def test_a_new_outcome_is_recorded_without_the_state(self):
		assert run()['new_outcome'] == [{'outcome': 'B', 'state': ''}]

	def test_the_digest_leaves_out_the_record_itself(self):
		first, recorded, began = run()['digests']
		assert first == recorded and began != first
