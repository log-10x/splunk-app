"""
The field replay rebuilds read the compact events by the time they were indexed, over every event
date, so an original sourcetype whose events are dated a year ago, or ahead of now, gets its replay
and unit when they are indexed (Splunk Enterprise 10.4.3, before this change: 60 events of each
indexed, neither rebuild wrote fr:old or fr:future, `txf(fr:old)` failed with "macro
'tenx-replay-uc0366a933767' cannot be found" and `txf` replayed fr_mark on 0 of 60). A sourcetype
expires only when no compact event of any date carries it, and `txf(<sourcetype>)` on one without
a unit stops while Splunk parses the search (the validation of txf(1)), with a message saying how
to write it: a check there reaches every client, the REST export endpoint in json and csv included,
where a command failing at run time gives an empty body (Splunk Enterprise 10.4.3).
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

import tenx_replay_builder as b
from test_replay_units import CHILD as UNITS_CHILD, macros

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def listed_units(validation):
	"""The unit hashes a txf(1) validation lets through, as Splunk's like() reads them."""
	m = re.match(r'^match\(st, "\^\[A-Za-z0-9_\.:/-\]\+\$"\) AND like\("\|([0-9a-f|]*)\|", "%\|" \. substr\(md5\(st\), 1, 12\) \. "\|%"\)$',
				 validation)
	assert m, validation
	return [h for h in m.group(1).split('|') if h]


def reaches_unit(validation, sourcetype):
	return hashlib.md5(sourcetype.encode()).hexdigest()[:12] in listed_units(validation)


class TestTxfOfOneSourcetype:
	def test_its_validation_lets_through_the_units_written(self):
		names = [b.unit_macro('fr:old'), b.unit_macro('app:kv')]
		validation = b.txf_one_validation(names + ['tenx-replay', 'tenx-replay-st-x'])
		assert reaches_unit(validation, 'fr:old') and reaches_unit(validation, 'app:kv')
		assert not reaches_unit(validation, 'fr:future') and not reaches_unit(validation, 'fr:ol')
		assert b.txf_one_validation(list(reversed(names))) == validation

	def test_none_written_none_passes(self):
		assert listed_units(b.txf_one_validation([])) == []
		conf = macros()
		assert conf.get('txf(1)', 'validation') == b.txf_one_validation([])
		assert conf.get('txf(1)', 'errormsg') == b.TXF_ONE_ERROR == (
			"no field replay is written yet for this sourcetype, so the search was not run. Rebuild Field Replay "
			"When New writes one within five minutes of the sourcetype's first compact event being indexed; to "
			"write it now, run | tenxreplay over All time. txf takes one original sourcetype, without quotes "
			"(letters, digits and _ . : / -)")
		# the definition is the unit's, as before
		assert conf.get('txf(1)', 'definition') == b.TXF_ONE_UNIT


class TestIndexTime:
	def test_terms(self):
		assert b.index_time_terms('-7d', 'now') == '_index_earliest=-7d'
		assert b.index_time_terms('-10m', None) == '_index_earliest=-10m'
		# the search's own range, as epochs: whole seconds, widened
		assert b.index_time_terms('1794700800.250000', '1795305600.500000') == (
			'_index_earliest=1794700800 _index_latest=1795305601')
		for bad in ('-7d ]', 'x"y', '-1d | delete'):
			try:
				b.index_time_terms(bad, None)
			except ValueError:
				continue
			raise AssertionError(bad)

	def test_an_expired_sourcetype_with_events_left_is_kept(self):
		recorded = {'fr:old': {'sources': 'a', 'last_seen': '1'}, 'gone': {'sources': 'b', 'last_seen': '1'},
					'app:kv': {'sources': 'c', 'last_seen': str(300 * 86400)}}
		covered, expired = b.expire_covered(recorded, 400 * 86400 + 2 * 86400, 400)
		assert expired == ['fr:old', 'gone']
		covered, expired = b.keep_present(recorded, covered, expired, {'fr:old': 60}, 400 * 86400 + 2 * 86400)
		assert expired == ['gone']
		assert covered['fr:old'] == {'sources': 'a', 'last_seen': str(402 * 86400)}
		assert sorted(covered) == ['app:kv', 'fr:old']


# The command against a fake splunkd that also knows when each event was indexed: a row is
# (sourcetype, source, host, count, index, dated within the last 7 days, indexed within the window).
SCENARIO = UNITS_CHILD[:UNITS_CHILD.index('# (sourcetype, source, host, count, index, in the 7-day lookback)')] + r'''
import tenx_replay_builder as b

class IndexTimeSplunk(FakeSplunk):
	def rest(self, path, data=None, method=None):
		if path.endswith('/search/jobs') and data is not None:
			if data.get('earliest_time') != '-1s':  # not the dry runs of the rules
				self.jobs.append((data['search'], data.get('earliest_time'), data.get('latest_time', 'none')))
			if '_index_earliest=' in data['search']:
				saved, self.rows = self.rows, [r for r in self.rows if r[6]]
				try:
					return FakeSplunk.rest(self, path, data, method)
				finally:
					self.rows = saved
		return FakeSplunk.rest(self, path, data, method)

def go(fake, by_index_time, only_new=False, earliest='-7d'):
	cmd = tenxreplay.TenxReplayCommand()
	cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
		username='splunk-system-user', splunkd_uri='https://127.0.0.1:8089', session_key='key',
		earliest_time=earliest, latest_time='now'))
	cmd._apply, cmd._only_new, cmd._lookback, cmd._by_index_time = True, only_new, '-7d', by_index_time
	cmd._rest = fake.rest
	fake.searches, fake.writes, fake.jobs = [], [], []
	return list(cmd.generate())

ROWS = [('app:kv', '/var/app/a.log', 'web-1', 5, 'app', True, True),
		('fr:old', '/var/app/old.log', 'web-2', 60, 'fr_j', False, True),
		('fr:future', '/var/app/new.log', 'web-3', 60, 'fr_j', False, True)]
out = {}
before = IndexTimeSplunk(ROWS)
go(before, False)
out['event_time'] = sorted(before.conf)
fake = IndexTimeSplunk(ROWS)
rows = go(fake, True)
out['index_time'] = sorted(fake.conf)
out['jobs'] = fake.jobs
out['units'] = sorted(n for n in fake.macros if n.startswith(b.UNIT_PREFIX))
out['txf_one'] = fake.validations.get('txf(1)')
# fr:old: not indexed lately, last seen more than replay_expire_days ago, events still there
fake.rows = [ROWS[0], ROWS[1][:6] + (False,), ROWS[2]]
fake.conf['fr:old']['last_seen'] = '1'
go(fake, True)
out['kept_writes'] = fake.writes
out['kept_jobs'] = fake.jobs
out['kept_last_seen'] = fake.conf['fr:old']['last_seen']
out['kept_unit'] = fake.macros[b.unit_macro('fr:old')]
# now its events are gone
fake.rows = [ROWS[0], ROWS[2]]
fake.conf['fr:old']['last_seen'] = '1'
go(fake, True)
out['gone_writes'] = fake.writes
out['gone_unit'] = fake.macros[b.unit_macro('fr:old')]
out['no_op'] = b.no_op_unit().spl()
# the five-minute check, after an upgrade: nothing new, txf(1) not written yet
fake.validations.pop('txf(1)', None)
go(fake, True, only_new=True, earliest='-10m')
out['check_writes'] = fake.writes
out['check_jobs'] = fake.jobs
out['check_txf_one'] = fake.validations.get('txf(1)')
# a new sourcetype in the check: the rebuild reads the lookback by index time
fake.rows = fake.rows + [('fr:new', '/var/app/n.log', 'web-4', 1, 'fr_j', False, True)]
go(fake, True, only_new=True, earliest='-10m')
out['new_jobs'] = fake.jobs
out['new_conf'] = sorted(fake.conf)
print(json.dumps(out))
'''


def test_the_rebuilds_find_every_event_date_and_keep_what_still_has_events():
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', SCENARIO, ROOT, home], capture_output=True, text=True, timeout=120)
	assert proc.returncode == 0, proc.stderr[-3000:]
	out = json.loads(proc.stdout.strip().splitlines()[-1])
	old, future, kv = b.unit_macro('fr:old'), b.unit_macro('fr:future'), b.unit_macro('app:kv')
	# by event time (the shipped saved searches) only app:kv; by index time all three
	assert out['event_time'] == ['app:kv']
	assert out['index_time'] == ['app:kv', 'fr:future', 'fr:old']
	assert out['units'] == sorted([old, future, kv])
	assert all(reaches_unit(out['txf_one'], st) for st in ('fr:old', 'fr:future', 'app:kv'))
	# every read is over every event date (from 0, no end), held to the index-time range, except
	# the all-time read of a new sourcetype's sources, hosts and indexes
	for search, earliest, latest in out['jobs']:
		assert (earliest, latest) == ('0', 'none'), search
		assert '_index_earliest=-7d' in search or ('tenx_sourcetype="fr:future" OR ' in search), search
	# fr:old expired by last_seen but still has events: kept, last_seen today, its unit unchanged
	assert ['conf-', 'fr:old'] not in out['kept_writes'] and ['macro~', old] not in out['kept_writes']
	probe = [j for j in out['kept_jobs'] if '_index_earliest' not in j[0]]
	assert len(probe) == 1 and 'tenx_sourcetype="fr:old")' in probe[0][0], probe
	assert int(out['kept_last_seen']) > 1 and out['kept_unit'] != out['no_op']
	# with no event left it expires: its stanza goes, its unit becomes the no-op unit
	assert ['conf-', 'fr:old'] in out['gone_writes'] and out['gone_unit'] == out['no_op']
	# the five-minute check writes the txf(1) validation when it is missing, and reads by index time
	assert out['check_writes'] == [['macro~', 'txf(1)']] and reaches_unit(out['check_txf_one'], 'fr:old')
	assert all('_index_earliest=-10m' in j[0] for j in out['check_jobs'] if 'tstats' in j[0])
	# a new sourcetype: the rebuild reads the lookback (-7d) by index time
	assert 'fr:new' in out['new_conf']
	assert any('_index_earliest=-7d' in j[0] for j in out['new_jobs'])
	assert all(j[1:] == ['0', 'none'] for j in out['new_jobs'])



STALE = UNITS_CHILD[:UNITS_CHILD.index('# (sourcetype, source, host, count, index, in the 7-day lookback)')] + r'''
fake = FakeSplunk([('app:kv', '/var/app/a.log', 'web-1', 5, 'app', True)])
# an earlier build wrote a definition of its own into local/macros.conf
fake.macros['txf(1)'] = 'if(like("|x|", "%|" . substr(md5("$st$"), 1, 12) . "|%"), "a", "b")'
run(fake)
first = [w for w in fake.writes if w[1] == 'txf(1)']
run(fake)
print(json.dumps({'first': first, 'again': [w for w in fake.writes if w[1] == 'txf(1)'],
				  'definition': fake.macros['txf(1)'], 'validation': fake.validations.get('txf(1)')}))
'''


def test_a_definition_an_earlier_build_wrote_is_set_back():
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', STALE, ROOT, home], capture_output=True, text=True, timeout=120)
	assert proc.returncode == 0, proc.stderr[-3000:]
	out = json.loads(proc.stdout.strip().splitlines()[-1])
	assert out['first'] == [['macro~', 'txf(1)']] and out['again'] == []
	assert out['definition'] == b.TXF_ONE_UNIT and reaches_unit(out['validation'], 'app:kv')
