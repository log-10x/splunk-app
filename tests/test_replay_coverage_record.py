"""
The record of what the field replay covers (tenx_replay.conf) and the macros tenxreplay keeps.

1. On a search head cluster the search rewrite chooses what to replay from tenx_replay.conf, a
   custom conf that only replicates when default/server.conf names it. Unreplicated, a member
   that did not run the rebuild would read no coverage and the rewrite (dashboard hook, `| tx`,
   compiled alerts) would replay nothing there.
2. Unit macros stay bounded: a sourcetype that leaves the replay (expired, or pushed out by
   replay_max_sourcetypes) keeps a no-op unit only for replay_unit_grace_days, so
   local/macros.conf does not grow with every distinct tenx_sourcetype value ever seen.
3. An index the record does not know gets the full replay, an index recorded as holding no
   carrier ([tenx:nocarrier], the negative record) gets none, and a failing unit or an
   unreadable record never gives less than the full replay.
"""
import configparser
import json
import os
import subprocess
import sys
import tempfile

import tenx_replay_builder as b
from test_replay_units import CHILD, ROOT, compiled, baseline_builder

APP = os.path.join(ROOT, 'tenx-for-splunk')


class TestTheRewriteCoverageReplicates:
	def test_the_rewrite_replays_nothing_where_tenx_replay_conf_is_absent(self):
		# What a cluster member that never ran the rebuild reads: no stanza (get_replay_coverage
		# gives {}), so the text without replay, while the member that ran it replays.
		search = 'index=wineventlog sourcetype=tenx_encoded EventCode=4625'
		_, here = compiled(search, {'XmlWinEventLog': {'indexes': 'wineventlog'}, 'app:kv': {'indexes': 'app'}})
		_, there = compiled(search, {})
		assert b.unit_macro('XmlWinEventLog') in here
		assert 'tenx-replay' not in there and 'tenx_rst' not in there

	def test_tenx_replay_conf_is_replicated_like_tenx_config(self):
		# default/server.conf: "custom confs do not replicate across cluster members unless they
		# are named here". tenx_config is; tenx_replay, which the rewrite depends on, must be.
		conf = configparser.ConfigParser(strict=False)
		conf.read(os.path.join(APP, 'default', 'server.conf'))
		section = conf['shclustering'] if conf.has_section('shclustering') else {}
		assert str(section.get('conf_replication_include.tenx_config', '')).strip() == 'true'
		assert str(section.get('conf_replication_include.tenx_replay', '')).strip() == 'true'


SCENARIO = r'''
class CappedSplunk(FakeSplunk):
	"""replay_max_sourcetypes = 2, props for nothing but what FakeSplunk lists."""
	def rest(self, path, data=None, method=None):
		if urllib.parse.urlparse(path).path == NS + 'configs/conf-tenx_config/config':
			return {'entry': [{'content': {'replay_max_sourcetypes': '2'}}]}
		return FakeSplunk.rest(self, path, data, method)

fake = CappedSplunk([])
counts = []
for rnd in range(8):
	# two new busy original sourcetypes each rebuild (a sender whose tenx_sourcetype value
	# changes: per deploy, per file, a typo fixed); the earlier ones stop
	fake.rows = [('st%d_%d' % (rnd, i), '/var/x.log', 'h1', 100 + rnd, 'main', True) for i in range(2)]
	run(fake)
	units = [n for n in fake.macros if n.startswith(tenxreplay.builder.UNIT_PREFIX)]
	stanzas = [n for n in fake.conf if n not in ('default', tenxreplay.builder.NARROWING_STANZA,
												  tenxreplay.builder.RETIRED_STANZA)]
	counts.append((len(units), len(stanzas)))
# the grace period: every retired unit dated long ago is deleted at the next rebuild, with its alias
retired = sorted(fake.conf[tenxreplay.builder.RETIRED_STANZA])
for name in retired:
	fake.conf[tenxreplay.builder.RETIRED_STANZA][name] = '86400'
run(fake)
units = [n for n in fake.macros if n.startswith(tenxreplay.builder.UNIT_PREFIX)]
aliases = [n for n in fake.macros if n.startswith(tenxreplay.builder.ALIAS_PREFIX)]
print(json.dumps([counts, retired, units, aliases, sorted(fake.conf.get(tenxreplay.builder.RETIRED_STANZA, {}))]))
'''


def test_unit_macros_stay_bounded_when_sourcetype_values_rotate():
	marker = '# (sourcetype, source, host, count, index, in the 7-day lookback)'
	assert marker in CHILD
	child = CHILD.split(marker)[0] + SCENARIO
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', child, ROOT, home], capture_output=True, text=True, timeout=120)
	assert proc.returncode == 0, proc.stderr[-3000:]
	counts, retired, units_after, aliases_after, retired_after = json.loads(proc.stdout.strip().splitlines()[-1])
	units, stanzas = counts[-1]
	# past replay_unit_grace_days the no-op units and their aliases are deleted
	assert len(retired) == 2 and not set(retired) & set(units_after), (retired, units_after)
	assert len(units_after) == 2 and len(aliases_after) == 2 and retired_after == []
	# tenx_replay.conf is held to replay_max_sourcetypes ...
	assert stanzas <= 2, counts
	# ... and so are the macros (a no-op unit kept for a grace period is fine; one per value
	# ever seen is not: if no unit were ever deleted, 8 rebuilds would leave 16 units, 2 live
	# and 14 no-op).
	assert units <= 2 * 2, counts


ACL_SCENARIO = r'''
import urllib.error

class AclFailsOnce(FakeSplunk):
	"""The first ACL write fails, as a transient splunkd error would."""
	failed = False
	def rest(self, path, data=None, method=None):
		if path.endswith('/acl') and not self.failed:
			self.failed = True
			raise urllib.error.HTTPError(path, 503, 'busy', {}, None)
		return FakeSplunk.rest(self, path, data, method)

fake = AclFailsOnce([('app:kv', '/var/app/a.log', 'web-1', 5, 'app', True)])
try:
	run(fake)
except (SystemExit, AttributeError):  # error_exit needs a record writer the harness does not set up
	pass
first = dict((k, fake.acl_of(k)['sharing']) for k in fake.macros if k.startswith('tenx-replay-u'))
run(fake)
second = dict((k, fake.acl_of(k)['sharing']) for k in fake.macros if k.startswith('tenx-replay-u'))
print(json.dumps([first, second, 'app:kv' in fake.conf]))
'''


def child_run(scenario):
	marker = '# (sourcetype, source, host, count, index, in the 7-day lookback)'
	child = CHILD.split(marker)[0] + scenario
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', child, ROOT, home], capture_output=True, text=True, timeout=120)
	assert proc.returncode == 0, proc.stderr[-3000:]
	return json.loads(proc.stdout.strip().splitlines()[-1])


def test_a_unit_whose_acl_write_failed_is_shared_by_the_next_rebuild():
	first, second, stanza = child_run(ACL_SCENARIO)
	kv = b.unit_macro('app:kv')
	assert first == {kv: 'app'}, first          # created, the ACL write failed, the rebuild stopped
	assert second == {kv: 'global'}, second     # the next rebuild repairs it although the text is unchanged
	assert stanza


class TestNeverLessThanTheFullReplay:
	COVERED = {'XmlWinEventLog': {'indexes': 'wineventlog', 'unit': b.unit_macro('XmlWinEventLog')},
			   'app:kv': {'indexes': 'app', 'unit': b.unit_macro('app:kv')}}

	def test_an_index_recorded_after_the_last_rebuild(self):
		assert b.rewrite_replay(self.COVERED, ['newidx']) == b.FULL
		assert b.rewrite_replay(self.COVERED, ['wineventlog', 'newidx']) == b.FULL
		assert b.rewrite_replay(self.COVERED, ['sec_*']) == b.FULL
		assert b.rewrite_replay(self.COVERED, ['wineventlog']) == b.compose_units(['XmlWinEventLog'])
		# no carrier anywhere: the text without replay
		assert b.rewrite_replay({}, ['newidx']) is None

	def test_a_sourcetype_whose_unit_did_not_run(self):
		covered = dict(self.COVERED, XmlWinEventLog={'indexes': 'wineventlog', 'unit': ''})
		assert b.rewrite_replay(covered, ['wineventlog']) == b.FULL
		assert b.rewrite_replay(covered, ['app']) == b.compose_units(['app:kv'])


FAILING_UNIT_SCENARIO = r'''
class OneUnitFails(FakeSplunk):
	"""The dry run of any search holding app:json's unit fails; everything else runs."""
	def rest(self, path, data=None, method=None):
		if path.endswith('/search/jobs') and data and 'tstats' not in data['search'] \
				and tenxreplay.builder.unit_macro('app:json') not in data['search'] and '"json"' in data['search'] \
				and 'mvindex(tenx_sourcetype,0)=="app:json"' in data['search'] and 'tenx-replay-u' not in data['search']:
			return {'results': [], 'messages': [{'type': 'FATAL', 'text': 'unit app:json broke'}]}
		return FakeSplunk.rest(self, path, data, method)

fake = OneUnitFails([('app:kv', '/var/app/a.log', 'web-1', 5, 'app', True),
					 ('app:json', '/var/other/b.log', 'api-1', 3, 'shared', True)])
try:
	run(fake)
except (SystemExit, AttributeError):
	pass
kv, js = tenxreplay.builder.unit_macro('app:kv'), tenxreplay.builder.unit_macro('app:json')
print(json.dumps([kv in fake.macros, js in fake.macros, fake.conf.get('app:kv', {}), fake.conf.get('app:json', {})]))
'''


def test_one_failing_unit_does_not_stop_the_others_or_the_index_record():
	kv_written, js_written, kv, js = child_run(FAILING_UNIT_SCENARIO)
	assert kv_written and kv.get('indexes') == 'app' and kv.get('unit') == b.unit_macro('app:kv')
	assert not js_written and js.get('indexes') == 'shared' and js.get('unit') == ''


class TestUnreadableCoverageIsTheFullReplay:
	"""A tenx_replay.conf read that fails other than with 404 gives tenx-replay: correct results first."""

	def test_unreadable(self):
		from test_replay_units import TestTheRewriteReadsTheCoverage as T
		import tenx_util
		covered = tenx_util.get_replay_coverage(T().service('fails'))
		assert covered is None
		assert b.rewrite_replay(covered, ['wineventlog']) == b.FULL
		_, text = compiled('index=wineventlog sourcetype=tenx_encoded EventCode=4625', covered)
		assert '`tenx-replay`' in text

	def test_absent_is_no_replay(self):
		from test_replay_units import TestTheRewriteReadsTheCoverage as T
		import tenx_util
		assert tenx_util.get_replay_coverage(T().service(None)) == {}
		assert b.rewrite_replay({}, ['wineventlog']) is None


# ---------------------------------------------------------------------------
# The negative record [tenx:nocarrier]
# ---------------------------------------------------------------------------

class TestThreeCases:
	COVERED = {'XmlWinEventLog': {'indexes': 'wineventlog', 'unit': b.unit_macro('XmlWinEventLog')},
			   'app:kv': {'indexes': 'app', 'unit': b.unit_macro('app:kv')},
			   b.NOCARRIER_STANZA: {'indexes': 'main,sec_compact,sec_compact4663', 'unit': ''}}

	def test_recorded_with_sourcetypes_chains_their_units(self):
		assert b.rewrite_replay(self.COVERED, ['wineventlog']) == b.compose_units(['XmlWinEventLog'])

	def test_recorded_as_having_none_is_no_replay(self):
		assert b.rewrite_replay(self.COVERED, ['sec_compact']) is None
		assert b.rewrite_replay(self.COVERED, ['sec_compact', 'main']) is None
		search = 'index=sec_compact sourcetype=tenx_encoded status=500 payment'
		assert compiled(search, self.COVERED) == compiled(search, False, baseline_builder)

	def test_unknown_is_the_full_replay(self):
		assert b.rewrite_replay(self.COVERED, ['newidx']) == b.FULL
		assert b.rewrite_replay(self.COVERED, ['sec_compact', 'newidx']) == b.FULL

	def test_wildcards_resolve_against_both_lists(self):
		assert b.rewrite_replay(self.COVERED, ['sec_*']) is None                  # only negative matches
		assert b.rewrite_replay(self.COVERED, ['win*']) == b.compose_units(['XmlWinEventLog'])
		assert b.rewrite_replay(self.COVERED, ['zz*']) == b.FULL                  # matches neither: unknown

	def test_a_positive_record_wins_over_a_stale_negative_one(self):
		covered = dict(self.COVERED, **{b.NOCARRIER_STANZA: {'indexes': 'wineventlog,main'}})
		assert b.rewrite_replay(covered, ['wineventlog']) == b.compose_units(['XmlWinEventLog'])

	def test_the_negative_record_is_bounded_busiest_first(self):
		counts = dict(('ix%03d' % i, i) for i in range(500))
		value = b.nocarrier_value(counts, {'ix499'})
		kept = value.split(',')
		assert len(kept) == b.MAX_NOCARRIER and 'ix499' not in kept and 'ix498' in kept and 'ix000' not in kept
		assert b.nocarrier_value({'a,b': 9, 'ok': 1}, set()) == 'ok'


TRANSITION_SCENARIO = r'''
def run_check(fake):
	cmd = tenxreplay.TenxReplayCommand()
	cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
		username='splunk-system-user', splunkd_uri='https://127.0.0.1:8089', session_key='key',
		earliest_time='-10m', latest_time='now'))
	cmd._apply, cmd._only_new, cmd._lookback = True, True, '-7d'
	cmd._rest = fake.rest
	fake.searches, fake.writes = [], []
	return list(cmd.generate())

class CheckOnly(FakeSplunk):
	"""Records the writes made before the check starts the full rebuild (its props read)."""
	def rest(self, path, data=None, method=None):
		if urllib.parse.urlparse(path).path == NS + 'configs/conf-props':
			self.at_rebuild = list(self.writes)
		return FakeSplunk.rest(self, path, data, method)

fake = CheckOnly([('app:kv', '/var/app/a.log', 'web-1', 5, 'app', True)])
fake.compact_only = {'quiet': 40, 'sec_compact': 7}
run(fake)
before = json.loads(json.dumps(fake.conf))
# between rebuilds, app:kv events with the field start arriving in index quiet
fake.rows = fake.rows + [('app:kv', '/var/app/a.log', 'web-1', 3, 'quiet', True)]
fake.compact_only = {'sec_compact': 7}
fake.at_rebuild = None
run_check(fake)
print(json.dumps([before.get('tenx:nocarrier'), fake.at_rebuild, fake.conf.get('tenx:nocarrier'),
				  fake.conf['app:kv']['indexes']]))
'''


def test_an_index_that_gets_the_field_leaves_the_negative_record_at_the_check():
	before, at_rebuild, after, kv_indexes = child_run(TRANSITION_SCENARIO)
	assert before == {'indexes': 'quiet,sec_compact'}
	# the 5-minute check itself, before the full rebuild begins, takes quiet out of the negative
	# record and adds it to app:kv's indexes: from that write on, the rewrite chains app:kv's unit
	assert at_rebuild is not None and ['conf~', 'tenx:nocarrier'] in at_rebuild and ['conf~', 'app:kv'] in at_rebuild, at_rebuild
	assert after == {'indexes': 'sec_compact'} and 'quiet' in kv_indexes.split(',')
	covered = {'app:kv': {'indexes': kv_indexes, 'unit': b.unit_macro('app:kv')},
			   'other': {'indexes': 'elsewhere', 'unit': b.unit_macro('other')}, b.NOCARRIER_STANZA: after}
	assert b.rewrite_replay(covered, ['quiet']) == b.compose_units(['app:kv'])
	# and before the check wrote, the same search had no replay: the window
	stale = dict(covered, **{'app:kv': {'indexes': 'app', 'unit': b.unit_macro('app:kv')},
						   b.NOCARRIER_STANZA: before})
	assert b.rewrite_replay(stale, ['quiet']) is None


# ---------------------------------------------------------------------------
# Compiled alerts: the check dispatches "Recompile Compiled Alerts" when the record changes
# ---------------------------------------------------------------------------

RECOMPILE_SCENARIO = r'''
def run_check(fake, apply=True):
	cmd = tenxreplay.TenxReplayCommand()
	cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
		username='splunk-system-user', splunkd_uri='https://127.0.0.1:8089', session_key='key',
		earliest_time='-10m', latest_time='now'))
	cmd._apply, cmd._only_new, cmd._lookback = apply, True, '-7d'
	cmd._rest = fake.rest
	fake.searches, fake.writes, fake.dispatches = [], [], []
	return list(cmd.generate())

out = {}
fake = FakeSplunk([('app:kv', '/var/app/a.log', 'web-1', 5, 'app', True)])
fake.compact_only = {'quiet': 40, 'sec_compact': 7}
fake.dispatches = []
run(fake)
out['first_rebuild'] = (fake.dispatches, len(fake.writes))
fake.dispatches = []
run(fake)
out['unchanged_rebuild'] = fake.dispatches
# last_seen moves every hour; that alone changes no compiled text
fake.conf['app:kv']['last_seen'] = '1000'
fake.dispatches = []
run(fake)
out['last_seen_only'] = (fake.dispatches, fake.writes)
rows = run_check(fake)
out['quiet_check'] = (fake.dispatches, rows[0].get('recompile_dispatched'))
# app:kv events with the field start arriving in index quiet, which the record lists as having none
fake.rows = fake.rows + [('app:kv', '/var/app/a.log', 'web-1', 3, 'quiet', True)]
fake.compact_only = {'sec_compact': 7}
rows = run_check(fake, apply=False)
out['dry_check'] = (fake.dispatches, fake.writes)
rows = run_check(fake)
out['moving_check'] = (fake.dispatches, fake.writes, rows[0].get('recompile_dispatched'), rows[0].get('written'))
out['again'] = (run_check(fake)[0].get('recompile_dispatched'), fake.dispatches)
# a stale negative record for an index the stanza already lists: the check alone fixes it
fake.conf['tenx:nocarrier'] = {'indexes': 'quiet,sec_compact'}
rows = run_check(fake)
out['check_only'] = (fake.dispatches, fake.writes, rows[0].get('recompile_dispatched'), rows[0].get('written'))
# a dispatch that fails is logged; the writes stand
fake.conf['tenx:nocarrier'] = {'indexes': 'quiet,sec_compact'}
fake.dispatch_fails = True
rows = run_check(fake)
out['failed_dispatch'] = (fake.writes, rows[0].get('recompile_dispatched'), fake.conf.get('tenx:nocarrier'))
print(json.dumps(out))
'''


def test_a_record_change_dispatches_the_recompile_once_and_only_then():
	out = child_run(RECOMPILE_SCENARIO)
	name = 'Recompile Compiled Alerts'
	# the first rebuild writes the app:kv stanza and the negative record: one dispatch, after them
	dispatches, writes = out['first_rebuild']
	assert dispatches == [[name, writes]], out['first_rebuild']
	assert out['unchanged_rebuild'] == []
	dispatches, writes = out['last_seen_only']
	assert ['conf~', 'app:kv'] in writes and dispatches == []
	assert out['quiet_check'] == [[], 'no']
	# apply=false writes nothing and dispatches nothing
	assert out['dry_check'] == [[], []]
	# the 5-minute check takes quiet out of the negative record and adds it to app:kv's indexes,
	# then dispatches once, right after those two writes
	dispatches, writes, flag, written = out['moving_check']
	assert ['conf~', 'tenx:nocarrier'] in writes and ['conf~', 'app:kv'] in writes
	# (app:kv in quiet is new to its stanza, so the full rebuild follows; it changes nothing more)
	assert dispatches == [[name, 2]] and flag == 'yes' and written == 'no change'
	assert out['again'] == ['no', []]
	assert out['check_only'] == [[[name, 1]], [['conf~', 'tenx:nocarrier']], 'yes', 'indexes recorded']
	writes, flag, nocarrier = out['failed_dispatch']
	assert ['conf~', 'tenx:nocarrier'] in writes and flag == 'no' and nocarrier == {'indexes': 'sec_compact'}


def test_the_recompile_search_named_exists():
	conf = configparser.RawConfigParser(strict=False)
	conf.read(os.path.join(APP, 'default', 'savedsearches.conf'))
	import tenx_replay_builder  # noqa: F401 (the command module needs splunk; read its constant as text)
	text = open(os.path.join(APP, 'bin', 'tenxreplay.py'), encoding='utf-8').read()
	assert "RECOMPILE_SEARCH = 'Recompile Compiled Alerts'" in text
	assert conf.has_section('Recompile Compiled Alerts')
	assert conf.get('Recompile Compiled Alerts', 'search').strip() == '| tenxrecompile'


# ---------------------------------------------------------------------------
# Index-time masking of the original sourcetype, recorded and reported
# ---------------------------------------------------------------------------

class TestMaskingIsRecorded:
	TRANSFORMS = {'mask_card': {'DEST_KEY': '_raw', 'REGEX': '(.*)card=\\d+(.*)', 'FORMAT': '$1card=xxxx$2'},
				  'route_index': {'DEST_KEY': '_MetaData:Index', 'REGEX': '.', 'FORMAT': 'other'}}

	def stanzas(self):
		return [b.Stanza('app:kv', {'SEDCMD-pw': 's/password=\\S+/password=xxx/g', 'TRANSFORMS-a': 'mask_card, route_index',
									'EVAL-k': '"x"'}, {}),
				b.Stanza('source::/var/app/*.log', {'SEDCMD-tok': 's/token=\\S+/token=xxx/'}, {}),
				b.Stanza('other:st', {'TRANSFORMS-r': 'route_index'}, {})]

	def test_sedcmd_and_raw_rewriting_transforms_are_found(self):
		assert b.masking_rules(self.stanzas()[:1], self.TRANSFORMS) == [
			'SEDCMD-pw in [app:kv]', 'TRANSFORMS-a (mask_card) in [app:kv]']
		# a transform that routes or sets metadata does not change the text
		assert b.masking_rules(self.stanzas()[2:], self.TRANSFORMS) == []

	def test_the_replay_reports_them_per_sourcetype(self):
		replay = b.build(self.stanzas(), [('app:kv', '/var/app/a.log', 'web-1'), ('other:st', '/x', 'h')],
						 transforms=self.TRANSFORMS)
		kv = replay.per_sourcetype['app:kv']
		assert kv['masking'] == ['SEDCMD-pw in [app:kv]', 'SEDCMD-tok in [source::/var/app/*.log]',
								 'TRANSFORMS-a (mask_card) in [app:kv]']
		assert any('masked at index time' in w and 'unmasked' in w for w in kv['warnings'])
		assert replay.per_sourcetype['other:st']['masking'] == []


MASK_SCENARIO = r'''
class MaskingSplunk(FakeSplunk):
	def rest(self, path, data=None, method=None):
		route = urllib.parse.urlparse(path).path
		if route == NS + 'configs/conf-props':
			out = FakeSplunk.rest(self, path, data, method)
			out['entry'][0]['content']['SEDCMD-pw'] = 's/password=\\S+/password=xxx/g'
			return out
		return FakeSplunk.rest(self, path, data, method)

fake = MaskingSplunk([('app:kv', '/var/app/a.log', 'web-1', 5, 'app', True), ('app:json', '/var/other/b.log', 'api-1', 3, 'shared', True)])
rows = run(fake)
print(json.dumps([fake.conf['app:kv'].get('masked_at_index_time'), fake.conf['app:json'].get('masked_at_index_time'),
				  [r['masked_at_index_time'] for r in rows if r['sourcetype'] == 'app:kv']]))
'''


def test_the_record_holds_the_masking_rules_of_each_sourcetype():
	kv, js, row = child_run(MASK_SCENARIO)
	assert kv == 'SEDCMD-pw in [app:kv]' and js == '' and row == [['SEDCMD-pw in [app:kv]']]


def test_the_diagnostics_dashboard_lists_them():
	text = open(os.path.join(APP, 'default', 'data', 'ui', 'views', 'tenx_diagnostics.xml'), encoding='utf-8').read()
	assert 'Original Sourcetypes Masked at Index Time' in text and 'masked_at_index_time' in text
	spec = open(os.path.join(APP, 'README', 'tenx_replay.conf.spec'), encoding='utf-8').read()
	assert 'masked_at_index_time = ' in spec
