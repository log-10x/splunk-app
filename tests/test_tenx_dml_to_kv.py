"""
The template alert action must not write anything when the app's configuration cannot be
read: on the built-in defaults it would store templates in the wrong index and collection.
"""

import tenx_dml_to_kv
import tenx_util
import tenx_consts


def test_refuses_to_store_when_the_configuration_cannot_be_read(monkeypatch):
	calls = []

	def unreadable_config(**kwargs):
		config = dict(tenx_consts.DEFAULT_CONFIG)
		config[tenx_util.CONFIG_LOADED] = False
		return config

	class Recorder:
		def __init__(self, *args, **kwargs):
			calls.append((args, kwargs))

	monkeypatch.setattr(tenx_util, 'get_tenx_config', unreadable_config)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_dml_intf, 'TenxDmlInterface', Recorder)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_kv_intf, 'TenxKVInterface', Recorder)

	result = tenx_dml_to_kv.update_kv_store({'server_uri': 'https://x', 'session_key': 'k'})

	assert result == -1
	assert calls == []


def test_the_fallback_defaults_match_the_shipped_configuration():
	import configparser, os
	conf = configparser.ConfigParser(interpolation=None)
	conf.read(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'default', 'tenx_config.conf'))
	for key in ('dest_dml_index', 'dml_source_type', 'collection_name'):
		assert tenx_consts.DEFAULT_CONFIG[key] == conf.get('config', key), key


class StoreKV:
	"""A KV collection held in memory, keyed the way TenxKVInterface keys it."""
	KV_KEY = '_key'

	def __init__(self, *args, **kwargs):
		self.records = {}
		self.updates = []
		self.writes = []
		self.finds = 0
		self.fail_after = None
		StoreKV.last = self

	def kv_key(self, record_key):
		return record_key.strip()

	def get_entry(self, record_key):
		record = self.records.get(self.kv_key(record_key))
		return dict(record, _user='nobody') if record is not None else None

	def get_record(self, record_key):
		if getattr(self, 'unreadable', False):
			raise RuntimeError('KV store not ready')
		return self.get_entry(record_key)

	def batch_limits(self):
		return 1000, 50.0

	def find_many(self, keys):
		self.finds += 1
		return {k: dict(self.records[k], _user='nobody') for k in keys if k in self.records}

	def save_many(self, records, limits=None):
		if self.fail_after is not None and len(self.writes) + len(records) > self.fail_after:
			return False
		for record in records:
			key = record['_key']
			if key in self.records:
				self.updates.append(key)
			self.writes.append(key)
			self.records[key] = dict(record)
		return True

	def save_batch(self, records):
		return self.save_many(records)


class PureCopies:
	def __init__(self, *args, **kwargs):
		self.writes = 0
		PureCopies.last = self

	def write_pending(self, known=None, deadline=None):
		self.writes += 1
		return 0

	def any_pending(self):
		return False


def fill(monkeypatch, tmp_path, records, kv=None):
	return fill_rows(monkeypatch, tmp_path, [{'_raw': '', 'templateHash': h, 'template': t} for h, t in records], kv)


def fill_rows(monkeypatch, tmp_path, rows, kv=None):
	import csv, gzip
	path = tmp_path / 'results.csv.gz'
	with gzip.open(path, 'wt', newline='') as f:
		writer = csv.DictWriter(f, fieldnames=['_raw', 'templateHash', 'template'])
		writer.writeheader()
		for row in rows:
			writer.writerow(row)

	config = dict(tenx_consts.DEFAULT_CONFIG)
	config[tenx_util.CONFIG_LOADED] = True
	monkeypatch.setattr(tenx_util, 'get_tenx_config', lambda **kwargs: config)
	monkeypatch.setattr(tenx_util, 'ServerConnection', lambda **kwargs: None)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_kv_intf, 'TenxKVInterface', (lambda *a, **k: kv) if kv else StoreKV)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_dml_intf, 'TenxDmlInterface', PureCopies)

	settings = {'server_uri': 'https://x', 'session_key': 'k', 'results_file': str(path), 'server_host': 'h'}
	return tenx_dml_to_kv.update_kv_store(settings)


TEMPLATE_A = '$(yyyy-MM-dd HH:mm:ss) INFO payment $ declined'
TEMPLATE_B = '$(yyyy-MM-dd HH:mm:ss) INFO refund $ approved'


def test_a_second_template_under_one_hash_marks_the_key_and_keeps_its_events_compact(monkeypatch, tmp_path, caplog):
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A), ('-Abc123xyz', TEMPLATE_B)])
	record = StoreKV.last.records['-Abc123xyz']

	assert record['expand_unsafe'] == 'hash-conflict'
	assert record['pattern'] == TEMPLATE_A
	assert record['search_copy'] == 'pending'
	assert PureCopies.last.writes == 1
	assert any('hash conflict' in r.getMessage() for r in caplog.records if r.levelname == 'WARNING')


def test_the_same_template_sent_again_changes_nothing(monkeypatch, tmp_path):
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A), ('-Abc123xyz', TEMPLATE_A)])

	assert StoreKV.last.records['-Abc123xyz']['expand_unsafe'] == ''
	assert StoreKV.last.updates == []
	assert StoreKV.last.writes == ['-Abc123xyz']


def test_two_hashes_that_trim_to_one_key_are_a_conflict(monkeypatch, tmp_path):
	fill(monkeypatch, tmp_path, [('Abc123xyz ', TEMPLATE_A), ('Abc123xyz', TEMPLATE_B)])

	assert StoreKV.last.records['Abc123xyz']['expand_unsafe'] == 'hash-conflict'


def test_a_conflict_is_marked_once(monkeypatch, tmp_path):
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A), ('-Abc123xyz', TEMPLATE_B), ('-Abc123xyz', TEMPLATE_B)])

	assert StoreKV.last.writes == ['-Abc123xyz']
	assert StoreKV.last.records['-Abc123xyz']['expand_unsafe'] == 'hash-conflict'


def test_a_conflict_with_a_stored_template_is_marked_once(monkeypatch, tmp_path):
	kv = StoreKV()
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A)], kv=kv)
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_B), ('-Abc123xyz', TEMPLATE_B)], kv=kv)

	assert kv.updates == ['-Abc123xyz']


def test_a_stored_template_cut_short_is_replaced_by_the_whole_one(monkeypatch, tmp_path):
	whole = TEMPLATE_A + ' for order $ after $ retries'
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A[:30]), ('-Abc123xyz', whole)])
	record = StoreKV.last.records['-Abc123xyz']

	assert record['pattern'] == whole
	assert record['expand_unsafe'] == ''


def test_a_conflict_on_an_earlier_run_is_found_on_a_later_one(monkeypatch, tmp_path):
	kv = StoreKV()
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A)], kv=kv)
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_B)], kv=kv)

	assert kv.records['-Abc123xyz']['expand_unsafe'] == 'hash-conflict'


def test_a_whole_template_replacing_a_cut_one_gets_a_new_searchable_copy(monkeypatch, tmp_path):
	whole = TEMPLATE_A + ' for order $ after $ retries'
	kv = StoreKV()
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A[:30])], kv=kv)
	kv.records['-Abc123xyz']['search_copy'] = 'written'
	fill(monkeypatch, tmp_path, [('-Abc123xyz', whole)], kv=kv)

	assert kv.records['-Abc123xyz']['search_copy'] == 'pending'


def test_a_cut_re_send_of_a_stored_whole_template_is_not_a_conflict(monkeypatch, tmp_path):
	whole = TEMPLATE_A + ' for order $ after $ retries'
	fill(monkeypatch, tmp_path, [('-Abc123xyz', whole), ('-Abc123xyz', whole[:40])])
	record = StoreKV.last.records['-Abc123xyz']

	assert record['pattern'] == whole
	assert record['expand_unsafe'] == ''
	assert StoreKV.last.updates == []

def test_an_upgrade_refreshes_a_record_whose_derived_fields_changed(monkeypatch, tmp_path):
	# A record stored by an older build: the unpadded day was zero-padded (%d for d).
	template = '$(MMM  d HH:mm:ss) web01 sshd[$]: Failed password for $'
	kv = StoreKV()
	import tenx_dml_builder
	record = tenx_dml_builder.TenxDMLBuilder(timestamp_placeholder='__TENX_TS__', variable_separator='$').build_kv_record_data('-Sys1', template)
	record['timestamp_format'] = '%b  %d %H:%M:%S'
	record['search_copy'] = 'written'
	kv.records['-Sys1'] = dict(record, _key='-Sys1')

	fill(monkeypatch, tmp_path, [('-Sys1', template)], kv=kv)
	stored = kv.records['-Sys1']

	assert stored['timestamp_format'] == '%b  %-d %H:%M:%S'
	assert stored['search_copy'] == 'written'
	assert kv.updates == ['-Sys1']


def test_a_refresh_keeps_a_hash_conflict_mark(monkeypatch, tmp_path):
	kv = StoreKV()
	import tenx_dml_builder
	record = tenx_dml_builder.TenxDMLBuilder(timestamp_placeholder='__TENX_TS__', variable_separator='$').build_kv_record_data('-Abc123xyz', TEMPLATE_A)
	record['expand_unsafe'] = 'hash-conflict'
	record['timestamp_format'] = 'stale'
	kv.records['-Abc123xyz'] = dict(record, _key='-Abc123xyz')

	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A)], kv=kv)

	assert kv.records['-Abc123xyz']['expand_unsafe'] == 'hash-conflict'
	assert kv.records['-Abc123xyz']['timestamp_format'] == '%Y-%m-%d %H:%M:%S'



# ---------------------------------------------------------------------------------------------
# Consume KV: the alert action reads the template records itself, from a checkpoint of index
# time, in slices, and writes in batches (a scheduled window with a result cap skipped records
# when more than 10,000 arrived in one run).
# ---------------------------------------------------------------------------------------------

import collections
import json
import re
import time

import pytest


class FakeSplunk:
	"""search/jobs/export over template records held as (index time, hash, template)."""

	def __init__(self, records):
		self.records = list(records)
		self.searches = []

	def post(self, url, data, params=None, output_mode='json', read_result=True):
		assert url.endswith('/search/jobs/export') and not read_result
		search = data['search']
		self.searches.append(search)
		a = int(re.search(r'_index_earliest=(\d+)', search).group(1))
		b = int(re.search(r'_index_latest=(\d+)', search).group(1))
		rows = [r for r in self.records if a <= r[0] < b]
		if 'stats count by tenx_kv_step' in search:
			step = int(re.search(r'_indextime%(\d+)', search).group(1))
			counts = collections.Counter(t - t % step for t, _, _ in rows)
			lines = [{'result': {'tenx_kv_step': str(m), 'count': str(c)}} for m, c in counts.items()]
		else:
			lines = [{'preview': False, 'result': {'templateHash': h, 'template': p, '_indextime': str(t)}} for t, h, p in rows]
		return [(json.dumps(line) + '\n').encode() for line in lines]


def consume(monkeypatch, tmp_path, splunk, kv, state, configuration=None):
	import gzip
	path = tmp_path / 'trigger.csv.gz'
	with gzip.open(path, 'wt') as f:
		f.write('_time\n1794850000\n')

	config = dict(tenx_consts.DEFAULT_CONFIG)
	config[tenx_util.CONFIG_LOADED] = True
	monkeypatch.setattr(tenx_util, 'get_tenx_config', lambda **kwargs: config)
	monkeypatch.setattr(tenx_util, 'ServerConnection', lambda **kwargs: splunk)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_kv_intf, 'TenxKVInterface',
		lambda collection_name, **k: state if collection_name == 'tenx_kv_state' else kv)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_dml_intf, 'TenxDmlInterface', PureCopies)

	settings = {'server_uri': 'https://x', 'session_key': 'k', 'results_file': str(path), 'server_host': 'h',
				'configuration': configuration or {}}
	return tenx_dml_to_kv.update_kv_store(settings)


def flood(count, start, per_second=200, prefix='-H'):
	"""count distinct templates, per_second of them indexed each second from start."""
	return [(start + i // per_second, '%s%07d' % (prefix, i), '$(yyyy-MM-dd HH:mm:ss) INFO job %d took $ ms' % i)
			for i in range(count)]


def test_a_flood_of_thirty_thousand_templates_in_one_run_is_stored_in_full(monkeypatch, tmp_path):
	base = int(time.time()) - 3600
	records = flood(30000, base)
	records += records[:5000]  # every Receiver start sends its templates again
	splunk, kv, state = FakeSplunk(records), StoreKV(), StoreKV()

	read = consume(monkeypatch, tmp_path, splunk, kv, state)

	assert read == 35000
	assert len(kv.records) == 30000
	assert len(kv.writes) == 30000
	stored = state.records['consume_kv']
	assert stored['status'] == 'current'
	assert stored['loaded_through'] == max(t for t, _, _ in records) + 1


def test_a_second_run_reads_the_overlap_and_writes_nothing(monkeypatch, tmp_path):
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(3000, base)), StoreKV(), StoreKV()
	consume(monkeypatch, tmp_path, splunk, kv, state)
	writes = len(kv.writes)

	consume(monkeypatch, tmp_path, splunk, kv, state)

	assert len(kv.writes) == writes
	assert len(kv.records) == 3000


def test_the_first_run_reads_from_the_start_of_the_index(monkeypatch, tmp_path):
	# An upgrade from a version without the checkpoint: records its seven-minute window skipped
	# are hours or months old by index time, and are stored.
	old = flood(100, 1700000000, prefix='-Old')
	splunk, kv, state = FakeSplunk(old), StoreKV(), StoreKV()

	before = int(time.time())
	consume(monkeypatch, tmp_path, splunk, kv, state)

	assert len(kv.records) == 100
	assert '_index_earliest=0 ' in splunk.searches[0]
	# the time this version first ran, which the tx prefilter reads (it checks the lookup on the indexers
	# for some minutes after it); a later run of the same version keeps it
	since = state.records['consume_kv']['version_since']
	assert before <= int(since) <= int(time.time())
	consume(monkeypatch, tmp_path, splunk, kv, state)
	assert state.records['consume_kv']['version_since'] == since


def test_a_run_that_stops_is_resumed_from_the_checkpoint(monkeypatch, tmp_path):
	monkeypatch.setattr(tenx_dml_to_kv, 'SLICE_RECORDS', 1000)
	monkeypatch.setattr(tenx_dml_to_kv, 'RUN_BUDGET_SECONDS', -1)
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(5000, base, per_second=10)), StoreKV(), StoreKV()

	consume(monkeypatch, tmp_path, splunk, kv, state)

	first = len(kv.records)
	assert 0 < first < 5000
	assert state.records['consume_kv']['status'] == 'loading'

	monkeypatch.setattr(tenx_dml_to_kv, 'RUN_BUDGET_SECONDS', 10000)
	consume(monkeypatch, tmp_path, splunk, kv, state)

	assert len(kv.records) == 5000
	assert state.records['consume_kv']['status'] == 'current'


def test_a_store_that_refuses_a_write_keeps_the_checkpoint_before_it(monkeypatch, tmp_path):
	monkeypatch.setattr(tenx_dml_to_kv, 'SLICE_RECORDS', 1000)
	base = int(time.time()) - 3600
	records = flood(3000, base, per_second=10)
	splunk, kv, state = FakeSplunk(records), StoreKV(), StoreKV()
	kv.fail_after = 1500

	assert consume(monkeypatch, tmp_path, splunk, kv, state) == -1

	stored = state.records['consume_kv']
	assert stored['status'] == 'failed'
	# every record before the checkpoint is stored
	assert all(h in kv.records for t, h, _ in records if t < stored['loaded_through'])

	kv.fail_after = None
	consume(monkeypatch, tmp_path, splunk, kv, state)

	assert len(kv.records) == 3000


def test_a_record_indexed_late_within_the_overlap_is_read(monkeypatch, tmp_path):
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(100, base)), StoreKV(), StoreKV()
	consume(monkeypatch, tmp_path, splunk, kv, state)
	through = state.records['consume_kv']['loaded_through']

	# an indexer whose clock is behind stamps a later record with an earlier index time
	splunk.records.append((through - 200, '-Late', TEMPLATE_A))
	consume(monkeypatch, tmp_path, splunk, kv, state)

	assert '-Late' in kv.records


def test_the_from_parameter_loads_again_from_that_index_time(monkeypatch, tmp_path):
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(100, base - 7200) + flood(10, base, prefix='-New')), StoreKV(), StoreKV()
	consume(monkeypatch, tmp_path, splunk, kv, state)
	del kv.records['-H0000007']  # the collection lost a record indexed two hours before the last one

	consume(monkeypatch, tmp_path, splunk, kv, state)
	assert '-H0000007' not in kv.records  # the checkpoint is past it

	consume(monkeypatch, tmp_path, splunk, kv, state, configuration={'from': '0'})
	assert '-H0000007' in kv.records


def test_the_source_parameter_is_the_search_the_records_are_read_with(monkeypatch, tmp_path):
	splunk, kv, state = FakeSplunk(flood(10, int(time.time()) - 3600)), StoreKV(), StoreKV()

	consume(monkeypatch, tmp_path, splunk, kv, state, configuration={'source': 'index=tmpl sourcetype=tenx_dml_raw_json'})

	assert all(s.startswith('search index=tmpl sourcetype=tenx_dml_raw_json _index_earliest=') for s in splunk.searches)


def test_a_source_that_is_not_an_event_search_is_refused(monkeypatch, tmp_path):
	splunk, kv, state = FakeSplunk([]), StoreKV(), StoreKV()

	assert consume(monkeypatch, tmp_path, splunk, kv, state, configuration={'source': '| inputlookup x'}) == -1
	assert splunk.searches == []


def test_records_in_the_results_are_read_from_raw_when_their_fields_are_wrong(monkeypatch, tmp_path):
	# The later rows of a large results file can carry an empty template, or another row's, beside a whole _raw.
	records = [('-H%07d' % i, TEMPLATE_A + ' %d' % i) for i in range(3000)]
	rows = []
	for i, (template_hash, template) in enumerate(records):
		row = {'_raw': json.dumps({'templateHash': template_hash, 'template': template}), 'templateHash': template_hash, 'template': template}
		if i >= 2000:
			row['template'] = ''
		elif i >= 1000:
			row['templateHash'] = records[i - 1000][0]
		rows.append(row)

	assert fill_rows(monkeypatch, tmp_path, rows) == 3000
	stored = StoreKV.last.records
	assert {k: r['pattern'] for k, r in stored.items()} == dict(records)
	assert not any(r.get('expand_unsafe') for r in stored.values())


def test_a_result_without_a_template_record_in_raw_is_read_from_its_fields(monkeypatch, tmp_path):
	fill_rows(monkeypatch, tmp_path, [{'_raw': '{"event": "~-Abc123xyz,1"}', 'templateHash': '-Abc123xyz', 'template': TEMPLATE_A}])

	assert StoreKV.last.records['-Abc123xyz']['pattern'] == TEMPLATE_A


def test_a_result_whose_raw_nests_too_deep_to_parse_is_read_from_its_fields(monkeypatch, tmp_path):
	fill_rows(monkeypatch, tmp_path, [{'_raw': '{"a":' + '[' * 20000 + ']' * 20000 + '}', 'templateHash': '-Abc123xyz', 'template': TEMPLATE_A}])

	assert StoreKV.last.records['-Abc123xyz']['pattern'] == TEMPLATE_A


def test_records_in_the_results_are_stored_in_batches(monkeypatch, tmp_path):
	kv = StoreKV()
	fill(monkeypatch, tmp_path, [('-H%07d' % i, TEMPLATE_A + ' %d' % i) for i in range(4500)], kv=kv)

	assert len(kv.records) == 4500
	assert kv.finds == 3  # one batch_find per 2,000 records


def test_a_minute_over_the_slice_size_is_cut_by_second(monkeypatch, tmp_path):
	monkeypatch.setattr(tenx_dml_to_kv, 'SLICE_RECORDS', 1000)
	base = int(time.time()) - 3600
	base -= base % 60
	splunk, kv, state = FakeSplunk(flood(5000, base, per_second=100)), StoreKV(), StoreKV()

	consume(monkeypatch, tmp_path, splunk, kv, state)

	reads = [q for q in splunk.searches if 'fields templateHash' in q]
	assert len(reads) == 5
	assert len(kv.records) == 5000


def test_slices_split_at_minutes_and_cover_the_range():
	minutes = [(60, 10), (120, 30000), (180, 5), (240, 20000), (300, 20000)]
	slices = tenx_dml_to_kv.plan_slices(minutes, 30, 400, slice_records=25000)

	assert slices[0][0] == 30 and slices[-1][1] == 400
	assert all(a[1] == b[0] for a, b in zip(slices, slices[1:]))
	assert sum(n for _, _, n in slices) == 70015
	assert tenx_dml_to_kv.plan_slices([], 30, 400) == [(30, 400, 0)]


def test_save_many_keeps_each_call_within_the_kv_store_limits():
	import tenx_kv_intf

	calls = []

	class Conn:
		def post(self, url, data, **kwargs):
			calls.append(json.loads(data))
			return None

	kv = tenx_kv_intf.TenxKVInterface('tenx_dml', Conn(), 'nobody', 'tenx-for-splunk')
	records = [{'_key': 'k%d' % i, 'pattern': 'x' * 900} for i in range(2500)]

	assert kv.save_many(records, limits=(1000, 1.0))
	assert sum(len(c) for c in calls) == 2500
	assert all(len(c) <= 1000 and len(json.dumps(c)) <= 1024 * 1024 // 2 for c in calls)


def test_find_many_reads_with_batch_find_and_raises_when_it_cannot():
	import tenx_kv_intf

	class Conn:
		def __init__(self, answer):
			self.answer = answer
			self.bodies = []

		def post(self, url, data, **kwargs):
			assert url.endswith('/storage/collections/data/tenx_dml/batch_find')
			self.bodies.append(json.loads(data))
			return self.answer

	conn = Conn([[{'_key': 'a', 'pattern': 'p'}]])
	kv = tenx_kv_intf.TenxKVInterface('tenx_dml', conn, 'nobody', 'tenx-for-splunk')
	assert kv.find_many(['a', 'b', 'a']) == {'a': {'_key': 'a', 'pattern': 'p'}}
	assert conn.bodies == [[{'query': {'_key': {'$in': ['a', 'b']}}}]]

	kv = tenx_kv_intf.TenxKVInterface('tenx_dml', Conn({'messages': [{'type': 'ERROR'}]}), 'nobody', 'tenx-for-splunk')
	with pytest.raises(RuntimeError):
		kv.find_many(['a'])


# The message `tx` shows when the template store can lack templates (tenxprefilter).

def test_tx_warns_while_consume_kv_is_behind_or_failed():
	import tenx_prefilter_parser as parser
	now = 1794856000

	assert parser.store_warning({}, now) is None
	assert parser.store_warning({'updated': now - 60, 'loaded_through': now - 90, 'status': 'current'}, now) is None
	loading = parser.store_warning({'updated': now - 60, 'loaded_through': now - 4000, 'status': 'loading'}, now)
	assert 'still storing templates indexed after' in loading
	failed = parser.store_warning({'updated': now - 60, 'loaded_through': now - 90, 'status': 'failed', 'detail': 'KV store down'}, now)
	assert 'KV store down' in failed and 'stay compact' in failed
	stale = parser.store_warning({'updated': now - 3600, 'loaded_through': now - 3600, 'status': 'current'}, now)
	assert 'has not run since' in stale
	assert parser.store_warning({'updated': 'x'}, now) is None


def test_a_record_this_version_compared_already_is_not_built_again(monkeypatch, tmp_path):
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(500, base)), StoreKV(), StoreKV()
	consume(monkeypatch, tmp_path, splunk, kv, state)

	import tenx_dml_builder
	built = []
	real = tenx_dml_builder.TenxDMLBuilder.build_kv_record_data
	monkeypatch.setattr(tenx_dml_builder.TenxDMLBuilder, 'build_kv_record_data', lambda self, *a: built.append(a) or real(self, *a))
	consume(monkeypatch, tmp_path, splunk, kv, state)

	assert built == []


def test_an_upgrade_reads_every_record_again_and_refreshes_what_it_derives(monkeypatch, tmp_path):
	template = '$(MMM  d HH:mm:ss) web01 sshd[$]: Failed password for $'
	old = [(1700000000, '-Sys1', template)]
	splunk, kv, state = FakeSplunk(old + flood(10, int(time.time()) - 3600)), StoreKV(), StoreKV()
	monkeypatch.setattr(tenx_dml_to_kv, 'app_version', lambda: '1.2.2')
	consume(monkeypatch, tmp_path, splunk, kv, state)
	kv.records['-Sys1']['timestamp_format'] = '%b  %d %H:%M:%S'  # what an older build derived

	consume(monkeypatch, tmp_path, splunk, kv, state)
	assert kv.records['-Sys1']['timestamp_format'] == '%b  %d %H:%M:%S'  # same version: not compared again

	monkeypatch.setattr(tenx_dml_to_kv, 'app_version', lambda: '1.2.3')
	consume(monkeypatch, tmp_path, splunk, kv, state)
	assert kv.records['-Sys1']['timestamp_format'] == '%b  %-d %H:%M:%S'
	assert state.records['consume_kv']['version'] == '1.2.3'
	assert state.records['consume_kv']['status'] == 'current'


def test_save_many_writes_every_batch_when_calls_run_at_once():
	import tenx_kv_intf
	import threading

	seen, lock = [], threading.Lock()

	class Conn:
		def post(self, url, data, **kwargs):
			with lock:
				seen.extend(r['_key'] for r in json.loads(data))
			return None

	kv = tenx_kv_intf.TenxKVInterface('tenx_dml', Conn(), 'nobody', 'tenx-for-splunk')
	assert kv.save_many([{'_key': 'k%d' % i} for i in range(10500)], limits=(1000, 50.0))
	assert sorted(seen) == sorted('k%d' % i for i in range(10500))


def test_an_idle_run_reads_the_records_before_the_checkpoint_again_once(monkeypatch, tmp_path):
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(200, base)), StoreKV(), StoreKV()
	consume(monkeypatch, tmp_path, splunk, kv, state)
	reads = lambda: [q for q in splunk.searches if 'fields templateHash' in q]

	# the checkpoint moved an hour ago (this host's clock): the next run reads the overlap once
	state.records['consume_kv']['advanced_at'] = int(time.time()) - 3600
	splunk.searches.clear()
	consume(monkeypatch, tmp_path, splunk, kv, state)
	assert len(reads()) == 1
	assert state.records['consume_kv']['rechecked'] == 1

	splunk.searches.clear()
	consume(monkeypatch, tmp_path, splunk, kv, state)
	assert reads() == []

	# a record an indexer makes visible late, before the checkpoint, after an outage of Consume KV
	state.records['consume_kv']['rechecked'] = 0
	splunk.records.append((state.records['consume_kv']['loaded_through'] - 100, '-Late', TEMPLATE_A))
	consume(monkeypatch, tmp_path, splunk, kv, state)
	assert '-Late' in kv.records


def test_the_overlap_is_read_again_while_the_checkpoint_moved_recently(monkeypatch, tmp_path):
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(200, base)), StoreKV(), StoreKV()
	consume(monkeypatch, tmp_path, splunk, kv, state)
	splunk.searches.clear()

	consume(monkeypatch, tmp_path, splunk, kv, state)

	assert len([q for q in splunk.searches if 'fields templateHash' in q]) == 1
	assert state.records['consume_kv']['rechecked'] == 0


def test_a_checkpoint_that_cannot_be_read_is_not_taken_for_a_first_run(monkeypatch, tmp_path):
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(100, base)), StoreKV(), StoreKV()
	consume(monkeypatch, tmp_path, splunk, kv, state)
	through = state.records['consume_kv']['loaded_through']
	splunk.searches.clear()

	state.unreadable = True
	assert consume(monkeypatch, tmp_path, splunk, kv, state) == -1

	assert splunk.searches == []
	assert state.records['consume_kv']['loaded_through'] == through


class KVCopies:
	"""The searchable copy over a StoreKV: copies every pending record and marks it written."""

	def __init__(self, kv):
		self.kv = kv
		self.copied = []

	def __call__(self, *args, **kwargs):
		return self

	def any_pending(self):
		return any(r.get('search_copy') == 'pending' for r in self.kv.records.values())

	def write_pending(self, known=None, deadline=None):
		keys = [k for k, r in self.kv.records.items() if r.get('search_copy') == 'pending']
		for k in keys:
			self.kv.records[k] = dict(self.kv.records[k], search_copy='written')
		self.copied.extend(keys)
		return len(keys)


def test_a_run_with_no_new_records_writes_the_copies_an_earlier_run_left(monkeypatch, tmp_path):
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(3000, base)), StoreKV(), StoreKV()
	# a run that stored the templates and stopped before writing any copy
	consume(monkeypatch, tmp_path, splunk, kv, state)
	assert all(r['search_copy'] == 'pending' for r in kv.records.values())
	state.records['consume_kv']['rechecked'] = 1  # nothing to read again: no new record either

	copies = KVCopies(kv)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_dml_intf, 'TenxDmlInterface', copies)
	config = dict(tenx_consts.DEFAULT_CONFIG)
	import gzip
	path = tmp_path / 'trigger2.csv.gz'
	with gzip.open(path, 'wt') as f:
		f.write('_time\n1794850000\n')
	splunk.searches.clear()
	read = tenx_dml_to_kv.update_kv_store({'server_uri': 'https://x', 'session_key': 'k', 'results_file': str(path), 'configuration': {}})

	assert read == 0
	assert [q for q in splunk.searches if 'fields templateHash' in q] == []
	assert len(copies.copied) == 3000
	assert state.records['consume_kv']['status'] == 'current'


def test_a_run_stopped_from_outside_is_reported_by_the_next(monkeypatch, tmp_path, caplog):
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(100, base)), StoreKV(), StoreKV()
	consume(monkeypatch, tmp_path, splunk, kv, state)
	# a run that started and never ended
	state.records['consume_kv']['run_started'] = state.records['consume_kv']['run_ended'] + 60

	consume(monkeypatch, tmp_path, splunk, kv, state)

	assert any('did not finish' in r.getMessage() for r in caplog.records if r.levelname == 'WARNING')
	assert 'did not finish' in state.records['consume_kv']['last_cut']
	assert state.records['consume_kv']['run_ended'] >= state.records['consume_kv']['run_started']


def test_a_run_that_ends_with_copies_pending_does_not_say_current(monkeypatch, tmp_path):
	class Stuck(PureCopies):
		def any_pending(self):
			return True

	monkeypatch.setattr(tenx_dml_to_kv.tenx_dml_intf, 'TenxDmlInterface', Stuck)
	base = int(time.time()) - 3600
	splunk, kv, state = FakeSplunk(flood(100, base)), StoreKV(), StoreKV()
	import gzip
	path = tmp_path / 't.csv.gz'
	with gzip.open(path, 'wt') as f:
		f.write('_time\n1\n')
	config = dict(tenx_consts.DEFAULT_CONFIG)
	config[tenx_util.CONFIG_LOADED] = True
	monkeypatch.setattr(tenx_util, 'get_tenx_config', lambda **kwargs: config)
	monkeypatch.setattr(tenx_util, 'ServerConnection', lambda **kwargs: splunk)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_kv_intf, 'TenxKVInterface',
		lambda collection_name, **k: state if collection_name == 'tenx_kv_state' else kv)
	tenx_dml_to_kv.update_kv_store({'server_uri': 'https://x', 'session_key': 'k', 'results_file': str(path), 'configuration': {}})

	assert state.records['consume_kv']['status'] == 'loading'
	assert 'searchable copies are still pending' in state.records['consume_kv']['detail']


def test_the_action_sets_limits_above_splunks_defaults():
	import configparser, os
	conf = configparser.RawConfigParser(strict=False, interpolation=None)
	conf.read(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'default', 'alert_actions.conf'))
	assert int(conf.get('tenx_dml_to_kv', 'maxresults')) >= 1000000
	assert conf.get('tenx_dml_to_kv', 'maxtime') == '10m'
	# a run stops itself, with its last slice and copies, well inside maxtime
	assert tenx_dml_to_kv.RUN_BUDGET_SECONDS + tenx_dml_to_kv.COPY_GRACE_SECONDS + 120 < 600
