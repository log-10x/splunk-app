"""
The searchable copy of each template is written with `collect` as sourcetype stash, which
Splunk does not count against the licence. A record is marked written only when the copy
search returned its key, so a failed write leaves it pending for the next run.
"""
import json

import tenx_dml_intf
from tenx_kv_intf import TenxKVInterface


class FakeConnection:
	"""
	The KV store's data endpoint as measured: a read returns the matching records sorted by sort, from
	skip, at most limit of them, and never more than read_cap (the rows that fit in max_size_per_result_mb).
	"""
	def __init__(self, pending, copied=None, fail_search=False, read_cap=None):
		self.pending = pending
		self.copied = copied
		self.fail_search = fail_search
		self.read_cap = read_cap
		self.searches = []
		self.batches = []
		self.reads = []

	def get(self, url, params=None, output_mode="json"):
		assert json.loads(params['query']) == {'search_copy': 'pending'}
		self.reads.append(dict(params))
		rows = [dict(r) for r in self.pending]
		if params.get('sort') == '_key':
			rows.sort(key=lambda r: r['_key'])
		rows = rows[int(params.get('skip', 0)):]
		limit = int(params.get('limit', 0)) or len(rows)
		return rows[:min(limit, self.read_cap or len(rows))]

	def post(self, url, data, params=None, output_mode="json", read_result=True):
		if url.endswith('/search/jobs'):
			self.searches.append(data)
			if self.fail_search:
				raise RuntimeError('search failed')
			keys = self.copied if self.copied is not None else [r['_key'] for r in self.pending]
			return {'results': [{'_key': k} for k in keys]}
		if url.endswith('/batch_save'):
			self.batches.append(json.loads(data))
			return {}
		raise AssertionError('unexpected post to ' + url)


def writer(conn):
	kv = TenxKVInterface(collection_name='tenx_dml', server_connection=conn, owner='nobody', app_name='tenx-for-splunk')
	return tenx_dml_intf.TenxDmlInterface(server_connection=conn, kv_intf=kv, app_name='tenx-for-splunk',
		lookup_name='tenx-dml-lookup', index_name='tenx_dml', source='tenx_dml_pure')


def record(key):
	return {'_key': key, '_user': 'nobody', 'pattern_hash': key, 'pattern': 'p', 'pattern_parts': ['a', 'b'],
		'pattern_search': 'p', 'search_copy': 'pending'}


def test_the_copy_is_written_as_stash_under_its_source_name():
	search = writer(FakeConnection([])).build_copy_search()

	assert '| inputlookup tenx-dml-lookup where search_copy="pending"' in search
	assert '_raw=pattern_hash."\t".pattern_search' in search
	assert 'collect index=tenx_dml sourcetype=stash source=tenx_dml_pure addtime=false' in search


def test_copied_records_are_marked_written_whole():
	conn = FakeConnection([record('a'), record('b')])

	assert writer(conn).write_pending() == 2
	saved = conn.batches[0]
	assert [r['search_copy'] for r in saved] == ['written', 'written']
	assert saved[0]['pattern_parts'] == ['a', 'b']
	assert '_user' not in saved[0] and saved[0]['_key'] == 'a'


def test_a_record_the_search_did_not_copy_stays_pending():
	conn = FakeConnection([record('a'), record('b')], copied=['a'])

	assert writer(conn).write_pending() == 1
	assert [r['_key'] for r in conn.batches[0]] == ['a']


def test_a_failed_copy_search_marks_nothing():
	conn = FakeConnection([record('a')], fail_search=True)

	assert writer(conn).write_pending() == -1
	assert conn.batches == []


def test_nothing_pending_runs_no_search():
	conn = FakeConnection([])

	assert writer(conn).write_pending() == 0
	assert conn.searches == []


def test_pending_records_past_what_one_read_returns_are_all_marked():
	# one read gives at most 1,700 rows here, as 50 MB of records did on Splunk (16,990 of 18,809)
	keys = ['k%05d' % i for i in range(4500)]
	conn = FakeConnection([record(k) for k in reversed(keys)], read_cap=1700)

	assert writer(conn).write_pending() == 4500
	assert sorted(r['_key'] for b in conn.batches for r in b) == keys
	assert len(conn.searches) == 1
	# pages of at most 1,000, each starting where the rows read so far end, until one brings nothing new
	assert [(r['skip'], r['limit']) for r in conn.reads] == [(k, 1000) for k in (0, 1000, 2000, 3000, 4000, 4500)]


def test_a_store_that_ignores_skip_ends_the_read():
	class IgnoresSkip(FakeConnection):
		def get(self, url, params=None, output_mode="json"):
			return FakeConnection.get(self, url, dict(params, skip=0), output_mode)

	conn = IgnoresSkip([record('a'), record('b')])

	assert writer(conn).write_pending() == 2
	assert len(conn.reads) == 2


class FindingConnection(FakeConnection):
	"""Also answers batch_find, from the records it holds."""

	def post(self, url, data, params=None, output_mode="json", read_result=True):
		if url.endswith('/batch_find'):
			keys = json.loads(data)[0]['query']['_key']['$in']
			return [[dict(r) for r in self.pending if r['_key'] in keys]]
		return FakeConnection.post(self, url, data, params, output_mode, read_result)


def test_records_the_caller_just_wrote_are_marked_without_reading_the_collection():
	held = [record('k%d' % i) for i in range(3)]
	earlier = record('old1')
	conn = FindingConnection(held + [earlier])

	assert writer(conn).write_pending(known=held) == 4

	assert conn.reads == []
	marked = {r['_key']: r['search_copy'] for batch in conn.batches for r in batch}
	assert marked == {'k0': 'written', 'k1': 'written', 'k2': 'written', 'old1': 'written'}


def test_records_the_copy_search_missed_stay_pending():
	held = [record('k%d' % i) for i in range(3)]
	conn = FindingConnection(held, copied=['k0', 'k2'])

	assert writer(conn).write_pending(known=held) == 2
	marked = {r['_key'] for batch in conn.batches for r in batch}
	assert marked == {'k0', 'k2'}
