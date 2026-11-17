"""
The searchable copy of each template is written with `collect` as sourcetype stash, which
Splunk does not count against the licence. A record is marked written only when the copy
search returned its key, so a failed write leaves it pending for the next run.
"""
import json
import re

import tenx_dml_intf
from tenx_kv_intf import TenxKVInterface


class FakeConnection:
	"""
	The KV store and the copy search as measured: a read by query returns the matching records, at
	most limit; the copy search copies the pending records up to its head; batch_save replaces whole
	records (so a record saved written is no longer pending); batch_find returns records by key.
	"""
	def __init__(self, pending, copied=None, fail_search=False, fail_save_after=None):
		self.records = {r['_key']: dict(r) for r in pending}
		self.copied = copied
		self.fail_search = fail_search
		self.fail_save_after = fail_save_after
		self.searches = []
		self.batches = []
		self.reads = []
		self.copies = []

	def pending(self):
		return [k for k in sorted(self.records) if self.records[k].get('search_copy') == 'pending']

	def get(self, url, params=None, output_mode="json"):
		assert json.loads(params['query']) == {'search_copy': 'pending'}
		self.reads.append(dict(params))
		return [{'_key': k} for k in self.pending()][:int(params.get('limit', 0)) or None]

	def post(self, url, data, params=None, output_mode="json", read_result=True):
		if url.endswith('/search/jobs'):
			self.searches.append(data)
			if self.fail_search:
				raise RuntimeError('search failed')
			head = int(re.search(r'\| head (\d+)', data['search']).group(1))
			keys = [k for k in self.pending() if self.copied is None or k in self.copied][:head]
			self.copies.extend(keys)
			return {'results': [{'_key': k} for k in keys]}
		if url.endswith('/batch_find'):
			keys = json.loads(data)[0]['query']['_key']['$in']
			return [[dict(self.records[k]) for k in keys if k in self.records]]
		if url.endswith('/batch_save'):
			if self.fail_save_after is not None and len(self.batches) >= self.fail_save_after:
				raise RuntimeError('KV store not ready')
			batch = json.loads(data)
			self.batches.append(batch)
			for r in batch:
				self.records[r['_key']] = r
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
	assert conn.pending() == ['b']


def test_a_failed_copy_search_marks_nothing():
	conn = FakeConnection([record('a')], fail_search=True)

	assert writer(conn).write_pending() == -1
	assert conn.batches == []


def test_nothing_pending_runs_no_search():
	conn = FakeConnection([])

	assert writer(conn).write_pending() == 0
	assert conn.searches == []
	assert [r['limit'] for r in conn.reads] == [1]


def test_more_pending_than_one_copy_search_takes_are_copied_batch_by_batch(monkeypatch):
	monkeypatch.setattr(tenx_dml_intf, 'COPY_BATCH', 1000)
	keys = ['k%05d' % i for i in range(4500)]
	conn = FakeConnection([record(k) for k in keys])

	assert writer(conn).write_pending() == 4500

	assert conn.pending() == []
	assert len(conn.searches) == 5
	assert all('| head 1000 ' in q['search'] for q in conn.searches)
	# every template copied once
	assert sorted(conn.copies) == keys


def test_a_run_that_stops_between_batches_leaves_the_batches_it_marked(monkeypatch):
	monkeypatch.setattr(tenx_dml_intf, 'COPY_BATCH', 1000)
	keys = ['k%05d' % i for i in range(4500)]
	conn = FakeConnection([record(k) for k in keys], fail_save_after=2)

	assert writer(conn).write_pending() == -1

	# two batches were copied and marked; the third was copied and not marked, so it stays pending
	assert len(conn.pending()) == 2500
	assert len(conn.copies) == 3000

	conn.fail_save_after = None
	assert writer(conn).write_pending() == 2500
	assert conn.pending() == []
	# the batch copied without its mark is copied a second time; the template search counts by hash
	assert len(conn.copies) - len(set(conn.copies)) == 1000


def test_no_copy_search_starts_after_the_deadline(monkeypatch):
	monkeypatch.setattr(tenx_dml_intf, 'COPY_BATCH', 1000)
	conn = FakeConnection([record('k%05d' % i) for i in range(4500)])

	assert writer(conn).write_pending(deadline=0) == 0
	assert conn.searches == []
	assert len(conn.pending()) == 4500


def test_records_the_caller_just_wrote_are_marked_without_reading_them_back():
	held = [record('k%d' % i) for i in range(3)]
	earlier = record('old1')
	conn = FakeConnection(held + [earlier])
	finds = []
	real = conn.post
	conn.post = lambda url, data, **k: (finds.append(json.loads(data)) if url.endswith('/batch_find') else None) or real(url, data, **k)

	assert writer(conn).write_pending(known=held) == 4

	assert conn.pending() == []
	assert finds == [[{'query': {'_key': {'$in': ['old1']}}}]]
