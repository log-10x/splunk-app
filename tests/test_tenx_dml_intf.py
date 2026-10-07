"""
The searchable copy of each template is written with `collect` as sourcetype stash, which
Splunk does not count against the licence. A record is marked written only when the copy
search returned its key, so a failed write leaves it pending for the next run.
"""
import json

import tenx_dml_intf
from tenx_kv_intf import TenxKVInterface


class FakeConnection:
	def __init__(self, pending, copied=None, fail_search=False):
		self.pending = pending
		self.copied = copied
		self.fail_search = fail_search
		self.searches = []
		self.batches = []

	def get(self, url, params=None, output_mode="json"):
		assert json.loads(params['query']) == {'search_copy': 'pending'}
		return [dict(r) for r in self.pending]

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
