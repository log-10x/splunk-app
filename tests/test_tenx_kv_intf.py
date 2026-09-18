"""
Unit tests for tenx_kv_intf.

The KV store key has to be the value the search will look up with. Splunk's
search-time extraction trims surrounding whitespace, so a hash the engine emits
with a trailing space must be stored under its trimmed form or it never matches.
"""
import json
import os
import sys
import urllib.error
from urllib.parse import unquote

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'bin'))

import pytest
from tenx_kv_intf import TenxKVInterface


class FakeConnection:
	"""Records what the interface asks the server for; serves a fixed record set."""

	def __init__(self, records=None):
		self.records = records or {}
		self.gets = []
		self.posts = []

	def get(self, url, params=None, output_mode="json"):
		self.gets.append(url)
		key = unquote(url.rsplit('/', 1)[1])
		if key in self.records:
			return self.records[key]
		raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

	def post(self, url, data, params=None, output_mode="json", read_result=True):
		self.posts.append((url, json.loads(data)))
		return {}


@pytest.fixture
def conn():
	return FakeConnection()


@pytest.fixture
def kv(conn):
	return TenxKVInterface(collection_name='tenx_dml', server_connection=conn,
	                       owner='nobody', app_name='tenx-for-splunk')


class TestKeyTrimming:

	def test_trailing_space_is_not_part_of_the_key(self, kv, conn):
		# A hash the E21 run found unexpanded: '*44L<h{N. ' with a trailing space.
		assert kv.create_entry('*44L<h{N. ', {'pattern_hash': '*44L<h{N. ', 'pattern': 'x'})
		_, record = conn.posts[0]
		assert record['_key'] == '*44L<h{N.'

	def test_pattern_hash_keeps_the_hash_as_emitted(self, kv, conn):
		kv.create_entry('abc ', {'pattern_hash': 'abc ', 'pattern': 'x'})
		_, record = conn.posts[0]
		assert record['pattern_hash'] == 'abc '

	def test_lookup_asks_for_the_trimmed_key(self, kv, conn):
		kv.get_entry('abc ')
		assert conn.gets[0].endswith('/abc')
		assert '%20' not in conn.gets[0]

	def test_a_hash_without_whitespace_is_unchanged(self, kv, conn):
		kv.create_entry('-3gTMRPTTYm', {'pattern_hash': '-3gTMRPTTYm'})
		_, record = conn.posts[0]
		assert record['_key'] == '-3gTMRPTTYm'

	def test_write_and_read_agree_on_the_key(self, kv, conn):
		conn.records['abc'] = {'_key': 'abc', 'pattern_hash': 'abc '}
		assert kv.get_entry('abc ') is not None
		assert kv.get_entry('abc') is not None

	def test_special_characters_are_still_url_quoted(self, kv, conn):
		kv.get_entry('$+[?l?!!f ')
		assert conn.gets[0].endswith('/%24%2B%5B%3Fl%3F%21%21f')
