"""
The DML resolution search, which is how a term in the original text becomes a set of
template hashes.

This is one assertion and it is worth a file. Splunk searches only a user's default
indexes when a search names none, and that default is `main`. While the app wrote its
template events to `main` the omission was invisible. Pointed at any other index, every
term resolved to zero hashes, the search ran with the user's terms still in front of the
inflate macro, and it returned nothing at all, with no error anywhere: the words being
searched for live in the original line, not in the compact event.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'bin'))

from tenx_search_manager import TenxSearchManager


class RecordingConnection:
	"""Captures the job Splunk would have been asked to create."""

	def __init__(self):
		self.posted = []
		self.user = 'admin'

	def post(self, url, data=None, **kwargs):
		self.posted.append((url, data))
		return {'sid': 'fake-sid'}


CONFIG = {
	'dest_dml_index': 'tenx_dml',
	'dml_source_type': 'tenx_dml_pure',
	'collection_name': 'tenx_dml',
	'timestamp_placeholder': '__TENX_TS__',
	'variable_separator': '$',
}


@pytest.fixture
def manager():
	return TenxSearchManager(RecordingConnection(), dict(CONFIG))


def test_resolution_search_names_the_index(manager, monkeypatch):
	captured = {}
	monkeypatch.setattr(manager, 'create_search_job', lambda data: captured.update(data))

	manager.create_dml_search('ProducerStateManager')

	assert captured['search'] == (
		'search index=tenx_dml sourcetype=tenx_dml_pure ProducerStateManager | stats count by dml_hash')


def test_resolution_search_follows_a_relocated_index(manager, monkeypatch):
	manager.tenx_config['dest_dml_index'] = 'somewhere_else'
	captured = {}
	monkeypatch.setattr(manager, 'create_search_job', lambda data: captured.update(data))

	manager.create_dml_search('error')

	assert captured['search'].startswith('search index=somewhere_else sourcetype=tenx_dml_pure ')


def test_resolution_search_covers_all_time(manager, monkeypatch):
	# A template is stored once, when it is first seen, which can be long before the window
	# the user is searching. Resolution has to look at all of it or it loses old templates.
	captured = {}
	monkeypatch.setattr(manager, 'create_search_job', lambda data: captured.update(data))

	manager.create_dml_search('error')

	assert captured['earliest_time'] == '0'
	assert captured['latest_time'] == 'now'


class ResultsConnection(RecordingConnection):
	"""Answers the results endpoint with a fixed set of rows and the job with a resultCount."""
	def __init__(self, rows, result_count):
		RecordingConnection.__init__(self)
		self.rows = rows
		self.result_count = result_count
		self.gets = []

	def get(self, url, params=None, **kwargs):
		self.gets.append((url, params))

		if url.endswith('/results'):
			return {'results': self.rows}

		return {'entry': [{'content': {'resultCount': self.result_count}}]}


def test_results_are_distinct_hashes_read_from_the_results_endpoint():
	# The probe collapses rows to distinct hashes with stats, so the results endpoint, not
	# the events endpoint, is where the answer is; and the cap counts those hashes.
	connection = ResultsConnection([{'dml_hash': 'h_b'}, {'dml_hash': 'h_a'}], result_count=2)
	manager = TenxSearchManager(connection, dict(CONFIG))

	hashes, truncated = manager.get_dml_results('sid-1')

	assert hashes == ['h_a', 'h_b']
	assert truncated is False
	assert connection.gets[0][0].endswith('/search/jobs/sid-1/results')
	assert connection.gets[0][1]['f'] == 'dml_hash'


def test_more_distinct_hashes_than_fetched_is_truncated():
	from tenx_search_manager import DML_FETCH_LIMIT
	connection = ResultsConnection([{'dml_hash': 'h_a'}], result_count=DML_FETCH_LIMIT + 1)
	manager = TenxSearchManager(connection, dict(CONFIG))

	hashes, truncated = manager.get_dml_results('sid-2')

	assert hashes == ['h_a']
	assert truncated is True


def test_jobs_are_created_in_the_callers_app():
	# A dashboard in another app may use that app's private macros, lookups or eventtypes,
	# which resolve only in a job created in that app's namespace.
	manager = TenxSearchManager(RecordingConnection(), dict(CONFIG), app='ops_app')
	assert manager.create_search_job_url() == '/servicesNS/admin/ops_app/search/jobs/'
	assert manager.parse_search_string_url() == '/servicesNS/admin/ops_app/search/parser'


def test_jobs_default_to_the_search_app():
	assert TenxSearchManager(RecordingConnection(), dict(CONFIG)).create_search_job_url() \
		== '/servicesNS/admin/search/search/jobs/'
