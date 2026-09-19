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
		'search index=tenx_dml sourcetype=tenx_dml_pure ProducerStateManager')


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
