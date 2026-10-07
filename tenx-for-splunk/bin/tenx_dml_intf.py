"""
Tenx DML Searchable Copy Interface Module
=========================================

This module writes the searchable copy of each 10x template, which the search rewrite uses
to turn a search term into the template hashes whose text carries it.

Searchable copy
---------------
One event per template in the template index:

    Format: "<template_hash>\t<template text with separators removed>"

    Example:
        abc123hash	INFO [main] MyService - User  logged in from

The copy is written with `collect` as sourcetype `stash`, which Splunk does not count against
the licence, under the source named by `dml_source_type` (default `tenx_dml_pure`).
props.conf's [source::tenx_dml_pure] stanza keeps one template per event and extracts the hash.

How it is written
-----------------
The Consume KV alert stores each new template in the KV store with `search_copy` set to
"pending". One search then copies every pending record:

    | inputlookup tenx-dml-lookup where search_copy="pending"
    | eval _raw=pattern_hash."\t".pattern_search
    | collect index=<index> sourcetype=stash source=<source> addtime=false

and the records it copied are marked "written". A record whose copy failed stays pending and
is copied by the next run.

See Also
--------
- props.conf: [source::tenx_dml_pure] and [tenx_dml_pure]
- tenx_dml_to_kv.py: the alert that stores templates and calls this module
- tenx_search_manager.py: the search that reads the copy
"""

import json
import logging
import urllib.parse

import tenx_dml_builder

logger = logging.getLogger(__name__)

SEARCH_COPY = "search_copy"
SEARCH_COPY_PENDING = "pending"
SEARCH_COPY_WRITTEN = "written"

# The KV store's default limit on documents per batch_save call is 1,000.
BATCH_SIZE = 500


class TenxDmlInterface:
	"""
	Writes the searchable copy of templates whose KV records are pending.
	"""
	def __init__(self, server_connection, kv_intf, app_name, lookup_name, index_name, source):
		self.server_connection = server_connection
		self.kv_intf = kv_intf
		self.app_name = app_name
		self.lookup_name = lookup_name
		self.index_name = index_name
		self.source = source

	def build_copy_search(self):
		return ('| inputlookup {lookup} where {flag}="{pending}"'
			' | eval _raw={hash_field}."\t".{text_field}'
			' | collect index={index} sourcetype=stash source={source} addtime=false'
			' | fields _key').format(
				lookup=self.lookup_name, flag=SEARCH_COPY, pending=SEARCH_COPY_PENDING,
				hash_field=tenx_dml_builder.RECORD_PATTERN_HASH,
				text_field=tenx_dml_builder.RECORD_PATTERN_SEARCH,
				index=self.index_name, source=self.source)

	def run_copy_search(self):
		"""
		Runs the copy search to completion. Returns the KV keys it copied, or None on failure.
		"""
		url = '/servicesNS/nobody/{}/search/jobs'.format(urllib.parse.quote(self.app_name))
		data = {'search': self.build_copy_search(), 'exec_mode': 'oneshot', 'count': 0}

		try:
			response = self.server_connection.post(url, data)
		except Exception as e:
			logger.error("The searchable copy search failed - {}".format(e), exc_info=1)
			return None

		return [r.get('_key') for r in (response or {}).get('results', []) if r.get('_key')]

	def pending_records(self):
		query = json.dumps({SEARCH_COPY: SEARCH_COPY_PENDING})

		return self.server_connection.get(self.kv_intf.build_collection_url(), {'query': query})

	def write_pending(self):
		"""
		Writes the searchable copy of every pending template and marks those records written.

		Returns the number of templates copied, or -1 when the copy could not be written; the
		records then stay pending for the next run.
		"""
		try:
			pending = self.pending_records()
		except Exception as e:
			logger.error("Could not read pending templates - {}".format(e), exc_info=1)
			return -1

		if not pending:
			return 0

		copied_keys = self.run_copy_search()

		if copied_keys is None:
			return -1

		copied = set(copied_keys)
		done = []

		for record in pending:
			if record.get('_key') in copied:
				record = {k: v for k, v in record.items() if k == '_key' or not k.startswith('_')}
				record[SEARCH_COPY] = SEARCH_COPY_WRITTEN
				done.append(record)

		for start in range(0, len(done), BATCH_SIZE):
			if not self.kv_intf.save_batch(done[start:start + BATCH_SIZE]):
				return -1

		logger.info("Wrote the searchable copy of {} templates.".format(len(done)))

		return len(done)
