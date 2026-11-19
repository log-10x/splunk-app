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
"pending". Searches then copy the pending records, COPY_BATCH at a time:

    | inputlookup tenx-dml-lookup where search_copy="pending" | head <COPY_BATCH>
    | eval _raw=pattern_hash."\t".pattern_search
    | collect index=<index> sourcetype=stash source=<source> addtime=false

and the records each one copied are marked "written" before the next runs. A record whose copy
failed, or whose run stopped before marking it, stays pending and is copied by the next run.

See Also
--------
- props.conf: [source::tenx_dml_pure] and [tenx_dml_pure]
- tenx_dml_to_kv.py: the alert that stores templates and calls this module
- tenx_search_manager.py: the search that reads the copy
"""

import json
import logging
import time
import urllib.parse

import tenx_dml_builder

logger = logging.getLogger(__name__)

SEARCH_COPY = "search_copy"
SEARCH_COPY_PENDING = "pending"
SEARCH_COPY_WRITTEN = "written"
# The hour (epoch seconds // 3600, as text) in which Consume KV last wrote the record. The `tx`
# prefilter reads only the records of recent hours when it holds an earlier answer for its words
# (tenx_prefilter_parser.cache_hours); collections.conf indexes the field.
STORED_HOUR = "stored_hour"

# Records marked written are saved with TenxKVInterface.save_many, within the KV store's batch limits.

# Templates one copy search writes. A oneshot search returns at most limits.conf [restapi]
# maxresultrows keys (50,000), so each search copies fewer, and its records are marked written
# before the next search runs.
COPY_BATCH = 20000


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

	def build_copy_search(self, limit=None):
		return ('| inputlookup {lookup} where {flag}="{pending}" | head {limit}'
			' | eval _raw={hash_field}."\t".{text_field}'
			' | collect index={index} sourcetype=stash source={source} addtime=false'
			' | fields _key').format(
				lookup=self.lookup_name, flag=SEARCH_COPY, pending=SEARCH_COPY_PENDING,
				limit=int(limit or COPY_BATCH),
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

	def any_pending(self):
		"""Whether any record waits for its searchable copy (one read of one key, on an indexed field)."""
		query = json.dumps({SEARCH_COPY: SEARCH_COPY_PENDING})
		page = self.server_connection.get(self.kv_intf.build_collection_url(), {'query': query, 'limit': 1, 'fields': '_key'})
		return bool(page)

	def write_pending(self, known=None, deadline=None):
		"""
		Writes the searchable copy of the pending templates, COPY_BATCH at a time, and marks each
		batch written before the next copy search runs. A run that stops leaves written, and
		marked, every batch it finished; the records of a batch it did not mark stay pending and
		the next copy search copies them again (a template with two copies is matched once: the
		prefilter's template search counts by template hash).

		known: pending records the caller just wrote, whole, marked from memory; any other record
		a copy search copied (pending from an earlier run) is read by its key. deadline: no copy
		search starts after this time.

		Returns the number of templates copied and marked, or -1 when a copy search or a marking
		failed; the records not marked stay pending for the next run.
		"""
		known = {r.get('_key'): r for r in (known or [])}

		try:
			if not known and not self.any_pending():
				return 0
		except Exception as e:
			logger.error("Could not read pending templates - {}".format(e), exc_info=1)
			return -1

		total, marked = 0, set()

		while deadline is None or time.time() < deadline:
			began = time.time()
			keys = self.run_copy_search()
			searched = time.time() - began

			if keys is None:
				return -1

			fresh = [k for k in dict.fromkeys(keys) if k not in marked]

			if not fresh:
				if keys:
					logger.warning("The copy search copied {} templates already marked written; their marks did not hold.".format(len(keys)))
					return -1
				return total

			records = [known[k] for k in fresh if k in known]
			others = [k for k in fresh if k not in known]

			if others:
				try:
					records.extend(self.kv_intf.find_many(others).values())
				except Exception as e:
					logger.warning("Could not read {} templates copied from an earlier run; they are copied again later - {}".format(len(others), e))
					return -1

			done = []
			for record in records:
				record = {k: v for k, v in record.items() if k == '_key' or not k.startswith('_')}
				record[SEARCH_COPY] = SEARCH_COPY_WRITTEN
				done.append(record)

			if not self.kv_intf.save_many(done):
				return -1

			marked.update(fresh)
			total += len(done)
			logger.info("Wrote the searchable copy of {} templates ({:.1f} s searching, {:.1f} s marking).".format(len(done), searched, time.time() - began - searched))

			if len(keys) < COPY_BATCH:
				return total

		logger.info("Stopped writing searchable copies at the run's time limit; the next run continues.")
		return total
