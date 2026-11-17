"""
Tenx KV Store Interface Module
=============================

This module provides an interface to Splunk's KV store for managing 10x
template data. The KV store is used at search time by the tenx-inflate macro
to look up template parts for reconstructing original log events.

KV Store Collection: tenx_dml
--------------------------
The tenx_dml collection stores parsed template data with the following schema:

    {
        "_key": "<template_hash>",           # Primary key (same as pattern_hash)
        "pattern_hash": "<template_hash>",   # Template identifier
        "pattern": "<original_template>",    # Original template string
        "pattern_parts": ["...", "..."],     # Middle template segments
        "part_0": "<first_segment>",         # First segment (before first variable)
        "pattern_terminator": "<last>",      # Last segment (after last variable)
        "timestamp_format": "%Y-%m-%d..."    # Splunk strftime format
    }

API Endpoints Used
------------------
GET /servicesNS/{owner}/{app}/storage/collections/data/{collection}/{key}
    Retrieve a specific record by key

POST /servicesNS/{owner}/{app}/storage/collections/data/{collection}/
    Create a new record

POST /servicesNS/{owner}/{app}/storage/collections/data/{collection}/batch_find
    Read the records under many keys ({"_key": {"$in": [...]}})

POST /servicesNS/{owner}/{app}/storage/collections/data/{collection}/batch_save
    Write many whole records

Usage
-----
    from tenx_util import ServerConnection
    from tenx_kv_intf import TenxKVInterface

    conn = ServerConnection(server_uri, user, {'session_key': token})
    kv = TenxKVInterface('tenx_dml', conn, 'nobody', 'tenx-for-splunk')

    # Check if template exists
    existing = kv.get_entry('abc123hash')

    # Create new entry
    kv.create_entry('abc123hash', {
        'pattern_hash': 'abc123hash',
        'pattern': '$INFO User $ logged in',
        'pattern_parts': [' User ', ' logged in'],
        'part_0': '',
        'pattern_terminator': '',
        'timestamp_format': ''
    })

See Also
--------
- collections.conf: KV store schema definition
- transforms.conf: Lookup definition for search-time access
- macros.conf: tenx-inflate macro that uses the lookup
"""

import logging

logger = logging.getLogger(__name__)

import json
import urllib.parse
import urllib.error

# Splunk's defaults for limits.conf [kvstore] max_documents_per_batch_save and max_size_per_batch_save_mb.
DEFAULT_BATCH_DOCUMENTS = 1000
DEFAULT_BATCH_SIZE_MB = 50
# Keys asked for in one batch_find query. One query returns at most max_rows_per_query rows (50,000)
# and max_size_per_batch_result_mb (100 MB); 500 templates stay far below both.
FIND_KEYS = 500


class TenxKVInterface:
	"""
	Class to interface with the 10x KV store inside splunk.
	Used for adding items into the KV store, which are later used as part of the 10x decode process.
	"""
	def __init__(self, collection_name, server_connection, owner, app_name):
		self.collection_name = collection_name
		self.server_connection = server_connection
		self.owner = owner if owner is not None else 'nobody'
		self.app_name = app_name

		self.KV_KEY = "_key"

	def kv_key(self, record_key):
		"""
		The KV store key for a template hash.

		Splunk's search-time field extraction trims surrounding whitespace from the
		value it extracts, and the inflate macro looks the hash up with that value.
		A hash the engine emits with a trailing space would be stored under one key
		and looked up under another, and never match: on the E21 capture that was 43
		of 2,986 hashes and every one of their 45 events came back unexpanded. Keying
		on the trimmed hash stores it under the key the search will ask for. The
		pattern_hash field in the record keeps the hash exactly as emitted.
		"""
		return record_key.strip()

	def build_collection_url(self):
		"""
		Returns the base url for collection-wide based actions.
		"""
		return self.build_record_url("")

	def build_record_url(self, record_key):
		"""
		Returns the base url for specific record actions.
		"""
		url_tmpl = '/servicesNS/%(owner)s/%(app)s/storage/collections/data/%(collection)s/%(name)s'
		return url_tmpl % dict(
			owner=self.owner,
			app=self.app_name,
			collection=urllib.parse.quote(self.collection_name),
			# URL-encode the record key to handle special characters in template hashes
			# (e.g., #, {, }, |, spaces) that would otherwise break the URL
			name=urllib.parse.quote(record_key, safe=''))

	def get_entry(self, record_key):
		"""
		Returns the matching entry from the KV store.

		Note that while trying to get a missing entry will throw an HTTPError, we don't treat it as an actual problem.
		"""
		try:
			record_url = self.build_record_url(self.kv_key(record_key))

			return self.server_connection.get(record_url)
		except urllib.error.HTTPError as e:
			if e.code == 404:
				logger.info("No record for {}.".format(record_key))
				return None

			logger.warning("HTTPError while fetching record for {} - {}".format(record_key, e), exc_info=1)
			return None
		except Exception as e:
			logger.error("Failed fetching record for {} - {}".format(record_key, e), exc_info=1)
			return None

	def create_entry(self, record_key, record_data):
		"""
		Adds a new entry to the KV store, based on the provided record_key and record_data
		"""
		try:
			collection_url = self.build_collection_url()
			record = {self.KV_KEY: self.kv_key(record_key)}
			record.update(record_data)

			self.server_connection.post(collection_url, json.dumps(record))

			logger.info("Created new KV entry for {}.".format(record_key))
			
			return True
		except urllib.error.HTTPError as e:
			logger.warning("HTTPError while updating record for {} - {}".format(record_key, e), exc_info=1)
		except Exception as e:
			logger.error("Failed updating record for {} - {}".format(record_key, e), exc_info=1)

		return False

	def update_entry(self, record_key, record_data):
		"""
		Replaces the entry stored under record_key with record_data.
		"""
		try:
			key = self.kv_key(record_key)
			record = {self.KV_KEY: key}
			record.update(record_data)

			self.server_connection.post(self.build_record_url(key), json.dumps(record))

			logger.info("Updated KV entry for {}.".format(record_key))

			return True
		except urllib.error.HTTPError as e:
			logger.warning("HTTPError while replacing record for {} - {}".format(record_key, e), exc_info=1)
		except Exception as e:
			logger.error("Failed replacing record for {} - {}".format(record_key, e), exc_info=1)

		return False

	def save_batch(self, records):
		"""
		Writes whole records, each carrying its _key, in one call. A record whose key exists
		is replaced.
		"""
		try:
			url = self.build_record_url("batch_save")
			self.server_connection.post(url, json.dumps(records))

			return True
		except Exception as e:
			logger.error("Failed saving {} records in a batch - {}".format(len(records), e), exc_info=1)

		return False

	def batch_limits(self):
		"""
		The KV store's limits on one batch_save call (limits.conf [kvstore]): documents and
		megabytes. Splunk's defaults when the settings cannot be read.
		"""
		docs, size_mb = DEFAULT_BATCH_DOCUMENTS, DEFAULT_BATCH_SIZE_MB
		try:
			content = self.server_connection.get('/services/configs/conf-limits/kvstore')['entry'][0]['content']
			docs = int(content.get('max_documents_per_batch_save') or docs)
			size_mb = float(content.get('max_size_per_batch_save_mb') or size_mb)
		except Exception as e:
			logger.info("Could not read the KV store batch limits, using {} documents and {} MB - {}".format(docs, size_mb, e))
		return max(1, docs), max(1.0, size_mb)

	def save_many(self, records, limits=None):
		"""
		Writes whole records, each carrying its _key, in as few batch_save calls as the KV
		store's limits allow. Returns True when every call succeeded.
		"""
		docs, size_mb = limits or self.batch_limits()
		# Half the size limit: the limit counts the stored form, which can be larger than the JSON.
		budget = int(size_mb * 1024 * 1024 / 2)
		batch, size = [], 0
		for record in records:
			length = len(json.dumps(record)) + 2
			if batch and (len(batch) >= docs or size + length > budget):
				if not self.save_batch(batch):
					return False
				batch, size = [], 0
			batch.append(record)
			size += length
		return self.save_batch(batch) if batch else True

	def find_many(self, record_keys):
		"""
		The stored records under the given KV keys, as {key: record}, read with batch_find in
		groups of FIND_KEYS keys. A key with no record is left out. Raises when the store
		cannot be read, so a caller never takes an unread key for a missing one.
		"""
		found = {}
		keys = list(dict.fromkeys(record_keys))
		url = self.build_record_url("batch_find")
		for start in range(0, len(keys), FIND_KEYS):
			group = keys[start:start + FIND_KEYS]
			answer = self.server_connection.post(url, json.dumps([{"query": {self.KV_KEY: {"$in": group}}}]))
			rows = answer[0] if isinstance(answer, list) and answer and isinstance(answer[0], list) else answer
			if not isinstance(rows, list):
				raise RuntimeError("unexpected batch_find answer: {}".format(str(answer)[:200]))
			for row in rows:
				if isinstance(row, dict) and row.get(self.KV_KEY) is not None:
					found[row[self.KV_KEY]] = row
		return found
