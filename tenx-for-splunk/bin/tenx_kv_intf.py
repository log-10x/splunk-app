"""
Tenx KV Store Interface Module
=============================

This module provides an interface to Splunk's KV store for managing 10x
template data. The KV store is used at search time by the tenx-inflate macro
to look up template parts for reconstructing original log events.

KV Store Collection: kvdml
--------------------------
The kvdml collection stores parsed template data with the following schema:

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

Usage
-----
    from tenx_util import ServerConnection
    from tenx_kv_intf import TenxKVInterface

    conn = ServerConnection(server_uri, user, {'session_key': token})
    kv = TenxKVInterface('kvdml', conn, 'nobody', 'tenx-for-splunk')

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
			record_url = self.build_record_url(record_key)

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
			record = {self.KV_KEY: record_key}
			record.update(record_data)

			self.server_connection.post(collection_url, json.dumps(record))

			logger.info("Created new KV entry for {}.".format(record_key))
			
			return True
		except urllib.error.HTTPError as e:
			logger.warning("HTTPError while updating record for {} - {}".format(record_key, e), exc_info=1)
		except Exception as e:
			logger.error("Failed updating record for {} - {}".format(record_key, e), exc_info=1)

		return False
