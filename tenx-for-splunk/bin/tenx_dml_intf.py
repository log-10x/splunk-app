"""
Tenx DML Sourcetype Interface Module
====================================

This module provides an interface for submitting events to the tenx_dml_pure
sourcetype. These events contain searchable versions of 10x templates,
enabling users to search for patterns and identify matching template hashes.

DML Pure Sourcetype
-------------------
The tenx_dml_pure sourcetype stores simplified template representations:

    Format: "<template_hash> <template_pattern_without_separators>"

    Example:
        abc123hash INFO [main] MyService - User  logged in from

This format strips variable separators ($) and newlines from templates,
making them searchable with standard Splunk queries.

API Endpoint
------------
POST /services/receivers/simple
    Submit raw events to Splunk with specified index/sourcetype

Usage
-----
    from tenx_util import ServerConnection
    from tenx_dml_intf import TenxDmlInterface

    conn = ServerConnection(server_uri, user, {'session_key': token})
    dml = TenxDmlInterface(conn, 'hostname', 'main', 'tenx_dml_pure')

    # Submit a searchable template entry
    dml.submit('abc123hash', 'abc123hash INFO User logged in', 'consume_kv_alert')

See Also
--------
- props.conf: tenx_dml_pure sourcetype definition
- tenx_dml_builder.py: Creates the DML line format
- savedsearches.conf: Alert that triggers template processing
"""

import logging

logger = logging.getLogger(__name__)


class TenxDmlInterface:
	"""
	Class to interface with the 10x dml sourcetype inside splunk.
	Used for adding the events the 10x search uses to convert a user search into the 10x decoded hash.
	"""
	def __init__(self, server_connection, host, index_name, dml_sourcetype):
		self.server_connection = server_connection
		self.host = host
		self.index_name = index_name
		self.dml_sourcetype = dml_sourcetype

	def submit(self, key, event, source):
		"""
		Submits a new event into the 10x dml sourcetype.

		The event is a simple union of the record_key (10x encoded hash) and the matching pattern, stripped of separators.
		"""

		try:
			params = {"index": self.index_name, "sourcetype": self.dml_sourcetype, "host": self.host, "source": source}

			url = '/services/receivers/simple'

			self.server_connection.post(url, event, params)

			logger.info("Submitted new dml entry for {}.".format(key))

			return True
		except Exception as e:
			logger.error("Failed submitting dml entry {} - {}".format(key, e), exc_info=1)

			return False
