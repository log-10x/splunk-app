"""
Tenx Search REST Handler
=======================

This module implements a REST API handler for creating 10x-compatible search
jobs. It provides a performant alternative to the tenxsearch generating command
for interactive use cases.

Endpoint
--------
POST /servicesNS/{owner}/{app}/tenx-search

Request Body (form-encoded):
    search: The user's search query
    earliest_time: Search time range start
    latest_time: Search time range end
    (other standard /services/search/jobs parameters)

Response:
    {
        "sid": "<search_job_id>"
    }

Workflow
--------
1. Client POSTs search to /tenx-search endpoint
2. Handler resolves search for 10x encoded data using TenxSearchBuilder
3. Creates new search job via /services/search/jobs
4. Returns SID for client to poll/retrieve results

Performance
-----------
This handler is faster than the tenxsearch command because:
- Returns immediately with SID (non-blocking)
- Client retrieves results directly from Splunk
- No Python streaming overhead

Usage Example
-------------
    curl -k -u <user>:<password> \\
        -d "search=error&earliest_time=-1h&latest_time=now" \\
        https://localhost:8089/servicesNS/admin/tenx-for-splunk/tenx-search

    # Response: {"sid": "1234567890.12345"}

    # Then poll for results:
    curl -k -u <user>:<password> \\
        https://localhost:8089/services/search/jobs/1234567890.12345/results

Logging
-------
Logs to: $SPLUNK_HOME/var/log/splunk/tenx_search_handler.log

See Also
--------
- restmap.conf: REST endpoint registration
- tenxsearch.py: Generating command alternative
- tenx_search_builder.py: Search resolution logic
"""


import os
import sys
import logging
import json

from splunk.clilib.bundle_paths import get_base_path
from splunk.persistconn.application import PersistentServerConnectionApplication

# ============================================================================
# Application Setup
# ============================================================================

# Application name - must match the app directory name
APP_NAME = 'tenx-for-splunk'
apphome = os.path.join(get_base_path(), APP_NAME)
sys.path.append(os.path.join(apphome, 'bin'))
sys.path.append(os.path.join(apphome, 'lib'))

import tenx_util
import tenx_search_manager
import tenx_search_builder
import tenx_alert_compiler

tenx_util.setup_logger('tenx_search_handler', logging.INFO)
logger = logging.getLogger(__name__)


def refusal(message):
	"""
	The response for a search this endpoint will not run. Shaped like splunkd's own
	rejection of a search job (HTTP 400 with a FATAL message), which is what the caller,
	a dashboard's search manager, already knows how to show in the panel.
	"""
	logger.warning(message)

	return {'payload': {'messages': [{'type': 'FATAL', 'text': message}]}, 'status': 400}


class TenxSearchHandler(PersistentServerConnectionApplication):
	"""
	Rest api handler which gets a search request, and returns a 10x compatible search job SID.

	Input/output params are the same as the base /services/search/jobs endpoint.

	Supports just POST method for creating a new search.
	"""
	def __init__(self, command_line, command_arg):
		PersistentServerConnectionApplication.__init__(self)

	def extract_original_search_data(self, params_list):
		"""
		Builds search data from a list of lists.
		"""
		search_data = {}

		for param_arr in params_list:
			if not isinstance(param_arr, list):
				continue

			if len(param_arr) != 2:
				continue

			key = param_arr[0]
			value = param_arr[1]

			search_data[key] = value

		return search_data

	def handle(self, in_string):
		"""
		Main handler method.

		Does all the work of parsing input, creating a new search job, and returning the SID.

		Wraps it all with a log specifing endpoint runtime.
		"""
		start_time = tenx_util.current_time_ms()

		try:
			in_string_json = json.loads(in_string)

			method = in_string_json["method"]

			if method != "POST":
				logger.warning("Unsupported method {}.".format(method))
				return {'payload': "Unsupported method " + method, 'status': 405}

			server_uri = in_string_json.get('server', {}).get('rest_uri')
			token = in_string_json.get('session', {}).get('authtoken')

			tenx_config = tenx_util.get_tenx_config(server_uri=server_uri, token=token)

			logger.debug("Loaded config - {}".format(json.dumps(tenx_config)))

			if not tenx_config.get(tenx_util.CONFIG_LOADED, True):
				return refusal("10x: the app's configuration could not be read, so this search was not "
					"run (built on the defaults it would look for templates in the wrong index and "
					"return the wrong events). See tenx_search_handler.log.")

			server_connection = tenx_util.ServerConnection(
				server_uri=server_uri,
				user=in_string_json["session"]["user"],
				auth={'session_key': token})

			search_manager = tenx_search_manager.TenxSearchManager(
				server_connection=server_connection,
				tenx_config=tenx_config,
				app=in_string_json.get('ns', {}).get('app'))

			# Get the original search params.
			#
			search_data = self.extract_original_search_data(in_string_json['form'])

			original_search = search_data.get('search')

			if original_search:
				search_builder = tenx_search_builder.TenxSearchBuilder(
					server_connection=server_connection,
					tenx_config=tenx_config,
					search_manager=search_manager)

				# Create a 10x compatible search on encoded data.
				#
				build_result = search_builder.build(original_search)
				new_search = build_result.resolved

				logger.info("Original search - {} ..xxx.. New search - {} ({})".format(
					original_search, new_search, build_result.state))

				# A search that could not be rewritten must not run as typed. On compact data
				# the words are not in the events, so a dashboard panel would show zero and
				# "Search has completed": measured, a panel reading `(error OR warn) kubernetes`
				# showed 0 against a truth of 468 this way. Refuse instead, the same three
				# ways tenxsearch.py does.
				#
				if build_result.state == tenx_search_builder.ResolvedState.FAILURE:
					if build_result.retryable:
						return refusal("10x: the template lookup did not complete, so this search was not run "
							"(run as typed it would return the wrong events). Run it again.")

					return refusal("10x: this search could not be parsed for compact data, so it was not "
						"run. See tenx_search_handler.log for the parse error.")

				if build_result.state == tenx_search_builder.ResolvedState.COMPLEX:
					return refusal("10x: this search mixes sourcetypes or fields in a way the rewrite cannot "
						"follow, so it was not run. Put the compact sourcetype in a plain sourcetype=... term.")

				if not build_result.engaged:
					compact_sources = tenx_alert_compiler._referenced_tenx_sources(original_search, tenx_config)

					if compact_sources:
						return refusal("10x: this search names the compact source(s) {} but could not be "
							"rewritten for compact data, so it was not run. See tenx_search_handler.log.".format(
								", ".join(sorted(compact_sources))))

				search_data['search'] = new_search

			# Create a new search job from the search data.
			#
			search_job_sid = search_manager.create_search_job(search_data)

			if not search_job_sid:
				return {'payload': "Missing sid in job creation result", 'status': 500}

			# Return SID
			return {'payload': {'sid': search_job_sid}, 'status': 200}
		except Exception as e:
			logger.error("Unexpected error in tenx search handler - {}.".format(e), exc_info=1)
			return {'payload': str(e), 'status': 500}
		finally:
			logger.info("Total runtime - {}ms".format(tenx_util.current_time_ms() - start_time))
