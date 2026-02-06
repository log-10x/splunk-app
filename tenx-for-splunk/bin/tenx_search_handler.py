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
    curl -k -u admin:password \\
        -d "search=error&earliest_time=-1h&latest_time=now" \\
        https://localhost:8089/servicesNS/admin/tenx-for-splunk/tenx-search

    # Response: {"sid": "1234567890.12345"}

    # Then poll for results:
    curl -k -u admin:password \\
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

from future import standard_library
standard_library.install_aliases()

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

tenx_util.setup_logger('tenx_search_handler', logging.INFO)
logger = logging.getLogger(__name__)


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

			logger.info("Loaded config - {}".format(json.dumps(tenx_config)))

			server_connection = tenx_util.ServerConnection(
				server_uri=server_uri,
				user=in_string_json["session"]["user"],
				auth={'session_key': token})

			search_manager = tenx_search_manager.TenxSearchManager(
				server_connection=server_connection,
				tenx_config=tenx_config)

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
				new_search = search_builder.resolve(original_search)

				logger.info("Original search - {} ..xxx.. New search - {}".format(original_search, new_search))

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
