"""
Tenx Search Generating Command
=============================

This module implements a Splunk generating command that enables searching
10x-encoded data using standard SPL queries. The command resolves user
search terms against the DML (template) data and returns inflated results.

Usage in SPL
------------
    | tenxsearch searchstring="index=myindex error"

The command:
1. Parses the user's search string
2. Searches the DML sourcetype to find matching template hashes
3. Creates a new search that includes both:
   - Original search terms (for variable data)
   - Template hashes (for encoded data)
4. Runs the search with tenx-inflate macro
5. Streams results back to the user

Performance Considerations
--------------------------
Because Python generating commands have overhead when streaming results,
using the REST handler (/tenx-search) is recommended for interactive use.
However, this command is necessary for:
- Saved searches
- Scheduled alerts
- Dashboard panels

Workflow
--------
1. User runs: | tenxsearch searchstring="error"
2. Command parses "error" and searches tenx_dml_pure for matching templates
3. Finds template hashes that contain "error"
4. Creates new search: (error OR tenx_hash IN (hash1,hash2)) | `tenx-inflate`
5. Runs search and streams inflated results

Logging
-------
Logs to: $SPLUNK_HOME/var/log/splunk/tenx_search_command.log

See Also
--------
- tenx_search_handler.py: REST API alternative (faster)
- tenx_search_builder.py: Search resolution logic
- commands.conf: Command registration
"""

from future import standard_library
standard_library.install_aliases()

import os
import sys
import json
import logging

from splunk.clilib.bundle_paths import get_base_path

# ============================================================================
# Application Setup
# ============================================================================

# Application name - must match the app directory name
APP_NAME = 'tenx-for-splunk'
apphome = os.path.join(get_base_path(), APP_NAME)
sys.path.append(os.path.join(apphome, 'bin'))
sys.path.append(os.path.join(apphome, 'lib'))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option

import tenx_util
import tenx_search_manager
import tenx_search_builder

tenx_util.setup_logger('tenx_search_command', logging.INFO)


@Configuration()
class TenxSearchCommand(GeneratingCommand):
	"""
	Generating command which effectively returns the result of doing the given searchstring
	on 10x encoded data.

	Because of the way python commands work and the possible slowness when transmitting results
	back, using this isn't recommended when it can be avoided.

	Better performance is achieved by instead using the '/tenx-search' rest handler which creates
	an 10x encoded search and returns the SID for the user.

	However, some cases (such as configuring periodic alerts via saved searches) can only perform
	searches on 10x encoded data via the usage of this command.

	See tenx_search_handler.py for more details
	"""

	searchstring = Option(require=True)

	def generate(self):
		try:
			server_uri = self._metadata.searchinfo.splunkd_uri
			token = self._metadata.searchinfo.session_key

			tenx_config = tenx_util.get_tenx_config(server_uri=server_uri, token=token)

			self.logger.info("Loaded config - {}".format(json.dumps(tenx_config)))

			server_connection = tenx_util.ServerConnection(
					server_uri=server_uri,
					user=self._metadata.searchinfo.username,
					auth={'session_key': token})

			search_manager = tenx_search_manager.TenxSearchManager(
				server_connection=server_connection,
				tenx_config=tenx_config)

			original_job_sid = self._metadata.searchinfo.sid

			# Getting the existing job details for easy extraction of the search timeframe.
			#
			job_details = search_manager.get_search_job_details(original_job_sid)

			if job_details is None:
				self.logger.error("Failed getting original search {} details.".format(original_job_sid))
				return

			search_builder = tenx_search_builder.TenxSearchBuilder(
						server_connection=server_connection,
						tenx_config=tenx_config,
						search_manager=search_manager)

			# Converting the input search into a matching 10x encoded search.
			#
			new_search = search_builder.resolve(self.searchstring)

			self.logger.info("Original search {} - {} ..xxx.. New search - {}".format(original_job_sid, self.searchstring, new_search))

			actual_search = self.searchstring if new_search is None else new_search

			search_data = {
				"earliest_time": job_details['request'].get('earliest_time', ''),
				"latest_time": job_details['request'].get('latest_time', ''),
				'rf': job_details['request'].get('rf', '*'),
				"search": actual_search
			}

			# Creating a search job for the new search.
			#
			search_sid = search_manager.create_search_job(search_data)

			if search_sid is None:
				self.logger.error("Failed getting search id for search - {} ({}).".format(actual_search, original_job_sid))
				return

			self.logger.info("Got new search {} ({}).".format(search_sid, original_job_sid))

			# Waiting for the job to finish.
			#
			search_job_state = search_manager.poll_for_job_end(search_sid, 60000, 100)  # TODO - infinity?

			if search_job_state != tenx_search_manager.JobState.SUCCESS:
				self.logger.warning("Job {} didn't finish, state is {} ({}).".format(search_sid, search_job_state, original_job_sid))
				return

			self.logger.info("Done running {} ({}).".format(search_sid, original_job_sid))

			search_job_details = search_manager.get_search_job_details(search_sid)

			if 'eventCount' not in search_job_details:
				self.logger.warning("Missing eventCount in job details {} ({}).".format(search_sid, original_job_sid))
				return

			event_count = int(search_job_details['eventCount'])

			if event_count <= 0:
				self.logger.info("No events returned for search {} ({}).".format(search_sid, original_job_sid))
				return

			self.logger.info("Job {} has {} events ({}).".format(search_sid, event_count, original_job_sid))

			increment = 100  # TODO - config?

			# Streaming back the results from the search job.
			#
			for start_offset in range(0, event_count, increment):
				event_count_to_request = min(increment, event_count - start_offset)

				params = {"offset": start_offset, "count": event_count_to_request}

				search_results = search_manager.get_search_results(search_sid, params)

				if search_results is None:
					self.logger.warning("Failed getting results {}->{} for {} ({}).".format(
						start_offset, start_offset + event_count_to_request, search_sid, original_job_sid))

					continue

				self.logger.info("Got results {}->{} for {} ({}).".format(
					start_offset, start_offset + event_count_to_request, search_sid, original_job_sid))

				if 'results' not in search_results:
					self.logger.warning("Got no actual results {}->{} for {} ({}).".format(
						start_offset, start_offset + event_count_to_request, search_sid, original_job_sid))

					continue

				actual_results = search_results['results']

				if len(actual_results) != event_count_to_request:
					self.logger.warning("Got {} events in results {}->{} for {} ({}).".format(
						len(actual_results), start_offset, start_offset + event_count_to_request, search_sid, original_job_sid))

				for result in actual_results:
					yield result

		except Exception as e:
			self.logger.error("Unexpected error running tenxsearch - {}.".format(e), exc_info=1)


dispatch(TenxSearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
