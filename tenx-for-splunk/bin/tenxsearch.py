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
3. Creates a new search that selects an event when each piece of each term is either
   in the compact event (a variable value) or in the event's template (see
   tenx_search_builder for the rules, including sub-token pieces such as the octets of
   an IP address)
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
4. Creates new search: ("error" OR ("~hash1" OR "~hash2")) | `tenx-inflate` | extract | search error
5. Runs search and streams inflated results

A search the builder cannot rewrite (a failed template lookup, a parse error, a shape it
cannot follow) is reported as an error and not run: run as typed on compact data it would
return the wrong events with no sign that anything was off.

Logging
-------
Logs to: $SPLUNK_HOME/var/log/splunk/tenx_search_command.log

See Also
--------
- tenx_search_handler.py: REST API alternative (faster)
- tenx_search_builder.py: Search resolution logic
- commands.conf: Command registration
"""


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
import tenx_alert_compiler

tenx_util.setup_logger('tenx_search_command', logging.INFO)

# How long to wait for the expanded search. Expanding 20,000 events took 54 seconds on a
# laptop container, so the previous 60 seconds was one bigger index away from returning
# nothing. The nested job is bounded by Splunk's own search limits either way.
MAX_WAIT_MS = 30 * 60 * 1000

# The expanded search runs as a job of its own, which this command polls every 100 ms while it
# waits and reads while it streams. Splunk cancels a job nobody has touched for this many
# seconds, so if this process is ended without running any cleanup, the expanded search stops
# with it.
NESTED_AUTO_CANCEL_S = 30


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
		# The expanded search runs as a job of its own. If this command stops before reading it
		# to the end (the outer search ended, or an error), that job is cancelled here; if the
		# process is ended outright, the job's auto_cancel stops it (see NESTED_AUTO_CANCEL_S).
		#
		search_manager = None
		search_sid = None
		finished = False

		try:
			server_uri = self._metadata.searchinfo.splunkd_uri
			token = self._metadata.searchinfo.session_key

			tenx_config = tenx_util.get_tenx_config(server_uri=server_uri, token=token)

			self.logger.debug("Loaded config - {}".format(json.dumps(tenx_config)))

			if not tenx_config.get(tenx_util.CONFIG_LOADED, True):
				self.write_error("10x: the app's configuration could not be read, so this search was not run "
					"(built on the defaults it would look for templates in the wrong index and return the "
					"wrong events). See tenx_search_command.log.")
				return

			server_connection = tenx_util.ServerConnection(
					server_uri=server_uri,
					user=self._metadata.searchinfo.username,
					auth={'session_key': token})

			search_manager = tenx_search_manager.TenxSearchManager(
				server_connection=server_connection,
				tenx_config=tenx_config,
				app=self._metadata.searchinfo.app)

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
			build_result = search_builder.build(self.searchstring)
			new_search = build_result.resolved

			self.logger.info("Original search {} - {} ..xxx.. New search - {} ({})".format(
				original_job_sid, self.searchstring, new_search, build_result.state))

			# A search that could not be rewritten must not run as typed: on compact data the
			# words are not in the events, so the bare search returns nothing, or the wrong
			# thing, with no sign that anything went wrong. Say so instead. A failed
			# dictionary lookup is transient (retry); a shape the rewrite cannot handle is not.
			#
			if build_result.state == tenx_search_builder.ResolvedState.FAILURE:
				if build_result.retryable:
					self.write_error("10x: the template lookup did not complete, so this search was not run "
						"(running it as typed would return the wrong events). Run it again.")
				else:
					self.write_error("10x: this search could not be parsed for compact data, so it was not run. "
						"See tenx_search_command.log for the parse error.")
				return

			if build_result.state == tenx_search_builder.ResolvedState.COMPLEX:
				self.write_error("10x: this search mixes sourcetypes or fields in a way the rewrite cannot "
					"follow, so it was not run (running it as typed would return the wrong events). "
					"Put the compact sourcetype in a plain sourcetype=... term.")
				return

			# A parse failure and a shape the grammar cannot follow both come back as a
			# passthrough of the search as typed. On a search that names a compact sourcetype
			# that is the silent wrong answer again, so it is refused the same way.
			#
			if not build_result.engaged:
				compact_sources = tenx_alert_compiler._referenced_tenx_sources(self.searchstring, tenx_config)

				if compact_sources:
					self.write_error("10x: this search names the compact source(s) {} but could not be rewritten "
						"for compact data, so it was not run (as typed it would return the wrong events). "
						"Check the search for a shape the rewrite does not follow, such as a parenthesised "
						"group followed by more terms, or a sourcetype inside an OR; the parse error is in "
						"tenx_search_command.log.".format(", ".join(sorted(compact_sources))))
					return

			actual_search = self.searchstring if new_search is None else new_search

			search_data = {
				"earliest_time": job_details['request'].get('earliest_time', ''),
				"latest_time": job_details['request'].get('latest_time', ''),
				'rf': job_details['request'].get('rf', '*'),
				"search": actual_search,
				"auto_cancel": NESTED_AUTO_CANCEL_S
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
			# Splunk does not stop this command when the outer search is cancelled; it keeps
			# waiting. So the outer search is checked while waiting, and the expanded search is
			# cancelled (in the finally below) once the outer one has ended.
			#
			search_job_state = search_manager.poll_for_job_end(search_sid, MAX_WAIT_MS, 100,
				keep_going=lambda: search_manager.is_job_live(original_job_sid))

			if search_job_state == tenx_search_manager.JobState.ABORTED:
				self.logger.info("Outer search {} ended; stopping {}.".format(original_job_sid, search_sid))
				return

			if search_job_state != tenx_search_manager.JobState.SUCCESS:
				self.logger.warning("Job {} didn't finish, state is {} ({}).".format(search_sid, search_job_state, original_job_sid))
				# Returning nothing here would look like "no matches". It is not.
				#
				self.write_error("10x: the expanded search {} did not finish ({}); no results were returned, "
					"which is not the same as no matches. Narrow the time range or run it again.".format(
						search_sid, search_job_state.name))
				return

			self.logger.info("Done running {} ({}).".format(search_sid, original_job_sid))

			search_job_details = search_manager.get_search_job_details(search_sid)

			# A search that ends in a transforming command (stats and the like) has its output
			# under /results, counted by resultCount; an event search has its events under
			# /events, counted by eventCount.
			#
			transformed = bool(search_job_details.get('reportSearch'))
			count_key = 'resultCount' if transformed else 'eventCount'

			if count_key not in search_job_details:
				self.logger.warning("Missing {} in job details {} ({}).".format(count_key, search_sid, original_job_sid))
				return

			event_count = int(search_job_details[count_key])

			if event_count <= 0:
				self.logger.info("No events returned for search {} ({}).".format(search_sid, original_job_sid))
				return

			self.logger.info("Job {} has {} events ({}).".format(search_sid, event_count, original_job_sid))

			# Rows fetched from the nested job per REST call. At 100 rows, 20,000 events were 200
			# round trips and 41 seconds end to end; at 5,000 rows, with the fields below dropped,
			# 21 seconds. The remaining time is this process writing the rows out one by one,
			# which is the cost of a generating command and the reason dashboards use the REST
			# handler instead (see tenx_search_handler.py).
			#
			increment = 5000

			# Splunk regenerates these for the outer job, so carrying them through only adds
			# to the bytes this process has to write.
			#
			regenerated_fields = ('_bkt', '_cd', '_si', '_kv', '_serial', '_indextime', '_sourcetype')

			# Streaming back the results from the search job.
			#
			for start_offset in range(0, event_count, increment):
				event_count_to_request = min(increment, event_count - start_offset)

				params = {"offset": start_offset, "count": event_count_to_request}

				search_results = search_manager.get_search_results(search_sid, params, transformed=transformed)

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
					for field in regenerated_fields:
						result.pop(field, None)

					yield result

			finished = True

		except Exception as e:
			self.logger.error("Unexpected error running tenxsearch - {}.".format(e), exc_info=1)

		finally:
			if search_sid is not None and not finished:
				self.logger.info("Cancelling nested search {}.".format(search_sid))
				search_manager.cancel_search_job(search_sid)


dispatch(TenxSearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
