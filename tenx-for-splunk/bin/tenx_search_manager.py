"""
Tenx Search Manager Module
=========================

This module provides utilities for managing Splunk search jobs and querying
the DML (template) sourcetype. It handles:

- Creating search jobs via /services/search/jobs
- Polling for job completion
- Retrieving search results
- Running DML searches to find matching template hashes

Key Operations
--------------
1. **Create Search Job**: POST to /services/search/jobs with search parameters
2. **Poll Job Status**: GET job details and check dispatchState
3. **Get Results**: Retrieve events from completed jobs
4. **DML Search**: Search tenx_dml_pure to find template hashes matching query

DML Search Workflow
-------------------
When a user searches for "error":
1. Create search: "search sourcetype=tenx_dml_pure error"
2. Poll until job completes
3. Extract unique dml_hash values from results
4. Return list of template hashes that contain "error"

These hashes are then used by TenxSearchBuilder to create a combined search
that covers both template matches and variable matches.

Classes
-------
TenxSearchManager
    Main class for search job operations.

JobState
    Enum for job completion states (SUCCESS, FAILURE, TIMEOUT).

API Endpoints Used
------------------
POST /servicesNS/{user}/search/search/jobs/
    Create new search job

GET /servicesNS/{user}/search/search/jobs/{sid}
    Get job details

GET /servicesNS/{user}/search/search/jobs/{sid}/events
    Get job results

GET /services/search/parser
    Parse search string

See Also
--------
- tenx_search_builder.py: Uses this module for DML searches
- tenxsearch.py: Search command that creates jobs
"""

import logging

logger = logging.getLogger(__name__)

import tenx_util

from enum import Enum, auto


class JobState(Enum):
	SUCCESS = auto()
	FAILURE = auto()
	TIMEOUT = auto()


# Cap on raw DML rows fetched per search. If a job actually matched more events than this,
# get_dml_results reports truncated=True - the returned hash set may be missing hashes that
# only appeared past the cap, so callers baking it into a persisted search should not treat
# it as a complete answer.
DML_FETCH_LIMIT = 25000


class TenxSearchManager:
	"""
	Class for handling common search related operations with the Splunk cluster.
	"""
	def __init__(self, server_connection, tenx_config):
		self.server_connection = server_connection
		self.tenx_config = tenx_config
		self.dml_key = 'dml_hash'

	def create_search_job_url(self):
		"""
		Returns the base url for creating a new search job.
		"""
		return '/servicesNS/' + self.server_connection.user + '/search/search/jobs/'

	def create_search_job(self, search_data):
		"""
		Creates a new search job with the provided search_data.
		Returns the new job SID, or None in case of errors.
		"""
		try:
			url = self.create_search_job_url()
			create_res = self.server_connection.post(url, search_data)

			if 'sid' not in create_res:
				logger.warning("Missing sid in job creation result for search - {}.".format(search_data['search']))
				return None

			return create_res['sid']
		except Exception as e:
			logger.error("Error creating search job for search - {} - {}.".format(search_data['search'], e), exc_info=1)
			return None

	def get_search_job_url(self, sid):
		"""
		Returns the base url for the specific search job SID provided.
		"""
		return self.create_search_job_url() + sid

	def get_search_job_details(self, sid):
		"""
		Returns the current details about an existing search job for the provided SID.
		Returns None in case of failures.
		"""
		try:
			url = self.get_search_job_url(sid)
			get_res = self.server_connection.get(url)

			return tenx_util.get_internal(get_res, 'entry', 0, 'content')
		except Exception as e:
			logger.error("Failed getting search {} state - {}.".format(sid, e), exc_info=1)
			return None

	def get_search_job_state(self, sid):
		"""
		Returns the current search job state for the provided SID.
		Returns None in case of errors or missing data.
		"""
		try:
			job_details = self.get_search_job_details(sid)

			if not job_details:
				logger.warning("Can't get job {} state from no details.".format(sid))
				return None

			return tenx_util.get_internal(job_details, 'dispatchState')
		except Exception as e:
			logger.error("Failed getting search {} state - {}.".format(sid, e), exc_info=1)
			return None

	def poll_for_job_end(self, sid, max_time_ms, poll_interval_ms):
		"""
		Polls a given search job until it either reach a terminal state (successful or not), or times out.
		Will poll for roughly a max time of max_time_ms (as the time it takes to actually poll is added),
		and in intervals of poll_interval_ms between different polls.

		If at any point the job state will be 'DONE', returns JobState.SUCCESS
		If at any point the job state will be 'FAILED', returns JobState.FAILURE

		If max_time_ms has been reached, returns JobState.TIMEOUT
		"""
		start_time = tenx_util.current_time_ms()

		while True:
			state = self.get_search_job_state(sid)

			if state == 'DONE':
				return JobState.SUCCESS

			if state == 'FAILED':
				return JobState.FAILURE

			if (tenx_util.current_time_ms() - start_time - poll_interval_ms) >= max_time_ms:
				break

			tenx_util.sleep_ms(poll_interval_ms)

		return JobState.TIMEOUT

	def get_search_results_url(self, sid):
		"""
		Returns the base url for the specific search job SID resulting events.
		"""
		return self.get_search_job_url(sid) + '/events'

	def get_search_results(self, sid, params=None):
		"""
		Returns the current search results for the search job matching the SID provided.

		Params may be used to affect different aspects of the returned results.
		"""
		if params is None:
			params = {}

		try:
			url = self.get_search_results_url(sid)
			return self.server_connection.get(url, params)

		except Exception as e:
			logger.error("Failed getting search {} state - {}.".format(sid, e), exc_info=1)
			return None

	def create_dml_search(self, dml_search):
		"""
		Creates a search job specifically for runs on the 10x DML sourcetype, from the given dml_search string.

		Jobs are always set to run from earliest_time of 0 until latest_time of now, as we need all the matches.
		Additionally sets to fetch the 'dml_hash' field from the events for easier usage later on.

		Returns the search job SID, or None in case of errors.
		"""
		search_data = {
			'earliest_time': '0',
			'latest_time': 'now',
			'rf': self.dml_key,
			'search': 'search sourcetype=%s %s' % (self.tenx_config['dml_source_type'], dml_search)
		}

		return self.create_search_job(search_data)

	def get_dml_results(self, sid):
		"""
		Returns (hashes, truncated) for a provided search job on the 10x DML.

		hashes is a list of all the unique hashes among the fetched rows (up to
		DML_FETCH_LIMIT). truncated is True when the job matched more raw rows than we
		fetched - past that cap, additional unique hashes may exist that this result set
		does not include, so it must not be treated as a complete answer.

		Returns (None, False) if any errors occured when trying to get the results.

		Note that a None result indicates an actual error, while an empty list is actually ok, it's quite possible
		no actual matches were found for a specific search.
		"""
		search_results = self.get_search_results(sid, {"f": self.dml_key, "count": DML_FETCH_LIMIT})

		if not search_results or 'results' not in search_results:
			return None, False

		raw_rows = search_results['results']
		hashes = list(set([result[self.dml_key] for result in raw_rows if self.dml_key in result]))

		job_details = self.get_search_job_details(sid)
		total_results = tenx_util.get_internal(job_details, 'resultCount') if job_details else None

		try:
			truncated = int(total_results) > DML_FETCH_LIMIT
		except (TypeError, ValueError):
			# Couldn't confirm the true total - fall back to the one signal we do have:
			# fetching exactly the cap is itself a sign there may be more.
			truncated = len(raw_rows) >= DML_FETCH_LIMIT

		return hashes, truncated

	def run_dml_search(self, dml_search, max_time_ms=2000, poll_interval_ms=50):
		"""
		Runs a search on the 10x DML, waits for the search job to finish, and returns the results.

		Basically a wrapper for create_dml_search -> poll_for_job_end -> get_dml_results.

		Returns (hashes, truncated); (None, False) in case of any errors along the way.
		"""
		logger.info("About to dml search - {}".format(dml_search))

		dml_sid = self.create_dml_search(dml_search)

		if dml_sid is None:
			logger.warning("Failed creating dml search for - {}.".format(dml_search))

			return None, False

		state = self.poll_for_job_end(dml_sid, max_time_ms, poll_interval_ms)

		if state != JobState.SUCCESS:
			logger.warning("Failed waiting for job {} - {} - {}.".format(dml_sid, dml_search, state))

			return None, False

		dml_results, truncated = self.get_dml_results(dml_sid)

		if dml_results is None:
			logger.warning("Failed getting dml results for job {} - {}.".format(dml_sid, dml_search))
			return None, False

		if truncated:
			logger.warning("DML search truncated at {} rows for {} - {}; hash set may be incomplete.".format(
				DML_FETCH_LIMIT, dml_sid, dml_search))

		logger.info("Got {} results for dml {} - {}.".format(len(dml_results), dml_sid, dml_search))

		return dml_results, truncated

	def parse_search_string_url(self):
		"""
		Returns the base url for parsing a search string a new search job.
		"""
		return '/services/search/parser'

	def parse_search_string(self, search, parse_only=False):
		try:
			data = {'q': search}

			if parse_only:
				data['parse_only'] = 'true'

			# Note: The search parser endpoint requires POST method
			return self.server_connection.post(self.parse_search_string_url(), data)
		except Exception as e:
			logger.error("Failed parsing search {} - {}.".format(search, e), exc_info=1)
			return None
