"""
Tenx DML to KV Store Alert Action
================================

This module implements the alert action that populates the KV store with parsed
template data. It is triggered by the "Consume KV" saved search which runs every
2 minutes to process new template definitions.

Data Flow
---------
1. 10x pipeline sends template definitions to Splunk with sourcetype `tenx_dml_raw_json`
2. "Consume KV" saved search finds new templates and triggers this alert action
3. This script reads the search results (JSON template definitions)
4. For each template:
   a. Check if it already exists in KV store (skip if yes)
   b. Parse template into structured format using TenxDMLBuilder
   c. Submit searchable version to `tenx_dml_pure` sourcetype
   d. Create entry in `kvdml` KV store collection

Input Format
------------
The saved search results contain JSON objects with:
    {
        "templateHash": "<unique_hash_identifier>",
        "template": "<template_pattern_with_$_separators>"
    }

Output Format
-------------
KV Store Entry (kvdml collection):
    {
        "_key": "<hash>",
        "pattern_hash": "<hash>",
        "pattern": "<original_template>",
        "pattern_parts": ["<part1>", "<part2>", ...],
        "part_0": "<first_part>",
        "pattern_terminator": "<last_part>",
        "timestamp_format": "<splunk_strftime_format>"
    }

DML Pure Event:
    "<hash> <template_with_separators_removed>"

Execution
---------
This script is invoked by Splunk as an alert action with the --execute flag:
    python tenx_dml_to_kv.py --execute

The script reads a JSON payload from stdin containing:
    - server_uri: Splunk REST API endpoint
    - session_key: Authentication token
    - results_file: Path to gzipped CSV of search results
    - server_host: Host name for event metadata

Configuration
-------------
Settings are loaded from tenx_config.conf via tenx_util.get_tenx_config():
    - variable_separator: Character separating variables in templates (default: $)
    - timestamp_placeholder: Placeholder for timestamp in patterns (default: __TENX_TS__)
    - collection_name: KV store collection name (default: kvdml)
    - dest_dml_index: Index for DML pure events (default: main)
    - dml_source_type: Sourcetype for DML pure events (default: tenx_dml_pure)

Logging
-------
Logs are written to: $SPLUNK_HOME/var/log/splunk/tenx_dml_to_kv.log

See Also
--------
- savedsearches.conf: "Consume KV" saved search definition
- alert_actions.conf: Alert action configuration
- tenx_dml_builder.py: Template parsing logic
- collections.conf: KV store schema
"""

from future import standard_library
standard_library.install_aliases()

import os
import sys
import logging
import json
import gzip
import csv

from splunk.clilib.bundle_paths import get_base_path

# ============================================================================
# Application Setup
# ============================================================================

# Application name - must match the app directory name in $SPLUNK_HOME/etc/apps/
APP_NAME = 'tenx-for-splunk'
apphome = os.path.join(get_base_path(), APP_NAME)
sys.path.append(os.path.join(apphome, 'bin'))
sys.path.append(os.path.join(apphome, 'lib'))

import tenx_util
import tenx_kv_intf
import tenx_dml_intf
import tenx_dml_builder

# Configure logging to write to $SPLUNK_HOME/var/log/splunk/tenx_dml_to_kv.log
tenx_util.setup_logger('tenx_dml_to_kv', logging.INFO)
logger = logging.getLogger(__name__)

# Validation limits to prevent resource exhaustion
MAX_TEMPLATE_SIZE = 65536  # 64KB max template size
MAX_HASH_SIZE = 256        # 256 char max hash length


# ============================================================================
# Helper Functions
# ============================================================================


def non_empty_string(s):
	"""
	Check if a string is non-empty and not just whitespace.

	Args:
		s: Value to check (may be None or any type)

	Returns:
		bool: True if s is a non-empty, non-whitespace string
	"""
	if not s or s.isspace():
		return False

	return True


def get_results_reader(settings):
	"""
	Returns a csv.DictReader for reading the results of the search, from the file in settings.get('results_file')

	Returns None and emits to log in case of failure.
	"""
	try:
		if 'results_file' not in settings:
			logger.warning("Missing results file")
			return None

		results_file = settings.get('results_file')

		if not non_empty_string(results_file):
			logger.warning("Missing actual results_file name")
			return None

		csv_results = gzip.open(results_file, mode='rt')
		return csv.DictReader(csv_results)
	except Exception as e:
		logger.error("Failed getting reader for results file {} - {}.".format(settings.get('results_file'), e), exc_info=1)
		return None


def get_result_parts(result):
	"""
	Returns the hash and content parts from each event result.

	Returns None, None if any of them are invalid or exceed size limits.
	"""
	raw_line = result.get('_raw')

	record_key = result.get('templateHash')
	pattern = result.get('template')

	if not non_empty_string(record_key):
		logger.warning("Missing dml_hash on line - {}".format(raw_line))
		return None, None

	if not non_empty_string(pattern):
		logger.warning("Missing actual pattern on line - {}".format(raw_line))
		return None, None

	# Size validation to prevent resource exhaustion
	if len(record_key) > MAX_HASH_SIZE:
		logger.warning("Hash exceeds max size ({} > {}), skipping: {}...".format(
			len(record_key), MAX_HASH_SIZE, record_key[:50]))
		return None, None

	if len(pattern) > MAX_TEMPLATE_SIZE:
		logger.warning("Template exceeds max size ({} > {}), skipping hash: {}".format(
			len(pattern), MAX_TEMPLATE_SIZE, record_key))
		return None, None

	return record_key, pattern


def update_kv_store(settings):
	"""
	Updateds the KV store and "pure" DML sourcetype from the "raw" DML data which is forwarded into splunk.

	This script is configured via a periodic cron based alert which fires with all new events inserted into the "raw" DML.

	Default config is to run this every 2 minutes, with the last 10 minutes of new events, to avoid missing stuff
	due to possible hiccups in the process.

	This config can be changed by modifying the savedsearches.conf file, either manually, via API, or Splunk's UI.

	The process runs over all the given results of the search, checks for their existence in the KV store, and if
	missing adds them to both the "pure" DML, and the KV store.

	Because the process checks existance before placing new items, duplicate items should be reduced to a minimum.
	They can still happen due to certain race conditions, as we don't actually "lock" or CAS data, but this is a
	relatively rare event, which we can live with.

	Returns the number of successful updates, or -1 in case of unexpected errors.
	"""
	try:
		server_uri = settings.get('server_uri')
		token = settings.get('session_key')

		tenx_config = tenx_util.get_tenx_config(server_uri=server_uri, token=token)

		logger.info("Loaded config - {}".format(json.dumps(tenx_config)))

		variable_separator = tenx_config['variable_separator']
		timestamp_placeholder = tenx_config['timestamp_placeholder']

		server_connection = tenx_util.ServerConnection(
			server_uri=server_uri,
			user="fill_this",
			auth={'session_key': token})

		dml_intf = tenx_dml_intf.TenxDmlInterface(
			server_connection=server_connection,
			host=settings.get('server_host'),
			index_name=tenx_config['dest_dml_index'],
			dml_sourcetype=tenx_config['dml_source_type'])

		kv_intf = tenx_kv_intf.TenxKVInterface(
			collection_name=tenx_config['collection_name'],
			server_connection=server_connection,
			app_name=APP_NAME,
			owner='nobody')

		dml_builder = tenx_dml_builder.TenxDMLBuilder(
			timestamp_placeholder=timestamp_placeholder,
			variable_separator=variable_separator)

		reader = get_results_reader(settings)

		if reader is None:
			# Logging already happens inside get_results_reader
			return -1

		events_source = "consume_kv_alert"

		# Counters for observability
		updates_performed = 0
		skipped_invalid = 0
		skipped_existing = 0
		skipped_dml_error = 0

		for result in reader:
			record_key, pattern = get_result_parts(result)

			if record_key is None:
				# Logging already happens inside get_result_parts
				skipped_invalid += 1
				continue

			if kv_intf.get_entry(record_key):
				logger.debug("Already has entry for {}, skipping.".format(record_key))
				skipped_existing += 1
				continue

			pure_dml_event = dml_builder.build_pure_dml_line(record_key, pattern)

			if not dml_intf.submit(record_key, pure_dml_event, events_source):
				logger.warning("Failed submitting {} to dml, won't update kv store.".format(record_key))
				skipped_dml_error += 1
				continue

			record_data = dml_builder.build_kv_record_data(record_key, pattern)

			if kv_intf.create_entry(record_key, record_data):
				updates_performed += 1

		# Log summary stats
		if skipped_invalid > 0 or skipped_dml_error > 0:
			logger.info("Processing summary: added={}, existing={}, invalid={}, errors={}".format(
				updates_performed, skipped_existing, skipped_invalid, skipped_dml_error))

		return updates_performed
	except Exception as e:
		logger.error("Unexpected error in tenx dml to kv handler - {}.".format(e), exc_info=1)
		return -1


if __name__ == "__main__":
	if len(sys.argv) > 1 and sys.argv[1] == "--execute":
		startTime = tenx_util.current_time_ms()
		payload = json.loads(sys.stdin.read())
		num_updates = update_kv_store(payload)

		if num_updates < 0:
			logger.warning("Failed updating KV store")
			sys.exit(2)
		
		logger.info("Updated KV store with {} records".format(num_updates))
		logger.info("Total runtime - {}ms".format(tenx_util.current_time_ms() - startTime))
	else:
		logger.error("Unsupported execution mode (expected --execute flag)")
		sys.exit(1)
