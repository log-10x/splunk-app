"""
Tenx DML to KV Store Alert Action
================================

This module implements the alert action that populates the KV store with parsed
template data. It is started by the "Consume KV" saved search every 5 minutes.

Data Flow
---------
1. 10x pipeline sends template definitions to Splunk with sourcetype `tenx_dml_raw_json`
2. "Consume KV" (`| makeresults`) starts this alert action on every run
3. The action reads the template records indexed since its checkpoint (the index time it has
   loaded through, kept in the `tenx_kv_state` collection) with its own export searches, in
   slices of index time, and moves the checkpoint after each slice (load_since)
4. For each chunk of records:
   a. Read what the KV store holds under their keys, in one batch_find
   b. Reconcile each record with it (reconcile: new, same, cut, conflict, refreshed)
   c. Write the records that change with batch_save, new ones with their searchable copy pending
5. Write the searchable copy of every pending template with `collect` (tenx_dml_intf.py)

A search that returns template records, piped to `| sendalert tenx_dml_to_kv`, has exactly
those records stored instead (the results carry a templateHash column).

Input Format
------------
The saved search results contain JSON objects with:
    {
        "templateHash": "<unique_hash_identifier>",
        "template": "<template_pattern_with_$_separators>"
    }

Output Format
-------------
KV Store Entry (tenx_dml collection):
    {
        "_key": "<hash>",
        "pattern_hash": "<hash>",
        "pattern": "<original_template>",
        "pattern_parts": ["<part1>", "<part2>", ...],
        "part_0": "<first_part>",
        "pattern_terminator": "<last_part>",
        "timestamp_format": "<splunk_strftime_format>",
        "expand_unsafe": "<empty, or why the template cannot be expanded>",
        "pattern_search": "<template_with_separators_removed>",
        "search_copy": "pending | written"
    }

Searchable copy, sourcetype stash, source tenx_dml_pure:
    "<hash>\t<template_with_separators_removed>"

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
Alert action parameters (alert_actions.conf):
    - source: the event search that finds template records
    - from: an index time to load from instead of the checkpoint (0: all)

Settings are loaded from tenx_config.conf via tenx_util.get_tenx_config():
    - variable_separator: Character separating variables in templates (default: $)
    - timestamp_placeholder: Placeholder for timestamp in patterns (default: __TENX_TS__)
    - collection_name: KV store collection name (default: tenx_dml)
    - dest_dml_index: Index for the searchable copy (default: tenx_dml)
    - dml_source_type: Source of the searchable copy (default: tenx_dml_pure)

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


import os
import sys
import time
import logging
import json
import gzip
import csv


# ============================================================================
# Application Setup
# ============================================================================

# Application name - must match the app directory name in $SPLUNK_HOME/etc/apps/
APP_NAME = 'tenx-for-splunk'
# The app's own folder, wherever Splunk keeps it (etc/apps, or etc/peer-apps on an indexer cluster peer).
apphome = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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


LOOKUP_NAME = 'tenx-dml-lookup'

RECONCILE_CREATED = "created"
RECONCILE_SAME = "same"
RECONCILE_REPLACED = "replaced"
RECONCILE_CONFLICT = "conflict"
RECONCILE_REFRESHED = "refreshed"

# Where Consume KV has loaded template records up to: one record in its own collection
# (collections.conf [tenx_kv_state]), which is not replicated to the indexers.
STATE_COLLECTION = 'tenx_kv_state'
STATE_KEY = 'consume_kv'
STATE_LOADED_THROUGH = 'loaded_through'
STATE_UPDATED = 'updated'
STATE_STATUS = 'status'
STATE_DETAIL = 'detail'
STATE_RECORDS = 'records'
STATUS_CURRENT = 'current'
STATUS_LOADING = 'loading'
STATUS_FAILED = 'failed'

# The event search that finds template records, when the alert action is given none.
DEFAULT_SOURCE = 'index=tenx_dml sourcetype=tenx_dml_raw_json'
# A record is read again for this long after the index time loaded through: a record an indexer
# writes with a clock behind another indexer's, or one that becomes searchable late, is still read.
# Reading a stored template again writes nothing.
OVERLAP_SECONDS = 300
# Records indexed in the last seconds are left to the next run.
LAG_SECONDS = 30
# Template records read and stored between two checkpoint writes.
SLICE_RECORDS = 25000
# A run starts no new slice after this long, so it ends well inside the alert action's maxtime
# (alert_actions.conf); the next run resumes from the checkpoint.
RUN_BUDGET_SECONDS = 240
# Records handed to the KV store together (one batch_find, then batch_save calls).
CHUNK_RECORDS = 2000
# New templates whose searchable copy is written together: one copy search returns at most
# 50,000 keys (limits.conf [restapi] maxresultrows), so it is run before that many are pending.
COPY_EVERY = 20000


def reconcile(dml_builder, existing, record_key, pattern):
	"""
	Decides what an incoming template means for the record stored under its key, and returns
	(outcome, record): one of the RECONCILE_* outcomes, and the whole record to write, or None
	when nothing is written.

	No stored record: the template is stored, its searchable copy pending.

	The key is the template hash, trimmed. The same key with the same text is a template sent
	again, which is normal: every Receiver sends each template once per start. The same key
	with different text is two templates under one hash, or two hashes that differ only by
	surrounding whitespace. Expanding their events with either text prints a line that was
	never written, so the record is marked hash-conflict and the inflate macro leaves those
	events compact.

	One different-text case is not a conflict: under the same hash, a text that is a strict
	prefix of the other was cut by a TRUNCATE limit on the way in. The longer one is kept; an
	incoming whole template replaces a stored cut one.

	The same text sent again is rebuilt, and the record is rewritten when a field derived from
	the text differs, as it does after an upgrade that changes how a field is derived (a
	timestamp format, say). The searchable copy and a hash-conflict mark are kept.
	"""
	if not isinstance(existing, dict):
		record = dml_builder.build_kv_record_data(record_key, pattern)
		record[tenx_dml_intf.SEARCH_COPY] = tenx_dml_intf.SEARCH_COPY_PENDING
		return RECONCILE_CREATED, record

	stored_hash = existing.get(tenx_dml_builder.RECORD_PATTERN_HASH)
	stored_pattern = existing.get(tenx_dml_builder.RECORD_PATTERN)

	same_hash = stored_hash is None or stored_hash == record_key
	same_pattern = stored_pattern is None or stored_pattern == pattern

	if same_hash and same_pattern:
		rebuilt = dml_builder.build_kv_record_data(record_key, pattern)

		if existing.get(tenx_dml_builder.RECORD_EXPAND_UNSAFE) == tenx_dml_builder.UNSAFE_HASH_CONFLICT:
			rebuilt[tenx_dml_builder.RECORD_EXPAND_UNSAFE] = tenx_dml_builder.UNSAFE_HASH_CONFLICT

		stale = [k for k, v in rebuilt.items() if existing.get(k) != v]

		if not stale:
			return RECONCILE_SAME, None

		if tenx_dml_intf.SEARCH_COPY in existing:
			rebuilt[tenx_dml_intf.SEARCH_COPY] = existing[tenx_dml_intf.SEARCH_COPY]

		logger.info("Refreshed the stored record for {}: {}.".format(record_key, ", ".join(sorted(stale))))
		return RECONCILE_REFRESHED, rebuilt

	if same_hash and stored_pattern.startswith(pattern):
		logger.info("Template {} arrived cut ({} of {} characters); the stored whole one is kept.".format(
			record_key, len(pattern), len(stored_pattern)))
		return RECONCILE_SAME, None

	if same_hash and pattern.startswith(stored_pattern):
		whole = dml_builder.build_kv_record_data(record_key, pattern)
		whole[tenx_dml_intf.SEARCH_COPY] = tenx_dml_intf.SEARCH_COPY_PENDING
		logger.info("Replaced the cut template stored for {} ({} of {} characters) with the whole one.".format(
			record_key, len(stored_pattern), len(pattern)))
		return RECONCILE_REPLACED, whole

	if existing.get(tenx_dml_builder.RECORD_EXPAND_UNSAFE) == tenx_dml_builder.UNSAFE_HASH_CONFLICT:
		return RECONCILE_SAME, None

	flagged = {k: v for k, v in existing.items() if not k.startswith('_')}
	flagged[tenx_dml_builder.RECORD_EXPAND_UNSAFE] = tenx_dml_builder.UNSAFE_HASH_CONFLICT

	logger.warning("Template hash conflict on key {!r}: stored hash {!r} with {} characters of text, incoming hash {!r} with {} characters of different text. "
		"Events under this key now stay compact, marked hash-conflict.".format(
			record_key.strip(), stored_hash, len(stored_pattern or ''), record_key, len(pattern)))

	return RECONCILE_CONFLICT, flagged


class TemplateStore:
	"""
	Stores template records in the KV store in chunks: one batch_find reads what is stored under
	the chunk's keys, each record is reconciled in arrival order against what is stored (or what
	an earlier record of the chunk made of it), and the records that change are written with
	batch_save. A template stored already is read and not written, so loading a record twice
	changes nothing.
	"""
	def __init__(self, kv_intf, dml_builder):
		self.kv_intf = kv_intf
		self.dml_builder = dml_builder
		self.limits = kv_intf.batch_limits()
		self.counts = dict.fromkeys((RECONCILE_CREATED, RECONCILE_SAME, RECONCILE_REPLACED,
			RECONCILE_CONFLICT, RECONCILE_REFRESHED), 0)
		self.invalid = 0
		self.written = 0
		# Records written with their searchable copy pending since the last copy (copy_pending).
		self.pending = {}

	def store(self, records):
		"""
		records: (template hash, template) pairs in arrival order. Raises when the KV store
		cannot be read or written, so a caller does not move its checkpoint past them.
		"""
		for start in range(0, len(records), CHUNK_RECORDS):
			self._store_chunk(records[start:start + CHUNK_RECORDS])

	def _store_chunk(self, records):
		valid = []
		for record_key, pattern in records:
			record_key, pattern = get_result_parts({'templateHash': record_key, 'template': pattern})
			if record_key is None:
				self.invalid += 1
				continue
			valid.append((record_key, pattern))

		if not valid:
			return

		current = self.kv_intf.find_many([self.kv_intf.kv_key(k) for k, _ in valid])
		writes = {}

		for record_key, pattern in valid:
			key = self.kv_intf.kv_key(record_key)
			outcome, record = reconcile(self.dml_builder, current.get(key), record_key, pattern)
			self.counts[outcome] += 1

			if record is not None:
				record = dict(record)
				record[self.kv_intf.KV_KEY] = key
				current[key] = record
				writes[key] = record

		if writes and not self.kv_intf.save_many(list(writes.values()), self.limits):
			raise RuntimeError("the KV store did not take {} template records".format(len(writes)))

		self.written += len(writes)
		for key, record in writes.items():
			if record.get(tenx_dml_intf.SEARCH_COPY) == tenx_dml_intf.SEARCH_COPY_PENDING:
				self.pending[key] = record
			else:
				self.pending.pop(key, None)

	def copy_pending(self, dml_intf):
		"""
		Writes the searchable copy of the templates stored since the last call (and of any other
		record still pending) and marks them written. A copy that fails leaves them pending for
		the next run.
		"""
		if not self.pending:
			return
		known, self.pending = list(self.pending.values()), {}
		if dml_intf.write_pending(known) < 0:
			logger.warning("The searchable copy of new templates was not written; they stay pending for the next run.")

	def summary(self):
		return "added={}, refreshed={}, replaced={}, conflicts={}, unchanged={}, invalid={}".format(
			self.counts[RECONCILE_CREATED], self.counts[RECONCILE_REFRESHED], self.counts[RECONCILE_REPLACED],
			self.counts[RECONCILE_CONFLICT], self.counts[RECONCILE_SAME], self.invalid)

	def changed(self):
		return self.counts[RECONCILE_CREATED] + self.counts[RECONCILE_REFRESHED] + self.counts[RECONCILE_REPLACED]


def export_results(server_connection, search):
	"""
	Runs search to completion through search/jobs/export, over all event time, and yields its
	results as they stream. The export endpoint returns every result: it is not held to the
	50,000 rows of a oneshot search nor to an alert action's maxresults. Raises on an error
	message from the search.
	"""
	url = '/servicesNS/nobody/{}/search/jobs/export'.format(APP_NAME)
	data = {'search': search, 'earliest_time': '0', 'latest_time': '+10y', 'preview': 'false'}
	response = server_connection.post(url, data, read_result=False)

	for line in response:
		line = line.strip()
		if not line:
			continue
		message = json.loads(line)
		if 'result' in message:
			yield message['result']
		for note in message.get('messages') or []:
			if note.get('type') in ('ERROR', 'FATAL'):
				raise RuntimeError("search failed: {}".format(note.get('text')))


def index_time_counts(server_connection, source, start, end, step):
	"""
	The number of template records indexed in each step (60: minute, 1: second) of [start, end),
	as sorted (step start, count) pairs.
	"""
	search = ('search {} _index_earliest={} _index_latest={}'
		' | eval tenx_kv_step=_indextime-(_indextime%{}) | stats count by tenx_kv_step').format(source, int(start), int(end), int(step))
	counts = [(int(float(r['tenx_kv_step'])), int(float(r['count'])))
		for r in export_results(server_connection, search) if r.get('tenx_kv_step') not in (None, '')]
	return sorted(counts)


def index_time_plan(server_connection, source, start, end, slice_records=None):
	"""
	The record counts of [start, end) by minute, and by second inside a minute that holds more
	than slice_records, so plan_slices can cut there.
	"""
	slice_records = SLICE_RECORDS if slice_records is None else slice_records
	plan = []
	for minute, count in index_time_counts(server_connection, source, start, end, 60):
		if count > slice_records:
			plan.extend(index_time_counts(server_connection, source, max(start, minute), min(end, minute + 60), 1))
		else:
			plan.append((minute, count))
	return plan


def plan_slices(minutes, start, end, slice_records=None):
	"""
	Splits [start, end) of index time into consecutive [a, b) slices at the step boundaries of
	`minutes` (index_time_plan), each with about slice_records records or one step. Returns
	[(a, b, records)].
	"""
	slice_records = SLICE_RECORDS if slice_records is None else slice_records
	slices, a, n = [], start, 0
	for minute, count in minutes:
		if n and n + count > slice_records and minute > a:
			slices.append((a, minute, n))
			a, n = minute, 0
		n += count
	slices.append((a, end, n))
	return slices


def read_state(state_intf):
	state = state_intf.get_entry(STATE_KEY)
	return state if isinstance(state, dict) else {}


def write_state(state_intf, previous, **fields):
	"""Writes the checkpoint record; loaded_through never moves back."""
	state = {k: v for k, v in previous.items() if not k.startswith('_')}
	state.update(fields)
	if previous.get(STATE_LOADED_THROUGH) is not None and state.get(STATE_LOADED_THROUGH) is not None:
		state[STATE_LOADED_THROUGH] = max(float(previous[STATE_LOADED_THROUGH]), float(state[STATE_LOADED_THROUGH]))
	state[STATE_UPDATED] = int(time.time())
	state[state_intf.KV_KEY] = STATE_KEY
	if not state_intf.save_batch([state]):
		raise RuntimeError("the checkpoint could not be written")
	previous.clear()
	previous.update(state)
	return state


def load_since(server_connection, store, state_intf, dml_intf, source, start_from=None, now=None, budget=None):
	"""
	Loads every template record indexed since the checkpoint (or since start_from, an index time)
	into the KV store, slice by slice in index-time order, and moves the checkpoint after each
	slice, so a run that stops is resumed by the next one. Returns the number of records read.
	"""
	now = int(now if now is not None else time.time())
	budget = RUN_BUDGET_SECONDS if budget is None else budget
	began = time.time()
	state = read_state(state_intf)

	if start_from is not None:
		start = max(0, int(float(start_from)))
	elif state.get(STATE_LOADED_THROUGH) is not None:
		start = max(0, int(float(state[STATE_LOADED_THROUGH])) - OVERLAP_SECONDS)
	else:
		# First run (a new install, or an upgrade from a version without the checkpoint): every
		# template record in the index, so a template an earlier version skipped is stored too.
		start = 0

	end = now - LAG_SECONDS
	if end <= start:
		return 0

	slices = plan_slices(index_time_plan(server_connection, source, start, end), start, end, SLICE_RECORDS)
	read = 0

	for index, (a, b, planned) in enumerate(slices):
		if index and time.time() - began > budget:
			write_state(state_intf, state, status=STATUS_LOADING, detail="stopped after {} s with records indexed from {} left".format(int(time.time() - began), a))
			logger.info("Stopped after {} s; the next run continues from index time {}.".format(int(time.time() - began), a))
			return read

		last = None
		count = 0
		slice_began = time.time()
		if planned:
			search = 'search {} _index_earliest={} _index_latest={} | fields templateHash, template, _indextime | fields - _raw'.format(source, int(a), int(b))
			chunk = []
			for result in export_results(server_connection, search):
				chunk.append((result.get('templateHash'), result.get('template')))
				try:
					seen = int(float(result.get('_indextime')))
					last = seen if last is None else max(last, seen)
				except (TypeError, ValueError):
					pass
				if len(chunk) >= CHUNK_RECORDS:
					store.store(chunk)
					count += len(chunk)
					chunk = []
					if len(store.pending) >= COPY_EVERY:
						store.copy_pending(dml_intf)
			store.store(chunk)
			count += len(chunk)
		store.copy_pending(dml_intf)
		read += count
		if planned:
			logger.info("Index time {} to {}: {} records read and stored in {:.1f} s ({}).".format(int(a), int(b), count, time.time() - slice_began, store.summary()))

		# The last slice ends at the newest record seen, not at this host's clock, so a record
		# an indexer stamps with a clock behind this one's is still read by the next run.
		through = b if index < len(slices) - 1 else (min(b, last + 1) if last is not None else None)
		fields = {STATE_STATUS: STATUS_CURRENT if index == len(slices) - 1 else STATUS_LOADING, STATE_DETAIL: '', STATE_RECORDS: read}
		if through is not None:
			fields[STATE_LOADED_THROUGH] = through
		elif state.get(STATE_LOADED_THROUGH) is None:
			fields[STATE_LOADED_THROUGH] = start
		write_state(state_intf, state, **fields)

	return read


def update_kv_store(settings):
	"""
	Stores template records in the KV store and writes the searchable copy of new templates.

	Two ways in:

	- Records in the results: a search that returns template records, piped to
	  `| sendalert tenx_dml_to_kv`, has exactly those records stored.
	- Anything else (the scheduled Consume KV search is `| makeresults`): every template record
	  indexed since the checkpoint is read by this action itself and stored, and the checkpoint
	  moves past them (load_since). The parameter `from` (an index time; 0 for all) loads from
	  there instead: `| makeresults | sendalert tenx_dml_to_kv param.from=0`.

	Returns the number of records read, or -1 in case of unexpected errors.
	"""
	state_intf = None
	state = {}
	try:
		server_uri = settings.get('server_uri')
		token = settings.get('session_key')
		configuration = settings.get('configuration') or {}

		tenx_config = tenx_util.get_tenx_config(server_uri=server_uri, token=token)

		logger.info("Loaded config - {}".format(json.dumps(tenx_config)))

		# On the defaults the templates would be written to the wrong index and collection.
		#
		if not tenx_config.get(tenx_util.CONFIG_LOADED, True):
			logger.error("The app's configuration could not be read; no templates were stored.")
			return -1

		variable_separator = tenx_config['variable_separator']
		timestamp_placeholder = tenx_config['timestamp_placeholder']

		server_connection = tenx_util.ServerConnection(
			server_uri=server_uri,
			user=settings.get('owner') or 'nobody',
			auth={'session_key': token})

		kv_intf = tenx_kv_intf.TenxKVInterface(
			collection_name=tenx_config['collection_name'],
			server_connection=server_connection,
			app_name=APP_NAME,
			owner='nobody')

		dml_intf = tenx_dml_intf.TenxDmlInterface(
			server_connection=server_connection,
			kv_intf=kv_intf,
			app_name=APP_NAME,
			lookup_name=LOOKUP_NAME,
			index_name=tenx_config['dest_dml_index'],
			source=tenx_config['dml_source_type'])

		dml_builder = tenx_dml_builder.TenxDMLBuilder(
			timestamp_placeholder=timestamp_placeholder,
			variable_separator=variable_separator)

		reader = get_results_reader(settings)

		if reader is None:
			# Logging already happens inside get_results_reader
			return -1

		store = TemplateStore(kv_intf, dml_builder)

		if 'templateHash' in (reader.fieldnames or []):
			records = []
			for result in reader:
				records.append((result.get('templateHash'), result.get('template')))
				if len(records) >= CHUNK_RECORDS:
					store.store(records)
					records = []
					if len(store.pending) >= COPY_EVERY:
						store.copy_pending(dml_intf)
			store.store(records)
			store.copy_pending(dml_intf)
			read = sum(store.counts.values()) + store.invalid
		else:
			source = (configuration.get('source') or DEFAULT_SOURCE).strip()
			if source.startswith('|'):
				logger.error("The source parameter must be an event search, not {!r}; no templates were stored.".format(source))
				return -1

			state_intf = tenx_kv_intf.TenxKVInterface(
				collection_name=STATE_COLLECTION,
				server_connection=server_connection,
				app_name=APP_NAME,
				owner='nobody')

			start_from = str(configuration.get('from') or '').strip() or None
			read = load_since(server_connection, store, state_intf, dml_intf, source, start_from=start_from)

		logger.info("Processing summary: read={}, written={}, {}".format(read, store.written, store.summary()))

		return read
	except Exception as e:
		logger.error("Unexpected error in tenx dml to kv handler - {}.".format(e), exc_info=1)
		if state_intf is not None:
			try:
				write_state(state_intf, read_state(state_intf), status=STATUS_FAILED, detail=str(e)[:500])
			except Exception:
				logger.warning("The checkpoint record could not be marked failed.", exc_info=1)
		return -1


if __name__ == "__main__":
	if len(sys.argv) > 1 and sys.argv[1] == "--execute":
		startTime = tenx_util.current_time_ms()
		payload = json.loads(sys.stdin.read())
		num_read = update_kv_store(payload)

		if num_read < 0:
			logger.warning("Failed updating KV store")
			sys.exit(2)

		logger.info("Read {} template records".format(num_read))
		logger.info("Total runtime - {}ms".format(tenx_util.current_time_ms() - startTime))
	else:
		logger.error("Unsupported execution mode (expected --execute flag)")
		sys.exit(1)
