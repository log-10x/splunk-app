"""
Tenx Alert REST Handler
=======================

Persistent REST handler that compiles a human-authored search into native Splunk SPL **once,
at save time**, and (when storable and confirmed) writes it into a saved search so a scheduled
alert on 10x compact data runs as an ordinary saved search - no browser hook, no per-run proxy.

This is the save/update wiring on top of the pure compiler (tenx_alert_compiler): the compiler
classifies the search, tenx_alert_persist decides what to do with that classification, and this
handler performs the Splunk I/O (read the request, write saved/searches).

Endpoint
--------
POST /servicesNS/{owner}/{app}/tenx-alert

Request Body (form-encoded):
    search : the human-authored search to compile (required)
    name   : the saved-search stanza to create/update (required to apply; optional for a
             dry-run compile that only returns the candidate)
    confirm: "true" to apply a needs_review candidate anyway (default: do not apply it)
    <any other key> : forwarded verbatim as a saved-search attribute (cron_schedule,
             alert_type, alert.track, actions, dispatch.earliest_time, is_scheduled, ...)

Response (JSON):
    {
      "strategy": "NATIVE" | "PASSTHROUGH" | "RETRYABLE" | "REJECTED",
      "storable": bool,
      "needs_review": bool,
      "reason": str | null,
      "compiled_search": str | null,
      "original_search": str,
      "applied": bool          # whether a saved search was actually written
    }

Status codes:
    200 applied (clean or confirmed) OR returned-for-review (applied=false)
    422 REJECTED - cannot be compiled into a schedulable alert
    503 RETRYABLE - transient DML failure; keep the existing alert and retry
    400 bad request (missing search, or apply requested without a name)
    405 non-POST
    500 unexpected error

Workflow
--------
1. Client POSTs the human search + alert attributes.
2. Handler compiles it via TenxAlertCompiler (which uses TenxSearchBuilder + the live
   search manager for SPL parse + DML hash lookup).
3. tenx_alert_persist.decide() dispatches on the result.
4. On APPLY, the handler writes the compiled SPL + the human original into saved/searches
   (create if the stanza is new, update if it exists).
5. The classification is always returned so a UI can surface strategy/needs_review/reason.

Logging
-------
Logs to: $SPLUNK_HOME/var/log/splunk/tenx_alert_handler.log

See Also
--------
- restmap.conf / web.conf: REST endpoint registration.
- tenx_alert_compiler.py:  the compile step.
- tenx_alert_persist.py:   the (offline-tested) decision + payload logic.
- tenx_search_handler.py:  the sibling interactive handler this mirrors.
- SAVE_TIME_ALERTS.md:     the wiring plan.
"""

from future import standard_library
standard_library.install_aliases()

import os
import sys
import logging
import json
import urllib.parse
import urllib.error

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
import tenx_alert_persist

tenx_util.setup_logger('tenx_alert_handler', logging.INFO)
logger = logging.getLogger(__name__)


class TenxAlertHandler(PersistentServerConnectionApplication):
	"""
	REST handler that compiles a search at save time and writes it to a saved search.

	Supports POST only. See module docstring for the request/response contract.
	"""
	def __init__(self, command_line, command_arg):
		PersistentServerConnectionApplication.__init__(self)

	def extract_form(self, params_list):
		"""
		Flattens the persistconn 'form' (a list of [key, value] pairs) into a dict.
		"""
		form = {}

		for param_arr in params_list:
			if not isinstance(param_arr, list) or len(param_arr) != 2:
				continue

			form[param_arr[0]] = param_arr[1]

		return form

	def saved_searches_base_url(self, user):
		"""
		Base URL for the saved/searches collection in this app's namespace for the given owner.
		"""
		return '/servicesNS/' + user + '/' + APP_NAME + '/saved/searches'

	def conf_savedsearches_url(self, user, name):
		"""
		URL for the raw conf-editing endpoint for a single savedsearches stanza. Unlike the
		saved/searches EAI endpoint, this accepts arbitrary stanza keys, which is how the
		human-original search is stored (the EAI endpoint rejects unknown arguments).
		"""
		return ('/servicesNS/' + user + '/' + APP_NAME +
			'/configs/conf-savedsearches/' + urllib.parse.quote(name, safe=''))

	def _read_error_body(self, http_error):
		"""
		Best-effort extraction of Splunk's error message from an HTTPError, so the caller sees
		the real reason (e.g. 'Invalid alert_comparator') instead of a bare status code.
		"""
		try:
			return http_error.read().decode('utf-8', 'replace')
		except Exception:
			return str(http_error)

	def write_original_search(self, server_connection, user, name, original_search):
		"""
		Stashes the human-authored original on the saved-search stanza via configs/conf-
		savedsearches, so the alert can be recompiled when new templates arrive. The stanza
		already exists at this point (write_saved_search ran first).
		"""
		server_connection.post(
			self.conf_savedsearches_url(user, name),
			tenx_alert_persist.build_original_search_data(original_search))

	def write_saved_search(self, server_connection, user, name, data):
		"""
		Creates the saved search if the stanza is new, or updates it if it already exists.

		`data` must NOT contain 'name' (name identifies the stanza: it goes in the URL for an
		update and is added to the body for a create). Returns 'created' or 'updated'.
		"""
		base_url = self.saved_searches_base_url(user)
		update_url = base_url + '/' + urllib.parse.quote(name, safe='')

		try:
			# Try update first - POST to the specific stanza. Name lives in the URL here.
			server_connection.post(update_url, data)
			return 'updated'
		except urllib.error.HTTPError as e:
			if e.code != 404:
				raise

			# Stanza does not exist yet - create it. Name goes in the body for a create.
			create_data = dict(data)
			create_data['name'] = name
			server_connection.post(base_url, create_data)
			return 'created'

	def list_managed_savedsearches(self, server_connection, user):
		"""
		Returns a stanza dict {name, search, tenx_original_search} for every savedsearches stanza
		in this app namespace, read via configs/conf-savedsearches (which exposes the custom
		tenx_original_search key that saved/searches hides). The caller filters to the ones the
		compiler actually manages.
		"""
		url = '/servicesNS/' + user + '/' + APP_NAME + '/configs/conf-savedsearches'
		res = server_connection.get(url, {'count': 0})

		stanzas = []

		for entry in res.get('entry', []) or []:
			content = entry.get('content', {}) or {}
			stanzas.append({
				'name': entry.get('name'),
				'search': content.get('search', ''),
				tenx_alert_persist.ORIGINAL_SEARCH_KEY: content.get(tenx_alert_persist.ORIGINAL_SEARCH_KEY, ''),
			})

		return stanzas

	def recompile_all(self, server_connection, user, compiler):
		"""
		Recompiles every managed saved search from its human original, applying only clean,
		storable results whose compiled form actually changed. This migrates legacy
		`| tenxsearch` alerts to native compiled searches, and refreshes existing compiles to
		pick up template hashes that appeared after the alert was first saved.

		A recompile is conservative: it never auto-applies a needs_review result (a human must
		confirm those via /tenx-alert), never touches a RETRYABLE/REJECTED result, and skips
		unchanged compiles so it does not churn live alerts.
		"""
		summary = {'examined': 0, 'recompiled': 0, 'migrated': 0, 'unchanged': 0,
			'needs_review': 0, 'skipped': 0, 'errors': 0, 'updated': []}

		for stanza in self.list_managed_savedsearches(server_connection, user):
			source = tenx_alert_persist.recompile_source(stanza)

			if source is None:
				continue

			summary['examined'] += 1
			name = stanza['name']
			is_legacy = tenx_alert_persist.is_legacy_tenxsearch(stanza)

			try:
				result = compiler.compile(source)
				decision = tenx_alert_persist.decide(result, confirm=False)

				if decision.action != tenx_alert_persist.APPLY:
					summary['needs_review' if decision.action == tenx_alert_persist.REVIEW else 'skipped'] += 1
					continue

				# Only rewrite when the compiled search actually changed, so a recompile pass over
				# already-current alerts is a no-op rather than needless churn.
				if result.compiled_search == stanza['search']:
					summary['unchanged'] += 1
					continue

				self.write_saved_search(server_connection, user, name, {'search': result.compiled_search})
				self.write_original_search(server_connection, user, name, result.original_search)

				summary['migrated' if is_legacy else 'recompiled'] += 1
				summary['updated'].append(name)
			except Exception as e:
				logger.warning("Recompile failed for {} - {}".format(name, e))
				summary['errors'] += 1

		return summary

	def handle(self, in_string):
		"""
		Main handler: parse -> compile -> decide -> (maybe) write -> respond.
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
			user = in_string_json["session"]["user"]

			form = self.extract_form(in_string_json.get('form', []))
			action = (form.get('action') or '').lower()

			tenx_config = tenx_util.get_tenx_config(server_uri=server_uri, token=token)

			server_connection = tenx_util.ServerConnection(
				server_uri=server_uri,
				user=user,
				auth={'session_key': token})

			search_manager = tenx_search_manager.TenxSearchManager(
				server_connection=server_connection,
				tenx_config=tenx_config)

			search_builder = tenx_search_builder.TenxSearchBuilder(
				server_connection=server_connection,
				tenx_config=tenx_config,
				search_manager=search_manager)

			compiler = tenx_alert_compiler.TenxAlertCompiler(search_builder)

			# Bulk recompile/migrate: recompile every managed alert from its stored original.
			if action == 'recompile':
				summary = self.recompile_all(server_connection, user, compiler)
				logger.info("Recompile pass - {}".format(summary))
				return {'payload': summary, 'status': 200}

			original_search = form.get('search')

			if not original_search:
				return {'payload': "Missing required 'search' parameter", 'status': 400}

			name = form.get('name')
			confirm = str(form.get('confirm', '')).lower() == 'true'

			result = compiler.compile(original_search)

			logger.info("Compiled alert - name={} strategy={} needs_review={} reason={}".format(
				name, result.strategy.name, result.needs_review, result.reason))

			decision = tenx_alert_persist.decide(result, confirm=confirm)

			# Only an APPLY decision writes anything. Applying requires a target stanza name.
			if decision.action == tenx_alert_persist.APPLY:
				if not name:
					return {'payload': "Applying a compiled alert requires a 'name'", 'status': 400}

				data = tenx_alert_persist.build_saved_search_data(form, result)

				try:
					write_result = self.write_saved_search(server_connection, user, name, data)

					# The saved/searches EAI endpoint rejects unknown args, so the human original
					# is stashed as a raw stanza key via configs/conf-savedsearches (the stanza
					# exists now that write_saved_search has run).
					self.write_original_search(server_connection, user, name, result.original_search)
				except urllib.error.HTTPError as write_error:
					# Splunk rejected the write (e.g. an incomplete alert spec). Surface its real
					# status and message rather than collapsing it into an opaque 500 - the compile
					# itself was fine, the saved-search attributes the caller sent were not.
					detail = self._read_error_body(write_error)
					logger.warning("Saved-search write failed - name={} status={} detail={}".format(
						name, write_error.code, detail))

					decision.payload['applied'] = False
					decision.payload['saved_search_error'] = detail
					return {'payload': decision.payload, 'status': write_error.code}

				logger.info("Saved search {} - name={}".format(write_result, name))

				decision.payload['saved_search'] = write_result

			return {'payload': decision.payload, 'status': decision.status}
		except Exception as e:
			logger.error("Unexpected error in tenx alert handler - {}.".format(e), exc_info=1)
			return {'payload': str(e), 'status': 500}
		finally:
			logger.info("Total runtime - {}ms".format(tenx_util.current_time_ms() - start_time))
