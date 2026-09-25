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
- SAVE_TIME_ALERTS.md in the app repository: how compiled alerts work.
"""


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
import tenx_alert_recompile

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

	def _read_error_body(self, http_error):
		"""
		Best-effort extraction of Splunk's error message from an HTTPError, so the caller sees
		the real reason (e.g. 'Invalid alert_comparator') instead of a bare status code.
		"""
		try:
			return http_error.read().decode('utf-8', 'replace')
		except Exception:
			return str(http_error)

	def write_tenx_metadata(self, server_connection, user, name, original_search, compiled_search):
		tenx_alert_recompile.write_tenx_metadata(server_connection, user, name, original_search, compiled_search)

	def write_saved_search(self, server_connection, user, name, data):
		return tenx_alert_recompile.write_saved_search(server_connection, user, name, data)

	def recompile_all(self, server_connection, user, compiler):
		"""Recompiles the managed alerts visible to `user`; see tenx_alert_recompile."""
		return tenx_alert_recompile.recompile_all(server_connection, user, compiler)

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

			if not tenx_config.get(tenx_util.CONFIG_LOADED, True):
				return {'payload': "10x: the app's configuration could not be read, so this alert was not "
					"compiled (built on the defaults it would look for templates in the wrong index). "
					"See tenx_alert_handler.log.", 'status': 500}

			server_connection = tenx_util.ServerConnection(
				server_uri=server_uri,
				user=user,
				auth={'session_key': token})

			search_manager = tenx_search_manager.TenxSearchManager(
				server_connection=server_connection,
				tenx_config=tenx_config,
				app=in_string_json.get('ns', {}).get('app'))

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

				# Write the saved search first (a create must exist before its stanza can take the
				# conf-only metadata keys). If THIS fails, nothing was applied.
				try:
					write_result = self.write_saved_search(server_connection, user, name, data)
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

				# The compiled alert is now live. Stash the human original + compiled fingerprint
				# (conf-savedsearches, since the EAI endpoint rejects unknown args). If ONLY this
				# fails, the alert is still applied - report it honestly rather than as applied=false,
				# and warn that the recompile pass will not manage it until it is re-saved.
				try:
					self.write_tenx_metadata(
						server_connection, user, name, result.original_search, result.compiled_search)
				except urllib.error.HTTPError as meta_error:
					detail = self._read_error_body(meta_error)
					logger.warning("Metadata stash failed - name={} status={} detail={}".format(
						name, meta_error.code, detail))
					decision.payload['metadata_error'] = detail

			return {'payload': decision.payload, 'status': decision.status}
		except Exception as e:
			logger.error("Unexpected error in tenx alert handler - {}.".format(e), exc_info=1)
			return {'payload': str(e), 'status': 500}
		finally:
			logger.info("Total runtime - {}ms".format(tenx_util.current_time_ms() - start_time))
