"""
Tenx Alert Persist Module
=========================

Pure decision logic for the /tenx-alert save-time compile handler: given an
AlertCompileResult (from tenx_alert_compiler) and the caller's intent, decide what the
handler should do - apply the compiled search to a saved search, return a candidate for a
human to confirm, ask the caller to retry, or reject.

This module holds NO Splunk connection and imports nothing from splunk.* - all Splunk I/O
(reading the request, writing saved/searches) lives in tenx_alert_handler. Keeping the
decision logic here means it is unit-testable offline, exactly like the compiler itself.

Actions
-------
- APPLY:  the compiled search is storable and either clean or the caller confirmed a
          needs_review candidate. The handler should write it to saved/searches.
- REVIEW: storable but needs_review and the caller did not confirm. The handler returns the
          candidate WITHOUT writing it, so a human can confirm first.
- RETRY:  a transient DML failure (RETRYABLE). The handler keeps the existing alert and the
          caller should retry the compile later - do NOT overwrite a live alert.
- REJECT: the search could not be compiled safely (REJECTED). Nothing is written; the reason
          is surfaced.

See Also
--------
- tenx_alert_compiler.py: produces the AlertCompileResult this module dispatches on.
- tenx_alert_handler.py:  the REST handler that performs the actual saved/searches write.
- SAVE_TIME_ALERTS.md:    the wiring plan this implements (item 1).
"""

import re

from tenx_alert_compiler import AlertStrategy


# A legacy alert that decodes at runtime via the generating command:
#   | tenxsearch searchstring="<human search>"
# The searchstring is the human search; recompiling it migrates the alert from the per-run
# proxy to a native compiled saved search.
_TENXSEARCH_RE = re.compile(
	r'\|\s*tenxsearch\s+searchstring\s*=\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)


# Handler-control form keys that must NOT be forwarded as saved-search attributes.
# `search` is replaced by the compiled SPL; `name` is the target stanza; `confirm` gates
# needs_review application; `method`/`output_mode` are transport, not alert config.
CONTROL_KEYS = frozenset(['search', 'name', 'confirm', 'method', 'output_mode'])

# The saved-search attribute under which we stash the human-authored original, so the alert
# can be recompiled later (when new templates arrive) and the UI can show what the user typed.
ORIGINAL_SEARCH_KEY = 'tenx_original_search'


# Action constants (plain strings so payloads/logs are readable and tests are obvious).
APPLY = 'apply'
REVIEW = 'review'
RETRY = 'retry'
REJECT = 'reject'


class PersistDecision:
	"""
	What the handler should do with a compile result.

	Attributes
	----------
	action : str
		One of APPLY / REVIEW / RETRY / REJECT.
	status : int
		The HTTP status the handler should return.
	applied : bool
		Whether the compiled search will be written to a saved search.
	payload : dict
		The JSON body the handler returns to the caller.
	"""
	def __init__(self, action, status, applied, payload):
		self.action = action
		self.status = status
		self.applied = applied
		self.payload = payload

	def __repr__(self):
		return "PersistDecision(action={!r}, status={}, applied={})".format(
			self.action, self.status, self.applied)


def _base_payload(result):
	"""The result fields every response echoes back, so callers/UI can render the outcome."""
	return {
		'strategy': result.strategy.name,
		'storable': result.storable,
		'needs_review': result.needs_review,
		'reason': result.reason,
		'compiled_search': result.compiled_search,
		'original_search': result.original_search,
	}


def decide(result, confirm=False):
	"""
	Decide what to do with a compile result.

	confirm=True means the caller has already seen a needs_review candidate and wants it
	applied anyway (the UI's "confirm and schedule" action). It has no effect on a clean
	compile (already applied) or on RETRYABLE/REJECTED (never applied).

	Returns a PersistDecision. Only action == APPLY should trigger a saved/searches write;
	for every other action the handler writes nothing.
	"""
	if result.strategy == AlertStrategy.REJECTED:
		payload = _base_payload(result)
		payload['applied'] = False
		# 422: the request was well-formed but the search cannot be compiled into a
		# schedulable alert. The caller surfaces reason (and may fall back to | tenxsearch).
		return PersistDecision(REJECT, 422, False, payload)

	if result.strategy == AlertStrategy.RETRYABLE:
		payload = _base_payload(result)
		payload['applied'] = False
		# 503: transient - keep the existing alert untouched and retry later.
		return PersistDecision(RETRY, 503, False, payload)

	# From here the result is storable (NATIVE or PASSTHROUGH).
	if result.needs_review and not confirm:
		payload = _base_payload(result)
		payload['applied'] = False
		# 200: a valid candidate is returned, but NOT written - a human confirms first.
		return PersistDecision(REVIEW, 200, False, payload)

	payload = _base_payload(result)
	payload['applied'] = True
	return PersistDecision(APPLY, 200, True, payload)


def build_saved_search_data(form, result):
	"""
	Build the form data for the saved/searches write from the caller's request form and the
	compile result.

	Every non-control key the caller sent (cron_schedule, alert_type, actions,
	dispatch.earliest_time, ...) is forwarded verbatim as a saved-search attribute, so the
	handler is agnostic to the exact alert schema. `search` is set to the COMPILED SPL.

	The human original is NOT included here: the saved/searches EAI endpoint rejects unknown
	arguments ("Argument ... is not supported by this handler"), so the original is written
	separately as a raw stanza key via configs/conf-savedsearches (see
	build_original_search_data and the handler's write_original_search). `name` is likewise
	excluded - it identifies the stanza (URL for update / added by the handler for create),
	not an attribute.
	"""
	data = {}

	for key, value in form.items():
		if key in CONTROL_KEYS:
			continue
		data[key] = value

	data['search'] = result.compiled_search

	return data


def build_original_search_data(original_search):
	"""
	The single-key payload that stashes the human-authored original under ORIGINAL_SEARCH_KEY.

	Written via configs/conf-savedsearches (a raw conf write that accepts arbitrary stanza
	keys), because the saved/searches EAI endpoint rejects unknown arguments. It reads back on
	both the conf endpoint and the saved-search content, so the recompile/migrate pass can
	recover what the user typed.
	"""
	return {ORIGINAL_SEARCH_KEY: original_search}


def recompile_source(saved_search):
	"""
	Given a saved-search stanza (a dict with at least 'search', and optionally the stored
	ORIGINAL_SEARCH_KEY), return the human-authored search the recompile pass should re-compile,
	or None if this saved search is not one the alert compiler manages.

	Two managed shapes, in priority order:
	- A stored `tenx_original_search`: a search /tenx-alert already compiled. Recompiling it
	  picks up template hashes that appeared since it was saved (a better hash prefilter), or a
	  fixed compile after a builder change.
	- A legacy `| tenxsearch searchstring="..."` alert: the searchstring is the human search;
	  recompiling migrates it from the per-run generating-command proxy to a native compiled
	  saved search.

	A stored original wins over a tenxsearch match (an already-migrated alert keeps its original
	as the source of truth even if its compiled body still mentions tenxsearch for some reason).
	"""
	original = (saved_search.get(ORIGINAL_SEARCH_KEY) or '').strip()

	if original:
		return original

	match = _TENXSEARCH_RE.search(saved_search.get('search') or '')

	if match:
		# unescape the SPL string literal: \" -> " and \\ -> \
		return match.group(1).replace('\\"', '"').replace('\\\\', '\\')

	return None


def is_legacy_tenxsearch(saved_search):
	"""
	Whether a saved search is a legacy `| tenxsearch ...` alert with no stored original yet -
	i.e. recompiling it is a migration (proxy -> native), not a refresh of an existing compile.
	"""
	return (not (saved_search.get(ORIGINAL_SEARCH_KEY) or '').strip()
		and _TENXSEARCH_RE.search(saved_search.get('search') or '') is not None)
