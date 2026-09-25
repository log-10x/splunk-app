"""
Tenx Alert Recompile
====================

Keeps compiled alerts current. A compiled alert selects compact events by the template hashes
that matched its words when it was compiled, so a template that appears later (a new log
statement after a deploy) is not selected until the alert is compiled again. This module
recompiles every alert the app manages from the search as the user wrote it, and rewrites an
alert only when its compiled search changed.

It is used by the /tenx-alert endpoint (the Compile Alert view's "Recompile all managed
alerts") for the calling user's alerts, and by the `tenxrecompile` command, which the
"Recompile Compiled Alerts" saved search runs on a schedule for every user's alerts.

Every write goes to the alert's own owner namespace, so a private alert stays private to the
user who created it.
"""

import logging
import urllib.parse
import urllib.error

import tenx_alert_persist

logger = logging.getLogger(__name__)

APP_NAME = 'tenx-for-splunk'

# Owner value that lists every user's objects the caller can see.
ALL_OWNERS = '-'


def saved_searches_base_url(owner):
	"""The saved/searches collection in this app's namespace for the given owner."""
	return '/servicesNS/' + owner + '/' + APP_NAME + '/saved/searches'


def conf_savedsearches_url(owner, name):
	"""
	The raw conf-editing endpoint for one savedsearches stanza. Unlike saved/searches, it
	accepts arbitrary keys, which is how the search as written is stored.
	"""
	return ('/servicesNS/' + owner + '/' + APP_NAME +
		'/configs/conf-savedsearches/' + urllib.parse.quote(name, safe=''))


def write_tenx_metadata(server_connection, owner, name, original_search, compiled_search):
	"""Stores the search as written and the compiled fingerprint on an existing stanza."""
	server_connection.post(
		conf_savedsearches_url(owner, name),
		tenx_alert_persist.build_tenx_metadata(original_search, compiled_search))


def write_saved_search(server_connection, owner, name, data):
	"""
	Updates the saved search, or creates it when the stanza does not exist yet. `data` must not
	contain 'name'. Returns 'created' or 'updated'.
	"""
	base_url = saved_searches_base_url(owner)

	try:
		server_connection.post(base_url + '/' + urllib.parse.quote(name, safe=''), data)
		return 'updated'
	except urllib.error.HTTPError as e:
		if e.code != 404:
			raise

		create_data = dict(data)
		create_data['name'] = name
		server_connection.post(base_url, create_data)
		return 'created'


def list_managed_savedsearches(server_connection, owner):
	"""
	Every savedsearches stanza of this app visible to `owner` (ALL_OWNERS for every user), with
	its owner and the custom keys that saved/searches hides. The caller filters to the ones the
	compiler manages.
	"""
	url = '/servicesNS/' + owner + '/' + APP_NAME + '/configs/conf-savedsearches'
	res = server_connection.get(url, {'count': 0})

	stanzas = []

	for entry in res.get('entry', []) or []:
		acl = entry.get('acl', {}) or {}

		if acl.get('app') and acl.get('app') != APP_NAME:
			continue

		content = entry.get('content', {}) or {}
		stanzas.append({
			'name': entry.get('name'),
			'owner': acl.get('owner') or owner,
			'search': content.get('search', ''),
			tenx_alert_persist.ORIGINAL_SEARCH_KEY: content.get(tenx_alert_persist.ORIGINAL_SEARCH_KEY, ''),
			tenx_alert_persist.COMPILED_SEARCH_KEY: content.get(tenx_alert_persist.COMPILED_SEARCH_KEY, ''),
		})

	return stanzas


def recompile_all(server_connection, owner, compiler, migrate_legacy=True):
	"""
	Recompiles every managed saved search visible to `owner` from its search as written,
	applying only clean results whose compiled form changed. Never auto-applies a result that
	needs review, never touches one that failed or was rejected, and never overwrites an alert
	a person has edited by hand (counted as `drifted`).

	migrate_legacy=False leaves `| tenxsearch` saved searches alone: the scheduled pass only
	refreshes alerts already compiled through the app, and converting a saved search is left
	to a person pressing "Recompile all managed alerts".
	"""
	summary = {'examined': 0, 'recompiled': 0, 'migrated': 0, 'unchanged': 0,
		'needs_review': 0, 'skipped': 0, 'drifted': 0, 'errors': 0, 'updated': []}

	for stanza in list_managed_savedsearches(server_connection, owner):
		source = tenx_alert_persist.recompile_source(stanza)

		if source is None:
			continue

		is_legacy = tenx_alert_persist.is_legacy_tenxsearch(stanza)

		if is_legacy and not migrate_legacy:
			continue

		summary['examined'] += 1
		name = stanza['name']
		stanza_owner = stanza['owner']

		if tenx_alert_persist.is_drifted(stanza):
			summary['drifted'] += 1
			continue

		try:
			result = compiler.compile(source)
			decision = tenx_alert_persist.decide(result, confirm=False)

			if decision.action != tenx_alert_persist.APPLY:
				summary['needs_review' if decision.action == tenx_alert_persist.REVIEW else 'skipped'] += 1
				continue

			# Hashes are sorted, so an unchanged template set gives the identical string.
			if result.compiled_search == stanza['search']:
				summary['unchanged'] += 1
				continue

			# The metadata first: for a legacy alert the search as written lives only in the
			# body about to be replaced, so a failed search write must not lose it.
			write_tenx_metadata(server_connection, stanza_owner, name, result.original_search, result.compiled_search)
			write_saved_search(server_connection, stanza_owner, name, {'search': result.compiled_search})

			summary['migrated' if is_legacy else 'recompiled'] += 1
			summary['updated'].append(name)
		except Exception as e:
			logger.warning("Recompile failed for {} ({}) - {}".format(name, stanza_owner, e))
			summary['errors'] += 1

	return summary
