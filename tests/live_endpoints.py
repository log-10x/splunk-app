#!/usr/bin/env python3
"""
End to end check of the app's two REST endpoints against a running Splunk.

The unit suite covers the compiler, the builder and the KV interface as pure functions.
Nothing covered the REST handlers, which are where this app does its Splunk I/O and where
the bundled Splunk SDK is actually exercised. An SDK upgrade can leave every unit test
green and still break every endpoint, so this exists to be run before and after one.

It needs a Splunk with this app installed and its KV store filled. The benchmark harness
in log-10x/benchmarks (splunk-license) stands one up; any instance with compact events in
an index will do.

    python3 tests/live_endpoints.py \
        --url https://localhost:8089 --user admin --password '...' \
        --index tenx_enc --term Processing

Exits non-zero on the first failed check, and prints one line per check either way.
"""

import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class CheckFailed(Exception):
	pass


class Splunk:
	def __init__(self, url, user, password, app, owner):
		self.url = url.rstrip('/')
		self.app = app
		self.owner = owner
		# Splunk's management port is HTTPS with a self-signed certificate by default.
		self.ctx = ssl._create_unverified_context()
		self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ctx))
		self.basic = 'Basic ' + base64.b64encode(
			('%s:%s' % (user, password)).encode()).decode()

	def ns(self, path):
		return '%s/servicesNS/%s/%s/%s' % (self.url, self.owner, self.app, path.lstrip('/'))

	def call(self, path, data=None, method=None, absolute=False):
		"""Returns (status, body). Never raises on an HTTP error status."""
		target = path if absolute else self.ns(path)
		body = urllib.parse.urlencode(data).encode() if data else None
		request = urllib.request.Request(target, data=body, method=method)
		# Basic auth is sent up front: Splunk answers an unauthenticated call with 401 and
		# no challenge realm, which the auth handler cannot then satisfy.
		request.add_header('Authorization', self.basic)

		try:
			with self.opener.open(request, timeout=120) as response:
				return response.status, response.read().decode('utf-8', 'replace')
		except urllib.error.HTTPError as error:
			return error.code, error.read().decode('utf-8', 'replace')


def json_or_fail(body, what):
	try:
		return json.loads(body)
	except ValueError:
		raise CheckFailed('%s did not return JSON: %s' % (what, body[:300]))


def wait_for_job(splunk, sid, timeout=300):
	deadline = time.time() + timeout
	job = '%s/services/search/jobs/%s' % (splunk.url, urllib.parse.quote(sid))

	while time.time() < deadline:
		status, body = splunk.call(job + '?output_mode=json', absolute=True)

		if status == 200:
			try:
				entry = json.loads(body)['entry'][0]['content']
			except (ValueError, KeyError, IndexError):
				entry = {}

			if entry.get('isDone') in (True, '1', 1):
				return entry

		time.sleep(2)

	raise CheckFailed('search job %s did not finish within %ss' % (sid, timeout))


def results_of(splunk, sid):
	url = ('%s/services/search/jobs/%s/results?output_mode=json&count=0'
	       % (splunk.url, urllib.parse.quote(sid)))
	status, body = splunk.call(url, absolute=True)

	if status != 200:
		raise CheckFailed('fetching results for %s returned %s' % (sid, status))

	return json_or_fail(body, 'results').get('results', [])


def check_static_assets(splunk, app_dir, web_url):
	"""
	Every /static/app/... path the app's own files reference has to resolve.

	This is not pedantry. The app's 10x Search tab is an HTML view, not a dashboard, so the
	hook that routes searches through the expansion endpoint is not picked up from
	dashboard.js; it is loaded by one script tag in a Mako template. That tag named the wrong
	app and returned 404, so the tab quietly ran ordinary searches and showed compact events.
	Nothing failed, nothing logged, and no unit test could see it.
	"""
	pattern = re.compile(r"/static/app/[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+")
	referenced = {}

	for root, _dirs, names in os.walk(app_dir):
		if '__pycache__' in root:
			continue

		for name in names:
			if not name.endswith(('.js', '.html', '.xml', '.conf')):
				continue

			path = os.path.join(root, name)

			try:
				body = open(path, encoding='utf-8', errors='replace').read()
			except OSError:
				continue

			for match in pattern.findall(body):
				referenced.setdefault(match, os.path.relpath(path, app_dir))

	if not referenced:
		raise CheckFailed('no /static/app references found under %s, so this check proved '
		                  'nothing; is the app directory right?' % app_dir)

	broken = []

	for asset, where in sorted(referenced.items()):
		url = '%s/en-US%s' % (web_url.rstrip('/'), asset)
		request = urllib.request.Request(url)
		request.add_header('Authorization', splunk.basic)

		try:
			with splunk.opener.open(request, timeout=60) as response:
				if response.status != 200:
					broken.append((asset, where, response.status))
		except urllib.error.HTTPError as error:
			broken.append((asset, where, error.code))
		except Exception as error:  # noqa: BLE001
			broken.append((asset, where, type(error).__name__))

	if broken:
		lines = '; '.join('%s referenced by %s returned %s' % item for item in broken)
		raise CheckFailed('%d of %d static assets do not resolve: %s'
		                  % (len(broken), len(referenced), lines))

	return '%d static assets referenced by the app all resolve' % len(referenced)


def check_search_expands(splunk, index, term, sourcetype):
	"""
	The endpoint's whole job is to make a search written against the original text work on
	compact events. So the same search is run twice: once through the endpoint and once as
	an ordinary search. The ordinary one must find nothing, because the literal text is not
	in the compact event, and the endpoint's must find events whose expanded text carries
	the term. Either half passing alone would not show the endpoint did anything.
	"""
	# The sourcetype is named in the search. The endpoint rewrites on the sourcetype it can
	# see in the search string, so a search that gives only an index is passed through.
	query = 'search index=%s sourcetype=%s %s' % (index, sourcetype, term)
	return _search_expands(splunk, query, term)


def _search_expands(splunk, query, term):

	status, body = splunk.call('%s/services/search/jobs' % splunk.url,
	                           data={'search': query, 'earliest_time': '0',
	                                 'latest_time': 'now', 'output_mode': 'json'},
	                           method='POST', absolute=True)

	if status not in (200, 201):
		raise CheckFailed('control search could not be created: %s %s' % (status, body[:300]))

	control_sid = json_or_fail(body, 'control search')['sid']
	wait_for_job(splunk, control_sid)
	control = results_of(splunk, control_sid)

	if control:
		raise CheckFailed('the control search found %d events, so the term %r is present in the '
		                  'compact text and proves nothing about expansion'
		                  % (len(control), term))

	status, body = splunk.call('tenx-search',
	                           data={'search': query, 'earliest_time': '0', 'latest_time': 'now'},
	                           method='POST')

	if status != 200:
		raise CheckFailed('POST tenx-search returned %s: %s' % (status, body[:300]))

	payload = json_or_fail(body, 'POST tenx-search')
	sid = payload.get('sid')

	if not sid:
		raise CheckFailed('POST tenx-search returned no sid: %s' % body[:300])

	wait_for_job(splunk, sid)
	rows = results_of(splunk, sid)

	if not rows:
		raise CheckFailed('the endpoint search returned no events, so nothing was expanded')

	missing = [row for row in rows if term not in row.get('_raw', '')]

	if missing:
		raise CheckFailed('%d of %d events came back without %r in the expanded text'
		                  % (len(missing), len(rows), term))

	return ('tenx-search expanded %d events carrying %r, which the same search without the '
	        'endpoint could not find' % (len(rows), term))


def check_alert_compiles(splunk, index, term, name, sourcetype):
	"""
	Compile a search into a saved search and take it away again. This is the path a browser
	never touches and the scheduler depends on.
	"""
	# Named in the search, as the search check does. Without it the compiler has nothing to
	# recognise and answers PASSTHROUGH, which tells us only that the endpoint replied.
	return _alert_compiles(splunk, index, term, name, sourcetype)


def _alert_compiles(splunk, index, term, name, sourcetype):
	status, body = splunk.call('tenx-alert',
	                           data={'search': 'search index=%s sourcetype=%s %s'
	                                           % (index, sourcetype, term),
	                                 'name': name,
	                                 'cron_schedule': '*/30 * * * *',
	                                 'is_scheduled': '1'},
	                           method='POST')

	if status not in (200, 422, 503):
		raise CheckFailed('POST tenx-alert returned %s: %s' % (status, body[:300]))

	payload = json_or_fail(body, 'POST tenx-alert')

	for key in ('strategy', 'storable', 'needs_review', 'original_search', 'applied'):
		if key not in payload:
			raise CheckFailed('tenx-alert response is missing %r: %s' % (key, body[:300]))

	if status != 200:
		return 'tenx-alert answered %s with strategy %s, which is a defined outcome' % (
			status, payload.get('strategy'))

	if payload.get('applied'):
		saved = 'saved/searches/' + urllib.parse.quote(name)
		check_status, check_body = splunk.call(saved + '?output_mode=json')

		if check_status != 200:
			raise CheckFailed('tenx-alert reported applied but %s is not readable (%s)'
			                  % (name, check_status))

		splunk.call(saved, method='DELETE')

	return 'tenx-alert compiled with strategy %s, applied=%s' % (
		payload.get('strategy'), payload.get('applied'))


def main():
	parser = argparse.ArgumentParser(description=__doc__,
	                                 formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('--url', default='https://localhost:8089')
	parser.add_argument('--user', default='admin')
	parser.add_argument('--password', required=True)
	parser.add_argument('--app', default='tenx-for-splunk')
	parser.add_argument('--owner', default='admin')
	parser.add_argument('--index', default='tenx_enc')
	parser.add_argument('--term', required=True,
	                    help='a literal that appears in the original text and not in the '
	                         'compact event, so expansion is what makes it findable')
	parser.add_argument('--sourcetype', default='tenx_encoded',
	                    help='the sourcetype carrying compact events; it needs the app\'s '
	                         'REPORT-tenx extraction in props.conf, as tenx_encoded has')
	parser.add_argument('--alert-name', default='tenx-live-endpoint-check')
	parser.add_argument('--app-dir',
	                    help='the app directory, to check that every /static/app path its own '
	                         'files reference actually resolves')
	parser.add_argument('--web-url', default='http://localhost:8000',
	                    help='splunkweb, which serves static assets')
	args = parser.parse_args()

	splunk = Splunk(args.url, args.user, args.password, args.app, args.owner)

	checks = [
		('search expands', lambda: check_search_expands(splunk, args.index, args.term,
		                                                args.sourcetype)),
		('alert compiles', lambda: check_alert_compiles(splunk, args.index, args.term,
		                                                args.alert_name, args.sourcetype)),
	]

	if args.app_dir:
		checks.append(('static assets',
		               lambda: check_static_assets(splunk, args.app_dir, args.web_url)))

	failed = 0

	for label, run in checks:
		try:
			print('  PASS  %-20s %s' % (label, run()))
		except CheckFailed as error:
			print('  FAIL  %-20s %s' % (label, error))
			failed += 1
		except Exception as error:  # noqa: BLE001 - a broken endpoint is a failed check
			print('  FAIL  %-20s unexpected %s: %s' % (label, type(error).__name__, error))
			failed += 1

	print('%d of %d endpoint checks passed' % (len(checks) - failed, len(checks)))

	return 1 if failed else 0


if __name__ == '__main__':
	sys.exit(main())
