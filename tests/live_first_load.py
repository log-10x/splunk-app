#!/usr/bin/env python3
"""
Live check of `tx` on a search head with search peers in the minutes after the app is installed, and through
template loads, against a running Splunk.

Start it right after installing (or upgrading, then restarting) the app on a search head whose peers hold compact
events (--index). Until the knowledge bundle that carries the app's template lookup reaches the indexers, a `tx`
search there would fail with Splunk's lookup error; the prefilter keeps such a search on the search head and
says so. Right after Splunk starts, until its KV store is ready, the lookup fails on the search head
itself; the search still fails, and says why. Once the lookup is on the indexers, events whose template is stored
but not yet there come back compact, marked tenx_expand_refused=no-template, for about a minute after each Consume
KV run that stores templates. Every 5 seconds for --minutes it runs one `tx` search over --index and records the
counts by tenx_expand_refused and the search's messages. The rows:
- every search that failed said why (the KV store is still starting);
- every search that returned no row said why (the lookup has not reached the indexers);
- at the end every event expands, nothing refused.
It prints the timeline with repeated states folded.
    python3 tests/live_first_load.py --url https://sh:8089 --user admin --password-file pw --index web_compact
Exits non-zero when a check fails.
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import urllib.parse  # noqa: E402

from live_endpoints import CheckFailed, Splunk, json_or_fail  # noqa: E402

NOT_ON_INDEXERS = "has not reached the indexers yet"
KV_NOT_READY = "the KV store is still starting"


def job(splunk, spl):
	"""(rows, messages, failed) of a blocking job, the messages kept when it failed."""
	status, body = splunk.call('search/jobs', {'search': spl, 'exec_mode': 'blocking', 'output_mode': 'json',
											   'earliest_time': '0', 'latest_time': 'now'})
	if status not in (200, 201):
		raise CheckFailed('search returned HTTP %s: %s' % (status, body[:200]))
	sid = json_or_fail(body, 'search')['sid']
	url = '%s/services/search/jobs/%s' % (splunk.url, urllib.parse.quote(sid))
	content = json_or_fail(splunk.call(url + '?output_mode=json', absolute=True)[1], 'job')['entry'][0]['content']
	messages = ['%s %s' % (m.get('type'), m.get('text', '')) for m in content.get('messages', []) or []]
	status, body = splunk.call(url + '/results?output_mode=json&count=0', absolute=True)
	rows = json_or_fail(body, 'results').get('results', []) if status == 200 else []
	return rows, messages, content.get('isFailed') in (True, '1', 1)


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--url', default='https://localhost:8089')
	parser.add_argument('--user', default='admin')
	parser.add_argument('--password-file', required=True, help='read the password from this file')
	parser.add_argument('--owner', default='nobody')
	parser.add_argument('--index', required=True)
	parser.add_argument('--minutes', type=float, default=8)
	args = parser.parse_args()
	splunk = Splunk(args.url, args.user, open(args.password_file).read().strip(), 'tenx-for-splunk', args.owner)
	spl = ('search index=%s `tx` | fillnull value=expanded tenx_expand_refused | stats count by tenx_expand_refused'
		   % args.index)
	polls, last, end = [], None, time.time() + args.minutes * 60
	while time.time() < end:
		t0 = time.time()
		try:
			rows, msgs, is_failed = job(splunk, spl)
			state = 'failed' if is_failed else (','.join('%s=%s' % (r.get('tenx_expand_refused'), r['count']) for r in rows) or 'no rows')
			failed = [m for m in msgs if m.startswith(('ERROR', 'FATAL'))] or (['failed'] if is_failed else [])
		except CheckFailed as e:
			state, msgs, failed = 'failed', [], [str(e)]
		said = ('not on the indexers' if any(NOT_ON_INDEXERS in m for m in msgs) else
				'KV store starting' if any(KV_NOT_READY in m for m in msgs) else '')
		polls.append((time.strftime('%H:%M:%S', time.gmtime()), state, failed, said))
		shown = (state, bool(failed), said)
		if shown != last:
			print('%s %s%s%s' % (polls[-1][0], state, (' | ' + said) if said else '', (' | ' + failed[0][:160]) if failed else ''),
				  flush=True)
			last = shown
		time.sleep(max(0, 5 - (time.time() - t0)))
	bad = []

	def check(name, ok, detail):
		print('%s %s: %s' % ('PASS' if ok else 'FAIL', name, detail), flush=True)
		if not ok:
			bad.append(name)

	errors = [p for p in polls if p[2]]
	unsaid = [p for p in errors if not p[3]]
	check('every search that failed says why', not unsaid, '%d of %d searches failed, %d without a warning%s' % (
		len(errors), len(polls), len(unsaid), (', first at %s: %s' % (unsaid[0][0], unsaid[0][2][0][:160])) if unsaid else ''))
	silent = [p for p in polls if p[1] == 'no rows' and not p[3]]
	check('every search with no row says why', not silent, '%d of %d with no row and no warning' % (
		len(silent), len([p for p in polls if p[1] == 'no rows'])))
	final = polls[-1][1] if polls else ''
	check('every event expands at the end', final.startswith('expanded=') and ',' not in final, final)
	print('%d failed' % len(bad))
	sys.exit(1 if bad else 0)


if __name__ == '__main__':
	main()
