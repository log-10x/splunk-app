#!/usr/bin/env python3
"""
Live check of one `tx` and `txf` search over a source's raw history and its compact events, against a
running Splunk with this app installed.

The instance needs one index (--index) that holds a source's raw events (indexed before the Receiver,
with their original sourcetypes, --raw-sourcetypes) followed by its compact events, the compact ones
carrying the original sourcetype in tenx_sourcetype with the field replay written, and an index
(--ref-index) holding every line of both periods raw. The rows:
- with tenx-raw-events as shipped (it names no event), `tx` returns the compact events alone and the
  search carries the warning that the index also holds raw events of those sourcetypes;
- with tenx-raw-events naming the raw sourcetypes, `tx` and `txf` return every event once: the count,
  a checksum of (text, time) over every event, the count per day, and the words given (--words) equal
  the reference; the events come in time order across the boundary; no warning; nothing refused;
- the macro is put back as it was.
    python3 tests/live_raw_history.py --url https://localhost:8089 --user admin --password-file pw \\
        --index mixed --ref-index allraw --raw-sourcetypes access_combined,fortigate_traffic --earliest -90d
Exits non-zero when a check fails, and prints one line per check either way.
"""
import argparse
import json
import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_endpoints import CheckFailed, Splunk, json_or_fail  # noqa: E402

MACRO = 'tenx-raw-events'
SHIPPED = 'sourcetype::tenx_no_raw_events'
WARNING = 'also hold'  # tenx_prefilter_parser.raw_history_message: "index X also holds" / "indexes ... also hold"
# An order-independent checksum of (text, time) over every event: the sum of the first 7 hex digits of md5.
# The time is printed to the millisecond: a compact event's _time carries a fraction (.000) where the raw one may not.
CHECKSUM = ('eval tenx_h=tonumber(substr(md5(_raw . "|" . printf("%.3f", _time)), 1, 7), 16) '
			'| stats count, sum(tenx_h) AS h, dc(tenx_h) AS d')


def search(splunk, spl, earliest, timeout=1800):
	"""(results, messages) of a blocking job: every message of the job and of its subsearches."""
	status, body = splunk.call('search/jobs', {'search': spl, 'exec_mode': 'blocking', 'output_mode': 'json',
											   'earliest_time': earliest, 'latest_time': 'now', 'timeout': str(timeout)})
	if status not in (200, 201):
		raise CheckFailed('search returned HTTP %s: %s' % (status, body[:300]))
	sid = json_or_fail(body, 'search')['sid']
	job = '%s/services/search/jobs/%s' % (splunk.url, urllib.parse.quote(sid))
	status, body = splunk.call(job + '?output_mode=json', absolute=True)
	content = json_or_fail(body, 'job')['entry'][0]['content']
	messages = ['%s %s' % (m.get('type'), m.get('text', '')) for m in content.get('messages', []) or []]
	status, body = splunk.call(job + '/results?output_mode=json&count=0', absolute=True)
	results = json_or_fail(body, 'results').get('results', []) if status == 200 else []
	if content.get('isFailed') in (True, '1', 1):
		raise CheckFailed('search failed: %s' % '; '.join(messages)[:400])
	return results, messages


def set_macro(splunk, definition):
	status, body = splunk.call('admin/macros/%s' % MACRO, {'definition': definition})
	if status not in (200, 201):
		raise CheckFailed('setting %s returned HTTP %s: %s' % (MACRO, status, body[:200]))


def macro_definition(splunk):
	status, body = splunk.call('admin/macros/%s?output_mode=json' % MACRO)
	if status != 200:
		raise CheckFailed('reading %s returned HTTP %s' % (MACRO, status))
	return json_or_fail(body, MACRO)['entry'][0]['content'].get('definition')


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--url', default='https://localhost:8089')
	parser.add_argument('--user', default='admin')
	parser.add_argument('--password-file', required=True, help='read the password from this file')
	parser.add_argument('--owner', default='nobody')
	parser.add_argument('--index', required=True, help='raw history then compact events')
	parser.add_argument('--ref-index', required=True, help='every line of both periods, raw')
	parser.add_argument('--raw-sourcetypes', required=True, help='the original sourcetypes, comma-separated')
	parser.add_argument('--earliest', default='-90d')
	parser.add_argument('--words', default='', help='comma-separated words to compare with the reference')
	args = parser.parse_args()
	password = open(args.password_file).read().strip()
	splunk = Splunk(args.url, args.user, password, 'tenx-for-splunk', args.owner)
	sts = [s for s in args.raw_sourcetypes.split(',') if s]
	arranged = 'index=%s (%s)' % (args.index, ' OR '.join('sourcetype::%s' % s for s in sts))
	failed = []

	def check(name, ok, detail):
		print('%s %s: %s' % ('PASS' if ok else 'FAIL', name, detail), flush=True)
		if not ok:
			failed.append(name)

	base = 'search index=%s earliest=%s' % (args.index, args.earliest)
	ref = 'search index=%s earliest=%s' % (args.ref_index, args.earliest)
	before = macro_definition(splunk)
	try:
		ref_sum = search(splunk, ref + ' | ' + CHECKSUM, args.earliest)[0][0]
		ref_days = dict((r['_time'], r['count']) for r in search(splunk, ref + ' | timechart span=1d count', args.earliest)[0])
		compact = search(splunk, 'search index=%s earliest=%s sourcetype::tenx_encoded | stats count' % (
			args.index, args.earliest), args.earliest)[0][0]['count']

		set_macro(splunk, SHIPPED)
		rows, msgs = search(splunk, base + ' `tx` | stats count', args.earliest)
		check('shipped macro: tx returns the compact events alone', rows and rows[0]['count'] == compact,
			  '%s of %s compact (reference %s)' % (rows[0]['count'] if rows else 0, compact, ref_sum['count']))
		warned = [m for m in msgs if WARNING in m and 'tenx-raw-events' in m]
		check('shipped macro: the search warns of the raw events', bool(warned), (warned or msgs or ['no message'])[0][:200])

		set_macro(splunk, arranged)
		for macro in ('tx', 'txf'):
			t0 = time.time()
			rows, msgs = search(splunk, base + ' `%s` | %s' % (macro, CHECKSUM), args.earliest)
			got = rows[0] if rows else {}
			check('%s: every event once, text and time equal to the reference' % macro,
				  got.get('count') == ref_sum['count'] and got.get('h') == ref_sum['h'] and got.get('d') == ref_sum['d'],
				  'count %s of %s, checksum %s, %.1f s' % (got.get('count'), ref_sum['count'],
														   'equal' if got.get('h') == ref_sum['h'] else 'differs', time.time() - t0))
			check('%s: no raw events warning' % macro, not [m for m in msgs if WARNING in m and 'tenx-raw-events' in m],
				  '; '.join(m[:80] for m in msgs) or 'no message')
		days = dict((r['_time'], r['count']) for r in search(splunk, base + ' `tx` | timechart span=1d count', args.earliest)[0])
		differ = sorted(d for d in set(days) | set(ref_days) if days.get(d, '0') != ref_days.get(d, '0'))
		check('tx: count per day equal to the reference', not differ, '%d days, %d differ' % (len(ref_days), len(differ)))
		rows = search(splunk, base + ' `tx` | streamstats current=f last(_time) AS tenx_prev | where _time > tenx_prev | stats count',
					  args.earliest)[0]
		check('tx: events in time order across the boundary', rows and rows[0]['count'] == '0',
			  '%s inversions' % (rows[0]['count'] if rows else '?'))
		rows = search(splunk, base + ' `tx` | stats count(tenx_expand_refused) AS n', args.earliest)[0]
		check('tx: nothing refused', rows and rows[0]['n'] == '0', 'tenx_expand_refused on %s' % (rows[0]['n'] if rows else '?'))
		for word in [w for w in args.words.split(',') if w]:
			a = search(splunk, base + ' `tx` %s | stats count' % word, args.earliest)[0][0]['count']
			b = search(splunk, ref + ' %s | stats count' % word, args.earliest)[0][0]['count']
			check('tx: %s' % word, a == b, '%s, reference %s' % (a, b))
	except CheckFailed as e:
		check('run', False, str(e))
	finally:
		set_macro(splunk, before if before is not None else SHIPPED)
		check('macro put back', macro_definition(splunk) == (before if before is not None else SHIPPED), before or SHIPPED)
	print('%d failed' % len(failed))
	sys.exit(1 if failed else 0)


if __name__ == '__main__':
	main()
