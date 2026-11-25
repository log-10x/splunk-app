#!/usr/bin/env python3
"""
Live check of events the Receiver sends as their own text beside compact ones (its templateCreateAfter option),
against a running Splunk with this app installed.

The instance needs an index (--index) holding the Receiver's stream for some sources, compact events ("~...") and
events sent as text together, under the compact sourcetype with tenx_sourcetype set, and an index (--ref-index)
holding every line of those sources indexed raw, with the same host and source. The rows:
- the stream holds both kinds;
- with --cmp-index (the same lines through a Receiver without the option, all compact), through `tx` every event of
  either kind has the text, _time to the millisecond, host and source of the same line sent compact, and through
  `txf` the same fields;
- through `tx` and through `txf`, every event once: its text, host, source and original sourcetype (the sender's
  tenx_sourcetype against the raw event's sourcetype) equal the raw event's, by kind, or, for a line whose text
  arrived changed (a control character through Fluent Bit and HEC), the same line's text in --cmp-index; its _time equal to the
  millisecond on the sources named in --time-sources (a raw event without a timestamp, timestamp=none, is left
  out: it has the time it was indexed); no event carries tenx_expand_refused;
- through `txf`, every field of the raw event on every event, by kind (fields equal on every event, of the fields
  the raw events have);
- for each word (--words), the `| tx` command, a compiled alert (the tenx-alert endpoint's compile, run) and the
  dashboard hook (the tenx-search endpoint) count as many events as the raw index;
- with --hist-index (raw lines of an application that itself starts some lines with "~", indexed raw under
  --hist-sourcetype), what `tx` returns for them when tenx-raw-events names them (printed, not checked), and the
  macro is put back.
    python3 tests/live_text_events.py --url https://localhost:8089 --password-file pw --index mix --ref-index raw \\
        --time-sources /var/log/app/app.log,/var/log/fortigate/fwb.log --words declined,scheduler
Exits non-zero when a check fails, and prints one line per check either way.
"""
import argparse
import collections
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from live_endpoints import CheckFailed, Splunk, json_or_fail, results_of, wait_for_job  # noqa: E402
from live_raw_history import search  # noqa: E402
from live_txf_left_out import SKIP, export  # noqa: E402

KEYS = 'eval m=md5(_raw), t=printf("%.3f", _time), st=coalesce(tenx_sourcetype, sourcetype), refused=tenx_expand_refused'


def count_of(rows):
	return int(float((rows or [{}])[0].get('count') or 0))


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--url', default='https://localhost:8089')
	parser.add_argument('--user', default='admin')
	parser.add_argument('--password-file', required=True, help='read the password from this file')
	parser.add_argument('--owner', default='nobody')
	parser.add_argument('--index', required=True, help='the Receiver stream: compact events and events sent as text')
	parser.add_argument('--ref-index', required=True, help='every line of the same sources, raw')
	parser.add_argument('--time-sources', default='', help='sources whose _time must equal the raw event\'s, comma-separated')
	parser.add_argument('--words', default='', help='words to count through | tx, a compiled alert and the dashboard hook')
	parser.add_argument('--cmp-index', default='', help='the same lines through a Receiver without the option')
	parser.add_argument('--hist-index', default='')
	parser.add_argument('--hist-sourcetype', default='')
	args = parser.parse_args()
	splunk = Splunk(args.url, args.user, open(args.password_file).read().strip(), 'tenx-for-splunk', args.owner)
	failed = []
	time_sources = set(s for s in args.time_sources.split(',') if s)

	def check(name, ok, detail):
		print('%s %s: %s' % ('PASS' if ok else 'FAIL', name, detail), flush=True)
		if not ok:
			failed.append(name)

	try:
		stream = export(splunk, 'search index=%s | eval kind=if(match(_raw, "^~"), "compact", "text"), m=md5(_raw) '
						'| table kind m source' % args.index)
		text_md5 = collections.Counter(r['m'] for r in stream if r.get('kind') == 'text')
		kinds = collections.Counter((r.get('source'), r.get('kind')) for r in stream)
		n_text, n_compact = sum(text_md5.values()), len(stream) - sum(text_md5.values())
		check('the stream holds both kinds', n_text > 0 and n_compact > 0, '%d compact, %d sent as text; by source: %s' % (
			n_compact, n_text, ', '.join('%s %s %d' % (s, k, n) for (s, k), n in sorted(kinds.items()))))
		ref = export(splunk, 'search index=%s | %s | table m t host source st timestamp' % (args.ref_index, KEYS))

		norm = lambda v: None if v is None else (tuple(sorted(v)) if isinstance(v, list) else (v,))
		cmp_text = collections.Counter()
		if args.cmp_index:
			# A line whose compact form carries no epoch first takes the time it arrives with in either stream, and the
			# two streams arrive at different times: its _time is not compared.
			mix = export(splunk, 'search index=%s `tx` | %s | table m t host source' % (args.index, KEYS))
			rows = export(splunk, 'search index=%s | eval timed=if(match(_raw, "^~[^,]+,(\\d{13}|\\d{19}|\\d{10}\\.\\d{1,9})(,|$)"), 1, 0) '
						  '| `tenx-inflate` | %s | table m t host source timed' % (args.cmp_index, KEYS))
			cmp_text = collections.Counter(r['m'] for r in rows)
			cmp_ = collections.Counter((r['m'], r.get('host'), r.get('source'), r['t'] if r.get('timed') == '1' else '-') for r in rows)
			cmp_timed = set((r['m'], r.get('host'), r.get('source')) for r in rows if r.get('timed') == '1')
			by = collections.Counter()
			for r in mix:
				k = 'text' if r['m'] in text_md5 else 'compact'
				by[(k, 'n')] += 1
				timed = (r['m'], r.get('host'), r.get('source')) in cmp_timed
				by[(k, 'timed')] += timed
				key = (r['m'], r.get('host'), r.get('source'), r['t'] if timed else '-')
				if cmp_[key] > 0:
					cmp_[key] -= 1
					by[(k, 'eq')] += 1
			for k in ('compact', 'text'):
				check('tx, events %s: text, _time, host and source of the same line sent compact' % (
					'sent as text' if k == 'text' else k), by[(k, 'n')] > 0 and by[(k, 'eq')] == by[(k, 'n')],
					'%d of %d equal (_time compared on %d, where the compact line carries its time)' % (
						by[(k, 'eq')], by[(k, 'n')], by[(k, 'timed')]))
			fm = export(splunk, 'search index=%s `txf` | eval k=md5(_raw) | fields * | fields - _raw' % args.index)
			fc = collections.defaultdict(list)
			for r in export(splunk, 'search index=%s `txf` | eval k=md5(_raw) | fields * | fields - _raw' % args.cmp_index):
				fc[r.get('k')].append(r)
			skip = SKIP | {'index', 'splunk_server'}
			for kind in ('compact', 'text'):
				n = eq = 0
				bad = collections.Counter()
				for r in fm:
					if ('text' if r.get('k') in text_md5 else 'compact') != kind or not fc.get(r.get('k')):
						continue
					o = fc[r['k']][0]
					diff = [x for x in set(o) | set(r) if x not in skip and not x.startswith('tenx_') and norm(o.get(x)) != norm(r.get(x))]
					bad.update(diff)
					n += 1
					eq += not diff
				check('txf, events %s: the fields of the same line sent compact' % ('sent as text' if kind == 'text' else kind),
					  n > 0 and eq == n, '%d of %d events equal%s' % (eq, n, '; differ: ' + ', '.join(
						  '%s %d' % kv for kv in bad.most_common(5)) if bad else ''))

		def kind_of(row):
			return 'text' if row['m'] in text_md5 else 'compact'

		for mac in ('tx', 'txf'):
			got = export(splunk, 'search index=%s `%s` | %s | table m t host source st refused' % (args.index, mac, KEYS))
			left = collections.Counter((r['m'], r.get('host'), r.get('source'), r.get('st')) for r in ref)
			times = collections.Counter((r['m'], r.get('host'), r.get('source'), r['t']) for r in ref)
			untimed = set(r['m'] for r in ref if r.get('timestamp') == 'none')
			by = collections.Counter()
			for r in got:
				k = kind_of(r)
				by[(k, 'events')] += 1
				key = (r['m'], r.get('host'), r.get('source'), r.get('st'))
				if left[key] > 0:
					left[key] -= 1
					by[(k, 'equal')] += 1
				elif cmp_text[r['m']] > 0:
					# the same line sent compact came back with this text too: the text arrived changed for either kind
					by[(k, 'as_compact')] += 1
				if r.get('source') in time_sources and r['m'] not in untimed:
					by[(k, 'timed')] += 1
					tk = (r['m'], r.get('host'), r.get('source'), r['t'])
					if times[tk] > 0:
						times[tk] -= 1
						by[(k, 'time_equal')] += 1
				if r.get('refused'):
					by[(k, 'refused')] += 1
			missing = sum(left.values())
			for k in ('compact', 'text'):
				check('%s, events %s: text, host, source and original sourcetype as raw' % (mac, 'sent as text' if k == 'text' else k),
					  by[(k, 'events')] > 0 and by[(k, 'equal')] + by[(k, 'as_compact')] == by[(k, 'events')],
					  '%d of %d equal%s' % (by[(k, 'equal')], by[(k, 'events')], '; %d others as the same line sent compact '
										   '(the text arrived changed for either kind)' % by[(k, 'as_compact')] if by[(k, 'as_compact')] else ''))
				check('%s, events %s: _time as raw to the millisecond on %s' % (mac, 'sent as text' if k == 'text' else k,
																			  ', '.join(sorted(time_sources)) or 'no source'),
					  by[(k, 'time_equal')] == by[(k, 'timed')], '%d of %d equal' % (by[(k, 'time_equal')], by[(k, 'timed')]))
				check('%s, events %s: no tenx_expand_refused' % (mac, 'sent as text' if k == 'text' else k),
					  by[(k, 'refused')] == 0, '%d carry it' % by[(k, 'refused')])
			changed = by[('compact', 'as_compact')] + by[('text', 'as_compact')]
			check('%s returns every raw event once' % mac, len(got) == len(ref) and missing == changed,
				  'raw %d, %s %d, raw events not returned with their text %d (all-compact stream the same: %d)' % (
					  len(ref), mac, len(got), missing, changed))

		# fields through txf, by kind
		raw_rows = export(splunk, 'search index=%s | eval k=md5(_raw) | fields * | fields - _raw' % args.ref_index)
		txf_rows = export(splunk, 'search index=%s `txf` | eval k=md5(_raw) | fields * | fields - _raw' % args.index)
		a = collections.defaultdict(list)
		for r in raw_rows:
			a[r.get('k')].append(r)
		for kind in ('compact', 'text'):
			names, bad, n, eq = set(), collections.Counter(), 0, 0
			for r in txf_rows:
				if ('text' if r.get('k') in text_md5 else 'compact') != kind or not a.get(r.get('k')):
					continue
				base = a[r['k']][0]
				# timestamp=none: Splunk's mark on a raw event read from a file whose text has no timestamp; an event sent
				# to the HTTP Event Collector's event endpoint never carries it (props.conf ADD_EXTRA_TIME_FIELDS)
				skip = SKIP | {'timestamp'}
				names.update(x for x in base if x not in skip and not x.startswith('tenx_'))
				diff = [x for x in set(base) | set(r) if x not in skip and not x.startswith('tenx_') and norm(base.get(x)) != norm(r.get(x))]
				bad.update(diff)
				n += 1
				eq += not diff
			check('txf, events %s: every field of the raw event' % ('sent as text' if kind == 'text' else kind),
				  n > 0 and eq == n, '%d of %d events with every field equal; %d of %d fields equal on every event%s' % (
					  eq, n, len(names - set(bad)), len(names), '; differ: ' + ', '.join('%s %d' % kv for kv in bad.most_common(5)) if bad else ''))

		for word in [w for w in args.words.split(',') if w]:
			want = count_of(search(splunk, 'search index=%s %s | stats count' % (args.ref_index, word), '0')[0])
			cmd = count_of(search(splunk, '| tx index=%s sourcetype=tenx_encoded %s | stats count' % (args.index, word), '0')[0])
			name = 'tenx_text_events_check'
			status, body = splunk.call('tenx-alert', {'search': 'search index=%s sourcetype=tenx_encoded %s' % (args.index, word),
													  'name': name, 'is_scheduled': '0'}, method='POST')
			compiled = json_or_fail(body, 'tenx-alert').get('compiled_search') if status == 200 else None
			splunk.call('saved/searches/' + name, method='DELETE')
			if compiled and not compiled.lstrip().startswith(('|', 'search ')):
				compiled = 'search ' + compiled
			alert = count_of(search(splunk, compiled + ' | stats count', '0')[0]) if compiled else -1
			status, body = splunk.call('tenx-search', {'search': 'search index=%s sourcetype=tenx_encoded %s | stats count' % (
				args.index, word), 'earliest_time': '0', 'latest_time': '+10y'}, method='POST')
			hook = -1
			if status == 200 and json_or_fail(body, 'tenx-search').get('sid'):
				sid = json.loads(body)['sid']
				wait_for_job(splunk, sid)
				hook = count_of(results_of(splunk, sid))
			check('"%s": | tx, a compiled alert and the dashboard hook count as raw' % word, want > 0 and cmd == alert == hook == want,
				  'raw %d, | tx %d, compiled alert %d, dashboard hook %d' % (want, cmd, alert, hook))

		if args.hist_index:
			macro = 'admin/macros/tenx-raw-events'
			before = json_or_fail(splunk.call(macro + '?output_mode=json')[1], macro)['entry'][0]['content']['definition']
			try:
				splunk.call(macro, {'definition': 'index=%s sourcetype::%s' % (args.hist_index, args.hist_sourcetype)})
				raw_h = export(splunk, 'search index=%s | eval m=md5(_raw), tilde=if(match(_raw, "^~"), 1, 0) | table m tilde' % args.hist_index)
				got_h = export(splunk, 'search (index=%s OR index=%s) `tx` | where index="%s" | eval m=md5(_raw), tilde=if(match(_raw, "^~"), 1, 0) '
							   '| table m tilde tenx_expand_refused' % (args.index, args.hist_index, args.hist_index))
				same = len(collections.Counter(r['m'] for r in raw_h) & collections.Counter(r['m'] for r in got_h))
				marks = collections.Counter((r.get('tilde'), r.get('tenx_expand_refused') or '-') for r in got_h)
				print('INFO raw lines named in tenx-raw-events: %d raw (%d start with ~), tx returned %d, text equal %d; '
					  '(starts with ~, tenx_expand_refused): %s' % (len(raw_h), sum(int(r['tilde']) for r in raw_h), len(got_h), same,
																	', '.join('%s %s %d' % (k[0], k[1], v) for k, v in sorted(marks.items()))), flush=True)
			finally:
				splunk.call(macro, {'definition': before})
				check('tenx-raw-events put back', True, before)
	except CheckFailed as e:
		check('run', False, str(e))
	print('%d failed' % len(failed))
	sys.exit(1 if failed else 0)


if __name__ == '__main__':
	main()
