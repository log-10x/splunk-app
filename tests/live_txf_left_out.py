#!/usr/bin/env python3
"""
Live check of the field replay for sourcetypes the `tenx-replay` macro leaves out, against a running Splunk with
this app installed.

The macro `txf` runs holds every original sourcetype that has a unit, up to the commands one Splunk search runs;
past those, or past replay_max_macro_chars (tenx_config.conf) where an instance sets it, it holds the busiest
only. The others keep their own unit, which txf(<sourcetype>) and the search rewrite run; their record in
tenx_replay.conf says left_out=txf, and a `txf` search over their index warns. The instance needs the same
events twice: raw (--raw-index) and compact with tenx_sourcetype (--txf-index), of the sourcetypes named
(--sourcetypes). --max-macro-chars sets the limit for the run (and puts the previous value back), so that the
macro leaves some of them out on an instance where it would not. The rows:
- after | tenxreplay, every sourcetype named has a unit that replays its rules (not the no-op unit);
- for each, txf(<sourcetype>) gives every one of its events every field of the raw event;
- plain `txf` over --txf-index, when the record leaves none of them out, gives every event of them every field of
  the raw event (events, and fields equal on every event, of the fields the raw events have);
- a `txf` search over --txf-index warns, naming them, exactly when the record leaves one of them out.
    python3 tests/live_txf_left_out.py --url https://localhost:8089 --user admin --password-file pw \\
        --raw-index fgt_raw --txf-index fgt_compact --sourcetypes fortigate_traffic,fortigate_utm
Exits non-zero when a check fails, and prints one line per check either way.
"""
import argparse
import collections
import json
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', 'tenx-for-splunk', 'bin'))
from live_endpoints import CheckFailed, Splunk, json_or_fail  # noqa: E402
from live_raw_history import search  # noqa: E402
import tenx_replay_builder as builder  # noqa: E402

# Splunk's own per-event fields, and the time fields derived from the text (as the release gates compare).
SKIP = {'_bkt', '_cd', '_serial', '_si', '_sourcetype', '_indextime', '_subsecond', 'splunk_server', 'index',
		'_eventtype_color', 'linecount', 'timestartpos', 'timeendpos', 'date_hour', 'date_mday', 'date_minute',
		'date_month', 'date_second', 'date_wday', 'date_year', 'date_zone', 'punct', '_kv', '_time', '_raw', 'k'}
WARNING = 'the field replay of txf leaves out'


def export(splunk, spl):
	"""Every result row of a search through the export endpoint (all time), as dicts."""
	status, body = splunk.call('%s/services/search/jobs/export' % splunk.url,
							   {'search': spl, 'output_mode': 'json', 'earliest_time': '0', 'latest_time': '+10y',
								'adhoc_search_level': 'verbose', 'preview': 'false'}, absolute=True)
	if status != 200:
		raise CheckFailed('export returned HTTP %s: %s' % (status, body[:200]))
	rows = []
	for line in body.splitlines():
		if line.strip():
			o = json.loads(line)
			if o.get('result') and not o.get('preview'):
				rows.append(o['result'])
	return rows


def compare(raw, replayed):
	"""(events matched, events with every field equal, fields that differ) keyed on k (md5 of the text)."""
	a, b = collections.defaultdict(list), collections.defaultdict(list)
	for r in raw:
		a[r.get('k')].append(r)
	for r in replayed:
		b[r.get('k')].append(r)
	norm = lambda v: None if v is None else (tuple(sorted(v)) if isinstance(v, list) else (v,))
	keys = sorted(set(a) & set(b), key=str)
	equal, differ = 0, collections.Counter()
	for k in keys:
		ra, rb = a[k][-1], b[k][-1]
		names = set(n for n in set(ra) | set(rb) if n not in SKIP and not n.startswith('tenx_'))
		bad = [n for n in names if norm(ra.get(n)) != norm(rb.get(n))]
		differ.update(bad)
		equal += not bad
	return len(keys), equal, differ


def field_tally(raw, replayed):
	"""(fields the raw events have, those equal on every event matched on k, events matched)."""
	a, b = dict((r.get('k'), r) for r in raw), dict((r.get('k'), r) for r in replayed)
	norm = lambda v: None if v is None else (tuple(sorted(v)) if isinstance(v, list) else (v,))
	names, bad = set(), set()
	for r in raw:
		names.update(n for n in r if n not in SKIP and not n.startswith('tenx_'))
	keys = set(a) & set(b)
	for k in keys:
		for n in set(n for n in set(a[k]) | set(b[k]) if n not in SKIP and not n.startswith('tenx_')):
			if norm(a[k].get(n)) != norm(b[k].get(n)):
				bad.add(n)
	return len(names), len(names - bad), len(keys), sorted(bad)


def conf_entry(splunk, path):
	status, body = splunk.call(path + ('&' if '?' in path else '?') + 'output_mode=json&count=0')
	if status == 404:
		return None
	if status != 200:
		raise CheckFailed('%s returned HTTP %s' % (path, status))
	return json_or_fail(body, path)['entry']


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--url', default='https://localhost:8089')
	parser.add_argument('--user', default='admin')
	parser.add_argument('--password-file', required=True, help='read the password from this file')
	parser.add_argument('--owner', default='nobody')
	parser.add_argument('--raw-index', required=True)
	parser.add_argument('--txf-index', required=True)
	parser.add_argument('--sourcetypes', required=True, help='original sourcetypes of both indexes, comma-separated')
	parser.add_argument('--max-macro-chars', type=int, help='replay_max_macro_chars for this run')
	args = parser.parse_args()
	splunk = Splunk(args.url, args.user, open(args.password_file).read().strip(), 'tenx-for-splunk', args.owner)
	sts = [s for s in args.sourcetypes.split(',') if s]
	failed = []

	def check(name, ok, detail):
		print('%s %s: %s' % ('PASS' if ok else 'FAIL', name, detail), flush=True)
		if not ok:
			failed.append(name)

	config = 'configs/conf-tenx_config/config'
	before = None
	try:
		if args.max_macro_chars:
			before = (conf_entry(splunk, config) or [{}])[0].get('content', {}).get('replay_max_macro_chars')
			splunk.call(config, {'replay_max_macro_chars': str(args.max_macro_chars)})
		rows, msgs = search(splunk, '| tenxreplay', '0')
		check('tenxreplay ran', bool(rows) and not [m for m in msgs if m.startswith(('ERROR', 'FATAL'))],
			  '%d rows %s' % (len(rows), '; '.join(m[:100] for m in msgs if m.startswith(('ERROR', 'FATAL')))))
		record = dict((e['name'], e['content']) for e in conf_entry(splunk, 'configs/conf-tenx_replay') or [])
		no_op = builder.no_op_unit().spl()
		left = []
		for st in sts:
			kv = record.get(st) or {}
			if 'txf' in str(kv.get('left_out') or '').split(','):
				left.append(st)
			unit = builder.unit_macro(st)
			entry = conf_entry(splunk, 'configs/conf-macros/%s' % urllib.parse.quote(unit, safe='')) or [{}]
			definition = entry[0].get('content', {}).get('definition') or ''
			check('%s: a unit that replays its rules' % st, bool(definition) and definition != no_op,
				  '%s, %d characters, left_out=%s' % (unit, len(definition), kv.get('left_out') or '(none)'))
			raw = export(splunk, 'search index=%s sourcetype="%s" | eval k=md5(_raw) | fields * | fields - _raw'
						 % (args.raw_index, st))
			replayed = export(splunk, 'search index=%s `txf(%s)` | where tenx_sourcetype="%s" | eval k=md5(_raw) | fields * '
							  '| fields - _raw' % (args.txf_index, st, st))
			matched, equal, differ = compare(raw, replayed)
			check('%s: txf(%s) gives every event every field of the raw event' % (st, st),
				  matched == len(raw) == len(replayed) and equal == matched and matched > 0,
				  '%d of %d events equal (raw %d, replayed %d)%s' % (
					  equal, matched, len(raw), len(replayed),
					  '; differ: ' + ', '.join('%s %d' % kv for kv in differ.most_common(3)) if differ else ''))
		if sts:
			where = ' OR '.join('sourcetype="%s"' % st for st in sts)
			raw = export(splunk, 'search index=%s (%s) | eval k=md5(_raw) | fields * | fields - _raw' % (args.raw_index, where))
			replayed = export(splunk, 'search index=%s `txf` | where %s | eval k=md5(_raw) | fields * | fields - _raw' % (
				args.txf_index, ' OR '.join('tenx_sourcetype="%s"' % st for st in sts)))
			names, equal, matched, bad = field_tally(raw, replayed)
			detail = '%d of %d fields equal on every event, %d events matched (raw %d, txf %d)%s' % (
				equal, names, matched, len(raw), len(replayed), '; differ: ' + ', '.join(bad[:5]) if bad else '')
			if left:
				# the macro leaves some out by the limits set for this run: those events get only their text's fields
				print('INFO txf with %s left out: %s' % (', '.join(left), detail), flush=True)
			else:
				check('txf gives every event of %s every field of the raw event' % ', '.join(sts),
					  matched == len(raw) == len(replayed) and equal == names and matched > 0, detail)
		rows, msgs = search(splunk, 'search index=%s `txf` | stats count' % args.txf_index, '0')
		warned = [m for m in msgs if WARNING in m]
		if left:
			check('txf warns of the sourcetypes left out', bool(warned) and all(st in warned[0] for st in left[:3]),
				  'left out: %s; %s' % (', '.join(left), (warned or ['no warning'])[0][:200]))
		else:
			check('txf has no left-out warning when nothing named is left out', not warned, (warned or ['no warning'])[0][:200])
	except CheckFailed as e:
		check('run', False, str(e))
	finally:
		if args.max_macro_chars:
			if before is None:
				splunk.call(config, {'replay_max_macro_chars': str(builder.DEFAULT_SETTINGS['replay_max_macro_chars'])})
			else:
				splunk.call(config, {'replay_max_macro_chars': before})
			search(splunk, '| tenxreplay', '0')
			check('replay_max_macro_chars put back', True, before or 'default')
	print('%d failed' % len(failed))
	sys.exit(1 if failed else 0)


if __name__ == '__main__':
	main()
