#!/usr/bin/env python3
"""
Live check of `tx`, `txf(<sourcetype>)`, `| tx` and `| tenxsearch` inside other searches, and of
more than one of them in one search, against a running Splunk with this app installed.

The instance needs the same events twice: indexed raw (--raw-index) and compact (--tx-index), and,
for the `txf` rows, compact with their original sourcetype in tenx_sourcetype (--txf-index, may be
the same index), with the field replay written for --sourcetype. Every row compares a count with the
same search on the raw index. The defaults are the Windows Security sample of the release gates
(662 events of XmlWinEventLog): the word 4625, the field comparison EventCode=4625, and the word
searches Se*Privilege and TERM(attackrange.local).

The rows (Splunk Enterprise 10.4.3, app 1.2.2 to 1.2.3):
- `tx` and `txf` inside union, multisearch, append, appendcols, join, map, a subsearch used as a
  filter, after a leading generating command, in a dashboard base search with a post-process (a base
  search holding a union among them), in a saved search that is saved, dispatched and run by the
  scheduler, and run by a user whose only role is `user`. On 1.2.2 every union form failed with
  "Error in 'EvalCommand': The expression is malformed", and such a saved search could not be saved.
- `| tx` and `| tenxsearch` inside union, append and join. Up to 1.2.2 they returned nothing there.
- Two and three `tx` arms (words and runs of digits) and two `txf` arms in one multisearch, union
  and append, each arm's count equal to its own words' count on the raw index. Up to 1.2.2 an arm
  after the first in a multisearch or union kept too few events.
- The word searches outside a subsearch and inside a union, equal to raw.

    python3 tests/live_tx_in_subsearch.py --url https://localhost:8089 --user admin --password-file pw \\
        --raw-index win_raw --tx-index win_compact --txf-index win_compact

A temporary saved search and a temporary user (role `user`, a password made here and never shown)
are created and removed. Exits non-zero on any failed check, and prints one line per check.
"""

import argparse
import json
import os
import secrets
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from live_endpoints import CheckFailed, Splunk, json_or_fail  # noqa: E402

SAVED = 'tenx_live_union_check'
USER = 'tenx_live_user'


def run(splunk, spl, owner='admin', extra=None, post=None):
	"""(first result row or None, error and warning messages). A refused search gives (None, its messages)."""
	text = spl if spl.lstrip().startswith(('|', 'search ')) else 'search ' + spl
	data = {'search': text, 'exec_mode': 'blocking', 'earliest_time': '0', 'latest_time': '+10y', 'output_mode': 'json'}
	data.update(extra or {})
	status, body = splunk.call('%s/servicesNS/%s/search/search/jobs' % (splunk.url, owner), data, absolute=True)
	if status not in (200, 201):
		try:
			return None, [m['type'] + ': ' + m['text'] for m in json.loads(body).get('messages', [])]
		except ValueError:
			return None, [body[:300]]
	sid = json_or_fail(body, 'dispatch')['sid']
	job = '%s/servicesNS/%s/search/search/%%sjobs/%s' % (splunk.url, owner, urllib.parse.quote(sid))
	status, body = splunk.call(job % '' + '?output_mode=json', absolute=True)
	entry = json_or_fail(body, 'job')['entry'][0]['content']
	messages = [m['type'] + ': ' + m['text'] for m in entry.get('messages', []) if m.get('type') in ('FATAL', 'ERROR', 'WARN')]
	if entry.get('isFailed'):
		return None, messages
	if post:
		# a dashboard's post-process: Splunk Web posts it to the v2 results endpoint (v1 and GET refuse it)
		status, body = splunk.call(job % 'v2/' + '/results', {'search': post, 'output_mode': 'json', 'count': '5'}, absolute=True)
	else:
		status, body = splunk.call(job % '' + '/results?output_mode=json&count=5', absolute=True)
	rows = json_or_fail(body, 'results').get('results', [])
	return (rows[0] if rows else {}), messages


def count(splunk, spl, **kw):
	row, messages = run(splunk, spl, **kw)
	return (None if row is None else row.get('x', '0')), messages


def forms(arm, raw):
	"""(name, the form with the arm in it, the same on the raw index): each gives x."""
	return [
		('top level', '%s | stats count as x' % arm, '%s | stats count as x' % raw),
		('union', '| union [%s | eval a="r"] [%s | eval a="x"] | stats count(eval(a="x")) as x' % (raw, arm), None),
		('multisearch', '| multisearch [%s | eval a="r"] [%s | eval a="x"] | stats count(eval(a="x")) as x' % (raw, arm), None),
		('append', '%s | eval a="r" | append [%s | eval a="x"] | stats count(eval(a="x")) as x' % (raw, arm), None),
		('appendcols', '| makeresults | appendcols [%s | stats count as x] | table x' % arm, None),
		('join', '| makeresults | eval k=1 | join type=left k [%s | stats count as x | eval k=1] | table x' % arm, None),
		('map', '| makeresults | map maxsearches=1 search="%s | stats count as x" | table x' % arm.replace('"', '\\"'), None),
		('generating command, then append', '| makeresults | eval a="g" | append [%s | eval a="x"] | stats count(eval(a="x")) as x' % arm, None),
	]


def main():
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('--url', default='https://localhost:8089')
	parser.add_argument('--user', default='admin')
	parser.add_argument('--password')
	parser.add_argument('--password-file', help='read the password from this file, to keep it out of the process list')
	parser.add_argument('--raw-index', required=True)
	parser.add_argument('--tx-index', required=True)
	parser.add_argument('--txf-index', required=True)
	parser.add_argument('--sourcetype', default='XmlWinEventLog', help='the original sourcetype for txf(<sourcetype>)')
	parser.add_argument('--word', default='4625')
	parser.add_argument('--field', default='EventCode=4625', help='a field comparison for txf')
	parser.add_argument('--arms', default='Kerberos,NTLM,mvelazco', help='three words for the arms')
	parser.add_argument('--digit-arms', default='4625,4624,4672', help='three runs of digits for the arms')
	parser.add_argument('--field-arms', default='EventCode=4625,EventCode=4624', help='two field comparisons for txf arms')
	parser.add_argument('--index-words', default='Se*Privilege,TERM(attackrange.local)',
						help='words that match other events after a pipe than on the index')
	parser.add_argument('--no-scheduler', action='store_true', help='skip waiting for the scheduler to run the saved search')
	args = parser.parse_args()
	if args.password_file:
		with open(args.password_file) as f:
			args.password = f.read().strip()
	if not args.password:
		parser.error('give --password or --password-file')

	splunk = Splunk(args.url, args.user, args.password, 'search', 'admin')
	failed, checks = 0, 0

	def report(label, ok, detail):
		nonlocal failed, checks
		checks += 1
		failed += 0 if ok else 1
		print('  %s  %-58s %s' % ('PASS' if ok else 'FAIL', label, detail), flush=True)

	def equal(label, spl, raw_spl, **kw):
		want, _ = count(splunk, raw_spl)
		got, messages = count(splunk, spl, **kw)
		errors = [m for m in messages if m.startswith(('FATAL', 'ERROR'))]
		report(label, got is not None and got == want and want not in (None, '0') and not errors,
			   '%s, raw %s%s' % (got, want, ('; ' + '; '.join(errors)[:200]) if errors or got is None else ''))
		return got

	R = lambda words: 'search index=%s %s' % (args.raw_index, words)
	TX = lambda words: 'search index=%s `tx` %s' % (args.tx_index, words)
	TXF = lambda words: 'search index=%s `txf(%s)` %s' % (args.txf_index, args.sourcetype, words)
	user_made = False
	try:
		# 1. tx and txf inside other searches
		for label, arm, raw in (('tx', TX(args.word), R(args.word)), ('txf', TXF(args.field), R(args.field))):
			for name, spl, raw_spl in forms(arm, raw):
				equal('%s: %s' % (label, name), spl, raw_spl or '%s | stats count as x' % raw)
			equal('%s: a subsearch used as a filter' % label, '%s [%s | head 1 | eval search="%s" | fields search] | stats count as x'
				  % (raw, arm, args.word if label == 'tx' else args.field), '%s | stats count as x' % raw)
			stamp = int(time.time() * 1000)
			equal('%s: dashboard base search, post-process' % label, arm, '%s | stats count as x' % raw,
				  extra={'id': 'admin__admin__search__tenxlive_%d' % stamp}, post='| stats count as x')
			equal('%s: dashboard base search with union, post-process' % label, '| union [%s | eval a="r"] [%s | eval a="x"]' % (raw, arm),
				  '%s | stats count as x' % raw, extra={'id': 'admin__admin__search__tenxliveu_%d' % stamp}, post='| stats count(eval(a="x")) as x')

		# 2. the generating commands inside other searches
		for label, gen in (('| tx', '| tx index=%s sourcetype=tenx_encoded %s' % (args.tx_index, args.word)),
						   ('| tenxsearch', '| tenxsearch searchstring="index=%s sourcetype=tenx_encoded %s"' % (args.tx_index, args.word))):
			raw = R(args.word)
			for name, spl in (('union', '| union [%s | eval a="r"] [%s | eval a="x"] | stats count(eval(a="x")) as x' % (raw, gen)),
							  ('append', '%s | eval a="r" | append [%s | eval a="x"] | stats count(eval(a="x")) as x' % (raw, gen)),
							  ('join', '| makeresults | eval k=1 | join type=left k [%s | stats count as x | eval k=1] | table x' % gen)):
				equal('%s: %s' % (label, name), spl, '%s | stats count as x' % raw)

		# 3. more than one tx or txf in one search: each arm against its own words on the raw index
		arm_sets = [('tx', TX, args.arms.split(',')[:2]), ('tx', TX, args.arms.split(',')[:3]),
					('tx', TX, args.digit_arms.split(',')[:2]), ('tx', TX, args.digit_arms.split(',')[:3]),
					('txf', TXF, args.field_arms.split(',')[:2])]
		for form in ('multisearch', 'union', 'append'):
			for label, make, words in arm_sets:
				arms = ['%s | eval tenx_arm="a%d"' % (make(w), i) for i, w in enumerate(words)]
				if form == 'append':
					spl = arms[0] + ''.join(' | append [%s]' % a for a in arms[1:])
				else:
					spl = '| %s %s' % (form, ' '.join('[%s]' % a for a in arms))
				status, body = splunk.call('%s/servicesNS/admin/search/search/jobs' % splunk.url, {
					'search': spl + ' | stats count by tenx_arm', 'exec_mode': 'oneshot', 'earliest_time': '0', 'latest_time': '+10y',
					'output_mode': 'json', 'count': '0'}, absolute=True)
				got = {r.get('tenx_arm'): r.get('count') for r in json_or_fail(body, 'oneshot').get('results', [])} if status == 200 else None
				for i, w in enumerate(words):
					want, _ = count(splunk, '%s | stats count as x' % R(w))
					value = None if got is None else got.get('a%d' % i, '0')
					report('%s, %d %s arms, arm %d (%s)' % (form, len(words), label, i + 1, w), value == want and want not in (None, '0'),
						   '%s, raw %s%s' % (value, want, '' if got is not None else '; HTTP %s %s' % (status, body[:200])))

		# 4. the word searches that match other events after a pipe: outside a subsearch and inside a union
		for word in args.index_words.split(','):
			for label, make in (('tx', TX), ('txf', TXF)):
				raw = R(word)
				equal('%s %s: top level' % (label, word), '%s | stats count as x' % make(word), '%s | stats count as x' % raw)
				equal('%s %s: union' % (label, word), '| union [%s | eval a="r"] [%s | eval a="x"] | stats count(eval(a="x")) as x'
					  % (raw, make(word)), '%s | stats count as x' % raw)

		# 5. a saved search with a union: saved, dispatched, and run by the scheduler
		raw = R(args.word)
		union = '| union [%s | eval a="r"] [%s | eval a="x"] | stats count(eval(a="x")) as x' % (raw, TX(args.word))
		want, _ = count(splunk, '%s | stats count as x' % raw)
		splunk.call('%s/servicesNS/admin/search/saved/searches/%s' % (splunk.url, SAVED), method='DELETE', absolute=True)
		status, body = splunk.call('%s/servicesNS/admin/search/saved/searches' % splunk.url, {
			'name': SAVED, 'search': union, 'cron_schedule': '* * * * *', 'is_scheduled': '0' if args.no_scheduler else '1',
			'dispatch.earliest_time': '0', 'dispatch.latest_time': 'now'}, absolute=True)
		report('saved search with union: saved', status == 201, 'HTTP %s%s' % (status, '' if status == 201 else ' ' + body[:200]))
		if status == 201:
			status, body = splunk.call('%s/servicesNS/admin/search/saved/searches/%s/dispatch' % (splunk.url, SAVED),
									   {'output_mode': 'json'}, absolute=True)
			sid = json_or_fail(body, 'dispatch').get('sid') if status in (200, 201) else None
			value = None
			if sid:
				for _ in range(150):
					s, b = splunk.call('%s/services/search/jobs/%s?output_mode=json' % (splunk.url, urllib.parse.quote(sid)), absolute=True)
					if s == 200 and json.loads(b)['entry'][0]['content'].get('isDone'):
						break
					time.sleep(2)
				s, b = splunk.call('%s/services/search/jobs/%s/results?output_mode=json' % (splunk.url, urllib.parse.quote(sid)), absolute=True)
				rows = json_or_fail(b, 'results').get('results', []) if s == 200 else []
				value = rows[0].get('x') if rows else None
			report('saved search with union: dispatched', value == want, '%s, raw %s' % (value, want))
			if not args.no_scheduler:
				since, row = time.time(), None
				while time.time() - since < 200 and not row:
					time.sleep(15)
					status, body = splunk.call('%s/servicesNS/admin/search/search/jobs' % splunk.url, {
						'search': 'search index=_internal sourcetype=scheduler savedsearch_name=%s | head 1 | fields status result_count reason' % SAVED,
						'exec_mode': 'oneshot', 'earliest_time': str(int(since) - 5), 'output_mode': 'json'}, absolute=True)
					rows = json_or_fail(body, 'scheduler').get('results', []) if status == 200 else []
					row = rows[0] if rows else None
				report('saved search with union: run by the scheduler', bool(row) and row.get('status') == 'success' and row.get('result_count') == '1',
					   json.dumps({k: row.get(k) for k in ('status', 'result_count', 'reason') if row.get(k)}) if row else 'no scheduler run in 200 s')

		# 6. a user whose only role is `user`
		password = 'T1x' + secrets.token_urlsafe(18)
		splunk.call('%s/services/authentication/users/%s' % (splunk.url, USER), method='DELETE', absolute=True)
		status, body = splunk.call('%s/services/authentication/users' % splunk.url, {'name': USER, 'password': password, 'roles': 'user'}, absolute=True)
		user_made = status == 201
		report('user with the role user: created', user_made, 'HTTP %s' % status)
		if user_made:
			other = Splunk(args.url, USER, password, 'search', USER)
			for label, spl in (('tx top level', '%s | stats count as x' % TX(args.word)), ('tx in union', union),
							   ('txf in union', '| union [%s | eval a="r"] [%s | eval a="x"] | stats count(eval(a="x")) as x' % (R(args.field), TXF(args.field))),
							   ('tx in append', '%s | eval a="r" | append [%s | eval a="x"] | stats count(eval(a="x")) as x' % (raw, TX(args.word)))):
				want_raw, _ = count(splunk, '%s | stats count as x' % (R(args.field) if 'txf' in label else raw))
				got, messages = count(other, spl, owner=USER)
				report('user with the role user: %s' % label, got == want_raw and want_raw not in (None, '0'),
					   '%s, raw %s%s' % (got, want_raw, '' if got is not None else '; ' + '; '.join(messages)[:200]))
	except (CheckFailed, KeyError, ValueError) as error:
		report('run', False, error)
	finally:
		splunk.call('%s/servicesNS/admin/search/saved/searches/%s' % (splunk.url, SAVED), method='DELETE', absolute=True)
		if user_made:
			splunk.call('%s/services/authentication/users/%s' % (splunk.url, USER), method='DELETE', absolute=True)

	print('%d of %d checks passed' % (checks - failed, checks))
	return 1 if failed else 0


if __name__ == '__main__':
	sys.exit(main())
