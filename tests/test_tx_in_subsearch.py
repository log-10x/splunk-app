"""
`tx` and `txf` inside another search's subsearch, and more than one of them in one search (Splunk
Enterprise 10.4.3, measured on the Windows 662 sample).

1. Splunk's union checks the commands of each of its datasets before it runs the subsearches inside
   them, and there eval, where and rex refuse a subsearch as their argument ("Error in 'EvalCommand':
   The expression is malformed"); search and fillnull accept one. The step before the final search
   of the tx macros (macros.conf [tenx-wild]) therefore takes its marks through fillnull, as one
   percent-encoded value (tenx_prefilter_parser.wild_marks), and computes them in an eval that holds
   no subsearch. 1.2.2 read them with `eval [subsearch]`, and every `tx` and `txf` inside
   `| union [...]` failed.
2. Every `tx` and `txf` of a search runs the prefilter, which reads the whole search and took the
   words after the first one: the second arm of a multisearch or union kept too few events (NTLM:
   0 of 50). With more than one in the search, the prefilter selects every compact event and stores
   no word plan.
3. `| tx` and `| tenxsearch` inside a subsearch returned nothing: the subsearch's job has no request
   block, so reading its time range raised, and the error was only logged. The range now comes from
   searchEarliestTime and searchLatestTime there, and an unexpected error is shown on the search.

The live forms are in tests/live_tx_in_subsearch.py.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse

import pytest

import tenx_prefilter_parser as p
from wildcard_measured import EVENTS
from wildcard_plan_measured import TC_EVENTS, TERM_CASE, WORDS as PLAN_WORDS

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
APP = os.path.join(ROOT, 'tenx-for-splunk')
ROWS = PLAN_WORDS + TERM_CASE
# What the macro step does with the stored value, as its eval writes it (macros.conf [tenx-wild]):
# split on ",", the number before ":" is the mark, the rest is the percent-encoded expression.
NUMBER = re.compile(r'^\d+:')
REST = re.compile(r':[\s\S]*$')


def macro_marks(marks, text):
	"""The value of tenx_w the macro step gives an event with this text: the numbers of the expressions it matches."""
	found = []
	for item in marks.split(','):
		if re.search(urllib.parse.unquote(NUMBER.sub('', item)), text):
			found.append(REST.sub('', item))
	return found


class TestTheMarks:

	@pytest.mark.parametrize("row", ROWS, ids=[r[0] for r in ROWS])
	def test_the_same_expressions_as_the_rewrite(self, row):
		# the search rewrite writes wild_plan()'s eval into its search; the macros read wild_marks(): the same
		# expressions in the same order, and the same search with tenx_wN=1 written tenx_w=N
		word = row[0]
		plan, marks = p.wild_plan(word), p.wild_marks(word)
		assert (plan is None) == (marks is None)
		if plan is None:
			return
		items = marks[0].split(',')
		regexes = [urllib.parse.unquote(NUMBER.sub('', item)) for item in items]
		assert [REST.sub('', item) for item in items] == [str(n) for n in range(len(items))]
		assert plan[0] == ', '.join(
			'tenx_w%d=%s' % (n, '0' if rx == p.NEVER else 'if(match(_raw, %s), 1, 0)' % p._eval_string(rx))
			for n, rx in enumerate(regexes))
		assert marks[1] == re.sub(r'tenx_w(\d+)=1', r'tenx_w=\1', plan[1])

	@pytest.mark.parametrize("row", ROWS, ids=[r[0] for r in ROWS])
	def test_the_value_goes_into_the_search_as_one_quoted_value(self, row):
		marks = p.wild_marks(row[0])
		if marks is not None:
			assert re.fullmatch(r'\d+:[A-Za-z0-9_.~%-]+(,\d+:[A-Za-z0-9_.~%-]+)*', marks[0]), marks[0]

	@pytest.mark.parametrize("row", [r for r in ROWS if r[3] is not None], ids=[r[0] for r in ROWS if r[3] is not None])
	def test_the_step_marks_the_events_the_plan_marks(self, row):
		word = row[0]
		plan, marks = p.wild_plan(word), p.wild_marks(word)
		steps = re.findall(r'tenx_w(\d+)=(?:0|if\(match\(_raw, ("(?:[^"\\]|\\.)*")\), 1, 0\))', plan[0])
		for text in EVENTS + TC_EVENTS:
			planned = [n for n, rx in steps if rx and re.search(json.loads(rx), text)]
			assert macro_marks(marks[0], text) == planned, (word, text)

	def test_text_outside_ascii(self):
		marks, search = p.wild_marks('Sé*Privilège NOT TERM(+0000)')
		assert search == 'tenx_w=0 NOT tenx_w=1'
		assert [urllib.parse.unquote(NUMBER.sub('', i)) for i in marks.split(',')] == [p.term_regex('Sé*Privilège'), p.NEVER]
		assert macro_marks(marks, 'x SéDebugPrivilège y') == ['0'] and macro_marks(marks, 'x SeDebugPrivilege y') == []

	def test_case_keeps_its_letter_case_check(self):
		assert p.wild_marks('CASE(Se*Privilege) NOT CASE(root)')[1] == '(tenx_w=0 CASE(Se*Privilege)) NOT CASE(root)'


class TestTheMacroStep:

	def definitions(self):
		import configparser
		conf = configparser.RawConfigParser(strict=False)
		conf.read(os.path.join(APP, 'default', 'macros.conf'))
		return conf

	def test_the_marks_come_through_fillnull(self):
		step = self.definitions().get('tenx-wild', 'definition')
		head, rest = step.split('| fields search] tenx_wild | ', 1)
		assert head.startswith('fillnull [| makeresults | addinfo |') and 'fields custom.tenx_wild_marks' in head
		assert rest.startswith('eval tenx_wild=if(tenx_wild=="-", null(), split(tenx_wild, ",")), tenx_w=mvmap(tenx_wild, '
							   'if(match(_raw, urldecode(replace(tenx_wild, "^\\d+:", ""))), replace(tenx_wild, ":[\\s\\S]*$", ""), null()))')
		# the eval holds no subsearch; the search step still reads the words
		assert '[' not in re.sub(r'"(?:[^"\\]|\\.)*"', '""', rest.split(' | search [', 1)[0])

	def test_the_step_follows_the_same_patterns_as_this_model(self):
		step = self.definitions().get('tenx-wild', 'definition')
		assert '"%s"' % NUMBER.pattern in step and '"%s"' % REST.pattern in step


# The prefilter command, run in a child interpreter with the real vendored splunklib (the suite stubs it, see
# conftest.py), its REST calls answered here: the job's search text, the template lookup, the store state.
CHILD = r'''
import json, os, sys, types
root, home = sys.argv[1], sys.argv[2]
os.makedirs(os.path.join(home, 'var', 'log', 'splunk'), exist_ok=True)
os.environ['SPLUNK_HOME'] = home
splunk = types.ModuleType('splunk')
clilib = types.ModuleType('splunk.clilib')
bundle_paths = types.ModuleType('splunk.clilib.bundle_paths')
bundle_paths.get_base_path = lambda: root
clilib.bundle_paths = bundle_paths
splunk.clilib = clilib
sys.modules.update({'splunk': splunk, 'splunk.clilib': clilib, 'splunk.clilib.bundle_paths': bundle_paths})
sys.path.insert(0, os.path.join(root, 'tenx-for-splunk', 'lib'))
sys.path.insert(0, os.path.join(root, 'tenx-for-splunk', 'bin'))

import tenx_prefilter, tx, tenxsearch, tenx_util, tenx_search_builder, tenx_search_manager, tenx_alert_compiler

def prefilter(search):
	cmd = tenx_prefilter.TenxPrefilterCommand()
	cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
		sid='subsearch_1794937815.59_1794937816.89', username='admin', earliest_time=0, latest_time=0,
		splunkd_uri='https://127.0.0.1:8089', session_key='key'))
	calls, warnings, searches = [], [], []
	def rest(path, data=None, answer=True):
		calls.append([path.split('?')[0], sorted((data or {}).keys())])
		if path.startswith('/services/search/jobs/1794937815.59') and not data:
			return {'entry': [{'content': {'search': search}}]}
		if path.endswith('/search/jobs') and data and 'search' in data:
			searches.append(data['search'])
		# the dictionary read finds nothing; the word index check finds every compact event indexed with its words
		return {'results': []}
	cmd._rest = rest
	cmd.write_warning = lambda m, *a: warnings.append(m)
	rows = list(cmd.generate())
	stored = [c for c in calls if c[0].startswith('/services/search/jobs/1794937815.59') and c[1]]
	lookups = [s for s in searches if 'tenx-dml-lookup' in s]
	word_checks = [s for s in searches if 'TERM(~*)' in s]
	return {'rows': rows, 'warnings': warnings, 'stored': stored, 'lookups': len(lookups), 'word_checks': len(word_checks)}

out = {
	'one': prefilter('search index=c `tx` Se*Privilege | stats count'),
	'one_txf': prefilter('| union [search index=r 4625] [search index=c `txf(XmlWinEventLog)` Kerberos | eval a=1]'),
	'two': prefilter('| multisearch [search index=c `tx` Kerberos | eval a=1] [search index=c `tx` NTLM | eval a=2]'),
	'three': prefilter('search index=c `tx` 4625 | append [search index=c `txf` 4624] | append [search index=c `txf(XmlWinEventLog)` 4672]'),
	'quoted': prefilter('search index=c `tx` Kerberos | eval note="`tx` NTLM"'),
}

# | tx inside a subsearch: the job it runs in has no request block (Splunk 10.4.3)
class Manager:
	created = []
	def __init__(self, **kw): pass
	def get_search_job_details(self, sid):
		if sid == 'top':
			return {'request': {'earliest_time': '-1h', 'latest_time': 'now', 'rf': '*'}}
		if sid == 'sub_all_time':
			return {'searchLatestTime': '2110557108.000000000'}
		return {'searchEarliestTime': '1700000000.000000000', 'searchLatestTime': '1700003600.000000000', 'reportSearch': ''}
	def create_search_job(self, data):
		Manager.created.append({k: v for k, v in data.items() if k in ('earliest_time', 'latest_time', 'rf')})
		return 'nested'
	def poll_for_job_end(self, *a, **kw): return tenx_search_manager.JobState.SUCCESS
	def is_job_live(self, sid): return True
	def cancel_search_job(self, sid): pass
	def run_probe(self, *a): return []

class Built:
	state = tenx_search_builder.ResolvedState.SUCCESS
	resolved = '| search index=c sourcetype=tenx_encoded | `tenx-inflate`'
	engaged = True
	retryable = False
	parse_error = None

class Builder:
	def __init__(self, **kw): pass
	def build(self, s): return Built()

tenx_util.get_tenx_config = lambda **kw: {}
tenx_util.ServerConnection = lambda **kw: None
tenx_search_manager.TenxSearchManager = Manager
tenx_search_builder.TenxSearchBuilder = Builder
tenx_search_builder.compact_probe = lambda b, c: (None, None)

def command(sid):
	cmd = tx.TxCommand()
	cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
		raw_args=['index=c', 'sourcetype=tenx_encoded', '4625'], args=[], sid=sid, username='admin', app='search',
		splunkd_uri='https://127.0.0.1:8089', session_key='key'))
	errors = []
	cmd.write_error = lambda m, *a: errors.append(m)
	cmd.write_warning = lambda m, *a: None
	Manager.created = []
	rows = list(cmd.generate())
	return {'created': Manager.created, 'errors': errors}

def failing(sid):
	# an unexpected error is shown on the search, not only logged
	def boom(self, data): raise RuntimeError('boom')
	saved = Manager.create_search_job
	Manager.create_search_job = boom
	try:
		return command(sid)
	finally:
		Manager.create_search_job = saved

out['tx_top'] = command('top')
out['tx_sub'] = command('subsearch_1794937815.59_1794937816.89')
out['tx_sub_all'] = command('sub_all_time')
out['tx_error'] = failing('top')
print(json.dumps(out, default=str))
'''


def run_child():
	with tempfile.TemporaryDirectory() as home:
		result = subprocess.run([sys.executable, '-c', CHILD, ROOT, home], capture_output=True, text=True, timeout=120)
	assert result.returncode == 0, result.stderr
	return json.loads(result.stdout.strip().splitlines()[-1])


RESULT = None


def child():
	global RESULT
	if RESULT is None:
		RESULT = run_child()
	return RESULT


class TestSeveralInOneSearch:

	def test_counted_outside_quotes(self):
		for search, n in (('index=c `tx` a', 1), ('| union [search i `tx` a] [search j `tx` b]', 2),
						  ('index=w `txf(XmlWinEventLog)` x | append [search `txf` y]', 2), ('`tx` "`tx`"', 1),
						  ('| makeresults | map search="search `tx` $w$"', 0), ('`tx` a | eval s="x `txf` y"', 1),
						  ('`tenx-inflate` | `tx-other`', 0), ('', 0)):
			assert p.macro_calls(search) == n, search

	def test_one_call_keeps_its_plan(self):
		one = child()['one']
		assert one['warnings'] == []
		assert one['stored'] == [['/services/search/jobs/1794937815.59', ['custom.tenx_wild_marks', 'custom.tenx_wild_search']]]

	def test_one_call_in_a_union_is_read_as_before(self):
		one = child()['one_txf']
		assert one['warnings'] == [] and one['lookups'] == 1 and one['stored'] == []
		# a prefilter of terms is checked against compact events indexed without words, once
		assert one['word_checks'] == 1

	@pytest.mark.parametrize("name", ['two', 'three'])
	def test_more_than_one_selects_every_compact_event_and_stores_no_plan(self, name):
		got = child()[name]
		assert got['rows'] == [{'search': '(*)'}]
		assert got['warnings'] == ['tx: this search holds more than one tx or txf; every compact event in range is expanded.']
		assert got['stored'] == [] and got['lookups'] == 0 and got['word_checks'] == 0

	def test_a_call_inside_quotes_is_not_counted(self):
		got = child()['quoted']
		assert got['warnings'] == [] and got['lookups'] == 1


class TestTxCommandInASubsearch:

	def test_a_search_reads_its_request(self):
		assert child()['tx_top'] == {'created': [{'earliest_time': '-1h', 'latest_time': 'now', 'rf': '*'}], 'errors': []}

	def test_a_subsearch_reads_its_range(self):
		assert child()['tx_sub'] == {'created': [{'earliest_time': '1700000000.000000000',
												 'latest_time': '1700003600.000000000', 'rf': '*'}], 'errors': []}

	def test_a_subsearch_over_all_time(self):
		assert child()['tx_sub_all']['created'] == [{'earliest_time': '', 'latest_time': '2110557108.000000000', 'rf': '*'}]

	def test_an_unexpected_error_is_shown(self):
		errors = child()['tx_error']['errors']
		assert len(errors) == 1 and 'unexpected error (boom)' in errors[0] and 'not the same as no matches' in errors[0]
