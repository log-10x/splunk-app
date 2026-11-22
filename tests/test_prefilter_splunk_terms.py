"""
Field narrowing from Splunk's own index terms (tenx_config.conf field_narrowing = splunk; off by default).

A field comparison after `tx` or `txf` narrows the compact events by the index terms Splunk requires of raw
events for it, read from a probe job's search.log. Each term is required as the same text written as a word,
so the guarantees of word search carry over.

What the prefilter cannot read with certainty narrows nothing: an indexed term on its own or of a default
field, a NOT, an OR with such a branch, or a term with a quote, backslash, parenthesis or bracket. So does a
lispy it cannot parse, or a probe it cannot run (a subsearch in the words).
"""
import os

import tenx_prefilter_parser as p

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
STORED = [("%Y-%m-%dT%H:%M:%S.%7QZ", False, False), ("%H:%M:%S", False, False)]
D = {"error": (10, ["TERM(~e1)"]), "success": (4, ["TERM(~s1)", "TERM(~s2)"]), "kerberos": (2, ["TERM(~k1)"])}
LOG = """11-19-2026 10:00:00.100 INFO  SearchParser [123 searchOrchestrator] - PARSING: search EventCode=4625 | head 1
11-19-2026 10:00:00.200 INFO  UnifiedSearch [123 searchOrchestrator] - base lispy: [ AND 4625 [ OR kerberos error ] ]
11-19-2026 10:00:00.300 INFO  UnifiedSearch [123 searchOrchestrator] - base lispy: [ AND 4625 [ OR kerberos error ] ]
"""


def tree(text):
	return p.Parser(p.tokenize(text)).parse()


def narrowed(text, lispy, formats=STORED):
	"""The prefilter of `text` with Splunk's terms `lispy` ANDed in, as tenxprefilter builds it."""
	t = tree(text)
	terms = p.lispy_tree(lispy)
	if terms not in (None, p.TRUE):
		t = ("and", [t, terms])
	digits = p.digit_pieces_cleared(p.digit_candidates(t), formats)
	return p.prefilter(t, D, None, digits)


def as_words(text, extra=None, formats=STORED):
	"""The prefilter of `text`, and of `extra` written as words after it (ANDed in the same shape)."""
	t = tree(text)
	if extra is not None:
		t = ("and", [t, tree(extra)])
	digits = p.digit_pieces_cleared(p.digit_candidates(t), formats)
	return p.prefilter(t, D, None, digits)


class TestTheSetting:

	def test_modes(self):
		assert p.narrowing_mode({'field_narrowing': 'splunk'}) == 'splunk'
		assert p.narrowing_mode({'field_narrowing': ' Splunk '}) == 'splunk'
		assert p.narrowing_mode({'field_narrowing': 'true'}) == 'list'
		assert p.narrowing_mode({'field_narrowing': '1'}) == 'list'
		for off in ({'field_narrowing': 'false'}, {'field_narrowing': ''}, {}, None, {'field_narrowing': 'maybe'}):
			assert p.narrowing_mode(off) == 'off', off

	def test_shipped_default_is_off(self):
		# splunk is not the default until a live run has shown the base lispy in a probe's log
		app = os.path.join(ROOT, 'tenx-for-splunk')
		assert p.narrowing_mode_on_disk(app) == 'off'
		assert not p.narrowing_on_disk(app)

	def test_unreadable_is_off(self, tmp_path):
		assert p.narrowing_mode_on_disk(str(tmp_path / 'missing')) == 'off'

	def test_only_field_comparisons_start_a_probe(self):
		assert p.compares_fields(tree("EventCode=4625"))
		assert p.compares_fields(tree("error user IN (a, b)"))
		assert p.compares_fields(tree("NOT action=success"))
		assert p.compares_fields(tree("tag=authentication"))
		assert not p.compares_fields(tree("error kerberos"))
		assert not p.compares_fields(tree("host::web01 error"))
		assert not p.compares_fields(tree("count>5"))


class TestTheProbe:

	def test_the_words_alone(self):
		assert p.lispy_probe("EventCode=4625 user=bob", "`txf`") == "search EventCode=4625 user=bob | head 1"
		assert p.lispy_probe(" tag=authentication ", "`tx`") == "search tag=authentication | head 1"

	def test_txf_of_a_sourcetype_names_it(self):
		assert p.lispy_probe("EventCode=4625", "`txf(XmlWinEventLog)`") == 'search sourcetype="XmlWinEventLog" EventCode=4625 | head 1'
		assert p.lispy_probe("x=1", '`txf(a"b)`') == 'search sourcetype="a\\"b" x=1 | head 1'

	def test_a_subsearch_is_never_run_by_the_probe(self):
		assert p.lispy_probe("user=[| inputlookup users | return user]", "`txf`") is None


class TestReadingTheLispy:

	def test_the_base_lispy_of_the_log(self):
		assert p.lispy_from_log(LOG) == "[ AND 4625 [ OR kerberos error ] ]"
		assert p.lispy_from_log("no such line\n") is None
		assert p.lispy_from_log(None) is None

	def test_lines_that_differ_are_not_read(self):
		# which one is the search's own is not known: nothing is narrowed on a guess
		two = LOG + "11-19-2026 10:00:00.400 INFO  UnifiedSearch [123 searchOrchestrator] - base lispy: [ AND 4625 ]\n"
		assert p.lispy_from_log(two) is None

	def test_terms_and_operators(self):
		assert p.lispy_tree("[ AND 4625 index::main ]") == ("text", "4625")
		assert p.lispy_tree("[ AND 4625 bob index::main sourcetype::xmlwineventlog ]") == ("and", [("text", "4625"), ("text", "bob")])
		assert p.lispy_tree("[ AND [ OR 4624 4625 ] index::main ]") == ("or", [("text", "4624"), ("text", "4625")])
		assert p.lispy_tree("4625") == ("text", "4625")

	def test_what_places_no_restriction(self):
		# an OR with an indexed term of a default field: a compact event has its own sourcetype, source, host and index
		assert p.lispy_tree("[ OR 4625 sourcetype::xmlwineventlog ]") == p.TRUE
		assert p.lispy_tree("[ OR 4625 index::main ]") == p.TRUE
		assert p.lispy_tree("[ OR 4625 host::web01 ]") == p.TRUE
		assert p.lispy_tree("[ OR 4625 tenx_sourcetype::x ]") == p.TRUE
		# an indexed term required alone, or an OR of indexed terms only: a compact event can get the field at
		# search time instead
		assert p.lispy_tree("[ AND dstip::10.1.2.3 ]") == p.TRUE
		assert p.lispy_tree("[ OR a::1 b::2 ]") == p.TRUE
		assert p.lispy_tree('[ OR "a::1" 4625 ]') == p.TRUE
		assert p.lispy_tree("[ AND index::main [ NOT 4625 ] ]") == p.TRUE
		assert p.lispy_tree('[ AND "a b" ]') == p.TRUE
		assert p.lispy_tree("[ AND a\\b ]") == p.TRUE
		assert p.lispy_tree("[ AND index::main ]") == p.TRUE
		assert p.lispy_tree("[ AND x[1] ]") == p.TRUE

	def test_an_indexed_alternative_beside_the_terms(self):
		# Splunk's default (limits.conf always_include_indexedfield_lispy = true) for dstip=10.1.2.30: the indexed
		# form OR the terms of the value. The OR was read as no restriction, so field_narrowing = splunk narrowed
		# no field comparison (Splunk Enterprise 10.4.3, FortiGate: every compact event read).
		lispy = "[ AND [ OR dstip::10.1.2.30 [ AND 10 1 2 30 ] ] ]"
		assert p.lispy_tree(lispy) == ("or", [("indexed", "dstip::10.1.2.30"),
											  ("and", [("text", "10"), ("text", "1"), ("text", "2"), ("text", "30")])])
		assert p.lispy_tree("[ AND 4625 [ OR eventcode::4625 4625 ] ]") == ("and", [
			("text", "4625"), ("or", [("indexed", "eventcode::4625"), ("text", "4625")])])

	def test_what_it_cannot_read_narrows_nothing(self):
		for bad in ("", None, "[ AND 4625", "[ AND 4625 ] ]", "]", "[ XOR a b ]", "[ AND a ] b", "["):
			assert p.lispy_tree(bad) is None, bad


class TestTheNarrowing:

	def test_a_field_comparison_narrows_by_its_index_terms(self):
		# off before: a field comparison placed no restriction
		assert as_words("EventCode=4625") is None
		assert narrowed("EventCode=4625", "[ AND 4625 index::main ]") == "((TERM(4625)))"

	def test_each_term_is_required_exactly_as_the_word(self):
		# the guarantees of word search carry over: the same clause as the term written after the macro
		cases = [
			("EventCode=4625", "[ AND 4625 ]", "4625"),
			("action=success user=bob", "[ AND success bob index::main ]", "success bob"),
			("EventCode IN (4624, 4625)", "[ AND [ OR 4624 4625 ] ]", "4624 OR 4625"),
			("tag=authentication", "[ AND [ OR kerberos error ] ]", "kerberos OR error"),
			("src=10.0.1.14", "[ AND 10.0.1.14 ]", "10.0.1.14"),
			("user=adm*", "[ AND adm* ]", "adm*"),
			("error EventCode=4625", "[ AND 4625 error ]", "4625 error"),
		]
		for text, lispy, words in cases:
			assert narrowed(text, lispy) == as_words(text, words), (text, lispy)
			assert narrowed(text, lispy) is not None

	def test_terms_a_timestamp_could_print_place_no_restriction(self):
		# 2023 is a year the stored formats print, so it never narrows, as a word does not
		assert narrowed("year=2023", "[ AND 2023 ]") is None

	def test_an_indexed_alternative_keeps_the_narrowing_of_the_terms(self):
		# the compact event holding the terms stays selected, and one carrying the indexed field (a field map,
		# fields sent with the event) is selected by it
		got = narrowed("user=kerberos", "[ AND [ OR user::kerberos kerberos ] ]")
		assert got == "((user::kerberos OR ((TERM(kerberos) OR TERM(~k1)))))"
		# a branch that places no restriction leaves the whole OR without one
		assert narrowed("year=2023", "[ AND [ OR year::2023 2023 ] ]") is None
		assert narrowed("user=kerberos", "[ AND [ OR sourcetype::x kerberos ] ]") is None

	def test_no_lispy_leaves_the_search_as_before(self):
		for text in ("EventCode=4625", "error action=success", "user IN (a, b) kerberos"):
			assert narrowed(text, None) == as_words(text)
			assert narrowed(text, "[ OR 4625 sourcetype::x ]") == as_words(text)

	def test_it_only_ever_adds_requirements(self):
		# every clause of the search without Splunk's terms is still in it: AND only narrows
		before = as_words("error action=success")
		after = narrowed("error action=success", "[ AND success ]")
		assert before == "(((TERM(error) OR TERM(~e1))))"
		assert after == "((((TERM(error) OR TERM(~e1)))) AND ((TERM(success) OR TERM(~s1) OR TERM(~s2))))"

	def test_the_terms_are_looked_up_in_the_dictionary(self):
		t = ("and", [tree("action=success"), p.lispy_tree("[ AND success 4625 ]")])
		assert p.lookup_pieces(t) == {"success"}
		assert p.digit_candidates(t) == {"4625"}


COMMAND = r'''
import json, os, sys, types

root, home, text, macro, log, fail = sys.argv[1:7]
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
import tenx_prefilter

cmd = tenx_prefilter.TenxPrefilterCommand()
cmd.before = ('index=wineventlog ', macro)
cmd.parent_app = 'search'
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	username='u', splunkd_uri='https://127.0.0.1:8089', session_key='k', earliest_time='0', latest_time='now'))
calls = []
def rest(path, data=None, answer=True, method=None):
	calls.append([path, data, answer, method])
	if fail == 'post' and data:
		raise RuntimeError('refused')
	if path.endswith('/search/jobs'):
		return {'sid': 'probe_1'}
	if path.endswith('/search.log'):
		return log
	return None
cmd._rest = rest
terms = cmd._splunk_terms(text)
print(json.dumps({'terms': terms, 'calls': calls}))
'''


class TestTheCommand:

	def run(self, text, macro='`txf`', log=LOG, fail=''):
		import json
		import subprocess
		import sys
		import tempfile
		with tempfile.TemporaryDirectory() as home:
			proc = subprocess.run([sys.executable, '-c', COMMAND, ROOT, home, text, macro, log, fail],
								  capture_output=True, text=True, timeout=60)
		assert proc.returncode == 0, proc.stderr[-3000:]
		return json.loads(proc.stdout.strip().splitlines()[-1])

	def test_one_probe_in_the_searchs_app_over_no_event_then_removed(self):
		out = self.run('EventCode=4625', macro='`txf(XmlWinEventLog)`')
		post, read, delete = out['calls']
		assert post[0] == '/servicesNS/u/search/search/jobs'
		assert post[1] == {'search': 'search sourcetype="XmlWinEventLog" EventCode=4625 | head 1', 'exec_mode': 'blocking',
						   'earliest_time': '1', 'latest_time': '2', 'output_mode': 'json'}
		assert read[0] == '/services/search/jobs/probe_1/search.log' and read[2] == 'text'
		assert delete[0] == '/services/search/jobs/probe_1' and delete[3] == 'DELETE'
		assert out['terms'] == ['and', [['text', '4625'], ['or', [['text', 'kerberos'], ['text', 'error']]]]]

	def test_a_failed_probe_narrows_nothing(self):
		assert self.run('EventCode=4625', fail='post')['terms'] is None
		assert self.run('EventCode=4625', log='no lispy here')['terms'] is None

	def test_a_subsearch_starts_no_probe(self):
		out = self.run('user=[| inputlookup users | return user]')
		assert out == {'terms': None, 'calls': []}


GENERATE = r"""
import json, os, sys, types

root, home, text, mode, terms = sys.argv[1:6]
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
import tenx_prefilter
tenx_prefilter.parser.narrowing_mode_on_disk = lambda home: mode

cmd = tenx_prefilter.TenxPrefilterCommand()
warnings, probes, looked = [], [], []
cmd._store_check = lambda: True
cmd._search_text = lambda: text
cmd._store_plans = lambda t: None
cmd._original_sourcetype_rows = lambda tree: ([], '`txf`')
cmd._record_checks = lambda macro: None
cmd._text_field = lambda: None
def splunk_terms(t):
	probes.append(t)
	return None if terms == 'none' else tenx_prefilter.parser.lispy_tree(terms)
cmd._splunk_terms = splunk_terms
def dictionary(pieces, formats):
	looked.append(sorted(pieces))
	return dict((x, (1, ['TERM(~h_%s)' % x])) for x in pieces), None
cmd._dictionary = dictionary
# the word index check (_without_words) found every compact event indexed with its words
cmd._without_words = lambda prefilter: prefilter
cmd.write_warning = warnings.append
out = list(cmd.generate())
print(json.dumps({'out': out, 'warnings': warnings, 'probes': probes, 'looked': looked}))
"""


class TestTheSearch:
	"""What tenxprefilter does with the setting, the probe's answer and the words."""

	def run(self, text, mode, terms):
		import json
		import subprocess
		import sys
		import tempfile
		with tempfile.TemporaryDirectory() as home:
			proc = subprocess.run([sys.executable, '-c', GENERATE, ROOT, home, text, mode, terms],
								  capture_output=True, text=True, timeout=60)
		assert proc.returncode == 0, proc.stderr[-3000:]
		return json.loads(proc.stdout.strip().splitlines()[-1])

	def test_off_runs_no_probe_and_narrows_nothing(self):
		out = self.run('EventCode=4625', 'off', '[ AND 4625 ]')
		assert out['probes'] == [] and out['warnings'] == [] and out['out'] == [{'search': '(*)'}]

	def test_splunk_narrows_by_the_terms_it_read(self):
		out = self.run('EventCode=4625 kerberos', 'splunk', '[ AND alice ]')
		assert out['probes'] == ['EventCode=4625 kerberos'] and out['warnings'] == []
		assert out['looked'] == [['alice', 'kerberos']]
		assert 'TERM(alice)' in out['out'][0]['search'] and 'TERM(kerberos)' in out['out'][0]['search']

	def test_terms_it_cannot_read_narrow_nothing_and_the_search_says_so(self):
		out = self.run('EventCode=4625 kerberos', 'splunk', 'none')
		assert out['warnings'] == [p.SPLUNK_TERMS_UNREAD] and len(p.SPLUNK_TERMS_UNREAD) <= 256
		# the search is narrowed by its words alone, as with field_narrowing = false
		assert out['looked'] == [['kerberos']] and out['out'] == [{'search': '(((TERM(kerberos) OR TERM(~h_kerberos))))'}]
		assert self.run('EventCode=4625 kerberos', 'off', 'none')['out'] == out['out']

	def test_terms_that_require_nothing_narrow_nothing_without_a_warning(self):
		out = self.run('EventCode=4625', 'splunk', '[ AND index::main ]')
		assert out['warnings'] == [] and out['out'] == [{'search': '(*)'}]
