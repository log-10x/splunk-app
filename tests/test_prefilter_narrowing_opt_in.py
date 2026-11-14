"""
Field narrowing is opt-in (tenx_config.conf [config] field_narrowing, default false). Off, the
prefilter must be exactly the one of the parser without field narrowing: compared here against a
copy of that parser (tests/support/tenx_prefilter_parser_baseline.py) on a set of searches. On,
pieces the compact event stores in another written form (FORMAT_SPEC.md S2.2, S4.4) are not used.
"""
import json
import os
import subprocess
import sys
import tempfile

import tenx_prefilter_parser as new
import tenx_replay_builder as b
from support import tenx_prefilter_parser_address_rule as address_rule
from support import tenx_prefilter_parser_baseline as baseline

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

SEARCHES = [
	'', 'error', '"payment failed"', 'error OR warn', 'NOT bootstrap', 'error NOT retry', '(error OR warn) kafka',
	'user=bob', 'user="bob smith"', 'EventCode=4663', 'EventCode IN (4624, 4625, 4663)', 'status!=200', 'kb>500',
	'action=success tag=authentication', 'src=10.0.1.14', '10.0.1.14', '192.168.100.200', 'TERM(10.0.1.14)',
	'CASE(Error)', 'conn* refused', '*fail*', 'a* b', 'user=WIN-*', 'object_file_name=*.json',
	'process_name="C:\\\\Windows\\\\explorer.exe"', 'ts="2026-11-13 08:00:00.123"', '"08:00:00.123"', '2026-11-13',
	'c129-4320', 'earliest=-1h error', 'error [search index=x | head 1]', 'Event.System.EventID=4663',
	'"quote \\" inside"', 'café', 'x=1, y=2', 'error, retry', 'AND error', 'error AND', '(error', 'NOT',
	'kubernetes.container_name=accounting', 'msg="from lookup: login"', 'a OR b c OR d', 'NOT NOT x',
	'user.name=bob', 'chain_end=*', 'Error_Code=* NOT Error_Code="-"', '"User Data"', 'x IN ("a,b", c)',
]


def parse_both(text):
	out = []
	for mod in (baseline, new):
		try:
			reader = mod.Parser(mod.tokenize(text))
			tree = reader.parse()
			out.append((tree, reader.time_modifier, reader.unquoted_comma, None))
		except mod.Unparsed as e:
			out.append((None, None, None, str(e)))
	return out


def dictionary(pieces):
	"""Every piece is carried by two templates, except one carried by too many."""
	return dict((p, (6000 if p == 'kafka' else 2, ['TERM(~t1%s)' % p, 'TERM(~t2%s)' % p])) for p in pieces)


def has_address(text):
	return bool(new.addresses_of(text))


class TestOffMatchesTheBaseline:
	"""
	Off, the prefilter is the baseline parser's, except that an IPv4 address requires its parts:
	equal to the baseline on every search without an address, and equal to the parser with the
	address rule and no opt-in setting (tests/support/tenx_prefilter_parser_address_rule.py, no
	narrowing list) on every search.
	"""

	def test_the_prefilter_is_the_baselines_on_every_search_without_an_address(self):
		checked = 0
		for text in SEARCHES:
			if has_address(text):
				continue
			checked += 1
			(old_tree, old_tm, old_comma, old_err), (new_tree, new_tm, new_comma, new_err) = parse_both(text)
			assert (old_tm, old_comma, old_err) == (new_tm, new_comma, new_err), text
			if old_tree is None:
				continue
			old_pieces, new_pieces = baseline.lookup_pieces(old_tree), new.lookup_pieces(new_tree, text_field=None)
			assert old_pieces == new_pieces, text
			d = dictionary(old_pieces)
			assert baseline.prefilter(old_tree, d) == new.prefilter(new_tree, d, None), text
			if old_pieces:
				assert baseline.dictionary_search(old_pieces) == new.dictionary_search(new_pieces), text
		assert checked == len(SEARCHES) - 4

	def test_the_prefilter_is_the_address_rules_on_every_search(self):
		for text in SEARCHES + ['10.0.1.14:8443', 'kafka 10.0.1.14', '1.2.3.4', '10.0.1.14 OR 0.0.0.0']:
			try:
				ref = address_rule.Parser(address_rule.tokenize(text)).parse()
			except address_rule.Unparsed:
				continue
			tree = new.Parser(new.tokenize(text)).parse()
			pieces = address_rule.lookup_pieces(ref)
			assert pieces == new.lookup_pieces(tree, text_field=None), text
			d = dictionary(pieces)
			assert address_rule.prefilter(ref, d) == new.prefilter(tree, d, None), text

	def test_text_after_the_macro_is_the_baselines(self):
		for text in SEARCHES:
			search = 'index=x `tx` %s | stats count' % text
			assert baseline.text_after_macro(search) == new.text_after_macro(search), text

	def test_the_setting(self):
		assert not new.narrowing_on({}) and not new.narrowing_on({'field_narrowing': 'false'})
		assert not new.narrowing_on(None) and not new.narrowing_on({'field_narrowing': '0'})
		assert new.narrowing_on({'field_narrowing': 'true'}) and new.narrowing_on({'field_narrowing': '1'})


class TestTheListIsWrittenOnlyWhenWanted:
	def test_off_or_without_a_carrier_no_list(self):
		with_carrier = b.build([b.Stanza('st', {'EVAL-x': '1'}, {})], [('st', 's', 'h')])
		without = b.build([], [])
		assert not b.narrowing_wanted({}, with_carrier)
		assert not b.narrowing_wanted({'field_narrowing': 'false'}, with_carrier)
		assert not b.narrowing_wanted({'field_narrowing': 'true'}, without)
		assert b.narrowing_wanted({'field_narrowing': 'true'}, with_carrier)


def narrowed(text):
	reader = new.Parser(new.tokenize(text))
	tree = reader.parse()
	return new.prefilter(tree, dictionary(new.lookup_pieces(tree, text_field=new.text_field_predicate([]))),
						 new.text_field_predicate([])) or ''


class TestOnSkipsOtherWrittenForms:
	def test_digits_of_rendered_timestamps(self):
		for text, digits in (
				('ts="2026-11-13 08:00:00.123"', '123'), ('ts="2026-11-13T08:00:00.123456+00:00"', '123456'),
				('"20:11:46:346"', '346'), ('stamp=20261113080000', '20261113080000'), ('t=080000123', '080000123'),
				('epoch=1763020800.123456', '123456'), ('ns=1763020800123456789', '1763020800123456789'),
				('"13.11.2026"', '2026'), ('zone="+0000"', '0000'), ('"08:00 -0400"', '0400')):
			assert 'TERM(%s)' % digits not in narrowed(text), text

	def test_digits_kept_with_the_sign(self):
		# FORMAT_SPEC S2.2: c129-4320 is stored as the values c129 and -4320
		got = narrowed('c129-4320')
		assert 'TERM(c129)' in got and 'TERM(4320)' not in got

	def test_ordinary_words_and_values_still_narrow(self):
		assert 'TERM(error)' in narrowed('error') and 'TERM(4663)' in narrowed('EventCode=4663')
		assert 'TERM(reed)' in narrowed('user=REED_LARSEN') and 'TERM(0x80)' in narrowed('AccessMask=0x80')
		assert 'TERM(192)' in narrowed('src=192.168.100.200')


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

import tenx_prefilter

# The setting is read from the app's tenx_config.conf files on disk, not over REST, so with
# narrowing off the command makes no REST call for it. `config` is the local file's content
# (None: no local file, and no default file either: unreadable).
import tempfile, shutil

def run(config, narrowing, default=True):
	app = tempfile.mkdtemp()
	os.makedirs(os.path.join(app, 'default')); os.makedirs(os.path.join(app, 'local'))
	if default:
		shutil.copy(os.path.join(root, 'tenx-for-splunk', 'default', 'tenx_config.conf'), os.path.join(app, 'default'))
	if config is not None:
		with open(os.path.join(app, 'local', 'tenx_config.conf'), 'w') as f:
			f.write('[config]\n' + ''.join('%s = %s\n' % kv for kv in config.items()))
	tenx_prefilter.apphome = app
	cmd = tenx_prefilter.TenxPrefilterCommand()
	paths = []
	def rest(path, data=None):
		paths.append(path.split('?')[0])
		if narrowing is None:
			raise IOError('no stanza')
		return {'entry': [{'content': {'fields_not_in_text': narrowing}}]}
	cmd._rest = rest
	pred = cmd._text_field()
	shutil.rmtree(app)
	return {'paths': paths, 'pred': None if pred is None else [pred('user'), pred('action')]}

print(json.dumps({
	'default': run({}, 'action'),
	'off': run({'field_narrowing': 'false'}, 'action'),
	'unreadable': run(None, 'action', default=False),
	'on_no_list': run({'field_narrowing': 'true'}, None),
	'on': run({'field_narrowing': 'true'}, 'action'),
}))
'''


def test_the_command_reads_the_setting_before_anything_else():
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', CHILD, ROOT, home], capture_output=True, text=True, timeout=60)
	assert proc.returncode == 0, proc.stderr
	out = json.loads(proc.stdout.strip().splitlines()[-1])
	narrowing = '/servicesNS/nobody/tenx-for-splunk/configs/conf-tenx_replay/tenx%3Anarrowing'
	# off, by default or unreadable: no REST call at all; on: only the list's
	for case in ('default', 'off', 'unreadable'):
		assert out[case] == {'paths': [], 'pred': None}, case
	assert out['on_no_list'] == {'paths': [narrowing], 'pred': None}
	assert out['on'] == {'paths': [narrowing], 'pred': [True, False]}
