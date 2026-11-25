"""
Compact events indexed under their original sourcetype (transforms.conf [tenx-original-sourcetype]).

The parsing tier renames a compact event to the first value of tenx_sourcetype once the rules of
tenx_encoded have parsed it. The app then finds it by that indexed field, reads its template hash from
_raw, and holds its indexed fields aside around the extraction of `tx` and `txf`, so that a field both
attached and in the text is not counted twice. Splunk is modelled as in the other tests
(tests/support/spl_model.py); the stand-in for `extract` adds each value it finds to a field that
exists already, as Splunk did for the field-reader route's attached fields (Splunk Enterprise 10.4.3).
"""
import configparser
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile

import pytest

import tenx_replay_builder as b
from support.spl_model import Model, visible
from tenx_kv_intf import TenxKVInterface
from test_replay_indexed_per_sourcetype import STANZAS, LOOKUP_FIELDS, model as replay_model, txf_steps

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
APP = os.path.join(ROOT, 'tenx-for-splunk')
RULE = 'tenx-original-sourcetype'


def conf(name):
	parser = configparser.RawConfigParser(strict=False, interpolation=None)
	parser.optionxform = str
	parser.read(os.path.join(APP, 'default', name))
	return parser


def macro(name):
	return conf('macros.conf').get(name, 'definition')


class TestTheRule:
	def test_nothing_calls_it_as_shipped(self):
		props = conf('props.conf')
		assert not [(s, k) for s in props.sections() for k, v in props.items(s) if RULE in v]

	def test_its_class_runs_after_the_unwrap_and_the_event_time(self):
		text = open(os.path.join(APP, 'default', 'transforms.conf'), encoding='utf-8').read()
		assert '#     TRANSFORMS-tenx_type = %s\n' % RULE in text
		assert sorted(['00_tenx_unwrap', 'tenx_time', 'tenx_type'])[-1] == 'tenx_type'

	def test_only_functions_index_time_eval_takes(self):
		assert set(re.findall(r'([a-z_]+)\(', conf('transforms.conf').get(RULE, 'INGEST_EVAL'))) == {'if', 'len', 'mvindex'}

	@pytest.mark.parametrize('carried, sourcetype', [
		('fortigate_traffic', 'fortigate_traffic'),
		(['XmlWinEventLog', 'other'], 'XmlWinEventLog'),
		(None, 'tenx_encoded'),
		('', 'tenx_encoded'),
	])
	def test_the_rule_on_an_event(self, carried, sourcetype):
		event = {'_raw': '~h,1', 'sourcetype': 'tenx_encoded'}
		if carried is not None:
			event['tenx_sourcetype'] = carried
		Model().run('eval ' + conf('transforms.conf').get(RULE, 'INGEST_EVAL'), [event])
		assert event['sourcetype'] == sourcetype and event['_raw'] == '~h,1'


def selects(definition, event):
	"""Whether the indexed-field terms of `definition`, ORed, select `event` (the model of a term is fnmatch)."""
	terms = re.findall(r'(\w+)::(\S+?)\)?(?=\s|$)', definition)
	return any(fnmatch.fnmatchcase(str(event.get(k, '')), v) and k in event for k, v in terms)


class TestTheMarker:
	def test_compact_events_are_found_by_indexed_fields_alone(self):
		definition = macro('tenx-events')
		assert definition == 'index=* (sourcetype::tenx_encoded OR tenx_sourcetype::*)'
		# no field=value term, which Splunk would check against the text of every event it reads
		assert '=' not in definition.replace('index=*', '')

	@pytest.mark.parametrize('event, found', [
		({'sourcetype': 'tenx_encoded'}, True),
		({'sourcetype': 'tenx_encoded', 'tenx_sourcetype': 'XmlWinEventLog'}, True),
		({'sourcetype': 'fortigate_traffic', 'tenx_sourcetype': 'fortigate_traffic'}, True),
		({'sourcetype': 'fortigate_traffic'}, False),
		({'sourcetype': 'tenx_dml_raw_json'}, False),
	])
	def test_what_it_selects(self, event, found):
		assert selects(macro('tenx-events'), event) is found

	def test_every_search_of_compact_events_reads_it(self):
		for name in ('tx', 'txf', 'txf(1)'):
			assert '((`tenx-events`) OR (`tenx-raw-events`))' in macro(name), name


def hash_step(name):
	"""The step of an inflate macro that reads the hash: eval tenx_hash=if(isnull(tenx_hash) AND match(_raw, A), ...)."""
	step = [s for s in macro(name).split(' | ') if s.startswith('eval tenx_hash=')]
	assert len(step) == 1, name
	strings = re.findall(r'"((?:[^"\\]|\\.)*)"', step[0])
	return step[0], strings[0], strings[1]


def hash_of(raw, extracted=None, name='tenx-inflate'):
	"""The hash the step gives, as eval runs it: the extraction's value if there is one, else the text's, trimmed."""
	if extracted is not None:
		return extracted
	_, match, pattern = hash_step(name)
	if not re.search(match, raw):
		return None
	return re.sub(pattern, lambda m: m.group(1), raw, count=1).strip() or None


def extraction(raw):
	"""transforms.conf [tenx-hash-vars-extraction] as Splunk writes tenx_hash: trimmed, absent when empty."""
	regex = conf('transforms.conf').get('tenx-hash-vars-extraction', 'REGEX').replace('(?<', '(?P<')
	m = re.match(regex, raw)
	value = m.group('tenx_hash') if m else None
	return value.strip() if value and value.strip() else None


RAWS = ['~-Kw0UHgdH_9,127,0,1', '~ab c,1794013200448,x', '~#Q a ,1,2', '~h', '~h,1\r\nnext line', '~,x', ' ~h,1',
		'plain text, with a comma', '<Event>~h,1</Event>']


class TestTheHashFromTheText:
	@pytest.mark.parametrize('name', ['tenx-inflate', 'tenx-inflate-debug'])
	def test_both_macros_read_it_before_the_lookup(self, name):
		steps = macro(name).split(' | ')
		at = [i for i, s in enumerate(steps) if s.startswith('eval tenx_hash=')]
		assert len(at) == 1 and steps[at[0] + 1].startswith('lookup tenx-dml-lookup _key AS tenx_hash ')

	@pytest.mark.parametrize('raw', RAWS)
	def test_without_the_extraction_it_is_the_extractions_value(self, raw):
		# an event of the original sourcetype, whose props carry no REPORT-tenx
		assert hash_of(raw) == extraction(raw)

	@pytest.mark.parametrize('raw', RAWS)
	def test_it_is_the_key_the_template_is_stored_under(self, raw):
		value = hash_of(raw)
		if value is not None:
			assert TenxKVInterface.kv_key(None, raw[1:].split(',', 1)[0]) == value

	def test_the_extractions_value_is_kept(self):
		assert hash_of('~a,1', extracted='a') == 'a'
		step = hash_step('tenx-inflate')[0]
		assert step.startswith('eval tenx_hash=if(isnull(tenx_hash) AND ') and step.endswith(', tenx_hash)')


# ---------------------------------------------------------------------------
# No double count
# ---------------------------------------------------------------------------

def adding_extract(event, _):
	"""Splunk's extract: nothing on a hidden event, else each field of the test's __text added to what exists."""
	if not event.get('_raw') or event.get('sourcetype') in ('tenx_none', b.PLACEHOLDER) or event.get('_kv'):
		return
	for k, v in event.get('__text', {}).items():
		if k in event:
			have = event[k] if isinstance(event[k], list) else [event[k]]
			event[k] = have + [v]
		else:
			event[k] = v


def guard_macros():
	return dict((n, macro(n)) for n in ('tenx-whole-hide', 'tenx-whole-restore'))


def tx_steps():
	d = macro('tx')
	head, tail = '((`tenx-events`) OR (`tenx-raw-events`)) [| tenxprefilter] | ', ' | search *'
	assert d.startswith(head) and d.endswith(tail)
	return d[len(head):-len(tail)]


def inflate(event, _):
	"""tenx-inflate on a compact event: its text, and the lookup's empty tenx_expand_refused or the test's reason."""
	if event['_raw'].startswith('~'):
		event['tenx_expand_refused'] = event.get('__refused', '')
		event['_raw'] = event.get('__exp', event['_raw'])


def run_tx(events, extract_definition):
	m = Model(commands={'extract': adding_extract, 'inflatemodel': inflate},
			  macros=dict({'tenx-inflate': 'inflatemodel', 'tenx-extract': extract_definition}, **guard_macros()))
	return [visible(e) for e in m.run(tx_steps(), events)]


def renamed(**more):
	"""A FortiGate compact event indexed under its original sourcetype, with the Receiver's fields and a sender's."""
	e = {'_raw': '~f,10.1.2.3,deny', '__exp': 'srcip=10.1.2.3 action=deny', 'sourcetype': 'fortigate_traffic',
		 'tenx_sourcetype': 'fortigate_traffic', 'source': 'fgt', 'host': 'fw1', '_kv': 1,
		 'srcip': '10.1.2.3', 'action': 'deny', 'k8s_ns': 'edge', '__text': {'srcip': '10.1.2.3', 'action': 'deny'}}
	e.update(more)
	return e


ATTACHED = ['srcip', 'action', 'k8s_ns', 'host', 'tenx_sourcetype']


class TestTxCountsAnAttachedFieldOnce:
	def test_the_shipped_extraction_adds_the_text_value_to_the_indexed_one(self):
		out = run_tx([renamed()], macro('tenx-extract'))
		assert out[0]['srcip'] == ['10.1.2.3', '10.1.2.3']

	def test_held_aside_each_field_has_the_value_of_the_text(self):
		out = run_tx([renamed()], b.tx_extract(ATTACHED))
		assert (out[0]['srcip'], out[0]['action']) == ('10.1.2.3', 'deny')
		# a field only its sender indexed comes back, and the app's working fields are gone
		assert out[0]['k8s_ns'] == 'edge' and out[0]['host'] == 'fw1'
		assert not [k for k in out[0] if k.startswith(b.HELD)]
		assert out[0]['_raw'] == 'srcip=10.1.2.3 action=deny'

	def test_a_value_the_text_holds_otherwise_is_the_texts(self):
		# compactFieldsDecode true writes an XML entity decoded; the add-on's extraction of the text keeps it
		e = renamed(srcip='a&b', __text={'srcip': 'a&amp;b'})
		assert run_tx([e], b.tx_extract(ATTACHED))[0]['srcip'] == 'a&amp;b'

	def test_an_event_sent_whole_keeps_the_fields_it_was_read_with(self):
		whole = {'_raw': 'srcip=10.9.9.9 action=accept', 'sourcetype': 'fortigate_traffic', 'source': 'fgt',
				 'host': 'fw1', '_kv': 1, 'tenx_sourcetype': 'fortigate_traffic', 'srcip': '10.9.9.9',
				 'action': 'accept', '__text': {'srcip': '10.9.9.9', 'action': 'accept'}}
		out = run_tx([dict(whole)], b.tx_extract(ATTACHED))
		assert (out[0]['srcip'], out[0]['action'], out[0]['_raw']) == ('10.9.9.9', 'accept', whole['_raw'])

	def test_an_event_left_compact_is_not_held(self):
		# what the extraction finds in compact text is added as `tx` always added it; the indexed value stays
		e = renamed(__refused='no-template', __exp='~f,10.1.2.3,deny', __text={'srcip': 'other'})
		out = run_tx([e], b.tx_extract(ATTACHED))
		assert out[0]['srcip'] == ['10.1.2.3', 'other'] and out[0]['tenx_expand_refused'] == 'no-template'

	def test_only_fields_eval_can_write_and_none_of_splunks_own_are_held(self):
		assert b.held_names(['host', 'source', 'sourcetype', 'index', 'linecount', 'punct', 'date_hour', '_time',
							 'tenx_sourcetype', 'eventtype', 'tag', 'srcip', 'kubernetes.container_name', 'a{}.b',
							 "it's"]) == ['a{}.b', "it's", 'kubernetes.container_name', 'srcip']
		text = b.tx_extract(['srcip', 'kubernetes.container_name', 'a{}.b', "it's", 'Account Name'])
		assert 'foreach kubernetes.container_name srcip [eval ' in text
		assert '"Account Name"=if(isnotnull(tenx_ih), null(), \'Account Name\')' in text
		assert 'a{}.b' not in text and "it's" not in text

	def test_without_indexed_fields_it_is_the_shipped_extraction(self):
		assert b.tx_extract([]) == macro('tenx-extract') == 'extract'
		assert b.tx_extract(['host', 'tenx_time']) == 'extract'


def txf_event(**more):
	e = renamed(**more)
	e['__by_st'] = {'fortigate_traffic': e.pop('__text')}
	return e


def run_txf(events, by_st):
	present = [('fortigate_traffic', 'fgt', 'fw1')]
	full = b.build(STANZAS, present, LOOKUP_FIELDS, (), keep_by_sourcetype=by_st).spl()
	return [visible(e) for e in replay_model(full).run(txf_steps('`tenx-replay`'), events)]


class TestTxfCountsAnAttachedFieldOnce:
	def test_the_replay_holds_the_indexed_fields_around_its_extraction(self):
		out = run_txf([txf_event()], {'fortigate_traffic': ['srcip', 'action', 'k8s_ns']})
		assert (out[0]['srcip'], out[0]['action'], out[0]['k8s_ns']) == ('10.1.2.3', 'deny', 'edge')
		assert out[0]['sourcetype'] == 'fortigate_traffic'
		assert not [k for k in out[0] if k.startswith(b.HELD)]

	def test_without_the_hold_the_value_is_there_twice(self):
		full = b.build(STANZAS, [('fortigate_traffic', 'fgt', 'fw1')], LOOKUP_FIELDS, (),
					   keep_by_sourcetype={'fortigate_traffic': ['srcip', 'action', 'k8s_ns']}).spl()
		hold = b.held_steps(['action', 'k8s_ns', 'srcip'], 'isnotnull(%s)' % b.RST)
		assert hold[0] and b.block(b.ANY, hold[0]) in full and b.block(b.ANY, hold[1]) in full
		unheld = full.replace(' | ' + b.block(b.ANY, hold[0]), '').replace(' | ' + b.block(b.ANY, hold[1]), '')
		out = [visible(e) for e in replay_model(unheld).run(txf_steps('`tenx-replay`'), [txf_event()])]
		assert out[0]['srcip'] == ['10.1.2.3', '10.1.2.3']

	def test_the_shipped_replay_holds_nothing(self):
		assert b.HELD not in ' | '.join(b.UNCHANGED)


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

import tenxreplay

stored = {'tenx-extract': 'extract'}
calls = []

def rest(path, data=None, method=None):
	calls.append((path, data))
	if path.endswith('/configs/conf-macros/tenx-extract'):
		if data is not None:
			stored['tenx-extract'] = data['definition']
			return {}
		return {'entry': [{'content': {'definition': stored['tenx-extract']}}]}
	raise AssertionError(path)

cmd = tenxreplay.TenxReplayCommand()
cmd._rest = rest
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	username='splunk-system-user', splunkd_uri='https://127.0.0.1:8089', session_key='key'))
errors = {'value': None}
runs = []
cmd._dry_run = lambda spl: runs.append(spl) or errors['value']
out = {}
definition = tenxreplay.builder.tx_extract(['srcip', 'action'])
out['first'] = cmd._write_tx_extract(definition)
out['stored'] = stored['tenx-extract']
out['again'] = cmd._write_tx_extract(definition)
errors['value'] = 'Error in eval'
out['refused'] = cmd._write_tx_extract('extract')
out['kept'] = stored['tenx-extract']
out['runs'] = runs
print(json.dumps(out))
'''


def test_the_command_writes_the_extraction_once_and_only_when_it_runs():
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', CHILD, ROOT, home], capture_output=True, text=True, timeout=60)
	assert proc.returncode == 0, proc.stderr[-3000:]
	out = json.loads(proc.stdout.strip().splitlines()[-1])
	definition = b.tx_extract(['srcip', 'action'])
	assert out['first'] == ['tenx-extract'] and out['stored'] == definition
	assert out['again'] == []
	assert out['refused'] == [] and out['kept'] == definition
	assert out['runs'] == ['| makeresults | eval _raw="x" | %s | stats count' % d for d in (definition, 'extract')]


# ---------------------------------------------------------------------------
# After expansion, a field the original sourcetype computes keeps the value the search gave it, and every
# other field the compact event carries holds the values of the expanded text once.
# ---------------------------------------------------------------------------

def computed_event(**more):
	"""A renamed FortiGate event as the search read it: the add-on set action from the attached vendor value."""
	return renamed(action='blocked', **more)


class TestTxKeepsWhatTheSourcetypeComputed:
	def test_a_computed_field_keeps_the_value_the_search_gave_it(self):
		out = run_tx([computed_event()], b.tx_extract(ATTACHED, computed=['action', 'vendor_action']))
		assert (out[0]['action'], out[0]['srcip']) == ('blocked', '10.1.2.3')
		assert not [k for k in out[0] if k.startswith(('tenx_ih', 'tenx_ic', 'tenx_io'))]

	def test_held_as_any_other_field_it_takes_the_vendor_value_of_the_text(self):
		out = run_tx([computed_event()], b.tx_extract(ATTACHED))
		assert out[0]['action'] == 'deny'

	def test_without_a_value_before_it_takes_the_texts(self):
		e = computed_event()
		del e['action']
		assert run_tx([e], b.tx_extract(ATTACHED, computed=['action']))[0]['action'] == 'deny'

	def test_an_event_read_as_the_compact_sourcetype_takes_the_texts(self):
		# no add-on rule ran when Splunk read it, so its value is the attached one
		e = renamed(sourcetype='tenx_encoded', __text={'srcip': '10.1.2.3', 'action': 'deny-text'})
		assert run_tx([e], b.tx_extract(ATTACHED, computed=['action']))[0]['action'] == 'deny-text'

	def test_a_computed_field_no_compact_event_carries_is_not_held(self):
		assert 'vendor_action' not in b.tx_extract(ATTACHED, computed=['vendor_action'])


class TestTxHoldsEveryAttachedName:
	NAMES = ['srcip', 'kubernetes.container_name', 'Account Name', 'action']

	def test_the_names_a_definition_holds_are_read_back(self):
		assert b.tx_extract_names(b.tx_extract(self.NAMES, computed=['action'])) == sorted(self.NAMES)
		assert b.tx_extract_names(b.tx_extract(self.NAMES)) == sorted(self.NAMES)
		assert b.tx_extract_names('extract') == [] and b.tx_extract_names(None) == []

	def test_each_plain_name_costs_its_own_length(self):
		names = ['Field%02d_name' % n for n in range(92)]
		fixed = len(b.tx_extract(['a']))
		assert len(b.tx_extract(names)) - fixed == sum(len(n) + 1 for n in names) - 2

	def test_every_attached_name_comes_back_once(self):
		attached = dict(('f%d' % n, 'v%d' % n) for n in range(60))
		e = renamed(**attached)
		e['__text'] = dict(attached, srcip='10.1.2.3', action='deny')
		out = run_tx([e], b.tx_extract(list(attached) + ATTACHED))
		assert all(out[0]['f%d' % n] == 'v%d' % n for n in range(60))


class TestAValueExtractFindsTwiceIsCountedOnce:
	"""Two rules of the event's sourcetype and source read the same field from the text, and `extract` adds a value
	for each: the field the Receiver attached once comes back once."""

	def test_through_tx(self):
		e = renamed(EventCode='1', __text={'srcip': '10.1.2.3', 'action': 'deny', 'EventCode': ['1', '1']})
		out = run_tx([e], b.tx_extract(ATTACHED + ['EventCode']))
		assert (out[0]['EventCode'], out[0]['srcip']) == ('1', '10.1.2.3')
		assert not [k for k in out[0] if k.startswith(b.HELD)]
		# a value the attached ones lack, as many or fewer values, or none attached: what `extract` found
		for held, found in (('1', ['1', '2']), ('1', ['2', '2']), (['1', '1'], '1'), (['1', '2'], ['2', '1']), (None, ['1', '1'])):
			e = renamed(__text={'EventCode': found})
			if held is not None:
				e['EventCode'] = held
			assert run_tx([e], b.tx_extract(ATTACHED + ['EventCode']))[0]['EventCode'] == found, (held, found)

	def test_through_txf(self):
		e = txf_event(EventCode='1', __text={'srcip': '10.1.2.3', 'action': 'deny', 'EventCode': ['1', '1']})
		out = run_txf([e], {'fortigate_traffic': ['srcip', 'action', 'k8s_ns', 'EventCode']})
		assert (out[0]['EventCode'], out[0]['srcip']) == ('1', '10.1.2.3')
		assert not [k for k in out[0] if k.startswith(b.HELD)]


class TestAValueExtractJoinsIsAPlainValue:
	"""`extract` can return the values two rules find as one value with a line break between them ("1\n1"):
	the field comes back as the attached value, one plain value that a field=value term matches."""

	def test_through_tx(self):
		e = renamed(EventCode='1', __text={'srcip': '10.1.2.3', 'action': 'deny', 'EventCode': '1\n1'})
		out = run_tx([e], b.tx_extract(ATTACHED + ['EventCode']))
		assert out[0]['EventCode'] == '1'
		assert not [k for k in out[0] if k.startswith(b.HELD)]

	def test_through_txf(self):
		e = txf_event(EventCode='1', __text={'srcip': '10.1.2.3', 'action': 'deny', 'EventCode': '1\n1'})
		out = run_txf([e], {'fortigate_traffic': ['srcip', 'action', 'k8s_ns', 'EventCode']})
		assert out[0]['EventCode'] == '1'

	def test_a_value_of_several_lines_is_the_texts(self):
		for held, found in (('a\nb', 'a\nb'), ('a', 'a\nb'), ('a\nb', 'a\nb\nc')):
			e = renamed(EventCode=held, __text={'EventCode': found})
			assert run_tx([e], b.tx_extract(ATTACHED + ['EventCode']))[0]['EventCode'] == found, (held, found)


# ---------------------------------------------------------------------------
# Splunk ran the original sourcetype's aliases, calculated fields and lookups when it read the compact event,
# from its attached fields. Through `txf` each rule sees what it sees on the raw event: an alias or a calculated
# field never reads what a lookup wrote.
# ---------------------------------------------------------------------------

READ_TABLES = {'tasks': [{'Task': '12544', 'TaskCategory': 'Logon'}],
			   'protos': [{'proto': '6', 'transport': 'tcp', 'protocol': 'ip'}]}
READ_LOOKUP_FIELDS = {'tasks': ['Task', 'TaskCategory'], 'protos': ['proto', 'transport', 'protocol']}


def read_stanzas(mode):
	return [b.Stanza('default', {}, {}),
			b.Stanza('tenx_encoded', {'REPORT-tenx': 'tenx-hash-vars-extraction'}, {}),
			b.Stanza('XmlWinEventLog', {'FIELDALIAS-category': 'TaskCategory AS category',
										'EVAL-task_name': 'lower(TaskCategory)',
										'LOOKUP-task': 'tasks Task %s TaskCategory' % mode}, {}),
			b.Stanza('fortigate_traffic', {'FIELDALIAS-transport': 'transport AS vendor_transport',
										   'LOOKUP-proto': 'protos proto OUTPUT transport, protocol'}, {})]


def run_read(events, mode='OUTPUTNEW'):
	present = [('XmlWinEventLog', 'XmlWinEventLog:Security', 'dc01'), ('fortigate_traffic', 'fgt', 'fw1')]
	by_st = {'XmlWinEventLog': ['Task'], 'fortigate_traffic': ['proto', 'transport']}
	full = b.build(read_stanzas(mode), present, READ_LOOKUP_FIELDS, (), keep_by_sourcetype=by_st).spl()
	m = replay_model(full)
	m.lookups = READ_TABLES
	return [visible(e) for e in m.run(txf_steps('`tenx-replay`'), events)]


def read_event(st, exp, attached, read, text):
	"""A compact event indexed under `st`: its attached fields, and what that sourcetype's rules set from them when it was read."""
	e = {'_raw': '~h,1', '__exp': exp, 'sourcetype': st, 'tenx_sourcetype': st, 'source': 'src', 'host': 'h',
		 '_kv': 1, '__by_st': {st: text}}
	e.update(attached)
	e.update(read)
	return e


def win_read():
	return read_event('XmlWinEventLog', '<Event><Task>12544</Task></Event>', {'Task': '12544'},
					  {'TaskCategory': 'Logon'}, {'Task': '12544'})


class TestTxfRulesSeeWhatTheRawEventGives:
	def test_an_alias_of_a_field_only_a_lookup_sets_is_empty(self):
		for mode in ('OUTPUTNEW', 'OUTPUT'):
			out = run_read([win_read()], mode)
			assert out[0]['TaskCategory'] == 'Logon', mode
			assert 'category' not in out[0] and 'task_name' not in out[0], mode

	def test_an_alias_reads_the_text_value_a_lookup_overwrites(self):
		nat = read_event('fortigate_traffic', 'proto=6 transport=5555', {'proto': '6', 'transport': '5555'},
						 {'vendor_transport': '5555', 'transport': 'tcp', 'protocol': 'ip'}, {'proto': '6', 'transport': '5555'})
		plain = read_event('fortigate_traffic', 'proto=6', {'proto': '6'},
						   {'transport': 'tcp', 'protocol': 'ip'}, {'proto': '6'})
		out = run_read([nat, plain])
		assert (out[0]['vendor_transport'], out[0]['transport'], out[0]['protocol']) == ('5555', 'tcp', 'ip')
		assert 'vendor_transport' not in out[1] and (out[1]['transport'], out[1]['protocol']) == ('tcp', 'ip')

	def test_an_event_read_as_the_compact_sourcetype_is_replayed_alike(self):
		e = win_read()
		e['sourcetype'] = 'tenx_encoded'
		del e['TaskCategory']
		out = run_read([e])
		assert out[0]['TaskCategory'] == 'Logon' and 'category' not in out[0]


def appending_typer(event, _):
	"""A typer that adds the event types it finds to an eventtype the event has already."""
	found, have = 'et_%s' % event.get('sourcetype'), event.get('eventtype')
	event['eventtype'] = found if have is None else (have if isinstance(have, list) else [have]) + [found]


def run_txf_typed(events, by_st, typer):
	present = [('fortigate_traffic', 'fgt', 'fw1')]
	full = b.build(STANZAS, present, LOOKUP_FIELDS, (), keep_by_sourcetype=by_st).spl()
	m = replay_model(full)
	m.commands['typer'] = typer
	return [visible(e) for e in m.run(txf_steps('`tenx-replay`'), events)]


class TestTxfEventTypesAreTheTypersAlone:
	BY_ST = {'fortigate_traffic': ['srcip', 'action', 'eventtype']}

	def utm(self):
		# the vendor's eventtype key in the text, and the event types Splunk gave the compact event
		e = txf_event(eventtype='et_compact')
		e['__by_st']['fortigate_traffic']['eventtype'] = 'signature'
		return e

	def test_a_text_key_named_eventtype_is_not_an_event_type(self):
		for typer in (appending_typer, None):
			out = run_txf_typed([self.utm()], self.BY_ST, typer or replay_model('').commands['typer'])
			assert out[0]['eventtype'] == 'et_fortigate_traffic', typer

	def test_eventtype_and_tag_are_never_kept_as_indexed_fields(self):
		full = b.build(STANZAS, [('fortigate_traffic', 'fgt', 'fw1')], LOOKUP_FIELDS, ('tag',),
					   keep_by_sourcetype=self.BY_ST).spl()
		assert "eventtype=if(isnotnull(tenx_rst), null(), 'eventtype')" in full
		assert "tag=if(isnotnull(tenx_rst), null(), 'tag')" in full

	def test_the_shipped_tags_macro_clears_it_before_typer(self):
		d = macro('tenx-replay-tags')
		assert d == ' | '.join(b.TAGS_STEPS)
		assert d.index('eventtype=if(isnull(tenx_rst), eventtype, null())') < d.index('typer ')


class TestTheRewriteExpandsRenamedEvents:
	def service(self, replay):
		class Stanza(object):
			def __init__(self, name, content):
				self.name, self.content = name, content

		class Confs(object):
			def __getitem__(self, name):
				if name == 'tenx_config':
					return {'config': Stanza('config', {})}
				if name == 'props':
					return [Stanza('tenx_encoded', {'REPORT-tenx': 'tenx-hash-vars-extraction'}),
							Stanza('fortigate_traffic', {'EVAL-action': 'lower(action)'})]
				if name == 'tenx_replay':
					return [Stanza(n, c) for n, c in replay.items()]
				raise KeyError(name)

		class Service(object):
			confs = Confs()
		return Service()

	def config(self):
		import tenx_util
		return tenx_util.get_tenx_config(service=self.service({
			'fortigate_traffic': {'indexes': 'fgt', 'renamed': '1'}, 'XmlWinEventLog': {'indexes': 'win'},
			'tenx:narrowing': {'fields_not_in_text': 'action'}}))

	def test_a_sourcetype_compact_events_are_indexed_under_is_a_compact_sourcetype(self):
		import tenx_util
		config = self.config()
		assert config['tenx_source_types'] == ['tenx_encoded', 'fortigate_traffic']
		assert config[tenx_util.RENAMED_SOURCE_TYPES] == ['fortigate_traffic']

	def build(self, search, config):
		import tenx_search_builder
		from support.local_search_manager import LocalSearchManager, CsvTemplateStore
		config = dict(config, dml_source_type='tenx_dml_pure', timestamp_placeholder='__TENX_TS__',
					  variable_separator='$')
		manager = LocalSearchManager(CsvTemplateStore([('h_deny', 'action=deny policy $')]))
		return tenx_search_builder.TenxSearchBuilder(server_connection=None, tenx_config=config,
													 search_manager=manager).build(search)

	def test_the_command_the_hook_and_alerts_expand_a_search_that_names_it(self):
		config = self.config()
		got = self.build('search index=fgt sourcetype=fortigate_traffic deny', config)
		assert got.engaged and '`tenx-inflate`' in got.resolved
		not_renamed = dict(config, tenx_source_types=['tenx_encoded'])
		assert not self.build('search index=fgt sourcetype=fortigate_traffic deny', not_renamed).engaged

	def test_a_search_that_names_no_sourcetype_is_refused_only_for_compact_events(self):
		import tenx_search_builder
		config = self.config()
		got = self.build('search index=fgt deny', config)
		probe = tenx_search_builder.unnamed_compact_probe(got, config)
		assert probe == ('| tstats count where (index=fgt) (sourcetype=tenx_encoded OR '
						 '(sourcetype=fortigate_traffic tenx_sourcetype=*)) by index, sourcetype, source')

	def test_a_compiled_alert_that_names_it_is_flagged_when_passed_through(self):
		import tenx_alert_compiler
		assert tenx_alert_compiler._referenced_tenx_sources('index=fgt sourcetype=fortigate_traffic', self.config()) == [
			'fortigate_traffic']


RENAMED_SCENARIO = r'''
class RenamedSplunk(FakeSplunk):
	"""Compact events of app:kv indexed under app:kv while `renamed` is set; app:json's stay tenx_encoded."""
	renamed = False
	def rest(self, path, data=None, method=None):
		if path.endswith('/search/jobs') and data['search'].endswith('by tenx_sourcetype, sourcetype'):
			self.searches.append((data['search'], data.get('earliest_time')))
			return {'results': [{'tenx_sourcetype': 'app:kv', 'sourcetype': 'app:kv' if self.renamed else 'tenx_encoded'},
								{'tenx_sourcetype': 'app:json', 'sourcetype': 'tenx_encoded'}]}
		if path.endswith('/search/jobs') and data['search'].startswith('| tstats dc('):
			# the compact events of app:kv carry x and y
			self.searches.append((data['search'], data.get('earliest_time')))
			import re
			counted = dict((f, '1' if n in ('x', 'y') else '0') for n, f in re.findall(r'dc\("([^"]+)"\) as (f\d+)', data['search']))
			return {'results': [dict(counted, tenx_sourcetype='app:kv')]}
		return FakeSplunk.rest(self, path, data, method)

def flags():
	return dict((k, v.get('renamed')) for k, v in sorted(fake.conf.items()) if k.startswith('app:'))

out = {}
fake = RenamedSplunk([('app:kv', '/var/app/a.log', 'web-1', 5, 'app', True),
					  ('app:json', '/var/other/b.log', 'api-1', 3, 'shared', True)])
run(fake)
out['before'] = flags()
# the fields app:kv's alias and calculated field name are counted with the sample
out['named'] = [n for n in ('x', 'y', 'k') if any('dc("%s")' % n in s for s, _ in fake.searches)]
out['tx_extract'] = fake.macros.get('tenx-extract')
for step in ('renamed', 'kept'):
	fake.renamed = step == 'renamed'
	fake.dispatches = []
	run(fake)
	out[step] = (flags(), [d[0] for d in fake.dispatches])
print(json.dumps(out))
'''


def test_the_rebuild_records_the_sourcetypes_compact_events_are_indexed_under():
	from test_replay_coverage_record import child_run
	out = child_run(RENAMED_SCENARIO)
	assert out['before'] == {'app:json': None, 'app:kv': None}
	assert out['named'] == ['x', 'y', 'k']
	# y is the target of app:kv's alias: on an event read as app:kv it keeps the alias's value
	assert out['tx_extract'] == b.tx_extract(['x', 'y'], computed=['k', 'y'])
	assert 'foreach y [eval "tenx_ic_<<FIELD>>"' in out['tx_extract']
	# recorded, and compiled alerts recompiled at once
	assert out['renamed'] == [{'app:json': None, 'app:kv': '1'}, ['Recompile Compiled Alerts']]
	# events indexed under it earlier stay searchable, so the record keeps it
	assert out['kept'] == [{'app:json': None, 'app:kv': '1'}, []]


class TestTheNamesTheRulesRead:
	TRANSFORMS = {'fgt_kv': {'REGEX': r'(?<devid>FG\w+)', 'FIELDS': 'policyid'}}

	def stanzas(self):
		return [b.Stanza('default', {}, {}),
				b.Stanza('fortigate_traffic', {'EVAL-action': 'case(action=="deny", "blocked")',
											   'FIELDALIAS-src': 'srcip AS src', 'REPORT-kv': 'fgt_kv',
											   'LOOKUP-app': 'fgt_apps app OUTPUT app_category'}, {}),
				b.Stanza('source::fgt', {'EVAL-from_source': 'lower(vd)'}, {}),
				b.Stanza('other', {'EVAL-zz': 'lower(yy)'}, {})]

	def test_what_the_rules_of_the_sourcetype_read_and_write(self):
		got = b.rule_field_names(self.stanzas(), ['fortigate_traffic'], self.TRANSFORMS, {})
		assert {'action', 'srcip', 'src', 'devid', 'policyid', 'app', 'app_category', 'from_source', 'vd'} <= got
		assert not {'zz', 'yy'} & got

	def test_the_command_counts_them_with_the_sample(self):
		with tempfile.TemporaryDirectory() as home:
			proc = subprocess.run([sys.executable, '-c', NAMED_CHILD, ROOT, home], capture_output=True, text=True,
								  timeout=60)
		assert proc.returncode == 0, proc.stderr[-3000:]
		every, _, by_st = json.loads(proc.stdout.strip().splitlines()[-1])
		# policyid is named only by a rule and carried by the compact events; vd is named and not carried
		assert every == ['policyid', 'srcip'] and by_st == {'fortigate_traffic': ['policyid', 'srcip']}


NAMED_CHILD = CHILD.split('import tenxreplay')[0] + r'''
import re
import tenxreplay

CARRIED = {'srcip', 'policyid'}

def rest(path, data=None, method=None):
	if 'conf-fields' in path:
		return {'entry': []}
	if path.endswith('/configs/conf-macros/tenx-extract'):
		return {'entry': [{'content': {'definition': 'extract'}}]}
	s = data['search']
	if 'fieldsummary' in s:
		return {'results': [{'field': 'srcip'}]}
	if s.startswith('| tstats max(_time)'):
		return {'results': []}
	counted = dict((f, '1' if name in CARRIED else '0') for name, f in re.findall(r'dc\("([^"]+)"\) as (f\d+)', s))
	return {'results': [dict(counted, tenx_sourcetype='fortigate_traffic')]}

cmd = tenxreplay.TenxReplayCommand()
cmd._rest = rest
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	username='splunk-system-user', splunkd_uri='https://127.0.0.1:8089', session_key='key'))
print(json.dumps(cmd._indexed_fields('-7d', 'now', {'policyid', 'vd', 'if'})))
'''
