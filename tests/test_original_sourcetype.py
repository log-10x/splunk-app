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
							 'tenx_sourcetype', 'srcip', 'kubernetes.container_name', 'a{}.b', "it's"]) == [
			'a{}.b', "it's", 'kubernetes.container_name', 'srcip']
		text = b.tx_extract(['srcip', 'kubernetes.container_name', 'a{}.b', "it's"])
		assert '"kubernetes.container_name"=if(' in text and 'a{}.b' not in text and "it's" not in text

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
