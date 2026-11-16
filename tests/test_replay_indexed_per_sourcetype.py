"""
Which indexed fields the clearing step of the field replay keeps, run through the SPL model
(tests/support/spl_model.py). Indexed fields are set per event by whoever sent it, so the list is
kept per original sourcetype (build() keep_by_sourcetype): a field map that writes `app` as an
indexed field on FortiGate events is no reason to keep the `app` that Splunk set on a Windows
compact event when it read the compact text (Splunk Enterprise 10.4.3, 662 Windows Security
events with FortiGate field map sourcetypes named in tenx-events: 142 events kept
app=win:unknown where raw has win:remote, 177 of 183 fields equal to raw; 180 with the list per
sourcetype).

The stand-in for Splunk's extract adds each value it finds to a field that already exists, as
measured on Splunk Enterprise 10.4.3 for an extraction with MV_ADD.
"""
import configparser
import json
import os
import subprocess
import sys
import tempfile

import tenx_replay_builder as b
from support.spl_model import Model, visible

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def stanza(name, **rules):
	return b.Stanza(name, dict(rules), {})


def macros_conf():
	conf = configparser.RawConfigParser(strict=False)
	conf.read(os.path.join(ROOT, 'tenx-for-splunk', 'default', 'macros.conf'))
	return conf


def txf_steps(replay_call):
	"""The shipped `txf` definition between its prefilter and its final search, with `replay_call` in
	place of `tenx-replay` (a unit and the tags macro, for txf(<sourcetype>))."""
	text = macros_conf().get('txf', 'definition')
	text = text[text.index('eval tenx_compact_raw=_raw'):text.rindex(' | search *')]
	return text.replace('`tenx-replay`', replay_call)


def extract(event, _):
	"""Splunk's extract on this event: nothing on a hidden one (no text, a sourcetype no stanza
	names), else the fields its text holds under its current sourcetype (the test's __by_st), each
	value added to a field that exists already."""
	if event.get('sourcetype') in (b.PLACEHOLDER, 'tenx_none', 'tenx_replayed') or not event.get('_raw'):
		return
	for k, v in event.get('__by_st', {}).get(event.get('sourcetype'), {}).items():
		if k in event:
			have = event[k] if isinstance(event[k], list) else [event[k]]
			event[k] = have + (v if isinstance(v, list) else [v])
		else:
			event[k] = v


def typer(event, _):
	event['eventtype'] = 'et_%s' % event.get('sourcetype')


TABLES = {'win_apps': [{'LogonType': '3', 'app': 'win:remote'}, {'LogonType': '2', 'app': 'win:local'}]}
LOOKUP_FIELDS = {'win_apps': ['LogonType', 'app']}
STANZAS = [
	stanza('default'),
	stanza('tenx_encoded', **{'REPORT-tenx': 'tenx-hash-vars-extraction'}),
	# As in the Windows add-on: app comes from a lookup that does not overwrite (OUTPUTNEW), so a
	# value Splunk set on the compact text and the replay did not clear stays.
	stanza('source::XmlWinEventLog:Security', **{'LOOKUP-app': 'win_apps LogonType OUTPUTNEW app'}),
	stanza('win', **{'EVAL-k': '"win"'}),
	stanza('fgt', **{'EVAL-k': '"fgt"'}),
	stanza('ct', **{'FIELDALIAS-region': 'awsRegion AS region', 'EVAL-k': '"ct"'}),
]
PRESENT = [('win', 'XmlWinEventLog:Security', 'dc01'), ('fgt', 'fgt.log', 'fw1'), ('ct', 'ct.log', 'aws')]


def model(full, units=None):
	conf = macros_conf()
	macros = dict((n, conf.get(n, 'definition')) for n in ('tenx-mapped-hide', 'tenx-mapped-restore', 'tenx-whole-hide',
														  'tenx-whole-restore'))
	macros.update({'tenx-inflate': 'inflatemodel', 'tenx-replay': full, 'tenx-replay-tags': ' | '.join(b.TAGS_STEPS)})
	macros.update(units or {})
	return Model(commands={'extract': extract, 'typer': typer, 'tags': lambda e, _: None,
						   'inflatemodel': lambda e, _: e.__setitem__('_raw', e['__exp']) if '__exp' in e else None},
				 lookups=TABLES, macros=macros)


def win_compact():
	"""A Windows compact event as Splunk reads it: app set from the compact text by the source stanza."""
	return {'_raw': '~w,4624', '__exp': '<Event>4624 3</Event>', 'sourcetype': 'tenx_encoded',
			'source': 'XmlWinEventLog:Security', 'host': 'dc01', '_kv': 1, 'tenx_sourcetype': 'win',
			'app': 'win:unknown', '__by_st': {'win': {'EventID': '4624', 'LogonType': '3'}}}


def fgt_compact():
	"""A FortiGate compact event whose sender wrote app as an indexed field."""
	return {'_raw': '~f,1', '__exp': 'devid=FG1 app=HTTP', 'sourcetype': 'tenx_encoded', 'source': 'fgt.log',
			'host': 'fw1', '_kv': 1, 'tenx_sourcetype': 'fgt', 'app': 'HTTP', '__by_st': {'fgt': {'devid': 'FG1'}}}


def run(keep=(), by_st=None, evs=None, replay='`tenx-replay`'):
	full = b.build(STANZAS, PRESENT, LOOKUP_FIELDS, keep, keep_by_sourcetype=by_st).spl()
	units = dict((b.unit_macro(st), b.build_unit(STANZAS, st, {'sources': {src}, 'hosts': {host}, 'indexes': set()},
												 LOOKUP_FIELDS, keep, keep_by_sourcetype=by_st).spl())
				 for st, src, host in PRESENT)
	return [visible(e) for e in model(full, units).run(txf_steps(replay), evs)]


def unit_call(st):
	return '`%s` | `tenx-replay-tags`' % b.unit_macro(st)


class TestIndexedFieldsPerSourcetype:
	BY_ST = {'fgt': ['app'], 'win': [], 'ct': []}

	def test_a_field_one_sourcetype_indexes_is_cleared_on_another(self):
		for replay in ('`tenx-replay`', None):
			out = run(by_st=self.BY_ST, evs=[win_compact(), fgt_compact()],
					  replay=replay or unit_call('win'))
			assert out[0]['app'] == 'win:remote' and out[0]['k'] == 'win', replay
			if replay:
				assert out[1]['app'] == 'HTTP' and out[1]['k'] == 'fgt'
		out = run(by_st=self.BY_ST, evs=[fgt_compact()], replay=unit_call('fgt'))
		assert out[0]['app'] == 'HTTP'

	def test_one_list_for_every_sourcetype_kept_the_value_read_from_the_compact_text(self):
		# the behaviour this replaces: app indexed anywhere kept it on every replayed event
		out = run(keep=('app',), evs=[win_compact(), fgt_compact()])
		assert out[0]['app'] == 'win:unknown' and out[1]['app'] == 'HTTP'

	def test_the_clearing_step_names_the_sourcetypes_it_clears_on(self):
		steps = b.build(STANZAS, PRESENT, LOOKUP_FIELDS, (), keep_by_sourcetype=self.BY_ST).spl()
		assert ('app=if(isnotnull(tenx_rst) AND (mvindex(tenx_sourcetype,0)=="ct" OR '
				'mvindex(tenx_sourcetype,0)=="win"), null(), \'app\')') in steps
		# a field kept for every sourcetype present is not cleared at all
		every = b.build(STANZAS, PRESENT, LOOKUP_FIELDS, (), keep_by_sourcetype={'fgt': ['app'], 'win': ['app'], 'ct': ['app']})
		assert "app=if(isnotnull(tenx_rst)" not in every.spl()

	def test_a_sourcetype_that_was_not_counted_keeps_what_any_keeps(self):
		# win has no entry: no compact event of it in the time range that was counted
		out = run(by_st={'fgt': ['app'], 'ct': []}, evs=[win_compact()])
		assert out[0]['app'] == 'win:unknown'

	def test_an_unknown_sourcetype_keeps_it(self):
		e = win_compact()
		e['tenx_sourcetype'] = 'new:st'
		out = run(by_st=self.BY_ST, evs=[e])
		assert out[0]['app'] == 'win:unknown' and out[0]['sourcetype'] == 'new:st'


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

cmd = tenxreplay.TenxReplayCommand()
searches = []

def rest(path, data=None, method=None):
	if 'conf-fields' in path:
		return {'entry': [{'name': 'declared', 'content': {'INDEXED': 'true'}}, {'name': 'other', 'content': {}}]}
	s = data['search']
	searches.append(s)
	if 'dedup index host source sourcetype | fieldsummary' in s:
		# the most recent event of each sender: one sender writes the indexed field rare
		return {'results': [{'field': f} for f in ('host', 'rare', 'env')]}
	if 'fieldsummary' in s:
		return {'results': [{'field': f} for f in ('app', 'env', 'host', 'tenx_sourcetype', 'srcip', 'date_hour')]}
	if s.startswith('| tstats max(_time)'):
		return {'results': [{'index': 'ix', 'host': 'fw1', 'source': 'a.log', 'sourcetype': 'tenx_encoded', 't': '1590998439.250'},
							{'index': 'ix', 'host': 'fw`2', 'source': 'b.log', 'sourcetype': 'tenx_encoded', 't': '1590998400'},
							{'index': 'ix', 'host': 'fw"3', 'source': 'c.log', 'sourcetype': 'tenx_encoded', 't': '1590998401'}]}
	if s.endswith('by tenx_sourcetype'):
		return {'results': [{'tenx_sourcetype': 'fgt', 'f0': '0', 'f1': '1', 'f2': '1', 'f3': '1'},
							{'tenx_sourcetype': 'win', 'f0': '0', 'f1': '1', 'f2': '0', 'f3': '0'}]}
	return {'results': [{'f0': '3', 'f1': '2', 'f2': '1', 'f3': '1'}]}

cmd._rest = rest
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	username='splunk-system-user', splunkd_uri='https://127.0.0.1:8089', session_key='key'))
got = cmd._indexed_fields('-7d', 'now')
print(json.dumps({'got': got, 'searches': searches}))
'''


def test_the_command_counts_indexed_fields_per_original_sourcetype():
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', CHILD, ROOT, home], capture_output=True, text=True, timeout=60)
	assert proc.returncode == 0, proc.stderr
	out = json.loads(proc.stdout.strip().splitlines()[-1])
	every, declared, by_st = out['got']
	# app, env, rare and srcip are indexed somewhere (the prefilter's list); declared is fields.conf INDEXED = true
	assert every == ['app', 'declared', 'env', 'rare', 'srcip'] and declared == ['declared']
	# per sourcetype, over the events the replay works on: no field-map event (tenx_mapped)
	assert by_st == {'fgt': ['env', 'rare', 'srcip'], 'win': ['env']}
	assert out['searches'][0] == 'search `tenx-events` | head 1000 | fieldsummary | fields field'
	assert out['searches'][1] == '| tstats max(_time) as t where `tenx-events` by index host source sourcetype'
	# the most recent event of each sender, one second of it; a value with a backtick is left out (a macro), a
	# double quote is escaped
	assert out['searches'][2] == ('search `tenx-events` ((index="ix" host="fw1" source="a.log" sourcetype="tenx_encoded" '
		'earliest=1590998439 latest=1590998440) OR (index="ix" host="fw\\"3" source="c.log" sourcetype="tenx_encoded" '
		'earliest=1590998401 latest=1590998402)) | dedup index host source sourcetype | fieldsummary | fields field')
	funcs = 'dc("app") as f0, dc("env") as f1, dc("rare") as f2, dc("srcip") as f3'
	assert out['searches'][3] == '| tstats %s where `tenx-events`' % funcs
	assert out['searches'][4] == '| tstats %s where `tenx-events` NOT tenx_mapped=* by tenx_sourcetype' % funcs
