"""
The field replay must leave the search rewrite's extraction of compact events WITHOUT
tenx_sourcetype exactly as it is with no replay, and `txf` must leave them as `tx` does.

Without replay, the rewrite after the prefilter is `| tenx-inflate | extract | spath | fields -
tenx_hash, tenx_var_0, tenx_vars`, plus `| extract kvdelim="=" pairdelim=" "` when the search has
a field term; `tx` is `| tenx-inflate | fields - _kv | extract | fields - ...`. These tests run
that text and the text with the replay through the SPL model in tests/support/spl_model.py with
stand-ins for extract, spath and the key=value pass that log every call with the text and
metadata it saw, and compare, event by event, the fields at the end and the calls that could
change a field. What the model assumes about Splunk is listed in its docstring.
"""
import re

import tenx_replay_builder as b
from support.spl_model import Model, visible
from test_tenx_search_builder import compile_search

PLAIN_REWRITE = '`tenx-inflate` | extract | spath | fields - tenx_hash, tenx_var_0, tenx_vars'
PLAIN_KV = ' | extract kvdelim="=" pairdelim=" "'
PLAIN_TX = '`tenx-inflate` | fields - _kv | extract | fields - tenx_hash, tenx_var_0, tenx_vars'
REFUSED_STEP = ' | eval tenx_expand_refused=if(len(tenx_expand_refused)>0, tenx_expand_refused, null())'
PLAIN_TX += REFUSED_STEP


def kv_pairs(event):
	for k, v in re.findall(r'(\w+)=(\w+)', event.get('_raw') or ''):
		event[k] = v


def extract(event, _):
	"""Props as this test pretends they are: the app's compact-format REPORT, KV_MODE auto, and
	one rule of the original sourcetype. A placeholder sourcetype has no stanza."""
	raw, st = event.get('_raw') or '', event.get('sourcetype')
	if st in ('tenx_encoded', 'XmlWinEventLog'):
		if ',' in raw:
			event['tenx_hash'], event['tenx_vars'] = raw.split(',', 1)
	if st == 'XmlWinEventLog':
		m = re.search(r'<EventID>(\d+)<', raw)
		if m:
			event['EventCode'] = m.group(1)
	if st != 'tenx_hidden' and not event.get('_kv'):
		kv_pairs(event)


def spath(event, _):
	raw = event.get('_raw') or ''
	for tag, val in re.findall(r'<(\w+)>([^<]*)</\1>', raw):
		event['Event.System.' + tag] = val


def model(definition):
	return Model(
		commands={'extract': extract, 'spath': spath, 'extract kvdelim="=" pairdelim=" "': lambda e, _: kv_pairs(e),
				  'inflatemodel': lambda e, _: e.__setitem__('_raw', e['__exp']),
				  'typer': lambda e, _: e.__setitem__('eventtype', 'et_%s' % e.get('sourcetype')),
				  'tags': lambda e, _: None},
		macros={'tenx-inflate': 'inflatemodel', 'tenx-replay': definition})


def compact(raw, exp, carrier=None, **read_time):
	"""A compact event as Splunk reads it: marked extracted, with what tenx_encoded's rules found."""
	e = {'_raw': raw, '__exp': exp, 'sourcetype': 'tenx_encoded', 'source': 'app.log', 'host': 'web1', '_kv': 1,
		 'tenx_hash': raw.split(',')[0], 'eventtype': 'et_compact'}
	if carrier:
		e['tenx_sourcetype'] = carrier
	e.update(read_time)
	return e


def events():
	return [compact('~h1,alice,500', 'usr=alice status=500 payment failed, retry', app='x'),
			compact('~h2,4625', '<Event><EventID>4625</EventID><Data>a,b</Data></Event>'),
			compact('~h3,4663', '<Event><EventID>4663</EventID></Event>', carrier='XmlWinEventLog')]


def changing_calls(event):
	"""The calls of extract, spath and the key=value pass that saw the event's text: a call on the
	hidden form (no text, placeholder metadata) cannot set a field from the event. typer and tags
	are left out: in a chunk that also holds replayed events they run on every event, and the
	macro puts back the eventtype and tags of the others (the final fields are compared)."""
	return [c for c in event.get('__log', []) if c[0] not in ('inflatemodel', 'typer', 'tags') and c[1][0] != '']


def rewrite_tail(search):
	resolved = compile_search(search)[0].resolved
	start = resolved.index('| eval tenx_compact_raw=_raw')
	end = resolved.index(' | search ', start)
	return resolved[start + 2:end]


GENERATED = b.build([b.Stanza('XmlWinEventLog', {'EVAL-action': '"success"'}, {})],
					[('XmlWinEventLog', 'app.log', 'web1')]).spl()


def compare(definition, search, plain_tail, chunk):
	ours = model(definition).run(rewrite_tail(search), chunk())
	plain = model(definition).run(plain_tail, chunk())
	return ours, plain


class TestRewriteWithoutCarrierIsUnchanged:
	def test_shipped_macro(self):
		for search, tail in (('sourcetype=tenx_encoded payment', PLAIN_REWRITE),
							 ('sourcetype=tenx_encoded status=500', PLAIN_REWRITE + PLAIN_KV)):
			ours, plain = compare(' | '.join(b.UNCHANGED), search, tail, events)
			# with the shipped macro nothing is replayed, so every event, the carrier one too, is
			# extracted exactly as the rewrite without replay extracts it
			for o, m in zip(ours, plain):
				assert visible(o) == visible(m), search
				assert changing_calls(o) == changing_calls(m), search

	def test_generated_macro_mixed_chunk(self):
		for search, tail in (('sourcetype=tenx_encoded payment', PLAIN_REWRITE),
							 ('sourcetype=tenx_encoded status=500', PLAIN_REWRITE + PLAIN_KV)):
			ours, plain = compare(GENERATED, search, tail, events)
			for o, m in zip(ours[:2], plain[:2]):
				assert visible(o) == visible(m), search
				assert changing_calls(o) == changing_calls(m), search
			# the carrier event is replayed: its own sourcetype's rules, none of spath's paths, no
			# junk from the compact-format regex
			replayed = visible(ours[2])
			assert replayed['sourcetype'] == 'XmlWinEventLog' and replayed['EventCode'] == '4663'
			assert replayed['action'] == 'success'
			assert not any(k.startswith('Event.System.') for k in replayed)
			assert 'tenx_rst' not in replayed and 'tenx_hide_others' not in replayed

	def test_generated_macro_chunk_without_carrier(self):
		def no_carrier():
			return events()[:2]
		ours, plain = compare(GENERATED, 'sourcetype=tenx_encoded payment', PLAIN_REWRITE, no_carrier)
		for o, m in zip(ours, plain):
			assert visible(o) == visible(m)
			assert changing_calls(o) == changing_calls(m)


class TestTxfWithoutCarrierIsTx:
	def test_tx_macro(self):
		import configparser
		import os
		conf = configparser.RawConfigParser(strict=False)
		conf.read(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'default', 'macros.conf'))
		# tests/test_replay_units.py pins `tx`; the replay is `txf`.
		tx = conf.get('txf', 'definition')
		tail = tx[tx.index('eval tenx_compact_raw=_raw'):tx.rindex(' | search *')]
		for definition in (' | '.join(b.UNCHANGED), GENERATED):
			ours = model(definition).run(tail, events()[:2])
			plain = model(definition).run(PLAIN_TX, events()[:2])
			for o, m in zip(ours, plain):
				assert visible(o) == visible(m)
				assert changing_calls(o) == changing_calls(m)
