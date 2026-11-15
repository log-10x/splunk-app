"""
The field replay at the cost each search asks for. Splunk spends about 0.012 s per 1,000
characters of macro text on every search that expands it, even one that finds no event (observed
on Splunk Enterprise 10.4.3, where a generated `tenx-replay` for one install was 80,965
characters). So:

- `tx` is unchanged, character for character: it runs no replay.
- `txf` runs `tenx-replay` (every covered sourcetype); `txf(<sourcetype>)` runs only that
  sourcetype's unit and `tenx-replay-tags`.
- The search rewrite (dashboard hook, `| tx`, compiled alerts) writes the text without replay
  when tenx_replay.conf lists no sourcetype, or records the indexes the search names as holding
  none; the units of the sourcetypes recorded for those indexes; and `tenx-replay` when the
  search names no index, or an index the record does not know.

What runs in the SPL model (tests/support/spl_model.py) shows what the text does under the
model's assumptions about Splunk, which its docstring lists.
"""
import configparser
import json
import os
import re
import subprocess
import sys
import tempfile

import pytest

import tenx_prefilter_parser as pp
import tenx_replay_builder as b
from support import tenx_search_builder_baseline as baseline_builder
from support.local_search_manager import CsvTemplateStore
from support.spl_model import Model, visible
from test_tenx_search_builder import TEMPLATES, CountingManager, EXPAND, make_config

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
MACROS = os.path.join(ROOT, 'tenx-for-splunk', 'default', 'macros.conf')

# default/macros.conf [tx] at commit e12ec4e (release 1.1.7)
TX_SHIPPED = ('`tenx-events` [| tenxprefilter] | `tenx-inflate` | fields - _kv | extract | '
			  'fields - tenx_hash, tenx_var_0, tenx_vars | search *')
# The one step `tx` and `txf` add before their final search: the template lookup gives
# tenx_expand_refused an empty value on every event it expands, and only a refused event keeps it.
REFUSED_STEP = ' | eval tenx_expand_refused=if(len(tenx_expand_refused)>0, tenx_expand_refused, null())'
# [tx] now
TX_DEFINITION = TX_SHIPPED.replace(' | search *', REFUSED_STEP + ' | search *')


def macros():
	conf = configparser.RawConfigParser(strict=False)
	conf.read(MACROS)
	return conf


def stanza_text(text, name):
	"""The lines of one stanza of a .conf file as written, comments above it included."""
	lines = text.split('\n')
	i = lines.index('[%s]' % name)
	start = i
	while start > 0 and lines[start - 1].startswith('#'):
		start -= 1
	end = i + 1
	while end < len(lines) and lines[end] and not lines[end].startswith('['):
		end += 1
	return '\n'.join(lines[start:end])


class TestTheRefusedStep:
	"""REFUSED_STEP, as the end of `tx` and `txf` runs it, on the three kinds of event."""
	def run(self, value):
		event = {'_raw': 'x'}
		if value is not None:
			event['tenx_expand_refused'] = value
		return visible(Model().run(REFUSED_STEP.lstrip(' |'), [event])[0])

	def test_an_expanded_event_has_no_such_field(self):
		# the lookup's empty value for a template that expands
		assert 'tenx_expand_refused' not in self.run('')

	def test_a_refused_event_keeps_its_reason(self):
		for reason in ('back-reference', 'multi-timestamp', 'hash-conflict'):
			assert self.run(reason)['tenx_expand_refused'] == reason

	def test_an_event_of_an_unknown_template_is_unchanged(self):
		assert self.run(None) == {'_raw': 'x'}


class TestTxIsTheShippedMacro:
	"""
	`tx` is the shipped macro with one step added before its final search, REFUSED_STEP, which
	removes the empty tenx_expand_refused the template lookup leaves on every expanded event.
	TestTheRefusedStep runs it on a refused, an expanded and an unknown template's event.
	"""
	def test_the_definition(self):
		assert macros().get('tx', 'definition') == TX_DEFINITION
		assert TX_DEFINITION.replace(REFUSED_STEP, '') == TX_SHIPPED

	def test_every_other_shipped_stanza_is_unchanged_character_for_character(self):
		try:
			base = subprocess.run(['git', 'show', 'e12ec4e:tenx-for-splunk/default/macros.conf'], cwd=ROOT,
								  capture_output=True, text=True, timeout=30)
		except OSError:
			pytest.skip('git is not available')
		if base.returncode != 0:
			pytest.skip('commit e12ec4e is not in this checkout')
		ours = open(MACROS, encoding='utf-8').read()
		shipped = configparser.RawConfigParser(strict=False)
		shipped.read_string(base.stdout)
		assert macros().get('tx', 'definition').replace(REFUSED_STEP, '') == shipped.get('tx', 'definition')
		# every other stanza shipped at e12ec4e is unchanged, its comments included
		for name in shipped.sections():
			if name != 'tx':
				assert stanza_text(ours, name) == stanza_text(base.stdout, name), name

	def test_tx_runs_no_replay(self):
		assert 'tenx-replay' not in macros().get('tx', 'definition')

	def test_txf_is_tx_with_the_replay(self):
		conf = macros()
		head = '`tenx-events` [| tenxprefilter] | eval tenx_compact_raw=_raw | `tenx-inflate` | fields - _kv | '
		tail = ' | fields - tenx_compact_raw, tenx_rst, tenx_hash, tenx_var_0, tenx_vars' + REFUSED_STEP + ' | search *'
		assert conf.get('txf', 'definition') == head + '`tenx-replay`' + tail
		# Splunk Enterprise 10.4.3 refuses a colon in a macro name, so txf(1) computes the unit's
		# name with md5() in eval; on 10.4.3, md5 in eval equals hashlib's for the five names tried
		assert conf.get('txf(1)', 'iseval') == '1'
		assert conf.get('txf(1)', 'definition') == ('"' + head + '`tenx-replay-u" . substr(md5("$st$"), 1, 12) . '
													 '"` | `tenx-replay-tags`' + tail + '"')
		assert conf.get('txf(1)', 'args') == 'st'
		assert conf.get('txf(1)', 'validation') == 'match(st, "^[A-Za-z0-9_.:/-]+$")'
		assert conf.get('txf(1)', 'errormsg')
		assert len(b.unit_macro('x')) == len(b.UNIT_PREFIX) + 12

	def test_the_tags_macro_is_the_builders_text(self):
		assert macros().get('tenx-replay-tags', 'definition') == ' | '.join(b.TAGS_STEPS)

	def test_the_alias_is_written_only_for_valid_macro_names(self):
		# "Macro and argument names might only include alphanumerics, '_' and '-'" (Splunk 10.4.3)
		assert b.ALIAS_NAME.pattern == '^[A-Za-z0-9_-]+$'


# ---------------------------------------------------------------------------
# The search rewrite
# ---------------------------------------------------------------------------

def compiled(search, covered, module=None):
	"""(state, resolved text) of `search` compiled with tenx_replay.conf listing `covered`."""
	config = make_config()
	if covered is not False:
		config['tenx_replay'] = covered
	manager = CountingManager(CsvTemplateStore(TEMPLATES))
	module = module or __import__('tenx_search_builder')
	result = module.TenxSearchBuilder(server_connection=None, tenx_config=config, search_manager=manager).build(search)
	return result.state.name, result.resolved


SEARCHES = [
	'sourcetype=tenx_encoded error',
	'sourcetype=tenx_encoded "payment failed"',
	'sourcetype=tenx_encoded status=500',
	'sourcetype=tenx_encoded status=500 payment',
	'index=main sourcetype=tenx_encoded NOT bootstrap',
	'index=app sourcetype=tenx_encoded error | stats count by host',
	'sourcetype=tenx_encoded cart* OR payment',
	'sourcetype=tenx_encoded ip-192-168-42-205.ec2.internal',
	'sourcetype=tenx_encoded 192.168.45.200',
	'sourcetype=tenx_encoded',
	'sourcetype=tenx_encoded level=error | where x > 1',
	'sourcetype=other error',
	'index=main error',
]


class TestRewriteWithoutCarrierMatchesTheBaseline:
	"""
	The rewrite must produce exactly the text of the search builder without field replay
	(tests/support/tenx_search_builder_baseline.py) where nothing carries tenx_sourcetype.
	"""

	@pytest.mark.parametrize('search', SEARCHES)
	def test_no_sourcetype_covered(self, search):
		assert compiled(search, {}) == compiled(search, False, baseline_builder)

	@pytest.mark.parametrize('search', [s for s in SEARCHES if 'index=' in s])
	def test_an_index_the_record_does_not_know_gets_the_full_replay(self, search):
		# Where any compact event carries tenx_sourcetype, an index no stanza records may hold
		# such events not recorded yet, so it gets `tenx-replay`, never the text without replay.
		covered = {'XmlWinEventLog': {'indexes': 'wineventlog'}}
		state, text = compiled(search, covered)
		base_state, base_text = compiled(search, False, baseline_builder)
		if 'tenx-inflate' in base_text:
			assert '`tenx-replay`' in text
		else:
			assert (state, text) == (base_state, base_text)

	def test_what_it_compares_against_is_the_baselines_shape(self):
		state, text = compiled('sourcetype=tenx_encoded status=500 payment', False, baseline_builder)
		assert text.endswith('| `tenx-inflate` | fields - _kv | extract | eval tenx_xml=if(match(_raw, "^\\s*<"), _raw, null()) | spath input=tenx_xml | fields - tenx_xml, tenx_hash, tenx_var_0, tenx_vars'
							 ' | search status=500 | search payment')
		assert 'tenx-replay' not in text and 'tenx_compact_raw' not in text


COVERED = {'XmlWinEventLog': {'indexes': 'wineventlog'}, 'app:kv': {'indexes': 'app,shared'},
		   'app:json': {'indexes': 'shared'}}


def with_replay(replay):
	return EXPAND.replace('`tenx-replay`', replay)


class TestRewriteRunsWhatTheSearchNeeds:
	def test_an_index_with_one_sourcetype_gets_its_unit(self):
		_, text = compiled('index=wineventlog sourcetype=tenx_encoded error', COVERED)
		unit = '`%s` | `tenx-replay-tags`' % b.unit_macro('XmlWinEventLog')
		assert text.endswith(with_replay(unit) + '| search error')
		assert '`tenx-replay`' not in text

	def test_an_index_with_two_gets_both_units_composed(self):
		_, text = compiled('index=shared sourcetype=tenx_encoded error', COVERED)
		assert with_replay(b.compose_units(['app:json', 'app:kv'])) in text

	def test_wildcards_and_or(self):
		# a wildcard resolves against the record; matching nothing recorded: full
		_, text = compiled('index=app* sourcetype=tenx_encoded error', COVERED)
		assert with_replay(b.compose_units(['app:kv'])) in text
		_, text = compiled('(index=wineventlog OR index=app) sourcetype=tenx_encoded error', COVERED)
		assert with_replay(b.compose_units(['XmlWinEventLog', 'app:kv'])) in text

	def test_no_index_named_gets_every_sourcetype(self):
		# no index named: the full `tenx-replay`
		_, text = compiled('sourcetype=tenx_encoded error', COVERED)
		assert text.endswith(EXPAND + '| search error')

	def test_coverage_unreadable_gets_every_sourcetype(self):
		for covered in (None, False):
			_, text = compiled('index=wineventlog sourcetype=tenx_encoded error', covered)
			assert text.endswith(EXPAND + '| search error')

	def test_field_terms_are_filtered_after_the_replayed_events_are_back(self):
		_, text = compiled('index=wineventlog sourcetype=tenx_encoded EventCode=4625', COVERED)
		assert text.index(b.unit_macro('XmlWinEventLog')) < text.index('spath input=tenx_xml') \
			< text.index('tenx_h_raw, _raw)') < text.index('| search EventCode=4625')


class TestRewriteReplay:
	def test_choices(self):
		assert b.rewrite_replay(None, ['x']) == b.FULL
		assert b.rewrite_replay({}, ['x']) is None
		assert b.rewrite_replay({}, []) is None
		assert b.rewrite_replay(COVERED, []) == b.FULL
		assert b.rewrite_replay(COVERED, None) == b.FULL
		assert b.rewrite_replay(COVERED, ['nothing_here']) == b.FULL   # not recorded: never less than full
		assert b.rewrite_replay(COVERED, ['app*']) == b.compose_units(['app:kv'])
		assert b.rewrite_replay(COVERED, ['zz*']) == b.FULL
		assert b.rewrite_replay(COVERED, ['*']) == b.FULL
		assert b.rewrite_replay(COVERED, ['WINEVENTLOG']) == b.compose_units(['XmlWinEventLog'])
		assert b.rewrite_replay(COVERED, ['shared', 'wineventlog']) == b.FULL

	def test_a_sourcetype_listed_with_every_index_or_none_matches_any(self):
		# * past 200 indexes; empty in a stanza that records no index
		covered = {'a': {'indexes': '*'}, 'b': {'indexes': ''}, 'c': {'indexes': 'only_c'}, 'd': {'indexes': 'only_d'}}
		assert b.rewrite_replay(covered, ['only_c']) == b.compose_units(['a', 'b', 'c'])

	def test_reserved_and_unusable_names_are_not_sourcetypes(self):
		assert b.rewrite_replay({'default': {}, 'tenx:narrowing': {}}, ['x']) is None
		assert b.rewrite_replay({'a`b': {}}, []) is None

	def test_composition_keeps_each_units_events(self):
		text = b.compose_units(['b', 'a', 'c'])
		assert text == ' | '.join([
			'`%s`' % b.unit_macro('a'),
			'eval tenx_rprev=tenx_rst', '`%s`' % b.unit_macro('b'), 'eval tenx_rst=coalesce(tenx_rst, tenx_rprev)',
			'eval tenx_rprev=tenx_rst', '`%s`' % b.unit_macro('c'), 'eval tenx_rst=coalesce(tenx_rst, tenx_rprev)',
			'fields - tenx_rprev', '`tenx-replay-tags`'])


# ---------------------------------------------------------------------------
# Units, run in the SPL model
# ---------------------------------------------------------------------------

def stanza(name, **rules):
	return b.Stanza(name, dict(rules), {})


TABLES = {'users': [{'username': 'u1', 'dept': 'sales'}], 'depts': [{'dept': 'eng', 'floor': '3'}, {'dept': 'sales', 'floor': '1'}]}
LOOKUP_FIELDS = {'users': ['username', 'dept'], 'depts': ['dept', 'floor']}
STANZAS = [
	stanza('default', **{'EVAL-k': '"dflt"', 'EVAL-d_only': '"d"'}),
	stanza('tenx_encoded', **{'REPORT-tenx': 'tenx-hash-vars-extraction', 'EVAL-junk': '"compact"'}),
	stanza('app:kv', **{'EVAL-k': '"st"', 'FIELDALIAS-a': 'x AS y', 'FIELDALIAS-b': 'y AS z', 'EVAL-p': 'q', 'EVAL-q': '"new"',
						'LOOKUP-users': 'users username AS user OUTPUT dept', 'LOOKUP-a_dept': 'depts dept OUTPUT floor'}),
	stanza('app:json', **{'EVAL-j': '"json"', 'FIELDALIAS-j': 'x AS y'}),
	stanza('source::.../app/*.log', **{'EVAL-k': '"src"', 'EVAL-s_junk': '"from source"'}),
	stanza('source::/var/other/*.log', **{'EVAL-o': '"other source"'}),
	stanza('host::WEB-*', **{'EVAL-h': '"host"'}),
]
# (sourcetype, source, host, count, index) as tenxreplay's tstats returns them
ROWS = [('app:kv', '/var/app/a.log', 'web-1', 5, 'app'), ('app:json', '/var/other/b.log', 'api-1', 3, 'shared'),
		('app:json', '/var/app/a.log', 'web-2', 1, 'shared')]


def extract(event, _):
	"""Splunk's extract as these tests pretend: the expanded text's fields, set when the _kv mark is
	gone; on a compact event (still tenx_encoded) the compact sourcetype's comma split."""
	if event.get('sourcetype') in ('tenx_hidden', 'tenx_replayed') or not event.get('_raw'):
		return
	if event.get('sourcetype') == 'tenx_encoded':
		if ',' in event['_raw'] and not event.get('_kv'):
			event['tenx_hash'], event['tenx_vars'] = event['_raw'].split(',', 1)
		return
	if not event.get('_kv'):
		event.update(event.get('__text_fields', {}))


def typer(event, _):
	event['eventtype'] = 'et_%s' % event.get('sourcetype')


def model(**macros_):
	return Model(commands={'extract': extract, 'typer': typer, 'tags': lambda e, _: None,
						   'spath': lambda e, _: None, 'extract kvdelim="=" pairdelim=" "': lambda e, _: None,
						   'inflatemodel': lambda e, _: e.__setitem__('_raw', e['__exp'])},
				 lookups=TABLES, macros=dict({'tenx-inflate': 'inflatemodel'}, **macros_))


def compact(st=None, source='/var/app/a.log', host='web-1', **text_fields):
	"""A compact event as Splunk reads it: still tenx_encoded, marked extracted, with what the
	compact sourcetype's and the matching source stanza's rules set on the compact text."""
	e = {'_raw': '~h,1', '__exp': 'expanded text', 'sourcetype': 'tenx_encoded', 'source': source, 'host': host,
		 '_kv': 1, 'junk': 'compact', 'eventtype': 'et_compact', '__text_fields': text_fields}
	if source.startswith('/var/app/'):
		e['s_junk'] = 'compact'
	if st:
		e['tenx_sourcetype'] = st
	return e


def events():
	return [compact('app:kv', x='X', q='old', user='u1', dept='eng'),
			compact('app:json', source='/var/other/b.log', host='api-1', x='J'),
			compact('app:json', host='web-2', x='J2'),
			compact(x='plain'),
			compact('other:st', x='other')]


def full_macro():
	present = [r[:3] for r in ROWS]
	return b.build(STANZAS, present, LOOKUP_FIELDS).spl()


def units():
	cov = b.coverage(ROWS)
	return dict((st, b.build_unit(STANZAS, st, cov[st], LOOKUP_FIELDS).spl()) for st in cov)


TXF = 'eval tenx_compact_raw=_raw | `tenx-inflate` | fields - _kv | %s | fields - tenx_compact_raw, tenx_rst, tenx_hash, tenx_var_0, tenx_vars' + REFUSED_STEP.replace('%', '%%')
PLAIN_TX = '`tenx-inflate` | fields - _kv | extract | fields - tenx_hash, tenx_var_0, tenx_vars' + REFUSED_STEP


def run_txf(replay, evs):
	m = model(**dict({'tenx-replay': full_macro(), 'tenx-replay-tags': ' | '.join(b.TAGS_STEPS)},
					 **dict((b.unit_macro(st), u) for st, u in units().items())))
	return [visible(e) for e in m.run(TXF % replay, evs)]


def run_tx(evs):
	return [visible(e) for e in model().run(PLAIN_TX, evs)]


class TestTxfOfOneSourcetype:
	def unit(self, st):
		return '`%s` | `tenx-replay-tags`' % b.unit_macro(st)

	def test_its_events_get_what_txf_gives_them(self):
		full = run_txf('`tenx-replay`', events())
		for st, which in (('app:kv', [0]), ('app:json', [1, 2])):
			one = run_txf(self.unit(st), events())
			for i in which:
				assert one[i] == full[i], (st, i)
		# and what that is: the rules of the stanzas that apply, junk from the compact text gone
		assert full[0]['k'] == 'src' and full[0]['y'] == 'X' and full[0]['p'] == 'old' and full[0]['dept'] == 'sales'
		assert full[0]['floor'] == '3' and full[0]['eventtype'] == 'et_app:kv' and 'junk' not in full[0]
		assert full[1]['k'] == 'dflt' and full[1]['o'] == 'other source' and full[1]['j'] == 'json'
		# s_junk: what the source stanza computed on the compact text, computed again on the expanded event
		assert full[2]['h'] == 'host' and full[2]['k'] == 'src' and full[2]['s_junk'] == 'from source'

	def test_every_other_event_is_left_as_tx_leaves_it(self):
		plain = run_tx(events())
		for st, others in (('app:kv', [1, 2, 3, 4]), ('app:json', [0, 3, 4])):
			one = run_txf(self.unit(st), events())
			for i in others:
				assert one[i] == plain[i], (st, i)

	def test_a_source_or_host_not_recorded_is_the_one_difference(self):
		# A stanza is in a unit when it matches a source or host recorded for the sourcetype, and
		# then applies to every event its pattern matches. [host::dc*] matches no host recorded for
		# app:json, so an app:json event from dc01 does not get its rule until a rebuild records
		# dc01 (within 5 minutes for new events; over all time for a sourcetype seen first).
		stanzas = STANZAS + [stanza('host::dc*', **{'EVAL-site': '"hq"'})]
		ev = compact('app:json', host='DC01', x='J')

		def txf(rows):
			cov = b.coverage(rows)
			unit = b.build_unit(stanzas, 'app:json', cov['app:json'], LOOKUP_FIELDS).spl()
			m = model(**{b.unit_macro('app:json'): unit, 'tenx-replay-tags': ' | '.join(b.TAGS_STEPS)})
			return visible(m.run(TXF % self.unit('app:json'), [dict(ev)])[0])
		full = visible(model(**{'tenx-replay': b.build(stanzas, [r[:3] for r in ROWS], LOOKUP_FIELDS).spl()}).run(
			TXF % '`tenx-replay`', [dict(ev)])[0])
		assert full['site'] == 'hq'
		assert 'site' not in txf(ROWS)
		assert txf(ROWS + [('app:json', '/var/other/b.log', 'DC01', 1, 'shared')]) == full

	def test_the_no_op_unit_is_tx(self):
		m = model(**{b.unit_macro('gone'): b.no_op_unit().spl(), 'tenx-replay-tags': ' | '.join(b.TAGS_STEPS)})
		out = [visible(e) for e in m.run(TXF % self.unit('gone'), events())]
		assert out == run_tx(events())


PLAIN_REWRITE = '`tenx-inflate` | fields - _kv | extract | eval tenx_xml=if(match(_raw, "^\\s*<"), _raw, null()) | spath input=tenx_xml | fields - tenx_xml, tenx_hash, tenx_var_0, tenx_vars'


def rewrite_tail(replay):
	return EXPAND.replace('`tenx-replay`', replay).strip().lstrip('| ')


class TestUnitsComposedInTheRewrite:
	def run(self, replay, evs):
		macros_ = dict({'tenx-replay': full_macro(), 'tenx-replay-tags': ' | '.join(b.TAGS_STEPS)},
					   **dict((b.unit_macro(st), u) for st, u in units().items()))
		macros_[b.unit_macro('gone')] = b.no_op_unit().spl()
		return [visible(e) for e in model(**macros_).run(rewrite_tail(replay), evs)]

	def test_each_event_gets_what_the_full_macro_gives(self):
		full = self.run(b.FULL, events())
		for sts in (['app:json', 'app:kv'], ['app:kv', 'gone', 'app:json'], ['gone', 'app:json', 'app:kv']):
			got = self.run(' | '.join(b.compose_units(sts).split(' | ')), events())
			assert got[:3] == full[:3], sts

	def test_events_of_no_unit_are_extracted_as_without_replay(self):
		plain = [visible(e) for e in model().run(PLAIN_REWRITE, events())]
		for sts in (['app:json', 'app:kv'], ['app:kv'], ['gone']):
			got = self.run(b.compose_units(sts), events())
			assert got[3:] == plain[3:], sts

	def test_an_event_of_a_sourcetype_left_out_is_extracted_as_without_replay(self):
		plain = [visible(e) for e in model().run(PLAIN_REWRITE, events())]
		got = self.run(b.compose_units(['app:kv']), events())
		assert got[1:] == plain[1:]


class TestUnitText:
	def test_a_unit_replays_its_sourcetype_only_and_leaves_tags_to_the_tags_macro(self):
		cov = b.coverage(ROWS)
		unit = b.build_unit(STANZAS, 'app:kv', cov['app:kv'], LOOKUP_FIELDS).spl()
		assert 'AND (mvindex(tenx_sourcetype,0)=="app:kv"), mvindex(tenx_sourcetype,0), null())' in unit
		assert 'typer' not in unit and 'tags' not in unit.replace('tag::', '')
		assert '`' not in unit
		# source and host stanzas: only those matching what was recorded for app:kv
		assert '"src"' in unit and '"other source"' not in unit and '"host"' in unit

	def test_the_clearing_step_lists_names_once(self):
		cov = b.coverage(ROWS)
		unit = b.build_unit(STANZAS, 'app:kv', cov['app:kv'], LOOKUP_FIELDS).spl()
		# o is set only by [source::/var/other/*.log], which matches no source recorded for app:kv
		assert 'foreach d_only eventtype h junk k s_junk tag [eval "<<FIELD>>"=if(isnotnull(tenx_rst), null(), \'<<FIELD>>\')]' in unit
		# the full macro keeps one eval assignment per name
		assert 'junk=if(isnotnull(tenx_rst), null(), \'junk\')' in full_macro()

	def test_a_unit_is_smaller_than_the_full_macro(self):
		assert all(len(u) < len(full_macro()) for u in units().values())

	def test_a_quote_in_a_sourcetype_name_is_escaped_and_never_named_in_a_macro_call(self):
		unit = b.build_unit([stanza('x"y', **{'EVAL-a': '1'})], 'x"y', {'sources': set(), 'hosts': set()}).spl()
		assert 'mvindex(tenx_sourcetype,0)=="x\\"y"' in unit and '`' not in unit
		assert b.alias_macro('x"y') is None and re.match(r'^tenx-replay-u[0-9a-f]{12}$', b.unit_macro('x"y'))

	def test_alias_names(self):
		assert b.alias_macro('XmlWinEventLog') == 'tenx-replay-st-XmlWinEventLog'
		for bad in ('demo:kv', 'a.b', 'a b', 'a(b)', 'a`b', 'a$b$', 'a,b', ''):
			assert b.alias_macro(bad) is None, bad

	def test_over_the_size_cap_a_unit_replays_nothing(self):
		cov = b.coverage(ROWS)
		unit = b.build_unit(STANZAS, 'app:kv', cov['app:kv'], LOOKUP_FIELDS, limit=100)
		assert unit.spl() == b.no_op_unit().spl() and 'replays nothing' in unit.warnings[0]

	def test_the_dry_run_runs_units_composed(self):
		u = dict((st, b.build_unit(STANZAS, st, c, LOOKUP_FIELDS)) for st, c in b.coverage(ROWS).items())
		spl = b.units_dry_run(u)
		assert spl.startswith('| makeresults count=3 |') and 'tenx_hide_others=1 | ' + u['app:json'].spl() in spl
		assert 'eval tenx_rprev=tenx_rst | ' + u['app:kv'].spl() + ' | eval tenx_rst=coalesce(tenx_rst, tenx_rprev)' in spl
		assert spl.endswith(' | '.join(b.TAGS_STEPS) + ' | stats count')

	def test_failing_units_are_found_alone(self):
		u = dict((st, b.build_unit(STANZAS, st, c, LOOKUP_FIELDS)) for st, c in b.coverage(ROWS).items())
		calls = []

		def run(spl):
			calls.append(spl)
			return 'boom' if u['app:kv'].spl() in spl else None
		assert b.failing_units(u, run) == {'app:kv': 'boom'}
		assert b.failing_units(u, lambda spl: None) == {}


class TestCoverage:
	def test_sources_hosts_and_indexes_are_recorded(self):
		cov = b.coverage(ROWS)
		assert cov['app:json'] == {'sources': {'/var/other/b.log', '/var/app/a.log'}, 'hosts': {'api-1', 'web-2'},
								   'indexes': {'shared'}}

	def test_what_the_conf_lists_is_kept(self):
		covered = {'app:kv': {'sources': '/old.log', 'hosts': '*', 'indexes': 'old'}, 'plain': 'src1'}
		cov = b.coverage(ROWS, covered)
		assert cov['app:kv']['sources'] == {'/old.log', '/var/app/a.log'}
		assert cov['app:kv']['hosts'] is b.ALL and cov['app:kv']['indexes'] == {'old', 'app'}
		assert cov['plain'] == {'sources': {'src1'}, 'hosts': set(), 'indexes': set()}

	def test_past_the_cap_or_unlistable_a_list_is_every_value(self):
		rows = [('st', 's%d' % i, 'h', 1, 'ix') for i in range(b.MAX_LISTED + 1)]
		assert b.coverage(rows)['st']['sources'] is b.ALL
		assert b.coverage([('st', 'a,b', 'h', 1, 'ix')])['st']['sources'] is b.ALL
		assert b.listed_value(b.ALL) == '*' and b.listed_value({'b', 'a'}) == 'a,b'
		assert b.parse_listed('*') is b.ALL and b.parse_listed('a,b') == {'a', 'b'} and b.parse_listed('') == set()

	def test_unusable_sourcetypes_are_never_covered(self):
		assert b.coverage([('default', 's', 'h', 1, 'i'), ('tenx:narrowing', 's', 'h', 1, 'i'), ('a`b', 's', 'h', 1, 'i')]) == {}

	def test_a_new_host_or_index_starts_a_rebuild(self):
		covered = {'app:kv': {'sources': '/var/app/a.log', 'hosts': 'web-1', 'indexes': 'app'},
				   'every': {'hosts': '*', 'indexes': '*'}}
		assert b.uncovered_values(ROWS[:1], covered) == []
		assert b.uncovered_values([('app:kv', '/var/app/a.log', 'web-3', 1, 'app2')], covered) == [
			('app:kv', 'hosts', 'web-3'), ('app:kv', 'indexes', 'app2')]
		assert b.uncovered_values([('every', 's', 'anything', 1, 'any')], covered) == []
		# a sourcetype not covered at all is uncovered()'s
		assert b.uncovered_values([('new', 's', 'h', 1, 'i')], covered) == []


class TestPrefilterReadsTxf:
	def test_txf_forms(self):
		assert pp.text_after_macro('index=x `txf` error "a b" | stats count') == ' error "a b" '
		assert pp.text_after_macro('index=x `txf(XmlWinEventLog)` EventCode=4625') == ' EventCode=4625'
		assert pp.text_after_macro('index=x `txf(demo:kv)` dept=finance | head 1') == ' dept=finance '

	def test_tx_is_read_as_the_baseline_reads_it(self):
		from support import tenx_prefilter_parser_baseline as baseline_parser
		for search in ('index=x `tx` error | stats count', 'index=x "`tx`" `tx` a', 'index=x `tx`', 'index=x error',
					   'index=x `txfoo` a', 'index=x `tx(1)` a'):
			assert pp.text_after_macro(search) == baseline_parser.text_after_macro(search), search

	def test_other_macros_are_not_read(self):
		assert pp.text_after_macro('index=x `txfoo` a') is None
		assert pp.text_after_macro('index=x "`txf`" a') is None


# ---------------------------------------------------------------------------
# The command, against a fake Splunk REST API, in a child interpreter
# ---------------------------------------------------------------------------

CHILD = r'''
import json, os, sys, types, urllib.parse

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

NS = '/servicesNS/nobody/tenx-for-splunk/'
GLOBAL = {'sharing': 'global', 'perms': {'read': ['*']}}


class FakeSplunk(object):
	"""Just enough of splunkd's REST API for tenxreplay: props, lookups, macros, tenx_replay.conf, oneshot searches."""

	def __init__(self, rows):
		self.rows = rows
		self.macros = {'tenx-replay': 'shipped'}
		self.acl = {}
		self.conf = {}
		self.searches = []
		self.writes = []
		self.dispatches = []

	def rest(self, path, data=None, method=None):
		p = urllib.parse.urlparse(path)
		route, query = p.path, dict(urllib.parse.parse_qsl(p.query))
		if route.startswith(NS + 'saved/searches/') and route.endswith('/dispatch'):
			if getattr(self, 'dispatch_fails', False):
				raise OSError('dispatch refused')
			# the saved search's name, and how many writes this run had made before it
			self.dispatches.append((urllib.parse.unquote(route[len(NS + 'saved/searches/'):-len('/dispatch')]),
									len(self.writes)))
			return {'sid': 'scheduler_test'}
		if route.endswith('/search/jobs'):
			s = data['search']
			self.searches.append((s, data.get('earliest_time')))
			if 'tstats count where' in s and s.rstrip().endswith('by index'):
				# every compact event by index, carrier or not
				counts = dict(getattr(self, 'compact_only', {}))
				for r in self.rows:
					if data['earliest_time'] == '0' or r[5]:
						counts[r[4]] = counts.get(r[4], 0) + r[3]
				return {'results': [{'index': k, 'count': str(v)} for k, v in sorted(counts.items())]}
			if 'tstats count where' in s:
				rows = [r for r in self.rows if data['earliest_time'] == '0' or r[5]]
				if 'tenx_sourcetype="' in s:
					rows = [r for r in rows if 'tenx_sourcetype="%s"' % r[0] in s]
				return {'results': [{'tenx_sourcetype': r[0], 'source': r[1], 'host': r[2], 'count': str(r[3]),
									 'index': r[4]} for r in rows]}
			return {'results': [], 'messages': []}
		if route == NS + 'properties/props/default':
			return {'entry': []}
		if route == NS + 'configs/conf-props':
			return {'entry': [
				{'name': 'app:kv', 'content': {'EVAL-k': '"st"', 'FIELDALIAS-a': 'x AS y'}, 'acl': GLOBAL},
				{'name': 'app:json', 'content': {'EVAL-j': '"json"'}, 'acl': GLOBAL},
				{'name': 'source::.../app/*.log', 'content': {'EVAL-s': '"src"'}, 'acl': GLOBAL},
				{'name': 'host::web-*', 'content': {'EVAL-h': '"host"'}, 'acl': GLOBAL}]}
		if route in (NS + 'data/transforms/lookups', NS + 'configs/conf-transforms', NS + 'configs/conf-fields',
					 '/servicesNS/nobody/-/data/lookup-table-files', '/servicesNS/nobody/-/storage/collections/config'):
			return {'entry': []}
		if route == NS + 'configs/conf-tenx_config/config':
			return {'entry': [{'content': {}}]}
		if route == NS + 'configs/conf-tenx_replay':
			if data is not None:
				name = data.pop('name')
				self.conf[name] = dict(data)
				self.writes.append(('conf+', name))
				return {}
			return {'entry': [{'name': k, 'content': v} for k, v in sorted(self.conf.items())]}
		if route.startswith(NS + 'configs/conf-tenx_replay/'):
			name = urllib.parse.unquote(route.rsplit('/', 1)[1])
			if method == 'DELETE':
				del self.conf[name]
				self.writes.append(('conf-', name))
			else:
				self.conf[name].update(data)
				self.writes.append(('conf~', name))
			return {}
		if route == NS + 'configs/conf-macros':
			if data is not None:
				assert data['name'] not in self.macros, data['name']
				self.macros[data['name']] = data['definition']
				self.writes.append(('macro+', data['name']))
				return {}
			text = query.get('search', '')
			return {'entry': [{'name': k, 'content': {'definition': v}, 'acl': self.acl_of(k)}
							  for k, v in sorted(self.macros.items()) if text in k or text in v]}
		if route.startswith(NS + 'configs/conf-macros/'):
			tail = route[len(NS + 'configs/conf-macros/'):]
			if tail.endswith('/acl'):
				self.acl[urllib.parse.unquote(tail[:-4])] = dict(data)
				return {}
			name = urllib.parse.unquote(tail)
			if method == 'DELETE':
				del self.macros[name]
				self.writes.append(('macro-', name))
				return {}
			if data is not None:
				self.macros[name] = data['definition']
				self.writes.append(('macro~', name))
				return {}
			return {'entry': [{'name': name, 'content': {'definition': self.macros.get(name)}}]}
		raise AssertionError('unexpected REST call %s %s' % (path, data))

	def acl_of(self, name):
		"""A macro's acl as splunkd lists it: app sharing until an ACL write shares it."""
		if name not in self.acl:
			return {'sharing': 'app', 'owner': 'nobody', 'perms': {'read': ['*']}}
		return {'sharing': self.acl[name]['sharing'], 'owner': 'nobody',
				'perms': {'read': self.acl[name]['perms.read'].split(',')}}


def run(fake, earliest='-7d'):
	cmd = tenxreplay.TenxReplayCommand()
	cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
		username='splunk-system-user', splunkd_uri='https://127.0.0.1:8089', session_key='key',
		earliest_time=earliest, latest_time='now'))
	cmd._apply, cmd._only_new, cmd._lookback = True, False, '-7d'
	cmd._rest = fake.rest
	fake.searches, fake.writes = [], []
	return list(cmd.generate())


# (sourcetype, source, host, count, index, in the 7-day lookback)
ROWS = [('app:kv', '/var/app/a.log', 'web-1', 5, 'app', True),
		('app:kv', '/var/app/old.log', 'web-0', 2, 'app_old', False),
		('app:json', '/var/other/b.log', 'api-1', 3, 'shared', True)]
fake = FakeSplunk(ROWS)
fake.macros['tenx-replay-st-app:kv'] = 'an alias whose name is not a valid macro name'
out = {}
rows = run(fake)
out['rows'] = [(r['sourcetype'], r['unit'], r['txf'], r['indexes'], r['written']) for r in rows]
out['all_time'] = [s for s, e in fake.searches if e == '0']
out['writes_first'] = fake.writes
out['macros'] = sorted(fake.macros)
out['acl'] = sorted((k, v['sharing']) for k, v in fake.acl.items())
out['conf'] = fake.conf
out['kv_unit'] = fake.macros[tenxreplay.builder.unit_macro('app:kv')]
out['alias'] = fake.macros.get('tenx-replay-st-app:kv')
run(fake)
out['writes_second'] = fake.writes
# app:json stops: its stanza expires
fake.rows = ROWS[:2]
fake.conf['app:json']['last_seen'] = '1'
run(fake)
out['writes_third'] = fake.writes
out['json_unit'] = fake.macros[tenxreplay.builder.unit_macro('app:json')]
out['no_op'] = tenxreplay.builder.no_op_unit().spl()
print(json.dumps(out))
'''


def test_the_command_writes_units_aliases_and_what_they_cover():
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', CHILD, ROOT, home], capture_output=True, text=True, timeout=120)
	assert proc.returncode == 0, proc.stderr[-3000:]
	out = json.loads(proc.stdout.strip().splitlines()[-1])
	kv, js = b.unit_macro('app:kv'), b.unit_macro('app:json')
	assert out['rows'] == [['app:json', js, 'txf(app:json)', 'shared', 'yes'],
						   ['app:kv', kv, 'txf(app:kv)', 'app,app_old', 'yes']]
	# a colon is not valid in a macro name: no alias; txf(app:kv) reaches the unit through md5
	# both sourcetypes are new, so their sources, hosts and indexes are read over all time once
	assert len(out['all_time']) == 1 and 'tenx_sourcetype="app:json" OR tenx_sourcetype="app:kv"' in out['all_time'][0]
	# units before their aliases, every new macro shared with every app
	writes = [w for w in out['writes_first'] if w[0].startswith('macro')]
	assert writes == [['macro-', 'tenx-replay-st-app:kv']] + [['macro+', n] for n in sorted([js, kv])] + [['macro~', 'tenx-replay']]
	assert out['acl'] == [[n, 'global'] for n in sorted([js, kv])]
	assert out['alias'] is None
	assert out['conf']['app:kv']['hosts'] == 'web-0,web-1' and out['conf']['app:kv']['indexes'] == 'app,app_old'
	assert out['conf']['app:kv']['sources'] == '/var/app/a.log,/var/app/old.log' and out['conf']['app:kv']['unit'] == kv
	# the old source's events get the source stanza; the host stanza applies (web-0, web-1)
	assert '"src"' in out['kv_unit'] and '"host"' in out['kv_unit'] and 'mvindex(tenx_sourcetype,0)=="app:kv"' in out['kv_unit']
	# the next rebuild over the same events writes nothing
	assert out['writes_second'] == []
	# an expired sourcetype loses its stanza; its unit becomes the no-op unit, its alias stays
	assert ['conf-', 'app:json'] in out['writes_third'] and ['macro~', js] in out['writes_third']
	assert out['json_unit'] == out['no_op']


class TestPrefilterReadsTheSettingOnlyWhenItMatters:
	"""A search without a field compared with = or IN, and without a piece field narrowing would
	skip, gets the same prefilter whatever the setting says, so tenxprefilter does not read it."""

	def test_exact(self):
		from test_prefilter_narrowing_opt_in import SEARCHES as OPT_IN_SEARCHES, dictionary
		searches = OPT_IN_SEARCHES + ['error 20:11:45.936', 'payment failed', '"User Data"', 'a OR (b NOT c)']
		allow_all = pp.text_field_predicate([])
		skipped = 0
		for text in searches:
			try:
				tree = pp.Parser(pp.tokenize(text)).parse()
			except pp.Unparsed:
				continue
			if pp.narrowing_matters(tree):
				continue
			skipped += 1
			off = pp.lookup_pieces(tree, text_field=None)
			assert pp.lookup_pieces(tree, text_field=allow_all) == off, text
			d = dictionary(off)
			assert pp.prefilter(tree, d, allow_all) == pp.prefilter(tree, d, None), text
		assert skipped >= 20

	def test_it_matters_for_fields_and_written_forms(self):
		for text in ('user=bob', 'x IN (a, b)', '"20:11:45.936"', 'error user=bob'):
			assert pp.narrowing_matters(pp.Parser(pp.tokenize(text)).parse()), text
		for text in ('error', 'kb>500', 'NOT user=bob', '"payment failed" OR warn'):
			assert not pp.narrowing_matters(pp.Parser(pp.tokenize(text)).parse()), text


class TestTheRewriteReadsTheCoverage:
	"""tenx_util.get_replay_coverage: what get_tenx_config hands the search rewrite."""

	class Stanza(object):
		def __init__(self, name, content):
			self.name, self.content = name, content

	def service(self, conf):
		outer = self

		class Confs(object):
			def __getitem__(self, name):
				if name != 'tenx_replay' or conf is None:
					raise KeyError(name)
				if conf == 'fails':
					raise RuntimeError('HTTP 500')
				return [outer.Stanza(n, c) for n, c in conf.items()]

		class Service(object):
			confs = Confs()
		return Service()

	def test_no_conf_is_no_carrier(self):
		import tenx_util
		assert tenx_util.get_replay_coverage(self.service(None)) == {}
		assert tenx_util.get_replay_coverage(self.service({'default': {}, 'tenx:narrowing': {'fields_not_in_text': 'a'}})) == {}

	def test_unreadable_is_none(self):
		import tenx_util
		assert tenx_util.get_replay_coverage(self.service('fails')) is None

	def test_the_indexes_of_each_sourcetype(self):
		import tenx_util
		got = tenx_util.get_replay_coverage(self.service({'XmlWinEventLog': {'indexes': 'wineventlog', 'sources': 'x'},
														 'demo:kv': {}}))
		assert got == {'XmlWinEventLog': {'indexes': 'wineventlog', 'unit': ''}, 'demo:kv': {'indexes': '', 'unit': ''}}
		# JSON-safe: the search handler logs the config with json.dumps
		json.dumps(got)


class TestNarrowingOffMakesNoRestCall:
	"""With field narrowing off (the default), tenxprefilter reads the setting from the app's
	conf files on disk and makes no REST call for it; its prefilter is the baseline parser's on
	the opt-in test's searches (those without an IPv4 address, which the address rule changes)."""

	def test_the_setting_from_disk(self, tmp_path):
		for d in ('default', 'local'):
			(tmp_path / d).mkdir()
		(tmp_path / 'default' / 'tenx_config.conf').write_text('[config]\nfield_narrowing = false\nother=1\n')
		assert not pp.narrowing_on_disk(str(tmp_path))
		(tmp_path / 'local' / 'tenx_config.conf').write_text('# set by an admin\n[other]\nfield_narrowing = true\n[config]\n field_narrowing = true\n')
		assert pp.narrowing_on_disk(str(tmp_path))
		(tmp_path / 'local' / 'tenx_config.conf').write_bytes(b'\xff\xfe[config')
		assert not pp.narrowing_on_disk(str(tmp_path))
		assert not pp.narrowing_on_disk(str(tmp_path / 'missing'))

	def test_shipped_default_is_off(self):
		assert not pp.narrowing_on_disk(os.path.join(ROOT, 'tenx-for-splunk'))

	def test_off_equals_the_baseline_on_the_opt_in_searches(self):
		from support import tenx_prefilter_parser_baseline as baseline
		from test_prefilter_narrowing_opt_in import SEARCHES as OPT_IN_SEARCHES, dictionary
		compared = 0
		for text in OPT_IN_SEARCHES:
			if pp.addresses_of(text):
				continue
			try:
				tree, mtree = pp.Parser(pp.tokenize(text)).parse(), baseline.Parser(baseline.tokenize(text)).parse()
			except (pp.Unparsed, baseline.Unparsed):
				continue
			text_field = None   # what _text_field() returns with narrowing off: see the command test
			d = dictionary(baseline.lookup_pieces(mtree))
			assert pp.lookup_pieces(tree, text_field=text_field) == baseline.lookup_pieces(mtree), text
			assert pp.prefilter(tree, d, text_field) == baseline.prefilter(mtree, d), text
			compared += 1
		assert compared >= 40
