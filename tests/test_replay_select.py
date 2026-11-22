"""
`txf` replays only the rules that feed the fields the rest of the search reads (tenx_replay_plan.py,
tenx_replay_builder.Selection, macros.conf [tenx-replay-plan]).

On Splunk Enterprise 10.4.3 with the FortiGate add-on (BOTS v1, 100,000 events), field replay was 72-75%
of a `txf` search's indexer CPU, and Splunk's optimizer did not drop replay steps the search never read.
These tests hold the parts that decide correctness:

1. which fields a search reads, and every case where that cannot be told, so the whole replay runs;
2. the rules closed over what they read (a lookup reading a calculated field reading an alias);
3. run through the SPL model, a replay with a plan gives every needed field the value the whole replay
   gives, on every event, and the whole replay runs when no plan, or another macro's plan, is there;
4. field aliases written as one assignment each where that cannot differ, and copied first where it can;
5. the prefilter stores a plan only when the search's events are not kept, and the macros read it back.
"""
import itertools
import json
import re
import os
import subprocess
import sys
import tempfile

import pytest

import tenx_prefilter_parser as p
import tenx_replay_builder as b
import tenx_replay_plan as plan
from support.spl_model import Model, visible

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def needed(search):
	return plan.needed_fields(search, p)


# ---------------------------------------------------------------------------------------------------------
# 1. What a search reads
# ---------------------------------------------------------------------------------------------------------

class TestWhatASearchReads:
	@pytest.mark.parametrize('search, fields', [
		('index=fw `txf` dstip=10.1.2.3 | stats count', {'dstip'}),
		('search index=fw `txf` | stats count by action', {'action'}),
		('index=fw `txf` dest_ip=10.1.2.3 | stats count', {'dest_ip'}),
		('index=fw `txf` | stats count', set()),
		('index=fw `txf` NOT user=bob "failed" | stats dc(src) as n by dest', {'user', 'src', 'dest'}),
		('index=fw `txf` app IN (a, b) | timechart span=1h count by action', {'app', 'action'}),
		('index=fw `txf` | chart count over src by dest', {'src', 'dest'}),
		('index=fw `txf` | top limit=5 action by src', {'action', 'src'}),
		('index=fw `txf` | stats count(eval(bytes>100)) as big, values(dest_ip) by user', {'bytes', 'dest_ip', 'user'}),
		('index=fw `txf` | fields - vendor_action | stats count by action', {'action'}),
		('index=fw `txf` | table a, b', {'a', 'b'}),
		('index=fw `txf` | fields a b | eval c=a', {'a', 'b'}),
		('index=fw `txf` | lookup acts ftnt_action OUTPUT action AS a2 | stats count by a2', {'ftnt_action', 'a2'}),
		('index=fw `txf` | lookup users username AS user OUTPUTNEW dept | stats count by dept', {'user', 'dept'}),
		('index=fw `txf` | rex field=dest_ip "^(?<o1>\\d+)\\." | stats count by o1', {'dest_ip', 'o1'}),
		('index=fw `txf` | rex "user=(?<u>\\w+)" | stats count by u', {'_raw', 'u'}),
		('index=fw `txf` | spath input=payload path=a output=b | stats count by b', {'payload', 'b'}),
		('index=fw `txf` | rename dest_ip AS d | stats count by d', {'dest_ip', 'd'}),
		('index=fw `txf` | dedup src sortby -_time | sort - count | head 5 | table src', {'src', '_time', 'count'}),
		('index=fw `txf` | bin _time span=1h | stats count by _time', {'_time'}),
		('index=fw `txf` | fillnull value=0 bytes | streamstats sum(bytes) as s | stats max(s)', {'bytes', 's'}),
		('index=fw `txf` | mvexpand dest | stats count by dest', {'dest'}),
		('index=fw `txf` TERM(10.1.2.3) CASE(Error) | stats count', set()),
		('index=fw `txf` | stats count by action | append [search index=z]', None),
		# a macro name inside quotes is text
		('index=fw `txf` | stats count by action | eval s="`txf`"', {'action'}),
	])
	def test_the_fields(self, search, fields):
		assert needed(search) == fields

	def test_eval_and_where_read_every_name_they_hold(self):
		# function names are taken as fields too: that only replays more
		got = needed('index=fw `txf` | eval x=coalesce(src_ip, \'dest port\') | where len(user)>2 | stats count by x')
		assert {'src_ip', 'dest port', 'user', 'x'} <= got <= {'src_ip', 'dest port', 'user', 'x', 'coalesce', 'len'}

	@pytest.mark.parametrize('search', [
		# the search returns its events: every field of them is part of the result
		'index=fw `txf` dstip=10.1.2.3',
		'index=fw `txf` | fields - srcip',
		'index=fw `txf` | eval x=1 | where x=1',
		'index=fw `txf` | head 10',
		# wildcards
		'index=fw `txf` | table *',
		'index=fw `txf` | fields *',
		'index=fw `txf` | fields dest*',
		'index=fw `txf` | stats values(*) as *',
		'index=fw `txf` dest*=10.1.2.3 | stats count',
		'index=fw `txf` | stats count by dest*',
		'index=fw `txf` | fillnull value=0 | stats count by a',
		# event types and tags read every field
		'index=fw `txf` tag=network | stats count',
		'index=fw `txf` eventtype=fw_traffic | stats count',
		'index=fw `txf` | stats count by tag::action',
		'index=fw `txf` | stats count by eventtype',
		# commands this module does not read
		'index=fw `txf` | iplocation src | stats count by Country',
		'index=fw `txf` | transaction src | stats count',
		'index=fw `txf` | lookup acts ftnt_action | stats count by action',
		'index=fw `txf` | where searchmatch("dest_ip=10.1.2.3") | stats count',
		'index=fw `txf` | eval {name}=value | stats count',
		'index=fw `txf` | timechart count by action where max in top5',
		'index=fw `txf` | streamstats reset_after="(x>1)" count | stats max(count)',
		# subsearches, macros, more than one macro call, anything but plain search terms before txf
		'index=fw `txf` [| inputlookup ips | fields dest_ip] | stats count',
		'index=fw `txf` | stats count by action | appendcols [search index=x | stats count]',
		'index=fw `txf` | `my_macro` | stats count',
		'index=fw `txf` x=1 | append [search index=fw `txf` y=1] | stats count',
		'| multisearch [search index=fw `txf` a] [search index=fw b] | stats count',
		'| union [search index=fw `txf` a] [search index=fw b] | stats count',
		'index=a [| inputlookup t] `txf` | stats count',
		'search index=a | search `txf` x=1 | stats count',
		# saved searches and data models: the macro is not in the search's text
		'| savedsearch "fw report"',
		'| datamodel Network_Traffic All_Traffic search | stats count by All_Traffic.action',
		'| tstats summariesonly=false count from datamodel=Network_Traffic by All_Traffic.action',
		'| from datamodel:Network_Traffic.All_Traffic | stats count',
		# another macro: tx runs no replay; txf(<sourcetype>) runs its own unit
		'index=fw `tx` x | stats count',
		'index=fw `txf(fortigate_traffic)` dstip=10.1.2.3 | stats count',
		# not readable
		'index=fw `txf` | stats count by "a b"',
		# a single quote read as a field name's or as a character cuts the commands differently
		"index=fw `txf` user=o'brien | eval x='dest port' | stats count by x",
		"index=fw `txf` | where 'a|b'=1 | stats count",
		'index=fw `txf` "unclosed | stats count',
		'',
		None,
	])
	def test_the_whole_replay_runs(self, search):
		assert needed(search) is None, search

	def test_expression_fields_are_taken_widely(self):
		assert plan.expression_fields('if(isnull(a), "b c", \'d e\') . f') >= {'a', 'd e', 'f'}
		assert 'b' not in plan.expression_fields('"b"')
		with pytest.raises(plan.Unknown):
			plan.expression_fields('searchmatch("x=1")')
		with pytest.raises(plan.Unknown):
			plan.expression_fields('{x}')


# ---------------------------------------------------------------------------------------------------------
# 2. Closed over what the rules read
# ---------------------------------------------------------------------------------------------------------

TABLE = [[1, ['dest_ip'], ['dstip'], False],
		 [2, ['vendor_action'], ['action'], False],
		 [3, ['ftnt_action'], ['utmaction', 'vendor_action', 'vendor_status'], False],
		 [4, ['action'], ['ftnt_action'], False],
		 [5, ['vendor_status'], ['status'], True],
		 [6, ['x'], ['*'], False]]


class TestClosure:
	def test_a_lookup_reading_a_calculated_field_reading_aliases(self):
		assert plan.closure(TABLE, {'action'}) == {4, 3, 2, 5, plan.SHARED}

	def test_only_what_feeds_the_fields(self):
		assert plan.closure(TABLE, {'dest_ip'}) == {1}
		assert plan.closure(TABLE, {'dstip'}) == set()
		assert plan.closure(TABLE, set()) == set()

	def test_names_compare_without_case(self):
		assert plan.closure(TABLE, {'Dest_IP'}) == {1}

	def test_a_rule_whose_reads_are_not_known_means_the_whole_replay(self):
		assert plan.closure(TABLE, {'x'}) is None

	def test_the_flags_name_each_rule_once(self):
		value = plan.flags('0a1b2c3d', {4, 3, 12})
		assert value == 'tenx_ndm0a1b2c3d tenx_nd0a1b2c3d_3_4_12_'
		import fnmatch
		flag = value.split()[1]
		for rid in (3, 4, 12):
			assert fnmatch.fnmatchcase(flag, 'tenx_nd0a1b2c3d*_%d_*' % rid)
		for rid in (1, 2, 0, 13):
			assert not fnmatch.fnmatchcase(flag, 'tenx_nd0a1b2c3d*_%d_*' % rid)
		# the all-flag and the marker match no rule's guard, and a flag of another generation neither
		assert not fnmatch.fnmatchcase('tenx_ndall', 'tenx_nd0a1b2c3d*_3_*')
		assert not fnmatch.fnmatchcase('tenx_ndm0a1b2c3d', 'tenx_nd0a1b2c3d*_3_*')
		assert not fnmatch.fnmatchcase('tenx_nd99999999_3_', 'tenx_nd0a1b2c3d*_3_*')

	def test_only_the_parts_of_the_searched_sourcetypes_count(self):
		table = [[1, ['dest'], ['host_a', 'Computer'], False, [[['aws:cloudtrail'], ['dest'], ['host_a']],
															   [['XmlWinEventLog'], ['dest'], ['Computer']]]],
				 [2, ['Computer'], ['*'], False, [[['XmlWinEventLog'], ['Computer'], ['*']]]],
				 [3, ['host_a'], ['h'], False, [['*', ['host_a'], ['h']]]],
				 [4, ['src'], ['srcip'], False, [[['XmlWinEventLog'], ['src'], ['srcip']]]]]
		assert plan.closure(table, {'dest'}) is None
		assert plan.closure(table, {'dest'}, {'aws:cloudtrail'}) == {1, 3}
		assert plan.closure(table, {'src'}, {'aws:cloudtrail'}) == set()
		assert plan.closure(table, {'dest'}, {'aws:cloudtrail', 'XmlWinEventLog'}) is None
		# a rule written before the table held its parts counts whole
		assert plan.closure([r[:4] for r in table], {'dest'}, {'aws:cloudtrail'}) is None

	def test_the_parts_read_back(self):
		rules = [[1, ['a'], ['b'], False, [['*', ['a'], ['b']], [['st1', 'st2'], ['a'], []]]]]
		entry = {'generation': '0a1b2c3d', 'rules': json.dumps(rules)}
		assert plan.read_table(entry) == ('0a1b2c3d', [(1, ['a'], ['b'], False, [('*', ['a'], ['b']), (['st1', 'st2'], ['a'], [])])])
		for bad in ([[1, ['a'], ['b'], False, [['x', ['a'], ['b']]]]], [[1, ['a'], ['b'], False, [[[1], ['a'], ['b']]]]]):
			assert plan.read_table({'generation': '0a1b2c3d', 'rules': json.dumps(bad)}) is None

	def test_the_table_as_written_and_read(self):
		entry = {'generation': '0a1b2c3d', 'rules': json.dumps(TABLE)}
		assert plan.read_table(entry) == ('0a1b2c3d', [tuple(r[:3]) + (r[3],) for r in TABLE])
		for bad in ({}, {'generation': 'zz', 'rules': '[]'}, {'generation': '0a1b2c3d', 'rules': 'x'},
					{'generation': '0a1b2c3d', 'rules': '[[1, ["a"]]]'}, {'generation': '0a1b2c3d', 'rules': '{}'}):
			assert plan.read_table(bad) is None

	def test_no_table_or_most_rules_means_the_whole_replay(self):
		table = ('0a1b2c3d', TABLE)
		assert plan.plan_value(None, {'dest_ip'}) is None
		assert plan.plan_value(table, None) is None
		assert plan.plan_value(table, {'dest_ip'}) == 'tenx_ndm0a1b2c3d tenx_nd0a1b2c3d_1_'
		assert plan.plan_value(table, {'action', 'dest_ip'}) is None   # 5 of 6 rules


# ---------------------------------------------------------------------------------------------------------
# 3. Run through the SPL model
# ---------------------------------------------------------------------------------------------------------

def stanza(name, **rules):
	return b.Stanza(name, dict(rules), {})


STANZAS = [
	stanza('default', **{'EVAL-d': '"dflt"', 'FIELDALIAS-dh': 'host AS dvc'}),
	stanza('fw:traffic', **{'FIELDALIAS-dest': 'dstip AS dest_ip', 'FIELDALIAS-vact': 'action AS vendor_action',
							'FIELDALIAS-vstat': 'vstat AS vendor_status', 'FIELDALIAS-both': 'srcport AS src_port dstport AS dest_port',
							'EVAL-ftnt_action': 'coalesce(utmaction, vendor_action, vendor_status)',
							'EVAL-tcp_flag': 'if(vendor_action=="rst", "RST", tcp_flag)',
							'EVAL-proto': 'lower(service)',
							'LOOKUP-act': 'acts ftnt_action OUTPUT action',
							'LOOKUP-zone': 'zones dest_ip OUTPUTNEW zone AS dest_zone'}),
	stanza('fw:utm', **{'FIELDALIAS-vact': 'action AS vendor_action', 'EVAL-ftnt_action': 'coalesce(vendor_action, vendor_status)',
						'LOOKUP-act': 'acts ftnt_action OUTPUT action', 'FIELDALIAS-dest': 'dstip AS dest_ip'}),
	stanza('source::.../fw/*.log', **{'EVAL-src_kind': '"file"', 'FIELDALIAS-srcalias': 'srcip AS src_ip',
									  'EVAL-proto': '"from source"'}),
	stanza('host::FW-*', **{'EVAL-h': '"host"', 'LOOKUP-act': 'acts ftnt_action OUTPUT action'}),
]
PRESENT = [('fw:traffic', '/var/fw/a.log', 'fw-1'), ('fw:utm', '/var/other/b.log', 'api-1')]
LOOKUPS = {'acts': ['ftnt_action', 'action'], 'zones': ['dest_ip', 'zone']}
TABLES = {'acts': [{'ftnt_action': 'accept', 'action': 'allowed'}, {'ftnt_action': 'deny', 'action': 'blocked'},
				   {'ftnt_action': 'rst', 'action': 'teardown'}],
		  'zones': [{'dest_ip': '10.0.0.1', 'zone': 'dmz'}]}


def extract(event, _):
	if not event.get('_kv') and event.get('_raw'):
		event.update(event.get('__text_fields', {}))


def replayed(st, source='/var/fw/a.log', host='fw-1', **text_fields):
	return {'_raw': 'expanded', 'tenx_compact_raw': '~h,1', 'sourcetype': 'tenx_encoded', 'tenx_sourcetype': st,
			'source': source, 'host': host, '_kv': 1, '__text_fields': text_fields}


def events():
	return [
		replayed('fw:traffic', action='accept', dstip='10.0.0.1', srcip='1.1.1.1', srcport='5', dstport='53', service='DNS'),
		replayed('fw:traffic', action='rst', dstip='10.0.0.2', vstat='close', tcp_flag='S'),
		replayed('fw:traffic', source='/var/other/c.log', host='FW-9', vstat='deny', dstip='10.0.0.1', service='HTTP'),
		replayed('fw:utm', action='deny', utmaction='x', dstip='10.0.0.3'),
		replayed('fw:utm', host='fw-2', vstat='accept'),
		# not replayed: no original sourcetype; keeps what it has
		{'_raw': 'plain', 'sourcetype': 'tenx_encoded', 'source': '/var/fw/z.log', 'host': 'fw-1', 'action': 'kept',
		 'dest_ip': 'kept'},
	]


def run(replay, plan_fields=None, evs=None):
	model = Model(commands={'extract': extract, 'typer': lambda e, _: None, 'tags': lambda e, _: None}, lookups=TABLES)
	evs = evs if evs is not None else events()
	for e in evs:
		for f in (plan_fields or '').split():
			e[f] = '1'
	return [visible(e) for e in model.run(replay.spl(), evs)]


def selected():
	return b.build(STANZAS, PRESENT, LOOKUPS, select=True)


def outputs(table):
	return sorted(set(f for rule in table for f in rule[1]))


class TestTheModel:
	def test_the_whole_replay_is_the_same_with_and_without_guards(self):
		full = run(b.build(STANZAS, PRESENT, LOOKUPS))
		guarded = run(selected())
		assert guarded == full
		assert full[0]['dest_ip'] == '10.0.0.1' and full[0]['action'] == 'allowed' and full[0]['dest_zone'] == 'dmz'

	@pytest.mark.parametrize('fields', [set()] + [{f} for f in
		('dest_ip', 'action', 'ftnt_action', 'tcp_flag', 'src_ip', 'dest_zone', 'proto', 'h', 'd', 'dvc', 'src_kind',
		 'vendor_status', 'dest_port', 'dstip')] + [{'action', 'dest_ip'}, {'proto', 'src_port'}])
	def test_every_needed_field_has_the_whole_replays_value(self, fields):
		replay = selected()
		generation, table = replay.selection
		value = plan.flags(generation, plan.closure(table, fields))
		full, part = run(replay), run(replay, value)
		for whole, mine in zip(full, part):
			for f in fields:
				assert mine.get(f) == whole.get(f), (fields, f, whole, mine)
			# nothing the plan names is left on the event, and the event not replayed is untouched
			assert not [k for k in mine if k.startswith('tenx_nd')]
		assert part[-1] == full[-1]

	def test_rules_the_search_does_not_read_do_not_run(self):
		replay = selected()
		generation, table = replay.selection
		part = run(replay, plan.flags(generation, plan.closure(table, {'dest_ip'})))
		assert part[0]['dest_ip'] == '10.0.0.1'
		assert 'ftnt_action' not in part[0] and 'dest_zone' not in part[0] and 'd' not in part[0]
		# action stays as extracted: its lookup did not run
		assert part[0]['action'] == 'accept'

	def test_a_plan_of_another_macro_runs_the_whole_replay(self):
		replay = selected()
		generation, table = replay.selection
		other = '0' * 8 if generation != '0' * 8 else '1' * 8
		assert run(replay, plan.flags(other, {1})) == run(replay)

	def test_no_plan_stored_runs_the_whole_replay(self):
		replay = selected()
		assert run(replay, 'tenx_ndnone tenx_ndnoplan') == run(replay)

	def test_the_generation_follows_the_rules(self):
		one, two = selected(), selected()
		assert one.selection[0] == two.selection[0] and one.spl() == two.spl()
		changed = b.build(STANZAS[:-1], PRESENT, LOOKUPS, select=True)
		assert changed.selection[0] != one.selection[0]
		assert ('tenx_nd%s*_' % one.selection[0]) in one.spl() and b.GEN not in one.spl()

	def test_the_table_lists_each_rule_once_with_what_it_reads(self):
		generation, table = selected().selection
		by_writes = dict((tuple(w), (r, s)) for _, w, r, s, _ in table)
		assert by_writes[('action',)] == (['ftnt_action'], True)   # the host:: stanza's candidate is tested
		assert set(by_writes[('ftnt_action',)][0]) >= {'utmaction', 'vendor_action', 'vendor_status'}
		assert by_writes[('dest_zone',)][0] == ['dest_ip', 'dest_zone']   # OUTPUTNEW reads its output
		assert by_writes[('src_ip',)][1] is True
		assert outputs(table) == ['action', 'd', 'dest_ip', 'dest_port', 'dest_zone', 'dvc', 'ftnt_action', 'h',
								  'proto', 'src_ip', 'src_kind', 'src_port', 'tcp_flag', 'vendor_action', 'vendor_status']

	def test_each_part_names_the_sourcetypes_its_stanza_applies_to(self):
		generation, table = selected().selection
		by_writes = dict((tuple(w), parts) for _, w, _, _, parts in table)
		assert sorted(o for o, _, _ in by_writes[('ftnt_action',)]) == [['fw:traffic'], ['fw:utm']]
		traffic = [r for o, _, r in by_writes[('ftnt_action',)] if o == ['fw:traffic']][0]
		assert set(traffic) >= {'utmaction', 'vendor_action', 'vendor_status'}
		assert ['*', ['action'], ['ftnt_action']] in by_writes[('action',)]
		assert by_writes[('d',)] == [['*', ['d'], []]]

	def test_a_plan_for_one_sourcetype_replays_as_the_whole_replay_on_its_events(self):
		replay = selected()
		generation, table = replay.selection
		ids = plan.closure(table, {'ftnt_action'}, {'fw:utm'})
		assert ids is not None and ids != plan.closure(table, {'ftnt_action'})
		got = run(replay, plan.flags(generation, ids))
		whole = run(replay)
		for g, w in zip(got, whole):
			if g.get('tenx_sourcetype') == 'fw:utm':
				assert g.get('ftnt_action') == w.get('ftnt_action')

	def test_units_and_the_unselected_macro_carry_no_guard(self):
		assert 'foreach tenx_nd' not in b.build(STANZAS, PRESENT, LOOKUPS).spl()
		assert b.build(STANZAS, PRESENT, LOOKUPS).selection is None
		cov = b.coverage([('fw:traffic', '/var/fw/a.log', 'fw-1', 5, 'fw')])
		units = b.build_units(STANZAS, cov, ['fw:traffic'], LOOKUPS)
		assert 'tenx_nd' not in units['fw:traffic'].spl() and 'typer' not in units['fw:traffic'].spl()

	def test_commands_at_the_top_level_grow_by_two(self):
		plain, guarded = b.build(STANZAS, PRESENT, LOOKUPS).spl(), selected().spl()
		assert b.top_level_commands(guarded) == b.top_level_commands(plain) + 2


# ---------------------------------------------------------------------------------------------------------
# 4. Field aliases: one assignment where it cannot differ
# ---------------------------------------------------------------------------------------------------------

class TestAliasesWrittenOnce:
	def test_one_assignment_each_when_no_alias_reads_another(self):
		spl = b.build(STANZAS, PRESENT, LOOKUPS).spl()
		assert 'tenx_ra' not in spl and 'tenx_rw' not in spl
		assert "dest_ip=if(isnotnull(tenx_go1z), 'dstip', 'dest_ip')" in spl

	@pytest.mark.parametrize('rules', [
		{'FIELDALIAS-a': 'x AS y', 'FIELDALIAS-b': 'y AS z'},           # an alias of an alias's field
		{'FIELDALIAS-a': 'x AS y', 'FIELDALIAS-b': 'w AS y'},           # one field, two classes
		{'FIELDALIAS-a': 'x AS Y', 'FIELDALIAS-b': 'y AS z'},           # names compared without case
	])
	def test_copied_first_where_order_could_matter(self, rules):
		stanzas = [stanza('st', **rules)]
		spl = b.build(stanzas, [('st', 's', 'h')]).spl()
		assert 'tenx_ra0_0' in spl and 'tenx_rw0' in spl

	@pytest.mark.parametrize('rules', [
		{'FIELDALIAS-a': 'x AS y', 'FIELDALIAS-b': 'y AS z'},
		{'FIELDALIAS-a': 'x AS y', 'FIELDALIAS-b': 'w AS y'},
		{'FIELDALIAS-a': 'x AS y z ASNEW q', 'FIELDALIAS-b': 'w AS v'},
		{'FIELDALIAS-a': 'x ASNEW y', 'FIELDALIAS-b': 'w AS v'},
	])
	def test_both_forms_give_splunks_values(self, rules):
		# every alias reads the values from before any alias ran; AS removes the alias when the original
		# has none; ASNEW only sets an alias that has no value
		stanzas = [stanza('st', **rules), stanza('source::s', **{'FIELDALIAS-a': 'x AS y'}) if 'ASNEW' in str(rules) else
				   stanza('other', **{})]
		present = [('st', 's', 'h'), ('st', 't', 'h')]
		evs = [replayed('st', source=src, host='h', x='X', y='Y', w='W', z=None) for src in ('s', 't')] + [
			replayed('st', source='t', host='h', y='Y')]
		for e in evs:
			e['__text_fields'] = dict((k, v) for k, v in e['__text_fields'].items() if v is not None)
		out = run(b.build(stanzas, present), evs=evs)
		expected = []
		for e in evs:
			f = dict(e['__text_fields'])
			before = dict(f)
			winners = rules if e['source'] != 's' or 'ASNEW' not in str(rules) else dict(rules, **{'FIELDALIAS-a': 'x AS y'})
			for key in sorted(winners):
				toks = winners[key].split()
				for i in range(0, len(toks), 3):
					orig, mode, alias = toks[i:i + 3]
					if mode == 'AS':
						if before.get(orig) is None:
							f.pop(alias, None)
						else:
							f[alias] = before[orig]
					elif f.get(alias) is None and before.get(orig) is not None:
						f[alias] = before[orig]
			expected.append(f)
		for got, want in zip(out, expected):
			for k in set(want) | {'y', 'z', 'v', 'q'}:
				assert got.get(k) == want.get(k), (rules, k, got, want)


# ---------------------------------------------------------------------------------------------------------
# 5. The prefilter stores a plan, and the macros read it back
# ---------------------------------------------------------------------------------------------------------

STORE = r"""
import json, os, sys, types
root, home, search, job, table, fail = sys.argv[1:7]
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
real = tenx_prefilter.parser.conf_stanzas
tenx_prefilter.parser.conf_stanzas = lambda paths: json.loads(table) if any(x.endswith('tenx_replay.conf') for x in paths) else real(paths)
cmd = tenx_prefilter.TenxPrefilterCommand()
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	sid='subsearch_1794937815.59_1794937816.89', username='admin', earliest_time=0, latest_time=0,
	splunkd_uri='https://127.0.0.1:8089', session_key='key'))
stored, warnings = [], []
def rest(path, data=None, answer=True, method=None):
	if path.startswith('/services/search/jobs/1794937815.59') and not data:
		content = dict(json.loads(job), search=search)
		return {'entry': [{'content': content}]}
	if path.startswith('/services/search/jobs/1794937815.59') and data:
		if fail == '1':
			raise OSError('refused')
		stored.append(data)
		return None
	return {'results': []}
cmd._rest = rest
cmd._store_check = lambda: True
cmd._record_checks = lambda macro: None
cmd._original_sourcetype_rows = lambda tree: ([], '`txf`')
cmd._without_words = lambda prefilter: prefilter
cmd.write_warning = warnings.append
rows = list(cmd.generate())
print(json.dumps({'rows': rows, 'stored': stored, 'warnings': warnings}))
"""

PLAN_TABLE = {'tenx:plan': {'generation': '0a1b2c3d', 'rules': json.dumps(TABLE)}}


def store(search, job=None, table=PLAN_TABLE, fail=False):
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', STORE, ROOT, home, search, json.dumps(job or {'statusBuckets': 0}),
							   json.dumps(table), '1' if fail else '0'], capture_output=True, text=True, timeout=60)
	assert proc.returncode == 0, proc.stderr[-3000:]
	return json.loads(proc.stdout.strip().splitlines()[-1])


class TestThePrefilterStoresThePlan:
	def test_a_search_that_reads_one_field(self):
		out = store('search index=fw `txf` dest_ip=10.0.0.1 | stats count')
		assert out['stored'] == [{'custom.tenx_replay_plan': 'tenx_ndm0a1b2c3d tenx_nd0a1b2c3d_1_ tenx_ndnotags'}]
		assert out['warnings'] == []

	def test_with_a_word_plan_in_one_request(self):
		out = store('search index=fw `txf` Se*Privilege dest_ip=10.0.0.1 | stats count')
		assert len(out['stored']) == 1 and sorted(out['stored'][0]) == [
			'custom.tenx_replay_plan', 'custom.tenx_wild_marks', 'custom.tenx_wild_search']

	def test_a_plan_not_stored_runs_the_whole_replay_quietly(self):
		# only a word plan that could not be stored changes what the search matches, and says so
		assert store('search index=fw `txf` dest_ip=10.0.0.1 | stats count', fail=True)['warnings'] == []
		warned = store('search index=fw `txf` Se*Privilege | stats count', fail=True)['warnings']
		assert len(warned) == 1 and 'wildcard inside it' in warned[0]

	@pytest.mark.parametrize('job', [{'statusBuckets': 300}, {'statusBuckets': '300'}, {'request': {}},
									 {'statusBuckets': 0, 'request': {'adhoc_search_level': 'verbose'}}])
	def test_none_when_splunk_keeps_the_events(self, job):
		assert store('search index=fw `txf` dest_ip=10.0.0.1 | stats count', job)['stored'] == []

	@pytest.mark.parametrize('table', [{}, {'tenx:plan': {'generation': 'x', 'rules': '[]'}}])
	def test_without_a_table_only_event_types_and_tags_are_left_out(self, table):
		stored = store('search index=fw `txf` dest_ip=10.0.0.1 | stats count', table=table)['stored']
		assert stored == [{'custom.tenx_replay_plan': plan.NOTAGS}]

	@pytest.mark.parametrize('search', ['search index=fw `txf` dest_ip=10.0.0.1',
										'search index=fw `tx` dest_ip=10.0.0.1 | stats count',
										'search index=fw `txf` x | append [search index=fw `txf` y] | stats count',
										'search index=fw `txf` tag=network | stats count'])
	def test_none_when_the_search_cannot_be_read(self, search):
		assert store(search)['stored'] == []


PARTS_TABLE = [[1, ['dest'], ['host_a', 'Computer'], False, [[['aws:cloudtrail'], ['dest'], ['host_a']],
															  [['XmlWinEventLog'], ['dest'], ['Computer']]]],
			   [2, ['Computer'], ['*'], False, [[['XmlWinEventLog'], ['Computer'], ['*']]]],
			   [3, ['host_a'], ['h'], False, [['*', ['host_a'], ['h']]]],
			   [4, ['src'], ['s'], False, [[['XmlWinEventLog'], ['src'], ['s']]]],
			   [5, ['x'], ['y'], False, [[['XmlWinEventLog'], ['x'], ['y']]]]]
RECORDED = {'tenx:plan': {'generation': '0a1b2c3d', 'rules': json.dumps(PARTS_TABLE)},
			'aws:cloudtrail': {'indexes': 'ct'}, 'XmlWinEventLog': {'indexes': 'win'}, 'tenx:nocarrier': {'indexes': 'app'}}


class TestThePlanClosesOverTheSearchedSourcetypes:
	"""
	A rule of the replay can come from several add-ons' stanzas. Closed over every stanza, a field one
	sourcetype computes plainly can lead to another add-on's rule that reads fields that cannot be listed,
	and the whole replay runs. The plan counts only the stanzas of the sourcetypes tenxreplay recorded in the
	indexes the search is bound to.
	"""

	def test_the_indexes_a_search_is_bound_to(self):
		assert plan.bounding_indexes('index=ct ', p) == ['ct']
		assert plan.bounding_indexes('index=ct OR index=win ', p) == ['ct', 'win']
		assert plan.bounding_indexes('earliest=-1h (index=ct OR index=w*) sourcetype=x ', p) == ['ct', 'w*']
		assert plan.bounding_indexes('index IN (ct, win) ', p) == ['ct', 'win']
		for before in ('index=ct OR host=h ', 'NOT index=ct ', 'host=h ', '', '"unclosed '):
			assert plan.bounding_indexes(before, p) is None, before

	def test_the_sourcetypes_recorded_for_them(self):
		assert plan.searched_sourcetypes(RECORDED, ['ct']) == {'aws:cloudtrail'}
		assert plan.searched_sourcetypes(RECORDED, ['CT', 'app']) == {'aws:cloudtrail'}
		assert plan.searched_sourcetypes(RECORDED, ['app']) == set()
		assert plan.searched_sourcetypes(RECORDED, ['*']) == {'aws:cloudtrail', 'XmlWinEventLog'}
		# an index the record does not know may hold any sourcetype
		for indexes in (None, [], ['other'], ['ct', 'other'], ['o*']):
			assert plan.searched_sourcetypes(RECORDED, indexes) is None, indexes
		assert plan.searched_sourcetypes(dict(RECORDED, x={'indexes': '*'}), ['ct']) == {'aws:cloudtrail', 'x'}

	def test_the_prefilter_stores_the_plan_of_those_sourcetypes(self):
		out = store('search index=ct `txf` dest=a | stats count', table=RECORDED)
		assert out['stored'] == [{'custom.tenx_replay_plan': 'tenx_ndm0a1b2c3d tenx_nd0a1b2c3d_1_3_ tenx_ndnotags'}]

	@pytest.mark.parametrize('search', ['search index=ct OR host=x `txf` dest=a | stats count',
										'search index=other `txf` dest=a | stats count',
										'search index=ct OR index=win `txf` dest=a | stats count'])
	def test_the_whole_replay_where_another_sourcetype_can_be_read(self, search):
		assert store(search, table=RECORDED)['stored'] == [{'custom.tenx_replay_plan': plan.NOTAGS}]


class TestTxfOfASourcetypeLeavesOutTagsNoOneReads:
	"""
	txf(<sourcetype>) runs its sourcetype's unit whole, then event types and tags (tenx-replay-tags: `typer`
	and `tags` on every replayed event). A search that reads no event type and no tag, told by the same
	rules as the plan of plain `txf`, stores tenx_ndnotags, and tenx-replay-tags leaves those two out.
	"""

	DETECTION = ('search index=ct `txf(aws:cloudtrail)` sourcetype=aws:cloudtrail eventName=DeletePolicy DeletePolicy '
				 '(userAgent!=*.amazonaws.com) | rename user_name as user | stats count min(_time) as firstTime max(_time) as '
				 'lastTime BY signature dest user user_agent src vendor_account vendor_region vendor_product | convert '
				 'timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) | search *')

	def test_a_detection_that_counts_stores_it(self):
		out = store(self.DETECTION)
		assert out['stored'] == [{'custom.tenx_replay_plan': plan.NOTAGS}]
		assert re.match(r"^tenx_nd[A-Za-z0-9_ ]+$", plan.NOTAGS)

	@pytest.mark.parametrize('search', ['search index=ct `txf(aws:cloudtrail)` tag=authentication | stats count',
										'search index=ct `txf(aws:cloudtrail)` | stats count by eventtype',
										'search index=ct `txf(aws:cloudtrail)` | stats values(*) as *',
										'search index=ct `txf(aws:cloudtrail)` eventName=ConsoleLogin',
										'search index=ct `txf(aws:cloudtrail)` x | append [search index=ct y] | stats count',
										'search index=ct `txf(aws:cloudtrail)` x | `some_macro` | stats count'])
	def test_not_when_a_tag_may_be_read_or_events_are_returned(self, search):
		assert plan.tags_skipped(search, p) is False
		assert store(search)['stored'] == []

	def test_not_when_splunk_keeps_the_events(self):
		assert store(self.DETECTION, {'statusBuckets': 300})['stored'] == []

	def test_plain_txf_and_tx_are_not_read_this_way(self):
		assert plan.tags_skipped('search index=fw `txf` | stats count', p) is False
		assert plan.tags_skipped('search index=fw `tx` | stats count', p) is False

	def test_the_tags_step_is_gated_and_the_rewrite_never_sets_the_gate(self):
		d = macros().get('tenx-replay-tags', 'definition')
		assert d.startswith('eval tenx_go0z=if(isnotnull(tenx_rst) AND isnull(tenx_ndnotags),1,null()) | foreach tenx_go0z*')
		assert ' | '.join(b.TAGS_STEPS) == d
		import glob
		for f in glob.glob(os.path.join(ROOT, 'tenx-for-splunk', 'bin', '*.py')):
			if os.path.basename(f) in ('tenx_replay_plan.py', 'tenx_replay_builder.py'):
				continue
			assert 'ndnotags' not in open(f).read(), f

	def test_the_plan_gives_typer_its_event_types(self):
		assert 'typer ' + b.plan_switch('', 'eventtypes=tenx_no_event_type') in macros().get('tenx-replay-tags', 'definition')
		switch = b.plan_switch('ON', 'OFF')
		# the same read of the plan as tenx-replay-plan, and the flag only when the plan is field names
		plan_step = macros().get('tenx-replay-plan', 'definition')
		assert switch[:switch.index('| fields custom.tenx_replay_plan')] in plan_step
		test = re.search(r'eval search=if\((.*), "OFF", "ON"\)', switch).group(1)
		assert test == ('match(\'custom.tenx_replay_plan\', "^tenx_nd[A-Za-z0-9_ ]+$") AND '
						'match(\'custom.tenx_replay_plan\', "(^| )tenx_ndnotags( |$)")')
		for value, off_ in (('tenx_ndnotags', True), ('tenx_ndm0a1b2c3d tenx_nd0a1b2c3d_1_ tenx_ndnotags', True),
							('tenx_ndm0a1b2c3d tenx_nd0a1b2c3d_1_', False), ('tenx_ndnotagsx', False),
							('tenx_ndnotags | delete', False), ('', False)):
			got = bool(re.match(r"^tenx_nd[A-Za-z0-9_ ]+$", value)) and bool(re.search(r"(^| )tenx_ndnotags( |$)", value))
			assert got == off_, value

	def test_the_tags_step_of_plain_txf_is_closed_the_same_way(self):
		assert plan.NOTAGS == 'tenx_ndnotags'
		spl = selected().spl()
		assert 'foreach tenx_ndall* fieldstr="@@TENXN@@" matchstr="@@TENXO@@" [' + ' | '.join(b.TAGS_STEPS) + ']' in spl


def macros():
	import configparser
	conf = configparser.RawConfigParser(strict=False, interpolation=None)
	conf.read(os.path.join(ROOT, 'tenx-for-splunk', 'default', 'macros.conf'))
	return conf


class TestTheMacros:
	def test_txf_reads_the_plan_right_before_the_replay_and_removes_it_after(self):
		d = macros().get('txf', 'definition')
		assert '| `tenx-replay-plan` | `tenx-replay` |' in d
		assert 'fields - tenx_compact_raw, tenx_rst, tenx_hash, tenx_var_0, tenx_vars, tenx_nd* |' in d
		# txf(<sourcetype>) runs its unit whole; it reads the plan only to leave out event types and tags
		unit = macros().get('txf(1)', 'definition')
		assert '. "` | `tenx-replay-plan` | `tenx-replay-tags` |' in unit and 'tenx_vars, tenx_nd* |' in unit
		assert 'AND isnull(tenx_ndnotags)' in macros().get('tenx-replay-tags', 'definition')

	def test_the_plan_step_reads_the_stored_field_as_tenx_wild_reads_its_marks(self):
		d = macros().get('tenx-replay-plan', 'definition')
		wild = macros().get('tenx-wild', 'definition')
		# a field is always named: with no name, fillnull would fill every field of every event
		assert d.startswith('fillnull value=1 tenx_ndnone [| makeresults | addinfo | eval p=')
		head = wild[wild.index('[| makeresults'):wild.index('| fields custom.tenx_wild_marks')]
		assert head in d and '| fields custom.tenx_replay_plan" | appendpipe [stats count | where count=0] |' in d
		# only field names go into fillnull; anything else is the whole replay
		assert ('eval search=if(match(\'custom.tenx_replay_plan\', "^tenx_nd[A-Za-z0-9_ ]+$"), '
				'\'custom.tenx_replay_plan\', "tenx_ndnoplan")') in d
		import re
		for value, ok in (('tenx_ndm0a1b2c3d tenx_nd0a1b2c3d_1_', True), ('value=x tenx_ndm1', False), ('', False),
						  ('tenx_ndm1 | delete', False), ('tenx_nd1 [x]', False)):
			assert bool(re.match(r"^tenx_nd[A-Za-z0-9_ ]+$", value)) == ok, value

	def test_fillnull_never_gets_a_name_twice(self):
		# Splunk refuses the search ("Field 'tenx_ndnone' cannot be specified multiple times"): with no plan
		# stored, every txf search failed in a first build (Splunk Enterprise 10.4.3)
		d = macros().get('tenx-replay-plan', 'definition')
		literal = d[len('fillnull value=1 '):d.index(' [')].split()
		default = d[d.rindex('"tenx_nd'):].split('"')[1]
		assert literal == ['tenx_ndnone'] and default not in literal
		for generation, ids in (('0a1b2c3d', {1}), ('00000000', set())):
			assert not set(plan.flags(generation, ids).split()) & set(literal)
		model = Model(commands={'extract': extract, 'typer': lambda e, _: None, 'tags': lambda e, _: None},
					  macros={'tenx-replay': 'eval x=1'}, plan='tenx_ndnone')
		with pytest.raises(Exception):
			model.run('`tenx-replay-plan` | `tenx-replay`', events())

	def test_the_plan_names_only_fields_the_step_accepts(self):
		import re
		value = plan.flags('0a1b2c3d', range(0, 300))
		assert re.match(r"^tenx_nd[A-Za-z0-9_ ]+$", value)

	def test_the_txf_tail_with_no_plan_is_the_whole_replay(self):
		# the model's tenx-replay-plan step stores nothing: tenx_ndnone, removed with the plan's fields
		replay = selected()
		model = Model(commands={'extract': extract, 'typer': lambda e, _: None, 'tags': lambda e, _: None},
					  lookups=TABLES, macros={'tenx-replay': replay.spl()})
		out = [visible(e) for e in model.run('`tenx-replay-plan` | `tenx-replay` | fields - tenx_nd*', events())]
		assert out == run(replay)
		model.plan = plan.flags(replay.selection[0], plan.closure(replay.selection[1], {'dest_ip'}))
		out = [visible(e) for e in model.run('`tenx-replay-plan` | `tenx-replay` | fields - tenx_nd*', events())]
		assert out[0]['dest_ip'] == '10.0.0.1' and 'ftnt_action' not in out[0]


# ---------------------------------------------------------------------------------------------------------
# The source:: and host:: stanza tests behind one pattern per field
# ---------------------------------------------------------------------------------------------------------

class TestSourceAndHostTestsInOnePattern:
	"""
	Each source:: and host:: stanza with a rule was one regular expression per event; a stock Splunk 10.4.3
	has 53, every one from Splunk's own apps (.../var/log/splunk/...), which no compact event of another
	source matches (12% of a FortiGate `txf` search's indexer CPU). One pattern per field now tests them all,
	and only a chunk where some event matches runs the per-stanza tests.
	"""

	def test_one_pattern_per_field(self):
		shared = [b.Stanza('source::.../fw/*.log', {}, {}), b.Stanza('source::/var/log/x.log', {}, {}),
				  b.Stanza('host::FW-*', {}, {}), b.Stanza('host::web01', {}, {})]
		guard = b._union_guard(shared)
		assert guard.startswith('isnotnull(tenx_rst) AND (match(source, ') and guard.count('match(') == 2
		assert 'match(host, "(?i:^(?:' in guard

	def test_the_rules_apply_where_they_did(self):
		evs = [replayed('fw:traffic', source='/var/fw/a.log', host='other', srcip='1.1.1.1'),
			   replayed('fw:traffic', source='/x/y', host='fw-7', ftnt_action='deny'),
			   replayed('fw:traffic', source='/x/y', host='web', srcip='2.2.2.2')]
		out = run(b.build(STANZAS, PRESENT, LOOKUPS), evs=evs)
		assert out[0].get('src_ip') == '1.1.1.1' and out[0].get('src_kind') == 'file' and out[0].get('h') is None
		assert out[1].get('h') == 'host' and out[1].get('src_kind') is None
		assert out[2].get('src_ip') is None and out[2].get('src_kind') is None and out[2].get('h') is None

	def test_a_chunk_where_none_matches_runs_no_stanza_test(self):
		evs = [replayed('fw:traffic', source='/x/y', host='web', srcip='2.2.2.2')]
		model = Model(commands={'extract': extract, 'typer': lambda e, _: None, 'tags': lambda e, _: None}, lookups=TABLES)
		seen = []
		real = model.step

		def step(text, events):
			if text.startswith('eval tenx_rg'):
				seen.append(text)
			return real(text, events)
		model.step = step
		model.run(b.build(STANZAS, PRESENT, LOOKUPS).spl(), evs)
		assert seen == []
		model.run(b.build(STANZAS, PRESENT, LOOKUPS).spl(), [replayed('fw:traffic', source='/var/fw/a.log')])
		assert len(seen) == 1


# ---------------------------------------------------------------------------------------------------------
# The search rewrite leaves out event types and tags a compiled search does not read
# ---------------------------------------------------------------------------------------------------------

class TestTheRewriteLeavesOutTagsNoOneReads:
	COVERED = {'aws:cloudtrail': {'indexes': 'ct', 'unit': b.unit_macro('aws:cloudtrail'), b.COMMANDS_KEY: '17'},
			   'k8s:container:json': {'indexes': 'otel', 'unit': b.unit_macro('k8s:container:json'), b.COMMANDS_KEY: '13'}}

	def test_the_replay_of_a_search_that_reads_no_tag(self):
		unit = '`%s`' % b.unit_macro('aws:cloudtrail')
		assert b.rewrite_replay(self.COVERED, ['ct']) == unit + ' | `tenx-replay-tags`'
		assert b.rewrite_replay(self.COVERED, ['ct'], tags=False) == unit
		assert b.rewrite_replay(self.COVERED, None, tags=False) == (
			'eval tenx_ndnotags=1 | `tenx-replay` | fields - tenx_ndnotags')
		assert b.rewrite_replay({}, ['ct'], tags=False) is None

	@pytest.mark.parametrize('leading, rest, unread', [
		('index=ct sourcetype=tenx_encoded eventName=DeletePolicy', ['rename user_name as user', 'stats count by dest user'], True),
		('index=ct sourcetype=tenx_encoded tag=authentication', ['stats count'], False),
		('index=ct sourcetype=tenx_encoded', ['stats count by eventtype'], False),
		('index=ct sourcetype=tenx_encoded', ['stats values(*) as *'], False),
		('index=ct sourcetype=tenx_encoded eventName=ConsoleLogin', [], False),
		('index=ct sourcetype=tenx_encoded x', ['`some_macro`', 'stats count'], False)])
	def test_what_the_search_reads(self, leading, rest, unread):
		import tenx_search_builder as sb
		commands = [sb.TenxSplCommand({'command': c.split(' ', 1)[0], 'rawargs': c.split(' ', 1)[1] if ' ' in c else ''}, {})
					for c in rest]
		assert sb.tags_unread({'command': 'search', 'rawargs': leading}, commands) is unread
