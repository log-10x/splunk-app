"""
What the generated replay macro does to events, run through the SPL model
(tests/support/spl_model.py) rather than read as text: Splunk's precedence between source, host,
sourcetype and [default] stanzas, aliases and calculated fields reading the values from before
any of them ran, lookups in ASCII order of their class names, rules written once, and events
that are not replayed left alone. The model's assumptions about Splunk are in its docstring.
"""
import tenx_replay_builder as b
from support.spl_model import Model, visible


def stanza(name, **rules):
	return b.Stanza(name, dict(rules), {})


TABLES = {
	'users': [{'username': 'u1', 'dept': 'sales'}],
	'depts': [{'dept': 'eng', 'floor': '3'}, {'dept': 'sales', 'floor': '1'}],
}


def run(stanzas, present, events, lookups=None):
	replay = b.build(stanzas, present, lookups)
	model = Model(commands={'extract': extract, 'typer': lambda e, _: None, 'tags': lambda e, _: None},
				  lookups=TABLES)
	return replay, [visible(e) for e in model.run(replay.spl(), events)]


def extract(event, _):
	"""Stands in for Splunk's extract: the fields the test says the expanded text holds, set
	when the _kv mark is not there (the replay drops it on the events it replays)."""
	if not event.get('_kv') and event.get('_raw'):
		event.update(event.get('__text_fields', {}))


def replayed(st, source='/var/app/a.log', host='web-1', **text_fields):
	"""A compact event after expansion, carrying its original sourcetype; `text_fields` are what
	extract finds in the expanded text."""
	return {'_raw': 'expanded', 'tenx_compact_raw': '~h,1', 'sourcetype': 'tenx_encoded', 'tenx_sourcetype': st,
			'source': source, 'host': host, '_kv': 1, '__text_fields': text_fields}


STANZAS = [
	stanza('default', **{'EVAL-k': '"dflt"', 'EVAL-d_only': '"d"'}),
	stanza('app:kv', **{'EVAL-k': '"st"', 'FIELDALIAS-a': 'x AS y', 'FIELDALIAS-b': 'y AS z',
						'EVAL-p': 'q', 'EVAL-q': '"new"',
						'LOOKUP-users': 'users username AS user OUTPUT dept', 'LOOKUP-a_dept': 'depts dept OUTPUT floor'}),
	stanza('app:json', **{'EVAL-j': '"json"'}),
	stanza('source::.../app/*.log', **{'EVAL-k': '"src"'}),
	stanza('host::WEB-*', **{'EVAL-h': '"host"'}),
]
PRESENT = [('app:kv', '/var/app/a.log', 'web-1'), ('app:json', '/var/other/b.log', 'api-1')]


class TestPrecedence:
	def test_source_beats_sourcetype_beats_default(self):
		_, out = run(STANZAS, PRESENT, [
			replayed('app:kv'),                                   # source stanza matches
			replayed('app:kv', source='/var/other/b.log'),        # only the sourcetype stanza
			replayed('app:json', source='/var/other/b.log'),      # app:json has no EVAL-k
			replayed('unknown:st', source='/var/app/c.log'),      # no props stanza, source matches
		])
		assert [e.get('k') for e in out] == ['src', 'st', 'dflt', 'src']
		assert [e.get('d_only') for e in out] == ['d', 'd', 'd', 'd']

	def test_host_patterns_ignore_case(self):
		_, out = run(STANZAS, PRESENT, [replayed('app:json', host='web-7'), replayed('app:json', host='api-1')])
		assert [e.get('h') for e in out] == ['host', None]

	def test_rules_of_one_sourcetype_do_not_touch_another(self):
		_, out = run(STANZAS, PRESENT, [replayed('app:json', x='1', q='old'), replayed('app:kv', x='1', q='old')])
		assert out[0].get('j') == 'json' and 'y' not in out[0] and out[0]['q'] == 'old'
		assert out[1].get('j') is None and out[1]['y'] == '1'


class TestOrder:
	def test_aliases_read_values_from_before_any_alias(self):
		_, out = run(STANZAS, PRESENT, [replayed('app:kv', x='X', y='Y')])
		assert out[0]['y'] == 'X' and out[0]['z'] == 'Y'

	def test_calculated_fields_read_values_from_before_any_ran(self):
		_, out = run(STANZAS, PRESENT, [replayed('app:kv', q='old')])
		assert out[0]['p'] == 'old' and out[0]['q'] == 'new'

	def test_lookups_run_in_ascii_order_of_their_class(self):
		# LOOKUP-a_dept runs before LOOKUP-users, so it sees the dept the event had, not the one
		# users writes.
		_, out = run(STANZAS, PRESENT, [replayed('app:kv', user='u1', dept='eng')], {'users': ['username', 'dept'], 'depts': ['dept', 'floor']})
		assert out[0]['floor'] == '3' and out[0]['dept'] == 'sales'


class TestWrittenOnce:
	def test_default_and_source_rules_are_written_once_for_any_number_of_sourcetypes(self):
		present = [('st%d' % i, '/var/app/a.log', 'web-1') for i in range(50)]
		stanzas = [stanza('default', **{'EVAL-k': '"dflt"', 'LOOKUP-u': 'users username AS user OUTPUT dept'}),
				   stanza('source::.../app/*.log', **{'FIELDALIAS-s': 'a AS b'})]
		spl = b.build(stanzas, present, {'users': ['username', 'dept']}).spl()
		assert spl.count('"dflt"') == 1 and spl.count('lookup users') == 1 and spl.count("'a'") == 1

	def test_size_does_not_grow_with_default_rules_per_sourcetype(self):
		stanzas = [stanza('default', **{'EVAL-a': 'lower(x)', 'FIELDALIAS-b': 'c AS d', 'LOOKUP-e': 't f OUTPUT g'})]
		sizes = [len(b.build(stanzas, [('st%d' % i, 's', 'h') for i in range(n)]).spl()) for n in (10, 1000)]
		# about 45 characters per sourcetype for its flag; writing the [default] rules once per
		# sourcetype would give about 525,000 characters at 1,000
		assert sizes[1] - sizes[0] < 990 * 60, sizes


class TestNotReplayed:
	def test_events_without_an_original_sourcetype_keep_their_fields(self):
		# junk is what a rule of the compact sourcetype found in the compact text when it was read
		stanzas = STANZAS + [stanza('tenx_encoded', **{'EVAL-junk': '"compact"'})]
		plain = {'_raw': 'expanded', 'tenx_compact_raw': '~h,1', 'sourcetype': 'tenx_encoded', 'source': '/var/app/a.log',
				 'host': 'web-1', 'k': 'orig', 'x': 'X', 'junk': 'compact', 'eventtype': 'et', 'tag::eventtype': 't'}
		with_carrier = replayed('app:kv')
		with_carrier.update({'junk': 'compact', 'eventtype': 'et', 'tag::eventtype': 't', 'tenx_indexed': 'keep'})
		_, out = run(stanzas, PRESENT, [dict(plain), with_carrier])
		assert out[0] == visible(dict(plain))
		assert out[1].get('junk') is None and out[1].get('tag::eventtype') is None
		assert out[1]['tenx_indexed'] == 'keep'

	def test_a_refused_rule_still_hides_the_lower_one_and_changes_nothing(self):
		stanzas = [stanza('source::s', **{'EVAL-x': ''}), stanza('st', **{'EVAL-x': '"from st"'})]
		replay, out = run(stanzas, [('st', 's', 'h')], [replayed('st', source='s', x='kept'), replayed('st', source='t', x='kept')])
		assert [e['x'] for e in out] == ['kept', 'from st']
		assert any('EVAL-x' in w for w in replay.warnings)


class TestLookupOutputOffItsEvents:
	"""
	The `lookup` command removes its OUTPUT fields on an event whose input is null (KV store and
	CSV alike; OUTPUTNEW leaves the event alone; observed on Splunk Enterprise 10.4.3). The replay
	keeps a lookup off the events it does not apply to by giving them a null input, so an OUTPUT
	lookup must give those events their output fields back.
	"""
	STANZAS = [
		stanza('app:kv', **{'LOOKUP-users': 'users username AS user OUTPUT dept'}),
		stanza('app:json', **{'EVAL-j': '"json"'}),
		stanza('source::.../app/*.log', **{'LOOKUP-src': 'depts dept AS team OUTPUT floor'}),
		stanza('app:kv2', **{'LOOKUP-src': 'users username AS team OUTPUT dept AS floor'}),
	]
	PRESENT = [('app:kv', '/var/app/a.log', 'h'), ('app:json', '/var/app/b.log', 'h'), ('app:kv2', '/var/app/a.log', 'h')]
	LOOKUPS = {'users': ['username', 'dept'], 'depts': ['dept', 'floor']}

	def test_events_it_does_not_apply_to_keep_the_output_field(self):
		plain = {'_raw': 'expanded', 'tenx_compact_raw': '~h,1', 'sourcetype': 'tenx_encoded', 'source': '/x',
				 'host': 'h', 'dept': 'from text'}
		_, out = run(self.STANZAS, self.PRESENT, [dict(plain), replayed('app:json', dept='json text'),
												   replayed('app:kv', user='u1')], self.LOOKUPS)
		assert out[0]['dept'] == 'from text'      # not replayed, in a chunk with replayed events
		assert out[1]['dept'] == 'json text'      # replayed, another sourcetype
		assert out[2]['dept'] == 'sales'          # the rule applies

	def test_an_event_without_the_input_field_keeps_the_output(self):
		# raw Splunk leaves an event lacking the match field alone (observed on Splunk 10.4.3)
		_, out = run(self.STANZAS, self.PRESENT, [replayed('app:kv', dept='from text')], self.LOOKUPS)
		assert out[0]['dept'] == 'from text'

	def test_a_lower_candidate_does_not_undo_the_winner(self):
		# LOOKUP-src in the source stanza beats the one in [app:kv2]; the loser's lookup runs after
		# it with a null input and must not remove what the winner wrote
		_, out = run(self.STANZAS, self.PRESENT, [replayed('app:kv2', team='eng')], self.LOOKUPS)
		assert out[0].get('floor') == '3'


class TestTheMacroKeepsItsContract:
	"""
	No cleanup step of the macro may remove a field the macro must leave. A wildcard such as
	`fields - tenx_rs*` would also remove tenx_rst, so every replayed event would lose its event
	types and tags, and the search rewrite, which reads tenx_rst after the macro, would stop
	hiding replayed events from its own extract and spath.
	"""
	PROTECTED = ('tenx_rst', 'tenx_sourcetype', 'tenx_compact_raw', 'tenx_hide_others', 'tenx_expand_refused',
				 'tenx_hash', 'tenx_var_0', 'tenx_vars', 'eventtype', 'tag', 'sourcetype', 'source', 'host')

	def test_no_cleanup_wildcard_matches_a_field_the_macro_must_leave(self):
		import fnmatch
		import re
		from support.spl_model import split_top
		spl = b.build(STANZAS, PRESENT, {'users': ['username', 'dept'], 'depts': ['dept', 'floor']}).spl()
		patterns = []
		def walk(text):
			for step in split_top(text, '|'):
				m = re.match(r'^foreach \S+(?:\s+\w+="[^"]*")*\s*\[(.*)\]$', step, re.S)
				if m:
					walk(m.group(1))
				elif step.startswith('fields - '):
					patterns.extend(p.strip() for p in step[len('fields - '):].split(','))
		walk(spl)
		assert patterns
		for p in patterns:
			for name in self.PROTECTED:
				assert not fnmatch.fnmatchcase(name, p), (p, name)

	def test_a_replayed_event_keeps_tenx_rst_and_its_eventtype(self):
		def typer(e, _):
			if e.get('sourcetype') == 'app:kv':
				e['eventtype'] = 'kv_event'
		model = Model(commands={'extract': extract, 'typer': typer, 'tags': lambda e, _: None}, lookups=TABLES)
		replay = b.build(STANZAS, PRESENT, {'users': ['username', 'dept'], 'depts': ['dept', 'floor']})
		out = model.run(replay.spl(), [replayed('app:kv', user='u1')])
		assert out[0]['tenx_rst'] == 'app:kv' and out[0]['eventtype'] == 'kv_event'
