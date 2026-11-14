"""
The replay builder and the prefilter on hostile, unusual or boundary inputs.

Each test names the input it is about. They exercise only the pure builder and parser, so what
they show is the text that would be written into the `tenx-replay` macro, the conf the rebuild
reads back, and the prefilter `tx` would run, not the effect on a running Splunk.
"""
import re

import tenx_prefilter_parser as p
import tenx_replay_builder as b


def stanza(name, **settings):
	return b.Stanza(name, dict(settings), {})


def build(stanzas, present, **kw):
	return b.build([stanza('default')] + list(stanzas), present, **kw)


def outside_strings(spl):
	"""The macro text with every double-quoted string and single-quoted field name blanked."""
	out, i, n = [], 0, len(spl)
	while i < n:
		c = spl[i]
		if c == '"':
			j = i + 1
			while j < n and spl[j] != '"':
				j += 2 if spl[j] == '\\' else 1
			out.append('""')
			i = j + 1
			continue
		if c == "'":
			j = spl.find("'", i + 1)
			out.append("''")
			i = (j if j >= 0 else n) + 1
			continue
		out.append(c)
		i += 1
	return ''.join(out)


class TestRuleTextStaysOneRule:
	"""
	A calculated field's expression is pasted into the macro inside case(<guard>, (<expr>)). The
	macro is run by every `tx` search of every user, so text that is not one eval expression
	either breaks every such search or adds commands to it.
	"""

	def test_an_empty_calculated_field_does_not_break_the_macro(self):
		# EVAL-x = (empty), the usual way a local/props.conf turns off a shipped calculated field.
		r = build([stanza('st', **{'EVAL-x': ''})], [('st', 's', 'h')])
		# Pasted as is, it would give case(tenx_rg0==1, ()), which eval cannot parse.
		assert ', ())' not in outside_strings(r.spl())
		assert any('EVAL-x' in w for w in r.warnings)

	def test_a_calculated_field_cannot_add_a_command(self):
		# Whoever can write a calculated field the app can see (any role with write access to
		# an app that exports its props) could otherwise run `collect` in an admin's alerts.
		r = build([stanza('st', **{'EVAL-x': '1) | collect index=main | eval y=(1'})], [('st', 's', 'h')])
		assert 'collect' not in r.spl()
		assert any('EVAL-x' in w for w in r.warnings)

	def test_a_top_level_comma_cannot_split_the_expression(self):
		r = build([stanza('st', **{'EVAL-x': 'a, y=b'})], [('st', 's', 'h')])
		assert 'y=b' not in r.spl()

	def test_a_backtick_is_never_written(self):
		# Splunk expands `name` as a macro wherever it appears in a macro definition.
		r = build([stanza('st', **{'EVAL-x': 'replace(cmd, "`", "")'})], [('st', 's', 'h')])
		assert '`' not in r.spl()

	def test_ordinary_expressions_are_still_written(self):
		exprs = {
			'EVAL-a': r'replace(y, "\\[\\w+\\]", "")',
			'EVAL-b': 'if(a=="x|y", "[", "]")',
			'EVAL-c': 'case(a==1, "one", true(), \'Event.Data{}\')',
			'EVAL-d': 'mvmap(answer, replace(replace(answer,"\\(\\d+\\)","."),"\\\\[\\\\w+\\\\]",""))',
		}
		r = build([stanza('st', **exprs)], [('st', 's', 'h')])
		for key, expr in exprs.items():
			assert '(%s)' % expr in r.spl(), key
		assert not r.warnings

	def test_a_refused_rule_still_hides_the_lower_one_and_changes_nothing(self):
		# The source stanza turns the sourcetype's calculated field off; its events keep x as it was.
		r = build([stanza('source::s', **{'EVAL-x': ''}), stanza('st', **{'EVAL-x': '"from st"'})], [('st', 's', 'h')])
		spl = r.spl()
		i = spl.index('x=case(')
		case = spl[i:spl.index(' | ', i)]
		# the source candidate comes first in the case and leaves x as it is
		assert re.match(r"x=case\(tenx_rg0==1, 'x', isnotnull\(tenx_go1z\), tenx_rc\d+, true\(\), 'x'\)", case), case


class TestEventDataStaysData:
	"""
	tenx_sourcetype is an indexed field set by whoever sends the compact events (an HEC token is
	enough). Its values become text of the macro and stanza names of tenx_replay.conf.
	"""

	def test_a_sourcetype_with_a_backtick_or_a_control_character_is_not_written(self):
		bad = ['a`tenx-events`b', 'two\nlines', 'tab\there']
		r = build([stanza('ok', **{'EVAL-z': '1'})], [(s, 'src', 'h') for s in bad] + [('ok', 'src', 'h')])
		assert '`' not in r.spl() and '\n' not in r.spl() and '\t' not in r.spl()
		assert sorted(r.per_sourcetype) == ['ok']

	def test_reserved_names_do_not_rebuild_every_five_minutes(self):
		# tenxreplay._covered() drops [default] and [tenx:narrowing] when it reads the conf back,
		# so a sourcetype with one of those names would be "not covered" after every rebuild,
		# and "Rebuild Field Replay When New" would run a full 7-day rebuild every five minutes.
		for name in ('default', b.NARROWING_STANZA):
			r = build([], [(name, 'src', 'h')])
			assert name not in r.per_sourcetype, name
			assert b.uncovered([(name, 'src')], {}) == [], name

	def test_a_source_with_a_comma_does_not_rebuild_every_five_minutes(self):
		# The sources setting is a comma-separated list; a source name holding a comma, written
		# as is, would never match it again when read back.
		covered = {'st': b.sources_value(['/var/log/a,b.log'])}
		assert b.uncovered([('st', '/var/log/a,b.log')], covered) == []


class TestNarrowingMatchesRaw:
	"""
	The prefilter must never select fewer compact events than a raw search would return.
	"""

	def test_a_field_fields_conf_says_is_not_in_the_text_never_narrows(self):
		# fields.conf INDEXED_VALUE = false is how an add-on tells Splunk a field's value is not
		# a term of the raw text (Splunk_SA_CIM ships three such fields). Splunk then does not
		# look the value up in the text; the prefilter must not either.
		out = b.fields_not_in_text([stanza('default')], {}, {}, [], indexed_value_false=['prior_action_name'])
		text_field = p.text_field_predicate(out)
		assert not text_field('prior_action_name')
		tree = p.Parser(p.tokenize('prior_action_name=blocked')).parse()
		assert p.prefilter(tree, {}, text_field) is None

	def test_digits_of_a_rendered_timestamp_do_not_narrow(self):
		# The engine stores an event's timestamp as an epoch in its first value
		# (1763020800123), and tenx-inflate prints the fraction of a second from it. "123" is a
		# word of the expanded line and of the raw line, but not a term of the compact event, so
		# TERM(123) would drop every matching event, in a field value and in plain text
		# ("08:00:00.123") alike.
		text_field = p.text_field_predicate([])
		for search in ('ts="2026-11-13 08:00:00.123"', 'ts="2026-11-13T08:00:00.123456+00:00"', '"08:00:00.123"'):
			tree = p.Parser(p.tokenize(search)).parse()
			got = p.prefilter(tree, {}, text_field) or ''
			assert 'TERM(123' not in got, (search, got)


class TestRulesForOlderEvents:
	def test_host_stanzas_survive_for_a_sourcetype_kept_from_an_earlier_rebuild(self):
		# keep_covered() keeps a sourcetype and its sources, not its hosts; a [host::dc*] rule
		# must still be replayed on events older than the 7-day lookback.
		from support.spl_model import Model, visible
		stanzas = [stanza('st'), stanza('host::dc*', **{'EVAL-site': '"hq"'})]
		present = b.keep_covered([], {'st': 'src1'})
		r = build(stanzas, [x[:3] for x in present])
		event = {'_raw': 'expanded', 'tenx_compact_raw': '~h', 'tenx_sourcetype': 'st', 'source': 'src1', 'host': 'DC01'}
		out = Model(commands={'extract': lambda e, _: None, 'typer': lambda e, _: None,
							  'tags': lambda e, _: None}).run(r.spl(), [event])
		assert visible(out[0]).get('site') == 'hq'


class TestCapsAndExpiry:
	"""A bounded macro and a bounded list of sourcetypes."""

	def test_settings_read_with_defaults(self):
		assert b.replay_settings({}) == b.DEFAULT_SETTINGS
		got = b.replay_settings({'replay_max_sourcetypes': '5', 'replay_expire_days': 'x', 'replay_max_macro_chars': '-3'})
		assert got == {'replay_max_sourcetypes': 5, 'replay_expire_days': 400, 'replay_max_macro_chars': 0,
					   'replay_unit_grace_days': 90}

	def test_sourcetypes_over_the_cap_are_left_out_least_busy_first(self):
		present = [('busy', 's', 'h', 90), ('mid', 's', 'h', 10), ('old', 's', '', 0), ('quiet', 's', 'h', 1)]
		settings = dict(b.DEFAULT_SETTINGS, replay_max_sourcetypes=2)
		r = b.build_capped([stanza('default')], present, settings=settings, last_seen={'old': 5})
		assert sorted(r.per_sourcetype) == ['busy', 'mid'] and r.dropped == ['quiet', 'old']
		assert 'replay_max_sourcetypes = 2' in r.warnings[0] and 'quiet, old' in r.warnings[0]

	def test_the_macro_is_cut_down_to_the_size_cap(self):
		stanzas = [stanza('default'), stanza('source::/far/*', **{'EVAL-f': '"far"'})]
		stanzas += [stanza('st%d' % i, **{'EVAL-v%d' % i: '"%s"' % ('x' * 200)}) for i in range(20)]
		present = [('st%d' % i, '/near/a', 'h', 20 - i) for i in range(20)]
		full = len(b.build(stanzas, present).spl())
		limit = full // 2
		r = b.build_capped(stanzas, present, settings=dict(b.DEFAULT_SETTINGS, replay_max_macro_chars=limit))
		assert len(r.spl()) <= limit < full
		# the unmatched source stanza goes first, then the least busy sourcetypes
		assert '"far"' not in r.spl() and 'st0' in r.per_sourcetype and 'st19' in r.dropped
		assert any('replay_max_macro_chars' in w for w in r.warnings)

	def test_shared_rules_alone_over_the_cap_write_the_shipped_macro(self):
		stanzas = [stanza('default', **{'EVAL-d': '"%s"' % ('x' * 500)})]
		r = b.build_capped(stanzas, [('st', 's', 'h', 1)], settings=dict(b.DEFAULT_SETTINGS, replay_max_macro_chars=300))
		assert r.spl() == ' | '.join(b.UNCHANGED) and r.dropped == ['st']

	def test_expiry(self):
		now = 1000 * b.DAY
		covered = {'fresh': {'sources': 'a', 'last_seen': str(990 * b.DAY)},
				   'stale': {'sources': 'a', 'last_seen': str(500 * b.DAY)},
				   'unknown': {'sources': 'a', 'last_seen': ''}, 'plain': 'a'}
		kept, expired = b.expire_covered(covered, now, 400)
		assert expired == ['stale'] and sorted(kept) == ['fresh', 'plain', 'unknown']
		assert b.expire_covered(covered, now, 0) == (covered, [])
		# what is kept is covered as before, and what expired starts a rebuild when it comes back
		assert b.keep_covered([], kept) == [('fresh', 'a', ''), ('plain', 'a', ''), ('unknown', 'a', '')]
		assert b.uncovered([('stale', 'a'), ('fresh', 'a')], kept) == [('stale', 'a')]

	def test_last_seen_is_today_for_a_sourcetype_seen_and_kept_otherwise(self):
		now = 1000 * b.DAY + 5000
		present = [('seen', 's', 'h', 3), ('kept', 's', '', 0), ('new_kept', 's', '', 0)]
		got = b.last_seen_of(present, {'kept': {'last_seen': str(900 * b.DAY)}, 'seen': {'last_seen': '1'}}, now)
		assert got == {'seen': 1000 * b.DAY, 'kept': 900 * b.DAY, 'new_kept': 1000 * b.DAY}


class TestClearingSafeNames:
	"""The clearing step and field names with quotes or braces."""

	def test_a_field_name_with_a_quote_or_brace_never_reaches_eval(self):
		from support.spl_model import Model, visible
		read_time = [stanza('tenx_encoded', **{'EVAL-a{b}': '1', "EVAL-o'brien": '1', 'EVAL-q"x': '1', 'EVAL-fine': '1'})]
		r = build(read_time + [stanza('st', **{'EVAL-y': '"st"'})], [('st', 's', 'h')])
		spl = r.spl()
		assert 'foreach * ' not in spl and 'a{b}' not in spl and "o'brien" not in spl and 'q"x' not in spl
		assert "fine=if(isnotnull(tenx_rst), null(), 'fine')" in spl
		assert len([w for w in r.warnings if 'not cleared on replayed events' in w]) == 3
		# an event that carries such names as indexed fields (chosen by the sender) runs through
		event = {'_raw': 'expanded', 'tenx_compact_raw': '~h', 'tenx_sourcetype': 'st', 'source': 's', 'host': 'h',
				 "o'brien": 'v', 'a{b}': 'w', 'fine': 'junk'}
		out = Model(commands={'extract': lambda e, _: None, 'typer': lambda e, _: None,
							  'tags': lambda e, _: None}).run(spl, [event])
		got = visible(out[0])
		assert got["o'brien"] == 'v' and got['a{b}'] == 'w' and 'fine' not in got and got['y'] == 'st'

	def test_names_taken_from_the_data_are_reported(self):
		read_time = [stanza('source::x', **{'REPORT-kv': 'dyn'})]
		r = b.build(read_time + [stanza('st', **{'EVAL-y': '1'})], [('st', 's', 'h')],
					transforms={'dyn': {'REGEX': r'(\w+)=(\w+)', 'FORMAT': '$1::$2'}})
		assert any('take their names from the data' in w for w in r.warnings)


def test_the_capped_build_names_refused_sourcetypes():
	# build_capped() must not drop hostile tenx_sourcetype values before build() can name them
	# in its warnings, or nothing is logged about them.
	present = [('ok', 's', 'h', 3), ('default', 's', 'h', 1), ('a`b`', 's', 'h', 1), ('tenx:narrowing', 's', 'h', 1)]
	r = b.build_capped([stanza('ok', **{'EVAL-x': '1'})], present)
	named = [w for w in r.warnings if 'is not written into the macro' in w]
	assert len(named) == 3 and sorted(r.per_sourcetype) == ['ok']
