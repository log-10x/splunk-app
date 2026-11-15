"""
Unit tests for tenx_replay_builder: reading props rules, Splunk's precedence between stanzas, and
the order of the search steps written into the tenx-replay macro.

What these tests cannot show is that the steps reproduce Splunk's own fields. That was measured on
a Splunk 10.4.3 instance by exporting every field of every event from a raw index and from the
same events compact through `tx`, and comparing them field by field.
"""
import re

import pytest

import tenx_replay_builder as b


def stanza(name, default=None, **settings):
	return b.Stanza(name, dict(settings), default or {})


def rules_of(name, rules, default=None):
	return b.Stanza(name, dict(rules), default or {})


class TestReadingRules:
	def test_alias_pairs_with_as_and_asnew(self):
		assert b.parse_aliases('usr AS user src AS src_ip') == [('usr', 'AS', 'user'), ('src', 'AS', 'src_ip')]
		assert b.parse_aliases('host_name ASNEW dest') == [('host_name', 'ASNEW', 'dest')]
		assert b.parse_aliases('a as b, c asnew d') == [('a', 'AS', 'b'), ('c', 'ASNEW', 'd')]

	def test_alias_that_is_not_pairs_is_refused(self):
		for bad in ('usr user', 'usr AS', '', 'a AS b c'):
			with pytest.raises(b.ReplayError):
				b.parse_aliases(bad)

	def test_quoted_names_stay_whole(self):
		assert b.tokens('"a b" AS c, d') == ['a b', 'AS', 'c', 'd']

	def test_lookup_with_output_and_renames(self):
		table, inputs, mode, outputs = b.parse_lookup('users username AS user OUTPUT dept, role AS user_role')
		assert table == 'users'
		assert inputs == [('username', 'user')]
		assert mode == 'OUTPUT'
		assert outputs == [('dept', 'dept'), ('role', 'user_role')]

	def test_lookup_outputnew_and_several_match_fields(self):
		table, inputs, mode, outputs = b.parse_lookup('t a, b AS bb OUTPUTNEW c')
		assert inputs == [('a', 'a'), ('b', 'bb')] and mode == 'OUTPUTNEW' and outputs == [('c', 'c')]

	def test_lookup_without_output_writes_every_other_column(self):
		table, inputs, mode, outputs = b.parse_lookup('geo src_ip')
		assert (table, inputs, mode, outputs) == ('geo', [('src_ip', 'src_ip')], None, [])

	def test_lookup_keyword_is_case_insensitive(self):
		assert b.parse_lookup('t a output c')[2] == 'OUTPUT'

	def test_lookup_without_match_field_is_refused(self):
		with pytest.raises(b.ReplayError):
			b.parse_lookup('t OUTPUT c')

	def test_only_search_time_rules_are_kept(self):
		s = stanza('st', **{'EVAL-x': '1', 'FIELDALIAS-a': 'b AS c', 'LOOKUP-l': 't a', 'lookup_m': 't a',
							'REPORT-r': 'tr', 'TRUNCATE': '10', 'KV_MODE': 'none'})
		assert sorted(s.rules) == ['EVAL-x', 'FIELDALIAS-a', 'LOOKUP-l', 'lookup_m']

	def test_a_setting_equal_to_the_default_belongs_to_the_default(self):
		default = {'EVAL-d': '"x"'}
		s = stanza('st', default, **{'EVAL-d': '"x"', 'EVAL-own': '1'})
		assert sorted(s.rules) == ['EVAL-own']
		assert stanza('st', default, **{'EVAL-d': '"other"'}).rules == {'EVAL-d': '"other"'}


class TestPatterns:
	def match(self, pattern, value):
		return re.match('(?:' + b.pattern_regex(pattern) + r')\Z', value) is not None

	def test_dots_star_and_period(self):
		assert self.match('.../appdemo/*.log', '/var/log/appdemo/app.log')
		assert not self.match('.../appdemo/*.log', '/var/log/appdemo/sub/app.log')
		assert self.match('.../appdemo/...', '/var/log/appdemo/sub/app.log')
		assert not self.match('.../appdemo/*.log', '/var/log/appdemo/appXlog')

	def test_regex_only_in_or_after_a_wildcard_segment(self):
		# props.conf.spec: [source::WindowsEventLog:(s|S)ecurity*]
		assert self.match('WindowsEventLog:(s|S)ecurity*', 'WindowsEventLog:security')
		# no wildcard: the name is literal, parentheses included
		assert self.match('a(b|c)', 'a(b|c)') and not self.match('a(b|c)', 'ab')

	def test_spec_example_with_lookbehind(self):
		assert self.match('....(?<!tar.)(gz|bz2)', '/x/file.gz')
		assert not self.match('....(?<!tar.)(gz|bz2)', '/x/file.tar.gz')

	def test_host_matches_case_insensitively_unless_told(self):
		assert stanza('host::AB-WEB-*').matches('ab-web-01')
		assert stanza('host::foo').matches('FOO')
		assert not stanza('host::(?-i)bar*').matches('BAR1')
		assert not stanza('source::.../Ab*').matches('/x/ab1')

	def test_literal_and_pattern_default_priorities(self):
		assert stanza('source::XmlWinEventLog:Security').priority == 100
		assert stanza('source::...Security').priority == 0
		assert stanza('source::...Security', priority='7').priority == 7

	def test_guards(self):
		assert stanza('XmlWinEventLog').guard() == 'tenx_rst=="XmlWinEventLog"'
		assert stanza('source::X:Y').guard() == 'isnotnull(tenx_rst) AND source=="X:Y"'
		assert stanza('host::Web1').guard() == 'isnotnull(tenx_rst) AND lower(host)=="web1"'
		g = stanza('source::.../a/*.log').guard()
		assert g.startswith('isnotnull(tenx_rst) AND match(source, "^(?:')
		# a backslash reaches the regex as one backslash
		assert '\\\\.log' in g


class TestPrecedence:
	def test_source_then_host_then_sourcetype_then_default(self):
		order = sorted([stanza('default'), stanza('st'), stanza('host::h'), stanza('source::s')], key=b.Stanza.sort_key)
		assert [s.kind for s in order] == ['source', 'host', 'sourcetype', 'default']

	def test_within_source_priority_then_ascii(self):
		a = stanza('source::...a...')
		z = stanza('source::...z...')
		lit = stanza('source::az')
		assert [s.name for s in sorted([z, a, lit], key=b.Stanza.sort_key)] == \
			['source::az', 'source::...a...', 'source::...z...']
		z_high = stanza('source::...z...', priority='10')
		assert sorted([a, z_high], key=b.Stanza.sort_key)[0] is z_high


BLOCK = re.compile(r'^foreach (tenx_go\d+z|tenx_go[xw]|tenx_hide_others)\* fieldstr="@@TENXF@@" matchstr="@@TENXM@@" \[(.*)\]$')


def flat(steps):
	"""The steps with each block's body spliced in, in order (blocks hold no ' | ' of their own)."""
	out = []
	for step in steps:
		m = BLOCK.match(step)
		out.extend(m.group(2).split(' | ') if m else [step])
	return out


def blocks(steps):
	"""{flag: body steps of all its blocks, in order} for the blocks keyed on one original sourcetype."""
	out = {}
	for step in steps:
		m = BLOCK.match(step)
		if m and m.group(1) not in ('tenx_go0z', b.HIDE, b.AS_READ, b.WHOLE):
			out.setdefault(m.group(1), []).extend(m.group(2).split(' | '))
	return out


def build(stanzas, present, lookups=None, keep=()):
	return b.build(stanzas, present, lookups, keep)


DEMO = [
	rules_of('default', {'EVAL-dflt': '"d"'}),
	rules_of('app:kv', {
		'FIELDALIAS-user': 'usr AS user', 'FIELDALIAS-asnew': 'host_name ASNEW dest',
		'EVAL-status': 'if(status>=500, "err", status)', 'EVAL-status_class': 'substr(status,1,1)',
		'EVAL-kb': 'bytes/1024',
		'LOOKUP-users': 'users username AS user OUTPUT dept', 'LOOKUP-a_dept': 'depts dept OUTPUT floor',
		'LOOKUP-geo': 'geo src_ip'}),
	rules_of('app:json', {'EVAL-status': '"j"', 'FIELDALIAS-juser': 'user.name AS user'}),
	rules_of('source::.../app/*.log', {'EVAL-kb': 'bytes/1000'}),
	rules_of('source::.../other/*.log', {'EVAL-never': '1'}),
	rules_of('host::WEB-*', {'EVAL-host_rule': '1'}),
	rules_of('unused:st', {'EVAL-unused': '1'}),
]
PRESENT = [('app:kv', '/var/app/a.log', 'web-1'), ('app:json', '/var/app/b.log', 'api-1')]
LOOKUPS = {'users': ['username', 'dept'], 'depts': ['dept', 'floor'], 'geo': ['src_ip', 'site', 'rack']}


class TestBuild:
	def test_no_original_sourcetype_leaves_tx_as_it_was(self):
		assert build(DEMO, []).spl() == ' | '.join(b.UNCHANGED)
		assert [s for s in b.UNCHANGED if not BLOCK.match(s)] == ['extract']

	def test_only_the_stanzas_that_can_apply_are_written(self):
		# A sourcetype stanza is written for the original sourcetypes covered; source and host
		# stanzas always, whatever the lookback saw, each behind its own pattern.
		spl = build(DEMO, PRESENT, LOOKUPS).spl()
		assert 'unused' not in spl
		assert 'tenx_rst=="app:kv"' in spl and 'tenx_rst=="app:json"' in spl
		assert 'host_rule' in spl and 'never=' in spl and 'match(source, "^(?:.*/other/[^/]*\\\\.log)$")' in spl

	def test_the_sequence_follows_splunks(self):
		steps = flat(build(DEMO, PRESENT, LOOKUPS).steps)
		def first(pred):
			return next(i for i, s in enumerate(steps) if pred(s))
		clear = first(lambda s: s.startswith('eval ') and '=if(isnotnull(tenx_rst), null(), ' in s)
		retype = first(lambda s: s.startswith('eval sourcetype='))
		unmark = first(lambda s: s.startswith('eval _kv=if(isnotnull(tenx_rst)'))
		extract = first(lambda s: s == 'extract')
		assert retype < unmark < extract
		assert 'fields - _kv' not in steps
		alias = first(lambda s: 'tenx_ra0_0=' in s)
		calc = first(lambda s: 'tenx_rc0=' in s)
		lookup = first(lambda s: s.startswith('lookup '))
		typer = first(lambda s: s == 'typer')
		assert clear < retype < extract < alias < calc < lookup < typer
		assert steps[typer + 1] == 'tags'

	def test_lookups_run_in_ascii_order_of_their_class(self):
		steps = flat(build(DEMO, PRESENT, LOOKUPS).steps)
		tables = [s.split()[1] for s in steps if s.startswith('lookup ')]
		# LOOKUP-a_dept, LOOKUP-geo, LOOKUP-users: a_dept runs before users, as Splunk does, so it
		# does not see the dept that users writes.
		assert tables == ['depts', 'geo', 'users']

	def test_calculated_fields_read_values_from_before_any_ran(self):
		steps = flat(build(DEMO, PRESENT, LOOKUPS).steps)
		reads = [i for i, s in enumerate(steps) if re.match(r'eval tenx_rc\d+=', s)]
		writes = next(i for i, s in enumerate(steps) if re.search(r'(?:^eval |, )status=case\(', s))
		# every expression is evaluated into a temporary, in its own block, before any field is
		# assigned (the reads of each sourcetype sit in that sourcetype's block)
		assert reads and max(reads) < writes
		for i in reads:
			assigned = re.findall(r'(?:^eval |, )([^\s,=()]+)=(?!=)', steps[i])
			assert assigned and all(n.startswith('tenx_rc') for n in assigned), assigned
		assert 'tenx_rc' in steps[writes]
		assert any('substr(status,1,1)' in steps[i] for i in reads)

	def test_a_source_rule_beats_the_sourcetype_rule_of_the_same_name(self):
		r = build(DEMO, PRESENT, LOOKUPS)
		spl, kv = r.spl(), r.per_sourcetype['app:kv']['flag']
		m = re.search(r'kb=case\(tenx_rg(\d+)==1, tenx_rc(\d+), isnotnull\(%s\), tenx_rc(\d+), true\(\), \'kb\'\)' % kv, spl)
		assert m, spl
		src, from_src, from_kv = m.groups()
		assert 'tenx_rg%s=if(isnotnull(tenx_rst) AND match(source, "^(?:.*/app/[^/]*\\\\.log)$"),1,0)' % src in spl
		assert 'tenx_rc%s=if(tenx_rg%s==1, (bytes/1000), null())' % (from_src, src) in spl
		assert 'tenx_rc%s=if(isnotnull(%s), (bytes/1024), null())' % (from_kv, kv) in spl

	def test_rules_of_one_sourcetype_are_guarded_from_the_other(self):
		r = build(DEMO, PRESENT, LOOKUPS)
		by_flag = blocks(r.steps)
		kv, js = r.per_sourcetype['app:kv']['flag'], r.per_sourcetype['app:json']['flag']
		assert sorted(by_flag) == sorted([kv, js])
		kv_body, js_body = ' | '.join(by_flag[kv]), ' | '.join(by_flag[js])
		# each sourcetype's rules sit in its own block, behind its own flag and its own guards
		assert '"err"' in kv_body and '"err"' not in js_body
		assert '("j")' in js_body and '("j")' not in kv_body
		assert 'depts' in kv_body and 'depts' not in js_body
		assert re.search(r'tenx_rc\d+=if\(isnotnull\(%s\), \(if\(status>=500, "err", status\)\), null\(\)\)' % kv, kv_body)
		assert 'isnotnull(%s)' % js not in kv_body and 'isnotnull(%s)' % kv not in js_body

	def test_a_chunk_without_replayed_events_runs_no_replay_step(self):
		steps = build(DEMO, PRESENT, LOOKUPS).steps
		outside = [s for s in steps if not BLOCK.match(s)]
		assert outside[0].startswith('eval tenx_rst=')
		# whole events: marked, and one read under the sourcetype it needs is not replayed
		assert outside[1].startswith('eval tenx_gox=') and ', tenx_gow=' in outside[1]
		assert outside[2] == 'eval tenx_rst=if(isnotnull(tenx_gox), null(), tenx_rst)'
		assert outside[3].startswith('eval tenx_go0z=')
		assert outside[4:] == ['extract', 'fields - tenx_go*']
		flags = re.findall(r'(tenx_go\d+z)=', outside[3])
		assert flags == ['tenx_go0z', 'tenx_go1z', 'tenx_go2z']
		# no flag pattern matches another flag's name, so each block runs at most once per chunk
		marks = flags + ['tenx_gox', 'tenx_gow']
		for f in marks:
			assert [g for g in marks if re.match(f + '.*$', g)] == [f]

	def test_lookup_inputs_exist_only_where_the_rule_applies(self):
		steps = flat(build(DEMO, PRESENT, LOOKUPS).steps)
		i = next(n for n, s in enumerate(steps) if s.startswith('lookup users'))
		assert re.match(r"eval tenx_ri(\d+)_0=if\(isnotnull\(tenx_go\d+z\), 'user', null\(\)\), "
						r"tenx_rl\1=if\(isnull\(tenx_ri\1_0\), 1, 0\), tenx_ro\1_0=if\(tenx_rl\1==1, 'dept', null\(\)\)$", steps[i - 1])
		assert re.fullmatch(r'lookup users username AS tenx_ri\d+_0 OUTPUT dept', steps[i])
		# the lookup removes dept where its input is null (observed on Splunk 10.4.3): put it back there
		assert re.fullmatch(r"eval dept=if\(tenx_rl(\d+)==1, tenx_ro\1_0, 'dept'\)", steps[i + 1])

	def test_alias_modes(self):
		spl = build(DEMO, PRESENT, LOOKUPS).spl()
		assert re.search(r"user=if\(tenx_rw\d+==1, tenx_ra\d+_0, 'user'\)", spl)
		assert re.search(r"dest=if\(tenx_rw\d+==1, coalesce\('dest', tenx_ra\d+_0\), 'dest'\)", spl)
		assert "tenx_ra" in spl and "'user.name'" in spl

	def test_a_lookup_this_app_cannot_see_is_skipped_with_a_warning(self):
		r = build(DEMO, PRESENT, {'users': ['username', 'dept']})
		assert not any(s.startswith('lookup geo') for s in r.steps)
		assert any('geo' in w and 'not visible' in w for w in r.warnings)

	def test_computed_fields_per_sourcetype(self):
		info = build(DEMO, PRESENT, LOOKUPS).per_sourcetype
		assert info['app:kv']['computed'] == ['dept', 'dflt', 'floor', 'host_rule', 'kb', 'rack', 'site',
											  'status', 'status_class']
		assert info['app:json']['computed'] == ['dflt', 'kb', 'status']
		assert info['app:kv']['aliased'] == ['dest', 'user']

	def test_events_that_are_not_replayed_get_their_eventtypes_and_tags_back(self):
		spl = build(DEMO, PRESENT, LOOKUPS).spl()
		assert 'eventtype=if(isnull(tenx_rst), tenx_rk_et, eventtype)' in spl
		# tag is the union of the tag::<field> values: tags does not write it inside a block
		assert "foreach tag::* [eval tenx_rk_all=mvappend(tenx_rk_all, '<<FIELD>>')]" in spl
		assert 'tag=if(isnull(tenx_rst), tenx_rk_tag, mvsort(mvdedup(tenx_rk_all)))' in spl
		assert 'foreach tenx_rk_tag::* ' in spl
		# tenx_rst is left for the caller: the search rewrite reads it after the macro.
		assert spl.endswith('fields - tenx_rk_*] | fields - tenx_go*')

	def test_the_clearing_step_keeps_default_and_indexed_fields(self):
		# The clearing step names the fields that rules applying to the compact text can set
		# (by name, no `foreach *`), minus default, tenx_*, date_* and indexed fields.
		read_time = [rules_of('tenx_encoded', {'FIELDALIAS-h': 'x AS host', 'EVAL-app': '"win:unknown"',
											   'EVAL-k8s.namespace': '"a"', 'EVAL-timestamp': '1', 'EVAL-date_hour': '1',
											   'EVAL-tenx_sourcetype': '1', 'EVAL-k8s_namespace': '"b"'}),
					 rules_of('source::.../app/*.log', {'FIELDALIAS-u': 'usr AS user'})]
		steps = flat(build(DEMO + read_time, PRESENT, LOOKUPS, keep=('k8s.namespace', 'timestamp')).steps)
		clear = next(s for s in steps if s.startswith('eval ') and '=if(isnotnull(tenx_rst), null(), ' in s)
		named = re.findall(r'(?:^eval |, )("[^"]+"|[^\s=,]+)=if\(isnotnull\(tenx_rst\), null\(\), ', clear)
		named = [n.strip('"') for n in named]
		for kept in ('host', 'source', 'sourcetype', 'index', 'tenx_sourcetype', '_raw', 'date_hour',
					 'k8s.namespace', 'timestamp'):
			assert kept not in named, kept
		for cleared in ('app', 'user', 'eventtype', 'tag', 'k8s_namespace'):
			assert cleared in named, cleared
		assert any(s.startswith('foreach tag::* [eval "<<FIELD>>"=if(isnotnull(tenx_rst), null()') for s in steps)
		# no `foreach *` writes a field by eval; the one there is renames each field to a working name
		# and back, and clears only events that arrived whole (whole_clearing_steps())
		assert [s for s in steps if s.startswith('foreach * ')] == ['foreach * [rename "<<FIELD>>" AS tenx_wf']
		i = steps.index('foreach * [rename "<<FIELD>>" AS tenx_wf')
		assert steps[i + 1].startswith('eval tenx_wf=if(isnotnull(tenx_gow) AND NOT (')
		assert steps[i + 2] == 'rename tenx_wf AS "<<FIELD>>"]'

	def test_only_expanded_events_with_an_original_sourcetype_are_replayed(self):
		first = flat(build(DEMO, PRESENT, LOOKUPS).steps)[0]
		assert first.startswith('eval tenx_rst=if(isnotnull(tenx_sourcetype)')
		assert 'tenx_expand_refused' in first and '_raw!=tenx_compact_raw' in first

	def test_kv_mode_multi_and_index_time_fields_are_reported(self):
		st = b.Stanza('m:st', {'KV_MODE': 'multi', 'INDEXED_EXTRACTIONS': 'json', 'EVAL-x': '1'}, {})
		info = build([st], [('m:st', 's', 'h')]).per_sourcetype['m:st']
		assert any('multi' in w for w in info['warnings'])
		assert any('INDEXED_EXTRACTIONS' in w for w in info['warnings'])

	def test_field_names_that_need_quotes(self):
		st = rules_of('j', {'EVAL-latency.s': "'timing.ms'/1000", 'FIELDALIAS-u': 'user.name AS user'})
		spl = build([st], [('j', 's', 'h')]).spl()
		assert '"latency.s"=case(' in spl and "'latency.s')" in spl

	def test_a_field_name_with_a_brace_is_not_written_by_eval(self):
		# eval "E{@x}"=1 assigns E (measured): braces on the left name the target by value.
		st = rules_of('j', {'EVAL-a{b}': '1', 'FIELDALIAS-t': 'x AS tags{}', 'EVAL-ok': '2'})
		r = build([st], [('j', 's', 'h')])
		assert '"a{b}"' not in r.spl() and 'tags{}' not in r.spl() and 'ok=case(' in r.spl()
		assert len([w for w in r.warnings if 'brace' in w]) == 2


class TestFieldsNotInText:
	STANZAS = [
		rules_of('app:kv', {'EVAL-kb': 'bytes/1024', 'LOOKUP-u': 'users username AS user OUTPUT dept',
							'LOOKUP-g': 'geo src_ip', 'FIELDALIAS-a': 'usr AS user host AS dvc_host kb AS kb2'}),
		b.Stanza('source::...x', {'REPORT-ip': 'extract_ip', 'REPORT-t': 'from_text',
								  'EXTRACT-site': r'(?<site>\w+)-\d+ in host', 'EXTRACT-c': r'c=(?<code>\d+)'}, {}),
	]
	TRANSFORMS = {'extract_ip': {'SOURCE_KEY': 'host', 'REGEX': r'(?<dvc_ip>\d+\.\d+\.\d+\.\d+)'},
				  'from_text': {'REGEX': r'u=(?<uid>\d+)', 'FORMAT': 'uname::$1'}}

	def test_what_is_not_text(self):
		out = b.fields_not_in_text(self.STANZAS, self.TRANSFORMS, {'geo': ['src_ip', 'site', 'rack']}, ['k8s_ns'])
		for f in ('kb', 'dept', 'rack', 'site', 'dvc_ip', 'dvc_host', 'kb2', 'k8s_ns'):
			assert f in out, f
		for f in ('user', 'usr', 'uid', 'uname', 'code', 'src_ip'):
			assert f not in out, f

	def test_a_name_that_cannot_be_listed_turns_narrowing_off(self):
		t = {'extract_ip': {'SOURCE_KEY': 'MetaData:Host', 'REGEX': r'(\w+)=(\w+)', 'FORMAT': '$1::$2'}}
		assert '*' in b.fields_not_in_text(self.STANZAS[1:], t)
		assert '*' in b.fields_not_in_text([rules_of('s', {'LOOKUP-x': 'unseen a'})], {}, {})


class TestCoverage:
	def test_new_sourcetype_or_source_is_uncovered(self):
		covered = {'a': 'src1,src2', 'b': '*'}
		assert b.uncovered([('a', 'src1'), ('b', 'anything')], covered) == []
		assert b.uncovered([('a', 'src3'), ('c', 'src1')], covered) == [('a', 'src3'), ('c', 'src1')]

	def test_sources_past_the_cap_are_a_star(self):
		assert b.sources_value(['x'] * (b.MAX_LISTED_SOURCES + 1)) == '*'
		assert b.sources_value(['a', 'b']) == 'a,b'
		info = build(DEMO, PRESENT, LOOKUPS).per_sourcetype
		assert info['app:kv']['sources'] == ['/var/app/a.log']

	def test_a_rebuild_keeps_what_the_replay_already_covers(self):
		present = [('a', 'src1', 'h', 5)]
		out = b.keep_covered(present, {'a': 'src1,src2', 'b': 'x', 'c': '*'})
		assert out == [('a', 'src1', 'h', 5), ('a', 'src2', '', 0), ('b', 'x', '', 0), ('c', '', '', 0)]
		assert b.keep_covered([], {'a': 'src1'}) == [('a', 'src1', '')]
