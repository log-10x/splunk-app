"""
Tests for tenx_search_report: which saved searches, alerts and dashboard panels change when sources move to compact
events. Every search here is written for the test; none comes from a sample or a customer.
"""
import csv
import io
import json
import os
import re
import urllib.error

import pytest

import tenx_search_report as r

README_PATH = os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'README.md')
NOMAP = r.Move(['XmlWinEventLog'], ['wineventlog'])
MAP = r.Move(['XmlWinEventLog'], ['wineventlog'], ['XmlWinEventLog'])


def verdict(search, move=NOMAP, kind='report', expanded=None):
	return r.classify(search, move, kind, expanded)


def flat(text):
	return re.sub(r'\s+', ' ', text)


# -------------------------------------------------------------------------------------------
# The README sentences the reasons quote

class TestReadmeQuotes:
	@pytest.mark.parametrize('key', sorted(r.README))
	def test_each_quoted_sentence_is_in_the_readme(self, key):
		with open(README_PATH, encoding='utf-8') as f:
			text = flat(f.read())
		for piece in r.README[key].split(' [...] '):
			assert flat(piece) in text

	def test_reason_names_the_readme(self):
		res = verdict('index=wineventlog NOT Se*Privilege EventCode=4672 | stats count')
		assert 'README: "Under `NOT` through the `tx` and `txf` macros' in res.reason


# -------------------------------------------------------------------------------------------
# SPL text

class TestText:
	def test_commands_cut_at_top_level_pipes_only(self):
		parts = r.split_commands('index=a "x | y" [search b | head 1] | eval z=if(a=="|", 1, 0) | stats count')
		assert parts == ['index=a "x | y" [search b | head 1]', 'eval z=if(a=="|", 1, 0)', 'stats count']

	def test_leading_pipe_gives_an_empty_first_command(self):
		assert r.split_commands('| tstats count')[0] == ''

	def test_comments_removed_outside_quotes(self):
		assert r.strip_comments('a ```x | y``` b "```q```"') == 'a   b "```q```"'

	def test_unclosed_comment_runs_to_the_end(self):
		assert r.strip_comments('a ```b').strip() == 'a'

	def test_subsearches_top_level(self):
		assert r.subsearches('a [search b [search c]] "[d]" [| inputlookup e]') == ['search b [search c]', '| inputlookup e']

	def test_chunks_keep_groups_and_spaced_comparisons(self):
		assert r.chunks('index = w (a OR b) NOT c "d e" f= g `m(1)`') == [
			'index = w', '(a OR b)', 'NOT', 'c', '"d e"', 'f= g', '`m(1)`']

	def test_midword_wildcard(self):
		assert r.midword_wildcard('Se*Privilege')
		assert not r.midword_wildcard('*Privilege') and not r.midword_wildcard('Se*') and not r.midword_wildcard('*')
		assert r.midword_wildcard('S*P*e') and not r.midword_wildcard('10.0*14') and not r.midword_wildcard('foo.*.com')


# -------------------------------------------------------------------------------------------
# The edit

class TestEdit:
	def test_index_and_time_before_the_macro_the_rest_after(self):
		e = r.edit_with_macro('index=w sourcetype=X earliest=-24h EventCode=4625 | stats count', 'txf')
		assert e == 'index=w earliest=-24h `txf` sourcetype=X EventCode=4625 | stats count'

	def test_host_and_source_before(self):
		assert r.edit_with_macro('host=a source="s:1" error', 'tx') == 'host=a source="s:1" `tx` error'

	def test_terms_joined_by_or_or_not_stay_after(self):
		e = r.edit_with_macro('index=a OR index=b NOT host=c x', 'txf')
		assert e == '`txf` index=a OR index=b NOT host=c x'

	def test_search_keyword_kept(self):
		assert r.edit_with_macro('search index=w x', 'tx') == 'search index=w `tx` x'

	def test_spaced_time_term_moves_whole(self):
		assert r.edit_with_macro('latest = now x', 'tx') == 'latest = now `tx` x'

	def test_macro_call_stays_after(self):
		assert r.edit_with_macro('index=w `sec` EventCode=1', 'txf') == 'index=w `txf` `sec` EventCode=1'

	def test_negated_index_stays_after(self):
		assert r.edit_with_macro('index!=w x', 'tx') == '`tx` index!=w x'

	def test_generating_search_has_no_edit(self):
		assert r.edit_with_macro('| tstats count', 'tx') is None

	def test_time_term_from_a_macro_moves_into_the_edit(self):
		res = verdict('`win` EventCode=4625 | stats count by user',
			expanded='index=wineventlog earliest=-1d EventCode=4625 | stats count by user')
		assert res.edit == 'search index=wineventlog earliest=-1d `txf` EventCode=4625 | stats count by user'


# -------------------------------------------------------------------------------------------
# Without a field map

class TestWithoutFieldMap:
	def test_field_search_needs_txf(self):
		res = verdict('index=wineventlog EventCode=4625 | stats count by user')
		assert res.verdict == r.NEEDS_TXF
		assert res.edit == 'index=wineventlog `txf` EventCode=4625 | stats count by user'

	def test_original_sourcetype_needs_txf_and_says_so(self):
		res = verdict('index=wineventlog sourcetype=XmlWinEventLog | stats count')
		assert res.verdict == r.NEEDS_TXF and 'tenx_sourcetype' in res.reason

	def test_words_only_need_tx(self):
		res = verdict('index=wineventlog "NULL SID" | stats count by host')
		assert res.verdict == r.NEEDS_TX
		assert res.edit == 'index=wineventlog `tx` "NULL SID" | stats count by host'

	def test_words_with_an_addon_field_later_need_txf(self):
		assert verdict('index=wineventlog Kerberos | stats count by user').verdict == r.NEEDS_TXF

	def test_metadata_counts_are_unchanged(self):
		res = verdict('index=wineventlog | stats count by host source')
		assert res.verdict == r.UNCHANGED and res.edit == ''

	def test_events_of_metadata_only_search_need_tx(self):
		assert verdict('index=wineventlog host=dc1').verdict == r.NEEDS_TX

	def test_tag_and_eventtype_need_txf(self):
		assert verdict('index=wineventlog tag=authentication | stats count').verdict == r.NEEDS_TXF
		assert verdict('index=wineventlog eventtype=x | stats count').verdict == r.NEEDS_TXF

	def test_midword_wildcard_outside_not_needs_tx_under_not_is_a_limit(self):
		res = verdict('index=wineventlog Se*Privilege | stats count')
		assert res.verdict == r.NEEDS_TX and res.edit == 'index=wineventlog `tx` Se*Privilege | stats count'
		res = verdict('index=wineventlog EventCode=4672 NOT Se*Privilege | stats count')
		assert res.verdict == r.LIMIT and res.edit == 'index=wineventlog `txf` EventCode=4672 NOT Se*Privilege | stats count'
		assert 'fewer events' in res.reason
		assert verdict('index=wineventlog NOT (Se*Privilege OR x) | stats count').verdict == r.LIMIT

	def test_term_outside_not_needs_tx_with_a_minor_breaker_under_not_is_a_limit(self):
		assert verdict('index=wineventlog TERM(10.9.8.7) | stats count').verdict == r.NEEDS_TX
		res = verdict('index=wineventlog NOT TERM(10.9.8.7) | stats count')
		assert res.verdict == r.LIMIT and 'part of a longer term' in res.reason
		assert verdict('index=wineventlog NOT TERM(plain) | stats count').verdict == r.NEEDS_TX
		for q in ('index=wineventlog TERM(+0000) | stats count', 'index=wineventlog TERM("a b") | stats count',
				'index=wineventlog NOT TERM(x%20y) | stats count'):
			res = verdict(q)
			assert res.verdict == r.LIMIT and 'major breaker' in res.reason, q

	def test_case_is_not_a_limit(self):
		assert verdict('index=wineventlog CASE(Kerberos) | stats count').verdict == r.NEEDS_TX
		res = verdict('index=wineventlog NOT CASE(Kerberos) | stats count')
		assert res.verdict == r.LIMIT and '`NOT CASE()`' in res.reason

	def test_comma_is_a_limit(self):
		res = verdict('index=wineventlog 4625, 4624 | stats count')
		assert res.verdict == r.LIMIT and 'Remove the comma' in res.reason

	def test_punct_is_a_limit(self):
		assert verdict('index=wineventlog EventCode=1 | stats count by punct').verdict == r.LIMIT

	def test_xml_profile_fields_are_a_limit(self):
		res = verdict('index=wineventlog EventCode=4672 | stats count by vendor_privilege')
		assert res.verdict == r.LIMIT and 'xmlns' in res.reason

	def test_date_fields_not_classified(self):
		assert verdict('index=wineventlog EventCode=1 | stats count by date_hour').verdict == r.NOT_CLASSIFIED

	def test_data_model_needs_field_map(self):
		for s in ('| tstats count from datamodel=Authentication by Authentication.user',
				'| tstats summariesonly=t count FROM datamodel=Change.All_Changes',
				'| datamodel Authentication Failed_Authentication search | stats count',
				'| from datamodel:Authentication.Failed_Authentication | stats count',
				'| pivot Authentication Authentication count(Authentication) AS c'):
			assert verdict(s).verdict == r.NEEDS_MAP, s

	def test_tstats_by_host_unchanged(self):
		assert verdict('| tstats count where index=wineventlog by host source').verdict == r.UNCHANGED
		assert verdict('| tstats prestats=t count where index=wineventlog by _time span=1h').verdict == r.UNCHANGED

	def test_tstats_on_sourcetype_is_a_limit_with_the_fix(self):
		res = verdict('| tstats count where index=wineventlog sourcetype=XmlWinEventLog')
		# the same README sentence with and without a map: tstats reads the indexed, compact sourcetype
		assert res.verdict == r.LIMIT and r.README['tstats_sourcetype'] in res.reason
		assert 'tenx_sourcetype=XmlWinEventLog' in res.reason
		assert verdict('| tstats count where index=wineventlog by sourcetype').verdict == r.LIMIT

	def test_tstats_on_other_fields_not_classified(self):
		assert verdict('| tstats count where index=wineventlog by EventCode').verdict == r.NOT_CLASSIFIED

	def test_tstats_on_other_index_not_affected(self):
		assert verdict('| tstats count where index=main by host').verdict == r.NOT_AFFECTED


# -------------------------------------------------------------------------------------------
# With a field map

class TestWithFieldMap:
	def test_field_search_unchanged(self):
		res = verdict('index=wineventlog sourcetype=XmlWinEventLog LogonProcessName=Kerberos | stats count by user', MAP)
		assert res.verdict == r.UNCHANGED and res.edit == ''

	def test_words_need_txf(self):
		res = verdict('index=wineventlog Kerberos | stats count', MAP)
		assert res.verdict == r.NEEDS_TXF and res.edit == 'index=wineventlog `txf` Kerberos | stats count'

	def test_negated_word_needs_txf(self):
		assert verdict('index=wineventlog EventCode=4624 NOT Kerberos | stats count', MAP).verdict == r.NEEDS_TXF

	def test_commands_that_read_the_text_need_txf(self):
		for s in ('index=wineventlog EventCode=1 | rex "Name\'>(?<n>[^<]+)" | stats count by n',
				'index=wineventlog EventCode=1 | search Kerberos | stats count',
				'index=wineventlog EventCode=1 | regex "x+" | stats count',
				'index=wineventlog EventCode=1 | spath | stats count',
				'index=wineventlog EventCode=1 | eval n=len(_raw) | stats sum(n)',
				'index=wineventlog EventCode=1 | where searchmatch("x") | stats count',
				'index=wineventlog EventCode=1 | transaction user startswith="a" | stats count'):
			assert verdict(s, MAP).verdict == r.NEEDS_TXF, s

	def test_commands_given_another_field_are_unchanged(self):
		for s in ('index=wineventlog EventCode=1 | rex field=user "(?<d>\\w+)" | stats count by d',
				'index=wineventlog EventCode=1 | spath input=Message | stats count',
				'index=wineventlog EventCode=1 | regex user="^a" | stats count',
				'index=wineventlog EventCode=1 | search user=bob | stats count'):
			assert verdict(s, MAP).verdict == r.UNCHANGED, s

	def test_events_for_a_report_need_txf_for_an_alert_not(self):
		assert verdict('index=wineventlog EventCode=4625', MAP, 'report').verdict == r.NEEDS_TXF
		res = verdict('index=wineventlog EventCode=4625', MAP, 'alert')
		assert res.verdict == r.UNCHANGED and 'number of events' in res.reason

	def test_table_without_raw_is_unchanged_with_raw_needs_txf(self):
		assert verdict('index=wineventlog EventCode=1 | table _time user', MAP).verdict == r.UNCHANGED
		assert verdict('index=wineventlog EventCode=1 | table _time _raw', MAP).verdict == r.NEEDS_TXF
		assert verdict('index=wineventlog EventCode=1 | fields - _raw', MAP).verdict == r.UNCHANGED

	def test_data_models_unchanged(self):
		assert verdict('| tstats count from datamodel=Authentication by Authentication.user', MAP).verdict == r.UNCHANGED
		assert verdict('| datamodel Authentication Authentication search | stats count', MAP).verdict == r.UNCHANGED

	def test_datamodel_command_returning_events_needs_txf_in_a_report(self):
		assert verdict('| datamodel Authentication Authentication search', MAP).verdict == r.NEEDS_TXF

	def test_tstats_on_sourcetype_quotes_the_map_sentence(self):
		res = verdict('| tstats count where sourcetype=XmlWinEventLog by host', MAP)
		assert res.verdict == r.LIMIT and 'stays the compact one with or without a field map' in res.reason

	@pytest.mark.parametrize('search,quote', [
		('index=wineventlog EventCode=1 | stats count by date_wday', 'date_fields'),
		('index=wineventlog eventtype=err0r | stats count', 'eventtype_words'),
		('index=wineventlog eventtype IN (err0r, x) | stats count', 'eventtype_words'),
		('index=wineventlog EventCode=4672 | stats count by vendor_privilege', 'privilege_dash'),
		('index=wineventlog EventCode=4798 | stats count by dest', 'dest_4798'),
		('index=wineventlog EventCode=1 | table EventData_Xml', 'xml_blocks'),
		('index=wineventlog EventCode=1 | stats count by punct', 'punct'),
		('index=wineventlog EventCode=4104 | stats count by ScriptBlockText', 'long_value'),
	])
	def test_limits_of_the_map(self, search, quote):
		res = verdict(search, MAP)
		assert res.verdict == r.LIMIT and r.README[quote] in res.reason

	def test_dest_without_those_events_unchanged(self):
		assert verdict('index=wineventlog EventCode=4624 | stats count by dest', MAP).verdict == r.UNCHANGED

	def test_one_unmapped_sourcetype_means_no_map(self):
		move = r.Move(['XmlWinEventLog', 'app:log'], ['wineventlog'], ['XmlWinEventLog'])
		assert verdict('index=wineventlog EventCode=1 | stats count', move).verdict == r.NEEDS_TXF
		assert verdict('index=wineventlog sourcetype=XmlWinEventLog EventCode=1 | stats count', move).verdict == r.UNCHANGED

	def test_index_only_move_with_a_map(self):
		move = r.Move([], ['wineventlog'], ['XmlWinEventLog'])
		assert verdict('index=wineventlog EventCode=1 | stats count', move).verdict == r.UNCHANGED


# -------------------------------------------------------------------------------------------
# Sources whose compact events can carry another _time

FGT = r.Move(['fortigate_*', 'fgt_*'], ['fw'])
CT = r.Move(['aws:cloudtrail'], ['aws'])
CT_MAP = r.Move(['aws:cloudtrail'], ['aws'], ['aws:cloudtrail'])


class TestEventTime:
	@pytest.mark.parametrize('search', [
		'index=fw sourcetype=fortigate_traffic | timechart count',
		'index=fw sourcetype=fortigate_traffic action=deny',
		'index=fw sourcetype=fortigate_traffic | stats min(_time) by srcip',
		'index=fw sourcetype=fortigate_traffic | stats latest(action) by srcip',
		'index=fw earliest=-1d sourcetype=fortigate_utm | stats count',
		'index=fw sourcetype=fortigate_event | head 10 | stats count by logid',
		'| tstats count where index=fw by _time span=1h',
	])
	def test_fortigate_time_is_a_limit(self, search):
		res = verdict(search, FGT)
		assert res.verdict == r.LIMIT and 'can fall on another day' in res.reason

	def test_a_fortigate_map_gives_the_raw_time(self):
		# A map built with --target fortigate sets _time from date= and time= (the README's FortiGate field map).
		mapped = r.Move(['fortigate_*', 'fgt_*'], ['fw'], ['fortigate_traffic'])
		assert 'fall on another day' not in verdict('index=fw sourcetype=fortigate_traffic | timechart count', mapped).reason

	def test_fortigate_counts_over_all_time_are_not(self):
		assert verdict('index=fw sourcetype=fortigate_traffic | stats count by action', FGT).verdict == r.NEEDS_TXF
		assert verdict('| tstats count where index=fw by host', FGT).verdict == r.UNCHANGED

	def test_a_time_range_is_a_limit(self):
		assert r.classify('index=fw sourcetype=fortigate_traffic | stats count by action', FGT, 'alert', None,
			'-24h').verdict == r.LIMIT
		assert r.classify('index=fw sourcetype=fortigate_traffic | stats count by action', FGT, 'alert', None,
			None).verdict == r.LIMIT
		assert r.classify('index=fw sourcetype=fortigate_traffic | stats count by action', FGT, 'alert', None,
			'0').verdict == r.NEEDS_TXF

	def test_other_sourcetypes_of_the_index_are_not_time_limited(self):
		move = r.Move(['fortigate_*', 'XmlWinEventLog'], ['fw'])
		assert verdict('index=fw sourcetype=XmlWinEventLog | timechart count', move).verdict == r.NEEDS_TXF
		assert verdict('index=fw | timechart count', move).verdict == r.LIMIT

	def test_cloudtrail_without_a_map_with_one_not(self):
		res = verdict('index=aws sourcetype=aws:cloudtrail | timechart count by eventName', CT)
		assert res.verdict == r.LIMIT and 'creationDate' in res.reason
		assert verdict('index=aws sourcetype=aws:cloudtrail | timechart count by eventName', CT_MAP).verdict == r.UNCHANGED
		assert verdict('index=aws sourcetype=aws:cloudtrail | stats count by eventName', CT).verdict == r.NEEDS_TXF

	def test_windows_has_no_time_limit(self):
		assert verdict('index=wineventlog EventCode=1 | timechart count').verdict == r.NEEDS_TXF

	def test_dashboard_windows(self):
		xml = """<dashboard><label>t</label><search id="b"><query>index=fw sourcetype=fortigate_traffic | fields action</query>
		  <earliest>0</earliest></search>
		  <row><panel><table><search base="b"><query>| stats count by action</query></search></table></panel>
		  <panel><table><search><query>index=fw sourcetype=fortigate_utm | stats count</query></search></table></panel>
		  <panel><table><search><query>index=fw sourcetype=fortigate_utm | stats count by logid</query>
		  <earliest>0</earliest></search></table></panel></row></dashboard>"""
		got = r.run(FakeSource([], r.dashboard_items('t', 'a', 'o', xml)), FGT)
		verdicts = [i.result.verdict for i in got]
		assert verdicts == [r.NEEDS_TXF, r.NEEDS_TXF, r.LIMIT, r.NEEDS_TXF]


# -------------------------------------------------------------------------------------------
# Not affected, not classified, already written for compact events

class TestOtherVerdicts:
	def test_other_sourcetype_or_index_not_affected(self):
		res = verdict('index=wineventlog sourcetype=WinEventLog:System error')
		assert res.verdict == r.NOT_AFFECTED and 'WinEventLog:System' in res.reason
		assert verdict('index=main error').verdict == r.NOT_AFFECTED

	def test_wildcards_match_both_ways(self):
		assert verdict('index=win* EventCode=1 | stats count').verdict == r.NEEDS_TXF
		move = r.Move(['Xml*'], [])
		assert verdict('sourcetype=XmlWinEventLog EventCode=1 | stats count', move).verdict == r.NEEDS_TXF

	def test_negated_sourcetype_does_not_name_it(self):
		# it still reads the moved index; through `tx` the events would all carry the compact sourcetype
		assert verdict('index=wineventlog NOT sourcetype=XmlWinEventLog x').verdict == r.NEEDS_TXF
		assert verdict('index=wineventlog NOT sourcetype=a x').verdict == r.NEEDS_TXF

	def test_sourcetype_in_list(self):
		assert verdict('index=wineventlog sourcetype IN (a, b) x').verdict == r.NOT_AFFECTED
		assert verdict('index=wineventlog sourcetype IN (a, XmlWinEventLog) x').verdict == r.NEEDS_TXF

	def test_no_index_no_sourcetype_reads_the_moved_data(self):
		assert verdict('tag=authentication | stats count').verdict == r.NEEDS_TXF

	def test_generating_commands_without_events(self):
		for s in ('| inputlookup x.csv', '| makeresults', '| rest /services/server/info'):
			assert verdict(s).verdict == r.NOT_AFFECTED, s

	def test_map_savedsearch_and_subsearch_terms_not_classified(self):
		assert verdict('index=wineventlog x | map search="search y=$y$"').verdict == r.NOT_CLASSIFIED
		assert verdict('| savedsearch "other"').verdict == r.NOT_CLASSIFIED
		assert verdict('| loadjob savedsearch="a:b:c"').verdict == r.NOT_CLASSIFIED
		assert verdict('index=wineventlog [| inputlookup u.csv | fields user] | stats count').verdict == r.NOT_CLASSIFIED

	def test_subsearch_reading_moved_data_not_classified(self):
		res = verdict('index=main x | append [search index=wineventlog y]')
		assert res.verdict == r.NOT_CLASSIFIED and 'subsearch' in res.reason

	def test_subsearch_of_other_data_does_not_count(self):
		assert verdict('index=wineventlog x | append [search index=main y]').verdict == r.NEEDS_TXF

	def test_subsearch_starting_with_a_generating_command_without_a_pipe(self):
		assert verdict('index=main x | append [rest /services/server/info | fields a]').verdict == r.NOT_AFFECTED
		res = verdict('index=main x | append [savedsearch other]')
		assert res.verdict == r.NOT_CLASSIFIED and 'could not be classified' in res.reason

	def test_index_metadata_commands(self):
		assert verdict('| metadata type=hosts index=main').verdict == r.NOT_AFFECTED
		assert verdict('| metadata type=hosts index=wineventlog').verdict == r.NOT_CLASSIFIED

	def test_unknown_generating_command_not_classified(self):
		assert verdict('| mycommand x=1').verdict == r.NOT_CLASSIFIED

	def test_terms_that_do_not_parse_not_classified(self):
		res = verdict('index=wineventlog (a OR b')
		assert res.verdict == r.NOT_CLASSIFIED and 'could not be read' in res.reason

	def test_unexpanded_macros_not_classified(self):
		res = verdict('`x` y', expanded='!Macro `x` has no definition in what was read.')
		assert res.verdict == r.NOT_CLASSIFIED and 'no definition' in res.reason

	def test_app_macros_and_commands_with_limited_words(self):
		assert verdict('index=wineventlog `txf` NOT Se*Privilege').verdict == r.LIMIT
		res = verdict('| tx index=wineventlog sourcetype=tenx_encoded NOT Se*Privilege')
		assert res.verdict == r.LIMIT and 'exact opposite' in res.reason
		assert verdict('| tx index=wineventlog sourcetype=tenx_encoded Se*Privilege').verdict == r.UNCHANGED

	def test_app_macros_and_commands_unchanged(self):
		assert verdict('index=wineventlog `txf` EventCode=1').verdict == r.UNCHANGED
		assert verdict('index=wineventlog `txf(XmlWinEventLog)` EventCode=1').verdict == r.UNCHANGED
		assert verdict('| tx index=wineventlog sourcetype=tenx_encoded x').verdict == r.UNCHANGED

	def test_empty_search(self):
		assert verdict('   ').verdict == r.NOT_AFFECTED

	def test_comment_with_backticks_is_ignored(self):
		res = verdict('index=wineventlog EventCode=1 ```note: `x` | y``` | stats count')
		assert res.verdict == r.NEEDS_TXF

	def test_worst_keeps_edit_and_reasons(self):
		res = r.worst([r.Result(r.NEEDS_TX, ['a'], 'e'), r.Result(r.LIMIT, ['b'])])
		assert res.verdict == r.LIMIT and res.reasons == ['b', 'a'] and res.edit == 'e'

	def test_move_needs_something(self):
		with pytest.raises(ValueError):
			r.Move([], [])


# -------------------------------------------------------------------------------------------
# Macros and conf files

class TestMacros:
	def macros(self):
		return r.Macros({
			'sec': {'definition': 'index=w (eventtype=a OR source="s")'},
			'ctime(1)': {'args': 'field', 'definition': 'convert ctime($field$)'},
			'pair(2)': {'args': 'a, b', 'definition': '$a$=$b$'},
			'outer': {'definition': '`sec` x'},
			'ev(1)': {'args': 'x', 'iseval': '1', 'definition': '"a" . $x$'},
		})

	def test_expand_text_for_text(self):
		assert self.macros().expand('`sec` EventCode=1 | `ctime(firstTime)`') == (
			'index=w (eventtype=a OR source="s") EventCode=1 | convert ctime(firstTime)', None)

	def test_arguments_and_nesting(self):
		m = self.macros()
		assert m.expand('`pair(user, "b,c")`')[0] == 'user=b,c'
		assert m.expand('`outer`')[0] == 'index=w (eventtype=a OR source="s") x'

	def test_backticks_inside_quotes_are_text(self):
		assert self.macros().expand('x="`sec`"')[0] == 'x="`sec`"'

	def test_unknown_eval_and_unpaired(self):
		m = self.macros()
		assert 'no definition' in m.expand('`nope`')[1]
		assert 'iseval' in m.expand('`ev(1)`')[1]
		assert 'no pair' in m.expand('`sec')[1]

	def test_recursion_stops(self):
		m = r.Macros({'a': {'definition': '`a`'}})
		assert 'deep' in m.expand('`a`')[1]

	def test_conf_with_continued_lines(self):
		text = '# c\n[s 1]\nsearch = index=w \\\n  | stats count\nenableSched = 1\n\n[s2]\nsearch=x\n'
		assert r.read_conf_text(text) == {'s 1': {'search': 'index=w \n| stats count', 'enableSched': '1'},
			's2': {'search': 'x'}}

	@pytest.mark.parametrize('settings,kind', [
		({'enableSched': '1', 'alert_type': 'number of events'}, 'alert'),
		({'is_scheduled': '1', 'actions': 'email'}, 'alert'),
		({'enableSched': '1', 'action.email': '1'}, 'alert'),
		({'enableSched': '1', 'alert.track': '1'}, 'alert'),
		({'enableSched': '1', 'counttype': 'number of events'}, 'alert'),
		({'enableSched': '1', 'alert_type': 'always'}, 'report'),
		({'alert_type': 'number of events'}, 'report'),
		({}, 'report'),
	])
	def test_alert_or_report(self, settings, kind):
		assert r.saved_search_kind(settings) == kind


# -------------------------------------------------------------------------------------------
# Dashboards

CLASSIC = '''<form version="1.1">
  <label>D</label>
  <search id="base"><query>index=wineventlog EventCode=4624 | fields user Logon_Type</query></search>
  <fieldset><input type="dropdown" token="code"><label>Code</label><default>4625</default>
    <search><query>index=wineventlog | stats count by EventCode</query></search></input></fieldset>
  <row><panel><title>By type</title><chart><search base="base"><query>| stats count by Logon_Type</query></search></chart></panel>
  <panel><title>Word</title><single><search><query>index=wineventlog Kerberos | stats count</query></search></single></panel></row>
  <row><panel><title>Code</title><table><search><query>index=wineventlog EventCode=$code$ | stats count</query></search></table></panel>
  <panel><title>User</title><table><search><query>index=wineventlog user=$who$ | stats count</query></search></table></panel>
  <panel><title>Free</title><table><search><query>index=wineventlog $filter$ | stats count</query></search></table></panel>
  <panel><title>Saved</title><table><search ref="s1"></search></table></panel>
  <panel><title>Lost</title><table><search base="nowhere"><query>| stats count</query></search></table></panel></row>
</form>'''

STUDIO = {
	'dataSources': {
		'b': {'type': 'ds.search', 'options': {'query': 'index=wineventlog EventCode=4663 | fields ObjectType'}},
		'c': {'type': 'ds.chain', 'options': {'extend': 'b', 'query': '| stats count by ObjectType'}},
		't': {'type': 'ds.search', 'name': 'term', 'options': {'query': 'index=wineventlog TERM(a.b) | stats count'}},
		's': {'type': 'ds.savedSearch', 'options': {'ref': 's1'}},
		'i': {'type': 'ds.search', 'options': {'query': 'index=wineventlog | stats count by host'}},
	},
	'visualizations': {'v': {'title': 'Types', 'dataSources': {'primary': 'c'}}},
	'inputs': {'in': {'options': {'token': 'x', 'defaultValue': '1'}, 'dataSources': {'primary': 'i'}}},
}


class FakeSource(object):
	def __init__(self, saved, dashboards):
		self.saved, self.dashboards = saved, dashboards

	def items(self):
		return self.saved, self.dashboards

	def expand(self, item, text):
		return None


def by_name(items):
	return dict((i.name, i) for i in items)


class TestDashboards:
	def test_classic(self):
		dash = r.dashboard_items('d', 'app', 'nobody', CLASSIC)
		saved = [r.Item('s1', 'app', 'nobody', 'alert', 'index=wineventlog EventCode=4625')]
		got = by_name(r.run(FakeSource(saved, dash), MAP))
		assert got['d / search base'].kind == 'base search'
		assert got['d / search base'].result.verdict == r.UNCHANGED
		assert got['d / Code'].kind == 'input' or got['d / Code'].search.endswith('stats count')
		assert got['d / By type'].result.verdict == r.UNCHANGED
		assert got['d / Word'].result.verdict == r.NEEDS_TXF
		assert 'EventCode=4625 |' in r._shown(got['d / Code'])
		assert r._shown(got['d / User']).startswith('index=wineventlog user=tenx_token_value')
		assert got['d / Free'].result.verdict == r.NOT_CLASSIFIED and '$filter$' in got['d / Free'].result.reason
		assert got['d / Saved'].result.verdict == r.UNCHANGED and 's1' in got['d / Saved'].result.reason
		assert got['d / Lost'].result.verdict == r.NOT_CLASSIFIED

	def test_input_is_named_by_its_label(self):
		dash = r.dashboard_items('d', 'a', 'o', CLASSIC)
		assert 'input' in [i.kind for i in dash if i.name == 'd / Code']

	def test_base_search_gets_the_edit_of_its_posts(self):
		dash = r.dashboard_items('d', 'app', 'nobody', CLASSIC)
		got = by_name(r.run(FakeSource([], dash), NOMAP))
		base = got['d / search base']
		assert base.result.verdict == r.NEEDS_TXF
		assert base.result.edit == 'index=wineventlog `txf` EventCode=4624 | fields user Logon_Type'
		post = got['d / By type']
		assert post.result.edit.endswith('| fields user Logon_Type | stats count by Logon_Type')
		assert 'base search base' in post.result.reason
		assert got['d / Saved'].result.verdict == r.NOT_CLASSIFIED

	def test_studio(self):
		xml = '<dashboard version="2"><label>S</label><definition><![CDATA[%s]]></definition></dashboard>' % json.dumps(STUDIO)
		dash = r.dashboard_items('s', 'app', 'nobody', xml)
		saved = [r.Item('s1', 'app', 'nobody', 'report', '| tstats count from datamodel=Authentication')]
		got = by_name(r.run(FakeSource(saved, dash), NOMAP))
		assert got['s / b'].kind == 'base search' and got['s / b'].result.verdict == r.NEEDS_TXF
		assert got['s / Types'].result.verdict == r.NEEDS_TXF
		assert got['s / term'].result.verdict == r.NEEDS_TX
		assert got['s / s'].result.verdict == r.NEEDS_MAP
		assert got['s / i'].kind == 'input' and got['s / i'].result.verdict == r.UNCHANGED

	def test_bad_xml_and_other_views(self):
		got = r.dashboard_items('d', 'a', 'o', '<dashboard><row>')
		assert r.run(FakeSource([], got), NOMAP)[0].result.verdict == r.NOT_CLASSIFIED
		assert r.dashboard_items('v', 'a', 'o', '<view><module/></view>') == []

	def test_chained_post_process_and_a_loop(self):
		xml = """<dashboard><label>c</label>
		  <search id="a"><query>index=wineventlog EventCode=4624</query></search>
		  <row><panel><table><search id="b" base="a"><query>| fields user</query></search></table></panel>
		  <panel><table><search base="b"><query>| stats count by user</query></search></table></panel>
		  <panel><table><search id="x" base="y"><query>| head 1</query></search></table></panel>
		  <panel><table><search id="y" base="x"><query>| head 2</query></search></table></panel></row></dashboard>"""
		got = r.run(FakeSource([], r.dashboard_items('c', 'a', 'o', xml)), NOMAP)
		res = dict((i.sid or i.name, i.result) for i in got)
		assert res['a'].verdict == r.NEEDS_TXF and res['a'].edit == 'index=wineventlog `txf` EventCode=4624'
		assert res['b'].verdict == r.NEEDS_TXF and res['b'].edit == ''
		last = [i for i in got if i.sid is None][0]
		assert last.result.edit == 'index=wineventlog `txf` EventCode=4624 | fields user | stats count by user'
		assert res['x'].verdict == r.NOT_CLASSIFIED and res['y'].verdict == r.NOT_CLASSIFIED

	def test_post_process_of_a_saved_search_base(self):
		xml = """<dashboard><label>c</label><search id="a" ref="s1"></search>
		  <row><panel><table><search base="a"><query>| stats count by user</query></search></table></panel></row></dashboard>"""
		saved = [r.Item('s1', 'app', 'nobody', 'report', 'index=wineventlog EventCode=4624')]
		got = r.run(FakeSource(saved, r.dashboard_items('c', 'app', 'o', xml)), MAP)
		post = [i for i in got if i.base is not None][0]
		assert post.result.verdict == r.UNCHANGED
		assert r._shown(post) == 'index=wineventlog EventCode=4624 | stats count by user'

	def test_post_process_of_a_base_with_a_missing_token_says_why(self):
		xml = """<dashboard><label>c</label><search id="a"><query>index=wineventlog $f$</query></search>
		  <row><panel><table><search base="a"><query>| stats count</query></search></table></panel></row></dashboard>"""
		got = r.run(FakeSource([], r.dashboard_items('c', 'app', 'o', xml)), MAP)
		post = [i for i in got if i.base is not None][0]
		assert post.result.verdict == r.NOT_CLASSIFIED and '$f$' in post.result.reason

	def test_objects_of_this_app_are_unchanged(self):
		saved = [r.Item('Consume KV', 'tenx-for-splunk', 'nobody', 'alert', '| tstats count where index=* by sourcetype')]
		assert r.run(FakeSource(saved, []), NOMAP)[0].result.verdict == r.UNCHANGED
		assert verdict('`tenx-events` | stats count', NOMAP).verdict == r.UNCHANGED

	def test_tokens(self):
		assert r.substitute('index=w x=$a$ | stats count', {}) == 'index=w x=tenx_token_value | stats count'
		assert r.substitute('index=$i$ x', {}).startswith('!')
		assert r.substitute('index=$i$ x', {'i': 'w'}) == 'index=w x'
		assert r.substitute('x="$a|s$"', {}) == 'x="tenx_token_value"'


# -------------------------------------------------------------------------------------------
# Files and the command line

def write(path, text):
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, 'w', encoding='utf-8') as f:
		f.write(text)


@pytest.fixture
def etc(tmp_path):
	root = str(tmp_path / 'etc')
	write(os.path.join(root, 'apps', 'sec', 'default', 'macros.conf'),
		'[win]\ndefinition = index=wineventlog sourcetype=XmlWinEventLog\n\n[ctime(1)]\nargs = f\ndefinition = convert ctime($f$)\n')
	write(os.path.join(root, 'apps', 'sec', 'default', 'savedsearches.conf'),
		'[default]\ndispatch.earliest_time = -24h\n\n[failed]\nsearch = `win` EventCode=4625 \\\n| stats count by user\n'
		'enableSched = 1\nalert_type = number of events\n\n[words]\nsearch = index=wineventlog Kerberos | stats count\n\n'
		'[dm]\nsearch = | tstats count from datamodel=Authentication\n\n[broken]\nsearch = `nope` x\n\n[nosearch]\nx = 1\n')
	write(os.path.join(root, 'apps', 'sec', 'local', 'savedsearches.conf'),
		'[words]\nsearch = index=main Kerberos | stats count\n')
	write(os.path.join(root, 'users', 'ann', 'sec', 'local', 'savedsearches.conf'),
		'[mine]\nsearch = index=wineventlog | stats count by host\n')
	write(os.path.join(root, 'apps', 'sec', 'default', 'data', 'ui', 'views', 'd.xml'), CLASSIC)
	write(os.path.join(root, 'apps', 'other', 'default', 'data', 'ui', 'views', 'studio.json'), json.dumps(STUDIO))
	write(os.path.join(root, 'apps', 'other', 'default', 'data', 'ui', 'views', 'nav.xml'), '<nav><view name="x"/></nav>')
	return root


class TestCommandLine:
	def test_dir_source(self, etc):
		src = r.DirSource(etc)
		saved = by_name(src.saved)
		assert set(saved) == {'failed', 'words', 'dm', 'broken', 'mine'}
		assert saved['words'].search == 'index=main Kerberos | stats count'
		assert (saved['mine'].app, saved['mine'].owner) == ('sec', 'ann')
		assert saved['failed'].kind == 'alert' and saved['failed'].search.startswith('`win` EventCode=4625 \n|')
		assert {i.app for i in src.dashboards} == {'sec', 'other'}

	def test_dir_source_app_filter(self, etc):
		src = r.DirSource(etc, ['other'])
		assert src.saved == [] and {i.app for i in src.dashboards} == {'other'}

	def test_main_prints_table_summary_and_csv(self, etc, tmp_path):
		out, path = io.StringIO(), str(tmp_path / 'r.csv')
		assert r.main(['--dir', etc, '--sourcetype', 'XmlWinEventLog', '--index', 'wineventlog', '--csv', path], out) == 0
		text = out.getvalue()
		assert text.splitlines()[0].split()[:6] == ['object', 'app', 'owner', 'kind', 'verdict', 'reason']
		summary = [l for l in text.splitlines() if ' objects: ' in l][0]
		assert re.match(r'^\d+ objects: \d+ unchanged, \d+ needs tx, \d+ needs txf, \d+ needs field map, \d+ limit, '
			r'\d+ not classified, \d+ not affected$', summary)
		rows = list(csv.DictReader(open(path, encoding='utf-8')))
		assert list(rows[0]) == ['object', 'app', 'owner', 'kind', 'verdict', 'reason', 'search', 'edit']
		got = dict((x['object'], x) for x in rows)
		assert got['failed']['verdict'] == r.NEEDS_TXF
		assert got['failed']['edit'].startswith('`txf` `win` EventCode=4625')
		assert got['words']['verdict'] == r.NOT_AFFECTED
		assert got['dm']['verdict'] == r.NEEDS_MAP
		assert got['broken']['verdict'] == r.NOT_CLASSIFIED and '`nope`' in got['broken']['reason']
		assert got['mine']['verdict'] == r.UNCHANGED
		assert sum(int(n) for n in re.findall(r'(\d+) (?:unchanged|needs|limit|not)', summary)) == len(rows)

	def test_main_with_field_map(self, etc):
		out = io.StringIO()
		assert r.main(['--dir', etc, '--sourcetype', 'XmlWinEventLog', '--field-map', 'XmlWinEventLog'], out) == 0
		assert ' 0 needs field map' in out.getvalue()

	@pytest.mark.parametrize('argv', [
		['--dir', '.'],
		['--dir', '.', '--sourcetype', 'a', '--field-map', 'b'],
		['--dir', '/nonexistent/folder', '--sourcetype', 'a'],
	])
	def test_main_refuses(self, argv, capsys):
		assert r.main(argv, io.StringIO()) == 2

	def test_rest_needs_credentials(self, monkeypatch):
		monkeypatch.delenv('TENX_SPLUNKD_AUTH', raising=False)
		monkeypatch.delenv('TENX_SPLUNKD_TOKEN', raising=False)
		assert r.main(['--splunkd', 'https://127.0.0.1:1', '--sourcetype', 'a'], io.StringIO()) == 2


# -------------------------------------------------------------------------------------------
# REST

class FakeSplunkd(object):
	def __init__(self, parse=None, refuse=None):
		self.calls, self.parse, self.refuse = [], parse or {}, refuse

	def call(self, method, path, params=None):
		self.calls.append((method, path, params))
		if path.endswith('/saved/searches'):
			return {'entry': [
				{'name': 'a', 'acl': {'app': 'sec', 'owner': 'nobody'}, 'content': {'search': '`win` EventCode=1 | stats count',
					'is_scheduled': '1', 'alert_type': 'number of events'}},
				{'name': 'b', 'acl': {'app': 'other', 'owner': 'ann'}, 'content': {'search': 'index=main x'}}]}
		if path.endswith('/data/ui/views'):
			return {'entry': [
				{'name': 'd', 'acl': {'app': 'sec', 'owner': 'nobody'}, 'content': {'eai:data': CLASSIC}},
				{'name': 'h', 'acl': {'app': 'sec', 'owner': 'nobody'}, 'content': {'eai:data': '<x/>', 'isDashboard': '0'}}]}
		if path.endswith('/search/parser'):
			if self.refuse:
				raise urllib.error.HTTPError(path, 400, 'Bad Request', {}, io.BytesIO(json.dumps(
					{'messages': [{'type': 'FATAL', 'text': self.refuse}]}).encode()))
			return self.parse
		raise AssertionError(path)


class TestRest:
	PARSED = {'commands': [{'command': 'search', 'rawargs': 'index=wineventlog sourcetype=XmlWinEventLog EventCode=1 '},
		{'command': 'stats', 'rawargs': 'count'}]}

	def test_items_and_expansion(self):
		fake = FakeSplunkd(self.PARSED)
		items = by_name(r.run(r.RestSource(fake), NOMAP))
		assert items['a'].kind == 'alert' and items['a'].result.verdict == r.NEEDS_TXF
		assert items['a'].result.edit == '`txf` `win` EventCode=1 | stats count'
		assert items['b'].result.verdict == r.NOT_AFFECTED
		assert not any(i.startswith('h') for i in items)
		parser_calls = [c for c in fake.calls if c[1].endswith('/search/parser')]
		assert parser_calls[0][1] == '/servicesNS/nobody/sec/search/parser'
		assert parser_calls[0][2] == {'q': 'search `win` EventCode=1 | stats count', 'parse_only': 'true'}

	def test_expanded_generating_search(self):
		fake = FakeSplunkd({'commands': [{'command': 'tstats', 'rawargs': 'count from datamodel=Authentication'}]})
		src = r.RestSource(fake)
		assert src.expand(r.Item('x', 'a', 'o', 'report', ''), '| tstats `s` count from datamodel=Authentication') == \
			'| tstats count from datamodel=Authentication'

	def test_parser_refusal_is_not_classified(self):
		fake = FakeSplunkd(refuse='Error in macro: unknown')
		items = by_name(r.run(r.RestSource(fake), NOMAP))
		assert items['a'].result.verdict == r.NOT_CLASSIFIED and 'Error in macro: unknown' in items['a'].result.reason

	def test_app_filter(self):
		items = r.run(r.RestSource(FakeSplunkd(self.PARSED), ['other']), NOMAP)
		assert [i.name for i in items] == ['b']

	def test_no_macro_no_parser_call(self):
		fake = FakeSplunkd()
		assert r.RestSource(fake).expand(r.Item('x', 'a', 'o', 'report', ''), 'index=w x') is None
		assert fake.calls == []
