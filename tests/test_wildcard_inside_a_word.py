"""
A wildcard inside a word after `tx` (Splunk Enterprise 10.4.3). In a base search on the index, a word
with `*` in it is matched against the event's terms: some major segment or minor piece of the text
is the word, case-insensitively, `*` standing for any characters. `tx` applies its words in a
search after a pipe Splunk cannot fold, and there a word with a `*` after its first character is
matched as its prefix alone (Windows 662 sample, `Se*Privilege`: 3 on the index, 662 through `tx`;
`le*FO` 0 and 662). TERM() and CASE() of some words differ the same way (TERM(10.2.236.94): 0 on the
index, 1 after a pipe). wild_plan() replaces each such word by a field that an eval sets from
term_regex(); `tx` and `txf` apply that eval and search before their final search (macros.conf
[tenx-wild], the plan stored on the job by the prefilter), the search rewrite applies them as its
final search. searchmatch() is not used: it does not let `*` cross a minor breaker (Se:Privilege) or
stand for nothing (SePrivilege) as the index does.

The tables (wildcard_measured.py, wildcard_plan_measured.py) are 184 words, TERM() and CASE() among them, on 112
events, measured on the index, after a pipe, and through the plan.
"""
import hashlib
import os
import re

import pytest

import tenx_prefilter_parser as p
from wildcard_measured import EVENTS, MEASURED
from wildcard_plan_measured import TC_EVENTS, TERM_CASE, WORDS as PLAN_WORDS

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tenx-for-splunk')
# TERM() of a word with a major breaker where it selects events: left to the final search (see TestOnTheIndex)
MAJOR_TERM = {'TERM(+0000)', 'TERM(Se--Privilege)', 'TERM(SeX%20Privilege)', 'TERM(x=Y;z=W)'}
# NOT CASE() on the index (see TestOnTheIndex)
NOT_CASE = {'NOT CASE(root)', 'NOT CASE(Root)', 'NOT CASE(Se*Privilege)', 'NOT CASE(se*privilege)', 'NOT (CASE(root) OR TERM(0000))'}

INSIDE = [(w, base) for w, base, _ in MEASURED if len(w.strip('"').split()) == 1 and p.mid_wildcard(w.strip('"'))]
# words with none such inside them (a word among others that has one is in neither list)
OTHERS = [(w, base, pipe) for w, base, pipe in MEASURED
		  if not any(p.mid_wildcard(t.strip('"()')) for t in w.split())]


def matched(word):
	rx = re.compile(p.term_regex(word))
	return [n for n, event in enumerate(EVENTS) if rx.search(event)]


class TestTheTermRegex:
	@pytest.mark.parametrize("word, base", INSIDE)
	def test_matches_what_the_index_matches(self, word, base):
		assert matched(word.strip('"')) == base

	def test_the_table_covers_the_breakers(self):
		assert len(INSIDE) >= 30 and len(MEASURED) >= 75
		# a `*` crosses a minor breaker inside a major segment (Se:Privilege, se_x_privilege) and none
		# that ends one (Se(Privilege), SeBackup Privilege), stands for nothing (SePrivilege), and the
		# word is anchored at both ends of the term (abcSeXPrivilegedef is not Se*Privilege)
		assert matched('Se*Privilege') == [0, 1, 8, 10, 15, 17, 18, 27, 28, 29, 30, 33, 34, 35, 39]
		assert matched('ab*ef') == [9] and matched('Se*X') == [37] and matched('SeX*Y') == []


class TestWhereThePartsGo:
	"""The index takes each part after a `*` at its first place in the rest of the term, and the last part again only
	after the end of each place it found (Splunk Enterprise 10.4.3, events written for it, TC_EVENTS 26 on)."""

	@pytest.mark.parametrize("word, yes, no", [
		('19*44', ['a 19.2.3.4.44 b', 'a 198/544 b', 'a 19:2:3:4:44 b', 'a 198.27.166.158/44 b'],
		 ['a 19.2.3.444 b', 'a 198/55444 b', 'a 198.27.166.158/55444 b', '(198.27.166.158/55444)']),
		('19*4', ['a 19.2.3.444 b', 'a 198/55444 b'], []),
		('x*aa', ['q xbaa q'], ['q xaaa q']),
		('x*aba', [], ['q xababa q']),
		('x*ab', ['q xabab q', 'q xaab q', 'q xaaab q'], []),
		('y*abc', ['q yabcabc q'], ['q yabcab q']),
		('y*aa', ['q y.aa.aa q', 'q yaa.a q'], ['q y.aaa q']),
		('x*44*z', ['q x444z q'], []),
	])
	def test_as_the_index(self, word, yes, no):
		rx = re.compile(p.term_regex(word))
		assert all(rx.search(e) for e in yes) and not any(rx.search(e) for e in no)


class TestWhichWordsArePlanned:
	@pytest.mark.parametrize("word, base, pipe", OTHERS)
	def test_every_other_word_already_matches_after_the_pipe_as_on_the_index(self, word, base, pipe):
		# a leading `*`, a lone trailing `*`, a breaker in the word, a field comparison, a plain word,
		# a phrase of several words: the same events after the pipe as on the index; NOT is the one
		# exception below
		if word.startswith('NOT '):
			pytest.skip('NOT: see test_not')
		assert pipe == base, word
		assert p.wild_plan(word) is None, word

	def test_the_words_named(self):
		for word in ('Se*Privilege', 'le*FO', 'S*P*e', 'Se*Privilege*', 'Se*Se*Privilege', '2026*Z'):
			assert p.mid_wildcard(word), word
		for word in ('Se*', '*Privilege', '*Se*Privilege', '10.0*14', 'foo.*.com', 'x=Se*', 'Se?Privilege', 'abc', '*'):
			assert not p.mid_wildcard(word), word

	def test_not(self):
		# Under NOT the word is replaced too: NOT tenx_w0=1 is the opposite of the word as the index
		# matches it (on this index the base search gave the complement, 25 of 40). After the pipe
		# the word excludes every event its prefix matches, so the tx macros, whose final search
		# still applies it, can return fewer; the search rewrite writes the final search itself.
		assert p.wild_plan('NOT Se*Privilege')[1] == 'NOT tenx_w0=1'
		assert p.wild_plan('NOT (zzz OR Se*Privilege)')[1] == 'NOT (zzz OR tenx_w0=1)'


def regex_of(plan, mark):
	literal = re.search(r'%s=if\(match\(_raw, ("(?:[^"\\]|\\.)*")\)' % mark, plan[0]).group(1)
	return re.sub(r'\\(.)', r'\1', literal[1:-1])


class TestThePlan:
	def test_one_word(self):
		plan = p.wild_plan('Se*Privilege ')
		assert plan[1] == 'tenx_w0=1' and plan[0].startswith('tenx_w0=if(match(_raw, "(?i)') and plan[0].endswith('"), 1, 0)')
		assert regex_of(plan, 'tenx_w0') == p.term_regex('Se*Privilege')

	def test_every_place_of_the_word(self):
		plan = p.wild_plan('error Se*Privilege status=500 NOT foo "Sub*Sid"')
		assert plan[1] == 'error tenx_w0=1 status=500 NOT foo tenx_w1=1' and plan[0].count('match(_raw') == 2
		assert p.wild_plan('trace AND (currency OR 19*bc)')[1] == 'trace AND (currency OR tenx_w0=1)'
		assert p.wild_plan('a OR (b*c AND NOT d*e)')[1] == 'a OR (tenx_w0=1 AND NOT tenx_w1=1)'

	def test_next_to_a_phrase_a_comparison_or_a_breaker_word(self):
		# the searches the earlier filter left to the final search (the differential's OR next to a
		# phrase, a field comparison or a word with a breaker): the word is replaced where it stands
		for text, search in (('("level=INFO msg=\\"rate" OR 20*01)', '("level=INFO msg=\\"rate" OR tenx_w0=1)'),
							 ('((20*2Z OR 12.50) AND ("v1" OR NOT "089Z"))', '((tenx_w0=1 OR 12.50) AND ("v1" OR NOT "089Z"))'),
							 ('INFO AND (ra*00 OR service= search.api)', 'INFO AND (tenx_w0=1 OR service= search.api)'),
							 ('(tm*mp OR "ua=x")', '(tenx_w0=1 OR "ua=x")'), ('(*44 OR se*pi)', '(*44 OR tenx_w0=1)')):
			assert p.wild_plan(text)[1] == search, text

	def test_a_word_written_twice_has_one_mark(self):
		plan = p.wild_plan('Se*Privilege OR "Se*Privilege" NOT Se*Privilege')
		assert plan[1] == 'tenx_w0=1 OR tenx_w0=1 NOT tenx_w0=1' and plan[0].count('match(_raw') == 1

	def test_term(self):
		# a major breaker: on default segmentation no event holds the term (TERM(+0000): 0 on the index), but on
		# Windows events under the Windows add-on some did; under NOT it is taken as matching nothing (more events
		# than the final search, never fewer), elsewhere it is left to the final search
		assert p.wild_plan('NOT TERM(+0000)') == ('tenx_w0=0', 'NOT tenx_w0=1')
		assert p.wild_plan('TERM(+0000)') is None and p.wild_plan('NOT NOT TERM(+0000)') is None
		assert p.wild_plan('TERM(+0000) OR NOT TERM(+0000)')[1] == 'TERM(+0000) OR NOT tenx_w0=1'
		# a minor breaker: a whole major segment only
		plan = p.wild_plan('TERM(10.2.236.94) OR x')
		assert plan[1] == 'tenx_w0=1 OR x' and regex_of(plan, 'tenx_w0') == p.term_regex('10.2.236.94', major_only=True)
		# a wildcard inside the word: as the word alone
		plan = p.wild_plan('TERM(Se*Privilege)')
		assert plan[1] == 'tenx_w0=1' and regex_of(plan, 'tenx_w0') == p.term_regex('Se*Privilege')
		# a plain word matches alike after the pipe; a phrase inside is not read
		# a backslash: Splunk applies the escape before it matches (TERM(\\resource): what TERM(resource) matches)
		for text in ('TERM(root)', 'TERM(Se*)', 'TERM(*foo)', 'TERM("a.b")', 'TERM(a b)', 'TERM(\\resource)', 'TERM(a\\.b)',
					 'NOT TERM(\\dial)'):
			assert p.wild_plan(text) is None, text

	def test_case(self):
		# CASE(x) on the index: x as the word, any letter case, and CASE(x) as after the pipe
		plan = p.wild_plan('CASE(Se*Privilege) NOT CASE(root)')
		assert plan[1] == '(tenx_w0=1 CASE(Se*Privilege)) NOT CASE(root)'
		assert regex_of(plan, 'tenx_w0') == p.term_regex('Se*Privilege')
		for text in ('CASE(root)', 'CASE(Se*)', 'CASE(Se_*)', 'CASE(a.b*c)'):
			assert p.wild_plan(text) is None, text

	def test_a_word_against_another_word_is_left_alone(self):
		for text in ('TERM(Se*Privilege)x', 'x"y"Se*Privilege', 'Se*Privilege"x"'):
			assert p.wild_plan(text) is None, text
		assert p.wild_plan('(Se*Privilege)')[1] == '(tenx_w0=1)'

	def test_none_needed(self):
		for text in ('error', 'Se*', '*Privilege', '10.0*14', 'x=Se*Privilege', '"alpha Se*Privilege"', 'Se* | stats count',
					 '', 'a `m` b', 'a [search Se*X]', 'a (b'):
			assert p.wild_plan(text) is None, text

	def test_the_regex_reads_in_an_eval_string(self):
		unescaped = regex_of(p.wild_plan('le*FO'), 'tenx_w0')
		assert unescaped == p.term_regex('le*FO')
		assert re.search(unescaped, 'level=INFO msg') and not re.search(unescaped, 'level=INFOX')

	def test_timestamp_text(self):
		# the expanded text holds the rendered timestamp, as the raw event does
		assert matched('2026*Z') == [11] and not p.mid_wildcard('2026-11*')


class TestTheSearchRewrite:
	"""`| tx`, `| tenxsearch`, the dashboard hook and compiled alerts re-apply the words after expanding
	in the same kind of search after a pipe (Splunk Enterprise 10.4.3, Windows 662 sample:
	`| tx index=x sourcetype=tenx_encoded Se*Privilege` 662 events against 3 raw): the plan is their
	final search."""

	def resolved(self, search):
		from test_tenx_search_builder import make_builder
		return make_builder()[0].build(search).resolved

	def test_a_wildcard_inside_a_word_is_planned(self):
		got = self.resolved('search index=x sourcetype=tenx_encoded error Se*Privilege')
		assert ' | eval tenx_w0=if(match(_raw, "(?i)' in got
		assert got.endswith('"), 1, 0) | search error tenx_w0=1 | fields - tenx_w*')

	def test_other_words_are_not(self):
		got = self.resolved('search index=x sourcetype=tenx_encoded error Se*')
		assert 'tenx_w' not in got and got.endswith('| search error Se*')


class TestOnTheIndex:
	"""The plans measured on Splunk Enterprise 10.4.3 (wildcard_plan_measured.py): 96 words and 78 TERM() and CASE()
	words, each on the index, after a pipe, through the search rewrite's plan and through the tx macros' plan."""

	ROWS = PLAN_WORDS + TERM_CASE

	@pytest.mark.parametrize("word, base, pipe, search, digest, rewrite, macro", ROWS)
	def test_the_plan_is_the_one_measured(self, word, base, pipe, search, digest, rewrite, macro):
		plan = p.wild_plan(word)
		assert (plan[1] if plan else None) == search
		assert (hashlib.sha1(plan[0].encode()).hexdigest()[:12] if plan else None) == digest

	@pytest.mark.parametrize("word, base, pipe, search, digest, rewrite, macro", ROWS)
	def test_the_rewrite_keeps_what_the_index_keeps(self, word, base, pipe, search, digest, rewrite, macro):
		if word in NOT_CASE:
			# on the index NOT CASE(x) drops the letter case (NOT CASE(Root) leaves out root and ROOT too), so it is
			# not the opposite of CASE(x); the plan gives the opposite: more events, never fewer
			assert set(rewrite) > set(base)
			return
		if word in MAJOR_TERM:
			# on default segmentation the index holds no such term (0 events), but on Windows events indexed under
			# the Windows add-on it matched some; the final search after the pipe finds the text: more, never fewer
			assert set(rewrite) > set(base) and search is None
			return
		assert rewrite == base

	@pytest.mark.parametrize("word, base, pipe, search, digest, rewrite, macro", ROWS)
	def test_the_macros_keep_it_except_under_not(self, word, base, pipe, search, digest, rewrite, macro):
		if word in NOT_CASE or word in MAJOR_TERM:
			assert set(macro) > set(base)
		elif 'NOT ' in word and search is not None:
			# the final search after the pipe still excludes on the prefix (or on TERM() found inside a longer
			# term): fewer events where the word holds there, the limit named in the README
			assert set(macro) <= set(base), word
		else:
			assert macro == base

	def test_the_tables_cover_term_and_case(self):
		planned = [r for r in TERM_CASE if r[3] is not None]
		assert len(TERM_CASE) >= 70 and len(planned) >= 45 and len(PLAN_WORDS) >= 100
		# TERM() of a word with a breaker, alone: the regular expression itself gives the index's events
		for word, base, pipe, search, digest, rewrite, macro in TERM_CASE:
			m = re.fullmatch(r'TERM\(([^ ()"]+)\)', word)
			if m and search == 'tenx_w0=1':
				x = m.group(1)
				assert not p._major_breaker(x), word
				rx = re.compile(p.term_regex(x, major_only=any(c in p.MINOR_CHARS for c in x)))
				assert [n for n, e in enumerate(EVENTS + TC_EVENTS) if rx.search(e)] == base, word


class TestTheMacroStep:
	"""macros.conf [tenx-wild] reads back what the prefilter stores on the job: the same two custom fields, the same
	rule from a subsearch's name to the job's, and a default that marks nothing and keeps every event."""

	def definition(self):
		import configparser
		conf = configparser.RawConfigParser(strict=False)
		conf.read(os.path.join(APP, 'default', 'macros.conf'))
		return conf.get('tenx-wild', 'definition')

	def test_the_fields_and_the_job(self):
		step = self.definition()
		prefilter = open(os.path.join(APP, 'bin', 'tenx_prefilter.py')).read()
		for field in ('custom.tenx_wild_marks', 'custom.tenx_wild_search'):
			assert field in step and '"%s"' % field in prefilter
		assert 'custom.tenx_wild_eval' not in step and 'custom.tenx_wild_eval' not in prefilter
		assert step.count('replace(info_sid, "^subsearch_(.+)_\\d+\\.\\d+$", "\\1")') == 2
		assert 'SUBSEARCH_SID = re.compile(r"^subsearch_(.+)_\\d+\\.\\d+$")' in prefilter
		assert step.startswith('fillnull [') and '| search [' in step and step.endswith('| fields - tenx_w*')

	def test_no_subsearch_inside_eval_where_or_rex(self):
		# Splunk's union checks each dataset's commands before it runs the subsearches in them, and there eval, where
		# and rex refuse a subsearch argument ("The expression is malformed", Splunk Enterprise 10.4.3): `tx` and `txf`
		# inside | union [...] failed on 1.2.2. search and fillnull accept one.
		import configparser
		conf = configparser.RawConfigParser(strict=False)
		conf.read(os.path.join(APP, 'default', 'macros.conf'))
		for name in conf.sections():
			for command in re.split(r'\|', conf.get(name, 'definition')):
				words = command.split()
				if words and words[0] in ('eval', 'where', 'rex'):
					# outside quoted strings, a bracket in these commands can only open a subsearch
					assert '[' not in re.sub(r'"(?:[^"\\]|\\.)*"', '""', command), (name, command)

	def test_nothing_stored_marks_nothing(self):
		step = self.definition()
		assert "coalesce('custom.tenx_wild_marks', \"-\")" in step and "coalesce('custom.tenx_wild_search', \"*\")" in step
		assert 'eval search="value=\\"" . coalesce(' in step and 'tenx_wild=if(tenx_wild=="-", null(), split(tenx_wild, ","))' in step
		assert step.count('appendpipe [stats count | where count=0]') == 2

	def test_every_tx_macro_runs_it_before_the_final_search(self):
		import configparser
		conf = configparser.RawConfigParser(strict=False)
		conf.read(os.path.join(APP, 'default', 'macros.conf'))
		assert conf.get('tx', 'definition').endswith(' | `tenx-wild` | search *')
		# txf and txf(<sourcetype>) put the marks on the events in their plan step (tenx-replay-plan)
		for name in ('txf', 'txf(1)'):
			assert conf.get(name, 'definition').rstrip('"').endswith(' | `tenx-wild-planned` | search *'), name
		wild, planned = conf.get('tenx-wild', 'definition'), conf.get('tenx-wild-planned', 'definition')
		assert wild.endswith('] tenx_wild | ' + planned)
