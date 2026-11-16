"""
A wildcard inside a word after `tx` (Splunk Enterprise 10.4.3). In a base search on the index, a word
with `*` in it is matched against the event's terms: some major segment or minor piece of the text
is the word, case-insensitively, `*` standing for any characters. `tx` applies its words in a
search after a pipe Splunk cannot fold, and there a word with a `*` after its first character is
matched as its prefix alone (Windows 662 sample, `Se*Privilege`: 3 on the index, 662 through `tx`;
`le*FO` 0 and 662). The `tx` and `txf` macros now filter on term_regex() for such words before their
final search (wildcard_filter(), `eval [| tenxprefilter after=t] | search tenx_keep=1`). searchmatch()
is not used: it does not let `*` cross a minor breaker (Se:Privilege) or stand for nothing
(SePrivilege) as the index does, and for phrases and field comparisons it gave fewer events than the
final search.

The table (wildcard_measured.py) is 96 words on 40 events, measured on the index and after a pipe.
"""
import re

import pytest

import tenx_prefilter_parser as p
from wildcard_measured import EVENTS, MEASURED

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


class TestWhichWordsAreFiltered:
	@pytest.mark.parametrize("word, base, pipe", OTHERS)
	def test_every_other_word_already_matches_after_the_pipe_as_on_the_index(self, word, base, pipe):
		# a leading `*`, a lone trailing `*`, a breaker in the word, a field comparison, a plain word,
		# a phrase of several words: the same events after the pipe as on the index; NOT is the one
		# exception below
		if word.startswith('NOT '):
			pytest.skip('NOT: see test_not')
		assert pipe == base, word

	def test_the_words_named(self):
		for word in ('Se*Privilege', 'le*FO', 'S*P*e', 'Se*Privilege*', 'Se*Se*Privilege', '2026*Z'):
			assert p.mid_wildcard(word), word
		for word in ('Se*', '*Privilege', '*Se*Privilege', '10.0*14', 'foo.*.com', 'x=Se*', 'Se?Privilege', 'abc', '*'):
			assert not p.mid_wildcard(word), word

	def test_not(self):
		# On the Windows 662 sample a base search gives `NOT Se*Privilege` 0 events and `NOT Se*Zzz` 0,
		# the prefix test, as the search after the pipe does, and so does `tx`; on this small index the
		# base search gave the complement instead (25 of 40). The filter leaves a word under NOT alone.
		assert p.wildcard_filter('NOT Se*Privilege') is None
		assert p.wildcard_filter('NOT (zzz OR Se*Privilege)') is None


class TestTheFilter:
	def test_one_word(self):
		got = p.wildcard_filter('Se*Privilege ')
		assert got.startswith('tenx_w0=if(match(_raw, "(?i)') and got.endswith('"), 1, 0), tenx_keep=if(tenx_w0=1, 1, null())')

	def test_and_terms_are_their_matches(self):
		got = p.wildcard_filter('error Se*Privilege status=500 NOT foo "Sub*Sid"')
		assert got.count('match(_raw') == 2 and got.endswith('tenx_keep=if(tenx_w0=1 AND tenx_w1=1, 1, null())')

	def test_an_and_term_of_plain_words_is_evaluated_whole(self):
		got = p.wildcard_filter('trace AND (currency OR 19*bc)')
		assert got.endswith('tenx_keep=if((tenx_w0=1 OR tenx_w1=1), 1, null())') and got.count('match(_raw') == 2
		# under NOT, a word with a wildcard inside it is its prefix, as the index tests it
		got = p.wildcard_filter('a OR (b*c AND NOT d*e)')
		assert got.endswith('tenx_keep=if((tenx_w0=1 OR (tenx_w1=1 AND NOT (tenx_w2=1))), 1, null())')

	def test_anything_else_in_that_term_leaves_it_to_the_final_search(self):
		# measured on the key=value set (differential): searchmatch() of the whole term, phrases and
		# field comparisons included, gave fewer events than the final search for 4 of them
		for text in ('("level=INFO msg=\\"rate" OR 20*01)', '((20*2Z OR 12.50) AND ("v1" OR NOT "089Z"))',
					 'INFO AND (ra*00 OR service= search.api)', '(tm*mp OR "ua=x")', '(*44 OR se*pi)'):
			assert p.wildcard_filter(text) is None, text
		got = p.wildcard_filter('(tm*mp OR "ua=x") Se*Privilege')
		assert got.endswith('tenx_keep=if(tenx_w0=1, 1, null())') and got.count('match(_raw') == 1

	def test_none_needed(self):
		for text in ('error', 'Se*', '*Privilege', '10.0*14', 'x=Se*Privilege', '"alpha Se*Privilege"', 'Se* | stats count',
					 '', 'a `m` b', 'a [search Se*X]'):
			assert p.wildcard_filter(text) is None, text

	def test_the_regex_reads_in_an_eval_string(self):
		got = p.wildcard_filter('le*FO')
		literal = re.search(r'match\(_raw, ("(?:[^"\\]|\\.)*")\)', got).group(1)
		unescaped = re.sub(r'\\(.)', r'\1', literal[1:-1])
		assert unescaped == p.term_regex('le*FO')
		assert re.search(unescaped, 'level=INFO msg') and not re.search(unescaped, 'level=INFOX')

	def test_timestamp_text(self):
		# the expanded text holds the rendered timestamp, as the raw event does
		assert matched('2026*Z') == [11] and not p.mid_wildcard('2026-11*')


def evaluate(node, event):
	"""A parse tree on one event as a base search on the index evaluates its words (no field terms)."""
	kind = node[0]
	if kind == 'text':
		return bool(re.search(p.term_regex(node[1]), event))
	if kind == 'and':
		return all(evaluate(c, event) for c in node[1])
	if kind == 'or':
		return any(evaluate(c, event) for c in node[1])
	if kind == 'not':
		return not evaluate(node[1], event)
	raise AssertionError(node)


class TestWordsTogether:
	@pytest.mark.parametrize("word, base", [(w, b) for w, b, _ in MEASURED if len(w.split()) > 1 and 'NOT' not in w
											 and '"' not in w and any(p.mid_wildcard(t.strip('"()')) for t in w.split())])
	def test_and_and_or_as_on_the_index(self, word, base):
		# what the filter computes (term_regex for the wildcard words, the term itself for the others)
		tree = p.Parser(p.tokenize(word)).parse()
		assert [n for n, e in enumerate(EVENTS) if evaluate(tree, e)] == base
		assert p.wildcard_filter(word) is not None

	def test_plain_words_already_match_as_terms_after_the_pipe(self):
		plain = [(w, b, pipe) for w, b, pipe in MEASURED if '*' not in w and ' ' not in w and '=' not in w and '(' not in w]
		assert len(plain) >= 11 and all(b == pipe for _, b, pipe in plain)


class TestTheSearchRewrite:
	"""`| tx`, `| tenxsearch`, the dashboard hook and compiled alerts re-apply the words after expanding
	in the same kind of search after a pipe (Splunk Enterprise 10.4.3, Windows 662 sample:
	`| tx index=x sourcetype=tenx_encoded Se*Privilege` 662 events against 3 raw): the same filter
	runs before it."""

	def resolved(self, search):
		from test_tenx_search_builder import make_builder
		return make_builder()[0].build(search).resolved

	def test_a_wildcard_inside_a_word_is_filtered(self):
		got = self.resolved('search index=x sourcetype=tenx_encoded error Se*Privilege')
		assert ' | eval tenx_w0=if(match(_raw, "(?i)' in got
		assert got.endswith('tenx_keep=if(tenx_w0=1, 1, null()) | search tenx_keep=1 | fields - tenx_keep, tenx_w* '
							'| search error Se*Privilege')

	def test_other_words_are_not(self):
		got = self.resolved('search index=x sourcetype=tenx_encoded error Se*')
		assert 'tenx_keep' not in got and got.endswith('| search error Se*')
