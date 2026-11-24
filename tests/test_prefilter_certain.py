"""
Which compact events a `tx` search keeps whatever their values: the template's own text proves the words.

proves(tree, skeleton(record, raw)) says a compact event is CERTAIN: the words after `tx` stand in the
template's text between breakers, so the search after the expansion keeps the event whatever its values
and its rendered timestamp. Every other candidate is UNCERTAIN and only the expansion can decide it.

Checked here against the full path, modelled as tenx-inflate builds the text (values read from _raw,
empty ones dropped, mvzip stopping at the shorter list, the timestamp, the last CR) and as Splunk matches
a word after a pipe: a word is a term of the text (a major segment, or a minor piece of one, any letter
case); a phrase needs its terms and its text. A certain event must be kept by that path, and by the same
match on its skeleton, in every trial.
"""
import random
import re

import pytest

import tenx_prefilter_parser as p
from tenx_dml_builder import TenxDMLBuilder

MAJOR = re.compile(r"[ !;<>{}|&?+\[\]*,()'\"\n\r\t]")
MINOR = re.compile(r"[/:=@.\-$#%\\_]")
BUILDER = TenxDMLBuilder(timestamp_placeholder='__TENX_TS__', variable_separator='$')


def lower(text):
	return re.sub('[A-Z]', lambda m: m.group(0).lower(), text)


def terms(text):
	out = set()
	for seg in MAJOR.split(lower(text)):
		if seg:
			out.add(seg)
			out.update(x for x in MINOR.split(seg) if x)
	return out


def keeps(node, text):
	"""Splunk's search after a pipe, as modelled above, for AND, OR, words and phrases."""
	kind = node[0]
	if kind == 'text':
		words = lower(node[1]).split(' ')
		have = terms(text)
		return all(w in have for w in words) and (len(words) == 1 or lower(node[1]) in lower(text))
	if kind == 'and':
		return all(keeps(c, text) for c in node[1])
	if kind == 'or':
		return any(keeps(c, text) for c in node[1])
	raise AssertionError(kind)


def split_step(value):
	if value is None:
		return []
	text = re.sub(',,+', ',', value).strip(',')
	return text.split(',') if text else []


def expand(record, raw, stamp):
	"""tenx-inflate's _raw for a compact event (the event as it was when the macro leaves it compact)."""
	if not re.match(r'^~[^,]+,[^,]+,[\s\S]', raw) or not re.match(r'^~[^,]+,[^,]', raw):
		return raw
	values = split_step(re.sub(r'^~[^,]+,[^,]+,', '', raw, count=1))
	var_0 = re.sub(r'^~[^,]+,([^,]*)[\s\S]*$', r'\1', raw)
	parts = record['pattern_parts'] if isinstance(record['pattern_parts'], list) else [record['pattern_parts']]
	zipped = ''.join(a + b for a, b in zip(parts, values))
	if record['timestamp_format'] == '':
		text = record['part_0'] + var_0 + zipped + record['pattern_terminator']
	else:
		text = (zipped + record['pattern_terminator']).replace('__TENX_TS__', stamp)
	text = re.sub(r'\r(?![\s\S])', '', text)
	return text if text else raw


VOCAB = ['failed', 'Failed', 'FAILED', 'error', 'payment', 'cart', 'xfailed', 'failedx', 'fail', 'err', 'ok', '4625', 'x7']
BREAKS = [' ', ' ', '.', '=', ':', '-', '_', '"', ',', '\n', '\r\n', '\t', '[', ']', '{', '}', '//', '@', '#', '%', '~', '^', 'é']
WORDS = ['failed', 'error', 'payment', 'cart', 'fail', 'x7', '4625', 'Failed']


def random_template(rnd):
	out = []
	if rnd.random() < 0.4:
		out.append('$(yyyy-MM-dd HH:mm:ss)' + rnd.choice(['', ' ', 'Z ', 'x']))
	for _ in range(rnd.randint(1, 9)):
		r = rnd.random()
		if r < 0.3:
			out.append('$')
		elif r < 0.65:
			out.append(rnd.choice(VOCAB))
		else:
			out.append(rnd.choice(BREAKS))
	return ''.join(out)


def random_value(rnd):
	if rnd.random() < 0.05:
		return ''
	return ''.join(rnd.choice(VOCAB + [' ', '.', '=', '-', '_', 'a', '9', ':', '/', 'é'])
				   for _ in range(rnd.randint(1, 3))).replace(',', '')


def random_tree(rnd, depth=0):
	r = rnd.random()
	if depth < 2 and r < 0.25:
		return (rnd.choice(['and', 'or']), [random_tree(rnd, depth + 1) for _ in range(rnd.randint(2, 3))])
	if r < 0.4:
		return ('text', ' '.join(rnd.choice(WORDS) for _ in range(2)))
	return ('text', rnd.choice(WORDS))


def compact(record, rnd):
	"""A compact event for the record: the epoch or the first value, then one value per part, sometimes one too few or too many."""
	parts = record['pattern_parts'] if isinstance(record['pattern_parts'], list) else [record['pattern_parts']]
	head = '1795132800123' if record['timestamp_format'] else (random_value(rnd).strip() or 'v')
	count = max(len(parts) + rnd.choice([0, 0, 0, -1, 1]), 0)
	return '~h1,' + head + ',' + ','.join(random_value(rnd) for _ in range(count))


class TestCertainEventsAreKept:

	def test_random_templates_values_and_words(self):
		rnd = random.Random(23)
		certain = kept = trials = 0
		for trial in range(20000):
			template = random_template(rnd)
			record = BUILDER.build_kv_record_data('h1', template)
			if record.get('expand_unsafe'):
				continue
			raw = compact(record, rnd)
			tree = random_tree(rnd)
			if not p.provable(tree):
				continue
			trials += 1
			sk = p.skeleton(record, raw)
			text = expand(record, raw, rnd.choice(['2026-11-23 10:00:00', '1795132800', 'Nov 23 10:00:00 PM']))
			full = keeps(tree, text)
			kept += full
			if sk is not None and p.proves(tree, sk):
				certain += 1
				assert full, (trial, template, raw, tree, text, sk)
				assert keeps(tree, sk), (trial, template, raw, tree, sk)
		# the classification is not empty
		assert trials > 10000 and certain > 100 and kept > certain, (trials, kept, certain)

	def test_words_taken_from_the_template(self):
		# the same check where the words come from the template, so that many events are certain
		rnd = random.Random(29)
		certain = 0
		for trial in range(30000):
			template = random_template(rnd)
			record = BUILDER.build_kv_record_data('h1', template)
			words = [w for w in WORDS if w.lower() in template.lower()]
			if record.get('expand_unsafe') or not words:
				continue
			raw = compact(record, rnd)
			tree = ('and', [('text', w) for w in rnd.sample(words, min(len(words), rnd.randint(1, 2)))])
			sk = p.skeleton(record, raw)
			if sk is not None and p.proves(tree, sk):
				certain += 1
				for stamp in ('2026-11-23 10:00:00', 'failed', '', 'Z'):
					assert keeps(tree, expand(record, raw, stamp)), (trial, template, raw, tree, stamp)
				assert keeps(tree, sk), (trial, template, raw, tree)
		assert certain > 1000, certain

	def test_a_word_beside_a_value_or_the_timestamp_is_uncertain(self):
		for template, raw in (('x$failed', '~h1,v,'), ('failed$ ok', '~h1,v'), ('$(yyyy-MM-dd)failed', '~h1,1795132800123'),
							  ('a $ b failed', '~h1,v')):
			record = BUILDER.build_kv_record_data('h1', template)
			sk = p.skeleton(record, raw)
			assert sk is None or not p.proves(('text', 'failed'), sk), template

	def test_a_word_inside_the_templates_text(self):
		record = BUILDER.build_kv_record_data('h1', '$(yyyy-MM-dd HH:mm:ss) payment=$ Failed to charge card $')
		sk = p.skeleton(record, '~h1,1795132800123,77,visa')
		assert p.proves(('text', 'failed'), sk) and p.proves(('and', [('text', 'payment'), ('text', 'card')]), sk)
		assert p.proves(('text', 'failed to charge'), sk) and not p.proves(('text', 'card visa'), sk)
		assert not p.proves(('text', 'visa'), sk)

	def test_a_part_the_values_do_not_reach_is_not_text(self):
		# mvzip stops at the shorter list: a part past the last value is not in the text
		record = BUILDER.build_kv_record_data('h1', 'a $ b $ failed $ end')
		assert p.proves(('text', 'failed'), p.skeleton(record, '~h1,1,2,3'))
		assert not p.proves(('text', 'failed'), p.skeleton(record, '~h1,1,2'))

	def test_events_the_expansion_leaves_compact(self):
		record = BUILDER.build_kv_record_data('h1', 'failed $ x')
		assert p.skeleton(record, '~h1,') is None and p.skeleton(record, 'text sent whole failed') is None
		assert p.skeleton(dict(record, expand_unsafe='hash-conflict'), '~h1,v') is None
		assert p.skeleton(None, '~h1,v') is None


class TestWhatCanBeProved:

	def test_no_words_keep_every_event(self):
		assert p.provable(('true',)) and p.proves(('true',), '~h1,raw') and p.proves(('true',), '')

	@pytest.mark.parametrize('text', ['failed', 'Failed', 'payment failed', '"payment failed"', 'failed OR error',
									  '(failed OR error) payment', 'x7 4625'])
	def test_words_and_phrases(self, text):
		assert p.provable(p.Parser(p.tokenize(text)).parse())

	@pytest.mark.parametrize('text', ['fail*', '*ed', 'failed NOT retry', 'status=500 failed', 'TERM(failed)', 'CASE(Failed)',
									  'payment-service', 'host::web1 failed', '"payment  failed"', 'café', 'failed OR x=1'])
	def test_what_only_the_expansion_decides(self, text):
		assert not p.provable(p.Parser(p.tokenize(text)).parse())


class TestWhenTheResultNeedsNoText:

	def decide(self, search, job=None):
		import tenx_replay_plan as plan
		job = {'statusBuckets': 0, 'request': {}} if job is None else job
		text = p.text_after_macro(search)
		tree = p.Parser(p.tokenize(text)).parse()
		return p.needs_no_text(tree, plan.tx_reads(search, p), job)

	@pytest.mark.parametrize('search', [
		'search index=x `tx` failed | stats count',
		'search index=x `tx` "payment failed" OR error | timechart span=1h count',
		'search index=x earliest=-4h `tx` Failed | stats count AS n',
		'search index=x `tx` | timechart span=5m count',
	])
	def test_counts_and_timelines(self, search):
		assert self.decide(search)

	@pytest.mark.parametrize('search', [
		'search index=x `tx` failed',
		'search index=x `tx` failed | stats count by host',
		'search index=x `tx` failed | stats count by status',
		'search index=x `tx` failed | eval x=1 | stats count by x',
		'search index=x `tx` fail* | stats count',
		'search index=x `tx` failed NOT retry | stats count',
		'search index=x `tx` failed status=500 | stats count',
		'search index=x `txf` failed | stats count',
		'search index=x `tx` failed | stats count | append [search index=y `tx` error | stats count]',
	])
	def test_what_needs_the_text(self, search):
		assert not self.decide(search)

	def test_a_search_whose_events_splunk_keeps(self):
		assert not self.decide('search index=x `tx` failed | stats count', {'statusBuckets': 300, 'request': {}})
		assert not self.decide('search index=x `tx` failed | stats count', {'statusBuckets': 0, 'request': {'adhoc_search_level': 'verbose'}})
		assert not self.decide('search index=x `tx` failed | stats count', {})
