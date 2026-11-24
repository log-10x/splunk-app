"""
The `tx` prefilter's read in part of the template dictionary, answered without a search.

When every piece has a kept answer in tenx_dict_cache, the prefilter reads the template records stored in
the hours since from the KV store and answers them in Python (answer_records), as dictionary_search()
answers them. The search runs instead when the records are too many, when a second read finds more than
the first returned, or when a record holds text outside ASCII. A read that moves the kept answers' hour
forward is written back, so later searches read fewer hours.

What must hold: the answer is the search's answer over the same records, and a kept answer is never
narrower than the answer over every record readable when it was made. The search's SPL is applied in
Python here (spl_answer), read back from the text dictionary_search() writes.
"""
import json
import os
import random
import re
import subprocess
import sys
import tempfile

import tenx_prefilter_parser as p

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
H = 3600
NOW = 1_800_000_000


def spl_regex(rx):
	return re.compile(rx.replace('\\p{L}\\p{N}', 'a-zA-Z0-9').replace('\\"', '"'))


def spl_answer(search, records):
	"""dictionary_search()'s SPL applied in Python to KV records (dicts as the KV store returns them)."""
	formats = 'tenx_formats' in search
	prune = spl_regex(re.search(r'(?:where |tenx_any=if\()match\(tenx_t, "(.*?)"\)', search).group(1))
	marks = [(int(i), spl_regex(rx)) for i, rx in re.findall(r'm(\d+)=if\(match\(tenx_t, "(.*?)"\), 1, null\(\)\)', search)]
	chain = re.search(r'eval segs=split\(replace\(replace\(replace\("~" \. dml_hash, "(.*?)", " "\), "(.*?)", " "\), "(.*?)", " "\), " "\)', search)
	pats = [spl_regex(g) for g in chain.groups()]
	if formats:
		has = spl_regex(re.search(r'mvfilter\(match\(tenx_tp, "(.*?)"\)\)', search).group(1))
		left, right = [spl_regex(rx) for rx in re.findall(r'mvfind\(tenx_tp, "(.*?)"\)', search)]
	row, keys = {}, set()
	for r in records:
		text = r.get('pattern_search')
		if text is None and r.get('pattern') is not None:
			text = re.sub(r'[$]', '', r['pattern'])
		t = text.lower() if text is not None else None
		if formats:
			parts = [v for f in ('part_0', 'pattern_parts', 'pattern_terminator')
					 for v in ([r[f]] if isinstance(r.get(f), str) else r.get(f) or [])]
			parts = [v for v in parts if has.search(v)]
			if parts:
				keys.add(('1' if any(left.search(v) for v in parts) else '0') + ('1' if any(right.search(v) for v in parts) else '0')
						 + '|' + (r.get('timestamp_format') if r.get('timestamp_format') is not None else ''))
		if t is None or not prune.search(t):
			continue
		dml_hash = r.get('pattern_hash') if r.get('pattern_hash') is not None else r['_key']
		segs = '~' + dml_hash
		for pat in pats:
			segs = pat.sub(' ', segs)
		segs = segs.split(' ')
		cand = list(dict.fromkeys(x for x in segs if len(x) >= 2 and re.search(r'[A-Za-z0-9]', x)))
		pre = re.sub(r'\*[\s\S]*$', '', dml_hash)
		sel = (['"~%s"' % pre] if pre else []) + ['TERM(%s)' % x for x in cand]
		if '*' not in dml_hash:
			h = '"~%s"' % dml_hash
		elif sel:
			h = sel[0] if len(sel) == 1 else '(%s)' % ' '.join(sel)
		else:
			h = 'TERM(%s)' % segs[0]
		for i, rx in marks:
			if rx.search(t):
				row['n%d' % i] = row.get('n%d' % i, 0) + 1
				row.setdefault('hs%d' % i, set()).add(h)
	return [dict((k, sorted(v) if isinstance(v, set) else v) for k, v in row.items())], keys


WORDS = ['failed', 'error', 'jsmith', 'cart', 'door', 'payment', 'retry', '4625', '500', 'x7', 'valkey']
HASH_CHARS = ' !#$&*+./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}%-'
GLUE = ['', ' ', '0', 'a', '=', '-', '\n', '7']
FORMATS = ['%Y-%m-%dT%H:%M:%S.%3QZ', '%H:%M:%S', '%b %d %H:%M:%S', '', None, '__TENX_EPOCH__']


def random_text(rnd):
	out = []
	for _ in range(rnd.randint(1, 8)):
		word = rnd.choice(WORDS + ['w%d' % rnd.randint(0, 30), 'Failed', 'ERROR', 'failedx', 'xfailed', 'fail', '45'])
		out.append(word + rnd.choice(['', ' ', ' ', ',', '.', '=', '\n', '/', '-', '_', '$', ' $ ']))
	return ''.join(out)


def random_record(rnd, i):
	h = ''.join(rnd.choice(HASH_CHARS) for _ in range(rnd.randint(1, 12)))
	key = h.strip() or 'k%d' % i
	text = random_text(rnd)
	r = {'_key': key + '#%d' % i, 'pattern': text.replace(' ', ' $ ', 1) if rnd.random() < 0.8 else None}
	if rnd.random() < 0.8:
		r['pattern_hash'] = h + '#%d' % i
	if rnd.random() < 0.7:
		r['pattern_search'] = text
	if rnd.random() < 0.6:
		ts = lambda: rnd.choice(GLUE) + '__TENX_TS__' + rnd.choice(GLUE) if rnd.random() < 0.5 else rnd.choice(GLUE)
		r['part_0'] = ts()
		r['pattern_parts'] = [ts() for _ in range(rnd.randint(0, 3))] if rnd.random() < 0.8 else ts()
		r['pattern_terminator'] = rnd.choice([ts(), None])
		r['timestamp_format'] = rnd.choice(FORMATS)
	return dict((k, v) for k, v in r.items() if v is not None)


def as_rows(answer, pieces):
	dictionary, keys = answer
	return dict((piece, tuple(dictionary[piece])) for piece in pieces), set(keys)


class TestTheAnswerIsTheSearchs:

	def test_random_records(self):
		rnd = random.Random(11)
		for trial in range(300):
			records = [random_record(rnd, i) for i in range(rnd.randint(0, 40))]
			pieces = set(rnd.sample(WORDS + ['fail*', '*ed', 'pay*', '*rro*'], rnd.randint(1, 4)))
			formats = rnd.random() < 0.5
			search = p.dictionary_search(pieces, formats=formats)
			rows, keys = spl_answer(search, records)
			expected = (p.dictionary_from_rows(rows, pieces), keys if formats else set())
			got = p.answer_records(records, pieces, formats)
			assert got is not None, trial
			assert as_rows(got, pieces) == as_rows(expected, pieces), (trial, pieces)

	def test_a_word_only_as_part_of_another_is_not_carried(self):
		records = [{'_key': 'a', 'pattern_search': 'xfailed failedx fail-ed'}, {'_key': 'b', 'pattern_search': 'Login FAILED.'}]
		dictionary, _ = p.answer_records(records, {'failed'}, False)
		assert dictionary['failed'] == (1, ['"~b"'])

	def test_the_formats_of_every_record_read(self):
		records = [{'_key': 'a', 'pattern_search': 'nothing', 'part_0': '__TENX_TS__ x', 'timestamp_format': '%H:%M:%S'},
				   {'_key': 'b', 'pattern_search': 'nothing', 'pattern_parts': ['x 7__TENX_TS__', 'y'], 'timestamp_format': '%Y'},
				   {'_key': 'c', 'pattern_search': 'failed', 'pattern_terminator': 'end'}]
		dictionary, keys = p.answer_records(records, {'failed'}, True)
		assert keys == {'10|%H:%M:%S', '11|%Y'} and dictionary['failed'] == (1, ['"~c"'])
		assert p.answer_records(records, {'failed'}, False)[1] == set()


class TestWhatTheSearchAnswersInstead:

	def test_text_outside_ascii(self):
		assert p.answer_records([{'_key': 'a', 'pattern_search': 'Fehler beim Öffnen'}], {'fehler'}, False) is None
		assert p.answer_records([{'_key': 'a', 'pattern': 'KK $ failed'}], {'failed'}, False) is None
		assert p.answer_records([{'_key': 'aé', 'pattern_search': 'failed'}], {'failed'}, False) is None

	def test_empty_or_unexpected_values(self):
		assert p.answer_records([{'_key': 'a', 'pattern_search': '', 'pattern': 'failed $'}], {'failed'}, False) is None
		assert p.answer_records([{'_key': 'a', 'pattern_hash': '', 'pattern_search': 'failed'}], {'failed'}, False) is None
		assert p.answer_records([{'_key': 'a', 'pattern_search': ['failed']}], {'failed'}, False) is None
		assert p.answer_records([{'_key': 'a', 'pattern_search': 'x', 'pattern_parts': [1]}], {'failed'}, True) is None
		assert p.answer_records(['a'], {'failed'}, False) is None

	def test_a_piece_the_search_would_not_be_built_for(self):
		assert p.answer_records([{'_key': 'a', 'pattern_search': 'failed'}], {'fa.iled'}, False) is None

	def test_no_record(self):
		assert p.answer_records([], {'failed'}, True) == ({'failed': (0, [])}, set())


class TestTheRead:

	def test_the_records_of_the_hours_and_the_fields_the_search_reads(self):
		path = p.records_path(['500000', '500001'], False)
		assert path.startswith(p.DML_PATH + '?')
		query = dict(x.split('=', 1) for x in path.split('?', 1)[1].split('&'))
		assert json.loads(p.urllib.parse.unquote(query['query'])) == {'stored_hour': {'$in': ['500000', '500001']}}
		assert query['fields'] == '_key,pattern_hash,pattern_search,pattern'
		assert query['limit'] == str(p.RECORDS_MOST + 1) and query['skip'] == '0' and query['sort'] == '_key'
		fields = dict(x.split('=', 1) for x in p.records_path(['1'], True, 7, 1).split('?', 1)[1].split('&'))
		assert fields['fields'] == '_key,pattern_hash,pattern_search,pattern,timestamp_format,part_0,pattern_parts,pattern_terminator'
		assert fields['skip'] == '7' and fields['limit'] == '1'

	def test_the_search_reads_the_same_fields(self):
		for formats in (False, True):
			search = p.dictionary_search({'x'}, formats=formats)
			listed = re.search(r'\| fields (.*?) \|', search).group(1).split(', ')
			path = p.records_path(['1'], formats)
			assert dict(x.split('=', 1) for x in path.split('?', 1)[1].split('&'))['fields'].split(',') == listed


class TestKeptAnswersMoveForward:
	"""Templates arrive over time; one full read, then a run of searches that read in part and write back."""

	PIECES = {'jsmith', 'error', 'door', 'w7'}

	def answer(self, records, pieces):
		return p.answer_records(records, pieces, False)[0]

	def test_never_narrower_than_every_record_readable(self):
		rnd = random.Random(3)
		for trial in range(40):
			arrivals = []
			for i in range(rnd.randint(1, 150)):
				stamped = NOW + rnd.randint(0, 30 * H)
				words = rnd.sample(['jsmith', 'error', 'door', 'site', 'w7', 'w8'], rnd.randint(0, 3))
				arrivals.append((stamped, stamped + rnd.randint(0, p.CACHE_LAG_SECONDS - 1),
								 {'_key': 'h%04d' % i, 'pattern_search': ' '.join(words) + ' code='}))
			readable = lambda t: [r for s, v, r in arrivals if v < t]
			start = NOW + rnd.randint(0, 3 * H)
			kept = dict((r['_key'], r) for r in p.cache_records(self.answer(readable(start), self.PIECES), set(), self.PIECES, False, start))
			t = start
			for search in range(rnd.randint(1, 12)):
				t += rnd.randint(60, 4 * H)
				hours = p.cache_hours(kept, self.PIECES, False, t, 0)
				if hours is None:
					break
				fresh = self.answer([r for s, v, r in arrivals if v < t and str(p.hour_of(s)) in hours], self.PIECES)
				merged, _ = p.cache_merge(kept, fresh, set(), self.PIECES, False)
				truth = self.answer(readable(t), self.PIECES)
				for piece in self.PIECES:
					assert set(truth[piece][1]) <= set(merged[piece][1]), (trial, search, piece)
				for r in p.cache_advanced(kept, fresh, set(), self.PIECES, False, t):
					kept[r['_key']] = r

	def test_the_hour_moves_and_the_count_is_the_templates_named(self):
		kept = dict((r['_key'], r) for r in p.cache_records({'jsmith': (2, ['"~a"', '"~b"'])}, {'00|%H:%M:%S'}, {'jsmith'}, True, NOW))
		fresh = {'jsmith': (2, ['"~b"', '"~c"'])}
		later = NOW + 3 * H
		records = dict((r['_key'], r) for r in p.cache_advanced(kept, fresh, {'11|%Y'}, {'jsmith'}, True, later))
		piece = records[p.cache_key('jsmith')]
		assert piece['n'] == 3 and piece['hs'] == ['"~a"', '"~b"', '"~c"']
		assert piece['full_at'] == NOW and piece['through_hour'] == p.hour_of(later - p.CACHE_LAG_SECONDS)
		assert records[p.FORMATS_KEY]['formats'] == ['00|%H:%M:%S', '11|%Y']
		assert records[p.FORMATS_KEY]['through_hour'] == p.hour_of(later - p.CACHE_LAG_SECONDS)

	def test_nothing_to_write_when_the_hour_would_not_move(self):
		kept = dict((r['_key'], r) for r in p.cache_records({'jsmith': (1, ['"~a"'])}, set(), {'jsmith'}, False, NOW))
		assert p.cache_advanced(kept, {'jsmith': (1, ['"~b"'])}, set(), {'jsmith'}, False, NOW + 600) == []

	def test_past_the_template_limit_only_the_count_is_kept(self):
		kept = dict((r['_key'], r) for r in p.cache_records({'error': (p.MAX_TEMPLATES + 1, ['"~a"'])}, set(), {'error'}, False, NOW))
		records = p.cache_advanced(kept, {'error': (3, ['"~x"', '"~y"', '"~z"'])}, set(), {'error'}, False, NOW + 3 * H)
		assert records[0]['n'] > p.MAX_TEMPLATES and records[0]['hs'] == []
		many = ['"~t%d"' % i for i in range(p.MAX_TEMPLATES)]
		kept = dict((r['_key'], r) for r in p.cache_records({'door': (p.MAX_TEMPLATES, many)}, set(), {'door'}, False, NOW))
		records = p.cache_advanced(kept, {'door': (1, ['"~new"'])}, set(), {'door'}, False, NOW + 3 * H)
		assert records[0]['n'] == p.MAX_TEMPLATES + 1 and records[0]['hs'] == []


COMMAND = r'''
import json, os, sys, types

root, home, cached, records, more, rows, now = sys.argv[1:8]
os.makedirs(os.path.join(home, 'var', 'log', 'splunk'), exist_ok=True)
os.environ['SPLUNK_HOME'] = home
sys.path.insert(0, os.path.join(root, 'tenx-for-splunk', 'lib'))
sys.path.insert(0, os.path.join(root, 'tenx-for-splunk', 'bin'))
import tenx_prefilter
tenx_prefilter.time.time = lambda: float(now)

cmd = tenx_prefilter.TenxPrefilterCommand()
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	username='u', splunkd_uri='https://127.0.0.1:8089', session_key='k', earliest_time='0', latest_time='now'))
calls = []
def kv(path, data=None):
	calls.append(['kv', path, data])
	if '/collections/data/tenx_dml?' in path:
		if records == 'fail':
			raise RuntimeError('503')
		return json.loads(more if '&skip=0&' not in path else records)
	return json.loads(cached) if data is None else []
def rest(path, data=None, answer=True, method=None):
	calls.append(['search', data['search']])
	return {'results': json.loads(rows)}
cmd._kv, cmd._rest = kv, rest
cmd.store_state = {'version_since': float(now) - 86000}
d, f = cmd._dictionary({'jsmith'}, True)
print(json.dumps({'dictionary': d, 'formats': f, 'calls': calls}))
'''


class TestTheCommand:

	def run(self, kept, records, more='[]', rows=()):
		with tempfile.TemporaryDirectory() as home:
			proc = subprocess.run([sys.executable, '-c', COMMAND, ROOT, home, json.dumps(kept),
								   records if isinstance(records, str) else json.dumps(records), more, json.dumps(list(rows)), str(NOW)],
								  capture_output=True, text=True, timeout=60)
		assert proc.returncode == 0, proc.stderr[-3000:]
		return json.loads(proc.stdout.strip().splitlines()[-1])

	def kept(self, at=NOW - 600):
		return p.cache_records({'jsmith': (2, ['"~a"', '"~b"'])}, {'00|%H:%M:%S'}, {'jsmith'}, True, at)

	def test_records_stored_since_are_answered_without_a_search(self):
		records = [{'_key': 'c', 'pattern_search': 'jsmith logged in', 'part_0': '__TENX_TS__ ', 'timestamp_format': '%Y'}]
		out = self.run(self.kept(), records)
		assert [c[0] for c in out['calls']] == ['kv', 'kv', 'kv']
		hours = p.cache_hours(dict((r['_key'], r) for r in self.kept()), {'jsmith'}, True, NOW, NOW - 86000)
		assert out['calls'][1][1] == p.records_path(hours, True)
		assert out['calls'][2][1] == p.records_path(hours, True, 1, 1)
		assert out['dictionary'] == {'jsmith': [3, ['"~a"', '"~b"', '"~c"']]}
		assert sorted(map(tuple, out['formats'])) == [('%H:%M:%S', False, False), ('%Y', True, False)]

	def test_no_record_stored_since(self):
		out = self.run(self.kept(), [])
		assert [c[0] for c in out['calls']] == ['kv', 'kv']
		assert out['dictionary'] == {'jsmith': [2, ['"~a"', '"~b"']]}

	def test_an_answer_that_moves_its_hour_is_written_back(self):
		out = self.run(self.kept(NOW - 3 * H), [{'_key': 'c', 'pattern_search': 'jsmith'}])
		write = out['calls'][-1]
		assert write[1] == p.CACHE_PATH + '/batch_save?output_mode=json'
		kept = dict((r['_key'], r) for r in self.kept(NOW - 3 * H))
		assert write[2] == p.cache_advanced(kept, {'jsmith': (1, ['"~c"'])}, set(), {'jsmith'}, True, NOW)
		assert not any(c[0] == 'search' for c in out['calls'])

	def test_the_search_runs_when_the_records_cannot_be_answered_here(self):
		rows = [{'n0': '1', 'hs0': '"~c"', 'tenx_formats': '11|%Y'}]
		for records, more in ([{'_key': 'c', 'pattern_search': 'jsmith über'}], '[]'),\
							 ([{'_key': 'c%d' % i} for i in range(p.RECORDS_MOST + 1)], '[]'),\
							 ([{'_key': 'c', 'pattern_search': 'jsmith'}], '[{"_key": "d"}]'),\
							 ('fail', '[]'):
			out = self.run(self.kept(), records, more, rows)
			hours = p.cache_hours(dict((r['_key'], r) for r in self.kept()), {'jsmith'}, True, NOW, NOW - 86000)
			assert out['calls'][-1] == ['search', p.dictionary_search({'jsmith'}, formats=True, hours=hours)]
			assert out['dictionary'] == {'jsmith': [3, ['"~a"', '"~b"', '"~c"']]}
