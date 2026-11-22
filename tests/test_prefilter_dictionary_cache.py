"""
The `tx` prefilter's template dictionary, read in part.

Reading every record of the KV store for each search costs seconds of search head CPU per word search
at hundreds of thousands of templates. The prefilter keeps its answer for each piece (tenx_dict_cache), and a
later search for the same pieces reads only the records Consume KV wrote in the hours since
(stored_hour), adding them to the kept answer; once a day, or for a piece without a kept answer, it reads
every record again.

What must hold: the answer read in part is never narrower than the answer over every record. Each
template that carries a piece is named (its TERM()), its count is at least the true count, and every
stored timestamp format is known. The tests build the full answer with the harness of
test_prefilter_dictionary_from_kv (the dictionary search's SPL applied in Python) and compare.
"""
import json
import random
import subprocess
import sys
import tempfile
import os

import tenx_dml_to_kv
import tenx_dml_builder
import tenx_dml_intf
import tenx_prefilter_parser as p
from test_prefilter_dictionary_from_kv import run_dictionary
from test_tenx_dml_to_kv import StoreKV

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
H = 3600
NOW = 1_800_000_000


def entries_of(records):
	return dict((r["_key"], r) for r in records)


class TestTheSearch:

	def test_a_partial_read_names_its_hours_in_the_lookup(self):
		full = p.dictionary_search({"jsmith", "error"})
		part = p.dictionary_search({"jsmith", "error"}, hours=["500000", "500001"])
		assert part == full.replace("| inputlookup tenx-dml-lookup |",
									'| inputlookup tenx-dml-lookup where (stored_hour="500000" OR stored_hour="500001") |', 1)
		assert p.dictionary_search({"x"}, hours=None) == p.dictionary_search({"x"})
		assert p.dictionary_search({"x"}, hours=[]) == p.dictionary_search({"x"})

	def test_the_lookup_returns_the_field(self):
		text = open(os.path.join(ROOT, 'tenx-for-splunk', 'default', 'transforms.conf')).read()
		line = [l for l in text.splitlines() if l.startswith('fields_list = _key,pattern_hash')][0]
		assert line.split(' = ')[1].split(',')[-1] == 'stored_hour'


class TestWhenToReadEverything:

	def records(self, full_at=NOW - 60, through=None):
		through = p.hour_of(full_at - p.CACHE_LAG_SECONDS) if through is None else through
		return {p.cache_key("jsmith"): {"n": 3, "hs": ["TERM(~a)"], "full_at": full_at, "through_hour": through},
				p.FORMATS_KEY: {"formats": ["00|%H:%M:%S"], "full_at": full_at, "through_hour": through}}

	def test_hours_since_the_kept_answer(self):
		hours = p.cache_hours(self.records(), {"jsmith"}, True, NOW, 0)
		assert hours == [str(h) for h in range(p.hour_of(NOW - 60 - p.CACHE_LAG_SECONDS),
											   p.hour_of(NOW + p.CACHE_LAG_SECONDS) + 1)]
		assert len(hours) in (1, 2, 3)

	def test_a_record_stamped_by_a_clock_ahead_is_read(self):
		# Consume KV's clock up to CACHE_LAG_SECONDS ahead of this one stamps the next hour
		now = (p.hour_of(NOW) + 1) * H - 60
		hours = p.cache_hours(self.records(full_at=now - 60), {"jsmith"}, False, now, 0)
		assert str(p.hour_of(now + 300)) in hours and p.hour_of(now + 300) == p.hour_of(now) + 1

	def test_no_kept_answer_from_before_an_upgrade_or_a_reload(self):
		records = self.records(full_at=NOW - 600)
		# no Consume KV record, or one this cannot read: every record is read
		assert p.cache_hours(records, {"jsmith"}, True, NOW, None) is None
		assert p.cache_hours(records, {"jsmith"}, True, NOW, NOW - 601) is not None
		assert p.cache_hours(records, {"jsmith"}, True, NOW, NOW - 599) is None
		assert p.cache_valid_from(None) is None and p.cache_valid_from(False) is None and p.cache_valid_from({}) is None
		assert p.cache_valid_from({"version_since": NOW - 900, "dict_reset": NOW - 300}) == NOW - 300
		assert p.cache_valid_from({"version_since": str(NOW - 900)}) == NOW - 900
		assert p.cache_valid_from({"updated": NOW}) == 0
		assert p.cache_valid_from({"version_since": "x"}) is None

	def test_everything_when_an_answer_is_missing_or_old(self):
		assert p.cache_hours({}, {"jsmith"}, False, NOW, 0) is None
		assert p.cache_hours(self.records(), {"jsmith", "error"}, False, NOW, 0) is None
		assert p.cache_hours({p.cache_key("jsmith"): self.records()[p.cache_key("jsmith")]}, {"jsmith"}, True, NOW, 0) is None
		assert p.cache_hours(self.records(full_at=NOW - p.CACHE_FULL_SECONDS - 1), {"jsmith"}, False, NOW, 0) is None
		assert p.cache_hours(self.records(full_at=NOW + 60), {"jsmith"}, False, NOW, 0) is None
		assert p.cache_hours(self.records(through=p.hour_of(NOW) + 1), {"jsmith"}, False, NOW, 0) is None
		bad = self.records()
		bad[p.cache_key("jsmith")]["full_at"] = "x"
		assert p.cache_hours(bad, {"jsmith"}, False, NOW, 0) is None

	def test_keys(self):
		assert p.cache_key("valkey*") == "p_valkey-" and p.cache_key("*key") == "p_-key"
		assert p.cache_keys({"b", "a"}, True) == ["p_a", "p_b", "formats"]


class TestNeverNarrowerThanEveryRecord:
	"""Templates arrive over time; a full read happens at some moment; later searches read in part."""

	WORDS = ["jsmith", "error", "denied", "door", "site", "alpha", "beta"]

	def store(self, rnd, n):
		out = []
		for i in range(n):
			words = rnd.sample(self.WORDS, rnd.randint(0, 3)) + ["w%d" % rnd.randint(0, 50)]
			out.append(("h%05d%s" % (i, rnd.choice(["", " x", "*y"])), " ".join(words) + " $ code=$"))
		return out

	def answer(self, pieces, records):
		rows = run_dictionary(p.dictionary_search(pieces), records)
		return p.dictionary_from_rows(rows, pieces)

	def test_random_arrivals(self):
		rnd = random.Random(7)
		pieces = {"jsmith", "error", "door", "w7"}
		for trial in range(30):
			templates = self.store(rnd, rnd.randint(1, 120))
			# each template is written at a time; the full read starts at S and sees those written before S
			# (and none written later); a record may become readable up to the lag after its hour stamp
			times = sorted(NOW - rnd.randint(0, 20 * H) for _ in templates)
			S = NOW - rnd.randint(0, 10 * H)
			seen = [t for t, w in zip(templates, times) if w + rnd.randint(0, p.CACHE_LAG_SECONDS - 1) < S]
			kept = entries_of(p.cache_records(self.answer(pieces, seen), set(), pieces, False, S))
			later = NOW
			hours = p.cache_hours(kept, pieces, False, later, 0)
			assert hours is not None
			read = [t for t, w in zip(templates, times) if str(p.hour_of(w)) in hours]
			merged, _ = p.cache_merge(kept, self.answer(pieces, read), set(), pieces, False)
			truth = self.answer(pieces, templates)
			for piece in pieces:
				n, terms = truth.get(piece, (0, []))
				m, mterms = merged[piece]
				assert set(terms) <= set(mterms), (trial, piece)
				assert m >= n, (trial, piece)

	def test_a_template_written_again_is_read_again(self):
		pieces = {"jsmith"}
		kept = entries_of(p.cache_records(self.answer(pieces, [("h1", "nothing here")]), set(), pieces, False, NOW - 2 * H))
		# h1 refreshed later with new text, stamped with its new hour
		hours = p.cache_hours(kept, pieces, False, NOW, 0)
		merged, _ = p.cache_merge(kept, self.answer(pieces, [("h1", "jsmith logged in")]), set(), pieces, False)
		assert str(p.hour_of(NOW)) in hours and merged["jsmith"] == (1, ["TERM(~h1)"])

	def test_past_the_template_limit_only_the_count_is_kept(self):
		d = {"error": (p.MAX_TEMPLATES + 1, ["TERM(~a)"]), "door": (2, ["TERM(~b)", "TERM(~c)"])}
		rec = entries_of(p.cache_records(d, set(), {"error", "door"}, False, NOW))
		assert rec["p_error"]["hs"] == [] and rec["p_error"]["n"] == p.MAX_TEMPLATES + 1
		merged, _ = p.cache_merge(rec, {}, set(), {"error", "door"}, False)
		assert merged["error"][0] > p.MAX_TEMPLATES and merged["door"] == (2, ["TERM(~b)", "TERM(~c)"])
		assert p.prefilter(("text", "error"), merged) is None


class TestTheFormats:

	def test_formats_kept_and_added(self):
		rows = [{"n0": "1", "hs0": "TERM(~a)", "tenx_formats": ["00|%H:%M:%S", "10|%Y-%m-%d"]}]
		keys = p.format_keys_from_rows(rows)
		assert keys == {"00|%H:%M:%S", "10|%Y-%m-%d"}
		kept = entries_of(p.cache_records({"a": (1, ["TERM(~a)"])}, keys, {"a"}, True, NOW))
		_, formats = p.cache_merge(kept, {}, {"00|%b %d"}, {"a"}, True)
		assert sorted(formats) == sorted(p.formats_from_rows([{"tenx_formats": sorted(keys | {"00|%b %d"})}]))

	def test_no_format_known_still_narrows_no_digits(self):
		kept = entries_of(p.cache_records({"a": (0, [])}, set(), {"a"}, True, NOW))
		_, formats = p.cache_merge(kept, {}, set(), {"a"}, True)
		assert formats == [] and p.digit_pieces_cleared({"4625"}, formats) == frozenset()

	def test_a_read_in_part_returns_the_same_formats_as_a_full_read(self):
		every = ["00|%H:%M:%S", "11|%Y-%m-%dT%H:%M:%S.%7QZ"]
		kept = entries_of(p.cache_records({"x": (0, [])}, set(every[:1]), {"x"}, True, NOW - H))
		_, formats = p.cache_merge(kept, {}, set(every[1:]), {"x"}, True)
		assert sorted(formats) == sorted(p.formats_from_rows([{"tenx_formats": every}]))


class TestConsumeKvStampsTheHour:

	def test_every_record_it_writes_carries_its_hour(self, monkeypatch):
		kv = StoreKV()
		store = tenx_dml_to_kv.TemplateStore(kv, tenx_dml_builder.TenxDMLBuilder('__TENX_TS__', '$'))
		monkeypatch.setattr(tenx_dml_to_kv.time, 'time', lambda: NOW + 5)
		store.store([('h1', 'a $ b'), ('h2', 'c $ d')])
		assert {r[tenx_dml_intf.STORED_HOUR] for r in kv.records.values()} == {str(p.hour_of(NOW + 5))}
		# the same text again changes nothing, so the hour stays
		monkeypatch.setattr(tenx_dml_to_kv.time, 'time', lambda: NOW + 3 * H)
		store.store([('h1', 'a $ b')], refresh=False)
		assert kv.records['h1'][tenx_dml_intf.STORED_HOUR] == str(p.hour_of(NOW + 5))
		# a hash conflict rewrites the record, with the new hour
		store.store([('h1', 'other $ text')])
		assert kv.records['h1'][tenx_dml_intf.STORED_HOUR] == str(p.hour_of(NOW + 3 * H))
		assert p.STORED_HOUR == tenx_dml_intf.STORED_HOUR

	def test_a_load_from_the_start_of_the_index_marks_the_kept_answers_old(self, monkeypatch, tmp_path):
		# the step after the store was emptied or restored: records restored come back with the hours they had,
		# so no answer kept before this load is used again
		from test_tenx_dml_to_kv import FakeSplunk, consume, flood
		import time
		splunk, kv, state = FakeSplunk(flood(10, 1700000000)), StoreKV(), StoreKV()
		consume(monkeypatch, tmp_path, splunk, kv, state)
		assert p.cache_valid_from(state.records['consume_kv']) == float(state.records['consume_kv']['version_since'])
		before = int(time.time())
		consume(monkeypatch, tmp_path, splunk, kv, state, configuration={'from': '0'})
		reset = state.records['consume_kv'][tenx_dml_to_kv.STATE_DICT_RESET]
		assert before <= int(reset) <= int(time.time()) and p.cache_valid_from(state.records['consume_kv']) == float(reset)
		# a scheduled run after it keeps the mark
		consume(monkeypatch, tmp_path, splunk, kv, state)
		assert state.records['consume_kv'][tenx_dml_to_kv.STATE_DICT_RESET] == reset


COMMAND = r'''
import json, os, sys, types, urllib.parse

root, home, cached, rows, now, state = sys.argv[1:7]
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
tenx_prefilter.time.time = lambda: float(now)

cmd = tenx_prefilter.TenxPrefilterCommand()
cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
	username='u', splunkd_uri='https://127.0.0.1:8089', session_key='k', earliest_time='0', latest_time='now'))
calls = []
def kv(path, records=None):
	calls.append(['kv', path, records])
	if cached == 'fail':
		raise RuntimeError('403')
	return json.loads(cached) if records is None else []
def rest(path, data=None, answer=True, method=None):
	calls.append(['search', data['search']])
	return {'results': json.loads(rows)}
cmd._kv, cmd._rest = kv, rest
# the Consume KV record _store_check read
cmd.store_state = json.loads(state)
d, f = cmd._dictionary({'jsmith'}, True)
print(json.dumps({'dictionary': d, 'formats': f, 'calls': calls}))
'''


class TestTheCommand:

	def run(self, cached, rows, state={'version_since': NOW - 3600}):
		with tempfile.TemporaryDirectory() as home:
			proc = subprocess.run([sys.executable, '-c', COMMAND, ROOT, home, cached, json.dumps(rows), str(NOW),
								   json.dumps(state)],
								  capture_output=True, text=True, timeout=60)
		assert proc.returncode == 0, proc.stderr[-3000:]
		return json.loads(proc.stdout.strip().splitlines()[-1])

	def test_no_kept_answer_reads_everything_and_keeps_it(self):
		out = self.run('[]', [{"n0": "2", "hs0": ["TERM(~a)", "TERM(~b)"], "tenx_formats": "00|%H:%M:%S"}])
		read, search, write = out['calls']
		assert '/storage/collections/data/tenx_dict_cache?' in read[1] and read[2] is None
		assert search[1] == p.dictionary_search({'jsmith'}, formats=True)
		assert write[1].endswith('/tenx_dict_cache/batch_save?output_mode=json')
		assert write[2] == p.cache_records({'jsmith': (2, ['TERM(~a)', 'TERM(~b)'])}, {'00|%H:%M:%S'}, {'jsmith'}, True, NOW)
		assert out['dictionary'] == {'jsmith': [2, ['TERM(~a)', 'TERM(~b)']]} and out['formats'] == [['%H:%M:%S', False, False]]

	def test_a_kept_answer_reads_the_hours_since(self):
		kept = p.cache_records({'jsmith': (2, ['TERM(~a)', 'TERM(~b)'])}, {'00|%H:%M:%S'}, {'jsmith'}, True, NOW - 600)
		out = self.run(json.dumps(kept), [{"n0": "1", "hs0": "TERM(~c)", "tenx_formats": "11|%Y"}])
		assert len(out['calls']) == 2
		hours = p.cache_hours(entries_of(kept), {'jsmith'}, True, NOW, NOW - 3600)
		assert out['calls'][1][1] == p.dictionary_search({'jsmith'}, formats=True, hours=hours)
		assert out['dictionary'] == {'jsmith': [3, ['TERM(~a)', 'TERM(~b)', 'TERM(~c)']]}
		assert sorted(map(tuple, out['formats'])) == [('%H:%M:%S', False, False), ('%Y', True, True)]

	def test_a_kept_answer_from_before_a_reload_is_not_used(self):
		kept = p.cache_records({'jsmith': (2, ['TERM(~a)', 'TERM(~b)'])}, {'00|%H:%M:%S'}, {'jsmith'}, True, NOW - 600)
		out = self.run(json.dumps(kept), [{"n0": "1", "hs0": "TERM(~c)"}], state={'version_since': NOW - 3600, 'dict_reset': NOW - 300})
		assert out['calls'][1][1] == p.dictionary_search({'jsmith'}, formats=True)
		assert out['dictionary'] == {'jsmith': [1, ['TERM(~c)']]}
		# no Consume KV record read: no kept answer is used
		out = self.run(json.dumps(kept), [{"n0": "1", "hs0": "TERM(~c)"}], state=None)
		assert out['calls'][1][1] == p.dictionary_search({'jsmith'}, formats=True)

	def test_a_cache_it_cannot_read_or_write_means_a_full_read(self):
		out = self.run('fail', [{"n0": "1", "hs0": "TERM(~a)"}])
		assert out['calls'][1][1] == p.dictionary_search({'jsmith'}, formats=True)
		assert out['dictionary'] == {'jsmith': [1, ['TERM(~a)']]}
