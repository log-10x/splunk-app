"""
The template dictionary of the `tx` prefilter is read from the KV store, the store tenx-inflate expands
from, so it can never leave out a template whose events the search expands.

It was read from the searchable copy in the template index (`tenx-templates`), which the Consume KV
alert action writes after it stores a template, and only while new template records keep arriving.
A template in the KV store without its copy expanded its events, yet a word in its text selected none
of them: measured on Splunk Enterprise 10.4.3 with the access-control source of the scoped test
(175,480 templates, 2,171 holding `jsmith`): copies pending, `tx` jsmith 0 events against 905 raw; copies
written, 905.

The answer is checked as a whole: a message saying the lookup failed or cut its rows makes the
prefilter select every compact event, never a narrower set.
"""
import os
import random
import re

import tenx_prefilter_parser as p

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))


def load_command():
	"""tenx_prefilter.dictionary_failed, without importing the command (it dispatches at import)."""
	source = open(os.path.join(APP, 'bin', 'tenx_prefilter.py')).read()
	body = re.search(r'^def dictionary_failed\(result\):.*?(?=^\S)', source, re.S | re.M).group(0)
	scope = {}
	exec(body, scope)
	return scope['dictionary_failed']


def spl_regex(rx):
	"""An SPL regex of dictionary_search() as Python's re reads it."""
	return re.compile(rx.replace('\\p{L}\\p{N}', 'a-zA-Z0-9\\u00c0-\\uffff'))


def run_dictionary(search, templates):
	"""
	dictionary_search()'s SPL applied in Python to KV records [(pattern_hash, pattern_search)]: the
	prune, the per-piece marks, the hash term (the replace() chain as the search writes it) and the
	stats. Every record is read; nothing caps the rows.
	"""
	prune = spl_regex(re.search(r'\| where match\(tenx_t, "(.*?)"\) \|', search).group(1))
	marks = [(int(i), spl_regex(rx)) for i, rx in re.findall(r'm(\d+)=if\(match\(tenx_t, "(.*?)"\), 1, null\(\)\)', search)]
	chain = re.search(r'eval segs=split\(replace\(replace\(replace\("~" \. dml_hash, "(.*?)", " "\), "(.*?)", " "\), "(.*?)", " "\), " "\)', search)
	pats = [re.compile(g.replace('\\"', '"')) for g in chain.groups()]
	row = {}
	for dml_hash, text in templates:
		t = text.lower()
		if not prune.search(t):
			continue
		segs = "~" + dml_hash
		for pat in pats:
			segs = pat.sub(" ", segs)
		segs = segs.split(" ")
		cand = [x for x in segs if len(x) >= 2 and re.search(r"[A-Za-z0-9]", x)]
		best = max(cand, key=lambda x: "%03d" % len(x) + x) if cand else segs[0]
		cand = list(dict.fromkeys(cand))
		pre = dml_hash.split("*", 1)[0]
		sel = (['"~%s"' % pre] if pre else []) + ["TERM(%s)" % x for x in cand]
		if "*" not in dml_hash:
			h = '"~%s"' % dml_hash
		elif sel:
			h = sel[0] if len(sel) == 1 else "(%s)" % " ".join(sel)
		else:
			h = "TERM(%s)" % best
		for i, rx in marks:
			if rx.search(t):
				row["n%d" % i] = row.get("n%d" % i, 0) + 1
				row.setdefault("hs%d" % i, set()).add(h)
	return [dict((k, sorted(v) if isinstance(v, set) else v) for k, v in row.items())]


class TestTheDictionaryReadsTheKvStore:

	def test_it_reads_the_store_tenx_inflate_expands_from(self):
		s = p.dictionary_search({"jsmith"})
		assert s.startswith("| inputlookup tenx-dml-lookup ")
		assert "tenx-templates" not in s and "tenx_dml_pure" not in s

	def test_no_command_in_it_caps_the_rows(self):
		s = p.dictionary_search({"jsmith", "access_granted", "4625", "valkey*"})
		commands = [c.strip().split(" ")[0] for c in s.lstrip("| ").split(" | ")]
		assert set(commands) == {"inputlookup", "fields", "eval", "where", "stats"}, commands
		assert "[|" not in s and "[search" not in s

	def test_the_hash_as_the_engine_wrote_it(self):
		# the record key is trimmed; the compact event carries pattern_hash as written
		assert 'eval dml_hash=coalesce(pattern_hash, _key)' in p.dictionary_search({"x"})


class TestWordInTemplateTextWithManyTemplates:
	"""
	The harness class "a word in template text with more than N matching templates", N across the
	limits on the path (100; 5,000, the prefilter's own MAX_TEMPLATES, past which the word places no
	restriction; 10,000, alert maxresults; 50,000, the KV store's rows per query; 500,000), run here
	through the search's own SPL in Python. Live counts against raw: TXP.md.
	"""

	def templates(self, n_with, n_without, rnd):
		# the alphabet of the measured hashes; '-' only first, as in them (no "--" in 175,480)
		alphabet = " !#$&*+./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}"
		out, seen = [], set()
		while len(out) < n_with + n_without:
			h = ("-" if rnd.random() < 0.3 else "") + "".join(rnd.choice(alphabet) for _ in range(10))
			if h in seen:
				continue
			seen.add(h)
			k = len(out)
			text = "%s|ACS-1|site=SFO-02|event=ACCESS_GRANTED|user=%s|dept=HR" % (
				"" if k % 7 else "2026-11-13 ", "jsmith" if k < n_with else "jsmith2")
			out.append((h, text))
		return out

	def test_every_template_holding_the_word_is_counted_and_named(self):
		rnd = random.Random(500)
		for n in (100, 5000, 5001, 10001, 50001):
			kv = self.templates(n, 3000, rnd)
			search = p.dictionary_search({"jsmith"})
			d = p.dictionary_from_rows(run_dictionary(search, kv), {"jsmith"})
			assert d["jsmith"][0] == n, n
			assert d["jsmith"][1] == sorted(set(p.hash_selector(h) for h, _ in kv[:n])), n
			clause = p.prefilter(p.Parser(p.tokenize("jsmith")).parse(), d)
			if n <= p.MAX_TEMPLATES:
				assert clause == "((TERM(jsmith) OR %s))" % " OR ".join(d["jsmith"][1]), n
			else:
				# past MAX_TEMPLATES the word places no restriction: every compact event is expanded
				assert clause is None, n

	def test_five_hundred_thousand_templates_are_all_read(self):
		rnd = random.Random(5)
		kv = self.templates(120, 500000, rnd)
		d = p.dictionary_from_rows(run_dictionary(p.dictionary_search({"jsmith", "jsmith2"}), kv), {"jsmith", "jsmith2"})
		assert d["jsmith"][0] == 120 and d["jsmith2"][0] == 500000


class TestAFailedAnswerSelectsEverything:

	def test_errors_and_cut_rows(self):
		failed = load_command()
		assert failed({"results": [{"n0": "3"}], "messages": []}) is None
		assert failed({"results": [], "messages": [{"type": "INFO", "text": "ok"}]}) is None
		assert failed({"results": [], "messages": [{"type": "ERROR", "text": "KV Store is not available"}]})
		assert failed({"results": [], "messages": [{"type": "WARN", "text": "output will be truncated at 10000 results"}]})
		assert failed({"results": [], "messages": [{"type": "WARN", "text": "Search exceeded the memory limit"}]})
		assert failed({"results": [], "messages": [{"type": "FATAL", "text": "x"}]})
