"""
The clause that selects a template's compact events in the `tx` prefilter (hash_selector).

One run of the hash was the selector before. The base-84 hash (log10x format spec S5.5) is cut by the
14 major breakers of its alphabet into runs of a few characters, and a short run is a term of many other
templates' events: on CloudTrail (Splunk Enterprise 10.4.3, 5,895 templates, 105,093 compact events), the
word AccessDenied, carried by 1,078 templates, selected 82,713 compact events against 6,501 raw events
holding it. The phrase "~<hash>" (no '*' in the hash) or every run of the hash (a '*' in it) is required
instead. Checked here against a model of Splunk's index: an event's terms are its major segments and,
for a word with no minor breaker, its minor pieces; a phrase needs every term of it and the phrase in the
text (any letter case).
"""
import random
import re

import tenx_prefilter_parser as p

ALPHABET = " !#$&*+./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}"
MAJOR = re.compile(r"[ !;<>{}|&?+\[\]*,()'\"\n\r\t]")
WORD = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
MINOR = re.compile(r"[/:=@.\-$#%\\_]")


def random_hash(rnd, lengths=(1, 10)):
	return ("-" if rnd.random() < 0.3 else "") + "".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(*lengths)))


def terms(raw):
	"""The index terms of a raw text: major segments, and the minor pieces inside them (lowered)."""
	out = set()
	for seg in MAJOR.split(raw.lower()):
		if seg:
			out.add(seg)
			out.update(x for x in MINOR.split(seg) if x)
	return out


def selects(clause, raw):
	"""Whether the model index selects `raw` by one hash_selector clause: each phrase and each TERM() in it."""
	have = terms(raw)
	phrases = re.findall(r'"([^"]*)"', clause)
	words = re.findall(r"TERM\((.*?)\)(?= |\)|$)", re.sub(r'"[^"]*"', "", clause))
	assert phrases or words, clause
	for phrase in phrases:
		need = set(x for x in MAJOR.split(phrase.lower()) if x)
		if not (need <= have and phrase.lower() in raw.lower()):
			return False
	return all(w.lower() in have for w in words)


class TestTheSelector:

	def test_a_hash_without_a_star_is_its_phrase(self):
		assert p.hash_selector("KC 2c#eEev") == '"~KC 2c#eEev"'
		assert p.hash_selector("-K<dSy@u") == '"~-K<dSy@u"'

	def test_a_hash_with_a_star_requires_the_text_before_it_and_every_run(self):
		assert p.hash_selector("H*ly1wX1N{") == '("~H" TERM(~H) TERM(ly1wX1N))'
		assert p.hash_selector("-K<dSy@u*az") == '("~-K<dSy@u" TERM(~-K) TERM(dSy@u) TERM(az))'
		assert p.hash_selector("-!*x") == '"~-!"'
		assert p.hash_selector("*abc*") == "TERM(~)"

	def test_a_run_between_two_stars_is_never_required(self):
		# TERM() of such a run finds no event beside a field comparison (TestHashTerm)
		assert p.hash_selector("-*Hf8l*8.5}") == '("~-" TERM(8.5))'
		assert p.hash_selector("Nss*tLW2r*") == '("~Nss" TERM(~Nss))'
		assert p.hash_selector("a*bcdefg*hi") == '("~a" TERM(~a) TERM(hi))'

	def test_every_run_it_requires_is_a_run_hash_term_could_pick(self):
		rnd = random.Random(7)
		for _ in range(5000):
			h = random_hash(rnd)
			if "*" not in h:
				continue
			runs = p.hash_runs(h)
			assert all(r in p.HASH_SEGMENT.findall("~" + h) for r in runs), h
			assert p.hash_term(h) in runs or not runs, h

	def test_the_dictionary_search_writes_the_same_clause(self):
		# the SPL of the dictionary search, read back: segments as the test of hash_term splits them, then case()
		s = p.dictionary_search({"x"})
		chain = re.search(r'eval segs=split\(replace\(replace\(replace\("~" \. dml_hash, "(.*?)", " "\), "(.*?)", " "\), "(.*?)", " "\), " "\)', s)
		pats = [re.compile(g.replace('\\"', '"')) for g in chain.groups()]
		assert 'eval h=case(NOT match(dml_hash, "\\*"), "\\"~" . dml_hash . "\\"", mvcount(tenx_sel) > 1,' in s
		assert 'cand=mvdedup(cand), tenx_pre=replace(dml_hash, "\\*[\\s\\S]*$", "")' in s

		def spl(dml_hash):
			text = "~" + dml_hash
			for pat in pats:
				text = pat.sub(" ", text)
			segs = text.split(" ")
			cand = [x for x in segs if len(x) >= 2 and re.search(r"[A-Za-z0-9]", x)]
			best = max(cand, key=lambda x: "%03d" % len(x) + x) if cand else segs[0]
			cand = list(dict.fromkeys(cand))
			pre = re.sub(r"\*[\s\S]*$", "", dml_hash)
			sel = (['"~' + pre + '"'] if len(pre) > 0 else []) + ["TERM(" + c + ")" for c in cand]
			if not re.search(r"\*", dml_hash):
				return '"~' + dml_hash + '"'
			if len(sel) > 1:
				return "(" + " ".join(sel) + ")"
			if len(sel) == 1:
				return sel[0]
			return "TERM(" + best + ")"

		rnd = random.Random(11)
		hashes = ["-*Hf8l*8.5}", "*abc*", "a*bc", "-M;*DEsWy*;", "**", "-*", "*a*b*c*d", "KC 2c#eEev"]
		hashes += [random_hash(rnd) for _ in range(5000)]
		for h in hashes:
			assert spl(h) == p.hash_selector(h), h


class TestWhatItSelects:

	def population(self, rnd, n):
		# a signed 64-bit value in base 84 is 10 characters, fewer for a small value
		hashes = list(dict.fromkeys(random_hash(rnd, (9, 10)) for _ in range(n)))
		events = []
		for h in hashes:
			for _ in range(3):
				# short tokens, as ids, keys and codes in event values are: what a short run of a hash meets
				values = ",".join("".join(rnd.choice(WORD) for _ in range(rnd.randint(1, 4))) for _ in range(rnd.randint(0, 8)))
				events.append((h, "~%s,1795132800123%s" % (h, "," + values if values else "")))
		return hashes, events

	def test_never_fewer_events_than_the_template_has(self):
		rnd = random.Random(3)
		hashes, events = self.population(rnd, 2000)
		for h, raw in events:
			assert selects(p.hash_selector(h), raw), (h, raw)

	def test_fewer_other_templates_events_than_one_run(self):
		# a third of the templates carry the word, as AccessDenied on CloudTrail (1,078 of 5,895 there)
		rnd = random.Random(4)
		hashes, events = self.population(rnd, 2000)
		chosen = set(hashes[:600])
		one = [("TERM(%s)" % p.hash_term(h)) for h in chosen]
		now = [p.hash_selector(h) for h in chosen]
		by_one = sum(1 for h0, raw in events if h0 not in chosen and any(selects(c, raw) for c in one))
		by_now = sum(1 for h0, raw in events if h0 not in chosen and any(selects(c, raw) for c in now))
		assert by_one > 50 and by_now * 4 < by_one, (by_now, by_one)
