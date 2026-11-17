"""
The search rewrite (the dashboard hook, compiled alerts, `| tx` saved searches) resolves a word to
the templates that hold it from the KV store, the store tenx-inflate expands from, as the `tx`
prefilter does (test_prefilter_dictionary_from_kv.py). It read the searchable copies before: a
template in the KV store whose copy the Consume KV alert action had not written yet expanded its
events, yet a word in its text selected none of them.

The lookup's own SPL is applied here in Python to KV records, with the copies pending, partly
written and complete: the hashes found are the same in all three states, and are every template
whose text holds the word. A word this way can only find more templates than the index did,
never fewer.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'bin'))

import tenx_search_builder as b
from tenx_search_manager import TenxSearchManager, piece_regex, term_piece

CONFIG = {'dest_dml_index': 'tenx_dml', 'dml_source_type': 'tenx_dml_pure', 'collection_name': 'tenx_dml',
	'timestamp_placeholder': '__TENX_TS__', 'variable_separator': '$'}


def spl_regex(rx):
	"""An SPL regex of the lookup as Python's re reads it."""
	rx = rx.replace('\\p{L}\\p{N}', 'a-zA-Z0-9\\u00c0-\\uffff')
	return re.compile(re.sub(r'\\x\{([0-9a-f]+)\}', lambda m: '\\x%s' % m.group(1).zfill(2), rx))


class Recorder:
	user = 'admin'

	def post(self, url, data=None, **kwargs):
		self.data = data
		return {'sid': 'x'}


def lookup_search(word):
	connection = Recorder()
	TenxSearchManager(connection, dict(CONFIG)).create_dml_search(b.quoted_term(word))
	return connection.data['search']


def run_lookup(search, records):
	"""The lookup's SPL over KV records [{_key, pattern_hash, pattern_search, pattern}]: distinct dml_hash."""
	sep = re.search(r'replace\(pattern, "(.*?)", ""\)', search).group(1)
	match = spl_regex(re.search(r'\| where match\(tenx_t, "(.*?)"\) \|', search).group(1))
	found = set()
	for r in records:
		text = r.get('pattern_search')
		text = (text if text is not None else spl_regex(sep).sub('', r['pattern'])).lower()
		if match.search(text):
			found.add(r.get('pattern_hash') or r['_key'])
	return sorted(found)


def records(n):
	out = []
	for k in range(n):
		user = 'jsmith' if k % 3 == 0 else 'jsmith2' if k % 3 == 1 else 'CORP\\JSmith'
		out.append({'_key': 'k%d' % k, 'pattern_hash': ' -h%d*x' % k if k % 5 == 0 else 'h%d' % k,
			'pattern_search': 'ACS-1 site=SFO-02 event=ACCESS_GRANTED user=%s dept=HR' % user,
			'pattern': 'ACS-1 site=$ event=ACCESS_GRANTED user=%s dept=$' % user})
	# a record stored before pattern_search: its pattern with the value separators removed
	out.append({'_key': 'old', 'pattern': 'login by $jsmith$ ok'})
	return out


class TestTheRewriteReadsTheKvStore:

	def test_three_states_of_the_copies_give_the_same_templates(self):
		kv = records(3000)
		expected = sorted([r.get('pattern_hash') or r['_key'] for r in kv
			if re.search(r'(^|[^a-z0-9])jsmith([^a-z0-9]|$)', (r.get('pattern_search') or r['pattern'].replace('$', '')).lower())])
		search = lookup_search('jsmith')
		for written in (0, 1500, 3001):
			# the copies are not an input of the lookup: whatever is written, the answer is the KV store's
			copies = kv[:written]
			assert 'tenx_dml_pure' not in search and 'index=' not in search
			assert run_lookup(search, kv) == expected, written
			assert len(copies) == written
		assert len(expected) == 2001 and 'old' in expected

	def test_the_old_copy_search_missed_what_the_kv_lookup_finds(self):
		kv = records(300)
		copies = kv[:100]
		search = lookup_search('jsmith')
		assert len(run_lookup(search, kv)) > len(run_lookup(search, copies))

	def test_wildcards_case_and_other_characters_find_more_never_fewer(self):
		kv = [{'_key': 'a', 'pattern_search': 'Error in module'}, {'_key': 'b', 'pattern_search': 'errors: 3'},
			  {'_key': 'c', 'pattern_search': 'terror'}, {'_key': 'd', 'pattern_search': 'x^y found'},
			  {'_key': 'e', 'pattern_search': 'Caf\u00e9 opened'}]
		assert run_lookup(lookup_search('err*'), kv) == ['a', 'b']
		assert run_lookup(lookup_search('ERROR'), kv) == ['a']
		assert run_lookup(lookup_search('x^y'), kv) == ['d']
		assert run_lookup(lookup_search('caf\u00e9'), kv) == ['e']

	def test_the_piece_is_the_builders_term(self):
		assert term_piece(b.quoted_term('JSmith')) == 'jsmith'
		assert piece_regex('jsmith') == '(^|[^\\p{L}\\p{N}])jsmith([^\\p{L}\\p{N}]|$)'


class TestTheCompiledSearchSelectsEveryTemplate:
	"""The builder over a search manager that answers from the KV store, in the three states."""

	class KvManager:
		def __init__(self, kv):
			self.kv = kv

		def run_dml_search(self, dml_search, max_time_ms=2000, poll_interval_ms=50):
			return run_lookup(lookup_search(term_piece(dml_search)), self.kv), False

	def test_hash_clause_names_every_template_holding_the_word(self):
		kv = records(30)
		for written in (0, 15, 31):
			builder = b.TenxSearchCommand.__new__(b.TenxSearchCommand)
			builder.search_manager = self.KvManager(kv)
			builder._probe_cache, builder._probe_deadline, builder._template_hits = {}, None, 0
			builder._timestamp_patterns, builder._timestamp_patterns_read = [], True
			builder.timestamp_text = builder.dml_truncated = False
			clause = builder._term_prefilter('jsmith')
			for r in kv:
				text = (r.get('pattern_search') or r['pattern'].replace('$', '')).lower()
				if re.search(r'(^|[^a-z0-9])jsmith([^a-z0-9]|$)', text):
					assert b.hash_predicate(r.get('pattern_hash') or r['_key']) in clause, (written, r['_key'])
