"""
`tx` returned an event with no text and no tenx_expand_refused (Splunk Enterprise 10.4.3, a search
head with an indexer). The template's record was in the KV store once; the indexer's copy of the
collection, which the search head sends in the knowledge bundle as a series of CSV files, held it
twice: 3 of 403,196 records, each at the edge of two files (3 of 31 edges), the same record in both.
`lookup tenx-dml-lookup` runs on the indexer, returned both rows, every output field held two
values, the timestamp format among them, and the expansion came out null. Which records sit at an
edge depends on the collection's contents, so the same compact event expanded on one stack and not
on another: an application template (`tx` 32,904 of 32,905 events in each hour) and a classic
Windows one (196,259 of 196,260).

The inflate macros keep one copy of a repeated row (the lookup also outputs _key, once per row matched). They
do not ask the lookup for one row: with max_matches = 1, a table over max_memtable_bytes (indexed on disk, as an
indexer's copy of the collection is) and a search's lookups sent in batches, Splunk lost the match of another
key instead, one event an hour left compact with no reason (Splunk Enterprise 10.4.3, MT's application hour and
the indexer's own copy of the collection: 1 of 32,905). And an event `tx` could not expand is never returned
without a reason: a compact event whose template the lookup did not give says `no-template`, one whose
expansion gave no text says `empty-expansion`, and both keep their compact text.
"""
import configparser
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))

from support.spl_model import Model

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))


def conf(name):
	c = configparser.RawConfigParser(strict=False)
	c.read(os.path.join(APP, 'default', name))
	return c


def inflate(name):
	return conf('macros.conf').get(name, 'definition')


class TestOneRowPerKey:

	def test_the_template_lookup_keeps_its_default_matches(self):
		# max_matches = 1 lost another key's match in a search's batched lookups against a table indexed on disk
		assert not conf('transforms.conf').has_option('tenx-dml-lookup', 'max_matches')

	def test_both_macros_keep_one_copy_of_a_repeated_row(self):
		for name in ('tenx-inflate', 'tenx-inflate-debug'):
			d = inflate(name)
			assert 'lookup tenx-dml-lookup _key AS tenx_hash OUTPUT _key AS tenx_rows, ' in d, name
			i = d.index(' | eval tenx_n=mvcount(tenx_rows)')
			assert d.index('lookup tenx-dml-lookup') < i < d.index('eval tenx_ts_sec='), name
			for f in ('tenx_part_0', 'tenx_log_term', 'tenx_ts_f', 'tenx_expand_refused'):
				assert '%s=if(tenx_n>1, coalesce(mvindex(%s, 0), ""), %s)' % (f, f, f) in d, (name, f)
			assert 'tenx_log_parts=if(tenx_n>1, mvindex(tenx_log_parts, 0, floor(mvcount(tenx_log_parts)/tenx_n)-1), tenx_log_parts)' in d

	def test_every_lookup_of_the_table_matches_on_its_key(self):
		found = 0
		for root, _, files in os.walk(os.path.join(APP, 'default')):
			for f in files:
				text = open(os.path.join(root, f), encoding='utf-8', errors='replace').read()
				for m in re.finditer(r'(?<!input)lookup\s+(?:local=\S+\s+)?tenx-dml-lookup\s+(\S+)', text):
					found += 1
					assert m.group(1) == '_key', (f, m.group(0))
		assert found >= 4


class TestNoSilentEmptyExpansion:

	def guard(self, name):
		d = inflate(name)
		return d[d.index(' | eval tenx_expand_refused=case(isnull(tenx_log_term)') + 3:].split(' | fields', 1)[0]

	def test_both_macros_write_the_text_to_a_working_field_first(self):
		for name in ('tenx-inflate', 'tenx-inflate-debug'):
			d = inflate(name)
			assert 'eval tenx_text=if(isnull(tenx_log_term)' in d and 'eval _raw=if(isnull(tenx_log_term)' not in d, name
			assert self.guard(name) == self.guard('tenx-inflate'), name
		assert 'fields  - tenx_text, tenx_rows, tenx_n, ' in inflate('tenx-inflate')

	def run(self, **event):
		return Model().run(self.guard('tenx-inflate'), [dict(_raw='~h,1', **event)])[0]

	def test_an_expansion_without_text_keeps_the_compact_event_and_says_so(self):
		# found its template (tenx_log_term set, even to ''), nothing refused, no text: the event
		# that came back empty
		for term in ('.log"}', ''):
			for text in (None, ''):
				out = self.run(tenx_log_term=term, tenx_expand_refused='', tenx_text=text)
				assert out['_raw'] == '~h,1' and out['tenx_expand_refused'] == 'empty-expansion', (term, text)

	def test_an_expanded_event_is_unchanged(self):
		out = self.run(tenx_log_term='.log"}', tenx_expand_refused='', tenx_text='{"time":"..."}')
		assert out['_raw'] == '{"time":"..."}' and out['tenx_expand_refused'] == ''

	def test_a_refused_event_keeps_its_reason(self):
		for reason in ('back-reference', 'multiple-timestamps', 'hash-conflict'):
			out = self.run(tenx_log_term='x', tenx_expand_refused=reason, tenx_text=None)
			assert out['_raw'] == '~h,1' and out['tenx_expand_refused'] == reason

	def test_a_compact_event_whose_template_the_lookup_did_not_give_says_so(self):
		# no row (tenx_log_term absent): not stored yet, or the lookup missed it; returned as it is, never unmarked
		out = self.run(tenx_text=None)
		assert out['_raw'] == '~h,1' and out['tenx_expand_refused'] == 'no-template'

	def test_a_whole_event_is_not_marked(self):
		# an event the sender passed whole does not start with "~"; it has no template to find
		out = Model().run(self.guard('tenx-inflate'), [dict(_raw='2026-11-14 12:02:34 plain line', tenx_text=None)])[0]
		assert out['_raw'] == '2026-11-14 12:02:34 plain line' and out.get('tenx_expand_refused') is None
