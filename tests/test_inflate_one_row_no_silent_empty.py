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

Two changes. The lookup returns one row per key (transforms.conf max_matches = 1; every lookup of
the table matches on _key, which a record holds once). And an expansion that gives no text is never
silent: the event keeps its compact text and tenx_expand_refused says `empty-expansion`.
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

	def test_the_template_lookup_returns_one_row(self):
		assert conf('transforms.conf').get('tenx-dml-lookup', 'max_matches') == '1'

	def test_every_lookup_of_the_table_matches_on_its_key(self):
		found = 0
		for root, _, files in os.walk(os.path.join(APP, 'default')):
			for f in files:
				text = open(os.path.join(root, f), encoding='utf-8', errors='replace').read()
				for m in re.finditer(r'(?<!input)lookup\s+(?:local=\S+\s+)?tenx-dml-lookup\s+(\S+)', text):
					found += 1
					assert m.group(1) == '_key', (f, m.group(0))
		assert found >= 5


class TestNoSilentEmptyExpansion:

	def guard(self, name):
		d = inflate(name)
		return d[d.index(' | eval tenx_expand_refused=if(isnotnull(tenx_log_term)') + 3:].split(' | fields', 1)[0]

	def test_both_macros_write_the_text_to_a_working_field_first(self):
		for name in ('tenx-inflate', 'tenx-inflate-debug'):
			d = inflate(name)
			assert 'eval tenx_text=if(isnull(tenx_log_term)' in d and 'eval _raw=if(isnull(tenx_log_term)' not in d, name
			assert self.guard(name) == self.guard('tenx-inflate'), name
		assert 'fields  - tenx_text, ' in inflate('tenx-inflate')

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

	def test_an_event_of_an_unknown_template_is_unchanged(self):
		out = self.run(tenx_text=None)
		assert out['_raw'] == '~h,1' and out.get('tenx_expand_refused') is None
