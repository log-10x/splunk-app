"""
An empty line has the empty template, and a line of spaces or tabs has a template of the same text. The
template record of an empty line carries `"template":null`, which Splunk's JSON extraction reads as the
four characters "null". Consume KV stores each of them as its own text, and `tx` expands an empty line's
compact event to the empty text. A line that is the word null keeps its template "null".
"""
import configparser
import csv
import gzip
import os
import time

from support.spl_model import Model

import tenx_consts
import tenx_dml_to_kv
import tenx_util
from test_tenx_dml_to_kv import FakeSplunk, PureCopies, StoreKV, consume, fill

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))


def inflate(name):
	c = configparser.RawConfigParser(strict=False)
	c.read(os.path.join(APP, 'default', 'macros.conf'))
	return c.get(name, 'definition')


def fill_raw(monkeypatch, tmp_path, rows, kv):
	"""Piped results, as `... | sendalert tenx_dml_to_kv` writes them: (_raw, templateHash, template)."""
	path = tmp_path / 'results.csv.gz'
	with gzip.open(path, 'wt', newline='') as f:
		writer = csv.DictWriter(f, fieldnames=['_raw', 'templateHash', 'template'])
		writer.writeheader()
		for raw, template_hash, template in rows:
			writer.writerow({'_raw': raw, 'templateHash': template_hash, 'template': template})
	config = dict(tenx_consts.DEFAULT_CONFIG)
	config[tenx_util.CONFIG_LOADED] = True
	monkeypatch.setattr(tenx_util, 'get_tenx_config', lambda **kwargs: config)
	monkeypatch.setattr(tenx_util, 'ServerConnection', lambda **kwargs: None)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_kv_intf, 'TenxKVInterface', lambda *a, **k: kv)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_dml_intf, 'TenxDmlInterface', PureCopies)
	settings = {'server_uri': 'https://x', 'session_key': 'k', 'results_file': str(path), 'server_host': 'h'}
	return tenx_dml_to_kv.update_kv_store(settings)


class TestConsumeKV:

	def test_empty_and_whitespace_templates_are_stored_as_their_text(self, monkeypatch, tmp_path):
		kv = StoreKV()
		fill(monkeypatch, tmp_path, [('-Empty', ''), ('-Spaces', '   '), ('-Tab', '\t')], kv=kv)

		assert {k: r['pattern'] for k, r in kv.records.items()} == {'-Empty': '', '-Spaces': '   ', '-Tab': '\t'}
		assert kv.records['-Spaces']['pattern_terminator'] == '   '

	def test_a_null_template_in_the_record_is_the_empty_template(self, monkeypatch, tmp_path):
		kv = StoreKV()
		rows = [
			('{"templateHash":"-J}UrlyaKD8","template":null}', '-J}UrlyaKD8', 'null'),
			('{"template":null,"templateHash":"-Sorted"}', '-Sorted', 'null'),
			('{"templateHash":"-Word","template":"null"}', '-Word', 'null'),
		]
		fill_raw(monkeypatch, tmp_path, rows, kv)

		assert {k: r['pattern'] for k, r in kv.records.items()} == {'-J}UrlyaKD8': '', '-Sorted': '', '-Word': 'null'}

	def test_a_record_with_no_template_is_not_stored(self, monkeypatch, tmp_path):
		base = int(time.time()) - 3600
		splunk, kv, state = FakeSplunk([(base, '-NoTemplate', None), (base, '-Kept', 'a=$')]), StoreKV(), StoreKV()

		consume(monkeypatch, tmp_path, splunk, kv, state)

		assert list(kv.records) == ['-Kept']

	def test_the_load_search_reads_a_null_template_as_empty_before_it_drops_the_raw_text(self, monkeypatch, tmp_path):
		base = int(time.time()) - 3600
		splunk, kv, state = FakeSplunk([(base, '-A', 'a=$')]), StoreKV(), StoreKV()

		consume(monkeypatch, tmp_path, splunk, kv, state)

		reads = [q for q in splunk.searches if 'fields templateHash' in q]
		assert reads
		for q in reads:
			assert ' | ' + tenx_dml_to_kv.NULL_TEMPLATE_EVAL + ' | fields templateHash, template, _indextime | fields - _raw' in q


class TestTheInflateGuard:

	def guard(self, name):
		d = inflate(name)
		return d[d.index(' | eval tenx_expand_refused=case(isnull(tenx_log_term)') + 3:].split(' | fields', 1)[0]

	def run(self, name='tenx-inflate', **event):
		return Model().run(self.guard(name), [dict(_raw='~h', **event)])[0]

	def test_an_empty_template_expands_to_the_empty_text(self):
		# what the lookup gives for the empty template: no parts, empty part_0 and terminator
		for name in ('tenx-inflate', 'tenx-inflate-debug'):
			out = self.run(name, tenx_log_term='', tenx_part_0='', tenx_expand_refused='', tenx_text='')
			assert out['_raw'] == '' and out['tenx_expand_refused'] == '', name

	def test_a_whitespace_template_expands_to_its_text(self):
		for text in ('   ', '\t', ' \t '):
			out = self.run(tenx_log_term=text, tenx_part_0='', tenx_expand_refused='', tenx_text=text)
			assert out['_raw'] == text and out['tenx_expand_refused'] == ''

	def test_a_template_with_text_whose_expansion_is_empty_keeps_the_compact_event(self):
		# "a=$" with its value missing: the template has text, so no text is not an empty line
		out = self.run(tenx_log_term='', tenx_part_0='a=', tenx_expand_refused='', tenx_text='')
		assert out['_raw'] == '~h' and out['tenx_expand_refused'] == 'empty-expansion'
		out = self.run(tenx_log_term='', tenx_part_0='', tenx_log_parts=['x'], tenx_expand_refused='', tenx_text='')
		assert out['_raw'] == '~h' and out['tenx_expand_refused'] == 'empty-expansion'

	def test_an_expansion_that_came_out_null_keeps_the_compact_event(self):
		out = self.run(tenx_log_term='', tenx_part_0='', tenx_expand_refused='', tenx_text=None)
		assert out['_raw'] == '~h' and out['tenx_expand_refused'] == 'empty-expansion'

	def test_a_refused_empty_template_keeps_its_reason(self):
		out = self.run(tenx_log_term='', tenx_part_0='', tenx_expand_refused='hash-conflict', tenx_text=None)
		assert out['_raw'] == '~h' and out['tenx_expand_refused'] == 'hash-conflict'

	def test_a_word_null_template_expands_to_null(self):
		out = self.run(tenx_log_term='null', tenx_part_0='', tenx_expand_refused='', tenx_text='null')
		assert out['_raw'] == 'null'
