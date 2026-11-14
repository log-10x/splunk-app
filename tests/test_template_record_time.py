"""
Template records take their index time.

A record sent to HEC's event endpoint carries the sender's time, which for Fluent Bit is the
time of the event that made the template, and DATETIME_CONFIG = CURRENT does not apply to
that endpoint. So [tenx_dml_raw_json] runs tenx-dml-time, which sets _time to the clock
while the record is parsed, and Consume KV (savedsearches.conf) stores the records indexed in
the last seven minutes, by index time, so a record that reaches the index late is stored too.
"""
import configparser
import os
import re

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))


def conf(name):
	parser = configparser.RawConfigParser(strict=False, interpolation=None)
	parser.optionxform = str
	parser.read(os.path.join(APP, 'default', name))
	return parser


def transforms_of(stanza):
	props = conf('props.conf')
	return {k: v for k, v in props.items(stanza) if k.startswith('TRANSFORMS-')}


class TestTemplateRecordTime:
	def test_the_template_sourcetype_runs_the_transform(self):
		assert transforms_of('tenx_dml_raw_json') == {'TRANSFORMS-tenx_dml_time': 'tenx-dml-time'}

	def test_the_transform_sets_time_to_the_clock_and_nothing_else(self):
		expr = conf('transforms.conf').get('tenx-dml-time', 'INGEST_EVAL')
		assert expr == '_time=time()'
		# now() is rejected at index time ("Bad function"), see transforms.conf.
		assert 'now()' not in expr
		# One assignment: a working field set and removed in the same expression was metered.
		assert len(re.findall(r'(?<![=!<>])=(?!=)', expr)) == 1

	def test_index_time_without_a_sender_time_is_unchanged(self):
		assert conf('props.conf').get('tenx_dml_raw_json', 'DATETIME_CONFIG') == 'CURRENT'

	def test_consume_kv_reads_the_last_seven_minutes_of_index_time(self):
		# A record held on a heavy forwarder reaches the index after the time it was parsed;
		# selecting by index time stores it in the first run after it is indexed.
		saved = conf('savedsearches.conf')
		search = saved.get('Consume KV', 'search')
		assert search == 'index=tenx_dml sourcetype=tenx_dml_raw_json _index_earliest=-7m _index_latest=now'
		assert saved.get('Consume KV', 'cron_schedule') == '*/5 * * * *'
		# the event-time window only bounds the buckets read, and is wider than the index-time one
		assert saved.get('Consume KV', 'dispatch.earliest_time') == '-24h'
		assert saved.get('Consume KV', 'dispatch.latest_time') == 'now'

	def test_backfill_kv_is_unchanged(self):
		saved = conf('savedsearches.conf')
		assert saved.get('Backfill KV', 'search') == 'index=tenx_dml sourcetype=tenx_dml_raw_json'
		assert saved.get('Backfill KV', 'dispatch.earliest_time') == '-30d'
		assert saved.get('Backfill KV', 'enableSched') == '0'

	def test_compact_events_keep_their_own_time_transform(self):
		assert transforms_of('tenx_encoded') == {'TRANSFORMS-tenx_time': 'tenx-event-time'}
