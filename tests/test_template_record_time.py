"""
Template records take their index time.

A record sent to HEC's event endpoint carries the sender's time, which for Fluent Bit is the
time of the event that made the template, and DATETIME_CONFIG = CURRENT does not apply to
that endpoint. So [tenx_dml_raw_json] runs tenx-dml-time, which sets _time to the clock
while the record is parsed, and Consume KV (savedsearches.conf) stores the records by index
time, from a checkpoint, so a record that reaches the index late is stored too.
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

	def test_consume_kv_starts_the_action_on_every_run(self):
		# The action reads the records itself, from its checkpoint of index time, so a record
		# that reaches the index late is stored in the first run after it is indexed, and no
		# result cap or window of the search limits what is stored.
		saved = conf('savedsearches.conf')
		assert saved.get('Consume KV', 'search') == '| makeresults'
		assert saved.get('Consume KV', 'cron_schedule') == '*/5 * * * *'
		assert saved.get('Consume KV', 'action.tenx_dml_to_kv') == '1'
		actions = conf('alert_actions.conf')
		assert actions.get('tenx_dml_to_kv', 'param.source') == 'index=tenx_dml sourcetype=tenx_dml_raw_json'
		assert actions.get('tenx_dml_to_kv', 'param.from') == ''

	def test_backfill_kv_loads_from_the_start(self):
		saved = conf('savedsearches.conf')
		assert saved.get('Backfill KV', 'search') == '| makeresults'
		assert saved.get('Backfill KV', 'action.tenx_dml_to_kv.param.from') == '0'
		assert saved.get('Backfill KV', 'enableSched') == '0'

	def test_health_shows_the_template_store_gap_search(self):
		gap = conf('savedsearches.conf').get('Template Store Gap', 'search')
		view = open(os.path.join(APP, 'default', 'data', 'ui', 'views', 'tenx_health.xml')).read()
		assert '<query>%s | table missing</query>' % gap in view
		assert 'missing=indexed-stored' in gap

	def test_the_checkpoint_collection_is_not_replicated(self):
		collections = conf('collections.conf')
		assert collections.get('tenx_kv_state', 'replicate') == 'false'

	def test_compact_events_keep_their_own_time_transform(self):
		assert transforms_of('tenx_encoded') == {'TRANSFORMS-tenx_time': 'tenx-event-time'}
