"""
A search through `| tx`, `| tenxsearch`, the search hook or a compiled alert that names no compact
sourcetype or source is not rewritten: it runs as typed. Over an index that holds compact events that
reads their compact text, which for most words means zero events with no sign of a problem (Splunk
Enterprise 10.4.3: `| tx index=sr_compact error` 0 events, 102 with sourcetype=tenx_encoded added,
the same as on the raw events). So such a search is first checked with a tstats probe for events of
the registered compact sourcetypes and sources in the indexes it names; when there are some, the
commands and the hook refuse with a message naming the sourcetype, and a compiled alert is flagged
for review. A search that names a sourcetype or a source, or that is rewritten, is not probed.
"""
import tenx_search_builder as sb
from tenx_alert_compiler import AlertStrategy
from test_tenx_alert_compiler import make_compiler, make_config


def result(search, config=None):
	return make_compiler(config=config).builder.build(search)


class TestTheProbe:
	def test_a_search_naming_no_sourcetype_is_probed_in_its_indexes(self):
		assert sb.unnamed_compact_probe(result('index=sr_compact error'), make_config()) == (
			'| tstats count where (index=sr_compact) (sourcetype=tenx_encoded) by index, sourcetype, source')
		assert sb.unnamed_compact_probe(result('(index=a OR index=b) error'), make_config()) == (
			'| tstats count where (index=a OR index=b) (sourcetype=tenx_encoded) by index, sourcetype, source')

	def test_no_index_named_probes_the_default_indexes(self):
		assert sb.unnamed_compact_probe(result('error'), make_config()) == (
			'| tstats count where (sourcetype=tenx_encoded) by index, sourcetype, source')

	def test_every_registered_sourcetype_and_source(self):
		config = make_config(source_types=('tenx_encoded', 'my_compact'), sources=('/var/log/x.log',))
		assert sb.unnamed_compact_probe(result('index=a error', config), config) == (
			'| tstats count where (index=a) (sourcetype=tenx_encoded OR sourcetype=my_compact OR '
			'source="/var/log/x.log") by index, sourcetype, source')

	def test_not_probed(self):
		for search in ('index=main sourcetype=web error', 'index=main source=/var/log/a.log error',
					   'index=sr_compact sourcetype=tenx_encoded error'):
			assert sb.unnamed_compact_probe(result(search), make_config()) is None, search
		assert sb.unnamed_compact_probe(result('index=a error'), make_config(source_types=())) is None

	def test_the_message_says_what_is_missing(self):
		msg = sb.unnamed_compact_message([{'index': 'sr_compact', 'sourcetype': 'tenx_encoded', 'source': 'a', 'count': '102'}])
		assert msg == ("10x: this search reads compact events (sourcetype tenx_encoded in index sr_compact) but names "
					   "no compact sourcetype or source, so it was not run: as typed it would read their compact text and "
					   "return the wrong events. Add the sourcetype to the search, for example sourcetype=tenx_encoded.")


class TestACompiledAlert:
	def test_flagged_when_the_probe_finds_compact_events(self):
		compiler = make_compiler()
		compiler.builder.search_manager.probe_rows = [{'index': 'sr_compact', 'sourcetype': 'tenx_encoded', 'count': '3'}]
		got = compiler.compile('index=sr_compact error')
		assert got.strategy == AlertStrategy.PASSTHROUGH and got.needs_review
		assert got.reason == ("this search reads compact events (sourcetype tenx_encoded in index sr_compact) but names "
							  "no compact sourcetype or source: as typed it reads their compact text and returns the wrong "
							  "events. Add the sourcetype to the search, for example sourcetype=tenx_encoded.")
		assert compiler.builder.search_manager.probes == [
			'| tstats count where (index=sr_compact) (sourcetype=tenx_encoded) by index, sourcetype, source']

	def test_unchanged_when_it_finds_none(self):
		got = make_compiler().compile('index=main error')
		assert got.strategy == AlertStrategy.PASSTHROUGH and not got.needs_review
		assert got.compiled_search == 'index=main error'
