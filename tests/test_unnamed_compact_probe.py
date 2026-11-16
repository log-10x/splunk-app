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
		assert msg == ("10x: the search was not run. Add the sourcetype to it, for example sourcetype=tenx_encoded: it "
					   "reads compact events (sourcetype tenx_encoded in index sr_compact) and names no compact sourcetype "
					   "or source, so it would return the wrong events.")


class TestACompiledAlert:
	def test_flagged_when_the_probe_finds_compact_events(self):
		compiler = make_compiler()
		compiler.builder.search_manager.probe_rows = [{'index': 'sr_compact', 'sourcetype': 'tenx_encoded', 'count': '3'}]
		got = compiler.compile('index=sr_compact error')
		assert got.strategy == AlertStrategy.PASSTHROUGH and got.needs_review
		assert got.reason == ("Add the sourcetype to the search, for example sourcetype=tenx_encoded: it reads compact "
							  "events (sourcetype tenx_encoded in index sr_compact) and names no compact sourcetype or "
							  "source, so it returns the wrong events.")
		assert compiler.builder.search_manager.probes == [
			'| tstats count where (index=sr_compact) (sourcetype=tenx_encoded) by index, sourcetype, source']

	def test_unchanged_when_it_finds_none(self):
		got = make_compiler().compile('index=main error')
		assert got.strategy == AlertStrategy.PASSTHROUGH and not got.needs_review
		assert got.compiled_search == 'index=main error'


class TestTheOriginalSourcetype:
	"""`| tx index=df sourcetype=df:kv error`: df:kv is the events' original sourcetype, carried in
	tenx_sourcetype; the compact events are indexed as tenx_encoded, so the search, not rewritten,
	matched none of them (0 events against 10,000 raw)."""

	def test_probed_for_compact_events_carrying_it(self):
		assert sb.compact_probe(result('index=df sourcetype=df:kv error'), make_config())[0] == (
			'| tstats count where (index=df) (sourcetype=tenx_encoded) NOT tenx_mapped=* (tenx_sourcetype=df:kv) '
			'by index, sourcetype, tenx_sourcetype')

	def test_not_probed(self):
		for search in ('index=df sourcetype=tenx_encoded error', 'index=df sourcetype=tenx* error',
					   'index=df sourcetype=* error', 'index=df NOT sourcetype=df:kv error'):
			assert sb.original_sourcetype_probe(result(search), make_config()) is None, search

	def test_a_wildcard_that_misses_the_compact_sourcetype_is_probed(self):
		assert sb.original_sourcetype_probe(result('index=df sourcetype=df:* error'), make_config()) == (
			'| tstats count where (index=df) (sourcetype=tenx_encoded) NOT tenx_mapped=* (tenx_sourcetype=df:*) '
			'by index, sourcetype, tenx_sourcetype')

	def test_the_message(self):
		rows = [{'index': 'df', 'sourcetype': 'tenx_encoded', 'tenx_sourcetype': 'df:kv', 'count': '10000'}]
		assert sb.original_sourcetype_message(rows) == (
			"10x: the search was not run. Write sourcetype=tenx_encoded tenx_sourcetype=df:kv instead. The compact "
			"events are indexed as tenx_encoded and carry df:kv in tenx_sourcetype, so as typed it would return none "
			"of them.")
		rows.append({'index': 'df', 'sourcetype': 'tenx_encoded', 'tenx_sourcetype': 'df:json', 'count': '7'})
		assert sb.original_sourcetype_message(rows) == (
			"10x: the search was not run. Write sourcetype=tenx_encoded (tenx_sourcetype=df:json OR "
			"tenx_sourcetype=df:kv) instead. The compact events are indexed as tenx_encoded and carry df:json and "
			"df:kv in tenx_sourcetype, so as typed it would return none of them.")

	def test_a_compiled_alert_is_flagged(self):
		compiler = make_compiler()
		compiler.builder.search_manager.probe_rows = [{'index': 'df', 'sourcetype': 'tenx_encoded', 'tenx_sourcetype': 'df:kv', 'count': '5'}]
		got = compiler.compile('index=df sourcetype=df:kv error')
		assert got.needs_review and got.reason.startswith('Write sourcetype=tenx_encoded tenx_sourcetype=df:kv instead.')


class TestTheMacroPath:
	"""The same spelling through the `tx` macro: before `tx` (or `txf`) the base search selects no
	compact event, and after `tx` the expanded event still carries the compact sourcetype (`txf`
	gives it its original one, so after `txf` the spelling works)."""

	def named(self, search):
		import tenx_prefilter_parser as pp
		before, macro = pp.macro_call(search)
		tree = pp.Parser(pp.tokenize(pp.text_after_macro(search))).parse()
		return pp.named_sourcetypes(before, tree, after_counts=(macro == '`tx`')), pp.named_indexes(before)

	def test_where_the_original_sourcetype_matches_nothing(self):
		assert self.named('index=df sourcetype=df:kv `tx` error') == (['df:kv'], ['df'])
		assert self.named('index=df `tx` sourcetype=df:kv error') == (['df:kv'], ['df'])
		assert self.named('index="df" sourcetype="df:kv" `txf` x') == (['df:kv'], ['df'])
		assert self.named('index=a OR index=b sourcetype::df:kv `tx` y') == (['df:kv'], ['a', 'b'])
		assert self.named('index=df `tx` sourcetype IN (a, b)') == (['a', 'b'], ['df'])
		# a wildcard is probed; the probe leaves out events its sourcetype term selects (tenx* selects them all)
		assert self.named('index=df sourcetype=df:* `tx` y') == (['df:*'], ['df'])

	def test_where_it_does_not_apply(self):
		for search in ('index=df `txf` sourcetype=df:kv', 'index=df msg="sourcetype=x" `tx` y',
					   'index=df tenx_sourcetype=df:kv `tx` y', 'index=df NOT sourcetype=df:kv `tx` y',
					   'index=df NOT (sourcetype=df:kv OR sourcetype=df:json) `tx` y', 'index=df sourcetype=* `tx` y',
					   'index=df sourcetype!=df:kv `tx` y'):
			assert self.named(search)[0] == [], search
		assert self.named('index=df NOT (host=a) sourcetype=df:kv `tx` y')[0] == ['df:kv']

	def test_the_probe_and_message(self):
		import tenx_prefilter_parser as pp
		assert pp.original_sourcetype_probe(['df:kv'], ['df']) == (
			'| tstats count where (index="df") `tenx-events` NOT tenx_mapped=* (tenx_sourcetype="df:kv") '
			'NOT (sourcetype="df:kv") by tenx_sourcetype')
		# events the search's own sourcetype term selects (the compact sourcetype, for tenx*) are not counted
		assert pp.original_sourcetype_probe(['tenx*', 'df:kv'], []) == (
			'| tstats count where `tenx-events` NOT tenx_mapped=* (tenx_sourcetype="df:kv" OR tenx_sourcetype="tenx*") '
			'NOT (sourcetype="df:kv" OR sourcetype="tenx*") by tenx_sourcetype')
		assert pp.original_sourcetype_probe([], ['df']) is None
		assert pp.original_sourcetype_message([{'tenx_sourcetype': 'df:kv', 'count': '3'}], '`tx`') == (
			"tx: the search was not run. Write sourcetype=df:kv after `txf` for the add-on's fields; "
			"tenx_sourcetype=df:kv before `tx` gives only the fields in their text. sourcetype=df:kv matches no "
			"compact event.")
		assert pp.original_sourcetype_message([{'tenx_sourcetype': 'df:kv', 'count': '3'}], '`txf`') == (
			"txf: the search was not run. Write tenx_sourcetype=df:kv before `txf`, or the sourcetype after it: "
			"`txf` gives each event its original sourcetype. sourcetype=df:kv selects no compact events: "
			"they carry it in tenx_sourcetype.")
		two = [{'tenx_sourcetype': 'df:kv', 'count': '3'}, {'tenx_sourcetype': 'df:json', 'count': '1'}]
		assert pp.original_sourcetype_message(two, '`tx`') == (
			"tx: the search was not run. Write (sourcetype=df:json OR sourcetype=df:kv) after `txf` for the add-ons' "
			"fields; (tenx_sourcetype=df:json OR tenx_sourcetype=df:kv) before `tx` gives only the fields in their "
			"text. sourcetype=df:json and sourcetype=df:kv match no compact event.")


class TestTheStopsArriveWhole:
	"""Splunk keeps the first 256 characters of a search command's message (Splunk Enterprise 9.4.15, 10.4.3 and
	10.6.0.5: a longer message arrived cut, here before the sourcetype to add). Each stop says what to do first, and
	with names of common length the whole message fits."""
	LIMIT = 256

	def messages(self, sourcetype, index):
		import tenx_prefilter_parser as pp
		compact = [{'index': index, 'sourcetype': 'tenx_encoded', 'source': 'a', 'count': '1'}]
		original = [{'index': index, 'sourcetype': 'tenx_encoded', 'tenx_sourcetype': sourcetype, 'count': '1'}]
		return {'| tx, | tenxsearch': (sb.unnamed_compact_message(compact), 'Add the sourcetype to it, for example sourcetype=tenx_encoded'),
				'| tx sourcetype=': (sb.original_sourcetype_message(original), 'Write sourcetype=tenx_encoded tenx_sourcetype=%s instead.' % sourcetype),
				'`tx`': (pp.original_sourcetype_message(original, '`tx`'), "Write sourcetype=%s after `txf` for the add-on's fields;" % sourcetype),
				'`txf`': (pp.original_sourcetype_message(original, '`txf`'), '`txf` gives each event its original sourcetype.')}

	def test_whole_with_names_of_common_length(self):
		for st, index in (('XmlWinEventLog', 'wineventlog'), ('aws:cloudtrail', 'my_compact_index'), ('fortigate_traffic', 'fw')):
			for path, (message, _) in self.messages(st, index).items():
				assert len(message) <= self.LIMIT, (path, st, len(message))

	def test_the_instruction_comes_first_with_long_names(self):
		for path, (message, instruction) in self.messages('a_very_long_original_sourcetype:name', 'an_index_with_a_long_name').items():
			assert instruction in message[:self.LIMIT], path
