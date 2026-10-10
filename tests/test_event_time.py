"""
Event time and timestamp rendering for compact events.

- tenx-event-time (transforms.conf) sets _time from the epoch a compact event carries in
  its first variable, 13 digits for milliseconds or 19 for nanoseconds, and leaves every
  other event at its index time. The patterns tested here are read from the conf file, so
  the test runs the expression Splunk runs.
- tenx-inflate renders every timestamp in UTC for every viewer, a DST transition
  included. strftime renders in the viewer's zone, so everything that depends on the hour
  is computed from the epoch and spliced in as literal text before strftime runs.

The live check behind both is tests/live_event_time/.
"""
import configparser
import os
import re

import pytest

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))


def conf(name):
	parser = configparser.RawConfigParser(strict=False, interpolation=None)
	parser.optionxform = str
	parser.read(os.path.join(APP, 'default', name))
	return parser


def ingest_eval():
	return conf('transforms.conf').get('tenx-event-time', 'INGEST_EVAL')


def spl_strings(expr):
	return re.findall(r'"((?:[^"\\]|\\.)*)"', expr)


def match_pattern():
	return [s for s in spl_strings(ingest_eval()) if s.startswith('^~?') and '{13}' in s][0]


def capture_pattern():
	return [s for s in spl_strings(ingest_eval()) if s.startswith('^~?') and '(\\d+)' in s][0]


def event_seconds(raw):
	"""What the INGEST_EVAL computes for _time, or None where it keeps the index time."""
	if not re.search(match_pattern(), raw):
		return None
	epoch = re.sub(capture_pattern(), r'\1', raw)
	return int(epoch[:10]) + float('0.' + epoch[10:16])


class TestEventTime:
	def test_the_sourcetype_runs_the_transform(self):
		assert conf('props.conf').get('tenx_encoded', 'TRANSFORMS-tenx_time') == 'tenx-event-time'

	def test_index_time_stays_the_fallback(self):
		assert conf('props.conf').get('tenx_encoded', 'DATETIME_CONFIG') == 'CURRENT'

	@pytest.mark.parametrize('raw,seconds', [
		('~-3gTMRPTTYm,1759386934498,cart,7', 1759386934.498),
		('~a b,1759386934498,c', 1759386934.498),
		('~h,1759386934498123456,x', 1759386934.498123),
		('~h,1759386934498', 1759386934.498),
	])
	def test_a_millisecond_or_nanosecond_first_variable_is_the_event_time(self, raw, seconds):
		assert event_seconds(raw) == pytest.approx(seconds, abs=1e-6)

	@pytest.mark.parametrize('raw', [
		'~h',
		'~h,80d793bf70a5dbe9408a516aa34542972497a8fdc0909b59c3c4957000c211a7,6f7cb8cd4d',
		'~h,1759349505,info',
		'~h,17593495051234,x',
		'~h,CORECLR,1',
		'~h,,1759386934498',
	])
	def test_any_other_first_variable_keeps_the_index_time(self, raw):
		assert event_seconds(raw) is None

	def test_the_window_is_splunks_default_for_a_timestamp(self):
		expr = ingest_eval()
		assert 'time() - 2000*86400' in expr and 'time() + 2*86400' in expr

	def test_the_working_fields_are_removed(self):
		expr = ingest_eval()
		for field in set(re.findall(r'\b(tenx_t_\w+)=', expr)):
			assert field + ':=null()' in expr


MACROS = ('tenx-inflate', 'tenx-inflate-debug')
HOUR_DIRECTIVES = ('%H', '%I', '%M', '%S', '%p')
ZONE_DIRECTIVES = {'%:::z': '+00', '%:z': '+00:00', '%z': '+0000', '%Z': 'UTC'}


def macro(name):
	return conf('macros.conf').get(name, 'definition')


class TestUtcRendering:
	@pytest.mark.parametrize('name', MACROS)
	def test_no_offset_is_sampled_at_the_event_instant(self, name):
		assert 'strftime(tenx_ts_sec' not in macro(name)

	@pytest.mark.parametrize('name', MACROS)
	def test_every_hour_directive_is_literal_before_strftime(self, name):
		definition = macro(name)
		render = definition.index('strftime(tenx_ts_utc')
		for directive in HOUR_DIRECTIVES:
			assert definition.index('"%s"' % directive) < render

	@pytest.mark.parametrize('name', MACROS)
	def test_zone_directives_print_utc(self, name):
		definition = macro(name)
		for directive, text in ZONE_DIRECTIVES.items():
			assert '"%s","%s"' % (directive, text) in definition

	@pytest.mark.parametrize('name', MACROS)
	def test_the_date_renders_from_noon(self, name):
		definition = macro(name)
		assert 'tenx_ts_noon=tenx_ts_sec-tenx_ts_sod+43200' in definition
		assert 'tenx_tz=strftime(tenx_ts_noon,"%z")' in definition

	def test_the_debug_macro_is_the_same_chain(self):
		inflate = macro('tenx-inflate')
		assert inflate[:inflate.index('| fields')].strip() == macro('tenx-inflate-debug').strip()

	def test_every_directive_the_converter_emits_is_covered(self):
		from tenx_dml_builder import convert_timestamp_segment
		emitted = {convert_timestamp_segment(c, n) for c in 'yMwDdEaHkKhmsSzZX' for n in (1, 2, 3, 4)}
		emitted.discard(None)
		date = {'%Y', '%y', '%B', '%b', '%m', '%V', '%j', '%d', '%A', '%a'}
		fraction = {d for d in emitted if re.fullmatch(r'%\d+Q', d)}
		assert emitted - date - fraction <= set(HOUR_DIRECTIVES) | set(ZONE_DIRECTIVES)
