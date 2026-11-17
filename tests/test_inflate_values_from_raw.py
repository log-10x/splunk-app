"""
The values tenx-inflate expands a compact event with.

A search-time extraction trims white space at both ends of each value it writes (Splunk Enterprise
10.4.3: "~h,<epoch>,a,b<CR>" gave tenx_vars "a,b", and "~h,<epoch>,  a,b" gave "a,b"), and makemv
drops empty values. The engine leaves the CR of a CR LF line end at the end of the value before the
template's line feed, so the last value of a Windows event whose text ends with fixed lines ends in
CR, or is a lone CR. Both inflate macros therefore read the values from _raw. These tests run that
expression with Python's re, and model the rest of the chain as observed on Splunk Enterprise 10.4.3
(makemv drops empty values, mvzip stops at the shorter list) on records tenx_dml_builder makes from
the templates, as Consume KV stores them.

The templates and compact lines below have the shapes the engine writes for such events (an empty
line, a line of fixed words, or a value line right before the last line); their text is made up.
"""
import configparser
import os
import re

import pytest

from tenx_dml_builder import TenxDMLBuilder

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))
MACROS = ('tenx-inflate', 'tenx-inflate-debug')
STAMP = '11/15/2026 12:07:11 PM'
CR = '\r'


def conf(name):
	parser = configparser.RawConfigParser(strict=False, interpolation=None)
	parser.optionxform = str
	parser.read(os.path.join(APP, 'default', name))
	return parser


def macro(name):
	return conf('macros.conf').get(name, 'definition')


def values_step(name):
	"""The first step of the macro: eval tenx_vars=if(match(_raw, A), replace(_raw, B, ""), tenx_vars)."""
	step = macro(name).split(' | ', 1)[0]
	strings = re.findall(r'"((?:[^"\\]|\\.)*)"', step)
	return step, strings[0], strings[1]


def extraction():
	regex = conf('transforms.conf').get('tenx-hash-vars-extraction', 'REGEX')
	return re.compile(regex.replace('(?<', '(?P<'))


def extracted(raw):
	"""The search-time extraction as Splunk writes it: each value trimmed at both ends, an empty one absent."""
	m = extraction().match(raw)
	out = {}
	for name in ('tenx_hash', 'tenx_var_0', 'tenx_vars'):
		value = m.group(name)
		if value is not None and value.strip():
			out[name] = value.strip()
	return out


def values_from_raw(raw, name='tenx-inflate'):
	_, match, prefix = values_step(name)
	if re.match(match, raw):
		return re.sub(prefix, '', raw, count=1)
	return extracted(raw).get('tenx_vars')


def makemv(value):
	return [v for v in value.split(',') if v != ''] if value else []


def expand(raw, template, values):
	"""tenx-inflate's text for a template with a timestamp: mvjoin(mvzip(parts, values) + terminator), the
	timestamp placeholder written as STAMP."""
	record = TenxDMLBuilder(timestamp_placeholder='__TENX_TS__', variable_separator='$').build_kv_record_data(
		extracted(raw)['tenx_hash'], template)
	assert record['timestamp_format']
	zipped = [p + v for p, v in zip(record['pattern_parts'], makemv(values))]
	return ''.join(zipped + [record['pattern_terminator']]).replace('__TENX_TS__', STAMP)


# (template, compact line with CR LF line ends, the event it came from)
CASES = {
	'empty line before the last line': (
		'$(MM/dd/yyyy hh:mm:ss a)\nEventCode=$\nMessage=A sample session was closed.$\n$\nLogon ID:\t\t$\n$\n'
		'Logon Type:\t\t\t$\n$\nEnd of sample record.',
		'~Hb1,1794744431000,9001,\r,\r,0x3f8\r,\r,2\r,\r',
		STAMP + '\nEventCode=9001\nMessage=A sample session was closed.\r\n\r\nLogon ID:\t\t0x3f8\r\n\r\n'
		'Logon Type:\t\t\t2\r\n\r\nEnd of sample record.'),
	'line of fixed words before the last line': (
		'$(MM/dd/yyyy hh:mm:ss a)\nEventCode=$\nMessage=A sample share was read.$\n$\nAccess Mask:\t\t$\n\t\t\t\t$\n'
		'Access Check Results:$\n\t-',
		'~Hb2,1794744431000,9002,\r,\r,0x45e\r,\r,\r',
		STAMP + '\nEventCode=9002\nMessage=A sample share was read.\r\n\r\nAccess Mask:\t\t0x45e\r\n\t\t\t\t\r\n'
		'Access Check Results:\r\n\t-'),
	'value line before the last line': (
		'$(MM/dd/yyyy hh:mm:ss a)\nEventCode=$\nMessage=A sample state was changed.$\n$\nProcess ID:\t\t$\n'
		'Process Name:\t\t-',
		'~Hb3,1794744431000,9003,\r,\r,0x4c4\r',
		STAMP + '\nEventCode=9003\nMessage=A sample state was changed.\r\n\r\nProcess ID:\t\t0x4c4\r\nProcess Name:\t\t-'),
}

# The same events with LF line ends: no value ends in white space, so both readings expand them.
LF_CASES = {
	'empty line before the last line': (
		'$(MM/dd/yyyy hh:mm:ss a)\nEventCode=$\nMessage=A sample session was closed.\n\nLogon ID:\t\t$\n\n'
		'Logon Type:\t\t\t$\n\nEnd of sample record.',
		'~Hb4,1794744431000,9001,0x3f8,2',
		STAMP + '\nEventCode=9001\nMessage=A sample session was closed.\n\nLogon ID:\t\t0x3f8\n\n'
		'Logon Type:\t\t\t2\n\nEnd of sample record.'),
	'line of fixed words before the last line': (
		'$(MM/dd/yyyy hh:mm:ss a)\nEventCode=$\nMessage=A sample share was read.\n\nAccess Mask:\t\t$\n\t\t\t\t\n'
		'Access Check Results:\n\t-',
		'~Hb5,1794744431000,9002,0x45e',
		STAMP + '\nEventCode=9002\nMessage=A sample share was read.\n\nAccess Mask:\t\t0x45e\n\t\t\t\t\n'
		'Access Check Results:\n\t-'),
	'value line before the last line': (
		'$(MM/dd/yyyy hh:mm:ss a)\nEventCode=$\nMessage=A sample state was changed.\n\nProcess ID:\t\t$\n'
		'Process Name:\t\t-',
		'~Hb6,1794744431000,9003,0x4c4',
		STAMP + '\nEventCode=9003\nMessage=A sample state was changed.\n\nProcess ID:\t\t0x4c4\nProcess Name:\t\t-'),
}


class TestValuesFromRaw:
	@pytest.mark.parametrize('name', MACROS)
	def test_the_macro_reads_the_values_before_makemv(self, name):
		step, _, _ = values_step(name)
		assert step.startswith('eval tenx_vars=if(match(_raw, ')
		assert step.endswith(', tenx_vars)')
		assert macro(name).index(step) < macro(name).index('makemv delim="," tenx_vars')

	@pytest.mark.parametrize('raw, values', [
		('~h,1794744431000,a,b\r', 'a,b\r'),
		('~h,1794744431000,a,\r', 'a,\r'),
		('~h,1794744431000,\r', '\r'),
		('~h,1794744431000,  a,b ', '  a,b '),
		('~h,1794744431000,a\r,\r,b\t', 'a\r,\r,b\t'),
		('~h a,1794744431000,x', 'x'),
	])
	def test_every_value_keeps_its_characters(self, raw, values):
		assert values_from_raw(raw) == values

	@pytest.mark.parametrize('raw', ['~h,1794744431000', '~h', '~h,1794744431000,'])
	def test_an_event_with_no_value_after_the_epoch_keeps_the_extraction(self, raw):
		assert values_from_raw(raw) == extracted(raw).get('tenx_vars')

	def test_the_split_is_the_extractions(self):
		for template, raw, _ in CASES.values():
			m = extraction().match(raw)
			assert values_from_raw(raw).strip() == m.group('tenx_vars').strip()


class TestExpansion:
	@pytest.mark.parametrize('case', sorted(CASES))
	def test_a_crlf_event_expands_to_its_text(self, case):
		template, raw, event = CASES[case]
		assert expand(raw, template, values_from_raw(raw)) == event

	@pytest.mark.parametrize('case', sorted(CASES))
	def test_the_trimmed_extraction_loses_text(self, case):
		# What the macros did with tenx_vars from the extraction: the last value lost its CR, or was dropped
		# with the template text before it.
		template, raw, event = CASES[case]
		assert expand(raw, template, extracted(raw).get('tenx_vars')) != event

	@pytest.mark.parametrize('case', sorted(LF_CASES))
	def test_an_lf_event_expands_the_same_either_way(self, case):
		template, raw, event = LF_CASES[case]
		assert expand(raw, template, extracted(raw).get('tenx_vars')) == event
		assert expand(raw, template, values_from_raw(raw)) == event
