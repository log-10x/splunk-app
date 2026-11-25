"""
Events the Receiver sends as their own text beside compact events (its templateCreateAfter option, or an event of
65,535 characters or more), in the same stream and sourcetype. The engine writes a compact event as "~<hash>,..."
and never writes an event as text when its text starts with "~" (such an event is templated on its first sight),
so the first character decides: every rule that reads a compact event requires the leading "~".

- the search-time extraction gives a text line no tenx_hash, so no part of its text is looked up as a hash;
- tenx-inflate reads values only from a line that starts with "~", and leaves a text line unmarked;
- tenx-event-time leaves a text line at the time it arrived with (test_event_time.py);
- the dashboard counts text events as one row of their own and no template.
"""
import configparser
import os
import re

import pytest

from support.spl_model import Model, visible

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))
INFLATE = ('tenx-inflate', 'tenx-inflate-debug')


def conf(name):
	parser = configparser.RawConfigParser(strict=False, interpolation=None)
	parser.optionxform = str
	parser.read(os.path.join(APP, 'default', name))
	return parser


def extraction():
	return re.compile(conf('transforms.conf').get('tenx-hash-vars-extraction', 'REGEX').replace('(?<', '(?P<'))


def first_steps(name):
	"""The two value steps of an inflate macro: [(match regex, replace regex)] for tenx_vars and tenx_var_0."""
	steps = conf('macros.conf').get(name, 'definition').split(' | ')[:2]
	return [tuple(re.findall(r'"((?:[^"\\]|\\.)*)"', s)[:2]) for s in steps]


class TestTheExtraction:
	@pytest.mark.parametrize('raw,want', [
		('~h1,1759386934498,a,b', {'tenx_hash': 'h1', 'tenx_var_0': '1759386934498', 'tenx_vars': 'a,b'}),
		('~-J}UrlyaKD8', {'tenx_hash': '-J}UrlyaKD8', 'tenx_var_0': None, 'tenx_vars': None}),
	])
	def test_a_compact_line(self, raw, want):
		assert extraction().match(raw).groupdict() == want

	@pytest.mark.parametrize('raw', [
		'h1,1759386934498,a,b',
		'2025-11-10T10:00:00.000Z web01 auth: user alice logged in',
		'date=2026-11-10 time=10:00:00 devname="fw1" type="traffic"',
		'<Event xmlns="x"><System>',
		'{"eventVersion":"1.08","eventTime":"2026-11-10T10:00:00Z"}',
	])
	def test_a_line_sent_as_text_gets_no_hash(self, raw):
		assert extraction().match(raw) is None


class TestTheInflateMacros:
	@pytest.mark.parametrize('name', INFLATE)
	def test_values_are_read_only_from_a_compact_line(self, name):
		for match, replace in first_steps(name):
			assert match.startswith('^~[') and replace.startswith('^~[')
			assert re.match(match, '~h,1759386934498,a,b')
			assert not re.match(match, 'h,1759386934498,a,b')

	@pytest.mark.parametrize('name', INFLATE)
	def test_no_optional_tilde_is_left(self, name):
		assert '^~?' not in conf('macros.conf').get(name, 'definition')

	def test_a_text_line_whose_first_value_names_a_template_is_not_marked(self):
		# without tenx_hash the lookup gives no row: the guard leaves the text and sets no tenx_expand_refused
		definition = conf('macros.conf').get('tenx-inflate', 'definition')
		guard = [s for s in definition.split(' | ') if s.startswith('eval tenx_expand_refused=case(')][0]
		out = visible(Model().run(guard, [{'_raw': 'h1,1759386934498,a,b'}])[0])
		assert out == {'_raw': 'h1,1759386934498,a,b'}
		out = visible(Model().run(guard, [{'_raw': '~h1,1759386934498,a,b'}])[0])
		assert out['tenx_expand_refused'] == 'no-template'
