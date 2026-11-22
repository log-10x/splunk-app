"""
The CR of a CR LF line end at the very end of an expanded event.

An engine that keeps the CR of a CR LF line end in the template gives the expansion of such an event a final
CR, in the template's last part or at the end of its last value. Splunk's raw event of the same line has none,
so a field rule ending in `$` fails and `.*` captures the CR. Both inflate macros drop exactly one CR at the
very end of the expanded text, and no CR inside it.

The step is run here with Python's re, as test_inflate_values_from_raw runs the macros' other regular
expressions; the text it reads is what expand() there builds from the records tenx_dml_builder makes.
"""
import re

import pytest

from test_inflate_values_from_raw import CASES, CR, MACROS, expand, macro, values_from_raw

STEP = re.compile(r'eval tenx_text=replace\(tenx_text, "((?:[^"\\]|\\.)*)", ""\)')


def step(name):
	"""The step of the macro that drops the CR, and its regular expression as Splunk reads it."""
	steps = [s for s in macro(name).split(' | ') if STEP.fullmatch(s)]
	assert len(steps) == 1, name
	return steps[0], STEP.fullmatch(steps[0]).group(1)


def dropped(text, name='tenx-inflate'):
	return re.sub(step(name)[1], '', text, count=1)


class TestTheStep:
	@pytest.mark.parametrize('name', MACROS)
	def test_it_runs_after_the_text_is_built_and_before_raw_is_set(self, name):
		parts = macro(name).split(' | ')
		at = parts.index(step(name)[0])
		assert parts[at - 1].startswith('eval tenx_text=if(')
		assert parts[at + 1].startswith('eval tenx_expand_refused=case(') and '_raw=if(len(tenx_text)>0' in parts[at + 1]

	def test_both_macros_hold_the_same_step(self):
		assert step('tenx-inflate') == step('tenx-inflate-debug')

	def test_exactly_one_cr_at_the_very_end(self):
		assert dropped('a b' + CR) == 'a b'
		assert dropped('a' + CR + CR) == 'a' + CR
		assert dropped('a' + CR + '\nb') == 'a' + CR + '\nb'
		assert dropped('a' + CR + '\n') == 'a' + CR + '\n'
		assert dropped(CR + 'a') == CR + 'a'
		assert dropped('a') == 'a'


class TestAnEventKeepsItsInnerCrs:
	@pytest.mark.parametrize('case', sorted(CASES))
	def test_a_final_cr_in_the_template(self, case):
		# the template keeps the CR of the event's last line end; the CRs of the lines before it stay
		template, raw, event = CASES[case]
		text = expand(raw, template + CR, values_from_raw(raw))
		assert text == event + CR
		assert dropped(text) == event and dropped(text).count(CR) == event.count(CR) > 0

	def test_a_final_cr_at_the_end_of_the_last_value(self):
		template = '$(MM/dd/yyyy hh:mm:ss a)\nEventCode=$\nProcess ID:\t\t$'
		raw = '~Hb7,1794744431000,9003' + CR + ',0x4c4' + CR
		text = expand(raw, template, values_from_raw(raw))
		assert text.endswith('0x4c4' + CR)
		assert dropped(text) == text[:-1] and CR in dropped(text)
