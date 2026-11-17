"""
The README's limit sentence for the `tx` and `tenxsearch` commands, the values the live check
(tests/live_tx_command_cr.py) asserts, and the probe it installs must agree. The live check pins
what Splunk does; this pins that the sentence still says the same, and that the probe stays out of
the app package.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROBE = os.path.join(HERE, 'support', 'tx_cr_probe')
sys.path.insert(0, os.path.join(PROBE, 'bin'))

import tenx_cr_cases  # noqa: E402


def readme():
	with open(os.path.join(ROOT, 'tenx-for-splunk', 'README.md')) as f:
		return f.read()


def test_the_readme_states_the_limit_under_the_commands_paragraph():
	text = readme()
	assert tenx_cr_cases.README_SENTENCE in ' '.join(text.split())
	paragraph = text[text.index('**The `tx` and `tenxsearch` commands.**'):]
	paragraph = paragraph[:paragraph.index('\n\n')]
	assert tenx_cr_cases.README_SENTENCE in ' '.join(paragraph.split())


def test_every_measured_value_follows_the_sentence():
	for case, written, read_back in tenx_cr_cases.CASES:
		assert tenx_cr_cases.as_read_back(written) == read_back, case


def test_the_cases_cover_each_clause_of_the_sentence():
	by_case = {case: (written, read_back) for case, written, read_back in tenx_cr_cases.CASES}
	written, read_back = by_case['crlf']
	assert '\r\n' in written and '\r' not in read_back and read_back.count('\n') == written.count('\n')
	written, read_back = by_case['endcr']
	assert written.endswith('\r') and read_back == written
	written, read_back = by_case['lonecr']
	assert read_back == written and '\r' in read_back
	written, read_back = by_case['crcr']
	assert written.count('\r') == 2 and read_back.count('\r') == 1


def test_the_probe_writes_exactly_the_cases_and_is_not_packaged():
	with open(os.path.join(PROBE, 'bin', 'tenxcrprobe.py')) as f:
		source = f.read()
	assert 'from tenx_cr_cases import CASES' in source and 'for case, value, _ in CASES' in source
	assert not os.path.abspath(PROBE).startswith(os.path.join(ROOT, 'tenx-for-splunk') + os.sep)
	with open(os.path.join(PROBE, 'default', 'commands.conf')) as f:
		assert 'chunked = true' in f.read()
