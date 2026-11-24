"""
tenxprefilter speaks the chunked protocol through bin/tenx_chunked.py, without the Python SDK. Its replies
must be the SDK's: the expected bytes below are what the SDK's GeneratingCommand wrote for a command that
yields {"search": "*"}, with a warning and with error_exit, captured from Splunk Enterprise 10.4.3.
"""
import io
import json
import os
import subprocess
import sys

import pytest

import tenx_chunked

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PREFILTER = os.path.join(ROOT, 'tenx-for-splunk', 'bin', 'tenx_prefilter.py')
INFO = {'args': [], 'sid': 'subsearch_1.2_3.4', 'app': 'search', 'earliest_time': '0', 'latest_time': '1795219200',
		'search': '%7C%20tenxprefilter', 'splunkd_uri': 'https://127.0.0.1:1', 'session_key': 'k', 'username': 'admin',
		'command': 'tenxprefilter'}
GETINFO_REPLY = b'chunked 1.0,37,0\n{"generating":true,"type":"stateful"}'


def chunk(metadata, body=b''):
	meta = json.dumps(metadata).encode()
	return b'chunked 1.0,%d,%d\n' % (len(meta), len(body)) + meta + body


GETINFO = chunk({'action': 'getinfo', 'preview': False, 'searchinfo': INFO})
EXECUTE = chunk({'action': 'execute', 'finished': True})


class Command(tenx_chunked.GeneratingCommand):
	mode = 'ok'

	def generate(self):
		if self.mode == 'warn':
			self.write_warning('tx: a warning text')
		if self.mode == 'err':
			self.error_exit(RuntimeError('x'), 'tx: an error text')
		yield {'search': '*'}


def run(mode):
	out = io.BytesIO()
	Command.mode = mode
	code = 0
	try:
		tenx_chunked.run(Command, INFO, out)
	except SystemExit as e:
		code = e.code
	return out.getvalue(), code


class TestTheReplies:
	def test_getinfo(self):
		out = io.BytesIO()
		assert tenx_chunked.answer_getinfo(io.BytesIO(GETINFO + EXECUTE), out) == INFO
		assert out.getvalue() == GETINFO_REPLY

	def test_a_start_that_only_asks_for_the_settings_runs_nothing(self):
		out = io.BytesIO()
		assert tenx_chunked.answer_getinfo(io.BytesIO(GETINFO), out) is None
		assert out.getvalue() == GETINFO_REPLY

	def test_rows(self):
		assert run('ok') == (b'chunked 1.0,17,24\n{"finished":true}search,__mv_search\r\n*,\r\n', 0)

	def test_a_warning(self):
		assert run('warn') == (b'chunked 1.0,74,24\n{"inspector":{"messages":[["WARN","tx: a warning text"]]},'
							   b'"finished":true}search,__mv_search\r\n*,\r\n', 0)

	def test_an_error_stops_the_search(self):
		assert run('err') == (b'chunked 1.0,74,0\n{"inspector":{"messages":[["ERROR","tx: an error text"]]},'
							  b'"finished":true}', 1)

	@pytest.mark.parametrize('value', ['(TERM(a) OR "~h,x")', 'a "b" c', 'line\nbreak'])
	def test_a_value_is_quoted_as_csv(self, value):
		class One(tenx_chunked.GeneratingCommand):
			def generate(self):
				yield {'search': value}
		out = io.BytesIO()
		tenx_chunked.run(One, INFO, out)
		body = out.getvalue().split(b'"finished":true}', 1)[1].decode()
		import csv
		assert list(csv.reader(io.StringIO(body))) == [['search', '__mv_search'], [value, '']]

	def test_the_search_information_is_the_sdks(self):
		info = tenx_chunked.searchinfo(INFO)
		assert (info.earliest_time, info.latest_time, info.search, info.sid) == (0.0, 1795219200.0, '| tenxprefilter',
																				 'subsearch_1.2_3.4')


class TestThePrefilterScript:
	def start(self, data):
		return subprocess.run([sys.executable, PREFILTER], input=data, capture_output=True, timeout=60)

	def test_a_settings_start_ends_after_getinfo(self):
		proc = self.start(GETINFO)
		assert (proc.returncode, proc.stdout) == (0, GETINFO_REPLY)

	def test_a_run_without_its_search_selects_every_event(self):
		proc = self.start(GETINFO + EXECUTE)
		assert proc.returncode == 0
		assert proc.stdout.startswith(GETINFO_REPLY + b'chunked 1.0,')
		assert proc.stdout.endswith(b'"finished":true}search,__mv_search\r\n(*),\r\n')
