"""
tenxprefilter sends every request of a run to splunkd over one connection (tenx_prefilter.Splunkd), opened
again when splunkd closes it. Checked here against a local HTTP server: requests and answers as before, one
connection while the server keeps it, a new one when it does not, and an error status raised with its code
and body.
"""
import json
import os
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(ROOT, 'tenx-for-splunk', 'bin'))
import tenx_prefilter


class Handler(BaseHTTPRequestHandler):
	protocol_version = 'HTTP/1.1'
	seen = []
	mode = 'keep'

	def log_message(self, *args):
		pass

	def answer(self, code, obj):
		body = json.dumps(obj).encode()
		self.send_response(code)
		self.send_header('Content-Type', 'application/json')
		self.send_header('Content-Length', str(len(body)))
		if Handler.mode == 'close':
			self.send_header('Connection', 'close')
		self.end_headers()
		self.wfile.write(body)
		if Handler.mode == 'drop':
			self.close_connection = True

	def handle_one(self, method):
		length = int(self.headers.get('Content-Length') or 0)
		body = self.rfile.read(length) if length else b''
		Handler.seen.append((method, self.path, self.client_address[1], self.headers.get('Content-Type'),
							 self.headers.get('Authorization'), body))
		if self.path.startswith('/missing'):
			return self.answer(404, {'messages': [{'type': 'ERROR', 'text': 'not found'}]})
		if self.path.startswith('/starting'):
			return self.answer(503, {'messages': [{'type': 'ERROR', 'text': 'KV Store is initializing'}]})
		return self.answer(200, {'path': self.path, 'method': method})

	def do_GET(self):
		self.handle_one('GET')

	def do_POST(self):
		self.handle_one('POST')

	def do_DELETE(self):
		self.handle_one('DELETE')


@pytest.fixture
def server():
	Handler.seen, Handler.mode = [], 'keep'
	srv = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
	threading.Thread(target=srv.serve_forever, daemon=True).start()
	yield srv
	srv.shutdown()
	srv.server_close()


def command(srv):
	cmd = tenx_prefilter.TenxPrefilterCommand()
	cmd._metadata = types.SimpleNamespace(searchinfo=types.SimpleNamespace(
		splunkd_uri='http://127.0.0.1:%d' % srv.server_address[1], session_key='k', username='u'))
	return cmd


class TestOneConnection:

	def test_requests_and_answers(self, server):
		cmd = command(server)
		assert cmd._rest('/services/search/jobs/x?output_mode=json') == {'path': '/services/search/jobs/x?output_mode=json', 'method': 'GET'}
		assert cmd._rest('/services/search/jobs', {'search': '| tstats count', 'exec_mode': 'oneshot'})['method'] == 'POST'
		assert cmd._rest('/services/search/jobs/x', answer=False, method='DELETE') is None
		assert json.loads(cmd._rest('/a', answer='text')) == {'path': '/a', 'method': 'GET'}
		assert cmd._kv('/storage/x?output_mode=json')['method'] == 'GET'
		assert cmd._kv('/storage/x/batch_save?output_mode=json', [{'_key': 'a'}])['method'] == 'POST'
		get, post, delete, text, kv_get, kv_post = Handler.seen
		assert get[4] == 'Splunk k' and kv_post[4] == 'Splunk k'
		assert post[3] == 'application/x-www-form-urlencoded' and post[5] == b'search=%7C+tstats+count&exec_mode=oneshot'
		assert kv_post[3] == 'application/json' and json.loads(kv_post[5]) == [{'_key': 'a'}]
		assert delete[0] == 'DELETE'

	def test_one_connection_while_the_server_keeps_it(self, server):
		cmd = command(server)
		for i in range(5):
			cmd._rest('/r%d' % i)
			cmd._kv('/k%d' % i)
		assert len(set(s[2] for s in Handler.seen)) == 1 and len(Handler.seen) == 10

	def test_a_new_connection_when_the_server_closes_it(self, server):
		cmd = command(server)
		for mode in ('close', 'drop'):
			Handler.seen, Handler.mode = [], mode
			for i in range(4):
				assert cmd._rest('/r%d' % i)['path'] == '/r%d' % i
			# 'drop' closes the connection without saying so: the request sent on it is sent again on a new one
			assert len(set(s[2] for s in Handler.seen)) == 4 and [s[1] for s in Handler.seen] == ['/r0', '/r1', '/r2', '/r3'], mode

	def test_an_error_status_carries_its_code_and_body(self, server):
		cmd = command(server)
		with pytest.raises(tenx_prefilter.HTTPError) as e:
			cmd._rest('/missing')
		assert e.value.code == 404 and json.loads(e.value.read())['messages'][0]['text'] == 'not found'
		with pytest.raises(tenx_prefilter.HTTPError) as e:
			cmd._kv('/starting')
		assert e.value.code == 503 and b'initializing' in e.value.read()
		assert cmd._rest('/after')['path'] == '/after'

	def test_the_store_check_reads_the_error_as_before(self, server, monkeypatch):
		cmd = command(server)
		monkeypatch.setattr(tenx_prefilter.parser, 'STORE_STATE_PATH', '/starting')
		monkeypatch.setattr(tenx_prefilter.parser, 'KV_STARTING', 'initializing')
		assert cmd._store_check() is True and cmd.store_state is None
		assert [m[0] for m in cmd._messages] == ['WARN']
		monkeypatch.setattr(tenx_prefilter.parser, 'STORE_STATE_PATH', '/missing')
		cmd = command(server)
		assert cmd._store_check() is True and cmd.store_state is None
