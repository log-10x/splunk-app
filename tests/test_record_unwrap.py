"""
The rule a heavy forwarder runs on the compact events it reads back from files (transforms.conf
[tenx-record-unwrap], props.conf [source::/opt/tenx/compact/events/...]).

Fluent Bit's file output with Format plain writes each record the Receiver returns as one JSON object
per line, with the keys the heavy forwarder's ingest actions file destination wrote: time, event, host,
source, sourcetype, index. The rule gives the event back host, source, index and _time from the line,
marks the time tenx_time=sender, writes the original sourcetype as tenx_sourcetype, adds the line's
"meta" text (the Receiver's compactFields in the text form) to the event's indexed fields, and makes the
compact text _raw. What Splunk does with it was measured on Splunk Enterprise 10.4.3 (tests/live_hf_monitor/);
these tests pin the text, and run it through a small model of the eval functions it uses.
"""
import configparser
import json
import os
import re

import pytest

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))
STANZA = 'source::/opt/tenx/compact/events/...'
CLASS = 'TRANSFORMS-00_tenx_unwrap'
RULE = 'tenx-record-unwrap'


def conf(name):
	parser = configparser.RawConfigParser(strict=False, interpolation=None)
	parser.optionxform = str
	parser.read(os.path.join(APP, 'default', name))
	return parser


def ingest_eval():
	return conf('transforms.conf').get(RULE, 'INGEST_EVAL')


def split_top(text, sep=','):
	"""Splits at sep outside parentheses and double-quoted strings."""
	parts, depth, quoted, cur, i = [], 0, False, '', 0
	while i < len(text):
		c = text[i]
		if quoted:
			cur += c
			if c == '\\':
				cur += text[i + 1]
				i += 1
			elif c == '"':
				quoted = False
		elif c == '"':
			quoted, cur = True, cur + c
		elif c == '(':
			depth, cur = depth + 1, cur + c
		elif c == ')':
			depth, cur = depth - 1, cur + c
		elif c == sep and depth == 0:
			parts.append(cur.strip())
			cur = ''
		else:
			cur += c
		i += 1
	parts.append(cur.strip())
	return parts


def assignments():
	"""[(field, ':=' or '=', expression)] in the rule's order."""
	out = []
	for part in split_top(ingest_eval()):
		m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*(:=|=)\s*(.*)$', part, re.S)
		out.append((m.group(1), m.group(2), m.group(3)))
	return out


def evaluate(expr, event):
	"""The value of one expression of the rule on an event (a dict of fields), for the functions it uses."""
	expr = expr.strip()
	parts = split_top(expr, '.') if '" . "' in expr or ') . ' in expr else [expr]
	if len(parts) > 1:
		values = [evaluate(p, event) for p in parts]
		return None if any(v is None for v in values) else ''.join(values)
	if expr.startswith('"'):
		return json.loads(expr)
	m = re.match(r'^([a-z_]+)\((.*)\)$', expr, re.S)
	if not m:
		return event.get(expr)
	name, args = m.group(1), split_top(m.group(2)) if m.group(2).strip() else []
	if name == 'null':
		return None
	if name == 'if':
		cond = evaluate(args[0], event)
		return evaluate(args[1], event) if cond else evaluate(args[2], event)
	value = evaluate(args[0], event)
	if name == 'coalesce':
		return next((v for v in [value] + [evaluate(a, event) for a in args[1:]] if v is not None), None)
	if name == 'isnull':
		return value is None
	if name == 'isnotnull':
		return value is not None
	if name == 'json_extract':
		try:
			obj = json.loads(value)
		except (TypeError, ValueError):
			return None
		return obj.get(evaluate(args[1], event)) if isinstance(obj, dict) else None
	if name == 'tostring':
		return None if value is None else (value if isinstance(value, str) else repr(value))
	if name == 'tonumber':
		return None if value is None else float(value)
	raise AssertionError('function the model does not know: %s' % name)


def run(raw, **fields):
	event = dict(fields, _raw=raw)
	for field, _, expr in assignments():
		value = evaluate(expr, event)
		if value is None:
			event.pop(field, None)
		else:
			event[field] = value
	return event


LINE = {'time': 1794013200.448351, 'event': '~-3gTMRPTTYm,1794013200448,cart,7', 'host': 'dc1',
	'source': 'XmlWinEventLog:Security', 'sourcetype': 'XmlWinEventLog', 'index': 'wineventlog'}
MONITOR = {'host': 'hf1', 'source': '/opt/tenx/compact/events/win/tenx.rfs.win.x.ndjson', 'index': 'main', '_time': 1.0}


class TestWhereTheRuleRuns:
	def test_only_the_compact_folder_runs_it(self):
		props = conf('props.conf')
		assert props.get(STANZA, CLASS) == 'tenx-relay-line, ' + RULE
		users = [(s, k) for s in props.sections() for k, v in props.items(s) if RULE in v]
		assert users == [(STANZA, CLASS)]

	def test_template_records_sit_outside_the_folder_it_reads(self):
		# Fluent Bit writes the template records beside events/, and the heavy forwarder reads them as tenx_dml_raw_json.
		assert STANZA.endswith('/events/...')

	def test_compact_events_outside_the_folder_are_not_touched(self):
		props = conf('props.conf')
		assert props.get('tenx_encoded', 'TRANSFORMS-tenx_time') == 'tenx-event-time'
		assert [k for k, _ in props.items('tenx_encoded') if k.startswith('TRANSFORMS-')] == ['TRANSFORMS-tenx_time']

	def test_the_class_sorts_before_event_time(self):
		# The TRANSFORMS- classes of the source and sourcetype stanzas that match an event run in the order of their
		# names: on Splunk Enterprise 10.4.3 the unwrap (class 00_...) ran before tenx-event-time on every event
		# (tests/live_hf_monitor/).
		assert sorted(['tenx_time', CLASS[len('TRANSFORMS-'):]])[0] == '00_tenx_unwrap'


class TestTheRuleText:
	def test_raw_is_replaced_last(self):
		fields = [f for f, _, _ in assignments()]
		assert fields == ['host', 'source', 'index', 'tenx_sourcetype', 'tenx_time', '_time', 'tenx_unwrap', 'tenx_pattern',
			'message_pattern', 'severity_level', '_meta', '_raw']

	def test_metadata_is_set_and_the_rest_indexed(self):
		ops = dict((f, op) for f, op, _ in assignments())
		assert [f for f in ops if ops[f] == '='] == ['host', 'source', 'index', '_time', '_meta', '_raw']
		assert [f for f in ops if ops[f] == ':='] == ['tenx_sourcetype', 'tenx_time', 'tenx_unwrap', 'tenx_pattern',
			'message_pattern', 'severity_level']

	def test_the_time_keeps_its_fraction(self):
		# tonumber() straight on json_extract() of a JSON number dropped the fraction on Splunk Enterprise 10.4.3.
		text = ingest_eval()
		assert 'tonumber(tostring(json_extract(_raw, "time")))' in text
		assert 'tonumber(json_extract(' not in text

	def test_only_functions_index_time_eval_takes(self):
		names = set(re.findall(r'([a-z_]+)\(', ingest_eval()))
		assert names == {'if', 'isnotnull', 'isnull', 'json_extract', 'tonumber', 'tostring', 'null', 'coalesce'}


class TestTheRuleOnLines:
	def test_a_line_gives_the_event_back(self):
		e = run(json.dumps(LINE), **MONITOR)
		assert (e['host'], e['source'], e['index']) == ('dc1', 'XmlWinEventLog:Security', 'wineventlog')
		assert e['_time'] == pytest.approx(1794013200.448351, abs=1e-6)
		assert (e['tenx_sourcetype'], e['tenx_time'], e['_raw']) == ('XmlWinEventLog', 'sender', LINE['event'])
		assert 'tenx_unwrap' not in e

	def test_a_whole_event_is_given_back_whole(self):
		raw = '<Event xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System>, "quoted"\r\n</System></Event>'
		e = run(json.dumps(dict(LINE, event=raw)), **MONITOR)
		assert e['_raw'] == raw and e['tenx_time'] == 'sender'

	def test_keys_the_line_lacks_keep_the_monitor_values(self):
		e = run(json.dumps({'event': '~h,1'}), **MONITOR)
		assert (e['host'], e['source'], e['index'], e['_time']) == ('hf1', MONITOR['source'], 'main', 1.0)
		assert 'tenx_time' not in e and 'tenx_sourcetype' not in e and e['_raw'] == '~h,1'

	@pytest.mark.parametrize('raw', ['~h,1794013200448,x', '{"time": 1794013200, "host": "dc1"}', '{not json'])
	def test_a_line_without_an_event_keeps_its_text_and_is_marked(self, raw):
		e = run(raw, **MONITOR)
		assert e['_raw'] == raw and e['tenx_unwrap'] == 'failed'

	def test_a_line_without_a_sourcetype_keeps_the_one_the_event_has(self):
		# A Universal Forwarder's _meta = tenx_sourcetype::<st>; := with null() would remove it.
		line = dict(LINE)
		del line['sourcetype']
		e = run(json.dumps(line), tenx_sourcetype='aws:cloudtrail', **MONITOR)
		assert e['tenx_sourcetype'] == 'aws:cloudtrail'
		e = run(json.dumps(LINE), tenx_sourcetype='aws:cloudtrail', **MONITOR)
		assert e['tenx_sourcetype'] == 'XmlWinEventLog'

	def test_a_line_without_meta_leaves_the_indexed_fields_alone(self):
		e = run(json.dumps(LINE), **MONITOR)
		assert '_meta' not in e
		e = run(json.dumps(LINE), _meta='tenx_sourcetype::XmlWinEventLog', **MONITOR)
		assert e['_meta'] == 'tenx_sourcetype::XmlWinEventLog'

	def test_the_meta_text_is_added_to_the_indexed_fields(self):
		meta = 'EventCode::"4625" Account_Name::"a \\"b\\""'
		e = run(json.dumps(dict(LINE, meta=meta)), **MONITOR)
		assert e['_meta'] == ' ' + meta and e['_raw'] == LINE['event']
		e = run(json.dumps(dict(LINE, meta=meta)), _meta='host::x', **MONITOR)
		assert e['_meta'] == 'host::x ' + meta

	def test_the_pattern_keys_become_indexed_fields(self):
		line = dict(LINE, tenx_pattern='Xb3kQ_9aZ1c', message_pattern='cart_checkout_failed', severity_level='ERROR')
		e = run(json.dumps(line), **MONITOR)
		assert (e['tenx_pattern'], e['message_pattern'], e['severity_level']) == ('Xb3kQ_9aZ1c', 'cart_checkout_failed', 'ERROR')
		assert e['_raw'] == LINE['event']

	def test_a_line_without_them_writes_none(self):
		e = run(json.dumps(LINE), **MONITOR)
		assert not {'tenx_pattern', 'message_pattern', 'severity_level'} & set(e)

	def test_a_value_the_event_has_is_kept_when_the_line_has_none(self):
		e = run(json.dumps(LINE), tenx_pattern='Xb3kQ_9aZ1c', **MONITOR)
		assert e['tenx_pattern'] == 'Xb3kQ_9aZ1c'

	def test_a_tenx_hash_key_is_not_indexed(self):
		# The expansion looks up an existing tenx_hash as the template id, so a pattern hash under that name would
		# leave every event compact.
		e = run(json.dumps(dict(LINE, tenx_hash='Xb3kQ_9aZ1c')), **MONITOR)
		assert 'tenx_hash' not in e and 'tenx_hash' not in ingest_eval()
