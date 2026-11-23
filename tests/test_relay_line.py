"""
The line a Universal Forwarder reads from a Receiver's relay file (transforms.conf [tenx-relay-line], then
[tenx-record-unwrap]).

Fluent Bit's file output with Format out_file writes "<tag>: [<seconds>.<nanoseconds>, <record>]", the
record being the JSON object the Receiver returned: the compact text under "event", the Receiver's
compactFields in the text form under "meta", and any other key the record arrived with. These tests run the
two rules through a small model of the eval functions they use, and send hostile values through the whole
chain: the Receiver's text form, Fluent Bit's JSON, both rules, and Splunk's reading of name::"value" text.
"""
import re
import urllib.parse

import pytest

from test_record_unwrap import MONITOR, conf, run as unwrap, split_top

RELAY = 'tenx-relay-line'
TAG = 'tenx.app.logs'
SECONDS, NANOS = '1794013200', '448351999'
SOURCE = '/opt/tenx/compact/events/app/app.log'


def relay_eval():
	return conf('transforms.conf').get(RELAY, 'INGEST_EVAL')


def spl_string(literal):
	"""An eval string literal's text: the rule's strings hold no quote, and their backslashes stay, as \\d
	and \\1 do."""
	assert literal[0] == literal[-1] == '"' and '"' not in literal[1:-1]
	return literal[1:-1]


def spl_replace(text, regex, replacement):
	"""replace() as measured on Splunk Enterprise 10.4.3: \\<digits> is read greedily and names a group that
	exists, else it stays as text; every other backslash is text."""
	def fill(m):
		out, i, r = [], 0, replacement
		while i < len(r):
			d = re.match(r'\\(\d+)', r[i:])
			if d and int(d.group(1)) <= (m.re.groups):
				out.append(m.group(int(d.group(1))) or '')
				i += len(d.group(0))
			else:
				out.append(r[i])
				i += 1
		return ''.join(out)
	return re.sub(regex, fill, text)


def evaluate(expr, event):
	expr = expr.strip()
	parts = split_top(expr, '.')
	if len(parts) > 1:
		return ''.join(evaluate(p, event) for p in parts)
	if expr.startswith('"'):
		return spl_string(expr)
	m = re.match(r'^([a-z_]+)\((.*)\)$', expr, re.S)
	if not m:
		return event.get(expr)
	name, args = m.group(1), split_top(m.group(2))
	if name == 'if':
		return evaluate(args[1], event) if evaluate(args[0], event) else evaluate(args[2], event)
	values = [evaluate(a, event) for a in args]
	if name == 'match':
		return re.search(values[1], values[0]) is not None
	if name == 'replace':
		return spl_replace(values[0], values[1], values[2])
	if name == 'urldecode':
		return urllib.parse.unquote(values[0])
	raise AssertionError('function the model does not know: %s' % name)


def relay(raw, **fields):
	event = dict(fields, _raw=raw)
	for part in split_top(relay_eval()):
		field, expr = part.split('=', 1)
		event[field.strip()] = evaluate(expr, event)
	return event


def both(raw, **fields):
	"""The two rules in the order props.conf lists them."""
	e = relay(raw, **fields)
	raw = e.pop('_raw')
	return unwrap(raw, **e)


def text_form(pairs):
	"""The Receiver's compactFieldsForm text with compactFieldsSeparator :: (CompactFieldsWriter.pair)."""
	return ' '.join('%s::"%s"' % (n, v.replace('\\', '\\\\').replace('"', '\\"')) for n, v in pairs)


def fluent_bit_json(value):
	"""A record as Fluent Bit 5.1.5 writes it with json.escape_unicode on (flb_pack.c, flb_utils.c): no
	spaces; quote, backslash and control characters escaped; every other non-ASCII character as \\uXXXX,
	in a surrogate pair past U+FFFF."""
	if isinstance(value, dict):
		return '{' + ','.join(fluent_bit_json(k) + ':' + fluent_bit_json(v) for k, v in value.items()) + '}'
	if isinstance(value, (int, float)):
		return repr(value)
	short = {'"': '\\"', '\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f'}
	out = []
	for c in value:
		o = ord(c)
		if c in short:
			out.append(short[c])
		elif o < 0x20 or o == 0x7f or 0x80 <= o <= 0xffff:
			out.append('\\u%04x' % o)
		elif o > 0xffff:
			o -= 0x10000
			out.append('\\u%04x\\u%04x' % (0xd800 + (o >> 10), 0xdc00 + (o & 0x3ff)))
		else:
			out.append(c)
	return '"' + ''.join(out) + '"'


def out_file_line(record, seconds=SECONDS, nanos=NANOS, tag=TAG):
	"""Fluent Bit's out_file format: "%s: [%llu.%09lu, %s]" (out_file.c write_log_record)."""
	return '%s: [%s.%s, %s]' % (tag, seconds, nanos, fluent_bit_json(record))


_PAIR = re.compile(r'(\S+?)::"((?:[^"\\]|\\.)*)"')


def read_meta(text):
	"""(name, value) pairs as Splunk reads index-time field text: a quoted value, \\" and \\\\ read back
	(measured on Splunk Enterprise 10.4.3 with a"b c\\d, and with :: inside a value)."""
	return [(m.group(1), re.sub(r'\\(["\\])', r'\1', m.group(2))) for m in _PAIR.finditer(text or '')]


HOSTILE = [
	'a"b', 'c\\d', 'ends with \\', '\\', '"', '""', '\\"', '\\\\"', 'x::y', '::', 'ipv6 ::', 'k=v',
	'a=b=c', '=', ' leading', 'trailing ', '  both  ', 'a b  c', 'a,b,c', '~h,1,2', '{"json":[1,2]}',
	'}]', ': [1794013200.448351000, {', 'x" y::"z', 'name::"inner"', '$1 \\1 \\12 %5C', 'é', '中文',
	'😀 emoji', 'mixed é"\\😀', 'a' * 1000,
]
COMPACT = '~h,1794013200448,a"b,c\\d,}],: [1.123456789, {x}]'


def record(pairs, event=COMPACT, **keys):
	out = {'event': event}
	out.update(keys)
	if pairs:
		out['meta'] = text_form(pairs)
	return out


class TestTheRuleText:
	def test_the_folder_runs_it_before_the_unwrap(self):
		props = conf('props.conf')
		assert props.get('source::/opt/tenx/compact/events/...', 'TRANSFORMS-00_tenx_unwrap') == \
			RELAY + ', tenx-record-unwrap'

	def test_one_assignment_of_raw_with_the_same_regex_twice(self):
		parts = split_top(relay_eval())
		assert len(parts) == 1 and parts[0].startswith('_raw=')
		regexes = re.findall(r'"(\^[^"]*\$)"', relay_eval())
		assert len(regexes) == 2 and regexes[0] == regexes[1]

	def test_only_functions_index_time_eval_takes(self):
		assert set(re.findall(r'([a-z_]+)\(', relay_eval())) == {'if', 'match', 'replace', 'urldecode'}

	def test_the_strings_hold_regex_escapes_and_references_only(self):
		# The quote of the time key comes from urldecode("%22"), as in rules measured at index time.
		assert set(re.findall(r'\\(.)', relay_eval())) <= set('dsS.[]{}123')


class TestTheLine:
	def test_the_line_becomes_the_record_with_its_time(self):
		e = relay(out_file_line(record([('user', 'bob')])))
		assert e['_raw'].startswith('{"time":1794013200.448351,"event":')

	def test_the_time_is_cut_to_microseconds(self):
		for nanos, time in (('448351999', 1794013200.448351), ('448000000', 1794013200.448), ('000000999', 1794013200.0)):
			e = both(out_file_line(record([]), nanos=nanos), **MONITOR)
			assert e['_time'] == pytest.approx(time, abs=1e-7) and e['tenx_time'] == 'sender'

	@pytest.mark.parametrize('raw', [
		'{"time":1794013200.448351,"event":"~h,1","sourcetype":"XmlWinEventLog"}',
		'{"event":"x: [1794013200.448351000, {\\"a\\":1}]"}',
		'~h,1794013200448,x',
		'{not json',
		'tenx.app.logs: [1794013200.448351000, {}]',
		'tenx.app.logs: [1794013200.448351, {"event":"~h"}]',
		'tenx.app.logs: [1794013200.448351000, {"event":"~h"}',
	])
	def test_every_other_line_is_left_as_it_is(self, raw):
		assert relay(raw)['_raw'] == raw

	def test_a_tag_with_colons_and_brackets(self):
		e = both(out_file_line(record([]), tag='tenx.C:.logs.app[1]:[x'), **MONITOR)
		assert e['_raw'] == COMPACT and e['tenx_time'] == 'sender'

	def test_a_tag_with_white_space_is_not_read(self):
		line = out_file_line(record([]), tag='tenx.my app')
		assert relay(line)['_raw'] == line

	def test_a_cut_line_is_kept_and_marked(self):
		line = out_file_line(record([('user', 'bob')]))[:-20]
		e = both(line, **MONITOR)
		assert e['_raw'] == line and e['tenx_unwrap'] == 'failed'


class TestRoundTrip:
	def test_hostile_values_come_back_exactly(self):
		pairs = [('f%d' % i, v) for i, v in enumerate(HOSTILE)]
		e = both(out_file_line(record(pairs, source='/var/log/app/app.log')), **MONITOR)
		assert read_meta(e['_meta']) == pairs
		assert e['_raw'] == COMPACT and e['source'] == '/var/log/app/app.log'
		assert (e['host'], e['index']) == (MONITOR['host'], MONITOR['index'])

	def test_each_hostile_value_alone_as_the_last_pair(self):
		for v in HOSTILE:
			pairs = [('user', 'bob'), ('v', v)]
			e = both(out_file_line(record(pairs)), **MONITOR)
			assert read_meta(e['_meta']) == pairs, v

	def test_several_values_of_one_field_keep_their_order(self):
		pairs = [('tag', 'a'), ('tag', 'b "c"'), ('tag', 'd\\'), ('user', 'x')]
		e = both(out_file_line(record(pairs)), **MONITOR)
		assert read_meta(e['_meta']) == pairs

	def test_the_universal_forwarder_meta_stays_first(self):
		e = both(out_file_line(record([('user', 'bob')])), _meta='tenx_sourcetype::aws:cloudtrail',
			tenx_sourcetype='aws:cloudtrail', **MONITOR)
		assert e['_meta'].startswith('tenx_sourcetype::aws:cloudtrail ')
		assert read_meta(e['_meta']) == [('user', 'bob')] and e['tenx_sourcetype'] == 'aws:cloudtrail'

	def test_a_sourcetype_in_the_record_wins(self):
		e = both(out_file_line(record([], sourcetype='fortigate_traffic')), tenx_sourcetype='fgt_log', **MONITOR)
		assert e['tenx_sourcetype'] == 'fortigate_traffic'

	@pytest.mark.parametrize('text', [
		COMPACT, '~h', 'whole event\nsecond line\t"quoted" \\ back', '<Event><Data Name="a">é 中 😀</Data></Event>',
		'tenx.app.logs: [1794013200.448351000, {"event":"inner"}]',
	])
	def test_the_event_text_comes_back_exactly(self, text):
		e = both(out_file_line(record([], event=text)), **MONITOR)
		assert e['_raw'] == text and 'tenx_unwrap' not in e

	def test_an_event_sent_whole_has_no_fields(self):
		e = both(out_file_line(record([], event='2026-11-22 10:00:00 plain line')), **MONITOR)
		assert '_meta' not in e and e['_raw'] == '2026-11-22 10:00:00 plain line'

	def test_the_heavy_forwarder_line_reads_as_before(self):
		line = fluent_bit_json({'time': 1794013200.448351, 'event': COMPACT, 'host': 'dc1', 'source': 's',
			'sourcetype': 'XmlWinEventLog', 'index': 'wineventlog', 'meta': text_form([('user', 'a"b')])})
		assert both(line, **MONITOR) == unwrap(line, **MONITOR)
