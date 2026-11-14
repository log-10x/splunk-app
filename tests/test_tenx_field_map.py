"""
Tests for tenx_field_map: the generator of index-time field transforms for compact events.

Two kinds:

- Unit tests on small templates written here, always run. They pin each rule the first
  generator of these files learned (hash spaces, the values FORMAT cannot hold, stanza names)
  and each reader.
- Tests on samples and on the files validated on Splunk 10.4.3 (conf/b2 for the 662-event
  Windows sample, conf/b2_4663 for the 7,649-event 4663 sample, data/t3 for the encoded
  samples). They are not in this repository (third-party sample data, 2 to 16 MB each), so they
  run only where TENX_FIELD_MAP_SAMPLES names a directory holding them. Elsewhere they are
  skipped.

What the golden tests compare: the generated props.conf byte for byte, and transforms.conf
byte for byte after its first line (a comment naming the generator). What verify compares:
each compact line, expanded from the marked template, against the raw sample's events with
CR removed; then the fields the generated REGEX and FORMAT write, applied in Python, against
the reader's fields on the raw event. Neither says what Splunk does with the files.
"""
import io
import json
import os
import re

import pytest

import tenx_field_map as fm

M = fm.MARK


def tpl(key, parts, terminator, ts='%H:%M:%S', part_0='', unsafe='', pattern='', written=None):
	return fm.Template(key=key, written_hash=written or key, parts=parts, part_0=part_0, terminator=terminator,
		timestamp_format=ts, expand_unsafe=unsafe, pattern=pattern)


# -------------------------------------------------------------------------------------------
# Template records and marked text

class TestRecords:
	def test_templates_json_hash_is_stripped_and_record_matches_the_builder(self, tmp_path):
		p = tmp_path / 'templates.json'
		p.write_text(json.dumps({'templateHash': ' ab#c ', 'template': 'time=$(HH:mm:ss) user=$ ok'}) + '\n')
		[t] = fm.load_templates(str(p))
		assert t.key == 'ab#c' and t.written_hash == ' ab#c '
		assert t.parts == ['time=__TENX_TS__ user='] and t.terminator == ' ok'
		assert t.timestamp_format == '%H:%M:%S'

	def test_kv_export_with_a_one_element_array_as_a_string(self, tmp_path):
		p = tmp_path / 'kv.json'
		p.write_text(json.dumps([{'_key': 'h', 'pattern_parts': 'a=__TENX_TS__ b=', 'pattern_terminator': '',
			'part_0': '', 'timestamp_format': '%H', 'expand_unsafe': ''}]))
		[t] = fm.load_templates(str(p))
		assert t.parts == ['a=__TENX_TS__ b=']

	def test_two_different_templates_under_one_hash_are_refused(self):
		a = tpl('h', ['x='], '')
		b = tpl('h', ['y='], '')
		templates, refused = fm.merge_templates([[a], [b]])
		assert templates == {} and refused == {'h': fm.REFUSED_CONFLICT}

	def test_marked_text_with_a_timestamp(self):
		t = tpl('h', ['<T>__TENX_TS__</T><A>', '</A><B>'], '</B>')
		assert fm.marked_text(t) == ('<T>' + M % 0 + '</T><A>' + M % 1 + '</A><B>' + M % 2 + '</B>', 3)

	def test_marked_text_without_a_timestamp(self):
		t = tpl('h', ['-b='], ' end', ts='', part_0='a=')
		assert fm.marked_text(t) == ('a=' + M % 0 + '-b=' + M % 1 + ' end', 2)

	def test_without_a_timestamp_the_pattern_decides_between_no_value_and_one(self):
		literal = tpl('h', [], 'all text', ts='', pattern='all text')
		one = tpl('h', [], ' rest', ts='', pattern='$ rest')
		unknown = tpl('h', [], ' rest', ts='', pattern=None)
		assert fm.marked_text(literal) == ('all text', 0)
		assert fm.marked_text(one) == (M % 0 + ' rest', 1)
		with pytest.raises(ValueError):
			fm.marked_text(unknown)


# -------------------------------------------------------------------------------------------
# FORMAT, REGEX and stanza names

class TestFormat:
	NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')

	def test_values_join_text_and_groups(self):
		assert fm.to_format('win-' + M % 4 + '.' + M % 5, False) == ('win-$5.$6', None)

	@pytest.mark.parametrize('expr,why', [
		('a"b' + M % 1, fm.WHY_QUOTE),
		('a\nb' + M % 1, fm.WHY_LINE_BREAK),
		('a\r\nb', fm.WHY_LINE_BREAK),
		('cost $5 ' + M % 1, fm.WHY_DOLLAR_DIGIT),
		(M % 1 + '2', fm.WHY_GROUP_DIGIT),
		('a' + fm.UNDECODABLE + M % 1, fm.WHY_SPLIT_ESCAPE),
	])
	def test_values_format_cannot_hold(self, expr, why):
		assert fm.to_format(expr, False) == (None, why)

	def test_a_group_followed_by_another_group_is_fine(self):
		assert fm.to_format(M % 1 + M % 2, False) == ('$2$3', None)

	def test_names(self):
		assert fm.to_format(M % 14, True, self.NAME) == ('$15', None)
		assert fm.to_format('EventID', True, self.NAME) == ('EventID', None)
		assert fm.to_format('a' + M % 1, True, self.NAME) == (None, fm.WHY_NAME_MIXES)
		assert fm.to_format('a-b', True, self.NAME) == (None, fm.WHY_NAME_NOT_FIELD)

	def test_mixed_names_only_when_asked(self):
		name = 'requestParameters.' + M % 5 + '.items{}.deviceName'
		assert fm.to_format(name, True, fm.JsonReader.field_name) == (None, fm.WHY_NAME_MIXES)
		assert fm.to_format(name, True, fm.JsonReader.field_name, mixed_names=True) == \
			('requestParameters.$6.items{}.deviceName', None)

	def test_regex_escape_is_re_escape_plus_slash(self):
		# Pinned so the REGEX does not change with the interpreter: the files were made with Python 3.13.
		for c in map(chr, range(32, 127)):
			assert fm.regex_escape(c) == (re.escape(c) if c != '/' else '\\/'), c

	def test_compact_line_regex(self):
		tolerant = fm.compact_line_regex('#8_a:t', 2)
		assert tolerant == r'^~ *\#8_a:t *,([^,]*),([^,]*)$'
		assert re.match(tolerant, '~ #8_a:t ,1,2') and re.match(tolerant, '~#8_a:t,1,2')
		exact = fm.compact_line_regex('#8_a:t', 2, 'exact')
		assert exact == r'^~\#8_a:t,([^,]*),([^,]*)$' and not re.match(exact, '~#8_a:t ,1,2')
		assert fm.compact_line_regex('a/b', 0) == r'^~ *a\/b *$'

	def test_stanza_names(self):
		assert fm.stanza_name('tenx_win', 7, '!6c>z*a', 'indexed') == 'tenx_win_00007__6c_z_a'
		assert fm.stanza_name('tenx_win', 7, '!6c>z*a', 'hash') == 'tenx_win__6c_z_a'
		stable = fm.stanza_name('tenx_win', 7, '!6c>z*a', 'stable')
		assert stable.startswith('tenx_win__6c_z_a_') and stable == fm.stanza_name('x', 0, '!6c>z*a', 'stable') \
			.replace('x_', 'tenx_win_', 1)

	def test_hash_names_that_clash_are_refused(self):
		templates = {'a<b': tpl('a<b', ['x='], ''), 'a>b': tpl('a>b', ['x='], '')}
		with pytest.raises(ValueError):
			fm.FieldMap(templates, fm.KeyValueReader(), 'p', stanza_names='hash')
		names = [t.stanza for t in fm.FieldMap(templates, fm.KeyValueReader(), 'p').transforms]
		assert names == ['p_00000_a_b', 'p_00001_a_b']


# -------------------------------------------------------------------------------------------
# Readers

class TestXmlWindowsReader:
	def test_system_eventdata_and_attributes(self):
		text = ("<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>" + M % 1 +
			"</EventID><" + M % 2 + ">" + M % 3 + "</" + M % 4 + "><Computer>win-" + M % 5 +
			"</Computer></System><EventData><Data Name='" + M % 6 + "'>" + M % 7 +
			"</Data><Data Name='LogonType'>3</Data></EventData></Event>")
		assert fm.XmlWindowsReader().pairs(text) == [
			('EventID', M % 1), (M % 2, M % 3), ('Computer', 'win-' + M % 5),
			('Name', 'Microsoft-Windows-Security-Auditing'), (M % 6, M % 7), ('LogonType', '3')]

	def test_a_literal_tag_needs_its_own_closing_tag(self):
		assert fm.XmlWindowsReader().pairs('<System><A>x</B></System>') == []


# Event 1102 (audit log cleared), shaped by the add-on's own UserData rules: <UserData> holding
# <LogFileCleared> with <tag>value</tag> children, <SubjectUserName> among them.
EVENT_1102 = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
	"<Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/>"
	"<EventID>1102</EventID><Version>0</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode>"
	"<Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2023-04-25T09:05:05.618699400Z'/>"
	"<EventRecordID>12345</EventRecordID><Correlation/><Execution ProcessID='1024' ThreadID='2048'/>"
	"<Channel>Security</Channel><Computer>win-dc-01.example.local</Computer><Security/></System>"
	"<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>"
	"<SubjectUserSid>S-1-5-21-1111-2222-3333-500</SubjectUserSid><SubjectUserName>Administrator</SubjectUserName>"
	"<SubjectDomainName>EXAMPLE</SubjectDomainName><SubjectLogonId>0x3e7</SubjectLogonId>"
	"</LogFileCleared></UserData></Event>")
USERDATA_PAIRS = [('SubjectUserSid', 'S-1-5-21-1111-2222-3333-500'), ('SubjectUserName', 'Administrator'),
	('SubjectDomainName', 'EXAMPLE'), ('SubjectLogonId', '0x3e7'), ('Caller_User_Name', 'Administrator')]
VALUES_1102 = ['12345', 'S-1-5-21-1111-2222-3333-500', 'Administrator', 'EXAMPLE', '0x3e7']


def template_1102():
	text = EVENT_1102.replace('2023-04-25T09:05:05.618699400Z', '__TENX_TS__')
	for v in VALUES_1102:
		text = text.replace('>%s<' % v, '>\x01<', 1)
	pieces = text.split('\x01')
	return tpl('h1102', pieces[:-1], pieces[-1], ts='%Y-%m-%dT%H:%M:%S.%9QZ')


class TestUserData:
	def test_reader_reads_the_log_cleared_block_and_the_caller(self):
		assert fm.XmlWindowsReader().pairs(EVENT_1102)[-5:] == USERDATA_PAIRS

	def test_transform_for_a_1102_template(self):
		f = fm.FieldMap({'h1102': template_1102()}, fm.XmlWindowsReader(), 'p')
		assert f.transforms[0].format.endswith('SubjectUserSid::"$3" SubjectUserName::"$4" SubjectDomainName::"$5" '
			'SubjectLogonId::"$6" Caller_User_Name::"$4"')

	def test_verify_on_a_1102_event(self, tmp_path):
		t = template_1102()
		f = fm.FieldMap({t.key: t}, fm.XmlWindowsReader(), 'p')
		encoded = tmp_path / 'encoded.log'
		encoded.write_text('~h1102,1682413505618699400,%s\n' % ','.join(VALUES_1102))
		raw = tmp_path / 'raw.log'
		raw.write_text(EVENT_1102 + '\n')
		result = fm.verify({t.key: t}, f, str(encoded), str(raw), out=io.StringIO())
		assert result['expanded_equal_raw'] == 1 and result['transform_regex_did_not_match'] == 0
		assert result['fields_missing_or_different_events'] == {'SystemTime': 1}

	@pytest.mark.skipif(not os.path.isdir(os.environ.get('TENX_TA_WINDOWS', '/nonexistent')),
		reason='set TENX_TA_WINDOWS to an unpacked Splunk_TA_windows')
	def test_reader_equals_the_add_on_userdata_rules(self):
		# Runs the add-on's own REPORT chain for source XmlWinEventLog:Security on the synthetic
		# event, every rule whose SOURCE_KEY is the UserData block or a block cut from it, classes
		# in name order, and compares with the reader. This is Python's re, not Splunk.
		import configparser
		ta = os.path.join(os.environ['TENX_TA_WINDOWS'], 'default')

		def conf(name):
			c = configparser.RawConfigParser(strict=False, interpolation=None)
			c.optionxform = str
			c.read(os.path.join(ta, name))
			return c
		transforms, props = conf('transforms.conf'), conf('props.conf')['source::XmlWinEventLog:Security']

		def py(rx):
			return re.sub(r'\(\?<(?=[A-Za-z])', '(?P<', rx)
		fields = {'UserData_Xml': re.search(py(transforms['userdata_xml_block']['REGEX']), EVENT_1102).group(1)}
		got = []
		for cls in sorted(k for k in props if k.startswith('REPORT-')):
			for name in (n.strip() for n in props[cls].split(',')):
				if not transforms.has_section(name):
					continue
				st = transforms[name]
				src = st.get('SOURCE_KEY', '_raw')
				# First-link rules only: a rule reading a field such as SubjectUserName runs at
				# search time on the indexed field as well (one gave src_user here).
				if src not in fields or not src.endswith('_Xml'):
					continue
				for m in re.finditer(py(st['REGEX']), fields[src]):
					for token in st['FORMAT'].split():
						k, v = (re.sub(r'\$(\d+)', lambda g: m.group(int(g.group(1))), x) for x in token.split('::'))
						fields[k] = v
						if not k.endswith('_Xml'):
							got.append((k, v))
		assert sorted(got) == sorted(USERDATA_PAIRS)


class TestJsonReader:
	def test_paths_as_splunk_names_json_fields(self):
		text = ('{"a": {"b": "x", "c": [1, {"d": true}], "e": {}, "f": []}, "g": [[' + M % 1 + ']], '
			'"h": null, "i": "q\\"\\\\\\/"}')
		assert fm.JsonReader().pairs(text) == [
			('a.b', 'x'), ('a.c{}', '1'), ('a.c{}.d', 'true'), ('g{}{}', M % 1), ('h', 'null'), ('i', 'q"\\/')]

	def test_markers_in_keys_and_bare_values(self):
		text = '{"' + M % 1 + '": {"n": ' + M % 2 + '.' + M % 3 + '}, "v": "' + M % 4 + '-' + M % 5 + '"}'
		assert fm.JsonReader().pairs(text) == [(M % 1 + '.n', M % 2 + '.' + M % 3), ('v', M % 4 + '-' + M % 5)]

	def test_text_that_is_not_one_json_value_yields_nothing(self):
		assert fm.JsonReader().pairs('<13>host app: {"a": 1}') == []
		assert fm.JsonReader().pairs('{"a": 1} trailing') == []
		assert fm.JsonReader().pairs('{"a": 1') == []

	def test_an_escape_split_by_a_value_loses_only_that_string(self):
		text = '{"t": "ab\\' + M % 1 + 'c", "u": "' + M % 2 + '"}'
		pairs = fm.JsonReader().pairs(text)
		assert pairs[1] == ('u', M % 2)
		assert fm.to_format(pairs[0][1], False) == (None, fm.WHY_SPLIT_ESCAPE)


class TestKeyValueReader:
	def test_quoted_unquoted_and_value_names(self):
		text = 'date=' + M % 1 + M % 2 + ' logid="' + M % 3 + '" ' + M % 4 + '="' + M % 5 + '" x= end=1'
		assert fm.KeyValueReader().pairs(text) == [
			('date', M % 1 + M % 2), ('logid', M % 3), (M % 4, M % 5), ('x', ''), ('end', '1')]

	def test_pairs_start_at_whitespace(self):
		assert fm.KeyValueReader().pairs('a=1,b=2 msg="x y" c="d"e') == [('a', '1,b=2'), ('msg', 'x y'), ('c', '"d"e')]


# -------------------------------------------------------------------------------------------
# The field map, the app and verify on small inputs

class TestFieldMap:
	def test_skips_are_counted_and_named(self):
		t = tpl('h', ['time=__TENX_TS__ user=', ' msg="say \\"', '" path=', ' n='], '2',
			pattern='time=$(HH:mm:ss) user=$ msg="say \\"$" path=$ n=$2')
		f = fm.FieldMap({'h': t}, fm.KeyValueReader(), 'p')
		[tr] = f.transforms
		assert tr.format == 'time::"$1" user::"$2" path::"$4"'
		# msg="say \"..." is not closed by a quote before whitespace, so the kv reader reads it
		# unquoted, and that value holds a double quote.
		assert f.report()['skipped'] == {'value: ' + fm.WHY_GROUP_DIGIT: 1, 'value: ' + fm.WHY_QUOTE: 1}
		assert f.report()['timestamp_written_as_epoch'] == {'time': 1}

	def test_xml_values_are_trimmed_as_splunk_extracts_them(self):
		# Splunk 10.4.3: <Data Name='LogonProcessName'>NtLmSsp </Data> reads as
		# "NtLmSsp" through the add-on, and the indexed field kept the space until this.
		t = tpl('h', ["<Event><System><EventID>__TENX_TS__</EventID></System><EventData><Data Name='LogonProcessName'>"],
			" </Data><Data Name='x'> a b </Data></EventData></Event>")
		trimmed = fm.FieldMap({'h': t}, fm.XmlWindowsReader(), 'p').transforms[0].format
		kept = fm.FieldMap({'h': t}, fm.XmlWindowsReader(), 'p', trim_values=False).transforms[0].format
		assert trimmed == 'EventID::"$1" LogonProcessName::"$2" x::"a b"'
		assert kept == 'EventID::"$1" LogonProcessName::"$2 " x::" a b "'

	def test_json_and_kv_values_are_not_trimmed_by_default(self):
		t = tpl('h', ['time=__TENX_TS__ msg="'], ' "')
		assert fm.FieldMap({'h': t}, fm.KeyValueReader(), 'p').transforms[0].format == 'time::"$1" msg::"$2 "'

	def test_reserved_names_ignore_case(self):
		# Splunk 10.4.3: the indexed field eventType arrived as extracted_eventType.
		for name in ('eventType', 'eventtype', 'Host', 'SOURCE', 'sourcetype', 'index', '_time', 'tag::eventtype',
				'date_hour', 'punct', 'linecount', 'splunk_server', 'timestamp'):
			assert fm.reserved_name(name), name
		for name in ('eventTypeName', 'requestParameters.host', 'userIdentity.type', 'Computer', 'EventID'):
			assert not fm.reserved_name(name), name

	def test_reserved_names_are_left_out_by_default_and_reported(self):
		t = tpl('h', ['time=__TENX_TS__ eventType=', ' Source=', ' user='], '')
		f = fm.FieldMap({'h': t}, fm.KeyValueReader(), 'p')
		assert f.transforms[0].format == 'time::"$1" user::"$4"'
		assert f.report()['reserved_field_names'] == {'action': 'left out', 'templates_per_name': {'eventType': 1, 'Source': 1}}
		assert f.skipped == {'name: ' + fm.WHY_RESERVED: 2}

	def test_reserved_names_under_a_prefix(self):
		t = tpl('h', ['time=__TENX_TS__ eventType='], '')
		f = fm.FieldMap({'h': t}, fm.KeyValueReader(), 'p', reserved_names='prefix', reserved_prefix='x_')
		assert f.transforms[0].format == 'time::"$1" x_eventType::"$2"'
		assert f.report()['reserved_field_names']['action'] == 'written as x_<name>'

	def test_timestamp_values_can_be_left_out(self):
		t = tpl('h', ['time=__TENX_TS__ user='], '')
		f = fm.FieldMap({'h': t}, fm.KeyValueReader(), 'p', timestamp_values='skip')
		assert f.transforms[0].format == 'user::"$2"'
		assert f.skipped == {'value: ' + fm.WHY_TIMESTAMP: 1}

	def test_unsafe_and_fieldless_templates_get_no_transform(self):
		templates = {'u': tpl('u', ['a='], '', unsafe='back-reference'), 'n': tpl('n', ['no pairs '], '')}
		f = fm.FieldMap(templates, fm.KeyValueReader(), 'p')
		assert f.transforms == []
		assert f.refused == {'u': fm.REFUSED_UNSAFE % 'back-reference', 'n': fm.REFUSED_NO_FIELDS}

	def test_positions_count_every_input_template_before_the_filter(self):
		templates = {k: tpl(k, ['a='], '') for k in ('a', 'b', 'c')}
		f = fm.FieldMap(templates, fm.KeyValueReader(), 'p', keep={'c'})
		assert [t.stanza for t in f.transforms] == ['p_00002_c']


class TestApp:
	def test_parsing_settings_of_tenx_encoded(self):
		# If the app adds a setting to [tenx_encoded], this fails until someone decides whether
		# it applies where data is parsed (copy it) or at search time (leave it).
		copied, not_copied = fm.parsing_settings(fm.default_app_props())
		assert copied == [('DATETIME_CONFIG', 'CURRENT'), ('LINE_BREAKER', '([\\r\\n]+)'),
			('SHOULD_LINEMERGE', 'false'), ('NO_BINARY_CHECK', 'true'), ('TRUNCATE', '262144'),
			('TRANSFORMS-tenx_time', 'tenx-event-time')]
		assert sorted(not_copied) == ['REPORT-tenx', 'category', 'disabled', 'pulldown_type']

	def test_gen_writes_the_app_folder(self, tmp_path):
		records = tmp_path / 'templates.json'
		records.write_text(json.dumps({'templateHash': 'k1 ', 'template': 'time=$(HH:mm:ss) user=$ src=$'}) + '\n')
		out = tmp_path / 'app'
		assert fm.main(['gen', '--records', str(records), '--reader', 'kv', '--sourcetype', 'tenx_fw',
			'--rename', 'fw:traffic', '--indexed-value-false', 'user', '--out', str(out)]) == 0
		assert sorted(os.listdir(str(out / 'default'))) == ['app.conf', 'fields.conf', 'props.conf', 'transforms.conf']
		assert (out / 'metadata' / 'default.meta').read_text() == '[]\nexport = system\n'
		props = (out / 'default' / 'props.conf').read_text()
		assert '[tenx_fw]\n' in props and \
			'TRANSFORMS-tenx_fw = tenx_fw_sourcetype, tenx_fw_00000_k1, tenx_fw_ingest_eval\n' in props
		assert 'rename = fw:traffic\n' in props
		assert props.endswith('[fw:traffic]\nREPORT-tenx_fm_hash_vars = tenx_fm_hash_vars\n')
		assert '[tenx_fw_00000_k1]\nREGEX = ^~ *k1 *,([^,]*),([^,]*),([^,]*)$\n' \
			'FORMAT = user::"$2" src::"$3" tenx_fmf_time::"1" tenx_fmv_time_1::"$1" tenx_mapped::"1"\nWRITE_META = true\n' \
			in (out / 'default' / 'transforms.conf').read_text()
		assert '[user]\nINDEXED_VALUE = false\n' in (out / 'default' / 'fields.conf').read_text()
		report = json.loads((tmp_path / 'app_report.json').read_text())
		assert report['hashes_with_outer_spaces'] == 1 and report['templates'] == 1

	def test_verify_counts_names_from_values_that_collide(self, tmp_path):
		# A name that is a compact value cannot be checked when the transform is written.
		records = tmp_path / 'templates.json'
		records.write_text(json.dumps({'templateHash': 'k', 'template': 'time=$(HH:mm:ss) $=$'}) + '\n')
		encoded = tmp_path / 'encoded.log'
		encoded.write_text('~k,1700000000000,Host,web1\n~k,1700000000000,user,bob\n')
		raw = tmp_path / 'raw.log'
		raw.write_text('time=22:13:20 Host=web1\ntime=22:13:20 user=bob\n')
		templates, _ = fm.merge_templates([fm.load_templates(str(records))])
		result = fm.verify(templates, fm.FieldMap(templates, fm.KeyValueReader(), 'p'), str(encoded), str(raw),
			out=io.StringIO())
		assert result['reserved_names_from_values_events'] == {'Host': 1}

	def test_verify_on_a_small_sample(self, tmp_path):
		records = tmp_path / 'templates.json'
		records.write_text('\n'.join(json.dumps(x) for x in [
			{'templateHash': ' k1', 'template': 'time=$(HH:mm:ss) user=$ src=$.$.$.$ msg="a \\"b\\""'},
			{'templateHash': 'k2', 'template': 'action=$ n=$'}]) + '\n')
		encoded = tmp_path / 'encoded.log'
		encoded.write_text('~ k1,1700000000000,bob,10,0,1,14\n~k2,deny,7\n')
		raw = tmp_path / 'raw.log'
		raw.write_text('time=22:13:20 user=bob src=10.0.1.14 msg="a \\"b\\""\r\naction=deny n=7\n')
		templates, _ = fm.merge_templates([fm.load_templates(str(records))])
		f = fm.FieldMap(templates, fm.KeyValueReader(), 'p')
		result = fm.verify(templates, f, str(encoded), str(raw), out=io.StringIO())
		assert result['expanded_equal_raw'] == 2 and result['transform_regex_did_not_match'] == 0
		# time is written as epoch; msg holds a double quote; both are named in the report.
		assert result['events_all_fields_equal'] == 1 and result['events_differing_only_as_reported'] == 1
		assert result['fields_missing_or_different_events'] == {'time': 1, 'msg': 1}
		assert f.report()['skipped'] == {'value: ' + fm.WHY_QUOTE: 1}


# -------------------------------------------------------------------------------------------
# Values written by INGEST_EVAL

class TestIngestEval:
	def xml(self):
		# UserAccountControl's text holds line breaks; SystemTime is the timestamp slot.
		return tpl('h', ["<Event><System><TimeCreated SystemTime='__TENX_TS__'/><EventID>",
			"</EventID></System><EventData><Data Name='UserAccountControl'>\n\t\t%%", "\n\t\t%%",
			"</Data><Data Name='CommandLine'>\"C:\\x\\"], ".exe\" --a</Data></EventData></Event>",
			ts='%Y-%m-%dT%H:%M:%S.%7QZ')

	def test_values_format_cannot_hold_go_to_one_ingest_eval(self):
		f = fm.FieldMap({'h': self.xml()}, fm.XmlWindowsReader(), 'p', eval_values=True, timestamp_values='text')
		[tr] = f.transforms
		assert tr.format == ('EventID::"$2" tenx_fmf_SystemTime::"1" tenx_fmv_SystemTime_1::"$1" '
			'tenx_fmf_UserAccountControl::"2" tenx_fmv_UserAccountControl_1::"$3" tenx_fmv_UserAccountControl_2::"$4" '
			'tenx_fmf_CommandLine::"3" tenx_fmv_CommandLine_1::"$5"')
		assert tr.fields == 4 and f.skipped == {}
		text = fm.ingest_eval_text(f)
		# the line break leaves the field's ends, as Splunk trims it; the one inside stays
		assert 'UserAccountControl=case(tenx_fmf_UserAccountControl=="2", urldecode("%25%25") . ' \
			'coalesce(tenx_fmv_UserAccountControl_1, "") . urldecode("%0A%09%09%25%25") . ' \
			'coalesce(tenx_fmv_UserAccountControl_2, ""))' in text
		assert text.endswith('tenx_fmf_SystemTime:=null(), tenx_fmv_SystemTime_1:=null(), '
			'tenx_fmf_UserAccountControl:=null(), tenx_fmv_UserAccountControl_1:=null(), '
			'tenx_fmv_UserAccountControl_2:=null(), tenx_fmf_CommandLine:=null(), tenx_fmv_CommandLine_1:=null()')
		# no line break, tab, quote, backslash, dollar or percent sign in the .conf line itself
		assert not re.search(r'[\n\t\\$]', text) and '"C:' not in text

	def test_off_leaves_them_out_as_before(self):
		f = fm.FieldMap({'h': self.xml()}, fm.XmlWindowsReader(), 'p')
		[tr] = f.transforms
		assert tr.format == 'EventID::"$2" SystemTime::"$1"' and not f.forms
		assert f.skipped == {'value: ' + fm.WHY_LINE_BREAK: 1, 'value: ' + fm.WHY_QUOTE: 1}

	def test_the_python_reading_of_a_form_is_the_expanded_text(self):
		f = fm.FieldMap({'h': self.xml()}, fm.XmlWindowsReader(), 'p', eval_values=True, timestamp_values='text')
		[tr] = f.transforms
		pairs = dict(fm.apply_transform(tr, '~h,1697157342412381800,4624,2080,2082,prog', f.forms))
		assert pairs == {'EventID': '4624', 'SystemTime': '2023-10-13T00:35:42.4123818Z',
			'UserAccountControl': '%%2080\n\t\t%%2082', 'CommandLine': '"C:\\x\\prog.exe" --a'}

	def test_templates_with_the_same_shape_share_a_form(self):
		a = tpl('a', ["</Data><Data Name='N'>"], '</Data></EventData></Event>', ts='',
			part_0="<Event><EventData><Data Name='L'>x\n")
		b = tpl('b', ["</Data><Data Name='L'>x\n"], '</Data></EventData></Event>', ts='',
			part_0="<Event><EventData><Data Name='N'>")
		f = fm.FieldMap({'a': a, 'b': b}, fm.XmlWindowsReader(), 'p', eval_values=True)
		assert len(f.forms) == 1 and f.eval_fields == {'L': 2}
		assert [t.evals for t in f.transforms] == [(('L', 1, (1,)),), (('L', 1, (2,)),)]

	def test_a_name_from_a_value_is_left_out(self):
		t = tpl('h', ["'>a\nb"], '</Data></EventData></Event>', ts='', part_0="<Event><EventData><Data Name='")
		f = fm.FieldMap({'h': t}, fm.XmlWindowsReader(), 'p', eval_values=True)
		assert f.skipped == {'name: ' + fm.WHY_EVAL_NAME: 1}

	def test_spl_text(self):
		assert fm.spl_text('C:/Program Files') == '"C:/Program Files"'
		assert fm.spl_text('a"b\n%$\\+') == 'urldecode("a%22b%0A%25%24%5C%2B")'
		from urllib.parse import unquote
		for text in ('a"b\n%$\\+', '\t\t%%', 'é ü', "'x'"):
			assert unquote(fm.spl_text(text)[len('urldecode("'):-2]) == text

	def test_spl_timestamp_uses_no_strftime_for_the_time_of_day(self):
		expr = fm.spl_timestamp('v', '%Y-%m-%dT%H:%M:%S.%7QZ')
		# the date from noon shifted by the instance's offset; the hour, minute, second by arithmetic
		assert expr.count('strftime(') == 4 and ', "%Y-%m-%dT")' in expr and ', "%z")' in expr
		assert 'substr(v . "000000000", 11, 7)' in expr and expr.endswith(' . "Z"')
		assert fm.spl_timestamp('v', fm.tenx_dml_builder.EPOCH_PASSTHROUGH) == 'v'
		assert fm.spl_timestamp('v', '%H:%M:%S %Q') is None


# -------------------------------------------------------------------------------------------
# Samples and the files validated on Splunk (not in this repository)

SAMPLES = os.environ.get('TENX_FIELD_MAP_SAMPLES', '/nonexistent')
needs_samples = pytest.mark.skipif(not os.path.isdir(os.path.join(SAMPLES, 'conf', 'b2_4663')),
	reason='samples not present (set TENX_FIELD_MAP_SAMPLES)')


def sample(*parts):
	return os.path.join(SAMPLES, *parts)


def read(path):
	with open(path, encoding='utf-8', newline='') as f:
		return f.read()


def generate(tmp_path, name, argv):
	out = tmp_path / name
	assert fm.main(['gen'] + argv + ['--out', str(out)]) == 0
	return out


def run_verify(argv):
	args = fm.build_parser().parse_args(['verify'] + argv)
	_, templates, field_map = fm._build(args)
	return fm.verify(templates, field_map, args.encoded, args.raw, out=io.StringIO()), field_map


T4663 = ('data', 't3', 'win_security_4663_redline', 'splunk')
# The first validated files had neither the tenx_mapped mark nor the search-time hash extraction.
FIRST_FILES = ['--mark', 'none', '--search-hash', 'off', '--sourcetype-field', 'none', '--eval-values', 'off',
	'--timestamp-values', 'epoch']
TAUTH = ('data', 't3', 'win_security_auth_change', 'splunk')


@needs_samples
class TestGoldenWindows:
	def test_662_event_sample_equals_the_first_files(self, tmp_path):
		out = generate(tmp_path, 'b2', ['--records', sample('data', 'b2_kv_rows.json'), '--target', 'windows-security',
			'--stanza-names', 'hash', '--hash-match', 'exact', '--trim-values', 'off'] + FIRST_FILES)
		assert read(str(out / 'default' / 'props.conf')) == read(sample('conf', 'b2', 'props.conf'))
		assert read(str(out / 'default' / 'transforms.conf')).split('\n', 1)[1] == \
			read(sample('conf', 'b2', 'transforms.conf')).split('\n', 1)[1]
		golden = json.load(open(sample('conf', 'b2', 'gen_report.json')))
		report = json.load(open(str(tmp_path / 'b2_report.json')))
		assert {k: report[k] for k in golden} == golden

	def test_4663_sample_equals_the_first_files(self, tmp_path):
		out = generate(tmp_path, 'b2_4663', ['--records', sample('data', 'b2_kv_rows_all.json'),
			'--only-hashes-in', sample(*T4663 + ('templates.json',)), '--target', 'windows-security',
			'--sourcetype', 'tenx_win4663'] + FIRST_FILES)
		assert read(str(out / 'default' / 'props.conf')) == read(sample('conf', 'b2_4663', 'props.conf'))
		assert read(str(out / 'default' / 'transforms.conf')).split('\n', 1)[1] == \
			read(sample('conf', 'b2_4663', 'transforms.conf')).split('\n', 1)[1]

		def stanzas(path):
			return [l for l in read(path).splitlines() if not l.startswith('#')]
		assert stanzas(str(out / 'default' / 'fields.conf')) == stanzas(sample('conf', 'b2_4663', 'fields.conf'))

	def test_templates_json_gives_the_same_transforms_as_the_kv_rows(self):
		kv, _ = fm.merge_templates([fm.load_templates(sample('data', 'b2_kv_rows_all.json'))])
		tj, _ = fm.merge_templates([fm.load_templates(sample(*T4663 + ('templates.json',)))])
		a = fm.FieldMap(kv, fm.XmlWindowsReader(), 'p', keep=set(tj))
		b = fm.FieldMap(tj, fm.XmlWindowsReader(), 'p')
		assert len(a.transforms) == len(b.transforms) == 1783
		assert [(t.key, t.regex, t.format) for t in a.transforms] == [(t.key, t.regex, t.format) for t in b.transforms]
		assert b.outer_space_hashes == 26

	V662 = ['--records', sample('data', 'b2_kv_rows.json'), '--target', 'windows-security',
		'--encoded', sample(*TAUTH + ('encoded.log',)), '--raw', sample('samples', 'win_security_auth_change.xml.log')]
	V4663 = ['--records', sample('data', 'b2_kv_rows_all.json'), '--only-hashes-in',
		sample(*T4663 + ('templates.json',)), '--target', 'windows-security',
		'--encoded', sample(*T4663 + ('encoded.log',)), '--raw', sample('samples', 'win_security_4663_redline.xml.log')]
	FORMAT_ONLY = ['--eval-values', 'off', '--timestamp-values', 'epoch']

	def test_verify_662_event_sample(self):
		result, f = run_verify(self.V662)
		assert result['compact_lines'] == result['expanded_equal_raw'] == 662
		assert result['transform_regex_did_not_match'] == 0
		assert result['events_all_fields_equal'] == 662
		assert result['fields_missing_or_different_events'] == {} and result['fields_extra_or_different_events'] == {}
		assert f.report()['written_by_ingest_eval']['templates_per_field'] == {
			'SystemTime': 96, 'UserAccountControl': 2, 'CommandLine': 4, 'PrivilegeList': 2}

	def test_verify_662_event_sample_format_only(self):
		result, f = run_verify(self.V662 + self.FORMAT_ONLY)
		assert result['events_differing_only_as_reported'] == 662
		assert set(result['fields_missing_or_different_events']) == {
			'CommandLine', 'PrivilegeList', 'UserAccountControl', 'SystemTime'}
		assert set(result['fields_extra_or_different_events']) == {'SystemTime'}

	def test_verify_4663_sample(self):
		result, f = run_verify(self.V4663)
		assert result['compact_lines'] == result['expanded_equal_raw'] == 7649
		assert result['transform_regex_did_not_match'] == 0
		assert result['events_all_fields_equal'] == 7649
		# AccessList is "%%" and a value once the line break and tabs at its end are trimmed, as
		# Splunk trims them, so FORMAT writes it; only the timestamp is left to INGEST_EVAL.
		assert f.report()['written_by_ingest_eval']['templates_per_field'] == {'SystemTime': 1783}
		assert f.report()['skipped'] == {}

	def test_verify_4663_sample_format_only(self):
		result, f = run_verify(self.V4663 + self.FORMAT_ONLY)
		assert result['events_differing_only_as_reported'] == 7649
		assert result['fields_missing_or_different_events'] == {'AccessList': 7649, 'SystemTime': 7649}


@needs_samples
class TestJsonAndKeyValueSamples:
	CT = ('data', 't3', 'cloudtrail', 'splunk')
	FG = ('data', 't3', 'fortigate', 'splunk')

	def ct(self, *extra):
		return ['--records', sample(*self.CT + ('templates.json',)), '--reader', 'json', '--sourcetype', 'tenx_ct',
			'--rename', 'aws:cloudtrail', '--encoded', sample(*self.CT + ('encoded.log',)),
			'--raw', sample('samples', 'cloudtrail.json')] + list(extra)

	def fg(self, *extra):
		return ['--records', sample(*self.FG + ('templates.json',)), '--reader', 'kv', '--sourcetype', 'tenx_fg',
			'--rename', 'fortigate_traffic', '--encoded', sample(*self.FG + ('encoded.log',)),
			'--raw', sample('samples', 'fortigate.log')] + list(extra)

	def test_cloudtrail_json(self):
		result, f = run_verify(self.ct())
		assert result['compact_lines'] == result['expanded_equal_raw'] == 8100
		assert result['transform_regex_did_not_match'] == 0
		# Every difference is a field the report names: keys the engine stored as values make
		# the paths under them mixed names, left out by default.
		assert result['events_differing_only_as_reported'] == 8100
		assert len(f.transforms) == 11
		# A timestamp under a JSON path name is left out: INGEST_EVAL is given plain names only.
		assert set(f.skipped) == {'name: ' + fm.WHY_NAME_MIXES, 'value: ' + fm.WHY_SPLIT_ESCAPE, 'name: ' + fm.WHY_RESERVED,
			'name: ' + fm.WHY_EVAL_NAME_SHAPE}
		assert f.report()['timestamp_written_as_text'] == {'eventTime': 5}

	def test_cloudtrail_eventtype_is_reported_and_left_out(self):
		result, f = run_verify(self.ct('--mixed-names'))
		assert f.report()['reserved_field_names'] == {'action': 'left out', 'templates_per_name': {'eventType': 11}}
		assert all('eventType::' not in t.format for t in f.transforms)
		assert result['events_differing_only_as_reported'] == 8100

	def test_cloudtrail_json_with_mixed_names(self):
		result, f = run_verify(self.ct('--mixed-names'))
		assert result['events_differing_only_as_reported'] == 8100
		assert set(result['fields_missing_or_different_events']) == {
			'userIdentity.sessionContext.attributes.creationDate', 'responseElements.credentials.sessionToken', 'eventType'}
		assert result['fields_extra_or_different_events'] == {}

	def test_fortigate_key_value(self):
		result, f = run_verify(self.fg())
		assert result['compact_lines'] == result['expanded_equal_raw'] == 82
		assert result['transform_regex_did_not_match'] == 0
		assert result['events_all_fields_equal'] == 56 and result['events_differing_only_as_reported'] == 26
		# FortiGate's own eventtype= key is Splunk's eventtype field: left out and reported.
		assert result['fields_missing_or_different_events'] == {'eventtype': 26}
		assert f.report()['written_by_ingest_eval']['templates_per_field'] == {'time': 78, 'msg': 1}
		assert f.report()['reserved_field_names']['templates_per_name'] == {'eventtype': 25}
		assert f.outer_space_hashes == 2

	def test_fortigate_exact_hash_match_misses_the_hashes_with_spaces(self):
		# Why tolerant is the default: the store keeps hashes stripped, compact lines do not.
		result, f = run_verify(self.fg('--hash-match', 'exact'))
		spaced = [line for line in read(sample(*self.FG + ('encoded.log',))).splitlines()
			if fm.split_compact(line)[0] != fm.split_compact(line)[0].strip()]
		assert len(spaced) > 0 and result['transform_regex_did_not_match'] == len(spaced)


# -------------------------------------------------------------------------------------------
# What `tx` needs: the hash and values under the rename target, and the mark

class TestWhatTxNeeds:
	def gen(self, tmp_path, *extra):
		records = tmp_path / 'templates.json'
		records.write_text(json.dumps({'templateHash': 'h1', 'template': 'time=$(HH:mm:ss) user=$ src=$'}) + '\n',
			encoding='utf-8')
		out = generate(tmp_path, 'app', ['--records', str(records), '--reader', 'kv', '--sourcetype', 'tenx_fw',
			'--rename', 'XmlWinEventLog'] + list(extra))
		return read(str(out / 'default' / 'props.conf')), read(str(out / 'default' / 'transforms.conf'))

	def test_the_hash_is_read_under_the_rename_target(self, tmp_path):
		props, transforms = self.gen(tmp_path)
		# a renamed event runs only the target's search-time rules: REPORT-tenx under [tenx_win]
		# gave tenx_hash on 0 of 662 renamed events on Splunk 10.4.3, this on 662 of 662
		assert props.split('[XmlWinEventLog]\n', 1)[1] == 'REPORT-tenx_fm_hash_vars = tenx_fm_hash_vars\n'
		assert '\n[tenx_fm_hash_vars]\nREGEX = ^~(?<tenx_hash>[^,]+)' in transforms

	def test_the_search_time_regex_is_the_apps_with_the_tilde_required(self):
		import configparser
		conf = configparser.RawConfigParser(strict=False, interpolation=None)
		conf.read(os.path.join(os.path.dirname(fm.default_app_props()), 'transforms.conf'))
		app = conf.get('tenx-hash-vars-extraction', 'REGEX')
		assert app.startswith('^~?') and fm.HASH_REGEX == '^~' + app[len('^~?'):]
		rx = re.compile(fm.HASH_REGEX.replace('(?<', '(?P<'))
		assert rx.match('~h1,4625,dc01').groupdict() == {'tenx_hash': 'h1', 'tenx_var_0': '4625', 'tenx_vars': 'dc01'}
		assert rx.match('<Event xmlns="x"><System>') is None

	def test_every_format_writes_the_mark_last(self, tmp_path):
		_, transforms = self.gen(tmp_path)
		formats = [l for l in transforms.splitlines() if l.startswith('FORMAT = ') and 'tenx_compact_st' not in l]
		assert formats and all(f.endswith(' tenx_mapped::"1"') for f in formats)

	def test_every_event_of_the_compact_sourcetype_gets_the_sourcetype_field(self, tmp_path):
		props, transforms = self.gen(tmp_path)
		# first in the list, so it does not depend on any template's transform
		assert 'TRANSFORMS-tenx_fw = tenx_fw_sourcetype, tenx_fw_00000_h1, tenx_fw_ingest_eval\n' in props
		assert '[tenx_fw_sourcetype]\nREGEX = .\nFORMAT = tenx_compact_st::"tenx_fw"\nWRITE_META = true\n' in transforms
		# no mark: an event of a template without a transform, or written whole, gets it too
		assert 'tenx_mapped' not in transforms.split('[tenx_fw_sourcetype]', 1)[1].split('\n[', 1)[0]

	def test_gen_names_the_sourcetype_field_for_tenx_events(self, tmp_path, capsys):
		self.gen(tmp_path)
		out = capsys.readouterr().out
		assert 'index=* (sourcetype::tenx_encoded OR tenx_compact_st::tenx_fw)' in out
		# sourcetype::<compact> is checked against the renamed search-time sourcetype, see the docstring
		assert 'sourcetype::tenx_fw)' not in out
		report = json.loads((tmp_path / 'app_report.json').read_text())
		assert report['sourcetype_field'] == 'tenx_compact_st'

	def test_the_sourcetype_field_can_be_left_out(self, tmp_path, capsys):
		props, transforms = self.gen(tmp_path, '--sourcetype-field', 'none')
		assert 'tenx_compact_st' not in transforms and 'tenx_fw_sourcetype' not in props
		assert 'TRANSFORMS-tenx_fw = tenx_fw_00000_h1, tenx_fw_ingest_eval\n' in props
		assert 'tenx-events' not in capsys.readouterr().out

	def test_the_sourcetype_field_is_not_a_tenx_mapped_field(self):
		# tenx-mapped-hide runs `foreach tenx_mapped*`: a second field of that prefix would run it twice
		assert not fm.SOURCETYPE_FIELD.startswith(fm.MARK_FIELD)

	def test_the_mark_and_the_extraction_can_be_left_out(self, tmp_path):
		props, transforms = self.gen(tmp_path, '--mark', 'none', '--search-hash', 'off')
		assert 'tenx_mapped' not in transforms and '[XmlWinEventLog]' not in props
		assert 'tenx_fm_hash_vars' not in transforms

	def test_the_mark_is_not_a_field_of_the_event(self):
		t = fm.Transform('h1', 's', r'^~ *h1 *,([^,]*),([^,]*)$', 'EventID::"$1" Computer::"$2" tenx_mapped::"1"', 2, 2)
		assert fm.apply_transform(t, '~h1,4625,dc01') == [('EventID', '4625'), ('Computer', 'dc01')]


# -------------------------------------------------------------------------------------------
# The Receiver's compact cap file

class FakeSplunkd(object):
	"""
	A management port in a thread, holding a loaded configuration as Splunk 10.4.3 does: GET
	.../configs/conf-<conf> returns the stanzas of the folder loaded last (none at first), booleans as
	digits; a POST (server/control/restart) loads the folder on disk. Every call is
	recorded with the cap file's text at that moment.
	"""

	def __init__(self, on_disk, app_name, cap_file, loaded=None):
		import http.server
		import threading
		self.on_disk, self.app_name, self.cap_file, self.loaded = on_disk, app_name, cap_file, loaded
		self.calls = []
		outer = self

		class Handler(http.server.BaseHTTPRequestHandler):
			def log_message(self, *a):
				pass

			def _send(self, obj):
				body = json.dumps(obj).encode('utf-8')
				self.send_response(200)
				self.send_header('Content-Type', 'application/json')
				self.send_header('Content-Length', str(len(body)))
				self.end_headers()
				self.wfile.write(body)

			def do_POST(self):
				self.rfile.read(int(self.headers.get('Content-Length') or 0))
				path = self.path.split('?')[0]
				outer.calls.append(('POST', path, read(outer.cap_file)))
				outer.loaded = outer.on_disk
				self._send({})

			def do_GET(self):
				path = self.path.split('?')[0]
				outer.calls.append(('GET', path, None))
				entries = []
				if '/conf-' in path and outer.loaded:
					conf = path.rsplit('/conf-', 1)[1]
					# REST returns a boolean setting as a digit
					entries = [{'name': n, 'content': dict((k, '1' if v == 'true' else v) for k, v in c.items()),
						'acl': {'app': outer.app_name}} for n, c in
						fm.read_conf(os.path.join(outer.loaded, 'default', conf + '.conf')).items()]
				self._send({'entry': entries})

		self.server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
		self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
		threading.Thread(target=self.server.serve_forever, daemon=True).start()

	def posts(self):
		return [c for c in self.calls if c[0] == 'POST']

	def close(self):
		self.server.shutdown()
		self.server.server_close()


class TestCapFile:
	def records(self, tmp_path, hashes):
		p = tmp_path / 'templates.json'
		p.write_text(''.join(json.dumps({'templateHash': h, 'template': 'time=$(HH:mm:ss) user=$ n=%d' % i}) + '\n'
			for i, h in enumerate(hashes)), encoding='utf-8')
		return str(p)

	def gen(self, tmp_path, hashes, cap, *extra):
		return fm.main(['gen', '--records', self.records(tmp_path, hashes), '--reader', 'kv', '--sourcetype',
			'tenx_fw', '--rename', 'fw:traffic', '--out', str(tmp_path / 'fm_fw'), '--cap-file', str(cap)] + list(extra))

	def test_rows_quote_every_hash_keep_outer_spaces_and_sort(self):
		assert fm.cap_text({'b', '#a b ', 'x"y'}, [('c', 'false')]) == \
			'pattern_hash,value\n"#a b ",true\n"b",true\n"c",false\n"x""y",true\n'

	def test_the_engine_reads_the_rows_back(self, tmp_path):
		import csv
		p = tmp_path / 'cap.csv'
		p.write_text(fm.cap_text({'#a b ', 'x"y', ' lead'}), encoding='utf-8')
		with open(str(p), encoding='utf-8', newline='') as f:
			assert sorted(r[0] for r in list(csv.reader(f))[1:]) == [' lead', '#a b ', 'x"y']

	def test_gen_writes_only_the_header_and_a_pending_list(self, tmp_path):
		cap = tmp_path / 'policy' / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1 ', 'k2'], cap) == 0
		assert read(str(cap)) == 'pattern_hash,value\n'
		assert read(str(cap) + '.pending') == 'pattern_hash,value\n"k1 ",true\n"k2",true\n'
		report = json.loads((tmp_path / 'fm_fw_report.json').read_text())
		assert report['compact_cap']['waiting_for_activation'] == 2 and report['compact_cap']['listed_now'] == 0

	def test_gen_drops_templates_without_a_transform_and_never_adds(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		cap.write_text('pattern_hash,value\n"gone",true\n"k1",true\n"keep",false:0:audit\n"k2",false\n',
			encoding='utf-8')
		assert self.gen(tmp_path, ['k1', 'k2', 'k3'], cap) == 0
		# k1 stays, gone is dropped, k3 waits, k2 stays whole because its row says so, keep is kept
		assert read(str(cap)) == 'pattern_hash,value\n"k1",true\n"k2",false\n"keep",false:0:audit\n'
		assert read(str(cap) + '.pending') == \
			'pattern_hash,value\n"k1",true\n"k2",false\n"k3",true\n"keep",false:0:audit\n'

	def test_an_unchanged_list_is_not_rewritten(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		cap.write_text('pattern_hash,value\n"k1",true\n', encoding='utf-8')
		os.utime(str(cap), (1000000000, 1000000000))
		assert fm.write_if_changed(str(cap), 'pattern_hash,value\n"k1",true\n') is False
		assert os.stat(str(cap)).st_mtime == 1000000000
		assert fm.write_if_changed(str(cap), 'pattern_hash,value\n') is True
		assert read(str(cap)) == 'pattern_hash,value\n' and os.listdir(str(tmp_path)) == ['compact-cap.csv']

	def test_a_rewritten_file_keeps_its_mode_and_a_new_one_gets_the_usual_mode(self, tmp_path):
		umask = os.umask(0o022)
		try:
			fresh, old = tmp_path / 'new.conf', tmp_path / 'old.conf'
			old.write_text('a', encoding='utf-8')
			os.chmod(str(old), 0o640)
			fm.write_if_changed(str(fresh), 'x')
			fm.write_if_changed(str(old), 'b')
		finally:
			os.umask(umask)
		assert os.stat(str(fresh)).st_mode & 0o777 == 0o644 and os.stat(str(old)).st_mode & 0o777 == 0o640

	def test_rest_returns_booleans_as_digits(self):
		assert fm._same_setting('WRITE_META', 'true', '1') and fm._same_setting('FORMAT', 'a::"1"', 'a::"1" ')
		assert not fm._same_setting('WRITE_META', 'true', '0') and not fm._same_setting('FORMAT', 'a', 'b')

	def test_kv_rows_give_the_hash_as_written(self, tmp_path):
		p = tmp_path / 'kv.json'
		p.write_text(json.dumps([{'_key': 'h', 'pattern_hash': ' h', 'pattern_parts': ['a=__TENX_TS__ b='],
			'pattern_terminator': '', 'part_0': '', 'timestamp_format': '%H', 'expand_unsafe': ''}]))
		[t] = fm.load_templates(str(p))
		assert t.key == 'h' and t.written_hash == ' h'

	def test_activate_restarts_checks_then_lists(self, tmp_path, monkeypatch):
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1', 'k2'], cap) == 0
		app = str(tmp_path / 'fm_fw')
		fake = FakeSplunkd(app, 'fm_fw', str(cap))
		monkeypatch.setattr(fm.time, 'sleep', lambda s: None)
		try:
			assert fm.activate(app, str(cap), fm.Splunkd(fake.url), out=io.StringIO()) == 0
		finally:
			fake.close()
		# the restart came first, while the cap file still listed nothing; then the check
		assert fake.posts() == [('POST', fm.RESTART_ENDPOINT, 'pattern_hash,value\n')]
		assert [c[1].rsplit('/', 1)[1] for c in fake.calls if c[0] == 'GET'][-2:] == ['conf-transforms', 'conf-props']
		assert read(str(cap)) == 'pattern_hash,value\n"k1",true\n"k2",true\n'
		assert not os.path.exists(str(cap) + '.pending')

	def test_no_restart_when_nothing_is_added(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		cap.write_text('pattern_hash,value\n"gone",true\n"k1",true\n', encoding='utf-8')
		assert self.gen(tmp_path, ['k1'], cap) == 0
		app = str(tmp_path / 'fm_fw')
		fake = FakeSplunkd(app, 'fm_fw', str(cap), loaded=app)
		try:
			assert fm.activate(app, str(cap), fm.Splunkd(fake.url), out=io.StringIO()) == 0
		finally:
			fake.close()
		assert fake.posts() == [] and read(str(cap)) == 'pattern_hash,value\n"k1",true\n'

	def test_activate_leaves_the_list_when_the_instance_does_not_load_the_app(self, tmp_path, monkeypatch):
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1', 'k2'], cap) == 0
		# the instance's folder holds the app of an earlier run, with k1 only
		os.makedirs(str(tmp_path / 'old'))
		assert self.gen(tmp_path / 'old', ['k1'], tmp_path / 'old' / 'cap.csv') == 0
		fake = FakeSplunkd(str(tmp_path / 'old' / 'fm_fw'), 'fm_fw', str(cap))
		monkeypatch.setattr(fm.time, 'sleep', lambda s: None)
		try:
			out = io.StringIO()
			assert fm.activate(str(tmp_path / 'fm_fw'), str(cap), fm.Splunkd(fake.url), out=out) == 1
		finally:
			fake.close()
		assert 'does not hold app fm_fw' in out.getvalue()
		assert read(str(cap)) == 'pattern_hash,value\n'
		assert os.path.exists(str(cap) + '.pending')

	def test_gen_with_splunkd_activates_the_app_it_wrote(self, tmp_path, monkeypatch):
		cap = tmp_path / 'compact-cap.csv'
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		monkeypatch.setenv('TENX_SPLUNKD_AUTH', 'admin:x')
		monkeypatch.setattr(fm.time, 'sleep', lambda s: None)
		try:
			assert self.gen(tmp_path, ['k1'], cap, '--splunkd', fake.url) == 0
		finally:
			fake.close()
		assert fake.posts()[0][2] == 'pattern_hash,value\n'
		assert read(str(cap)) == 'pattern_hash,value\n"k1",true\n'

	def test_without_the_option_nothing_changes(self, tmp_path):
		records = self.records(tmp_path, ['k1'])
		generate(tmp_path, 'a', ['--records', records, '--reader', 'kv', '--sourcetype', 'tenx_fw', '--rename', 'fw:traffic'])
		report = json.loads((tmp_path / 'a_report.json').read_text())
		assert 'compact_cap' not in report and sorted(os.listdir(str(tmp_path))) == ['a', 'a_report.json', 'templates.json']
