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
import gzip
import io
import json
import os
import re
import time
import urllib.parse

import pytest

import tenx_field_map as fm

M = fm.MARK


TPL_CT = '{"eventTime": "$(yyyy-MM-dd\'T\'HH:mm:ss\'Z\')", "eventType": "$", "eventName": "$"}'
TPL_FGT = '<$>date=$$$ time=$(HH:mm:ss) devname="$" type="traffic"'


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

class TestDelimsReader:
	def test_pairs_split_on_space_and_comma_outside_quotes(self):
		r = fm.DelimsReader()
		assert r.pairs('date=2026-11-13 time=10:00:00 msg="a b, c" x=1,y=2 user=""') == [
			('date', '2026-11-13'), ('time', '10:00:00'), ('msg', 'a b, c'), ('x', '1'), ('y', '2'), ('user', '')]

	def test_a_syslog_priority_before_the_first_key_is_not_part_of_its_name(self):
		# Splunk Enterprise 10.4.3, DELIMS with KV_MODE = none: "<190>date=..." gave date on 62 of 62 events.
		r = fm.DelimsReader()
		assert r.pairs('<190>date=2026-11-13 devname="fw"') == [('date', '2026-11-13'), ('devname', 'fw')]
		assert r.pairs('<' + M % 0 + '>date=' + M % 1) == [('date', M % 1)]

	def test_other_characters_of_a_name_become_underscores_and_markers_stay(self):
		r = fm.DelimsReader()
		assert r.pairs('a-b=1 dev' + M % 2 + 'x=' + M % 3) == [('a_b', '1'), ('dev' + M % 2 + 'x', M % 3)]

	def test_the_first_value_of_a_key_is_kept(self):
		# The same Splunk: tz="UTC-5:00" ... tz=-0500 gave tz "UTC-5:00".
		assert fm.DelimsReader().pairs('tz="UTC-5:00" n=1 tz=-0500') == [('tz', 'UTC-5:00'), ('n', '1')]

	def test_gen_takes_the_reader(self, tmp_path):
		records = tmp_path / 'templates.json'
		records.write_text(json.dumps({'templateHash': 'k1', 'template': TPL_FGT}) + '\n')
		assert fm.main(['gen', '--rules', 'lookup', '--records', str(records), '--reader', 'delims', '--sourcetype', 'tenx_fgt',
			'--rename', 'fortigate_traffic', '--out', str(tmp_path / 'fm')]) == 0
		row = fm.read_lookup_file(str(tmp_path / 'fm' / 'lookups' / 'tenx_fgt_fields.csv.gz'))['k1']['f']
		assert row.startswith('date::"') and ' devname::"' in row and ' type::"traffic"' in row


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

	def test_reserved_names_restored_at_search_time(self, tmp_path):
		# Splunk Enterprise 10.4.3 returned the indexed field eventType of 14,791 mapped CloudTrail events
		# as extracted_eventType, and the AWS add-on's FIELDALIAS eventType AS app found nothing.
		records = tmp_path / 'templates.json'
		records.write_text(json.dumps({'templateHash': 'k1', 'template': TPL_CT}) + '\n', encoding='utf-8')
		out = tmp_path / 'fm_ct'
		assert fm.main(['gen', '--rules', 'lookup', '--records', str(records), '--reader', 'json', '--sourcetype', 'tenx_ct',
			'--rename', 'aws:cloudtrail', '--reserved-names', 'restore', '--out', str(out)]) == 0
		props = (out / 'default' / 'props.conf').read_text()
		assert props.endswith('[aws:cloudtrail]\nREPORT-tenx_fm_hash_vars = tenx_fm_hash_vars\n'
			'# Search-time: each name Splunk does not keep for an indexed field, given back from extracted_<name>.\n'
			'REPORT-tenx_fm_restore = tenx_fm_restore_eventType\n')
		transforms = (out / 'default' / 'transforms.conf').read_text()
		assert ('[tenx_fm_restore_eventType]\nSOURCE_KEY = extracted_eventType\nREGEX = ^([\\s\\S]*)$\n'
			'FORMAT = eventType::$1\n') in transforms
		rows = fm.read_lookup_file(str(out / 'lookups' / 'tenx_ct_fields.csv.gz'))
		assert 'extracted_eventType::' in rows['k1']['f'] and ' eventType::' not in rows['k1']['f']
		report = json.loads((tmp_path / 'fm_ct_report.json').read_text())
		assert report['reserved_field_names']['action'] == 'written as extracted_<name>, given back as <name> at search time'

	def test_reserved_names_restore_without_the_search_hash(self):
		t = tpl('h', ['time=__TENX_TS__ eventType='], '')
		f = fm.FieldMap({'h': t}, fm.KeyValueReader(), 'p', reserved_names='restore', reserved_prefix='x_')
		assert f.transforms[0].format == 'time::"$1" x_eventType::"$2"'
		target = {'sourcetype': 'tenx_p', 'rename': 'p:st', 'transforms_class': 'p', 'transform_prefix': 'p', 'description': 'd'}
		props = fm.props_text(target, f, [], search_hash=False)
		assert props.endswith('[p:st]\n# Search-time: each name Splunk does not keep for an indexed field, given back from '
			'x_<name>.\nREPORT-tenx_fm_restore = tenx_fm_restore_eventType\n')
		assert 'SOURCE_KEY = x_eventType' in fm.transforms_text(f, search_hash=False, target=target, sourcetype_field=None)

	def test_no_restore_stanza_when_nothing_collides(self):
		t = tpl('h', ['time=__TENX_TS__ user='], '')
		f = fm.FieldMap({'h': t}, fm.KeyValueReader(), 'p', reserved_names='restore')
		target = {'sourcetype': 'tenx_p', 'rename': 'p:st', 'transforms_class': 'p', 'transform_prefix': 'p', 'description': 'd'}
		assert 'restore' not in fm.props_text(target, f, []) and 'restore' not in fm.transforms_text(f, target=target)

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
			('ADD_EXTRA_TIME_FIELDS', 'subseconds'), ('TRANSFORMS-tenx_time', 'tenx-event-time')]
		assert sorted(not_copied) == ['REPORT-tenx', 'category', 'disabled', 'pulldown_type']

	def test_gen_says_where_the_floor_app_goes(self, tmp_path, capsys):
		records = tmp_path / 'templates.json'
		records.write_text(json.dumps({'templateHash': 'k1', 'template': 'time=$(HH:mm:ss) user=$ src=$'}) + '\n')
		assert fm.main(['gen', '--rules', 'lookup', '--records', str(records), '--reader', 'kv', '--sourcetype', 'tenx_fw',
			'--rename', 'fw:traffic', '--out', str(tmp_path / 'app')]) == 0
		out = capsys.readouterr().out
		assert 'floor app: %s; install it on every instance that parses the compact events\n' % (tmp_path / 'app_floor') in out

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

	def test_gen_says_a_kv_export_that_failed_holds_no_templates(self, tmp_path, capsys):
		# curl -u admin in a script: no password, and Splunk's answer is written as the export.
		records = tmp_path / 'kv_0.json'
		records.write_text('{"messages":[{"type":"ERROR","text":"Unauthorized"}]}')
		assert fm.main(['gen', '--rules', 'lookup', '--records', str(records), '--target', 'windows-security',
			'--out', str(tmp_path / 'app')]) == 2
		err = capsys.readouterr().err
		assert 'holds no template records: Splunk answered "Unauthorized"' in err and 'KeyError' not in err
		assert not os.path.exists(str(tmp_path / 'app'))

	def test_gen_names_a_line_that_is_not_a_template_record(self, tmp_path, capsys):
		records = tmp_path / 'templates.json'
		records.write_text(json.dumps({'templateHash': 'k1', 'template': 'a=$'}) + '\n' + json.dumps({'x': 1}) + '\n')
		assert fm.main(['gen', '--rules', 'lookup', '--records', str(records), '--reader', 'kv', '--sourcetype', 'tenx_fw',
			'--rename', 'fw:traffic', '--out', str(tmp_path / 'app')]) == 2
		assert 'line 2 is not a template record' in capsys.readouterr().err

	def test_gen_says_so_when_no_template_gets_a_rule(self, tmp_path, capsys):
		# Records the Windows reader finds no field in: gen still writes the app and exits 0, and says so.
		records = tmp_path / 'templates.json'
		records.write_text(json.dumps({'templateHash': 'k1', 'template': 'time=$(HH:mm:ss) user=$ src=$'}) + '\n')
		assert fm.main(['gen', '--rules', 'lookup', '--records', str(records), '--target', 'windows-security',
			'--out', str(tmp_path / 'app')]) == 0
		err = capsys.readouterr().err
		assert 'none of the 1 templates read got a rule (the reader found no field: 1)' in err
		assert 'Check that --target or --reader matches these records.' in err

	def test_gen_is_quiet_when_templates_get_rules(self, tmp_path, capsys):
		records = tmp_path / 'templates.json'
		records.write_text(json.dumps({'templateHash': 'k1', 'template': 'time=$(HH:mm:ss) user=$ src=$'}) + '\n')
		assert fm.main(['gen', '--rules', 'lookup', '--records', str(records), '--reader', 'kv', '--sourcetype', 'tenx_fw',
			'--rename', 'fw:traffic', '--out', str(tmp_path / 'app')]) == 0
		assert 'got a rule' not in capsys.readouterr().err

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


def as_first_files(text):
	# ADD_EXTRA_TIME_FIELDS is copied from [tenx_encoded], which set it after the first files were made.
	return ''.join(l for l in text.splitlines(True) if not l.startswith('ADD_EXTRA_TIME_FIELDS ='))


@needs_samples
class TestGoldenWindows:
	def test_662_event_sample_equals_the_first_files(self, tmp_path):
		out = generate(tmp_path, 'b2', ['--records', sample('data', 'b2_kv_rows.json'), '--target', 'windows-security',
			'--stanza-names', 'hash', '--hash-match', 'exact', '--trim-values', 'off'] + FIRST_FILES)
		assert as_first_files(read(str(out / 'default' / 'props.conf'))) == read(sample('conf', 'b2', 'props.conf'))
		assert read(str(out / 'default' / 'transforms.conf')).split('\n', 1)[1] == \
			read(sample('conf', 'b2', 'transforms.conf')).split('\n', 1)[1]
		golden = json.load(open(sample('conf', 'b2', 'gen_report.json')))
		report = json.load(open(str(tmp_path / 'b2_report.json')))
		assert {k: report[k] for k in golden} == golden

	def test_4663_sample_equals_the_first_files(self, tmp_path):
		out = generate(tmp_path, 'b2_4663', ['--records', sample('data', 'b2_kv_rows_all.json'),
			'--only-hashes-in', sample(*T4663 + ('templates.json',)), '--target', 'windows-security',
			'--sourcetype', 'tenx_win4663'] + FIRST_FILES)
		assert as_first_files(read(str(out / 'default' / 'props.conf'))) == read(sample('conf', 'b2_4663', 'props.conf'))
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

	def test_verify_lookup_rules_every_field_of_both_samples(self):
		# the lookup recipe writes what FORMAT cannot (quotes, line breaks, timestamps as written)
		for argv, n in ((self.V662, 662), (self.V4663, 7649)):
			result, f = run_verify(argv + ['--rules', 'lookup'])
			assert result['compact_lines'] == result['expanded_equal_raw'] == result['events_all_fields_equal'] == n
			assert result['transform_regex_did_not_match'] == 0 and f.skipped == {} and f.forms == {}

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
# --rules lookup: one static rule, one lookup row per template

class TestLookupRules:
	def records(self, tmp_path, items, name='templates.json'):
		p = tmp_path / name
		p.write_text(''.join(json.dumps({'templateHash': h, 'template': t}) + '\n' for h, t in items), encoding='utf-8')
		return str(p)

	def gen(self, tmp_path, items, out='fm_fw', *extra):
		rc = fm.main(['gen', '--rules', 'lookup', '--records', self.records(tmp_path, items, out + '.json'), '--reader', 'kv',
			'--sourcetype', 'tenx_fw', '--rename', 'fw:traffic', '--out', str(tmp_path / out)] + list(extra))
		return rc, tmp_path / out

	def test_adding_a_template_changes_only_the_lookup_file(self, tmp_path):
		one = [('k1', 'time=$(HH:mm:ss) user=$ n=1')]
		_, a = self.gen(tmp_path, one, 'a')
		_, b = self.gen(tmp_path, one + [('k2', 'user=$ src=$ msg="a b"')], 'b')
		for rel in ('default/props.conf', 'default/transforms.conf', 'default/fields.conf', 'default/app.conf'):
			if os.path.exists(str(a / rel)):
				assert read(str(a / rel)) == read(str(b / rel)), rel
		la, lb = (fm.read_lookup_file(str(x / 'lookups' / 'tenx_fw_fields.csv.gz')) for x in (a, b))
		assert sorted(la) == ['k1'] and sorted(lb) == ['k1', 'k2'] and la['k1'] == lb['k1']
		props = read(str(a / 'default' / 'props.conf'))
		assert 'TRANSFORMS-tenx_fw = tenx_fw_sourcetype, tenx_fw_fields_eval\n' in props
		transforms = read(str(a / 'default' / 'transforms.conf'))
		assert '[tenx_fw_fields]\nfilename = tenx_fw_fields.csv.gz\ncase_sensitive_match = true\n' in transforms

	def test_the_lookup_file_is_the_same_bytes_for_the_same_rows(self, tmp_path):
		items = [('k2', 'user=$'), ('k1', 'user=$ n=1')]
		_, a = self.gen(tmp_path, items, 'a')
		_, b = self.gen(tmp_path, list(reversed(items)), 'b')
		pa, pb = (str(x / 'lookups' / 'tenx_fw_fields.csv.gz') for x in (a, b))
		assert open(pa, 'rb').read() == open(pb, 'rb').read()
		import gzip
		text = gzip.open(pa, 'rt').read()
		assert text.splitlines()[0] == 'hash,n,e,t,f' and [l.split(',')[0] for l in text.splitlines()[1:]] == ['k1', 'k2']

	def test_a_lookup_file_over_the_limit_is_not_written(self, tmp_path, capsys):
		rc, out = self.gen(tmp_path, [('k1', 'user=$')], 'fm_fw', '--lookup-max-bytes', '10')
		assert rc == 2 and 'over --lookup-max-bytes' in capsys.readouterr().err and not os.path.exists(str(out))

	def test_the_rule_looks_up_compact_events_only(self):
		text = fm.lookup_eval_text('tenx_fw_fields')
		assert text.startswith('$pd:tenx_fm_row$=if(substr(_raw, 1, 1)=="~", lookup("tenx_fw_fields", ')
		# every intermediate value is a pd: key; only _meta is written
		assert [e.split('=', 1)[0] for e in re.split(r', (?=\$pd:tenx_fm_\w+\$=|_meta=)', text)] == \
			['$pd:tenx_fm_%s$' % k for k in ('row', 'f', 't', 'n', 'ok', 'e', 'x', 'm')] + ['_meta'] + \
			['$pd:tenx_fm_why$'] * 2 + ['_meta']

	def test_the_rule_builds_a_regex_only_from_a_row_it_can_use(self):
		text = fm.lookup_eval_text('tenx_fw_fields')
		# a recipe of name::value pairs and a value count of at most 984 in digits; anything else is bad_row
		assert '$pd:tenx_fm_ok$=if(isnotnull($pd:tenx_fm_f$) AND isnotnull($pd:tenx_fm_n$), if(match($pd:tenx_fm_f$, "::") ' \
			'AND match($pd:tenx_fm_n$, "^[0-9]{1,3}$"), if(tonumber($pd:tenx_fm_n$) <= 984, 1, 0), 0), 0)' in text
		assert '$pd:tenx_fm_x$=if($pd:tenx_fm_ok$ == 1, _raw . ' in text
		assert 'tonumber(json_extract(' not in text

	def test_a_compact_event_without_fields_gets_the_reason(self):
		text = fm.lookup_eval_text('tenx_fw_fields')
		assert '$pd:tenx_fm_why$=case(substr(_raw, 1, 1)!="~", null(), isnull($pd:tenx_fm_f$) AND isnull($pd:tenx_fm_n$), ' \
			'"no_row", $pd:tenx_fm_ok$ != 1, "bad_row", isnull($pd:tenx_fm_m$) OR $pd:tenx_fm_m$==$pd:tenx_fm_x$, "no_match")' in text
		# the floor copy holds only FLOOR_HASH: finding it means the template rows were not read
		assert 'lookup("tenx_fw_fields", json_object("hash", "tenx-fm-floor"), json_array("n"))' in text
		assert text.endswith('_meta=if(isnull($pd:tenx_fm_why$), _meta, coalesce(_meta, "") . " tenx_unmapped::" . '
			'$pd:tenx_fm_why$)')

	def test_the_fields_reach_an_event_that_has_no_indexed_field_yet(self):
		# _meta is null on an HEC event without "fields" when no earlier rule wrote one (Splunk 10.4.3:
		# without coalesce(), 0 of 2 such events got their fields; with it, 2 of 2)
		text = fm.lookup_eval_text('tenx_fw_fields')
		assert '_meta=if(isnull($pd:tenx_fm_m$) OR $pd:tenx_fm_m$==$pd:tenx_fm_x$, _meta, coalesce(_meta, "") . " " . ' \
			'$pd:tenx_fm_m$)' in text
		assert ' _meta . ' not in text.replace('coalesce(_meta, "") . ', '')

	def test_the_floor_app_holds_the_definition_and_one_row(self, tmp_path):
		_, a = self.gen(tmp_path, [('k1', 'user=$ n=1')], 'fm_fw')
		floor = tmp_path / 'fm_fw_floor'
		assert sorted(['fm_fw', 'fm_fw_floor'])[0] == 'fm_fw'
		app_def = fm.read_conf(str(a / 'default' / 'transforms.conf'))['tenx_fw_fields']
		assert fm.read_conf(str(floor / 'default' / 'transforms.conf')) == {'tenx_fw_fields': app_def}
		assert fm.read_lookup_file(str(floor / 'lookups' / 'tenx_fw_fields.csv.gz')) == {
			fm.FLOOR_HASH: {'hash': fm.FLOOR_HASH, 'n': '0', 'e': '0', 't': '', 'f': ''}}
		assert read(str(floor / 'metadata' / 'default.meta')) == '[]\nexport = system\n'
		assert sorted(os.listdir(str(floor))) == ['default', 'lookups', 'metadata']

	def test_the_floor_app_does_not_change_when_templates_are_added(self, tmp_path):
		self.gen(tmp_path, [('k1', 'user=$ n=1')], 'fm_fw')
		floor = tmp_path / 'fm_fw_floor'
		files = [str(floor / rel) for rel in ('lookups/tenx_fw_fields.csv.gz', 'default/transforms.conf', 'default/app.conf',
			'metadata/default.meta')]
		for f in files:
			os.utime(f, (1000000000, 1000000000))
		before = [open(f, 'rb').read() for f in files]
		self.gen(tmp_path, [('k1', 'user=$ n=1'), ('k2', 'src=$')], 'fm_fw')
		assert [open(f, 'rb').read() for f in files] == before
		assert all(os.stat(f).st_mtime == 1000000000 for f in files)

	def test_the_app_ships_an_unscheduled_search_for_events_without_fields(self):
		conf = fm.read_conf(os.path.join(os.path.dirname(fm.default_app_props()), 'savedsearches.conf'))
		ss = conf['Field Map Events Without Fields']
		assert ss['enableSched'] == '0' and ss['counttype'] == 'number of events' and ss['relation'] == 'greater than'
		assert ss['search'].startswith('| tstats count where index=* %s=* NOT host=%s _index_earliest=-15m _index_latest=now '
			'by index sourcetype %s' % (fm.UNMAPPED_FIELD, fm.PROBE_HOST, fm.UNMAPPED_FIELD))
		assert '"processor=regexreplacement" "Runtime exception"' in ss['search'] and ss['search'].endswith('| where count > 0')

	def test_the_search_for_events_without_fields_selects_by_index_time(self):
		# A compact event keeps its original date: an event dated a day ago and indexed now must count, so the
		# 15 minutes are index time and the dispatch range is every event date.
		conf = fm.read_conf(os.path.join(os.path.dirname(fm.default_app_props()), 'savedsearches.conf'))
		ss = conf['Field Map Events Without Fields']
		assert ss['dispatch.earliest_time'] == '0' and ss['dispatch.latest_time'] == '+10y'
		tstats, internal = ss['search'].split('| append [', 1)
		assert '_index_earliest=-15m _index_latest=now' in tstats
		# splunkd.log lines are dated when they are written, so that part keeps its own 15 minutes of event time.
		assert internal.startswith('search index=_internal earliest=-15m latest=now ')

	def test_no_floor_app_with_floor_off_or_per_template_transforms(self, tmp_path):
		self.gen(tmp_path, [('k1', 'user=$')], 'fm_fw', '--floor', 'off')
		generate(tmp_path, 'fm_tr', ['--records', self.records(tmp_path, [('k1', 'user=$')]), '--reader', 'kv',
			'--sourcetype', 'tenx_fw', '--rename', 'fw:traffic'])
		assert not os.path.exists(str(tmp_path / 'fm_fw_floor')) and not os.path.exists(str(tmp_path / 'fm_tr_floor'))

	def test_the_rule_cuts_its_regex_from_a_constant_without_escapes(self):
		# an escape would change the constant's length once SPL reads the string
		assert '\\' not in fm.LOOKUP_VALUE_GROUP and '"' not in fm.LOOKUP_VALUE_GROUP
		text = fm.lookup_eval_text('t')
		assert 'substr("%s", 1, %d * ' % (fm.LOOKUP_VALUE_GROUP * fm.LOOKUP_MAX_VALUES, len(fm.LOOKUP_VALUE_GROUP)) in text
		spl = re.search(r'"(\^~\[\^,\[:cntrl:\]\]\*)" \. replace\(substr', text).group(1)
		assert 'replace(substr("%s", 1, %d * tonumber($pd:tenx_fm_n$)), "%s", urldecode("%%0D"))' % (
			fm.LOOKUP_VALUE_GROUP * fm.LOOKUP_MAX_VALUES, len(fm.LOOKUP_VALUE_GROUP), fm.LOOKUP_CR) in text
		tail = re.search(r'"\[\|\]\(\[\^\|\[:cntrl:\]\]\*\)\[\|\]((?:\(\[\^\|\]\))+)\$"', text).group(1)
		for n in (0, 1, 5):
			regex = spl + fm.LOOKUP_VALUE_GROUP * n + (',?' if n == 0 else '') + '[|]([^|[:cntrl:]]*)[|]' + tail + '$'
			assert regex.replace('[:cntrl:]', '\\x00-\\x1f\\x7f').replace(fm.LOOKUP_CR, '\\r') == fm.lookup_line_regex(n)

	def test_replace_reads_references_as_measured(self):
		groups = ['ab', 'a', 'b']
		assert fm.splunk_replace_expand('\\2\\1', groups) == 'ba'
		assert fm.splunk_replace_expand('\\12', groups) == '\\12'
		assert fm.splunk_replace_expand('x\\\\y', groups) == 'x\\\\y'
		assert fm.splunk_replace_expand('\\U\\1$2&', groups) == '\\Ua$2&'
		assert fm.splunk_replace_expand('\\0', groups) == 'ab'

	def test_the_recipe_writes_backslashes_tabs_and_digits_after_a_value_by_reference(self):
		n = 2
		bs, tab, d4 = n + 2 + fm.LOOKUP_TAIL.index('\\'), n + 2 + fm.LOOKUP_TAIL.index('\t'), n + 2 + 4
		assert fm.recipe_text([('text', 'C:\\x'), ('group', 1), ('text', '42a\t9')], n) == \
			'C:\\%dx\\1\\%d\\%da\\%d\\%d' % (bs, d4, n + 2 + 2, tab, n + 2 + 9)
		assert fm.meta_escape('a"b\\c') == 'a\\"b\\\\c'

	def test_the_timestamp_as_written_and_the_value_count(self, tmp_path):
		self.gen(tmp_path, [('k1', 'time=$(HH:mm:ss) user=$ n=7')])
		args = fm.build_parser().parse_args(['verify', '--rules', 'lookup', '--records', str(tmp_path / 'fm_fw.json'),
			'--reader', 'kv', '--sourcetype', 'tenx_fw', '--rename', 'fw:traffic', '--encoded', '/dev/null', '--raw', '/dev/null'])
		_, _, field_map = fm._build(args)
		[t] = field_map.transforms
		assert (t.value_count, t.epoch, t.ts_format) == (2, True, '%H:%M:%S')
		assert fm.apply_lookup_row(t, '~k1,1700000000123000000,root') == [('time', '22:13:20'), ('user', 'root'), ('n', '7')]
		assert fm.apply_lookup_row(t, '~k1,1700000000123000000') is None

	def test_a_line_of_two_lines_gets_no_fields(self):
		t = fm.Transform('k', 's', '', '', 1, 1, (), 'user::"\\1" tenx_mapped::"1"', '', False)
		assert fm.apply_lookup_row(t, '~k,root') == [('user', 'root')]
		assert fm.apply_lookup_row(t, '~k,root\n~k,admin') is None

	def crlf_windows(self):
		"""A Windows template as the engine writes it from CR LF text: the carriage return of each line end
		stays in the value before it, the line feed is template text."""
		reader = fm.XmlWindowsReader()
		tpl = fm.Template(key='h', written_hash=' h', parts=["</EventID></System><EventData><Data Name='AccessList'>%%",
			"\n\t\t\t\t</Data><Data Name='PrivilegeList'>", "\n\t\t"], part_0="<Event><System><EventID>",
			terminator="</Data></EventData></Event>", timestamp_format='', expand_unsafe='', pattern=None)
		field_map = fm.FieldMap({'h': tpl}, reader, 'p', rules=fm.RULES_LOOKUP, mark=fm.MARK_FIELD)
		[t] = field_map.transforms
		raw = ("<Event><System><EventID>4663</EventID></System><EventData><Data Name='AccessList'>%%1538\r\n\t\t\t\t"
			"</Data><Data Name='PrivilegeList'>SeA\r\n\t\tSeB</Data></EventData></Event>")
		want = dict((n, v.strip(field_map.trim_chars)) for n, v in reader.pairs(raw))
		return field_map, t, want

	def test_a_value_may_end_with_the_carriage_return_of_a_cr_lf_line_end(self):
		field_map, t, want = self.crlf_windows()
		assert field_map.trim_values and want == {'EventID': '4663', 'AccessList': '%%1538', 'PrivilegeList': 'SeA\r\n\t\tSeB'}
		got = dict(fm.apply_lookup_row(t, '~ h ,4663,1538\r,SeA\r,SeB', trim=True))
		# trimmed at the end of a field, as the add-on trims; kept inside one
		assert got == want
		assert dict(fm.apply_lookup_row(t, '~ h ,4663,1538\r,SeA\r,SeB'))['AccessList'] == '%%1538\r'
		# the same line from text without carriage returns gives the same fields
		assert dict(fm.apply_lookup_row(t, '~ h ,4663,1538,SeA,SeB', trim=True)) == dict(want, PrivilegeList='SeA\n\t\tSeB')

	def test_verify_reads_cr_lf_data(self, tmp_path):
		field_map, t, _ = self.crlf_windows()
		enc, raw = tmp_path / 'encoded.log', tmp_path / 'raw.log'
		enc.write_bytes('~ h ,4663,1538\r,SeA\r,SeB\n'.encode('utf-8'))
		raw.write_bytes(("<Event xmlns='x'><System><EventID>4663</EventID></System><EventData><Data Name='AccessList'>%%1538\r\n"
			"\t\t\t\t</Data><Data Name='PrivilegeList'>SeA\r\n\t\tSeB</Data></EventData></Event>\r\n").encode('utf-8'))
		templates = {'h': fm.Template(key='h', written_hash=' h', parts=["</EventID></System><EventData><Data Name='AccessList'>%%",
			"\n\t\t\t\t</Data><Data Name='PrivilegeList'>", "\n\t\t"], part_0="<Event xmlns='x'><System><EventID>",
			terminator="</Data></EventData></Event>", timestamp_format='', expand_unsafe='', pattern=None)}
		field_map = fm.FieldMap(templates, fm.XmlWindowsReader(), 'p', rules=fm.RULES_LOOKUP, mark=fm.MARK_FIELD)
		result = fm.verify(templates, field_map, str(enc), str(raw), out=io.StringIO())
		assert result['expanded_equal_raw'] == 1 and result['transform_regex_did_not_match'] == 0
		assert result['events_all_fields_equal'] == 1

	def test_a_line_feed_in_a_value_still_gets_no_fields(self):
		_, t, _ = self.crlf_windows()
		assert fm.apply_lookup_row(t, '~ h ,4663,1538\n,SeA,SeB', trim=True) is None
		assert fm.apply_lookup_row(t, '~ h ,4663,1538,SeA\r\n~ h ,4663', trim=True) is None

	def test_the_rule_trims_field_ends_only_for_a_reader_that_trims(self, tmp_path):
		xml = fm.lookup_eval_text('t', None, True)
		assert 'replace(replace($pd:tenx_fm_m$, "::" . urldecode("%22") . "[[:space:]]+", "::" . urldecode("%22")), ' \
			'"[[:space:]]+" . urldecode("%22"), urldecode("%22"))' in xml
		assert '_meta=if(isnull($pd:tenx_fm_m$) OR $pd:tenx_fm_m$==$pd:tenx_fm_x$, _meta, coalesce(_meta, "") . " " . ' \
			'$pd:tenx_fm_mt$)' in xml
		plain = fm.lookup_eval_text('t')
		assert '$pd:tenx_fm_mt$' not in plain and '[[:space:]]' not in plain
		# value 0, the timestamp, is read whatever line ends the text holds
		assert 'replace(_raw, "(?s)^~[^,]*,([^,|]*).*$", "\\1")' in plain

	def test_quotes_backslashes_and_line_breaks_in_template_text(self):
		reader = fm.XmlWindowsReader()
		tpl = fm.Template(key='h', written_hash=' h', parts=[], part_0="<Event><System><EventID>",
			terminator="</EventID></System><EventData><Data Name='CommandLine'>\"C:\\Program Files\\a.exe\" -n 3"
			"</Data><Data Name='PrivilegeList'>SeA\n\t\tSeB</Data></EventData></Event>", timestamp_format='',
			expand_unsafe='', pattern=None)
		field_map = fm.FieldMap({'h': tpl}, reader, 'p', rules=fm.RULES_LOOKUP, mark=fm.MARK_FIELD)
		[t] = field_map.transforms
		pairs = dict(fm.apply_lookup_row(t, '~ h ,4688'))
		assert pairs['EventID'] == '4688' and pairs['CommandLine'] == '"C:\\Program Files\\a.exe" -n 3'
		assert pairs['PrivilegeList'] == 'SeA\n\t\tSeB'
		assert '\t' not in t.recipe and '\n' not in t.recipe and field_map.skipped == {}


# -------------------------------------------------------------------------------------------
# The Receiver's compact cap file

class FakeSplunkd(object):
	"""
	A management port in a thread that behaves as Splunk 10.4.3 was measured to: GET
	.../configs/conf-<conf> returns the stanzas of the app folder it holds (booleans as digits);
	receivers/simple indexes each line as an event of the probe stream, with tenx_mapped when the
	line's hash has a row in the lookup file as last read (refresh() rereads it from the folder, as
	Splunk does every ingest_lookup_refresh_period_secs); search/jobs (oneshot) answers activate's probe
	search from those events, indexed at or after its _index_earliest. Every call is recorded with the
	cap file's text at that moment. now gives each event its index time (a test can give it the clock it
	gives activate); schedule holds (time, function) pairs, each run once at the first request at or after
	its time; limits, when set, is what GET configs/conf-limits/lookup returns.
	"""

	def __init__(self, on_disk, app_name, cap_file, loaded=True):
		import http.server
		import threading
		import urllib.parse as up
		self.on_disk, self.app_name, self.cap_file = on_disk, app_name, cap_file
		self.calls, self.events, self.rows = [], [], set()
		# drop: probe events are not indexed (a lookup that throws); floor: the instance holds the floor app
		self.drop, self.floor = False, True
		# hec_unmapped: events sent through HEC are parsed where the app is not installed (no fields)
		self.hec_unmapped = False
		# splunkd.log lines of events Splunk dropped: (node, sourcetype, index time); internal: whether _internal is readable
		self.dropped, self.internal = [], True
		self.now, self.schedule, self.limits = time.time, [], None
		self.loaded = on_disk if loaded else None
		if loaded:
			self.refresh()
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
				outer.run_schedule()
				data = self.rfile.read(int(self.headers.get('Content-Length') or 0)).decode('utf-8')
				path, _, query = self.path.partition('?')
				outer.calls.append(('POST', path, read(outer.cap_file) if os.path.exists(outer.cap_file) else None))
				if path == '/services/collector/event':
					for line in data.splitlines():
						e = json.loads(line)
						h = e['event'][1:].split(',', 1)[0].strip()
						if not outer.drop:
							outer.events.append(dict(index=e['index'], host=e['host'], source=e['source'], sourcetype=e['sourcetype'],
								raw=e['event'], hash=h, mapped=h in outer.rows and not outer.hec_unmapped, t=outer.now(), via='hec',
								node=e.get('fields', {}).get(fm.PROBE_NODE_FIELD, '')))
					self._send({'text': 'Success', 'code': 0})
				elif path == '/services/receivers/simple':
					q = dict(up.parse_qsl(query))
					for line in data.splitlines():
						if outer.drop:
							continue
						h = line[1:].split(',', 1)[0].strip()
						outer.events.append(dict(q, raw=line, hash=h, mapped=h in outer.rows, t=outer.now()))
					self._send({})
				elif path == '/services/search/jobs' and 'index=_internal' in dict(up.parse_qsl(data))['search']:
					m = dict(up.parse_qsl(data))
					if m['search'].startswith('| tstats'):
						self._send({'results': [{'count': '42'}] if outer.internal else []})
					else:
						st = re.search(r'where tenx_fm_st="([^"]*)"', m['search']).group(1)
						lo = int(re.search(r'_index_earliest=(-?\d+)', m['search']).group(1))
						hi = int(re.search(r'_index_latest=(-?\d+)', m['search']).group(1))
						by = {}
						for node, dst, t in outer.dropped:
							if dst == st and lo <= t < hi:
								c, a, b = by.get(node, (0, t, t))
								by[node] = (c + 1, min(a, t), max(b, t))
						self._send({'results': [{'host': n, 'count': str(c), 'first': str(a), 'last': str(b)}
							for n, (c, a, b) in sorted(by.items())]})
				elif path == '/services/search/jobs' and dict(up.parse_qsl(data))['search'].startswith('| tstats'):
					# check's count of the map's compact events indexed without their fields (not probes)
					m = dict(up.parse_qsl(data))
					st = re.search(r'sourcetype="([^"]*)"', m['search']).group(1)
					lo = int(re.search(r'_index_earliest=(-?\d+)', m['search']).group(1))
					hi = int(re.search(r'_index_latest=(-?\d+)', m['search']).group(1))
					counts = {}
					for e in outer.events:
						if e.get('host') != fm.PROBE_HOST and e.get('sourcetype') == st and not e['mapped'] and lo <= e['t'] < hi:
							counts[e.get('why', fm.WHY_NO_ROW)] = counts.get(e.get('why', fm.WHY_NO_ROW), 0) + 1
					self._send({'results': [{fm.UNMAPPED_FIELD: k, 'count': str(v)} for k, v in sorted(counts.items())]})
				elif path == '/services/search/jobs':
					m = dict(up.parse_qsl(data))
					assert m['exec_mode'] == 'oneshot' and 'host="%s"' % fm.PROBE_HOST in m['search']
					since = int(re.search(r'_index_earliest=(-?\d+)', m['search']).group(1))
					res, why = {}, {}
					# per node when the search groups by the probe's node field, as activate does with several endpoints
					per_node = 'tenx_fm_probe_n' in m['search']
					for e in outer.events:
						if e['host'] == fm.PROBE_HOST and e['source'] == fm.PROBE_SOURCE and e['t'] >= since:
							k = (e['hash'], e.get('node', '')) if per_node else e['hash']
							res[k] = max(res.get(k, 0), int(e['mapped']))
							if not e['mapped']:
								why.setdefault(k, set()).add(fm.WHY_NO_ROW)
					def key(k):
						return {'tenx_fm_probe_h': k[0], 'tenx_fm_probe_n': k[1]} if per_node else {'tenx_fm_probe_h': k}
					self._send({'results': [dict(key(k), m=str(v), **({'w': sorted(why[k])} if k in why else {}))
						for k, v in res.items()]})
				else:
					self._send({})

			def do_GET(self):
				outer.run_schedule()
				path = self.path.split('?')[0]
				outer.calls.append(('GET', path, None))
				entries = []
				if path == '/services/configs/conf-limits/lookup':
					if outer.limits is not None:
						entries = [{'name': 'lookup', 'content': outer.limits}]
				elif '/conf-' in path and outer.loaded:
					conf = path.rsplit('/conf-', 1)[1]
					app = up.unquote(path.split('/servicesNS/nobody/', 1)[1].split('/', 1)[0])
					folder = outer.loaded if app == outer.app_name else (fm.floor_dir(outer.loaded)
						if app == outer.app_name + fm.FLOOR_SUFFIX and outer.floor else None)
					if folder:
						entries = [{'name': n, 'content': dict((k, '1' if v == 'true' else v) for k, v in c.items()),
							'acl': {'app': app}} for n, c in fm.read_conf(os.path.join(folder, 'default', conf + '.conf')).items()]
				self._send({'entry': entries})

		self.server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
		self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
		threading.Thread(target=self.server.serve_forever, daemon=True).start()

	def refresh(self):
		layout = fm.lookup_app(self.on_disk)
		self.rows = set(fm.read_lookup_file(layout[1])) if layout else set()

	def run_schedule(self):
		due = [x for x in self.schedule if self.now() >= x[0]]
		self.schedule = [x for x in self.schedule if x not in due]
		for _, f in sorted(due, key=lambda x: x[0]):
			f()

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
		return fm.main(['gen', '--rules', 'lookup', '--records', self.records(tmp_path, hashes), '--reader', 'kv',
			'--sourcetype', 'tenx_fw', '--rename', 'fw:traffic', '--out', str(tmp_path / 'fm_fw'), '--cap-file', str(cap)]
			+ list(extra))

	def activate(self, tmp_path, cap, fake, **kw):
		out = io.StringIO()
		kw.setdefault('probe_index', 'probes')
		kw.setdefault('sleep', lambda s: None)
		rc = fm.activate(str(tmp_path / 'fm_fw'), str(cap), fm.Splunkd(fake.url), out=out, **kw)
		return rc, out.getvalue()

	def test_rows_quote_every_hash_keep_outer_spaces_and_sort(self):
		assert fm.cap_text({'b', '#a b ', 'x"y'}, [('c', 'false')]) == \
			'pattern_hash,value\n"#a b ",true\n"b",true\n"c",false\n"x""y",true\n'

	def test_the_engine_reads_the_rows_back(self, tmp_path):
		import csv
		p = tmp_path / 'cap.csv'
		p.write_text(fm.cap_text({'#a b ', 'x"y', ' lead'}), encoding='utf-8')
		with open(str(p), encoding='utf-8', newline='') as f:
			assert sorted(r[0] for r in list(csv.reader(f))[1:]) == [' lead', '#a b ', 'x"y']

	def test_the_cap_file_needs_the_lookup_rules(self, tmp_path, capsys):
		cap = tmp_path / 'compact-cap.csv'
		rc = fm.main(['gen', '--records', self.records(tmp_path, ['k1']), '--reader', 'kv', '--sourcetype', 'tenx_fw',
			'--rename', 'fw:traffic', '--out', str(tmp_path / 'fm_fw'), '--cap-file', str(cap)])
		assert rc == 2 and 'needs --rules lookup' in capsys.readouterr().err
		assert not os.path.exists(str(cap)) and not os.path.exists(str(tmp_path / 'fm_fw'))

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

	def test_activate_lists_a_template_only_once_its_probe_event_has_fields(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		os.makedirs(str(tmp_path / 'old'))
		assert self.gen(tmp_path / 'old', ['k1'], tmp_path / 'old' / 'cap.csv') == 0
		assert self.gen(tmp_path, ['k1', 'k2 '], cap) == 0
		# the instance still holds the lookup file of the earlier run (k1 only)
		fake = FakeSplunkd(str(tmp_path / 'old' / 'fm_fw'), 'fm_fw', str(cap))
		try:
			rc, out = self.activate(tmp_path, cap, fake, timeout=0)
			assert rc == 1 and read(str(cap)) == 'pattern_hash,value\n"k1",true\n'
			assert os.path.exists(str(cap) + '.pending') and "not yet: 'k2 '" in out
			# the instance rereads the file: k2's probe now has fields
			fake.on_disk = str(tmp_path / 'fm_fw')
			fake.refresh()
			rc, out = self.activate(tmp_path, cap, fake, timeout=0)
		finally:
			fake.close()
		assert rc == 0 and read(str(cap)) == 'pattern_hash,value\n"k1",true\n"k2 ",true\n'
		assert not os.path.exists(str(cap) + '.pending')
		# nothing restarted or reloaded: the only POSTs are events and searches
		assert set(c[1] for c in fake.posts()) == {'/services/receivers/simple', '/services/search/jobs'}
		# each run opens the probe stream with the heartbeat, then probes in the template's own shape
		probes = [e for e in fake.events if e['raw'] != fm.HEARTBEAT_LINE]
		assert fake.events[0]['raw'] == fm.HEARTBEAT_LINE and probes[0]['raw'].startswith('~k1,')
		assert all(e['host'] == fm.PROBE_HOST and e['source'] == fm.PROBE_SOURCE and e['index'] == 'probes'
			and e['sourcetype'] == 'tenx_fw' for e in fake.events)
		k2 = [e for e in probes if e['hash'] == 'k2']
		assert k2[-1]['mapped']
		# value 0 is the timestamp (19 digits), the other values are the word probe
		assert re.fullmatch(r'~k2 ,\d{19},probe', k2[-1]['raw'])
		# while it waited for k2, every round also probed the listed k1, as check does
		second = probes[probes.index(k2[0]):]
		assert [e['hash'] for e in second] == ['k2', 'k1'] * (len(second) // 2) and all(e['mapped'] for e in second)

	def test_while_the_file_is_not_read_one_template_stands_for_all(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1', 'k2', 'k3'], cap) == 0
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		fake.rows = set()
		clock = iter(range(0, 1000, 10))
		try:
			rc, _ = self.activate(tmp_path, cap, fake, timeout=25, clock=lambda: next(clock))
		finally:
			fake.close()
		probes = [e for e in fake.events if e['raw'] != fm.HEARTBEAT_LINE]
		assert rc == 1 and set(e['hash'] for e in probes) == {'k1'} and read(str(cap)) == 'pattern_hash,value\n'

	def test_removals_need_no_probe(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		cap.write_text('pattern_hash,value\n"gone",true\n"k1",true\n', encoding='utf-8')
		assert self.gen(tmp_path, ['k1'], cap) == 0
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		try:
			assert self.activate(tmp_path, cap, fake, probe_index=None)[0] == 0
		finally:
			fake.close()
		assert fake.posts() == [] and read(str(cap)) == 'pattern_hash,value\n"k1",true\n'

	def test_activate_leaves_the_list_when_the_instance_does_not_hold_the_rule(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1'], cap) == 0
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap), loaded=False)
		try:
			rc, out = self.activate(tmp_path, cap, fake)
		finally:
			fake.close()
		assert rc == 1 and 'does not hold app fm_fw' in out and fake.events == []
		assert 'install the app folders as gen wrote them, whole, and run activate again' in out
		assert read(str(cap)) == 'pattern_hash,value\n' and os.path.exists(str(cap) + '.pending')

	@pytest.mark.parametrize('broken', ['not gzip', 'no hash column'])
	def test_activate_refuses_a_lookup_file_splunk_cannot_read(self, tmp_path, broken):
		# Splunk drops every compact event of the map, floor app or not, while the file it reads is like this
		import gzip
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1'], cap) == 0
		table = tmp_path / 'fm_fw' / 'lookups' / 'tenx_fw_fields.csv.gz'
		text = gzip.open(str(table), 'rt', encoding='utf-8').read()
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		if broken == 'not gzip':
			table.write_text(text, encoding='utf-8')
		else:
			with gzip.open(str(table), 'wt', encoding='utf-8') as f:
				f.write(text.replace('hash,', 'key,', 1))
		try:
			rc, out = self.activate(tmp_path, cap, fake)
		finally:
			fake.close()
		assert rc == 1 and fake.events == [] and read(str(cap)) == 'pattern_hash,value\n'
		assert ('activate: the lookup file %s %s' % (table, 'cannot be read as gzip CSV' if broken == 'not gzip'
			else 'has no hash column')) in out and 'Splunk drops the compact events of tenx_fw' in out

	def test_activate_needs_a_probe_index_to_add(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1'], cap) == 0
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		try:
			rc, out = self.activate(tmp_path, cap, fake, probe_index=None)
		finally:
			fake.close()
		assert rc == 1 and '--probe-index' in out and read(str(cap)) == 'pattern_hash,value\n'

	def test_activate_refuses_per_template_transforms(self, tmp_path):
		generate(tmp_path, 'fm_fw', ['--records', self.records(tmp_path, ['k1']), '--reader', 'kv', '--sourcetype', 'tenx_fw',
			'--rename', 'fw:traffic'])
		cap = tmp_path / 'compact-cap.csv'
		cap.write_text('pattern_hash,value\n', encoding='utf-8')
		(tmp_path / 'compact-cap.csv.pending').write_text('pattern_hash,value\n"k1",true\n', encoding='utf-8')
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		try:
			rc, out = self.activate(tmp_path, cap, fake)
		finally:
			fake.close()
		assert rc == 1 and 'only after a restart' in out and fake.posts() == []

	def test_gen_with_splunkd_activates_the_app_it_wrote(self, tmp_path, monkeypatch):
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1'], cap) == 0
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		monkeypatch.setenv('TENX_SPLUNKD_AUTH', 'admin:x')
		monkeypatch.setattr(fm.time, 'sleep', lambda s: None)
		try:
			assert self.gen(tmp_path, ['k1'], cap, '--splunkd', fake.url, '--probe-index', 'probes') == 0
		finally:
			fake.close()
		assert fake.posts()[0][2] == 'pattern_hash,value\n'
		assert read(str(cap)) == 'pattern_hash,value\n"k1",true\n'

	def test_activate_needs_the_floor_app_on_the_instance(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1'], cap) == 0
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		fake.floor = False
		try:
			rc, out = self.activate(tmp_path, cap, fake)
		finally:
			fake.close()
		assert rc == 1 and 'floor app fm_fw_floor' in out and fake.events == []
		assert read(str(cap)) == 'pattern_hash,value\n'

	def listed(self, tmp_path, hashes, kept=''):
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, hashes, cap) == 0
		cap.write_text(fm.cap_text(set(hashes)) + kept, encoding='utf-8')
		os.remove(str(cap) + '.pending')
		return cap

	def check(self, tmp_path, cap, fake, **kw):
		out = io.StringIO()
		kw.setdefault('probe_index', 'probes')
		clock = iter(range(0, 100000, 5))
		rc = fm.check(str(tmp_path / 'fm_fw'), str(cap), fm.Splunkd(fake.url), out=out, sleep=lambda s: None,
			clock=lambda: next(clock), **kw)
		return rc, out.getvalue()

	def test_check_changes_nothing_while_probes_have_their_fields(self, tmp_path):
		cap = self.listed(tmp_path, ['k1', 'k2'])
		before = read(str(cap))
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		try:
			rc, out = self.check(tmp_path, cap, fake, sample=2)
		finally:
			fake.close()
		assert rc == 0 and read(str(cap)) == before and not os.path.exists(str(cap) + '.pending')
		assert sorted(e['hash'] for e in fake.events) == ['k1', 'k2'] and 'all indexed with their fields' in out
		assert set(c[1] for c in fake.posts()) == {'/services/receivers/simple', '/services/search/jobs'}

	def counted_from_zero(self, cap):
		# The first check counts from the cap file's own time; these tests run check on a clock that starts at 0.
		(cap.parent / (cap.name + fm.CAP_CHECKED_SUFFIX)).write_text('0\n', encoding='utf-8')

	def compact(self, fake, h, t, why=None, sourcetype='tenx_fw'):
		e = dict(index='main', host='app1', source='a.log', sourcetype=sourcetype, raw='~%s,x' % h, hash=h, mapped=False, t=t)
		if why:
			e['why'] = why
		fake.events.append(e)

	def test_check_fails_when_unlisted_templates_arrive_compact(self, tmp_path):
		# receiverOptimize true kept in the Receiver's arguments: templates the cap file does not list arrive compact,
		# with no row in the lookup. The probes of the listed ones pass; check counts those events and fails, and
		# leaves the list, since taking listed templates off it would not stop them.
		cap = self.listed(tmp_path, ['k1', 'k2'])
		before = read(str(cap))
		self.counted_from_zero(cap)
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		for i in range(3):
			self.compact(fake, 'unlisted%d' % i, 1)
		self.compact(fake, 'other', 1, sourcetype='tenx_other')
		try:
			rc, out = self.check(tmp_path, cap, fake, sample=2)
		finally:
			fake.close()
		assert rc == 1 and read(str(cap)) == before and not os.path.exists(str(cap) + '.pending')
		assert 'check: 3 compact events of tenx_fw were indexed without their fields since 1970-01-01T00:00:00Z (no_row 3)' in out
		assert 'receiverOptimize true' in out and 'the cap file is left as it was' in out

	def test_check_empties_the_list_when_rows_of_listed_templates_fail(self, tmp_path):
		cap = self.listed(tmp_path, ['k1', 'k2'])
		self.counted_from_zero(cap)
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		self.compact(fake, 'k1', 1, why='bad_row')
		self.compact(fake, 'x', 1)
		try:
			rc, out = self.check(tmp_path, cap, fake, sample=2)
		finally:
			fake.close()
		assert rc == 1 and fm.read_cap(str(cap))[0] == set() and fm.read_cap(str(cap) + '.pending')[0] == {'k1', 'k2'}
		assert '2 compact events of tenx_fw were indexed without their fields since' in out and '(bad_row 1, no_row 1)' in out

	def test_check_keeps_the_list_when_values_of_some_events_do_not_match(self, tmp_path):
		# a value holding a line feed: no_match on that event, while the probe of the same template has its fields
		cap = self.listed(tmp_path, ['k1', 'k2'])
		before = read(str(cap))
		self.counted_from_zero(cap)
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		self.compact(fake, 'k1', 1, why='no_match')
		self.compact(fake, 'x', 1)
		try:
			rc, out = self.check(tmp_path, cap, fake, sample=2)
		finally:
			fake.close()
		assert rc == 1 and read(str(cap)) == before and not os.path.exists(str(cap) + '.pending')
		assert '(no_match 1, no_row 1): templates the lookup file has no row for arrived compact' in out
		assert 'events of listed templates hold values their row does not take (a value with a line feed); ' \
			'the cap file is left as it was' in out

	def test_the_next_check_counts_only_what_was_indexed_since(self, tmp_path):
		cap = self.listed(tmp_path, ['k1'])
		self.counted_from_zero(cap)
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		self.compact(fake, 'u1', 1)
		try:
			first, _ = self.check(tmp_path, cap, fake)
			assert read(str(cap) + fm.CAP_CHECKED_SUFFIX).strip().isdigit()
			second, out = self.check(tmp_path, cap, fake)
		finally:
			fake.close()
		assert first == 1 and second == 0 and 'all indexed with their fields' in out

	def test_check_empties_the_list_when_a_probe_comes_back_without_fields(self, tmp_path):
		cap = self.listed(tmp_path, ['k1', 'k2'], '"keep",false\n')
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		fake.rows = set()
		try:
			rc, out = self.check(tmp_path, cap, fake)
		finally:
			fake.close()
		# the rows that are not `true` stay; every listed template waits for activate
		assert rc == 1 and read(str(cap)) == 'pattern_hash,value\n"keep",false\n'
		assert read(str(cap) + '.pending') == 'pattern_hash,value\n"k1",true\n"k2",true\n"keep",false\n'
		assert 'without its fields (tenx_unmapped=no_row)' in out

	def test_check_empties_the_list_when_a_probe_is_not_indexed(self, tmp_path):
		cap = self.listed(tmp_path, ['k1'])
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		fake.drop = True
		try:
			rc, out = self.check(tmp_path, cap, fake, timeout=20, poll=5)
		finally:
			fake.close()
		assert rc == 1 and read(str(cap)) == 'pattern_hash,value\n' and '1 of 1 probes not indexed within 20 s' in out
		assert read(str(cap) + '.pending') == 'pattern_hash,value\n"k1",true\n'

	def test_after_check_activate_lists_the_templates_again_once_they_have_fields(self, tmp_path):
		cap = self.listed(tmp_path, ['k1', 'k2'])
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		try:
			fake.drop = True
			assert self.check(tmp_path, cap, fake, timeout=20, poll=5)[0] == 1
			assert self.activate(tmp_path, cap, fake, timeout=0)[0] == 1 and read(str(cap)) == 'pattern_hash,value\n'
			fake.drop = False
			clock = iter(range(0, 1000, 10))
			rc, _ = self.activate(tmp_path, cap, fake, timeout=25, clock=lambda: next(clock))
		finally:
			fake.close()
		assert rc == 0 and read(str(cap)) == 'pattern_hash,value\n"k1",true\n"k2",true\n'
		assert not os.path.exists(str(cap) + '.pending')

	def test_check_withdraws_at_once_when_the_lookup_file_is_missing(self, tmp_path):
		cap = self.listed(tmp_path, ['k1'])
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		os.remove(str(tmp_path / 'fm_fw' / 'lookups' / 'tenx_fw_fields.csv.gz'))
		try:
			rc, out = self.check(tmp_path, cap, fake)
		finally:
			fake.close()
		assert rc == 1 and not [c for c in fake.posts() if c[1] != '/services/search/jobs'] and 'is missing' in out and read(str(cap)) == 'pattern_hash,value\n'

	def test_check_withdraws_at_once_when_the_lookup_file_is_not_gzip(self, tmp_path):
		cap = self.listed(tmp_path, ['k1'])
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		(tmp_path / 'fm_fw' / 'lookups' / 'tenx_fw_fields.csv.gz').write_text('hash,n\n', encoding='utf-8')
		try:
			rc, out = self.check(tmp_path, cap, fake)
		finally:
			fake.close()
		assert rc == 1 and not [c for c in fake.posts() if c[1] != '/services/search/jobs'] and 'cannot be read as gzip CSV' in out
		assert read(str(cap)) == 'pattern_hash,value\n' and fm.read_cap(str(cap) + '.pending')[0] == {'k1'}

	def test_the_list_activate_restores_is_a_newer_file_than_the_one_check_emptied(self, tmp_path):
		# the Receiver rereads its cap file when the file's time changes
		cap = self.listed(tmp_path, ['k1'])
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		try:
			fake.drop = True
			assert self.check(tmp_path, cap, fake, timeout=20, poll=5)[0] == 1
			os.utime(str(cap), (1000000000, 1000000000))
			os.utime(str(cap) + '.pending', (1000000000, 1000000000))
			fake.drop = False
			assert self.activate(tmp_path, cap, fake, timeout=0)[0] == 0
		finally:
			fake.close()
		assert read(str(cap)) == 'pattern_hash,value\n"k1",true\n' and os.stat(str(cap)).st_mtime > 1000000001
		assert not os.path.exists(str(cap) + '.pending')

	def test_probes_can_take_the_path_of_the_data(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1'], cap) == 0
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		# the management port's instance holds the app, the instance behind HEC parses without it
		fake.hec_unmapped = True
		out = io.StringIO()
		try:
			rc = fm.activate(str(tmp_path / 'fm_fw'), str(cap), fm.Splunkd(fake.url, hec_url=fake.url, hec_token='t'), out=out,
				sleep=lambda s: None, probe_index='probes', timeout=0)
		finally:
			fake.close()
		assert rc == 1 and read(str(cap)) == 'pattern_hash,value\n'
		assert fake.events and all(e.get('via') == 'hec' for e in fake.events)
		assert '/services/receivers/simple' not in set(c[1] for c in fake.posts())

	def test_check_with_nothing_listed_sends_no_probe(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1'], cap) == 0
		self.counted_from_zero(cap)
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		try:
			rc, out = self.check(tmp_path, cap, fake)
		finally:
			fake.close()
		assert rc == 0 and fake.events == [] and 'nothing listed' in out
		assert set(c[1] for c in fake.posts()) == {'/services/search/jobs'}

	def test_check_with_nothing_listed_fails_when_templates_arrive_compact(self, tmp_path):
		# The Receiver keeps receiverOptimize true: with nothing listed it still compacts every template, and the
		# ones the lookup has no row for arrive without their fields.
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, ['k1'], cap) == 0
		# no probe moves the clock, so the previous check is put before the events
		(tmp_path / ('compact-cap.csv' + fm.CAP_CHECKED_SUFFIX)).write_text('-10\n', encoding='utf-8')
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		self.compact(fake, 'u1', -5)
		self.compact(fake, 'u2', -5)
		try:
			rc, out = self.check(tmp_path, cap, fake)
		finally:
			fake.close()
		assert rc == 1 and fake.events[2:] == [] and read(str(cap)) == 'pattern_hash,value\n'
		assert 'check: nothing listed' in out and '2 compact events of tenx_fw were indexed without their fields' in out
		assert '(no_row 2)' in out and 'receiverOptimize true' in out

	class Clock(object):
		"""Time that moves only when activate or check sleeps."""

		def __init__(self, t=1000.0):
			self.t = t

		def __call__(self):
			return self.t

		def sleep(self, s):
			self.t += s

	def waiting(self, tmp_path, listed, added):
		"""The cap file lists `listed`; the pending list adds `added`; the instance still holds the lookup
		file of `listed` alone, so it has no row for `added` until refresh() is called."""
		cap = tmp_path / 'compact-cap.csv'
		os.makedirs(str(tmp_path / 'old'))
		assert self.gen(tmp_path / 'old', listed or ['k0'], tmp_path / 'old' / 'cap.csv') == 0
		assert self.gen(tmp_path, list(listed) + list(added), cap) == 0
		cap.write_text(fm.cap_text(set(listed)), encoding='utf-8')
		fake = FakeSplunkd(str(tmp_path / 'old' / 'fm_fw'), 'fm_fw', str(cap))
		clock = self.Clock()
		fake.now = clock
		return cap, fake, clock

	def test_activate_withdraws_the_list_when_the_lookup_stops_giving_rows_while_it_waits(self, tmp_path):
		# a new template waits for the instance to read the new file; meanwhile the file is emptied
		cap, fake, clock = self.waiting(tmp_path, ['k1'], ['k2'])
		fake.schedule = [(1015, lambda: setattr(fake, 'rows', set()))]
		try:
			rc, out = self.activate(tmp_path, cap, fake, timeout=300, poll=10, check_timeout=20, clock=clock,
				sleep=clock.sleep)
		finally:
			fake.close()
		assert rc == 1 and read(str(cap)) == 'pattern_hash,value\n'
		assert read(str(cap) + '.pending') == 'pattern_hash,value\n"k1",true\n"k2",true\n'
		assert "probe of 'k1' indexed without its fields (tenx_unmapped=no_row)" in out and 'withdrawn by check' in out
		# found by the first probe of the listed template sent after the change, one round later
		assert clock.t - 1015 <= 2 * 10

	def test_activate_stops_probing_a_new_template_whose_row_does_not_work_once_the_file_was_read(self, tmp_path):
		cap, fake, clock = self.waiting(tmp_path, [], ['k1', 'k2'])
		# the instance has read the new file, but the row of k2 gives no fields
		fake.rows = {'k1'}
		try:
			rc, out = self.activate(tmp_path, cap, fake, timeout=300, poll=10, clock=clock, sleep=clock.sleep)
		finally:
			fake.close()
		assert rc == 1 and read(str(cap)) == 'pattern_hash,value\n"k1",true\n'
		assert read(str(cap) + '.pending') == 'pattern_hash,value\n"k1",true\n"k2",true\n'
		assert "without their fields after the file was read: 'k2' (tenx_unmapped=no_row)" in out
		assert 'lookup refresh 60 s, the default: not read from the instance' in out
		# ended one round after the refresh period plus one poll, not at --timeout
		assert clock.t == 1000 + 60 + 10 + 10

	def test_activate_waits_for_the_refresh_period_the_instance_has(self, tmp_path):
		for limits, rc_expected in ((None, 1), ({'ingest_lookup_refresh_period_secs': '120'}, 0)):
			case = tmp_path / ('c%d' % rc_expected)
			os.makedirs(str(case))
			cap, fake, clock = self.waiting(case, ['k1'], ['k2'])
			fake.limits = limits
			# the instance reads the new file 100 s after activate starts
			fake.schedule = [(1100, lambda: (setattr(fake, 'on_disk', str(case / 'fm_fw')), fake.refresh()))]
			try:
				rc, out = self.activate(case, cap, fake, timeout=300, poll=10, clock=clock, sleep=clock.sleep)
			finally:
				fake.close()
			assert rc == rc_expected, out
			if limits:
				assert 'lookup refresh 120 s)' in out and read(str(cap)) == 'pattern_hash,value\n"k1",true\n"k2",true\n'
			else:
				assert read(str(cap)) == 'pattern_hash,value\n"k1",true\n' and "'k2' (tenx_unmapped=no_row)" in out

	def test_activate_probes_a_listed_template_on_every_round(self, tmp_path):
		cap, fake, clock = self.waiting(tmp_path, ['k1', 'k3'], ['k2'])
		try:
			rc, out = self.activate(tmp_path, cap, fake, timeout=300, poll=10, clock=clock, sleep=clock.sleep)
		finally:
			fake.close()
		listed = [e['t'] for e in fake.events if e['hash'] in ('k1', 'k3')]
		new = [e['t'] for e in fake.events if e['hash'] == 'k2']
		# rounds at 0, 10, ... 70 s: the probe indexed at 70 s (refresh 60 + poll 10) is the one that counts
		assert rc == 1 and len(listed) == len(new) == 8 and '8 checks' in out
		assert max(b - a for a, b in zip(listed, listed[1:])) == 10

	def test_activate_says_when_the_instance_has_not_read_the_rows(self, tmp_path):
		# Splunk 10.4.3 did not reread a lookup file that came back with the time it had when it was last read:
		# every probe is then indexed without fields (no_row), and activate says why that can be
		cap, fake, clock = self.waiting(tmp_path, [], ['k1', 'k2'])
		fake.rows = set()
		try:
			rc, out = self.activate(tmp_path, cap, fake, timeout=200, poll=10, clock=clock, sleep=clock.sleep)
		finally:
			fake.close()
		assert rc == 1 and read(str(cap)) == fm.cap_text(set())
		assert 'every probe came back tenx_unmapped=no_row, so the instance has not read the rows of tenx_fw_fields.csv.gz' in out
		assert 'stays unread until it is touched on that instance' in out

	def test_no_word_on_rows_when_some_template_has_its_fields(self, tmp_path):
		cap, fake, clock = self.waiting(tmp_path, [], ['k1', 'k2'])
		fake.rows = {'k2'}
		try:
			rc, out = self.activate(tmp_path, cap, fake, timeout=200, poll=10, clock=clock, sleep=clock.sleep)
		finally:
			fake.close()
		assert "'k1' (tenx_unmapped=no_row)" in out and 'has not read the rows' not in out

	def test_without_rows_activate_sends_one_probe_a_round_and_lists_templates_once_rows_return(self, tmp_path):
		added = ['k1', 'k2', 'k3', 'k4', 'k5', 'k6']
		cap, fake, clock = self.waiting(tmp_path, [], added)
		fake.rows = set()
		fake.schedule = [(1085, lambda: setattr(fake, 'rows', set(added)))]
		try:
			rc, out = self.activate(tmp_path, cap, fake, timeout=300, poll=10, clock=clock, sleep=clock.sleep)
			probes = [e for e in fake.events if e['raw'] != fm.HEARTBEAT_LINE]
			# one stand-in a round until one has its fields: k1 and k2 failed after the refresh period, k3 had them
			assert [e['hash'] for e in probes] == ['k1'] * 8 + ['k2', 'k3', 'k4', 'k5', 'k6']
			assert rc == 1 and read(str(cap)) == fm.cap_text({'k3', 'k4', 'k5', 'k6'})
			assert "without their fields after the file was read: 'k1' (tenx_unmapped=no_row), 'k2'" in out
			# the next run lists the two that failed
			rc, out = self.activate(tmp_path, cap, fake, timeout=300, poll=10, clock=clock, sleep=clock.sleep)
		finally:
			fake.close()
		assert rc == 0 and read(str(cap)) == fm.cap_text(set(added)) and not os.path.exists(str(cap) + '.pending')

	def test_check_withdraws_when_a_listed_template_has_no_row_in_the_lookup_file(self, tmp_path):
		for rows, sample in (([], 1), (['k1'], 1), (['k1'], 2)):
			case = tmp_path / ('c%d_%d' % (len(rows), sample))
			os.makedirs(str(case))
			cap = case / 'compact-cap.csv'
			assert self.gen(case, rows or ['k0'], cap) == 0
			if not rows:
				# the file emptied to its header
				table = str(case / 'fm_fw' / 'lookups' / 'tenx_fw_fields.csv.gz')
				with gzip.open(table, 'rt', encoding='utf-8') as f:
					header = f.readline()
				with gzip.open(table, 'wt', encoding='utf-8') as f:
					f.write(header)
			cap.write_text(fm.cap_text({'k1', 'k2'}), encoding='utf-8')
			os.remove(str(cap) + '.pending')
			fake = FakeSplunkd(str(case / 'fm_fw'), 'fm_fw', str(cap))
			try:
				rc, out = self.check(case, cap, fake, sample=sample)
			finally:
				fake.close()
			assert rc == 1 and not [c for c in fake.posts() if c[1] != '/services/search/jobs'] and read(str(cap)) == 'pattern_hash,value\n', out
			assert '%d listed templates have no row' % (2 - len(rows)) in out
			assert read(str(cap) + '.pending') == 'pattern_hash,value\n"k1",true\n"k2",true\n'

	def test_without_a_timeout_activate_probes_for_the_refresh_period_plus_three_polls(self, tmp_path):
		for limits, ends in ((None, 1000 + 60 + 30 + 10), ({'ingest_lookup_refresh_period_secs': '120'}, 1000 + 120 + 30 + 10)):
			case = tmp_path / ('c%d' % ends)
			os.makedirs(str(case))
			cap, fake, clock = self.waiting(case, [], ['k1'])
			fake.limits, fake.drop = limits, True
			try:
				rc, out = self.activate(case, cap, fake, poll=10, clock=clock, sleep=clock.sleep)
			finally:
				fake.close()
			# no probe comes back: the run ends at the first round past the timeout
			assert rc == 1 and clock.t == ends and 'of at most %d,' % (ends - 1010) in out

	def test_activate_takes_check_timeout_from_the_command_line(self, tmp_path, monkeypatch):
		seen = {}
		monkeypatch.setattr(fm, 'activate', lambda *a, **kw: seen.update(kw) or 0)
		assert fm.main(['activate', '--app', str(tmp_path), '--cap-file', str(tmp_path / 'c.csv'), '--splunkd',
			'https://127.0.0.1:1', '--check-timeout', '7']) == 0
		assert seen == {'check_timeout': 7.0}

	def test_without_the_option_nothing_changes(self, tmp_path):
		records = self.records(tmp_path, ['k1'])
		generate(tmp_path, 'a', ['--records', records, '--reader', 'kv', '--sourcetype', 'tenx_fw', '--rename', 'fw:traffic'])
		report = json.loads((tmp_path / 'a_report.json').read_text())
		assert 'compact_cap' not in report and sorted(os.listdir(str(tmp_path))) == ['a', 'a_report.json', 'templates.json']


class FakeNode(object):
	"""One parsing node's HTTP Event Collector in a thread: indexes each probe into the FakeSplunkd's events (so
	the search head finds it) with tenx_mapped when its hash has a row in this node's lookup as last read, and
	with the node field the probe carries. busy answers 503; close() stops it, so it can no longer be reached."""

	def __init__(self, fake, rows):
		import http.server
		import threading
		self.fake, self.rows, self.busy = fake, set(rows), False
		outer = self

		class Handler(http.server.BaseHTTPRequestHandler):
			def log_message(self, *a):
				pass

			def do_POST(self):
				outer.fake.run_schedule()
				data = self.rfile.read(int(self.headers.get('Content-Length') or 0)).decode('utf-8')
				if outer.busy:
					self.send_response(503)
					self.end_headers()
					return
				for line in data.splitlines():
					e = json.loads(line)
					h = e['event'][1:].split(',', 1)[0].strip()
					outer.fake.events.append(dict(index=e['index'], host=e['host'], source=e['source'], sourcetype=e['sourcetype'],
						raw=e['event'], hash=h, mapped=h in outer.rows, t=outer.fake.now(), via='hec',
						node=e.get('fields', {}).get(fm.PROBE_NODE_FIELD, '')))
				body = b'{"text":"Success","code":0}'
				self.send_response(200)
				self.send_header('Content-Length', str(len(body)))
				self.end_headers()
				self.wfile.write(body)

		self.server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
		self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
		threading.Thread(target=self.server.serve_forever, daemon=True).start()

	def close(self):
		self.server.shutdown()
		self.server.server_close()


class TestEveryParsingNode:
	"""--probe-hec given once per parsing node: a template is listed only when every node that answers returns its
	probe with fields, check probes every node, a node that cannot be reached is left out."""
	gen, records = TestCapFile.gen, TestCapFile.records
	Clock = TestCapFile.Clock

	def setup(self, tmp_path, listed, added, ready):
		"""The cap file lists `listed`, the pending list adds `added`; three nodes, those in `ready` (0, 1, 2) already
		read the new lookup file, the others still hold the rows of `listed` alone."""
		cap = tmp_path / 'compact-cap.csv'
		assert self.gen(tmp_path, list(listed) + list(added), cap) == 0
		cap.write_text(fm.cap_text(set(listed)), encoding='utf-8')
		fake = FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))
		clock = self.Clock()
		fake.now = clock
		nodes = [FakeNode(fake, set(listed) | (set(added) if i in ready else set())) for i in range(3)]
		return cap, fake, clock, nodes

	def splunkd(self, fake, nodes):
		return fm.Splunkd(fake.url, hec_url=[n.url for n in nodes], hec_token='t')

	def close(self, fake, nodes):
		for n in nodes:
			try:
				n.close()
			except Exception:
				pass
		fake.close()

	def test_a_template_is_listed_only_once_every_node_returns_it_with_fields(self, tmp_path):
		cap, fake, clock, nodes = self.setup(tmp_path, ['k1'], ['k2'], ready=[0])
		out = io.StringIO()
		# two of three nodes read the new file 25 s in (one refresh), the first already has it
		fake.schedule = [(1025, lambda: [nodes[i].rows.add('k2') for i in (1, 2)])]
		try:
			rc = fm.activate(str(tmp_path / 'fm_fw'), str(cap), self.splunkd(fake, nodes), out=out, probe_index='probes',
				timeout=20, poll=5, check_timeout=10, clock=clock, sleep=clock.sleep)
			# within 20 s only one node gave k2 its fields: k2 is not listed although node 0 confirmed it
			assert rc == 1 and read(str(cap)) == 'pattern_hash,value\n"k1",true\n' and "not yet: 'k2'" in out.getvalue()
			rc = fm.activate(str(tmp_path / 'fm_fw'), str(cap), self.splunkd(fake, nodes), out=out, probe_index='probes',
				timeout=60, poll=5, check_timeout=10, clock=clock, sleep=clock.sleep)
		finally:
			self.close(fake, nodes)
		assert rc == 0 and read(str(cap)) == 'pattern_hash,value\n"k1",true\n"k2",true\n'
		# every probe was sent to every node, each carrying the node it went to
		k2 = [e for e in fake.events if e['hash'] == 'k2']
		labels = set(urllib.parse.urlsplit(n.url).netloc for n in nodes)
		assert set(e['node'] for e in k2) == labels and all(e['via'] == 'hec' for e in k2)
		assert all(e['mapped'] for e in k2 if e['t'] >= 1025)

	def test_check_withdraws_when_one_node_returns_a_probe_without_fields(self, tmp_path):
		cap, fake, clock, nodes = self.setup(tmp_path, ['k1', 'k2'], [], ready=[0, 1, 2])
		nodes[2].rows = set()
		out = io.StringIO()
		try:
			rc = fm.check(str(tmp_path / 'fm_fw'), str(cap), self.splunkd(fake, nodes), probe_index='probes', sample=1,
				timeout=20, poll=5, out=out, clock=clock, sleep=clock.sleep)
		finally:
			self.close(fake, nodes)
		label = urllib.parse.urlsplit(nodes[2].url).netloc
		assert rc == 1 and read(str(cap)) == 'pattern_hash,value\n'
		assert 'sent to %s indexed without its fields (tenx_unmapped=no_row)' % nodes[2].url in out.getvalue()
		assert set(e['node'] for e in fake.events) == set(urllib.parse.urlsplit(n.url).netloc for n in nodes) and label

	def test_activate_withdraws_within_two_rounds_when_one_node_stops_giving_rows(self, tmp_path):
		cap, fake, clock, nodes = self.setup(tmp_path, ['k1'], ['k2'], ready=[])
		fake.schedule = [(1015, lambda: setattr(nodes[1], 'rows', set()))]
		out = io.StringIO()
		try:
			rc = fm.activate(str(tmp_path / 'fm_fw'), str(cap), self.splunkd(fake, nodes), out=out, probe_index='probes',
				timeout=300, poll=10, check_timeout=20, clock=clock, sleep=clock.sleep)
		finally:
			self.close(fake, nodes)
		assert rc == 1 and read(str(cap)) == 'pattern_hash,value\n' and 'withdrawn by check' in out.getvalue()
		assert 'sent to %s' % nodes[1].url in out.getvalue() and clock.t - 1015 <= 2 * 10

	def test_a_node_that_cannot_be_reached_is_left_out_and_counted_again_once_it_answers(self, tmp_path):
		cap, fake, clock, nodes = self.setup(tmp_path, ['k1'], ['k2'], ready=[0, 1])
		down = nodes[2]
		down.close()
		out = io.StringIO()
		try:
			rc = fm.activate(str(tmp_path / 'fm_fw'), str(cap), self.splunkd(fake, nodes), out=out, probe_index='probes',
				timeout=60, poll=5, check_timeout=10, clock=clock, sleep=clock.sleep)
			assert rc == 0 and read(str(cap)) == 'pattern_hash,value\n"k1",true\n"k2",true\n'
			assert 'left out of those rounds: %s' % down.url in out.getvalue()
			out = io.StringIO()
			rc = fm.check(str(tmp_path / 'fm_fw'), str(cap), self.splunkd(fake, nodes), probe_index='probes', sample=2,
				timeout=20, poll=5, out=out, clock=clock, sleep=clock.sleep)
			assert rc == 0 and 'on 2 nodes' in out.getvalue() and 'left out: %s' % down.url in out.getvalue()
			# a node busy (503) is left out as well, not counted as wrong
			nodes[1].busy = True
			rc = fm.check(str(tmp_path / 'fm_fw'), str(cap), self.splunkd(fake, nodes), probe_index='probes', sample=2,
				timeout=20, poll=5, out=io.StringIO(), clock=clock, sleep=clock.sleep)
			assert rc == 0 and read(str(cap)) == 'pattern_hash,value\n"k1",true\n"k2",true\n'
			nodes[1].busy = False
			# the node comes back without the rows: the next check withdraws the list
			back = FakeNode(fake, set())
			nodes[2] = back
			out = io.StringIO()
			rc = fm.check(str(tmp_path / 'fm_fw'), str(cap), self.splunkd(fake, nodes), probe_index='probes', sample=1,
				timeout=20, poll=5, out=out, clock=clock, sleep=clock.sleep)
		finally:
			self.close(fake, nodes)
		assert rc == 1 and read(str(cap)) == 'pattern_hash,value\n' and 'sent to %s' % back.url in out.getvalue()

	def test_with_no_node_reachable_check_changes_nothing(self, tmp_path):
		cap, fake, clock, nodes = self.setup(tmp_path, ['k1'], [], ready=[0, 1, 2])
		for n in nodes:
			n.close()
		out = io.StringIO()
		try:
			rc = fm.check(str(tmp_path / 'fm_fw'), str(cap), self.splunkd(fake, nodes), probe_index='probes', sample=1,
				timeout=20, poll=5, out=out, clock=clock, sleep=clock.sleep)
		finally:
			fake.close()
		assert rc == 2 and read(str(cap)) == 'pattern_hash,value\n"k1",true\n'
		assert 'no parsing node took the probes' in out.getvalue() and 'nothing checked' in out.getvalue()

	def test_the_option_given_several_times_gives_one_endpoint_per_node(self, tmp_path, monkeypatch):
		seen = {}
		monkeypatch.setattr(fm, 'check', lambda app, cap, splunkd, *a, **k: seen.setdefault('nodes', splunkd.nodes) and 0)
		fm.main(['check', '--app', str(tmp_path), '--cap-file', str(tmp_path / 'c.csv'), '--splunkd', 'https://sh:8089',
			'--probe-index', 'p', '--probe-hec', 'https://idx1:8088', '--probe-hec', 'https://idx2:8088/'])
		assert seen['nodes'] == ['https://idx1:8088', 'https://idx2:8088']
		assert fm.Splunkd('https://sh:8089', hec_url='https://lb:8088').nodes == [None]
		assert fm.Splunkd('https://sh:8089', hec_url=['https://lb:8088']).nodes == [None]



class TestCheckCountsDroppedEvents:
	"""check reads Splunk's own log for compact events dropped by the map's failing index-time lookup()."""

	def setup(self, tmp_path, hashes=('k1', 'k2')):
		t = TestCapFile()
		cap = t.listed(tmp_path, list(hashes)) if hashes else tmp_path / 'compact-cap.csv'
		if not hashes:
			assert t.gen(tmp_path, ['k1'], cap) == 0
		(tmp_path / ('compact-cap.csv' + fm.CAP_CHECKED_SUFFIX)).write_text('-100\n', encoding='utf-8')
		return t, cap, FakeSplunkd(str(tmp_path / 'fm_fw'), 'fm_fw', str(cap))

	def test_check_empties_the_list_and_names_the_count_the_nodes_and_the_times(self, tmp_path):
		t, cap, fake = self.setup(tmp_path)
		fake.dropped = [('idx1', 'tenx_fw', -50), ('idx1', 'tenx_fw', -40), ('idx2', 'tenx_fw', -45), ('idx1', 'other', -45)]
		try:
			rc, out = t.check(tmp_path, cap, fake, sample=2)
		finally:
			fake.close()
		assert rc == 1 and fm.read_cap(str(cap))[0] == set() and fm.read_cap(str(cap) + '.pending')[0] == {'k1', 'k2'}
		assert '3 compact events of tenx_fw were dropped by Splunk since 1969-12-31T23:58:20Z' in out
		assert 'idx1 2, first 1969-12-31T23:59:10Z, last 1969-12-31T23:59:20Z; idx2 1' in out
		# no probe was sent: the drops decide
		assert fake.events == [] and '/services/receivers/simple' not in set(c[1] for c in fake.posts())
		assert read(str(cap) + fm.CAP_CHECKED_SUFFIX).strip() == '0'

	def test_the_next_check_counts_only_what_was_dropped_since(self, tmp_path):
		t, cap, fake = self.setup(tmp_path)
		fake.dropped = [('idx1', 'tenx_fw', -50)]
		try:
			first, _ = t.check(tmp_path, cap, fake, sample=2)
			cap.write_text(fm.cap_text({'k1', 'k2'}), encoding='utf-8')
			second, out = t.check(tmp_path, cap, fake, sample=2)
		finally:
			fake.close()
		assert first == 1 and second == 0 and 'dropped' not in out

	def test_with_nothing_listed_check_still_fails_on_dropped_events(self, tmp_path):
		t, cap, fake = self.setup(tmp_path, hashes=())
		fake.dropped = [('hf1', 'tenx_fw', -10)]
		try:
			rc, out = t.check(tmp_path, cap, fake)
		finally:
			fake.close()
		assert rc == 1 and '1 compact events of tenx_fw were dropped by Splunk' in out and 'the cap file lists no template' in out

	def test_a_role_that_cannot_read_internal_is_told(self, tmp_path):
		t, cap, fake = self.setup(tmp_path)
		fake.internal = False
		fake.dropped = [('idx1', 'tenx_fw', -50)]
		try:
			rc, out = t.check(tmp_path, cap, fake, sample=2)
		finally:
			fake.close()
		assert 'cannot read _internal' in out and rc == 0 and fm.read_cap(str(cap))[0] == {'k1', 'k2'}
