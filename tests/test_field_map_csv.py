"""
The csv reader (a DELIMS extraction with FIELDS: positional values, as the Splunk Add-on for Palo Alto Networks reads
PAN-OS syslog), its layouts from an add-on, the [source::] stanzas that leave an add-on's text rules out for compact
events, and a TIME_PREFIX match that spans values. What Splunk does was measured on Splunk Enterprise 10.4.3 (see the
docstrings of CsvReader, csv_layouts and "Rules that read a compact event's text"); these tests pin what gen writes.
The add-on here is synthetic.
"""
import json
import os
import re

import tenx_field_map as fm

LOG, TRAFFIC, SYSTEM = 'fw:log', 'fw:traffic', 'fw:system'


def addon(tmp_path):
	d = tmp_path / 'addon' / 'default'
	os.makedirs(str(d))
	(d / 'props.conf').write_text(
		'[%s]\nTRANSFORMS-sourcetype = route_traffic, route_system\n\n'
		'[%s]\nKV_MODE = none\nREPORT-search = extract_traffic, extract_misc\n\n'
		'[%s]\nREPORT-search = extract_system\nREPORT-more = extract_desc\n' % (LOG, TRAFFIC, SYSTEM), encoding='utf-8')
	(d / 'transforms.conf').write_text(
		'[route_traffic]\nDEST_KEY = MetaData:Sourcetype\nREGEX = ^[^,]+,[^,]+,TRAFFIC,\nFORMAT = sourcetype::%s\n\n'
		'[route_system]\nDEST_KEY = MetaData:Sourcetype\nREGEX = ^[^,]+,[^,]+,SYSTEM,\nFORMAT = sourcetype::%s\n\n'
		'[extract_traffic]\nDELIMS = ","\nFIELDS = "head","when","type","src","dst","misc"\n\n'
		'[extract_misc]\nSOURCE_KEY = misc\nREGEX = ^(?<misc_host>[^/]+)\n\n'
		'[extract_system]\nDELIMS = ","\nFIELDS = "head","when","type","module","description"\n\n'
		'[extract_desc]\nSOURCE_KEY = description\nREGEX = user (?<user>\\S+)\n' % (TRAFFIC, SYSTEM), encoding='utf-8')
	return str(tmp_path / 'addon')


def records(tmp_path, items):
	p = tmp_path / 'templates.json'
	p.write_text(''.join(json.dumps({'templateHash': h, 'template': t}) + '\n' for h, t in items), encoding='utf-8')
	return str(p)


class TestSplit:
	def test_measured_cases(self):
		split = fm.CsvReader.split
		assert split('a,"Client,Server",c') == ['a', 'Client,Server', 'c']
		assert split('a,"  Client Server  ",c') == ['a', 'Client Server', 'c']
		assert split('a,  dns  ,c') == ['a', 'dns', 'c']
		assert split('a,"",,c') == ['a', '', '', 'c']
		assert split('a,"a""b,c",d') == ['a', 'a""b,c', 'd']
		assert split('a,"a\\"b,c",d') == ['a', 'a"b,c', 'd']
		assert split('a,d\tns,c') == ['a', 'd\tns', 'c']
		assert split('a,1 ') == ['a', '1']

	def test_a_quote_never_closed_takes_the_rest(self):
		assert fm.CsvReader.split('x,"abc,frothly,,dns,1 ') == ['x', '"abc,frothly,,dns,1']
		assert fm.CsvReader.split('x,a"b,frothly,,dns') == ['x', 'a"b,frothly,,dns']


class TestPairs:
	def test_names_by_position_empty_values_left_out(self):
		r = fm.CsvReader([(None, ['h', 'w', 'type', 'src', 'dst'], ',')])
		assert r.pairs('H,W,TRAFFIC,,\x000\x00.\x001\x00,extra') == [('h', 'H'), ('w', 'W'), ('type', 'TRAFFIC'),
			('dst', '\x000\x00.\x001\x00')]

	def test_layout_by_route_and_none_without_one(self):
		r = fm.CsvReader([('^[^,]+,[^,]+,TRAFFIC,', ['a', 'b', 'type', 'src'], ','),
			('^[^,]+,[^,]+,SYSTEM,', ['a', 'b', 'type', 'module'], ',')])
		assert ('module', 'auth') in r.pairs('\x000\x00 h,w,SYSTEM,auth')
		assert ('src', 'x') in r.pairs('\x000\x00 h,w,TRAFFIC,x')
		assert r.pairs('h,w,\x001\x00,x') == []


class TestLayoutsFromAddon:
	def test_fields_and_routes(self, tmp_path):
		layouts, report = fm.csv_layouts(addon(tmp_path), [TRAFFIC, SYSTEM, LOG])
		assert layouts == [('^[^,]+,[^,]+,TRAFFIC,', ['head', 'when', 'type', 'src', 'dst', 'misc'], ','),
			('^[^,]+,[^,]+,SYSTEM,', ['head', 'when', 'type', 'module', 'description'], ',')]
		assert 'no REPORT- transform' in report[LOG]

	def test_classes_that_read_the_text(self, tmp_path):
		props, transforms = fm.read_addon(addon(tmp_path))
		assert fm.text_reading_classes(props, transforms, TRAFFIC) == [('REPORT-search', ['extract_misc'])]
		assert fm.text_reading_classes(props, transforms, SYSTEM) == [('REPORT-search', [])]
		assert fm.text_reading_classes(props, transforms, LOG) == []


class TestGen:
	def target(self, tmp_path):
		p = tmp_path / 'target.json'
		p.write_text(json.dumps({'reader': 'csv', 'sourcetype': 'tenx_fw', 'rename': [TRAFFIC, SYSTEM, LOG],
			'compact_source': True, 'time_prefix': '^(?:[^,]*,){1}', 'time_format': ['%Y/%m/%d %H:%M:%S,%N',
			'%Y/%m/%d %H:%M:%S']}), encoding='utf-8')
		return str(p)

	def test_map_with_compact_source(self, tmp_path):
		items = [('t1', '$(MMM dd HH:mm:ss) $,$//$//$ $:$:$,TRAFFIC,$.$.$.$,$,site//a'),
			('s1', '$(MMM dd HH:mm:ss) $,$//$//$ $:$:$,SYSTEM,auth,user $ failed')]
		assert fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, items), '--target', self.target(tmp_path),
			'--addon', addon(tmp_path), '--out', str(tmp_path / 'fm')]) == 0
		rows = fm.read_lookup_file(str(tmp_path / 'fm' / 'lookups' / 'tenx_fw_fields.csv.gz'))
		names = dict((k, [n for n, _ in fm.parse_meta(r['f'])]) for k, r in rows.items())
		assert names['t1'][:5] == ['head', 'when', 'type', 'src', 'dst'] and 'misc' in names['t1']
		assert ['head', 'when', 'type', 'module', 'description'] == names['s1'][:5]
		props = (tmp_path / 'fm' / 'default' / 'props.conf').read_text(encoding='utf-8')
		transforms = (tmp_path / 'fm' / 'default' / 'transforms.conf').read_text(encoding='utf-8')
		assert '[source::tenx:fw:traffic:...]\nREPORT-search = extract_misc\n' in props
		assert '[source::tenx:fw:system:...]\nREPORT-search = \n' in props
		assert '[source::tenx:fw:log:' not in props
		assert re.search(r'TRANSFORMS-tenx_fw = .*tenx_fw_rename, tenx_fw_source\n', props)
		assert ('INGEST_EVAL = source:=if(substr(_raw,1,1)=="~" AND sourcetype!="tenx_fw", "tenx:" . sourcetype . ":" . '
			'source, source)') in transforms
		report = json.loads((tmp_path / 'fm_report.json').read_text(encoding='utf-8'))
		# The prefix spans the header's values (the timestamp and one more) and still ends at template text.
		assert report['event_time']['templates_with_rule'] == 2

	def test_columns_from_a_header_list(self, tmp_path, capsys):
		assert fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, [('k', 'a,$,"x,y",,$ ')]),
			'--reader', 'csv', '--sourcetype', 'tenx_csv', '--rename', 'app:csv', '--columns', 'one,two,three,four,five',
			'--out', str(tmp_path / 'fm')]) == 0
		row = fm.read_lookup_file(str(tmp_path / 'fm' / 'lookups' / 'tenx_csv_fields.csv.gz'))['k']['f']
		assert [n for n, _ in fm.parse_meta(row)][:4] == ['one', 'two', 'three', 'five']

	def test_csv_needs_names(self, tmp_path, capsys):
		assert fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, [('k', 'a,$')]), '--reader', 'csv',
			'--sourcetype', 'tenx_csv', '--rename', 'app:csv', '--out', str(tmp_path / 'fm')]) == 2
		assert 'the csv reader needs the column names' in capsys.readouterr().err

	def test_palo_alto_target(self):
		t = fm.load_target('palo-alto', {})
		assert t['reader'] == 'csv' and t['compact_source'] and fm.several(t)
		assert fm.renames(t)[0] == 'pan:traffic' and fm.renames(t)[-1] == 'pan:log'
		assert t['time_format'] == ['%Y/%m/%d %H:%M:%S,%N', '%Y/%m/%d %H:%M:%S']


class TestTimePrefixOverValues:
	def test_stable_when_the_values_hold_no_comma(self):
		rx = re.compile(r'^(?:[^,]*,){2}')
		text = '\x000\x00 \x001\x00.\x002\x00  \x003\x00,\x004\x00/\x005\x00,\x006\x00 rest'
		assert fm.prefix_match_is_stable(rx, text, rx.search(text).end())

	def test_not_stable_when_a_value_moves_the_match(self):
		rx = re.compile(r'^\S+ ')
		text = '\x000\x00 rest'
		assert not fm.prefix_match_is_stable(rx, text, rx.search(text).end())
