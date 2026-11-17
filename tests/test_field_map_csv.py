"""
The csv reader (a DELIMS extraction with FIELDS: positional values, as the Splunk Add-on for Palo Alto Networks reads
PAN-OS syslog), its layouts from an add-on, tenx_blank and the search-time rules that null what an add-on's positional
rule reads from a compact line, and a TIME_PREFIX match that spans values. What Splunk does was measured on Splunk Enterprise 10.4.3 (see the
docstrings of CsvReader, csv_layouts and "A positional rule on a compact line"); these tests pin what gen writes.
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

	def test_an_escaped_quote_outside_quotes_is_text(self):
		# Splunk Enterprise 10.4.3 on an elastic panw decryption fixture line
		assert fm.CsvReader.split('4,\\"used-by-malware,able,pervasive-use\\",,ssl') == ['4', '"used-by-malware', 'able',
			'pervasive-use"', '', 'ssl']
		assert fm.CsvReader.split('frothly.local\\amber.turing,x') == ['frothly.local\\amber.turing', 'x']

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


class TestGen:
	def target(self, tmp_path):
		p = tmp_path / 'target.json'
		p.write_text(json.dumps({'reader': 'csv', 'sourcetype': 'tenx_fw', 'rename': [TRAFFIC, SYSTEM, LOG],
			'time_prefix': '^(?:[^,]*,){1}', 'time_format': ['%Y/%m/%d %H:%M:%S,%N',
			'%Y/%m/%d %H:%M:%S']}), encoding='utf-8')
		return str(p)

	def test_map_of_several_layouts(self, tmp_path):
		items = [('t1', '$(MMM dd HH:mm:ss) $,$//$//$ $:$:$,TRAFFIC,$.$.$.$,$,site//a'),
			('s1', '$(MMM dd HH:mm:ss) $,$//$//$ $:$:$,SYSTEM,auth,user $ failed')]
		assert fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, items), '--target', self.target(tmp_path),
			'--addon', addon(tmp_path), '--out', str(tmp_path / 'fm')]) == 0
		rows = fm.read_lookup_file(str(tmp_path / 'fm' / 'lookups' / 'tenx_fw_fields.csv.gz'))
		names = dict((k, [n for n, _ in fm.parse_meta(r['f'])]) for k, r in rows.items())
		assert names['t1'][:5] == ['head', 'when', 'type', 'src', 'dst'] and 'misc' in names['t1']
		assert ['head', 'when', 'type', 'module', 'description'] == names['s1'][:5]
		props = (tmp_path / 'fm' / 'default' / 'props.conf').read_text(encoding='utf-8')
		# source is left as it is: no [source::] stanza and no index-time rule writes it
		assert '[source::' not in props and 'source:=' not in (tmp_path / 'fm' / 'default' / 'transforms.conf').read_text(
			encoding='utf-8')
		assert re.search(r'TRANSFORMS-tenx_fw = .*tenx_fw_rename\n', props)
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
		assert t['reader'] == 'csv' and fm.several(t)
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


class TestBlankColumns:
	def test_blank_columns_and_evals(self, tmp_path):
		p = tmp_path / 'target.json'
		p.write_text(json.dumps({'reader': 'csv', 'sourcetype': 'tenx_fw', 'rename': [TRAFFIC, SYSTEM, LOG]}),
			encoding='utf-8')
		# Values: the timestamp, 6 of the date and time, 4 of the address: 11, so the compact line fills 12 columns.
		items = [('t1', '$(MMM dd HH:mm:ss) $,$//$//$ $:$:$,TRAFFIC,$.$.$.$,,site//a')]
		assert fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, items), '--target', str(p),
			'--addon', addon(tmp_path), '--out', str(tmp_path / 'fm')]) == 0
		row = fm.read_lookup_file(str(tmp_path / 'fm' / 'lookups' / 'tenx_fw_fields.csv.gz'))['t1']['f']
		fields = dict(fm.parse_meta(row))
		assert fields[fm.BLANK_FIELD] == 'dst'
		props = (tmp_path / 'fm' / 'default' / 'props.conf').read_text(encoding='utf-8')
		assert 'EVAL-dst = if(match(tenx_blank, "(^| )(dst)( |$)"), null(), \'dst\')' in props
		assert '[source::' not in props
		transforms = (tmp_path / 'fm' / 'default' / 'transforms.conf').read_text(encoding='utf-8')
		assert 'source:=' not in transforms

	def test_add_on_rules_that_read_a_column_are_guarded(self, tmp_path):
		a = addon(tmp_path)
		with open(os.path.join(a, 'default', 'props.conf'), 'a', encoding='utf-8') as f:
			f.write('\n[%s]\nFIELDALIAS-url = misc AS url\nFIELDALIAS-type = when AS dst\nEVAL-who = coalesce(dst, "dst unknown")\n' % TRAFFIC)
		props, transforms = fm.read_addon(a)
		out = dict(fm.blank_overrides(props, transforms, TRAFFIC, ['head', 'when', 'type', 'src', 'dst', 'misc']))
		# the add-on's own calculated field, its column reference guarded, the literal kept
		# dst is overwritten by an alias from when, so its column no longer decides it
		assert out['EVAL-who'] == 'coalesce(if(match(tenx_blank, "(^| )(when)( |$)"), null(), \'dst\'), "dst unknown")'
		# fields an alias or a REPORT derives from a column are nulled with it
		assert out['EVAL-url'] == 'if(match(tenx_blank, "(^| )(misc)( |$)"), null(), \'url\')'
		assert out['EVAL-misc_host'] == 'if(match(tenx_blank, "(^| )(misc)( |$)"), null(), \'misc_host\')'
		assert out['EVAL-src'] == 'if(match(tenx_blank, "(^| )(src)( |$)"), null(), \'src\')'

	def test_tenx_blank_on_every_compact_event_and_a_reserved_column(self, tmp_path):
		a = addon(tmp_path)
		props, transforms = fm.read_addon(a)
		out = dict(fm.blank_overrides(props, transforms, TRAFFIC, ['head', 'when', 'timestamp', 'src'], 'extracted_'))
		# timestamp is written as extracted_timestamp; on a compact event that is the value, whatever the rule read
		assert out['EVAL-timestamp'] == "if(isnotnull(tenx_blank), 'extracted_timestamp', 'timestamp')"
		r = fm.BlankFieldReader(fm.CsvReader([(None, ['a', 'b'], ',')]), fm.CsvReader([(None, ['a', 'b'], ',')]))
		assert r.pairs('x,y') == [('a', 'x'), ('b', 'y'), (fm.BLANK_FIELD, '-')]
