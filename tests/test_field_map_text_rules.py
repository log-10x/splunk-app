"""
Tests for gen --addon: field-reading copies of the add-on rules that read the event's text.

A compact event's _raw is "~hash,values", so an add-on rule that reads _raw (no SOURCE_KEY) or a block that
another rule cuts out of _raw finds nothing on it. gen --addon reads the add-on's props.conf and
transforms.conf and writes, for each such rule, a copy that reads the field the map indexes for the same
text, in a class that sorts right after the rule's own. The add-on files here are written by the tests in
the shapes the Windows add-on uses; no add-on file is part of this repository.
"""
import io
import json
import os
import re
import ssl
import urllib.error
import urllib.request

import pytest

import tenx_field_map as fm


def write(path, text):
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, 'w', encoding='utf-8') as f:
		f.write(text)


PROPS = r"""
[XmlWinEventLog]
KV_MODE = none
REPORT-0xml_block_extract = sys_block, data_block
REPORT-0xml_kv_extract = sys_kv, data_kv
REPORT-EventCode_from_xml = EventID_field_as_EventCode, EventID_any_as_EventCode

[source::XmlWinEventLog:Security]
REPORT-dest_for_security = Server_as_dest, Computer_text_as_dest
REPORT-1ip_from_xml = ip_text_as_src_ip
REPORT-pid_from_xml = pid_from_data_block
REPORT-time_for_windows = time_text
REPORT-0dest_only_for_5156 = dest_text_5156
REPORT-words = account_words
REPORT-late_for_security = Computer_text_as_host_name, host_name_from_field
EVAL-src = case(EventCode IN (4727,4728), dest, true(), src)

[source::XmlWinEventLog:System]
REPORT-system_dest = Computer_text_as_dest

[source::...WindowsUpdate.Log]
REPORT-update = Computer_text_as_dest
"""

TRANSFORMS = r"""
[sys_block]
REGEX = (?ms)<System(?:\s+[^>]+)?>(.*?)<\/System>
FORMAT = System_Props_Xml::$1

[data_block]
REGEX = (?ms)<EventData(?:\s+[^>]+)?>(.*?)<\/EventData>
FORMAT = EventData_Xml::$1
MV_ADD = 1

[sys_kv]
SOURCE_KEY = System_Props_Xml
REGEX = (?ms)<(\w*)>([^<]*)<\/\1>
FORMAT = $1::$2

[data_kv]
SOURCE_KEY = EventData_Xml
REGEX = <(?:\w+)\sName='([^>]*)'\/?>([^<]*)(?:<\/\1>)?
FORMAT = $1::$2

[EventID_field_as_EventCode]
SOURCE_KEY = EventID
REGEX = (.+)
FORMAT = EventCode::$1

[EventID_any_as_EventCode]
REGEX = <EventID.*?>(.+?)<\/EventID>.*
FORMAT = EventCode::$1

[Server_as_dest]
SOURCE_KEY = TargetServerName
REGEX = (.+)
FORMAT = dest::"$1"

[Computer_text_as_dest]
REGEX = <Computer>([^<]+)<\/Computer>
FORMAT = dest::$1

[ip_text_as_src_ip]
REGEX = \<Data Name\=[}}\{\{'"]IpAddress['}}\{\{"]\>(?!\:\:1)(?!127\.0\.0\.1)(?<src_ip>[^\<]+)\<\/Data\>

[pid_from_data_block]
SOURCE_KEY = EventData_Xml
REGEX = <Data Name='(ProcessI(d|D))'>(?<process_id>[^<]+)<\/Data>

[time_text]
REGEX = <TimeCreated SystemTime='([^']+)'
FORMAT = event_time::$1

[dest_text_5156]
REGEX = (?ms)<EventID>(5156|5157)<\/EventID>.*<Data Name='DestAddress'>(?<dest>[^<]+)<\/Data>

[account_words]
REGEX = (?ms).*A user account was (.*?)[:\.]
FORMAT = account_action::"$1"

[Computer_text_as_host_name]
REGEX = <Computer>([^<]+)<\/Computer>
FORMAT = host_name::$1

[host_name_from_field]
SOURCE_KEY = Workstation
REGEX = (.+)
FORMAT = host_name::$1
"""


@pytest.fixture
def addon(tmp_path):
	d = tmp_path / 'TA_test'
	write(str(d / 'default' / 'props.conf'), PROPS)
	write(str(d / 'default' / 'transforms.conf'), TRANSFORMS)
	return str(d)


def copies_of(addon_dir, source='XmlWinEventLog:Security', seen=None):
	props, transforms = fm.read_addon(addon_dir)
	copies, report, _ = fm.text_rule_copies(props, transforms, 'XmlWinEventLog', source, 'tenx_win', seen)
	return copies, report


def derived_of(addon_dir):
	props, transforms = fm.read_addon(addon_dir)
	return fm.text_rule_copies(props, transforms, 'XmlWinEventLog', 'XmlWinEventLog:Security', 'tenx_win')[2]


def by_rule(copies):
	return dict(((c.rule, c.field), c) for c in copies)


def why(report, transform):
	return [x['why'] for x in report['not_copied'] if x['transform'] == transform]


class TestConfReading:
	def test_continued_values_comments_and_stanzas(self, tmp_path):
		p = tmp_path / 'props.conf'
		p.write_text('# comment\nTOP = 1\n[a]\nEVAL-x = case(a=1,\\\n  "b",\\\n  true(), "c")\n# k = v\nREPORT-y = t1, t2\n'
			'[source::a:b]\nk = v = w\n', encoding='utf-8')
		conf = fm.read_splunk_conf(str(p))
		assert conf['default'] == {'TOP': '1'}
		assert conf['a']['EVAL-x'] == 'case(a=1,\n  "b",\n  true(), "c")' and conf['a']['REPORT-y'] == 't1, t2'
		assert conf['source::a:b'] == {'k': 'v = w'}
		assert fm.read_splunk_conf(str(tmp_path / 'missing.conf')) == {}

	def test_local_settings_replace_default_ones_key_by_key(self, addon):
		write(os.path.join(addon, 'local', 'transforms.conf'), '[Computer_text_as_dest]\nSOURCE_KEY = Computer\nREGEX = (.+)\n')
		_, transforms = fm.read_addon(addon)
		assert transforms['Computer_text_as_dest'] == {'REGEX': '(.+)', 'FORMAT': 'dest::$1', 'SOURCE_KEY': 'Computer'}

	def test_an_addon_folder_without_props_is_refused(self, tmp_path):
		with pytest.raises(ValueError):
			fm.read_addon(str(tmp_path))

	@pytest.mark.parametrize('pattern, source, matches', [
		('XmlWinEventLog:Security', 'XmlWinEventLog:Security', True),
		('XmlWinEventLog:Security', 'XmlWinEventLog:System', False),
		('...WindowsUpdate.Log', 'C:\\Windows\\WindowsUpdate.Log', True),
		('...WindowsUpdate.Log', 'XmlWinEventLog:Security', False),
		('(WMI:WinEventLog|WinEventLog)...', 'WinEventLog:Security', True),
		('(WMI:WinEventLog|WinEventLog)...', 'XmlWinEventLog:Security', False),
		('*:Security', 'XmlWinEventLog:Security', True),
		('*:Security', 'a/b:Security', False),
	])
	def test_source_patterns(self, pattern, source, matches):
		assert fm.source_pattern_matches(pattern, source) is matches


class TestRegexReading:
	def test_the_fixed_language_of_a_pattern(self):
		assert fm.regex_language("<Data Name='(ProcessI(d|D))'>") == ["<Data Name='ProcessID'>", "<Data Name='ProcessId'>"]
		# an optional or repeated part takes its fewest repetitions
		assert fm.regex_language('<EventID.*?>') == ['<EventID>']
		assert fm.regex_language('(?ms)<System(?:\\s+[^>]+)?>') == ['<System>']
		assert fm.regex_language("<a[bc]{2}>") == ['<abb>', '<abc>', '<acb>', '<acc>']
		assert fm.regex_language('<a>.+') is None and fm.regex_language('[^<]') is None
		assert fm.regex_language('(') is None

	def test_groups_and_top_level_pieces(self):
		src = "<Data Name='(ProcessI(d|D))'>(?<process_id>[^<]+)<\\/Data>"
		groups, pieces = fm.regex_pieces(src)
		assert [(g[2], g[3], g[4]) for g in groups] == [('capture', 1, None), ('capture', 2, None), ('capture', 3, 'process_id')]
		g = groups[2]
		assert src[g[0]:g[1]] == '(?<process_id>[^<]+)' and (g[0], g[1]) in pieces
		_, pieces = fm.regex_pieces('(?ms)a[b\\]c]*(?!x)(y)+\\<')
		texts = [('(?ms)a[b\\]c]*(?!x)(y)+\\<')[a:b] for a, b in pieces]
		assert texts == ['(?ms)', 'a', '[b\\]c]*', '(?!x)', '(y)+', '\\<']


class TestCopies:
	def test_rules_that_read_one_item_get_a_copy_reading_its_field(self, addon):
		copies, report = copies_of(addon)
		got = by_rule(copies)
		c = got[('Computer_text_as_dest', 'Computer')]
		assert (c.stanza, c.cls, c.name, c.source_key, c.regex, c.format) == ('source::XmlWinEventLog:Security',
			'dest_for_security-tenx_win', 'tenx_win_text_Computer_text_as_dest', 'Computer', '\\A([^<]+)\\z', 'dest::$1')
		# the lookaheads before the value stay with it; the class of [}}{{'"] around the name reads as quotes
		c = got[('ip_text_as_src_ip', 'IpAddress')]
		assert c.regex == '\\A(?!\\:\\:1)(?!127\\.0\\.0\\.1)(?<src_ip>[^\\<]+)\\z' and c.format == ''
		# a block SOURCE_KEY: a Data value in EventData; the name's groups do not shift the named group
		c = got[('pid_from_data_block', 'ProcessId')]
		assert (c.source_key, c.regex, c.kind) == ('ProcessId', '\\A(?<process_id>[^<]+)\\z', 'data')
		# an attribute: the element of the rule is kept for the check, the field is the attribute
		c = got[('time_text', 'SystemTime')]
		assert (c.kind, c.source_key, c.format) == ('attribute', 'SystemTime', 'event_time::$1')
		# a rule of the sourcetype stanza goes to the sourcetype stanza; an element read with optional attributes
		c = got[('EventID_any_as_EventCode', 'EventID')]
		assert (c.stanza, c.cls, c.regex) == ('XmlWinEventLog', 'EventCode_from_xml-tenx_win', '\\A(.+?)\\z')
		assert report['stanzas'] == ['XmlWinEventLog', 'source::XmlWinEventLog:Security']
		assert report['blocks'] == {'System_Props_Xml': 'System', 'EventData_Xml': 'EventData'}

	def test_rules_that_are_not_copied_say_why(self, addon):
		copies, report = copies_of(addon)
		names = set(c.rule for c in copies)
		for t in ('sys_block', 'data_block', 'sys_kv', 'data_kv', 'Server_as_dest', 'EventID_field_as_EventCode',
				'Computer_text_as_host_name'):
			assert t not in names
		assert why(report, 'sys_block') == ['writes the whole text of element System as System_Props_Xml; the map writes '
			'the items the reader reads, not whole elements']
		assert why(report, 'sys_kv') == ['takes field names from the text; the map writes those fields itself']
		# a later transform of the same class writes the same field: a copy after the class would come too late
		assert 'later transform of its class (host_name_from_field)' in why(report, 'Computer_text_as_host_name')[0]
		# ProcessID is an attribute of every event's System block (Execution), so a Data ProcessID copy is refused
		assert any('System block holds ProcessID as an attribute' in w for w in why(report, 'pid_from_data_block'))

	def test_rules_of_more_than_one_item_get_a_copy_of_a_field_written_per_template(self, addon):
		copies, report = copies_of(addon)
		got = dict(((c.rule, c.kind), c) for c in copies)
		# a condition on a second item (the EventID), and free text around a lazy group
		c = got[('dest_text_5156', 'template')]
		assert (c.stanza, c.cls, c.name, c.source_key, c.regex, c.format) == ('source::XmlWinEventLog:Security',
			'0dest_only_for_5156-tenx_win', 'tenx_win_text_dest_text_5156_dest', 'tenx_win_fr_dest_text_5156_dest',
			'\\A([\\s\\S]*)\\z', 'dest::$1')
		assert got[('account_words', 'template')].source_key == 'tenx_win_fr_account_words_account_action'
		entry = [x for x in report['copied'] if x['transform'] == 'dest_text_5156'][0]
		assert 'not one item' in entry['why_per_template']
		# the item no copy reads (Data ProcessID) is covered per template, after the copy of ProcessId
		pid = [c for c in copies if c.rule == 'pid_from_data_block']
		assert [(c.kind, c.source_key) for c in pid] == [('data', 'ProcessId'),
			('template', 'tenx_win_fr_pid_from_data_block_process_id')]
		rule = [d for d in derived_of(addon) if d.rule == 'pid_from_data_block'][0]
		assert rule.covered == ('ProcessId',) and rule.block is not None
		# rules that read fields are not considered at all
		assert not why(report, 'Server_as_dest') and not why(report, 'EventID_field_as_EventCode')

	def test_only_the_stanzas_that_apply_are_read(self, addon):
		copies, report = copies_of(addon, source='XmlWinEventLog:System')
		assert [(c.stanza, c.rule) for c in copies if c.stanza != 'XmlWinEventLog'] == [
			('source::XmlWinEventLog:System', 'Computer_text_as_dest')]
		copies, _ = copies_of(addon, source=None)
		assert set(c.stanza for c in copies) == {'XmlWinEventLog'}

	def test_each_copy_runs_right_after_the_rule_s_class(self, addon):
		props, _ = fm.read_addon(addon)
		copies, _ = copies_of(addon)
		classes = sorted(set(k[len('REPORT-'):] for st in props.values() for k in st if k.startswith('REPORT-')) |
			set(c.cls for c in copies))
		for c in copies:
			rule_cls = c.cls[:-len('-tenx_win')]
			assert classes.index(c.cls) == classes.index(rule_cls) + 1

	def test_a_class_of_the_addon_between_the_rule_and_its_copy_refuses_the_copy(self, addon):
		with open(os.path.join(addon, 'default', 'props.conf'), 'a', encoding='utf-8') as f:
			f.write('\n[source::XmlWinEventLog:Security]\nREPORT-dest_for_security-a = Server_as_dest\n')
		copies, report = copies_of(addon)
		assert ('Computer_text_as_dest', 'Computer') not in by_rule(copies)
		assert 'dest_for_security-a of the add-on sorts between' in why(report, 'Computer_text_as_dest')[0]

	def test_a_value_not_enclosed_by_fixed_markup_gets_no_copy(self, tmp_path):
		d = tmp_path / 'TA'
		write(str(d / 'default' / 'props.conf'), '[X]\nREPORT-a = digits\n')
		# the rule reads the leading digits of a longer value; the copy, anchored at both ends, would not
		write(str(d / 'default' / 'transforms.conf'), "[digits]\nREGEX = <Data Name='N'>(?<n>\\d+)\\D*<\\/Data>\nFORMAT =\n")
		props, transforms = fm.read_addon(str(d))
		copies, report, _ = fm.text_rule_copies(props, transforms, 'X')
		# no copy reading one field; a copy of a field written per template instead
		assert [c.kind for c in copies] == ['template']
		assert report['copied'][0]['why_per_template'] == 'the value is not enclosed by fixed text on both sides'
		write(str(d / 'default' / 'transforms.conf'), "[digits]\nREGEX = <Data Name='N'>(?<n>[0-9]{2})<\\/Data>\n")
		props, transforms = fm.read_addon(str(d))
		copies, report, _ = fm.text_rule_copies(props, transforms, 'X')
		assert len(copies) == 1 and copies[0].regex == '\\A(?<n>[0-9]{2})\\z'

	def test_an_earlier_rule_without_a_one_field_copy_is_a_warning(self, addon):
		# dest_text_5156 sorts before dest_for_security and writes dest on 5156 events; with EventID a compact value its
		# per-template copy cannot fire, and the Computer copy then gives those events the Computer
		_, report = copies_of(addon)
		assert any(w.startswith('dest: on the events where dest_text_5156 gives dest') and
			'tenx_win_text_Computer_text_as_dest gives the element Computer instead' in w for w in report['warnings'])

	def test_templates_holding_the_name_as_another_item_are_a_warning(self, addon):
		copies, report = copies_of(addon, seen={'Computer': {'element': 1, 'data': 1}})
		assert ('Computer_text_as_dest', 'Computer') in by_rule(copies)
		assert 'tenx_win_text_Computer_text_as_dest reads element Computer, which templates also hold as data (up to 1 in one ' \
			'template)' in report['warnings']


def xml_event(computer='host1.example.local', ip='10.0.1.14', extra=''):
	return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='P'/>"
		"<EventID>4624</EventID><TimeCreated SystemTime='2023-10-13T00:35:42.412381800Z'/>"
		"<Execution ProcessID='4' ThreadID='8'/><Computer>%s</Computer></System><EventData>"
		"<Data Name='IpAddress'>%s</Data><Data Name='ProcessId'>0x3c8</Data>%s</EventData></Event>" % (computer, ip, extra))


class TestCopiesAgainstRules:
	"""Each copy on the reader's fields of an event gives what its rule gives on the event's text."""

	@pytest.mark.parametrize('ip', ['10.0.1.14', '::1', '127.0.0.1', '-', 'fe80::1'])
	def test_on_whole_events(self, addon, ip):
		props, transforms = fm.read_addon(addon)
		copies, _, _ = fm.text_rule_copies(props, transforms, 'XmlWinEventLog', 'XmlWinEventLog:Security', 'tenx_win')
		copies = [c for c in copies if c.kind != 'template']
		raw = xml_event(ip=ip)
		fields = dict((n, v.strip()) for n, v in fm.XmlWindowsReader().pairs(raw))
		blocks = {'System_Props_Xml': re.search(r'(?ms)<System(?:\s+[^>]+)?>(.*?)</System>', raw).group(1),
			'EventData_Xml': re.search(r'(?ms)<EventData(?:\s+[^>]+)?>(.*?)</EventData>', raw).group(1)}
		for c in copies:
			rule = transforms[c.rule]
			sk = rule.get('SOURCE_KEY', '_raw')
			text = raw if sk == '_raw' else blocks[sk]
			want = fm.report_outputs(fm._python_regex(rule['REGEX']), rule.get('FORMAT', ''), text) or {}
			got = {}
			if c.source_key in fields:
				got = fm.report_outputs(fm._python_regex(c.regex).replace('\\z', '\\Z'), c.format, fields[c.source_key]) or {}
			assert got == want, c.name


def marked(text):
	# a template's marked text: $k for compact value k
	return re.sub(r'\$(\d+)', lambda m: fm.MARK % int(m.group(1)), text)


class TestPerTemplate:
	def rules(self, addon):
		return dict((d.rule, d) for d in derived_of(addon))

	def test_a_condition_in_template_text_gives_the_value_s_field(self, addon):
		rule = self.rules(addon)['dest_text_5156']
		text = marked("<System><EventID>5156</EventID><Computer>$1</Computer></System><EventData>"
			"<Data Name='SourceAddress'>$2</Data><Data Name='DestAddress'>$3</Data></EventData>")
		assert fm.derive_pairs(rule, text) == ([('tenx_win_fr_dest_text_5156_dest', fm.MARK % 3)], False)
		# another EventID: no field; the EventID a value of the template: the condition cannot be read, no field
		assert fm.derive_pairs(rule, text.replace('5156', '4624')) == ([], False)
		assert fm.derive_pairs(rule, text.replace('5156', fm.MARK % 4)) == ([], False)

	def test_a_result_that_depends_on_the_values_is_left_out(self, tmp_path):
		d = tmp_path / 'TA'
		write(str(d / 'default' / 'props.conf'), '[X]\nREPORT-a = r\n')
		# the lookahead looks at a value: on "x" the rule does not match, on the marker it does
		write(str(d / 'default' / 'transforms.conf'), "[r]\nREGEX = (?ms)<A>(?!x)[^<]*</A>.*<Data Name='B'>(?<b>[^<]+)</Data>\n")
		props, transforms = fm.read_addon(str(d))
		_, _, derived = fm.text_rule_copies(props, transforms, 'X')
		text = marked("<A>$1</A><Data Name='B'>$2</Data>")
		assert fm.derive_pairs(derived[0], text) == ([], True)
		assert fm.derive_pairs(derived[0], marked("<A>y</A><Data Name='B'>$2</Data>")) == (
			[('tenx_fm_fr_r_b', fm.MARK % 2)], False)

	def test_the_reader_adds_the_fields_after_its_own_and_counts(self, addon):
		reader = fm.TextRuleReader(fm.XmlWindowsReader(), derived_of(addon))
		text = marked("<Event><System><EventID>5156</EventID></System><EventData><Data Name='ProcessID'>$1</Data>"
			"<Data Name='DestAddress'>$2</Data></EventData></Event>")
		pairs = reader.pairs(text)
		assert pairs[:3] == fm.XmlWindowsReader().pairs(text)
		assert ('tenx_win_fr_dest_text_5156_dest', fm.MARK % 2) in pairs
		assert ('tenx_win_fr_pid_from_data_block_process_id', fm.MARK % 1) in pairs
		assert reader.written['dest_text_5156'] == 1 and reader.written['pid_from_data_block'] == 1
		# ProcessId is read by the rule's own copy: no field of its own
		text2 = marked("<Event><System><EventID>4624</EventID></System><EventData><Data Name='ProcessId'>$1</Data>"
			"</EventData></Event>")
		assert not [p for p in reader.pairs(text2) if p[0].startswith('tenx_win_fr_')]
		assert reader.name == 'xml-windows' and reader.trims_values


class TestGenerated:
	def records(self, tmp_path):
		p = tmp_path / 'templates.json'
		t = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='P'/>"
			"<EventID>4624</EventID><TimeCreated SystemTime='$(yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z')'/>"
			"<Execution ProcessID='$' ThreadID='$'/><Computer>$</Computer></System><EventData>"
			"<Data Name='IpAddress'>$</Data><Data Name='ProcessId'>$</Data></EventData></Event>")
		p.write_text(json.dumps({'templateHash': 'h1', 'template': t.replace('/', '//')}) + '\n', encoding='utf-8')
		return str(p)

	def gen(self, tmp_path, *extra, out='fm_win'):
		err = io.StringIO()
		import sys
		old, sys.stderr = sys.stderr, err
		try:
			rc = fm.main(['gen', '--records', self.records(tmp_path), '--target', 'windows-security', '--rules', 'lookup',
				'--out', str(tmp_path / out)] + list(extra))
		finally:
			sys.stderr = old
		return rc, tmp_path / out, err.getvalue()

	def test_a_template_the_per_template_rule_matches_gets_the_field_in_its_row(self, tmp_path, addon):
		p = tmp_path / 'wfp.json'
		t = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5156</EventID>"
			"<TimeCreated>$(HH:mm:ss)</TimeCreated><Computer>$</Computer></System><EventData><Data Name='ProcessID'>$</Data>"
			"<Data Name='DestAddress'>$</Data></EventData></Event>")
		# the template record writes a "/" of the text as "//"
		p.write_text(json.dumps({'templateHash': 'w1', 'template': t.replace('/', '//')}) + '\n', encoding='utf-8')
		out = tmp_path / 'fm_wfp'
		assert fm.main(['gen', '--records', str(p), '--target', 'windows-security', '--rules', 'lookup', '--out', str(out),
			'--addon', addon]) == 0
		row = fm.read_lookup_file(str(out / 'lookups' / 'tenx_win_fields.csv.gz'))['w1']
		assert 'tenx_win_fr_dest_text_5156_dest::' in row['f'] and 'tenx_win_fr_pid_from_data_block_process_id::' in row['f']
		report = json.load(open(str(tmp_path / 'fm_wfp_report.json'), encoding='utf-8'))['addon_rules_reading_text']
		c = [x for x in report['copied'] if x['transform'] == 'dest_text_5156'][0]
		assert c['templates_written'] == 1 and c['templates_left_out_value_dependent'] == 0

	def test_gen_writes_the_copies_into_props_and_transforms(self, tmp_path, addon):
		rc, out, err = self.gen(tmp_path, '--addon', addon)
		assert rc == 0 and err == ''
		props = open(str(out / 'default' / 'props.conf'), encoding='utf-8').read()
		transforms = open(str(out / 'default' / 'transforms.conf'), encoding='utf-8').read()
		head, sec = props.split('\n[source::XmlWinEventLog:Security]\n', 1)
		assert 'REPORT-tenx_win_hash_vars = tenx_win_hash_vars\n' in head.split('[XmlWinEventLog]\n', 1)[1]
		assert 'REPORT-EventCode_from_xml-tenx_win = tenx_win_text_EventID_any_as_EventCode\n' in head
		assert 'REPORT-dest_for_security-tenx_win = tenx_win_text_Computer_text_as_dest\n' in sec
		assert 'REPORT-1ip_from_xml-tenx_win = tenx_win_text_ip_text_as_src_ip\n' in sec
		assert '[tenx_win_text_Computer_text_as_dest]\nSOURCE_KEY = Computer\nREGEX = \\A([^<]+)\\z\nFORMAT = dest::$1\n' in transforms
		report = json.load(open(str(tmp_path / 'fm_win_report.json'), encoding='utf-8'))['addon_rules_reading_text']
		assert len(report['copied']) == len(fm.read_conf(str(out / 'default' / 'transforms.conf'))) - 4
		# the generated files read back as Splunk's conf files
		conf = fm.read_conf(str(out / 'default' / 'props.conf'))
		assert conf['source::XmlWinEventLog:Security']['REPORT-time_for_windows-tenx_win'] == 'tenx_win_text_time_text'

	def test_the_lookup_and_index_time_rule_do_not_change(self, tmp_path, addon):
		_, a, _ = self.gen(tmp_path, out='a')
		_, b, _ = self.gen(tmp_path, '--addon', addon, out='b')
		for rel in ('lookups/tenx_win_fields.csv.gz',):
			assert open(str(a / rel), 'rb').read() == open(str(b / rel), 'rb').read()
		ta, tb = (fm.read_conf(str(x / 'default' / 'transforms.conf')) for x in (a, b))
		assert all(tb[k] == v for k, v in ta.items())
		pa, pb = (fm.read_conf(str(x / 'default' / 'props.conf')) for x in (a, b))
		assert pa['tenx_win'] == pb['tenx_win']

	def test_without_addon_gen_says_what_is_missing(self, tmp_path):
		rc, _, err = self.gen(tmp_path)
		assert rc == 0 and 'without --addon' in err and '--addon <the add-on\'s folder>' in err

	def test_a_bad_addon_folder_stops_gen(self, tmp_path):
		rc, out, err = self.gen(tmp_path, '--addon', str(tmp_path / 'nothing'))
		assert rc == 2 and err.startswith('gen: --addon: no props.conf') and not os.path.exists(str(out))

	def test_another_reader_reports_the_rules_and_copies_none(self, tmp_path, addon):
		p = tmp_path / 'ct.json'
		p.write_text(json.dumps({'templateHash': 'h1', 'template': '{"eventName": "$", "errorMessage": "$"}'}) + '\n',
			encoding='utf-8')
		rc = fm.main(['gen', '--records', str(p), '--reader', 'json', '--sourcetype', 'tenx_x', '--rename', 'XmlWinEventLog',
			'--rules', 'lookup', '--out', str(tmp_path / 'fm_x'), '--addon', addon])
		assert rc == 0
		report = json.load(open(str(tmp_path / 'fm_x_report.json'), encoding='utf-8'))['addon_rules_reading_text']
		assert report['copied'] == [] and any('the json reader has no copies' in x['why'] for x in report['not_copied'])
		assert '_text_' not in open(str(tmp_path / 'fm_x' / 'default' / 'transforms.conf'), encoding='utf-8').read()


class TestCertificateFailure:
	def test_a_certificate_that_does_not_verify_is_one_line(self, tmp_path, monkeypatch, capsys):
		records = tmp_path / 'templates.json'
		records.write_text(json.dumps({'templateHash': 'h', 'template': 'user=$ n=1'}) + '\n', encoding='utf-8')
		cap = tmp_path / 'cap.csv'
		assert fm.main(['gen', '--rules', 'lookup', '--records', str(records), '--reader', 'kv', '--sourcetype', 'tenx_fw',
			'--rename', 'fw:traffic', '--out', str(tmp_path / 'fm_fw'), '--cap-file', str(cap)]) == 0
		capsys.readouterr()

		def refuse(req, context=None, timeout=None):
			raise urllib.error.URLError(ssl.SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify '
				'failed: self-signed certificate in certificate chain (_ssl.c:1000)'))
		monkeypatch.setattr(urllib.request, 'urlopen', refuse)
		for mode in ('activate', 'check'):
			if mode == 'check':
				# check probes a listed template
				cap.write_text(fm.cap_text({'h'}), encoding='utf-8')
			rc = fm.main([mode, '--app', str(tmp_path / 'fm_fw'), '--cap-file', str(cap), '--splunkd',
				'https://splunk.example:8089', '--probe-index', 'p'])
			err = capsys.readouterr().err
			assert rc == 1
			assert err.count('\n') == 1 and 'Traceback' not in err
			assert err.startswith('%s: the certificate of https://splunk.example:8089 did not verify (' % mode)
			assert '; add --tls-ca-file with the PEM file of the authority that signed it, or, for an instance' in err
			assert err.rstrip().endswith('--tls-verify off')

	def test_other_failures_are_not_changed(self, monkeypatch):
		def down(req, context=None, timeout=None):
			raise urllib.error.URLError(ConnectionRefusedError(111, 'Connection refused'))
		monkeypatch.setattr(urllib.request, 'urlopen', down)
		with pytest.raises(urllib.error.URLError):
			fm.Splunkd('https://splunk.example:8089').call('GET', '/services/server/info')


def _openssl(*args, cwd=None):
	import subprocess
	subprocess.run(['openssl'] + list(args), cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def tls_server(tmp_path):
	"""An HTTPS server on 127.0.0.1 with a certificate for 127.0.0.1 signed by a CA made here: (url, CA file,
	another CA file)."""
	import shutil
	import subprocess
	import threading
	from http.server import BaseHTTPRequestHandler, HTTPServer
	if shutil.which('openssl') is None:
		pytest.skip('no openssl')
	d = str(tmp_path)
	for name in ('ca', 'other'):
		_openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.pem',
			'-days', '2', '-subj', '/CN=test %s' % name, '-addext', 'basicConstraints=critical,CA:TRUE',
			'-addext', 'keyUsage=critical,keyCertSign,cRLSign', cwd=d)
	(tmp_path / 'ext.cnf').write_text('subjectAltName = IP:127.0.0.1\nbasicConstraints = CA:FALSE\n'
		'keyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\n'
		'authorityKeyIdentifier = keyid,issuer\nsubjectKeyIdentifier = hash\n', encoding='utf-8')
	_openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'srv.key', '-out', 'srv.csr', '-subj', '/CN=127.0.0.1',
		cwd=d)
	_openssl('x509', '-req', '-in', 'srv.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'srv.pem',
		'-days', '2', '-extfile', 'ext.cnf', cwd=d)

	class Handler(BaseHTTPRequestHandler):
		def do_GET(self):
			body = json.dumps({'entry': [{'name': 'server-info'}]}).encode('utf-8')
			self.send_response(200)
			self.send_header('Content-Type', 'application/json')
			self.send_header('Content-Length', str(len(body)))
			self.end_headers()
			self.wfile.write(body)

		def log_message(self, *a):
			pass

	server = HTTPServer(('127.0.0.1', 0), Handler)
	ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
	ctx.load_cert_chain(os.path.join(d, 'srv.pem'), os.path.join(d, 'srv.key'))
	server.socket = ctx.wrap_socket(server.socket, server_side=True)
	t = threading.Thread(target=server.serve_forever, daemon=True)
	t.start()
	try:
		yield 'https://127.0.0.1:%d' % server.server_address[1], os.path.join(d, 'ca.pem'), os.path.join(d, 'other.pem')
	finally:
		server.shutdown()
		server.server_close()


class TestCaFile:
	def test_a_certificate_signed_by_the_given_authority_verifies(self, tls_server):
		url, ca, _ = tls_server
		got = fm.Splunkd(url, ca_file=ca).call('GET', '/services/server/info')
		assert got['entry'][0]['name'] == 'server-info'

	def test_without_it_the_same_certificate_does_not_verify(self, tls_server):
		url, _, _ = tls_server
		with pytest.raises(fm.TlsVerifyError):
			fm.Splunkd(url).call('GET', '/services/server/info')

	def test_another_authority_does_not_verify_it(self, tls_server):
		url, _, other = tls_server
		with pytest.raises(fm.TlsVerifyError):
			fm.Splunkd(url, ca_file=other).call('GET', '/services/server/info')

	def test_the_option_reaches_the_connection(self, tmp_path):
		args = fm.build_parser().parse_args(['check', '--app', 'a', '--cap-file', 'c', '--splunkd', 'https://h:8089',
			'--tls-ca-file', str(tmp_path / 'missing.pem')])
		assert args.tls_ca_file == str(tmp_path / 'missing.pem')
		with pytest.raises((FileNotFoundError, ssl.SSLError, OSError)):
			fm._splunkd(args)
