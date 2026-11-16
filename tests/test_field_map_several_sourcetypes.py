"""
The field map for a source whose add-on keeps its rules under several sourcetypes (FortiGate: fortigate_traffic,
fortigate_utm, fortigate_event, fortigate_anomaly), the classic Windows reader, and the DELIMS reader's unterminated
quote. What Splunk does with the generated files was measured on Splunk Enterprise 10.4.3 (see the tool's docstring,
"Several original sourcetypes"); these tests pin what gen writes.
"""
import json
import os

import tenx_field_map as fm

TPL_TRAFFIC = 'date=$$$ time=$(HH:mm:ss) devname="$" type="traffic" subtype="forward" srcip=$ action="$"'
TPL_UTM = 'date=$$$ time=$(HH:mm:ss) devname="$" type="utm" subtype="webfilter" eventtype="$" url="$"'


def read(p):
	with open(str(p), encoding='utf-8') as f:
		return f.read()


def records(tmp_path, items):
	p = tmp_path / 'templates.json'
	p.write_text(''.join(json.dumps({'templateHash': h, 'template': t}) + '\n' for h, t in items), encoding='utf-8')
	return str(p)


def gen(tmp_path, *extra, **kw):
	items = kw.get('items', (('k1', TPL_TRAFFIC), ('k2', TPL_UTM)))
	return fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, items), '--out', str(tmp_path / 'fm_fgt')]
		+ list(extra))


class TestFortigateTarget:
	def test_one_map_writes_the_sourcetype_rule_and_no_rename(self, tmp_path, capsys):
		assert gen(tmp_path, '--target', 'fortigate') == 0
		props = read(tmp_path / 'fm_fgt' / 'default' / 'props.conf')
		assert 'TRANSFORMS-tenx_fgt = tenx-event-time, tenx_fgt_sourcetype, tenx_fgt_fields_eval, tenx_fgt_rename\n' in props
		assert '\nrename = ' not in props
		for st in ('fortigate_traffic', 'fortigate_utm', 'fortigate_event', 'fortigate_anomaly'):
			stanza = props.split('[%s]\n' % st)[1].split('\n[')[0]
			assert 'REPORT-tenx_fm_hash_vars = tenx_fm_hash_vars\n' in stanza
			assert 'REPORT-tenx_fm_restore = tenx_fm_restore_eventtype' in stanza
		transforms = read(tmp_path / 'fm_fgt' / 'default' / 'transforms.conf')
		assert ('[tenx_fgt_rename]\nSOURCE_KEY = field:tenx_sourcetype\n'
			'REGEX = ^(fortigate_traffic|fortigate_utm|fortigate_event|fortigate_anomaly)$\n'
			'DEST_KEY = MetaData:Sourcetype\nFORMAT = sourcetype::$1\n') in transforms
		out = capsys.readouterr().out
		assert 'sender: set tenx_sourcetype on every event of tenx_fgt to its original sourcetype' in out

	def test_the_target_carries_the_time_rule_and_restores_eventtype(self, tmp_path):
		assert gen(tmp_path, '--target', 'fortigate') == 0
		report = json.loads(read(tmp_path / 'fm_fgt_report.json'))
		assert report['event_time']['rule']['prefix'] == r'\bdate=' and report['event_time']['templates_with_rule'] == 2
		assert report['reserved_field_names']['templates_per_name'] == {'eventtype': 1}
		row = fm.read_lookup_file(str(tmp_path / 'fm_fgt' / 'lookups' / 'tenx_fgt_fields.csv.gz'))['k2']
		assert 'extracted_eventtype::"' in row['f'] and row['w']

	def test_the_command_line_takes_several_sourcetypes_and_a_field(self, tmp_path):
		assert gen(tmp_path, '--reader', 'delims', '--sourcetype', 'tenx_fw', '--rename', 'fw:traffic, fw:threat',
			'--rename-field', 'fw_type') == 0
		transforms = read(tmp_path / 'fm_fgt' / 'default' / 'transforms.conf')
		assert 'SOURCE_KEY = field:fw_type\nREGEX = ^(fw:traffic|fw:threat)$\n' in transforms

	def test_one_sourcetype_is_written_as_before(self, tmp_path):
		assert gen(tmp_path, '--reader', 'delims', '--sourcetype', 'tenx_fgt', '--rename', 'fortigate_traffic') == 0
		props = read(tmp_path / 'fm_fgt' / 'default' / 'props.conf')
		assert 'rename = fortigate_traffic\n' in props and '_rename' not in props
		assert 'SOURCE_KEY = field:' not in read(tmp_path / 'fm_fgt' / 'default' / 'transforms.conf')

	def test_several_sourcetypes_need_the_sourcetype_field(self, tmp_path, capsys):
		assert gen(tmp_path, '--target', 'fortigate', '--sourcetype-field', 'none') == 2
		assert 'it cannot be none' in capsys.readouterr().err

	def test_names_the_rule_would_misread_are_refused(self, tmp_path, capsys):
		assert gen(tmp_path, '--reader', 'delims', '--sourcetype', 'tenx_fw', '--rename', 'a|b,c') == 2
		assert 'is not a sourcetype name' in capsys.readouterr().err

	def test_activate_and_check_find_the_map_and_its_field(self, tmp_path):
		assert gen(tmp_path, '--target', 'fortigate') == 0
		app = fm.lookup_app(str(tmp_path / 'fm_fgt'))
		assert app.sourcetype == 'tenx_fgt' and app.field == 'tenx_compact_st'
		assert app.table.endswith(os.path.join('lookups', 'tenx_fgt_fields.csv.gz'))

	def test_check_counts_events_stored_under_the_original_sourcetypes(self):
		class S(object):
			def search(self, q):
				self.q = q
				return []
		s = S()
		fm.unmapped_since(s, 'tenx_fgt', 0, 10, 'tenx_compact_st')
		assert '(sourcetype="tenx_fgt" OR tenx_compact_st="tenx_fgt")' in s.q
		fm.unmapped_since(s, 'tenx_win', 0, 10)
		assert ' sourcetype="tenx_win" ' in s.q


class TestDelimsUnterminatedQuote:
	def test_an_unterminated_quote_runs_to_the_end(self):
		# Splunk Enterprise 10.4.3, the FortiGate add-on's DELIMS: a line ending in msg="some text with key=value in it
		# gave msg without its quote and no field key.
		r = fm.DelimsReader()
		assert r.pairs('a=1 msg="some text with key=value in it') == [('a', '1'), ('msg', 'some text with key=value in it')]

	def test_a_closed_quote_is_read_as_before(self):
		assert fm.DelimsReader().pairs('a=1 msg="x y" b=2') == [('a', '1'), ('msg', 'x y'), ('b', '2')]


CLASSIC = ('11/07/2026 00:00:00 AM\nLogName=Security\nEventCode=4624\nEventType=0\nKeywords=Audit Success\n'
	'Message=An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n'
	'\nLogon Type:\t\t\t3\n\nNew Logon:\n\tAccount Name:\t\tbob\n\tLogon ID:\t\t0x1\n\nPrivileges:\n\t\t\tSeX\n')


class TestWindowsClassicReader:
	def test_header_and_message_lines(self):
		pairs = fm.WindowsClassicReader().pairs(CLASSIC)
		assert pairs[:4] == [('LogName', 'Security'), ('EventCode', '4624'), ('EventType', '0'),
			('Keywords', 'Audit Success')]
		assert ('Message', CLASSIC.split('Message=', 1)[1].rstrip('\n')) in pairs
		assert [p for p in pairs if p[0] == 'Account_Name'] == [('Account_Name', '-'), ('Account_Name', 'bob')]
		assert ('Logon_Type', '3') in pairs and ('Security_ID', 'NULL SID') in pairs and ('Logon_ID', '0x1') in pairs
		# a line with no value after the colon, and a line with no colon, give nothing
		assert not [p for p in pairs if p[0] in ('Subject', 'New_Logon', 'Privileges')]

	def test_names_are_cleaned_as_splunk_cleans_keys(self):
		assert fm.WindowsClassicReader.clean('\tAccount Name') == 'Account_Name'
		assert fm.WindowsClassicReader.clean('Logon GUID') == 'Logon_GUID'

	def test_text_without_a_message_line_gives_nothing(self):
		assert fm.WindowsClassicReader().pairs('11/07/2026 00:00:00 AM\nLogName=Security') == []

	def test_the_classic_target(self, tmp_path):
		tpl = CLASSIC.replace('bob', '$').replace('0x1', '$')
		assert fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, [('w1', tpl)]), '--target',
			'windows-security-classic', '--out', str(tmp_path / 'fm_w')]) == 0
		props = read(tmp_path / 'fm_w' / 'default' / 'props.conf')
		assert '[tenx_wincl]\n' in props and '\nrename = ' not in props and '[WinEventLog]\n' in props
		assert 'SOURCE_KEY = field:tenx_sourcetype\nREGEX = ^(WinEventLog)$\n' in read(tmp_path / 'fm_w' / 'default' / 'transforms.conf')
		row = fm.read_lookup_file(str(tmp_path / 'fm_w' / 'lookups' / 'tenx_wincl_fields.csv.gz'))['w1']['f']
		assert 'extracted_EventType::"0"' in row and row.count('Account_Name::"') == 2 and 'Account_Name::"-"' in row


class TestValueEndingInColons:
	def test_a_value_that_ends_with_two_colons_keeps_the_next_field(self):
		# FortiGate traffic with IPv6: transip=:: transport=0. The trim of a field's ends must not take the space after
		# the closing quote of "::" (Splunk Enterprise 10.4.3 read transip as "::transport::0" when it did).
		tpl = fm.Template(key='h', written_hash='h', parts=[], part_0='srcip=', terminator=' transip=:: transport=0',
			timestamp_format='', expand_unsafe='', pattern=None)
		field_map = fm.FieldMap({'h': tpl}, fm.DelimsReader(), 'p', rules=fm.RULES_LOOKUP, mark=fm.MARK_FIELD)
		[t] = field_map.transforms
		assert dict(fm.apply_lookup_row(t, '~h,10.0.0.1', trim=True)) == {'srcip': '10.0.0.1', 'transip': '::',
			'transport': '0'}
		rule = fm.lookup_eval_text('t', None, True)
		assert '[[:space:]]' not in rule and '"::" . urldecode("%22") . "[[:cntrl:]]+"' in rule

	def test_a_carriage_return_at_the_end_of_a_value_still_goes(self):
		tpl = fm.Template(key='h', written_hash='h', parts=[], part_0='a=', terminator=' b=1',
			timestamp_format='', expand_unsafe='', pattern=None)
		field_map = fm.FieldMap({'h': tpl}, fm.DelimsReader(), 'p', rules=fm.RULES_LOOKUP, mark=fm.MARK_FIELD)
		[t] = field_map.transforms
		assert dict(fm.apply_lookup_row(t, '~h,x\r', trim=True))['a'] == 'x'


class TestClassicWordRules:
	RULE = r'(?s)Process Information:.*?Process ID:\s+(?<process_id>\S+).*?(?:(?:\r*\n){2})'
	TEXT = ('Message=x\n\nProcess Information:\n\tProcess ID:\t\t' + fm.MARK % 3 + '\n\tProcess Name:\t\t' + fm.MARK % 4 +
		'\n\nEnd')

	def test_a_word_group_over_one_value_is_written_whole_and_cut_at_search_time(self):
		# The add-on's process_id rule reads (?<process_id>\S+); on raw text it stops at the value's first space. The
		# field carries the whole value and its copy reads \A(\S+), so a value with a space gives its first word as well.
		rule = fm.DerivedRule('p', fm._python_regex(self.RULE), None, [('process_id', 'process_id', 'f')], (),
			frozenset(['process_id']))
		assert fm.derive_pairs(rule, self.TEXT, fm.DERIVE_PROBES_NO_LINE_FEED) == ([('f', fm.MARK % 3)], False)
		assert fm.derive_pairs(rule._replace(words=frozenset()), self.TEXT, fm.DERIVE_PROBES_NO_LINE_FEED) == ([], True)

	def test_the_classic_target_writes_the_cutting_copy(self, tmp_path):
		addon = tmp_path / 'addon' / 'default'
		os.makedirs(str(addon))
		(addon / 'props.conf').write_text('[source::WinEventLog:Security]\nREPORT-pid = pid_rule\n', encoding='utf-8')
		(addon / 'transforms.conf').write_text('[pid_rule]\nREGEX = %s\n' % self.RULE, encoding='utf-8')
		tpl = ('11/07/2026 00:00:00 AM\nLogName=Security\nEventCode=4689\nMessage=x\n\nProcess Information:\n'
			'\tProcess ID:\t\t$\n\tProcess Name:\t\t$\n\nEnd')
		assert fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, [('w1', tpl)]), '--target',
			'windows-security-classic', '--addon', str(tmp_path / 'addon'), '--out', str(tmp_path / 'fm_w')]) == 0
		transforms = read(tmp_path / 'fm_w' / 'default' / 'transforms.conf')
		assert 'SOURCE_KEY = tenx_wincl_fr_pid_rule_process_id\nREGEX = \\A(\\S+)\nFORMAT = process_id::$1\n' in transforms
		row = fm.read_lookup_file(str(tmp_path / 'fm_w' / 'lookups' / 'tenx_wincl_fields.csv.gz'))['w1']['f']
		assert 'tenx_wincl_fr_pid_rule_process_id::"' in row


class TestSplitEscape:
	# The Receiver cuts a token at a backslash, so "abc\/def=" in a JSON string is text "abc", the backslash and a value
	# "/def=" (CloudTrail responseElements.credentials.sessionToken).
	def tpl(self):
		return fm.Template(key='h', written_hash='h', parts=['", "b": "x\\'], part_0='{"a": "', terminator='"}',
			timestamp_format='', expand_unsafe='', pattern=None)

	def test_the_field_is_written_and_decoded_with_the_value(self):
		field_map = fm.FieldMap({'h': self.tpl()}, fm.JsonReader(), 'p', rules=fm.RULES_LOOKUP, mark=fm.MARK_FIELD)
		[t] = field_map.transforms
		assert field_map.report()['fields_with_a_split_escape'] == {'b': 1}
		assert dict(fm.apply_lookup_row(t, '~h,1,/def=')) == {'a': '1', 'b': 'x/def='}
		# a line break or tab escape reads as a space, as in any indexed value
		assert dict(fm.apply_lookup_row(t, '~h,1,ndef')) == {'a': '1', 'b': 'x def'}
		# any other escape leaves the field out, not the event's other fields
		assert dict(fm.apply_lookup_row(t, '~h,1,u00e9')) == {'a': '1'}

	def test_the_transforms_rules_still_leave_it_out(self):
		field_map = fm.FieldMap({'h': self.tpl()}, fm.JsonReader(), 'p', mark=fm.MARK_FIELD)
		assert field_map.report()['skipped'] == {'value: ' + fm.WHY_SPLIT_ESCAPE: 1}

	def test_a_template_holding_the_marker_is_refused(self):
		t = fm.Template(key='h', written_hash='h', parts=[], part_0='{"a": "' + fm.SPLIT_ESCAPE, terminator='"}',
			timestamp_format='', expand_unsafe='', pattern=None)
		field_map = fm.FieldMap({'h': t}, fm.JsonReader(), 'p', rules=fm.RULES_LOOKUP, mark=fm.MARK_FIELD)
		assert field_map.transforms == [] and field_map.report()['templates_without_transform'] == {fm.REFUSED_SENTINEL: 1}


class TestLeaveOut:
	def test_named_fields_are_not_written(self, tmp_path):
		tpl = CLASSIC.replace('bob', '$')
		assert fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, [('w1', tpl)]), '--target',
			'windows-security-classic', '--leave-out', 'Message,Logon_ID', '--out', str(tmp_path / 'fm_w')]) == 0
		row = fm.read_lookup_file(str(tmp_path / 'fm_w' / 'lookups' / 'tenx_wincl_fields.csv.gz'))['w1']['f']
		assert 'Message::' not in row and 'Logon_ID::' not in row and 'Account_Name::"' in row

	def test_the_rule_matches_a_backslash_with_two(self):
		# Splunk Enterprise 10.4.3 refused the rule ("Regular expression error") with one backslash inside the class.
		rule = fm.lookup_eval_text('t', None, False)
		piece = [x for x in rule.split(', $pd') if fm.SPLIT_ESCAPE in x][0]
		assert 'urldecode("%5C%5C") . "]|" . urldecode("%5C%5C") . ".)*' in piece and 'urldecode("%5C") .' not in piece


class TestCimFields:
	def addon(self, tmp_path):
		a = tmp_path / 'addon' / 'default'
		os.makedirs(str(a))
		(a / 'props.conf').write_text('[fw:traffic]\nREPORT-kv = kv\nFIELDALIAS-src = srcip AS src\n'
			'EVAL-bytes = coalesce(rcvd + sent, 0)\nLOOKUP-act = act_lookup vendor_action OUTPUT action\n'
			'FIELDALIAS-va = act AS vendor_action\n', encoding='utf-8')
		(a / 'transforms.conf').write_text('[kv]\nDELIMS = " ", "="\n', encoding='utf-8')
		(a / 'eventtypes.conf').write_text('[fw_traffic]\nsearch = sourcetype=fw:traffic logid=13\n', encoding='utf-8')
		(a / 'tags.conf').write_text('[eventtype=fw_traffic]\nnetwork = enabled\ncommunicate = enabled\n', encoding='utf-8')
		c = tmp_path / 'cim' / 'default' / 'data' / 'models'
		os.makedirs(str(c))
		(c / 'Network_Traffic.json').write_text(json.dumps({'objects': [{'objectName': 'All_Traffic', 'parentName': 'BaseEvent',
			'constraints': [{'search': 'tag=network tag=communicate'}], 'fields': [{'fieldName': 'src'}, {'fieldName': 'bytes'},
			{'fieldName': 'action'}], 'calculations': []}]}), encoding='utf-8')
		(c / 'Email.json').write_text(json.dumps({'objects': [{'objectName': 'All_Email', 'parentName': 'BaseEvent',
			'constraints': [{'search': 'tag=email'}], 'fields': [{'fieldName': 'subject'}], 'calculations': []}]}), encoding='utf-8')
		return str(tmp_path / 'addon'), str(tmp_path / 'cim')

	def test_the_closure_over_the_add_on_rules(self, tmp_path):
		addon, cim = self.addon(tmp_path)
		needed = fm.needed_fields(addon, cim, ['fw:traffic'])
		assert {'src', 'srcip', 'bytes', 'rcvd', 'sent', 'action', 'vendor_action', 'act', 'logid'} <= needed
		# a model the add-on's tags never reach adds nothing
		assert 'subject' not in needed and 'time' not in needed

	def test_gen_writes_only_the_needed_fields(self, tmp_path):
		addon, cim = self.addon(tmp_path)
		tpl = 'logid=$ srcip=$ act=$ rcvd=$ sent=$ time=$ sessionid=$'
		assert fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, [('k', tpl)]), '--reader', 'delims',
			'--sourcetype', 'tenx_fw', '--rename', 'fw:traffic', '--fields', 'cim', '--addon', addon, '--cim', cim,
			'--out', str(tmp_path / 'fm')]) == 0
		row = fm.read_lookup_file(str(tmp_path / 'fm' / 'lookups' / 'tenx_fw_fields.csv.gz'))['k']['f']
		names = [n for n, _ in fm.parse_meta(row)]
		assert names == ['logid', 'srcip', 'act', 'rcvd', 'sent', 'tenx_mapped']

	def test_cim_needs_both_folders(self, tmp_path, capsys):
		assert fm.main(['gen', '--rules', 'lookup', '--records', records(tmp_path, [('k', 'a=$')]), '--reader', 'delims',
			'--sourcetype', 'tenx_fw', '--rename', 'fw:traffic', '--fields', 'cim', '--out', str(tmp_path / 'fm')]) == 2
		assert '--fields cim needs --addon and --cim' in capsys.readouterr().err
