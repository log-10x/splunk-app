"""
gen without --records: a field map's rules before the first event of its source.

Until a map is installed where its compact sourcetype is parsed, Splunk holds no stanza for that sourcetype, and the
map's index-time rules never run on an event indexed before: such a whole event keeps Splunk's default parsing (a
heavy forwarder that reads the Receiver's output folder merges its lines), keeps the compact sourcetype where the map
stores events under the add-on's (several targets), and lacks tenx_compact_st, so `tx` does not find it. gen without
--records writes the map with no template, so it can be installed before the first event; a later gen with the
records writes the same index-time rules and adds the template rows.
"""
import json
import os

import pytest

import tenx_field_map as fm

XML = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider "
	"Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><Computer>$</Computer></System><EventData>"
	"<Data Name='TargetUserName'>$</Data><Data Name='LogonType'>$</Data></EventData></Event>")
CLASSIC = ('11/07/2026 00:00:00 AM\nLogName=Security\nEventCode=4624\nEventType=0\nComputerName=$\n'
	'Message=An account was successfully logged on.\n\nNew Logon:\n\tAccount Name:\t\t$\n')
FGT = 'date=$$$ time=$(HH:mm:ss) devname="$" type="traffic" subtype="forward" srcip=$ action="$"'
PAN = '1,$,$,TRAFFIC,end,$,$'

TARGETS = {
	'windows-security': ('tenx_win', [], XML),
	'windows-security-classic': ('tenx_wincl', ['--mixed-names'], CLASSIC),
	'fortigate': ('tenx_fgt', ['--leave-out', 'time'], FGT),
	'palo-alto': ('tenx_pan', ['--columns', 'future_use1,receive_time,serial_number,type,log_subtype,src_ip,dest_ip'], PAN),
}


def write(path, text):
	os.makedirs(os.path.dirname(str(path)), exist_ok=True)
	with open(str(path), 'w', encoding='utf-8') as f:
		f.write(text)


def xml_addon(tmp_path):
	"""A synthetic add-on in the Windows add-on's shape: one search-time rule that reads the event's text."""
	d = tmp_path / 'TA_xml'
	write(d / 'default' / 'props.conf', '[source::XmlWinEventLog:Security]\nREPORT-dest = computer_as_dest\n')
	write(d / 'default' / 'transforms.conf', '[computer_as_dest]\nREGEX = <Computer>([^<]+)</Computer>\nFORMAT = dest::$1\n')
	return str(d)


def pan_addon(tmp_path):
	"""A synthetic add-on in the Palo Alto add-on's shape: the traffic sourcetype, its route and positional fields."""
	d = tmp_path / 'TA_pan'
	write(d / 'default' / 'props.conf', '[pan:log]\nTRANSFORMS-sourcetype = route_traffic\n\n'
		'[pan:traffic]\nREPORT-search = extract_traffic\n')
	write(d / 'default' / 'transforms.conf', '[route_traffic]\nDEST_KEY = MetaData:Sourcetype\n'
		'REGEX = ^[^,]*,[^,]*,[^,]*,TRAFFIC,\nFORMAT = sourcetype::pan:traffic\n\n[extract_traffic]\nDELIMS = ","\n'
		'FIELDS = "future_use1","receive_time","serial_number","type","log_subtype","src_ip","dest_ip"\n')
	return str(d)


def records(tmp_path, template):
	p = tmp_path / 'templates.json'
	p.write_text(json.dumps({'templateHash': 'h1', 'template': template}) + '\n', encoding='utf-8')
	return str(p)


def gen(out, target, extra, *more):
	return fm.main(['gen', '--rules', 'lookup', '--target', target, '--out', str(out)] + list(extra) + list(more))


def conf(app, name):
	return fm.read_conf(os.path.join(str(app), 'default', name + '.conf'))


def index_time(app, sourcetype):
	"""The compact sourcetype's stanza and the transforms its TRANSFORMS- list names (the app's own tenx-event-time is
	not in the map), with the lookup definition the lookup rule reads."""
	props, transforms = conf(app, 'props'), conf(app, 'transforms')
	stanza = props[sourcetype]
	names = [n.strip() for k, v in stanza.items() if k.startswith('TRANSFORMS-') for n in v.split(',')]
	used = [n for n in names if n in transforms]
	used.append(fm.lookup_stanza({'transform_prefix': sourcetype}))
	return stanza, dict((n, transforms[n]) for n in used)


class TestWithoutRecords:
	def test_the_fortigate_map_holds_its_index_time_rules_and_no_template(self, tmp_path, capsys):
		app = tmp_path / 'fm_fgt'
		assert gen(app, 'fortigate', ['--leave-out', 'time']) == 0
		stanza = conf(app, 'props')['tenx_fgt']
		# One event per line, as the app's [tenx_encoded]: no line merging, no cut at Splunk's 10,000 bytes.
		assert stanza['SHOULD_LINEMERGE'] == 'false' and stanza['LINE_BREAKER'] == '([\\r\\n]+)'
		assert stanza['TRUNCATE'] == '262144'
		assert stanza['TRANSFORMS-tenx_fgt'] == 'tenx-event-time, tenx_fgt_sourcetype, tenx_fgt_fields_eval, tenx_fgt_rename'
		transforms = conf(app, 'transforms')
		assert transforms['tenx_fgt_sourcetype']['FORMAT'] == 'tenx_compact_st::"tenx_fgt"'
		assert transforms['tenx_fgt_rename']['DEST_KEY'] == 'MetaData:Sourcetype'
		assert transforms['tenx_fgt_rename']['SOURCE_KEY'] == 'field:tenx_sourcetype'
		assert fm.read_lookup_file(str(app / 'lookups' / 'tenx_fgt_fields.csv.gz')) == {}
		assert os.path.isfile(str(tmp_path / 'fm_fgt_floor' / 'lookups' / 'tenx_fgt_fields.csv.gz'))
		out = capsys.readouterr().out
		assert 'no templates: install the map before the first event of tenx_fgt' in out

	def test_the_windows_xml_map_renames_without_templates(self, tmp_path):
		app = tmp_path / 'fm_win'
		assert gen(app, 'windows-security', []) == 0
		stanza = conf(app, 'props')['tenx_win']
		assert stanza['rename'] == 'XmlWinEventLog' and stanza['SHOULD_LINEMERGE'] == 'false'
		assert stanza['TRANSFORMS-tenx_win'] == 'tenx_win_sourcetype, tenx_win_fields_eval'

	@pytest.mark.parametrize('target, addon', [(t, None) for t in sorted(TARGETS)] + [('windows-security', xml_addon),
		('palo-alto', pan_addon)])
	def test_a_later_gen_writes_the_same_index_time_rules(self, tmp_path, target, addon):
		sourcetype, extra, template = TARGETS[target]
		if addon:
			extra = [a for a in extra if a != '--columns' and not a.startswith('future_use1')] + ['--addon', addon(tmp_path)]
		assert gen(tmp_path / 'before', target, extra) == 0
		assert gen(tmp_path / 'after', target, extra, '--records', records(tmp_path, template)) == 0
		assert fm.read_lookup_file(str(tmp_path / 'after' / 'lookups' / ('%s_fields.csv.gz' % sourcetype)))
		assert index_time(tmp_path / 'before', sourcetype) == index_time(tmp_path / 'after', sourcetype)

	def test_the_cap_file_lists_nothing(self, tmp_path):
		cap = tmp_path / 'compact-cap.csv'
		cap.write_text('pattern_hash,value\n', encoding='utf-8')
		assert gen(tmp_path / 'fm_fgt', 'fortigate', [], '--cap-file', str(cap)) == 0
		assert fm.read_cap(str(cap))[0] == set()
		assert fm.read_cap(str(cap) + fm.CAP_PENDING_SUFFIX)[0] == set()

	def test_verify_still_needs_records(self, tmp_path, capsys):
		with pytest.raises(SystemExit):
			fm.main(['verify', '--target', 'fortigate', '--encoded', 'e', '--raw', 'r'])
		assert '--records' in capsys.readouterr().err
