"""
The search-time stanzas that give compact Windows Security (XML) and Splunk Stream events the dest and src
fields their add-ons read from the event text: present, readable as Splunk reads them, applied to the sources
they name, and shared with every app as the app's other props and transforms are.
"""
import configparser
import os
import re

import pytest

import tenx_replay_builder as b

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))
WINDOWS = 'source::XmlWinEventLog:Security'
STREAM = 'source::stream:*'
TRANSFORM = 'tenx-computer-as-dest'


def conf(name, strict=False):
	parser = configparser.RawConfigParser(strict=strict, interpolation=None)
	parser.optionxform = str
	with open(os.path.join(APP, 'default', name), encoding='utf-8') as f:
		parser.read_file(f)
	return parser


def meta():
	with open(os.path.join(APP, 'metadata', 'default.meta'), encoding='utf-8') as f:
		return f.read()


class TestTheStanzas:
	def test_windows_xml_security_sets_dest_from_computer(self):
		assert dict(conf('props.conf').items(WINDOWS)) == {'REPORT-tenx_dest': TRANSFORM}
		assert dict(conf('transforms.conf').items(TRANSFORM)) == \
			{'SOURCE_KEY': 'Computer', 'REGEX': '^(.+)$', 'FORMAT': 'dest::$1'}

	def test_stream_aliases_src_and_dest(self):
		assert dict(conf('props.conf').items(STREAM)) == \
			{'FIELDALIAS-tenx_src_dest': 'src_ip ASNEW src dest_ip ASNEW dest'}

	@pytest.mark.parametrize('name', ['props.conf', 'transforms.conf'])
	def test_each_file_reads_without_a_repeated_stanza_or_setting(self, name):
		assert conf(name, strict=True).sections()

	def test_the_transform_writes_the_whole_value_to_dest(self):
		transform = dict(conf('transforms.conf').items(TRANSFORM))
		regex = re.compile(transform['REGEX'])
		assert regex.groups == 1 and re.findall(r'\$(\d+)', transform['FORMAT']) == ['1']
		assert b.transform_outputs(transform) == {'dest'}
		for value in ('WIN-DC01.corp.example.com', 'host 2', 'a'):
			assert regex.match(value).group(1) == value
		assert regex.match('') is None

	def test_the_alias_reads_as_two_asnew_pairs(self):
		value = conf('props.conf').get(STREAM, 'FIELDALIAS-tenx_src_dest')
		assert b.parse_aliases(value) == [('src_ip', 'ASNEW', 'src'), ('dest_ip', 'ASNEW', 'dest')]

	def test_both_are_search_time_only(self):
		props = conf('props.conf')
		for stanza in (WINDOWS, STREAM):
			assert all(k.startswith(('REPORT-', 'FIELDALIAS-')) for k in props.options(stanza)), stanza
		assert not set(conf('transforms.conf').options(TRANSFORM)) & {'INGEST_EVAL', 'DEST_KEY', 'WRITE_META'}

	def test_the_report_class_sorts_after_the_windows_add_ons_dest_and_xml_classes(self):
		# The Windows add-on's classes that extract Computer from the XML or write dest, on the same events.
		addon = ['0xml_block_extract', '0xml_kv_extract', '0dest_for_windows_security_4798',
				 '0dest_for_windows_security_from_xml', 'dest_for_windows_security']
		assert sorted(addon + ['tenx_dest'])[-1] == 'tenx_dest'


class TestTheSourcesTheyApplyTo:
	@pytest.mark.parametrize('source, applies', [
		('XmlWinEventLog:Security', True),
		('WinEventLog:Security', False),
		('XmlWinEventLog:Microsoft-Windows-Sysmon/Operational', False),
		('XmlWinEventLog:System', False),
	])
	def test_windows(self, source, applies):
		assert b.Stanza(WINDOWS, {}).matches(source) is applies

	@pytest.mark.parametrize('source, applies', [
		('stream:dns', True),
		('stream:tcp', True),
		('stream:ip', True),
		('stream', False),
		('/var/log/stream:dns', False),
	])
	def test_stream(self, source, applies):
		assert b.Stanza(STREAM, {}).matches(source) is applies


class TestSharedLikeTheOtherSearchTimeSettings:
	@pytest.mark.parametrize('kind', ['props', 'transforms'])
	def test_props_and_transforms_are_exported_to_every_app(self, kind):
		assert re.search(r'^\[%s\]\n(?:access = [^\n]*\n)?export = system$' % kind, meta(), re.M), kind

	def test_no_entry_of_their_own_changes_that(self):
		entries = re.findall(r'^\[((?:props|transforms)/[^\]]*)\]', meta(), re.M)
		assert entries and not [e for e in entries if re.search(r'XmlWinEventLog|stream|computer-as-dest', e, re.I)]

	def test_the_replay_counts_dest_and_src_as_fields_not_in_the_text(self):
		# The search rewrite then does not narrow a comparison on them by the compact text, where their values need not be.
		props, transforms = conf('props.conf'), conf('transforms.conf')
		stanzas = [b.Stanza(s, dict(props.items(s))) for s in (WINDOWS, STREAM)]
		found = b.fields_not_in_text(stanzas, {TRANSFORM: dict(transforms.items(TRANSFORM))},
									 keep_fields=('Computer', 'src_ip', 'dest_ip'))
		assert {'dest', 'src'} <= set(found)
