"""
The search-time aliases that give compact Windows Security and Splunk Stream events the dest and src fields their
add-ons read from the event text, and let a search for those fields find compact events: present, readable as
Splunk reads them, applied to the sources they name, and shared with every app as the app's other props are.
"""
import configparser
import os
import re

import pytest

import tenx_replay_builder as b

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))
WINDOWS = 'source::XmlWinEventLog:Security'
CLASSIC = 'source::WinEventLog:Security'
STREAM = 'source::stream:*'


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
	def test_windows_xml_security_aliases_computer_as_dest(self):
		assert dict(conf('props.conf').items(WINDOWS)) == {'FIELDALIAS-tenx_dest': 'Computer ASNEW dest'}

	def test_windows_classic_security_aliases_computername_as_dest(self):
		props = dict(conf('props.conf').items(CLASSIC))
		assert props['FIELDALIAS-tenx_dest'] == 'ComputerName ASNEW dest'
		assert [k for k in props if k.startswith('FIELDALIAS-')] == ['FIELDALIAS-tenx_dest']

	def test_stream_aliases_src_and_dest(self):
		assert dict(conf('props.conf').items(STREAM)) == \
			{'FIELDALIAS-tenx_src_dest': 'src_ip ASNEW src dest_ip ASNEW dest'}

	@pytest.mark.parametrize('name', ['props.conf', 'transforms.conf'])
	def test_each_file_reads_without_a_repeated_stanza_or_setting(self, name):
		assert conf(name, strict=True).sections()

	def test_the_aliases_read_as_asnew_pairs(self):
		props = conf('props.conf')
		assert b.parse_aliases(props.get(WINDOWS, 'FIELDALIAS-tenx_dest')) == [('Computer', 'ASNEW', 'dest')]
		assert b.parse_aliases(props.get(CLASSIC, 'FIELDALIAS-tenx_dest')) == [('ComputerName', 'ASNEW', 'dest')]
		assert b.parse_aliases(props.get(STREAM, 'FIELDALIAS-tenx_src_dest')) == [('src_ip', 'ASNEW', 'src'), ('dest_ip', 'ASNEW', 'dest')]

	def test_both_set_their_fields_by_alias_alone(self):
		# Splunk looks up the value of a search for an alias also as the source field's indexed value, which a compact
		# event carries; a value an extraction gives is looked up only as words of the event text.
		props, transforms = conf('props.conf'), conf('transforms.conf')
		for stanza in (WINDOWS, STREAM):
			assert all(k.startswith('FIELDALIAS-') for k in props.options(stanza)), stanza
		writes = [t for t in transforms.sections() if re.match(r'(?:dest|src)::', transforms.get(t, 'FORMAT', fallback=''))]
		assert not writes


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

	@pytest.mark.parametrize('source, applies', [
		('WinEventLog:Security', True),
		('XmlWinEventLog:Security', False),
		('WinEventLog:System', False),
	])
	def test_windows_classic(self, source, applies):
		assert b.Stanza(CLASSIC, {}).matches(source) is applies


class TestSharedLikeTheOtherSearchTimeSettings:
	@pytest.mark.parametrize('kind', ['props', 'transforms'])
	def test_props_and_transforms_are_exported_to_every_app(self, kind):
		assert re.search(r'^\[%s\]\n(?:access = [^\n]*\n)?export = system$' % kind, meta(), re.M), kind

	def test_no_entry_of_their_own_changes_that(self):
		entries = re.findall(r'^\[((?:props|transforms)/[^\]]*)\]', meta(), re.M)
		assert entries and not [e for e in entries if re.search(r'WinEventLog|stream', e, re.I)]

	def test_the_replay_counts_dest_and_src_as_fields_not_in_the_text(self):
		# The search rewrite then does not narrow a comparison on them by the compact text, where their values need not be.
		props = conf('props.conf')
		stanzas = [b.Stanza(s, dict(props.items(s))) for s in (WINDOWS, CLASSIC, STREAM)]
		found = b.fields_not_in_text(stanzas, {}, keep_fields=('Computer', 'ComputerName', 'src_ip', 'dest_ip'))
		assert {'dest', 'src'} <= set(found)
