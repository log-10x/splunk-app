"""
The search-time settings that give compact Windows Security events in the classic text form the src_nt_domain,
src and vendor_privilege values the Windows add-on reads from the event text: present, in the order Splunk
applies them, and taking the same part of the attached values.
"""
import configparser
import os
import re
import urllib.parse

import tenx_replay_builder as b

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))
CLASSIC = 'source::WinEventLog:Security'
SUBJECT = ('tenx-subject-security-id-as-src-nt-domain', 'tenx-subject-security-id-as-src')


def conf(name):
	parser = configparser.RawConfigParser(strict=True, interpolation=None)
	parser.optionxform = str
	with open(os.path.join(APP, 'default', name), encoding='utf-8') as f:
		parser.read_file(f)
	return parser


def splunk_regex(transform):
	# Splunk adds the dotall and multi-line modifiers in front of a search-time regex.
	return re.compile('(?ms)' + conf('transforms.conf').get(transform, 'REGEX'))


class TestTheSettings:
	def test_src_nt_domain_runs_the_add_ons_first_steps_then_the_attached_value(self):
		steps = [t.strip() for t in conf('props.conf').get(CLASSIC, 'REPORT-0tenx_src_nt_domain').split(',')]
		assert steps == ['Caller_Domain_as_src_nt_domain', 'Client_Domain_as_src_nt_domain',
			'Account_Domain_as_src_nt_domain', SUBJECT[0]]

	def test_the_src_nt_domain_class_sorts_before_the_add_ons(self):
		assert '0tenx_src_nt_domain' < 'src_nt_domain_for_windows_security'

	def test_src_subject_security_id_comes_from_the_attached_value(self):
		assert conf('props.conf').get(CLASSIC, 'REPORT-tenx_src_subject_security_id') == SUBJECT[1]

	def test_both_transforms_read_subject_security_id(self):
		transforms = conf('transforms.conf')
		assert [transforms.get(t, 'SOURCE_KEY') for t in SUBJECT] == ['Subject_Security_ID'] * 2
		assert [b.transform_outputs(dict(transforms.items(t))) for t in SUBJECT] == [{'src_nt_domain'}, {'src_subject_security_id'}]


class TestThePartTaken:
	def test_the_part_before_the_first_backslash(self):
		for t in SUBJECT:
			assert splunk_regex(t).search('DOMAIN\\user').group(1) == 'DOMAIN'

	def test_a_value_without_a_backslash_whole(self):
		for t in SUBJECT:
			assert splunk_regex(t).search('NULL SID').group(1) == 'NULL SID'

	def test_a_pipe_ends_it_too(self):
		assert splunk_regex(SUBJECT[0]).search('A|B').group(1) == 'A'


class TestVendorPrivilege:
	def test_raw_events_keep_the_add_ons_value(self):
		value = conf('props.conf').get(CLASSIC, 'EVAL-vendor_privilege')
		assert value.startswith('if(isnull(tenx_sourcetype), vendor_privilege, ')

	def test_a_list_is_joined_as_the_event_text_holds_it(self):
		value = conf('props.conf').get(CLASSIC, 'EVAL-vendor_privilege')
		joins = re.findall(r'mvjoin\(vendor_privilege, urldecode\("([^"]+)"\)\)', value)
		assert [urllib.parse.unquote(j) for j in joins] == ['\n\t\t\t']

	def test_the_access_check_label_is_read_as_the_add_on_reads_it(self):
		value = conf('props.conf').get(CLASSIC, 'EVAL-vendor_privilege')
		assert '"Used for Access Check:" . urldecode("%09") . Privileges_Used_for_Access_Check' in value
