"""
The compact-event extraction in transforms.conf, applied with Python's re, which agrees with
Splunk's PCRE on this pattern. A compact event is `~<hash>,<values>`, or `~<hash>` alone when its
template has no values.
"""
import configparser
import os
import re


def extraction():
	conf = configparser.ConfigParser(interpolation=None, strict=False)
	conf.read(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'default', 'transforms.conf'))
	return re.compile(conf.get('tenx-hash-vars-extraction', 'REGEX').replace('(?<', '(?P<'))


def test_an_event_with_values():
	m = extraction().match('~-JladI:@f4,1791280800000,abc,def')
	assert m.group('tenx_hash') == '-JladI:@f4'
	assert m.group('tenx_var_0') == '1791280800000'
	assert m.group('tenx_vars') == 'abc,def'


def test_an_event_with_one_value():
	m = extraction().match('~9aZXwGwVG/,1759364242000')
	assert m.group('tenx_hash') == '9aZXwGwVG/'
	assert m.group('tenx_var_0') == '1759364242000'
	assert m.group('tenx_vars') is None


def test_an_event_with_no_values_still_yields_its_hash():
	m = extraction().match('~>za#GPW8vY')
	assert m is not None
	assert m.group('tenx_hash') == '>za#GPW8vY'
	assert m.group('tenx_var_0') is None


def test_a_hash_with_spaces():
	m = extraction().match('~KC 2c#eEev,64,41c1')
	assert m.group('tenx_hash') == 'KC 2c#eEev'
