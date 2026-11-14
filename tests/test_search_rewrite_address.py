"""
The search rewrite (dashboard hook, | tx, | tenxsearch, compiled alerts) builds its own
prefilter, which requires every part of an IPv4 address as a term, short parts included. It uses
the `tx` prefilter's address functions to require the parts without a template dictionary
lookup: a part is digits only, so never template text.
"""
from test_tenx_search_builder import compile_search, prefilter


def test_address_parts_are_required_without_a_dictionary_lookup():
	result, manager = compile_search('sourcetype=tenx_encoded 10.0.1.14')
	assert prefilter(result.resolved) == '("10") AND ("0") AND ("1") AND ("14")'
	assert manager.probes == []
	result, manager = compile_search('sourcetype=tenx_encoded "from 192.168.39.89 port"')
	assert manager.probes == ['"from"', '"port"']
	assert '("192") AND ("168") AND ("39") AND ("89")' in prefilter(result.resolved)


def test_a_first_part_of_one_is_still_looked_up():
	_, manager = compile_search('sourcetype=tenx_encoded 1.2.3.4')
	assert manager.probes == ['"1"']


def test_what_is_not_an_address_keeps_the_lookup():
	_, manager = compile_search('sourcetype=tenx_encoded 1.2.3.4.5')
	assert manager.probes == ['"1"', '"2"', '"3"', '"4"', '"5"']
