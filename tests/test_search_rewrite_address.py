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


def test_a_prefix_of_three_parts_requires_them_without_a_lookup():
	result, manager = compile_search('sourcetype=tenx_encoded 10.0.1.*')
	assert prefilter(result.resolved) == '("10") AND ("0") AND ("1")'
	assert manager.probes == []


def test_a_wildcard_after_the_last_part_makes_it_a_prefix():
	result, manager = compile_search('sourcetype=tenx_encoded 10.0.2.1*')
	assert manager.probes == ['"1*"']
	assert '("10") AND ("0") AND ("2")' in prefilter(result.resolved)


def test_a_first_part_of_one_is_still_looked_up():
	_, manager = compile_search('sourcetype=tenx_encoded 1.2.3.4')
	assert manager.probes == ['"1"']


def test_what_is_not_an_address_keeps_the_lookup():
	_, manager = compile_search('sourcetype=tenx_encoded 1.2.3.4.5')
	assert manager.probes == ['"1"', '"2"', '"3"', '"4"', '"5"']


def test_term_and_case_are_read_and_applied_after_expansion():
	# Before, the rewrite's parser stopped at "(" and the search was refused ("could not be
	# rewritten for compact data"). The prefilter requires the pieces inside; the search after
	# expansion applies TERM() or CASE() itself.
	# TERM() of a word with a breaker in it is matched as the index matches it (a whole major segment of
	# the event, tenx_prefilter_parser.wild_plan); after a pipe Splunk finds it inside a longer one too.
	result, manager = compile_search('sourcetype=tenx_encoded TERM(10.0.1.14) | stats count')
	assert prefilter(result.resolved) == '("10") AND ("0") AND ("1") AND ("14")'
	assert ' | eval tenx_w0=if(match(_raw, "(?i)' in result.resolved
	assert result.resolved.endswith('"), 1, 0) | search tenx_w0=1 | fields - tenx_w* | stats count')
	assert manager.probes == []
	result, manager = compile_search('sourcetype=tenx_encoded CASE(Error)')
	assert manager.probes == ['"Error"'] and result.resolved.endswith('| search CASE(Error)')
	result, _ = compile_search('sourcetype=tenx_encoded NOT TERM(x)')
	assert prefilter(result.resolved) == '' and result.resolved.endswith('| search NOT TERM(x)')
	# a word that only starts like one is still a word
	_, manager = compile_search('sourcetype=tenx_encoded TERMS')
	assert manager.probes == ['"TERMS"']
