"""
A search for a MAC address finds the compact events that hold it, through `tx` and through the search rewrite
(`| tx`, the dashboard hook, compiled alerts), in the forms the Receiver writes it.

The Receiver writes each octet of a MAC address as a value of the compact event (option macAddressValues, on by
default), or, with the option off, an octet the symbol library holds as template text. A value between commas
is an index term of the compact event. Each prefilter is evaluated on the compact text with a model of Splunk's
index terms: the runs between major breakers and their pieces between minor breakers, in lower case.
"""
import re

import pytest

import tenx_prefilter_parser as p
from tenx_dml_builder import TenxDMLBuilder
from test_tenx_search_builder import make_builder, prefilter as rewrite_prefilter

PURE = TenxDMLBuilder(timestamp_placeholder='__TENX_TS__', variable_separator='$')

# (template hash, template, compact event); the event of each line is srcmac="<address>" action=deny
EVENTS = [
	# each octet a value
	('m_on', 'srcmac="$:$:$:$:$:$" action=deny', '~m_on,e4,ce,8f,01,a2,bc'),
	('m_up', 'srcmac="$-$-$-$-$-$" action=deny', '~m_up,E4,CE,8F,01,A2,BC'),
	('m_dig', 'srcmac="$:$:$:$:$:$" action=deny', '~m_dig,00,11,22,33,44,55'),
	('m_mix', 'srcmac="$:$:$:$:$:$" action=deny', '~m_mix,ac,de,48,00,11,22'),
	# the option off: the octets the library holds are template text
	('m_off', 'srcmac="e4:ce:$:$:a2:bc" action=deny', '~m_off,8f,01'),
]
ADDRESS = {'m_on': 'e4:ce:8f:01:a2:bc', 'm_up': 'E4-CE-8F-01-A2-BC', 'm_dig': '00:11:22:33:44:55',
		   'm_mix': 'ac:de:48:00:11:22', 'm_off': 'e4:ce:8f:01:a2:bc'}
FORTIGATE = '%H:%M:%S'


def terms(raw):
	out = set()
	for run in re.split('[' + re.escape(p.MAJOR_CHARS) + ']', raw.lower()):
		if run:
			out.add(run)
			out.update(x for x in re.split('[' + re.escape(p.MINOR_CHARS) + ']', run) if x)
	return out


def selects(spl, raw):
	"""Whether a prefilter (TERM(...) atoms and quoted terms joined by AND and OR) selects the compact event `raw`."""
	tokens = re.findall(r'\(|\)|\bAND\b|\bOR\b|TERM\([^()]*\)|"(?:[^"\\]|\\.)*"', spl or '')
	pos = [0]

	def atom():
		t = tokens[pos[0]]
		pos[0] += 1
		if t == '(':
			v = either()
			pos[0] += 1
			return v
		if t.startswith('TERM('):
			return t[len('TERM('):-1].lower() in terms(raw)
		phrase = t[1:-1]
		if phrase.startswith('~'):
			return phrase in raw
		return all(x in terms(raw) for x in re.split('[' + re.escape(p.MAJOR_CHARS + p.MINOR_CHARS) + ']', phrase.lower()) if x)

	def both():
		v = atom()
		while pos[0] < len(tokens) and tokens[pos[0]] not in (')', 'OR'):
			if tokens[pos[0]] == 'AND':
				pos[0] += 1
			v = atom() and v
		return v

	def either():
		v = both()
		while pos[0] < len(tokens) and tokens[pos[0]] == 'OR':
			pos[0] += 1
			v = both() or v
		return v
	return not tokens or either()


def tx_selects(text, raw):
	"""Whether the `tx` prefilter for `text` selects the compact event `raw`."""
	tree = p.Parser(p.tokenize(text)).parse()
	digits = p.digit_pieces_cleared(p.digit_candidates(tree), [(FORTIGATE, False, False)])
	dictionary = {}
	for piece in p.lookup_pieces(tree, digits=digits):
		word = re.compile(r'(^|[^a-z0-9])' + re.escape(piece) + r'([^a-z0-9]|$)')
		found = [p.hash_selector(h) for h, t, _ in EVENTS if word.search(PURE.build_pure_dml_line(h, t).lower())]
		dictionary[piece] = (len(found), found)
	return selects(p.prefilter(tree, dictionary, None, digits), raw)


def rewrite_selects(text, raw, formats=(FORTIGATE,)):
	"""Whether the search rewrite's prefilter for `text` selects the compact event `raw`."""
	builder, _ = make_builder(templates=[(h, t) for h, t, _ in EVENTS], timestamp_formats=list(formats))
	return selects(rewrite_prefilter(builder.build('sourcetype=tenx_encoded ' + text).resolved), raw)


def forms(address):
	"""The ways a search writes an address: as found, quoted, the other separator, the other case, a prefix."""
	other = address.replace(':', '-') if ':' in address else address.replace('-', ':')
	return [address, '"%s"' % address, other, address.swapcase(), address[:8] + '*']


@pytest.mark.parametrize('name', sorted(ADDRESS))
def test_tx_finds_the_address_in_every_form_a_search_writes(name):
	raw = next(r for h, _, r in EVENTS if h == name)
	for text in forms(ADDRESS[name]):
		assert tx_selects(text, raw), text


@pytest.mark.parametrize('name', sorted(ADDRESS))
def test_the_rewrite_finds_it_with_and_without_the_stored_formats(name):
	raw = next(r for h, _, r in EVENTS if h == name)
	for text in forms(ADDRESS[name]):
		assert rewrite_selects(text, raw), text
		assert rewrite_selects(text, raw, formats=()), text


def test_an_octet_that_is_a_value_narrows_the_search():
	# the letter octets the prefilter can use are terms of the compact event, so other events are not expanded
	assert not tx_selects('e4:ce:8f:01:a2:bc', '~x,deny,10.1.2.3')
	assert not rewrite_selects('e4:ce:8f:01:a2:bc', '~x,deny,10.1.2.3')
