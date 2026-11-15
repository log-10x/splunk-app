"""
The replay takes the sourcetype a raw event would have been searched under, not only the one it
arrived under (tenx_replay_builder.effective_sourcetypes()): an index-time rewrite of the sourcetype
from the raw text (TRANSFORMS- with DEST_KEY = MetaData:Sourcetype), then `rename`.

The rules and data are the FortiGate add-on's (Splunk_TA_fortinet_fortigate 1.6.10): fgt_log and
fortigate_log are rewritten to fortigate_<type> by [force_sourcetype_fortigate], and fgt_traffic,
fgt_utm, fgt_event, fgt_anomaly are renamed to the fortigate_ stanzas, which hold the rules.
"""
import re

import tenx_replay_builder as b

REGEX = r'^(?=.*\bdevid="?F(?:G|W|\dK)[^"\s]*"?).*?\btype="?(traffic|utm|event|anomaly)\b'
TRANSFORMS = {'force_sourcetype_fortigate': {'SOURCE_KEY': '_raw', 'DEST_KEY': 'MetaData:Sourcetype',
	'REGEX': REGEX, 'FORMAT': 'sourcetype::fortigate_$1'}}


def stanza(name, **settings):
	return b.Stanza(name, dict(settings), {})


STANZAS = [
	stanza('fgt_log', **{'TRANSFORMS-force_sourcetype_fgt': 'force_sourcetype_fortigate', 'SHOULD_LINEMERGE': 'false'}),
	stanza('fgt_traffic', rename='fortigate_traffic'),
	stanza('fgt_utm', rename='fortigate_utm'),
	stanza('fortigate_traffic', **{'EVAL-vendor': '"Fortinet"', 'FIELDALIAS-src': 'srcip as src'}),
	stanza('fortigate_utm', **{'EVAL-vendor': '"Fortinet"', 'EVAL-ids_type': '"network"'}),
	stanza('fortigate_event', **{'EVAL-vendor': '"Fortinet"'}),
	stanza('unrelated', **{'EVAL-x': '1'}),
]


def spl(present, **kw):
	return b.build(STANZAS, present, transforms=TRANSFORMS, **kw)


def splunk_replace(text, pattern, replacement):
	"""Python's reading of eval replace() for the patterns written here (no backslash in the text)."""
	return re.sub(pattern, replacement.replace('\\\\', '\\'), text, count=1)


class TestRename:
	def test_a_renamed_carrier_gets_the_targets_rules(self):
		r = spl([('fgt_traffic', 'ad/fgt.log', 'h1')])
		text = r.spl()
		assert 'eval tenx_rst=case(tenx_rst=="fgt_traffic", "fortigate_traffic", true(), tenx_rst)' in text
		assert 'tenx_rst=="fortigate_traffic"' in text and '"Fortinet"' in text
		assert 'ids_type' not in text and 'unrelated' not in text
		assert sorted(r.per_sourcetype) == ['fgt_traffic']
		assert r.per_sourcetype['fgt_traffic']['replayed_as'] == ['fortigate_traffic']
		assert r.per_sourcetype['fgt_traffic']['stanzas'] == ['fortigate_traffic']
		assert not any('rename' in w for w in r.per_sourcetype['fgt_traffic']['warnings'])

	def test_the_rename_step_runs_before_the_flags_and_the_retype(self):
		steps = spl([('fgt_traffic', 's', 'h')]).steps
		ren = next(i for i, s in enumerate(steps) if s.startswith('eval tenx_rst=case('))
		flag = next(i for i, s in enumerate(steps) if s.startswith('eval tenx_go0z='))
		assert ren < flag
		assert 'eval sourcetype=coalesce(tenx_rst, sourcetype)' in ' | '.join(steps[flag:])

	def test_renames_do_not_chain(self):
		st = [stanza('a', rename='b'), stanza('b', rename='c', **{'EVAL-x': '1'})]
		_, eff, _ = b.effective_sourcetypes(st, {}, ['a'])
		assert eff == {'a': ['b']}

	def test_no_rewrite_and_no_rename_writes_no_step(self):
		steps, eff, warnings = b.effective_sourcetypes(STANZAS, TRANSFORMS, ['fortigate_event'])
		assert steps == [] and eff == {'fortigate_event': ['fortigate_event']} and warnings == []


class TestIndexTimeRewrite:
	def test_the_rewrite_is_applied_to_the_expanded_text(self):
		steps, eff, _ = b.effective_sourcetypes(STANZAS, TRANSFORMS, ['fgt_log'])
		assert eff == {'fgt_log': ['fgt_log', 'fortigate_event', 'fortigate_traffic', 'fortigate_utm']}
		assert steps[0] == 'eval tenx_rst0=tenx_rst' and steps[-1] == 'fields - tenx_rst0'
		step = steps[1]
		assert step.startswith('eval tenx_rst=if(tenx_rst0=="fgt_log" AND match(_raw, "')
		m = re.search(r'replace\(_raw, "((?:[^"\\]|\\.)*)", "((?:[^"\\]|\\.)*)"\)', step)
		pattern = m.group(1).replace('\\\\', '\\').replace('\\"', '"')
		replacement = m.group(2)
		assert replacement == 'fortigate_\\\\1'
		cases = {
			'date=2026-11-13 time=11:37:47 devname="FGT-1" devid="FG100E1234" type="traffic" subtype="forward"': 'fortigate_traffic',
			'date=2026-11-13 devid=FGT60E type=utm subtype=ips': 'fortigate_utm',
			'date=2026-11-13 devid="SN000000000001" type="event"': None,
			'date=2026-11-13 type="traffic" subtype="forward"': None,
		}
		for text, want in cases.items():
			assert (re.search(REGEX, text) is not None) == (want is not None), text
			if want:
				assert splunk_replace(text, pattern, replacement) == want, text

	def test_the_carrier_keeps_its_own_rules_when_the_rewrite_does_not_match(self):
		r = spl([('fgt_log', 's', 'h')])
		assert r.per_sourcetype['fgt_log']['replayed_as'] == ['fgt_log', 'fortigate_event', 'fortigate_traffic', 'fortigate_utm']
		assert sorted(r.per_sourcetype['fgt_log']['stanzas']) == ['fortigate_event', 'fortigate_traffic', 'fortigate_utm']

	def test_a_unit_selects_by_the_carrier_and_replays_by_the_rewritten_sourcetype(self):
		r = spl([('fgt_log', '', '')], only=True)
		text = r.spl()
		assert 'mvindex(tenx_sourcetype,0)=="fgt_log"' in text
		assert 'mvindex(tenx_sourcetype,0)=="fortigate_traffic"' not in text
		assert 'tenx_rst=="fortigate_utm"' in text

	def test_a_rewrite_from_another_key_is_reported_not_replayed(self):
		t = {'st_from_host': {'SOURCE_KEY': 'MetaData:Host', 'DEST_KEY': 'MetaData:Sourcetype', 'REGEX': 'x',
			'FORMAT': 'sourcetype::y'}}
		st = [stanza('a', **{'TRANSFORMS-x': 'st_from_host', 'EVAL-v': '1'})]
		steps, eff, warnings = b.effective_sourcetypes(st, t, ['a'])
		assert steps == [] and eff == {'a': ['a']}
		assert warnings == ['the sourcetype rewrite st_from_host of a does not read _raw and is not replayed']

	def test_a_literal_format_and_a_rename_after_it(self):
		t = {'to_b': {'DEST_KEY': 'MetaData:Sourcetype', 'REGEX': 'kind=b', 'FORMAT': 'sourcetype::b'}}
		st = [stanza('a', **{'TRANSFORMS-1': 'to_b'}), stanza('b', rename='c'), stanza('c', **{'EVAL-v': '1'})]
		steps, eff, _ = b.effective_sourcetypes(st, t, ['a'])
		assert eff == {'a': ['a', 'c']}
		assert 'match(_raw, "kind=b"), "b", tenx_rst)' in steps[1]
		assert steps[2] == 'eval tenx_rst=case(tenx_rst=="b", "c", true(), tenx_rst)'
