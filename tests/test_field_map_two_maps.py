"""
Two maps of one target on one instance: every name a generated app defines (transforms stanzas, lookup definitions and
files, the floor app's) comes from the map's compact sourcetype, so maps generated with different --sourcetype never
define the same name, and a key both write in an original sourcetype's stanza has the same value in both.
"""
import collections
import json
import os

import tenx_field_map as fm

TEMPLATES = {
	'fortigate': 'date=$$$ time=$(HH:mm:ss) devname="$" type="utm" subtype="webfilter" eventtype="$" url="$"',
	'windows-security-classic': '$(MM/dd/yyyy hh:mm:ss a)\nLogName=Security\nEventCode=$\nEventType=$\nMessage=An account '
		'was logged on.\n\nSubject:\n\tSecurity ID:\t\t$\n\tAccount Name:\t\t$',
	'windows-security': "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>$</EventID>"
		"<Computer>$</Computer></System><EventData><Data Name='SubjectUserName'>$</Data></EventData></Event>",
}


def conf_stanzas(path):
	if not os.path.exists(path):
		return {}
	return fm.read_splunk_conf(path)


def names_of(app_dir):
	"""(transforms stanza names, lookup files, props: {stanza: {key: value}}) of an app and its floor app."""
	transforms, files, props = set(), set(), collections.defaultdict(dict)
	for d in (app_dir, fm.floor_dir(app_dir)):
		transforms |= set(conf_stanzas(os.path.join(d, 'default', 'transforms.conf')))
		if os.path.isdir(os.path.join(d, 'lookups')):
			files |= set(os.listdir(os.path.join(d, 'lookups')))
		for st, kv in conf_stanzas(os.path.join(d, 'default', 'props.conf')).items():
			props[st].update(kv)
	return transforms, files, props


def gen_two(tmp_path, target, template, extra=()):
	apps = []
	for st in ('tenx_one', 'tenx_two'):
		p = tmp_path / ('%s.json' % st)
		p.write_text(json.dumps({'templateHash': 'k1', 'template': template}) + '\n', encoding='utf-8')
		out = tmp_path / ('fm_%s' % st)
		assert fm.main(['gen', '--rules', 'lookup', '--records', str(p), '--target', target, '--sourcetype', st,
			'--app-name', 'fm_%s' % st, '--out', str(out)] + list(extra)) == 0
		apps.append(names_of(str(out)))
	return apps


def assert_coexist(apps):
	(t1, f1, p1), (t2, f2, p2) = apps
	assert t1 and t2 and not (t1 & t2), sorted(t1 & t2)
	assert f1 and f2 and not (f1 & f2), sorted(f1 & f2)
	for st in set(p1) & set(p2):
		for key in set(p1[st]) & set(p2[st]):
			assert p1[st][key] == p2[st][key], (st, key)


class TestTwoMapsOfOneTarget:
	def test_built_in_targets(self, tmp_path):
		for target, template in TEMPLATES.items():
			d = tmp_path / target
			os.makedirs(str(d))
			extra = ['--mixed-names'] if target == 'windows-security-classic' else []
			apps = gen_two(d, target, template, extra)
			assert_coexist(apps)
			# the prefix follows --sourcetype
			assert any(n.startswith('tenx_one_') for n in apps[0][0])
			assert any(n.startswith('tenx_two_') for n in apps[1][0])

	def test_the_built_in_default_is_unchanged(self):
		for target in ('fortigate', 'windows-security', 'windows-security-classic'):
			t = fm.load_target(target, {})
			assert t['transform_prefix'] == t['sourcetype'] and t['transforms_class'] == t['sourcetype']
