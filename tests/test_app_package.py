"""
Static checks on the app package: the things a Splunkbase reviewer or a first-time user
meets before any search runs, and that no other test reads.

Each guards a defect that shipped:

- Both dashboards named `index=tenx_encoded`, an index the setup guide never creates, so
  every panel read zero on a deployment that followed the guide. They now read the
  `tenx-events` macro.
- Those two dashboards measure the compact form (compact bytes, template hashes). Routed
  through the search rewrite they would be expanded first, so dashboard.js must leave them
  out.
- Splunkbase requires the listing name to match `[ui] label`, to lead with the brand, and
  not to read "for Splunk".
- Splunk 10's side navigation draws each view as the first character of its title; three
  titles starting "10x" drew three identical "1" icons.
"""
import configparser
import os
import re
import xml.etree.ElementTree as ET

import pytest

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk'))
VIEWS = os.path.join(APP, 'default', 'data', 'ui', 'views')


def conf(name):
	parser = configparser.RawConfigParser(strict=False, interpolation=None)
	parser.optionxform = str
	parser.read(os.path.join(APP, 'default', name))
	return parser


def view_files():
	return sorted(f for f in os.listdir(VIEWS) if f.endswith('.xml'))


def queries(view_file):
	root = ET.parse(os.path.join(VIEWS, view_file)).getroot()
	return [q.text or '' for q in root.iter('query')]


class TestDashboardsFindCompactEvents:
	def test_no_view_hard_codes_an_index_for_compact_events(self):
		offenders = [(f, q.strip()[:80]) for f in view_files() for q in queries(f)
					 if re.search(r'\bindex\s*=\s*tenx_encoded\b', q)]
		assert offenders == []

	def test_the_macro_the_dashboards_read_is_defined(self):
		macros = conf('macros.conf')
		assert macros.has_section('tenx-events')
		assert 'sourcetype=tenx_encoded' in macros.get('tenx-events', 'definition')

	def test_every_compact_panel_reads_the_macro(self):
		for f in ('tenx_dashboard.xml', 'tenx_diagnostics.xml'):
			compact = [q for q in queries(f) if 'inputlookup' not in q and 'index=_internal' not in q
					   and 'sourcetype=tenx_dml' not in q]
			assert compact, f
			assert all('`tenx-events`' in q for q in compact), f


class TestHookLeavesCompactFormViewsAlone:
	def test_dashboard_js_excludes_both_compact_form_views(self):
		js = open(os.path.join(APP, 'appserver', 'static', 'dashboard.js'), encoding='utf-8').read()
		listed = re.search(r'compactFormViews\s*=\s*\[([^\]]*)\]', js)
		assert listed, "dashboard.js no longer names the views it must leave alone"
		names = re.findall(r'"([^"]+)"', listed.group(1))
		assert set(names) >= {'tenx_dashboard', 'tenx_diagnostics'}

	def test_the_excluded_views_exist(self):
		for name in ('tenx_dashboard', 'tenx_diagnostics'):
			assert os.path.exists(os.path.join(VIEWS, name + '.xml'))


class TestSplunkbaseListingRules:
	def test_label_follows_the_naming_rules(self):
		label = conf('app.conf').get('ui', 'label')
		assert 5 <= len(label) <= 80
		assert label.startswith('Log10x')
		assert not re.search(r'\bfor splunk\b', label, re.I)
		assert not label.lower().startswith('splunk')

	def test_launcher_and_id_versions_agree(self):
		app = conf('app.conf')
		assert app.get('launcher', 'version') == app.get('id', 'version')
		assert re.fullmatch(r'\d+\.\d+\.\d+', app.get('launcher', 'version'))

	def test_package_id_matches_the_folder(self):
		assert conf('app.conf').get('package', 'id') == os.path.basename(APP)


class TestSideNavigationIsLegible:
	def test_views_in_the_nav_start_with_distinct_characters(self):
		nav = ET.parse(os.path.join(APP, 'default', 'data', 'ui', 'nav', 'default.xml')).getroot()
		own = [v.get('name') for v in nav.iter('view') if os.path.exists(os.path.join(VIEWS, v.get('name') + '.xml'))]
		firsts = [ET.parse(os.path.join(VIEWS, name + '.xml')).getroot().findtext('label').strip()[0].upper()
				  for name in own]
		assert len(own) >= 3
		assert len(set(firsts)) == len(firsts), dict(zip(own, firsts))


class TestPackageHygiene:
	def test_license_and_notices_ship_in_the_package(self):
		for name in ('LICENSE', 'THIRD_PARTY_NOTICES'):
			assert os.path.getsize(os.path.join(APP, name)) > 0, name

	def test_only_admins_and_power_users_write_the_template_store(self):
		meta = open(os.path.join(APP, 'metadata', 'default.meta')).read()
		for stanza in ('collections/tenx_dml', 'transforms/tenx-dml-lookup', 'props'):
			block = meta.split('[' + stanza + ']', 1)[1].split('\n[', 1)[0]
			assert 'write : [ * ]' not in block, stanza

	def test_no_handler_logs_the_raw_request(self):
		# The request payload carries the caller's session token.
		for name in os.listdir(os.path.join(APP, 'bin')):
			if name.endswith('.py'):
				source = open(os.path.join(APP, 'bin', name)).read()
				assert not re.search(r'logger\.\w+\(\s*in_string(_json)?\s*\)', source), name
