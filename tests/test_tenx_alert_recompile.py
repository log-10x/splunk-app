"""
The scheduled recompile pass: it finds every user's compiled alerts, writes each back to its
owner, and picks up a template that appeared after an alert was compiled.
"""
import tenx_alert_persist
import tenx_alert_recompile
import tenx_search_builder
from tenx_alert_compiler import TenxAlertCompiler
from support.local_search_manager import CsvTemplateStore, LocalSearchManager


class Conn:
	"""Answers the conf listing from a list of stanzas; records posts; applies search updates."""
	def __init__(self, stanzas):
		self.user = 'splunk-system-user'
		self.stanzas = stanzas
		self.posts = []

	def get(self, url, params=None):
		self.list_url = url
		return {'entry': [{'name': s['name'], 'acl': {'owner': s['owner'], 'app': s.get('app', 'tenx-for-splunk')},
			'content': {'search': s['search'],
				tenx_alert_persist.ORIGINAL_SEARCH_KEY: s.get('original', ''),
				tenx_alert_persist.COMPILED_SEARCH_KEY: s.get('compiled', s['search'] if s.get('original') else '')}}
			for s in self.stanzas]}

	def post(self, url, data):
		self.posts.append((url, data))
		for s in self.stanzas:
			if url.endswith('/saved/searches/' + s['name'].replace(' ', '%20')) and 'search' in data:
				s['search'] = data['search']
		return {}


CONFIG = {
	'tenx_source_types': ['tenx_encoded'], 'tenx_sources': [], 'dml_source_type': 'tenx_dml_pure',
	'timestamp_placeholder': '__TENX_TS__', 'variable_separator': '$',
	'tenx_extraction_name': 'REPORT-tenx', 'tenx_extraction': 'tenx-hash-vars-extraction',
}

TEMPLATES = [('h_cart1', 'cartstore get item $'), ('h_other', 'nothing to see $')]


def compiler_for(templates):
	manager = LocalSearchManager(CsvTemplateStore(templates))
	return TenxAlertCompiler(tenx_search_builder.TenxSearchBuilder(
		server_connection=None, tenx_config=CONFIG, search_manager=manager))


def compiled(templates, search):
	return compiler_for(templates).compile(search).compiled_search


SEARCH = 'sourcetype=tenx_encoded cartstore'


def test_every_owner_is_listed_and_each_alert_is_written_back_to_its_owner():
	old = compiled(TEMPLATES, SEARCH)
	conn = Conn([{'name': 'Cart alerts', 'owner': 'alice', 'search': old, 'original': SEARCH}])
	newer = TEMPLATES + [('h_cart2', 'cartstore quota exceeded for $')]

	summary = tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS, compiler_for(newer))

	assert conn.list_url.startswith('/servicesNS/-/tenx-for-splunk/')
	assert summary['recompiled'] == 1 and summary['updated'] == ['Cart alerts']
	assert all('/servicesNS/alice/tenx-for-splunk/' in url for url, _ in conn.posts)


def test_a_new_template_joins_the_alert():
	old = compiled(TEMPLATES, SEARCH)
	assert '"~h_cart2"' not in old
	conn = Conn([{'name': 'Cart alerts', 'owner': 'alice', 'search': old, 'original': SEARCH}])

	tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS,
		compiler_for(TEMPLATES + [('h_cart2', 'cartstore quota exceeded for $')]))

	assert '"~h_cart2"' in conn.stanzas[0]['search']


def test_nothing_is_written_when_no_template_changed():
	old = compiled(TEMPLATES, SEARCH)
	conn = Conn([{'name': 'Cart alerts', 'owner': 'alice', 'search': old, 'original': SEARCH}])

	summary = tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS, compiler_for(TEMPLATES))

	assert summary['unchanged'] == 1 and conn.posts == []


def test_other_apps_saved_searches_are_left_alone():
	conn = Conn([{'name': 'Theirs', 'owner': 'bob', 'app': 'search', 'search': 'x', 'original': SEARCH}])

	summary = tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS,
		compiler_for(TEMPLATES + [('h_cart2', 'cartstore quota exceeded for $')]))

	assert summary['examined'] == 0 and conn.posts == []


def test_a_hand_edited_alert_is_not_overwritten():
	old = compiled(TEMPLATES, SEARCH)
	conn = Conn([{'name': 'Cart alerts', 'owner': 'alice', 'search': old + ' | head 5',
		'original': SEARCH, 'compiled': old}])

	summary = tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS,
		compiler_for(TEMPLATES + [('h_cart2', 'cartstore quota exceeded for $')]))

	assert summary['drifted'] == 1 and conn.posts == []


def test_the_scheduled_pass_leaves_tenxsearch_saved_searches_alone():
	legacy = '| tenxsearch searchstring="sourcetype=tenx_encoded cartstore" | stats count'
	conn = Conn([{'name': 'Report', 'owner': 'alice', 'search': legacy}])

	summary = tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS,
		compiler_for(TEMPLATES), migrate_legacy=False)

	assert summary['examined'] == 0 and conn.posts == []
	assert conn.stanzas[0]['search'] == legacy


def test_the_button_still_converts_them():
	legacy = '| tenxsearch searchstring="sourcetype=tenx_encoded cartstore"'
	conn = Conn([{'name': 'Report', 'owner': 'alice', 'search': legacy}])

	summary = tenx_alert_recompile.recompile_all(conn, 'alice', compiler_for(TEMPLATES))

	assert summary['migrated'] == 1


def test_the_button_keeps_the_pipeline_after_tenxsearch():
	legacy = '| tenxsearch searchstring="sourcetype=tenx_encoded cartstore" | stats count'
	conn = Conn([{'name': 'Report', 'owner': 'alice', 'search': legacy}])

	summary = tenx_alert_recompile.recompile_all(conn, 'alice', compiler_for(TEMPLATES))

	assert summary['migrated'] == 1
	assert conn.stanzas[0]['search'] == compiled(TEMPLATES, 'sourcetype=tenx_encoded cartstore | stats count')
	assert conn.stanzas[0]['search'].endswith('| stats count')


def test_the_button_converts_a_tx_alert():
	conn = Conn([{'name': 'Report', 'owner': 'alice',
		'search': '| tx sourcetype=tenx_encoded cartstore | stats count'}])

	summary = tenx_alert_recompile.recompile_all(conn, 'alice', compiler_for(TEMPLATES))

	assert summary['migrated'] == 1
	assert conn.stanzas[0]['search'] == compiled(TEMPLATES, 'sourcetype=tenx_encoded cartstore | stats count')


def test_the_scheduled_pass_leaves_tx_saved_searches_alone():
	search = '| tx sourcetype=tenx_encoded cartstore | stats count'
	conn = Conn([{'name': 'Report', 'owner': 'alice', 'search': search}])

	summary = tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS,
		compiler_for(TEMPLATES), migrate_legacy=False)

	assert summary['examined'] == 0 and conn.stanzas[0]['search'] == search


def test_the_scheduled_pass_repairs_an_alert_stored_with_its_first_search_command():
	# Before 1.2.2 a native compile was stored as 'search <terms> | ...'; Splunk runs a saved search as
	# 'search <text>', so the alert found nothing. The scheduled pass rewrites it without that command,
	# also when its compile needs review (here no word restricts the compact events), and keeps the
	# fingerprint in step so later passes see no hand edit.
	now = compiled(TEMPLATES, SEARCH)
	assert not now.startswith('search ')
	before = 'search ' + now
	review = 'sourcetype=tenx_encoded NOT cartstore'
	before_review = 'search ' + compiled(TEMPLATES, review)
	conn = Conn([{'name': 'Cart alerts', 'owner': 'alice', 'search': before, 'original': SEARCH},
				 {'name': 'Not cart', 'owner': 'bob', 'search': before_review, 'original': review}])

	summary = tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS, compiler_for(TEMPLATES),
		migrate_legacy=False)

	assert summary['repaired'] == 2 and summary['updated'] == ['Cart alerts', 'Not cart']
	assert conn.stanzas[0]['search'] == now and conn.stanzas[1]['search'] == before_review[len('search '):]
	meta = [d for url, d in conn.posts if '/configs/conf-savedsearches/' in url]
	assert [d[tenx_alert_persist.COMPILED_SEARCH_KEY] for d in meta] == [now, before_review[len('search '):]]
	assert all('/servicesNS/%s/' % o in url for (url, _), o in zip(conn.posts, ['alice', 'alice', 'bob', 'bob']))


def test_a_repaired_alert_is_left_alone_on_the_next_pass():
	before = 'search ' + compiled(TEMPLATES, SEARCH)
	conn = Conn([{'name': 'Cart alerts', 'owner': 'alice', 'search': before, 'original': SEARCH}])
	tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS, compiler_for(TEMPLATES))
	conn.stanzas[0]['compiled'] = conn.stanzas[0]['search']
	conn.posts = []

	summary = tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS, compiler_for(TEMPLATES))

	assert summary['repaired'] == 0 and summary['unchanged'] == 1 and conn.posts == []


def test_a_hand_edited_old_alert_is_not_repaired():
	before = 'search ' + compiled(TEMPLATES, SEARCH)
	conn = Conn([{'name': 'Cart alerts', 'owner': 'alice', 'search': before + ' | head 5', 'original': SEARCH,
				  'compiled': before}])

	summary = tenx_alert_recompile.recompile_all(conn, tenx_alert_recompile.ALL_OWNERS, compiler_for(TEMPLATES))

	assert summary['drifted'] == 1 and summary['repaired'] == 0 and conn.posts == []


def test_only_a_leading_search_command_with_terms_is_repaired():
	r = tenx_alert_persist.repaired_search
	k = tenx_alert_persist.COMPILED_SEARCH_KEY
	assert r({'search': 'search index=a x | stats count', k: 'search index=a x | stats count'}) == 'index=a x | stats count'
	assert r({'search': 'SEARCH (a OR b)', k: 'SEARCH (a OR b)'}) == '(a OR b)'
	for text in ('| tx index=a x', 'searchtxn x', 'search | stats count', 'search', 'index=a x'):
		assert r({'search': text, k: text}) is None, text
	assert r({'search': 'search index=a x'}) is None
