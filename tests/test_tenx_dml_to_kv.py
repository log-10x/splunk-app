"""
The template alert action must not write anything when the app's configuration cannot be
read: on the built-in defaults it would store templates in the wrong index and collection.
"""

import tenx_dml_to_kv
import tenx_util
import tenx_consts


def test_refuses_to_store_when_the_configuration_cannot_be_read(monkeypatch):
	calls = []

	def unreadable_config(**kwargs):
		config = dict(tenx_consts.DEFAULT_CONFIG)
		config[tenx_util.CONFIG_LOADED] = False
		return config

	class Recorder:
		def __init__(self, *args, **kwargs):
			calls.append((args, kwargs))

	monkeypatch.setattr(tenx_util, 'get_tenx_config', unreadable_config)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_dml_intf, 'TenxDmlInterface', Recorder)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_kv_intf, 'TenxKVInterface', Recorder)

	result = tenx_dml_to_kv.update_kv_store({'server_uri': 'https://x', 'session_key': 'k'})

	assert result == -1
	assert calls == []


def test_the_fallback_defaults_match_the_shipped_configuration():
	import configparser, os
	conf = configparser.ConfigParser(interpolation=None)
	conf.read(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'default', 'tenx_config.conf'))
	for key in ('dest_dml_index', 'dml_source_type', 'collection_name'):
		assert tenx_consts.DEFAULT_CONFIG[key] == conf.get('config', key), key


class StoreKV:
	"""A KV collection held in memory, keyed the way TenxKVInterface keys it."""

	def __init__(self, *args, **kwargs):
		self.records = {}
		self.updates = []
		StoreKV.last = self

	def kv_key(self, record_key):
		return record_key.strip()

	def get_entry(self, record_key):
		record = self.records.get(self.kv_key(record_key))
		return dict(record, _user='nobody') if record is not None else None

	def create_entry(self, record_key, record_data):
		self.records[self.kv_key(record_key)] = dict(record_data, _key=self.kv_key(record_key))
		return True

	def update_entry(self, record_key, record_data):
		self.updates.append(record_key)
		self.records[self.kv_key(record_key)] = dict(record_data, _key=self.kv_key(record_key))
		return True


class PureCopies:
	def __init__(self, *args, **kwargs):
		self.writes = 0
		PureCopies.last = self

	def write_pending(self):
		self.writes += 1
		return 0


def fill(monkeypatch, tmp_path, records, kv=None):
	import csv, gzip
	path = tmp_path / 'results.csv.gz'
	with gzip.open(path, 'wt', newline='') as f:
		writer = csv.DictWriter(f, fieldnames=['_raw', 'templateHash', 'template'])
		writer.writeheader()
		for template_hash, template in records:
			writer.writerow({'_raw': '', 'templateHash': template_hash, 'template': template})

	config = dict(tenx_consts.DEFAULT_CONFIG)
	config[tenx_util.CONFIG_LOADED] = True
	monkeypatch.setattr(tenx_util, 'get_tenx_config', lambda **kwargs: config)
	monkeypatch.setattr(tenx_util, 'ServerConnection', lambda **kwargs: None)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_kv_intf, 'TenxKVInterface', (lambda *a, **k: kv) if kv else StoreKV)
	monkeypatch.setattr(tenx_dml_to_kv.tenx_dml_intf, 'TenxDmlInterface', PureCopies)

	settings = {'server_uri': 'https://x', 'session_key': 'k', 'results_file': str(path), 'server_host': 'h'}
	return tenx_dml_to_kv.update_kv_store(settings)


TEMPLATE_A = '$(yyyy-MM-dd HH:mm:ss) INFO payment $ declined'
TEMPLATE_B = '$(yyyy-MM-dd HH:mm:ss) INFO refund $ approved'


def test_a_second_template_under_one_hash_marks_the_key_and_keeps_its_events_compact(monkeypatch, tmp_path, caplog):
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A), ('-Abc123xyz', TEMPLATE_B)])
	record = StoreKV.last.records['-Abc123xyz']

	assert record['expand_unsafe'] == 'hash-conflict'
	assert record['pattern'] == TEMPLATE_A
	assert record['search_copy'] == 'pending'
	assert PureCopies.last.writes == 1
	assert any('hash conflict' in r.getMessage() for r in caplog.records if r.levelname == 'WARNING')


def test_the_same_template_sent_again_changes_nothing(monkeypatch, tmp_path):
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A), ('-Abc123xyz', TEMPLATE_A)])

	assert StoreKV.last.records['-Abc123xyz']['expand_unsafe'] == ''
	assert StoreKV.last.updates == []


def test_two_hashes_that_trim_to_one_key_are_a_conflict(monkeypatch, tmp_path):
	fill(monkeypatch, tmp_path, [('Abc123xyz ', TEMPLATE_A), ('Abc123xyz', TEMPLATE_B)])

	assert StoreKV.last.records['Abc123xyz']['expand_unsafe'] == 'hash-conflict'


def test_a_conflict_is_marked_once(monkeypatch, tmp_path):
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A), ('-Abc123xyz', TEMPLATE_B), ('-Abc123xyz', TEMPLATE_B)])

	assert StoreKV.last.updates == ['-Abc123xyz']


def test_a_stored_template_cut_short_is_replaced_by_the_whole_one(monkeypatch, tmp_path):
	whole = TEMPLATE_A + ' for order $ after $ retries'
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A[:30]), ('-Abc123xyz', whole)])
	record = StoreKV.last.records['-Abc123xyz']

	assert record['pattern'] == whole
	assert record['expand_unsafe'] == ''


def test_a_conflict_on_an_earlier_run_is_found_on_a_later_one(monkeypatch, tmp_path):
	kv = StoreKV()
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A)], kv=kv)
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_B)], kv=kv)

	assert kv.records['-Abc123xyz']['expand_unsafe'] == 'hash-conflict'


def test_a_whole_template_replacing_a_cut_one_gets_a_new_searchable_copy(monkeypatch, tmp_path):
	whole = TEMPLATE_A + ' for order $ after $ retries'
	kv = StoreKV()
	fill(monkeypatch, tmp_path, [('-Abc123xyz', TEMPLATE_A[:30])], kv=kv)
	kv.records['-Abc123xyz']['search_copy'] = 'written'
	fill(monkeypatch, tmp_path, [('-Abc123xyz', whole)], kv=kv)

	assert kv.records['-Abc123xyz']['search_copy'] == 'pending'


def test_a_cut_re_send_of_a_stored_whole_template_is_not_a_conflict(monkeypatch, tmp_path):
	whole = TEMPLATE_A + ' for order $ after $ retries'
	fill(monkeypatch, tmp_path, [('-Abc123xyz', whole), ('-Abc123xyz', whole[:40])])
	record = StoreKV.last.records['-Abc123xyz']

	assert record['pattern'] == whole
	assert record['expand_unsafe'] == ''
	assert StoreKV.last.updates == []
