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
