"""
A compiled alert is stored as a saved search, and Splunk token-substitutes a saved search's text when
it dispatches it: `$$` becomes `$`, and `$name$` is read as a token. A template hash holding `$` was
written into the compiled text as it is, so TERM(JVSWh$$) ran as TERM(JVSWh$) and selected none of
that template's events (Splunk Enterprise 10.4.3: 1,844 of 1,845 events; 21,439 of 175,480 measured
hashes hold a `$`). The compiler now writes each `$` of a hash as `$$`; the dashboard hook and the
`| tx` command, which run the text at once, keep it as it is.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'bin'))
sys.path.insert(0, os.path.dirname(__file__))

import tenx_search_builder
from tenx_alert_compiler import TenxAlertCompiler, AlertStrategy
from support.local_search_manager import LocalSearchManager, CsvTemplateStore

TEMPLATES = [
	('&h*JVSWh$$', 'user $ granted access by jsmith'),
	('ab$cd', 'jsmith logged out from $'),
	('plain1', 'jsmith opened $'),
]

CONFIG = {
	'tenx_source_types': ['tenx_encoded'], 'tenx_sources': [], 'dml_source_type': 'tenx_dml_pure',
	'timestamp_placeholder': '__TENX_TS__', 'variable_separator': '$',
	'tenx_extraction_name': 'REPORT-tenx', 'tenx_extraction': 'tenx-hash-vars-extraction',
}

SEARCH = 'search index=main sourcetype=tenx_encoded jsmith'


def builder():
	return tenx_search_builder.TenxSearchBuilder(
		server_connection=None, tenx_config=dict(CONFIG), search_manager=LocalSearchManager(CsvTemplateStore(TEMPLATES)))


def test_predicates_double_each_dollar_only_for_a_saved_search():
	assert tenx_search_builder.hash_predicate('ab$cd') == '"~ab$cd"'
	assert tenx_search_builder.hash_predicate('ab$cd', saved=True) == '"~ab$$cd"'
	term = tenx_search_builder.hash_predicate('&h*JVSWh$$')
	assert term.startswith('TERM(') and term.endswith('$$)') and '$$$$' not in term
	assert tenx_search_builder.hash_predicate('&h*JVSWh$$', saved=True) == term.replace('$', '$$')
	assert tenx_search_builder.hash_predicate('plain1', saved=True) == '"~plain1"'


def test_the_compiled_alert_doubles_and_the_hook_does_not():
	compiled = TenxAlertCompiler(builder()).compile(SEARCH)
	assert compiled.strategy == AlertStrategy.NATIVE, compiled.reason
	assert '"~ab$$cd"' in compiled.compiled_search
	assert '$$$$)' in compiled.compiled_search

	hook = builder().build(SEARCH).resolved
	assert '"~ab$cd"' in hook and '"~ab$$cd"' not in hook
	assert '$$)' in hook and '$$$$' not in hook


def test_what_splunk_runs_for_the_saved_search_holds_each_hash_as_written():
	compiled = TenxAlertCompiler(builder()).compile(SEARCH).compiled_search
	dispatched = compiled.replace('$$', '$')
	assert '"~ab$cd"' in dispatched
	assert tenx_search_builder.hash_predicate('&h*JVSWh$$') in dispatched
