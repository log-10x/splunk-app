"""
Unit tests for tenx_util module.

Focuses on escape_spl_string_literal, the SPL string-literal escaping used whenever a
DML-derived hash is embedded into a generated `tenx_hash IN (...)` clause.
"""
import tenx_consts
import tenx_util


class TestEscapeSplStringLiteral:
	"""Tests for escape_spl_string_literal."""

	def test_plain_hash_is_unchanged(self):
		assert tenx_util.escape_spl_string_literal("abc123") == "abc123"

	def test_dollar_prefixed_hash_is_unchanged(self):
		# real 10x hashes commonly start with a literal '$'
		assert tenx_util.escape_spl_string_literal("$bcj4ljY0Wn") == "$bcj4ljY0Wn"

	def test_embedded_double_quote_is_escaped(self):
		assert tenx_util.escape_spl_string_literal('h"ash') == 'h\\"ash'

	def test_embedded_backslash_is_escaped(self):
		assert tenx_util.escape_spl_string_literal("h\\ash") == "h\\\\ash"

	def test_backslash_immediately_before_quote_is_not_double_escaped_wrong(self):
		# backslash must be escaped first so the injected quote-escape backslash isn't
		# itself re-escaped
		assert tenx_util.escape_spl_string_literal('h\\"ash') == 'h\\\\\\"ash'

	def test_comma_pipe_and_brackets_pass_through(self):
		assert tenx_util.escape_spl_string_literal("h,ash|[pipe]") == "h,ash|[pipe]"

	def test_unicode_passes_through(self):
		assert tenx_util.escape_spl_string_literal("häsh") == "häsh"

	def test_empty_string(self):
		assert tenx_util.escape_spl_string_literal("") == ""

	def test_full_metacharacter_mix_round_trips_into_a_quoted_clause(self):
		hash_value = 'h"ash,\\ [pipe|bracket]'
		escaped = tenx_util.escape_spl_string_literal(hash_value)

		assert escaped == 'h\\"ash,\\\\ [pipe|bracket]'

		clause = 'tenx_hash IN ("{}")'.format(escaped)
		assert clause == 'tenx_hash IN ("h\\"ash,\\\\ [pipe|bracket]")'

	def test_newline_is_escaped(self):
		assert tenx_util.escape_spl_string_literal("h\nash") == "h\\nash"

	def test_carriage_return_is_escaped(self):
		assert tenx_util.escape_spl_string_literal("h\rash") == "h\\rash"

	def test_tab_is_escaped(self):
		assert tenx_util.escape_spl_string_literal("h\tash") == "h\\tash"


class _Stanza:
	def __init__(self, name, content):
		self.name = name
		self.content = content


class _Confs:
	"""
	Stands in for service.confs. props is a list rather than a set of merged stanzas
	because that is what Splunk returns: one entry per configuration layer that defines a
	stanza, so the same sourcetype legitimately appears more than once.
	"""

	def __init__(self, props, config=None):
		self._props = props
		self._config = config or {}

	def __getitem__(self, name):
		if name == 'props':
			return self._props

		if name == 'tenx_config':
			return {'config': _Stanza('config', self._config)}

		raise KeyError(name)


class _Service:
	def __init__(self, props, config=None):
		self.confs = _Confs(props, config)


def _service_with(*sourcetypes):
	# props.conf carries the extraction as "<REPORT key> = <transforms stanza>", and the
	# loader matches on both sides of that pair.
	extraction = {
		tenx_consts.DEFAULT_CONFIG[tenx_consts.TENX_EXTRACTION_NAME]:
			tenx_consts.DEFAULT_CONFIG[tenx_consts.TENX_EXTRACTION],
	}
	return _Service([_Stanza(name, dict(extraction)) for name in sourcetypes])


class TestGetTenxConfigDoesNotAccumulate:
	"""
	The sourcetype list is built by appending. It used to be appended to the list held in
	DEFAULT_CONFIG, because the loader handed out that object instead of a copy, so every
	call added another entry to the same list. A persistent REST handler is one process for
	as long as Splunk runs, and the endpoint's answer grew with every request and went on
	naming sourcetypes whose props stanza had been deleted.
	"""

	def test_two_calls_give_the_same_answer(self):
		service = _service_with('tenx_encoded')

		first = tenx_util.get_tenx_config(service=service)
		second = tenx_util.get_tenx_config(service=service)

		assert first['tenx_source_types'] == ['tenx_encoded']
		assert second['tenx_source_types'] == ['tenx_encoded']

	def test_ten_calls_do_not_grow_it(self):
		service = _service_with('tenx_encoded')

		for _ in range(10):
			result = tenx_util.get_tenx_config(service=service)

		assert result['tenx_source_types'] == ['tenx_encoded']

	def test_the_module_default_is_left_alone(self):
		service = _service_with('tenx_encoded')

		tenx_util.get_tenx_config(service=service)

		assert tenx_consts.DEFAULT_CONFIG['tenx_source_types'] == []
		assert tenx_consts.DEFAULT_CONFIG['tenx_sources'] == []

	def test_the_returned_list_is_not_the_default_object(self):
		service = _service_with()

		result = tenx_util.get_tenx_config(service=service)
		result['tenx_source_types'].append('mutated')

		assert tenx_consts.DEFAULT_CONFIG['tenx_source_types'] == []

	def test_a_sourcetype_in_two_layers_is_listed_once(self):
		# props_conf returns a stanza once per layer that defines it. That is still one
		# sourcetype, and the endpoint reported it twice.
		service = _service_with('tenx_encoded', 'tenx_encoded', 'other_encoded')

		result = tenx_util.get_tenx_config(service=service)

		assert result['tenx_source_types'] == ['tenx_encoded', 'other_encoded']
