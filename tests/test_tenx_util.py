"""
Unit tests for tenx_util module.

Focuses on escape_spl_string_literal, the SPL string-literal escaping used whenever a
DML-derived hash is embedded into a generated `tenx_hash IN (...)` clause.
"""
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
