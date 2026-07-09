"""
Offline test doubles for the Splunk-coupled parts of the 10x search path.

The alert compiler reuses TenxSearchBuilder, whose search_manager makes two Splunk
round-trips: parsing SPL into a command list, and looking up template hashes in the DML
store. These doubles reproduce both locally so the compiler can be tested end to end
without a live Splunk instance.

LocalSplParser.parse_search_string
    Mimics /services/search/parser for the single-search + simple-pipeline shapes that
    alerts use. It splits on top-level pipes (respecting quotes and bracket depth) and
    returns command dicts shaped like the endpoint's output. It does NOT split subsearches
    out of the leading search command the way Splunk's parser does - subsearches need the
    real endpoint - so tests here avoid them.

CsvTemplateStore / LocalSearchManager.run_dml_search
    Reproduce `search sourcetype=tenx_dml_pure <words>` against a set of templates. The
    searchable "pure" line is built with the app's own TenxDMLBuilder, so what we match
    against is exactly what Splunk would index. Matching is a case-insensitive substring
    test per OR'd word - lenient relative to Splunk's segment tokenizer, but deterministic
    and sufficient for asserting which hashes a search resolves to.
"""
import csv
import re

import tenx_consts
import tenx_dml_builder


def split_pipes(spl):
	"""
	Splits an SPL string on top-level '|' separators.

	Ignores pipes inside double-quoted strings and inside '[...]' subsearch brackets, and
	honours backslash escaping inside quotes. Returns the stripped, non-empty segments.
	"""
	parts = []
	buf = []
	depth = 0
	in_quote = False
	escaped = False

	for ch in spl:
		if escaped:
			buf.append(ch)
			escaped = False
			continue

		if ch == '\\':
			buf.append(ch)
			escaped = True
			continue

		if ch == '"':
			in_quote = not in_quote
			buf.append(ch)
			continue

		if not in_quote and ch == '[':
			depth += 1
			buf.append(ch)
			continue

		if not in_quote and ch == ']':
			depth = max(0, depth - 1)
			buf.append(ch)
			continue

		if not in_quote and ch == '|' and depth == 0:
			parts.append(''.join(buf))
			buf = []
			continue

		buf.append(ch)

	parts.append(''.join(buf))

	return [part.strip() for part in parts if part.strip()]


class LocalSplParser:
	"""Local stand-in for TenxSearchManager.parse_search_string."""

	def parse_search_string(self, search, parse_only=False):
		commands = []

		for part in split_pipes(search):
			tokens = part.split(None, 1)

			if not tokens:
				continue

			name = tokens[0].lower()
			rawargs = tokens[1] if len(tokens) > 1 else ''

			command = {'command': name, 'rawargs': rawargs, 'args': {}}

			if name == 'search':
				# Splunk returns the search body under args.search as a list the builder
				# concatenates; a single element preserving the full body is compatible for
				# non-subsearch inputs.
				command['args'] = {'search': [rawargs]}

			commands.append(command)

		return {'commands': commands}


class CsvTemplateStore:
	"""
	A DML template store backed by (hash, pattern) pairs, matching the way Splunk's
	tenx_dml_pure sourcetype answers keyword searches.
	"""

	def __init__(self, templates, timestamp_placeholder=None, variable_separator=None):
		config = tenx_consts.DEFAULT_CONFIG

		builder = tenx_dml_builder.TenxDMLBuilder(
			timestamp_placeholder=timestamp_placeholder or config['timestamp_placeholder'],
			variable_separator=variable_separator or config['variable_separator'])

		# Pre-build the searchable "pure" line for each template and tokenize it, approximating
		# Splunk's segment-based keyword matching (whole tokens, not substrings, so a search for
		# "count" does not match a template containing "account").
		self._token_sets = [
			(pattern_hash, self._tokenize(builder.build_pure_dml_line(pattern_hash, pattern)))
			for pattern_hash, pattern in templates
		]

	@staticmethod
	def _tokenize(text):
		return set(token for token in re.split(r'[^a-z0-9]+', text.lower()) if token)

	@staticmethod
	def _word_matches(word, tokens):
		if word.endswith('*'):
			prefix = word[:-1]
			return True if not prefix else any(token.startswith(prefix) for token in tokens)

		return word in tokens

	@classmethod
	def from_csv(cls, path):
		"""Loads templates from a demo/export CSV (columns _KEY/pattern_hash and pattern)."""
		templates = []

		# utf-8-sig strips a leading BOM if the export has one.
		with open(path, newline='', encoding='utf-8-sig') as handle:
			reader = csv.DictReader(handle)

			for row in reader:
				pattern_hash = row.get('_KEY') or row.get('pattern_hash')
				pattern = row.get('pattern', '')

				if pattern_hash:
					templates.append((pattern_hash, pattern))

		return cls(templates)

	def matching_hashes(self, or_based_search):
		"""
		Returns the hashes whose pure line contains any of the OR'd search words as a token.

		or_based_search is the ' OR '-joined word list the builder passes to run_dml_search.
		"""
		words = [word.strip().lower() for word in or_based_search.split(' OR ') if word.strip()]

		if not words:
			return []

		hits = [pattern_hash for pattern_hash, tokens in self._token_sets
				if any(self._word_matches(word, tokens) for word in words)]

		return sorted(set(hits))


class LocalSearchManager(LocalSplParser):
	"""
	Drop-in TenxSearchManager for the compiler tests.

	Provides the two methods TenxSearchBuilder needs off a search_manager for the
	non-subsearch path: parse_search_string (from LocalSplParser) and run_dml_search.
	"""

	def __init__(self, template_store, fail_dml=False):
		self.store = template_store
		# When True, run_dml_search returns None to exercise the compile-time DML failure
		# path (which the builder surfaces as ResolvedState.FAILURE -> REJECTED).
		self.fail_dml = fail_dml

	def run_dml_search(self, dml_search, max_time_ms=2000, poll_interval_ms=50):
		if self.fail_dml:
			return None

		return self.store.matching_hashes(dml_search)
