"""
Tenx Alert Compiler Module
==========================

Compiles a human-authored search into native Splunk SPL **once, at save time**, so a
scheduled alert on 10x compact data runs as an ordinary saved search - no browser hook,
no per-run Python proxy.

Why save-time and not dispatch-time
-----------------------------------
The interactive path (tenx_search_hook.js -> /tenx-search) rewrites SPL in the browser
before it is dispatched. An alert is a saved search the scheduler runs server-side, so no
browser is involved and that hook never fires. Splunk exposes no supported pre-dispatch
SPL rewrite hook for the scheduler, and automatic search-time config (props.conf EVAL/LOOKUP)
can deliver decoded *fields* but cannot make plain keyword search match compact `_raw`.
The clean answer is to compile the search once, when the alert is created or updated, and
store the compiled SPL in savedsearches.conf. The scheduler then runs a plain, supported
saved search.

This module is the compile step. The /tenx-alert REST handler (tenx_alert_handler.py), the
Compile Alert view and the recompile pass over existing alerts are built on it.

What it produces
----------------
compile(user_search) returns an AlertCompileResult classifying the search into one of:

- NATIVE:       the search touches 10x-compact data and was compiled to a native
                hash-prefilter + inflate pipeline. This is the common case - an alert over
                a message type or a field. Store `compiled_search`. Flagged needs_review
                when the compile is storable but not fully trustworthy (see below).
- PASSTHROUGH:  the search does not touch compact data; it is stored unchanged.
- RETRYABLE:    a transient DML lookup failure (e.g. a busy indexer) - not a permanent
                problem with the search. Nothing is stored; the save layer should retry
                rather than drop or overwrite a live alert.
- REJECTED:     the search could not be parsed/resolved, or cannot be compiled safely
                (unparseable, or too complex for the builder to modify - see resolve_state
                COMPLEX). Nothing is stored; the caller should
                surface the reason. A search this compiler rejects can still be scheduled
                manually via the `| tenxsearch` generating command (see tenxsearch.py) -
                that path is correct but proxies a nested job and is materially slower, so
                it is a human's call to make, not something this compiler auto-applies.

A NATIVE (or PASSTHROUGH) result is flagged needs_review, rather than rejected outright,
whenever the compile is storable but the compiler cannot fully vouch for it: an empty or
truncated hash prefilter, a string-valued field condition, a search with no hash prefilter
at all (full sourcetype scan, including a search whose every keyword is negated), or a
passthrough that still selects a configured compact source. See AlertCompileResult and
TenxAlertCompiler._compile_native for the exact cases.

Purity / testability
---------------------
The compiler itself holds no Splunk connection. All Splunk coupling lives in the injected
TenxSearchBuilder (its search_manager performs SPL parsing and the DML hash lookup). In
production that manager talks to Splunk; in tests it is a local double backed by the demo
template CSV, so compile() is exercised end to end without a live instance.

See Also
--------
- tenx_search_builder.py: TenxSearchBuilder.build() - the reused compile core.
- tenxsearch.py:          the generating command used for the escape hatch.
- SAVE_TIME_ALERTS.md in the app repository: how compiled alerts work.
"""

import logging

logger = logging.getLogger(__name__)

import re
import fnmatch

from enum import Enum, auto

from tenx_search_builder import ResolvedState


class AlertStrategy(Enum):
	"""How a search was (or could not be) compiled for use as a scheduled alert."""
	NATIVE = auto()        # compiled to a native hash-prefilter + inflate pipeline
	PASSTHROUGH = auto()   # not on compact data - stored unchanged
	RETRYABLE = auto()     # transient failure (e.g. DML lookup timed out) - retry, don't drop
	REJECTED = auto()      # could not parse/resolve, or cannot be compiled safely - do not store


# Strategies whose compiled_search is safe to persist into savedsearches.conf.
# RETRYABLE and REJECTED are NOT storable: RETRYABLE means "keep the existing alert and retry
# later", REJECTED means "surface the reason and store nothing".
_STORABLE = (AlertStrategy.NATIVE, AlertStrategy.PASSTHROUGH)


class AlertCompileResult:
	"""
	Result of compiling one search for save-time use.

	Attributes
	----------
	strategy : AlertStrategy
	compiled_search : str or None
		The SPL to persist. None only when strategy is REJECTED.
	original_search : str
		The search as the user authored it (kept so the alert can be recompiled later
		when new templates arrive, and so the UI can show the human original).
	state : ResolvedState or None
		The underlying resolution state, for logging/debugging.
	needs_review : bool
		True when a human should confirm before the compiled search is applied - the escape
		hatch is slower, and some searches are stored/flagged despite the builder not being
		able to compile them with full confidence.
	reason : str or None
		Human-readable explanation, set whenever the outcome is not a clean compile.
	"""
	def __init__(self, strategy, compiled_search, original_search, state=None, needs_review=False, reason=None):
		self.strategy = strategy
		self.compiled_search = compiled_search
		self.original_search = original_search
		self.state = state
		self.needs_review = needs_review
		self.reason = reason

	@property
	def storable(self):
		"""Whether compiled_search is safe to write into a saved search."""
		return self.strategy in _STORABLE

	def __repr__(self):
		return "AlertCompileResult(strategy={}, storable={}, needs_review={}, reason={!r})".format(
			self.strategy.name, self.storable, self.needs_review, self.reason)


def _normalize_native(resolved_search):
	"""
	Normalizes a natively-compiled search into an idiomatic saved-search value.

	The builder joins commands with a leading ' | ', so its output begins with
	'| search ...'. A leading pipe is valid but non-idiomatic in savedsearches.conf, where
	the first command is conventionally the bare 'search ...'. Strip exactly the leading
	pipe when the first command is the `search` command - matched as a whole token (followed
	by whitespace, '(' or end), so a leading-pipe generating command whose name merely starts
	with "search" (e.g. `searchtxn`) is never corrupted. Inner '| search' re-narrow clauses
	are left untouched.
	"""
	stripped = resolved_search.strip()

	if stripped.startswith('|'):
		remainder = stripped[1:].lstrip()

		if re.match(r'search(\s|\(|$)', remainder, re.IGNORECASE):
			return remainder

	return stripped


# Specifier assignments of the form `sourcetype=<value>` / `source=<value>` (quoted or not).
# Only a real '=' (not '!=', '<=', '>=') is captured, so exclusions are not treated as targeting.
_SPECIFIER_RE = re.compile(r'(?<![!<>])\b(?:sourcetype|source)\s*=\s*(?:"([^"]*)"|([^\s"()]+))', re.IGNORECASE)


def _specifier_values(original_search):
	"""Returns the sourcetype/source values a search selects on (may contain glob chars)."""
	return [quoted or unquoted for quoted, unquoted in _SPECIFIER_RE.findall(original_search or '')]


def _referenced_tenx_sources(original_search, tenx_config):
	"""
	Returns the configured 10x sourcetypes/sources a search selects on.

	Safety net: the builder silently passes a search through unchanged when it cannot
	confidently determine that the search targets compact data (an ambiguous
	'sourcetype=a OR sourcetype=b', a wildcard 'sourcetype=tenx_*', or a shape its grammar
	cannot fully parse). For an alert that is dangerous - it would run un-inflated against
	compact events. When such a passthrough still selects a known compact sourcetype/source,
	we flag it for review rather than storing it blind.

	Matching is glob-aware and case-insensitive: a configured compact name is flagged when the
	value the user selected on equals it OR is a glob that matches it (so 'sourcetype=tenx_*'
	flags 'tenx_encoded'). It over-flags rather than under-flags - the safe bias for alerts.
	"""
	if not original_search or not tenx_config:
		return []

	values = [value.lower() for value in _specifier_values(original_search)]

	if not values:
		return []

	configured = list(tenx_config.get('tenx_source_types') or []) + list(tenx_config.get('tenx_sources') or [])

	matched = set()

	for name in configured:
		if not name:
			continue

		low = name.lower()

		for value in values:
			# exact, or the user's (possibly wildcarded) value matches the configured name
			if value == low or fnmatch.fnmatch(low, value):
				matched.add(name)
				break

	return sorted(matched)


# The `NOT` boolean operator is uppercase in SPL; a lowercase "not" or a quoted "NOT" is a term.
_NOT_RE = re.compile(r'\bNOT\b')


def _has_negation(original_search):
	"""
	Whether a search uses the `NOT` boolean operator outside quotes.

	The builder keeps negation and applies it after expansion, where the words are back, so
	a negated alert compiles correctly. What it cannot do is use the exclusion to narrow the
	compact events first (the prefilter is a superset, and the complement of a superset is
	not one), so the compiled alert scans wider than the positive form would. Flagged for
	review on that account. Quoted spans are removed first so a literal "NOT" inside a
	phrase is not mistaken for the operator.
	"""
	if not original_search:
		return False

	unquoted = re.sub(r'"[^"]*"', ' ', original_search)

	return bool(_NOT_RE.search(unquoted))



class TenxAlertCompiler:
	"""
	Compiles human-authored searches into save-time alert SPL.

	Holds a TenxSearchBuilder (which owns all Splunk coupling via its search_manager). The
	compiler adds only the save-time policy on top of the builder's resolution.
	"""
	def __init__(self, builder):
		self.builder = builder

	def compile(self, user_search):
		"""
		Compiles user_search for use as a scheduled alert.

		Returns an AlertCompileResult. Never raises: a compiler-internal failure is reported
		as a REJECTED result rather than propagated, so a bad single alert can't abort a
		bulk migration.
		"""
		original = (user_search or "").strip()

		if not original:
			return AlertCompileResult(
				AlertStrategy.REJECTED, None, user_search or "",
				reason="empty search")

		try:
			result = self.builder.build(original)
		except Exception as e:
			logger.warning("Alert compile failed for {!r} - {}.".format(original, e), exc_info=1)
			return AlertCompileResult(
				AlertStrategy.REJECTED, None, original,
				reason="compiler error: {}".format(e))

		state = result.state

		if state == ResolvedState.SUCCESS:
			if result.engaged:
				return self._compile_native(original, result)

			return self._compile_passthrough(original, result)

		if state == ResolvedState.COMPLEX:
			# Do not auto-fall-back to `| tenxsearch`: it re-runs the same builder logic on
			# the same search, so a shape too complex for this compiler is generally too
			# complex for that command too, and it carries its own cost (a nested proxied
			# job, no streaming). Surface the reason; a human can still choose to schedule
			# `| tenxsearch searchstring="..."` manually, understanding that trade-off.
			return AlertCompileResult(
				AlertStrategy.REJECTED, None, original, state,
				reason=("search is too complex to compile into a native saved search; "
						"rewrite it, or schedule it manually via the `| tenxsearch` "
						"generating command (correct, and slower: it proxies a nested job)"))

		# A transient DML lookup failure is not a permanent problem with the search: the save
		# layer should retry rather than drop or overwrite a live alert.
		if state == ResolvedState.FAILURE and result.retryable:
			return AlertCompileResult(
				AlertStrategy.RETRYABLE, None, original, state,
				reason="template lookup failed (transient); retry, and keep the existing alert")

		# FAILURE (unparseable), PENDING or anything unexpected: do not persist a broken search.
		return AlertCompileResult(
			AlertStrategy.REJECTED, None, original, state,
			reason="could not resolve search (state {})".format(
				state.name if state is not None else "unknown"))

	def _compile_native(self, original, result):
		"""
		Builds a NATIVE result for a search that engaged 10x compilation, guarding constructs
		the builder mis-handles (or under-informs about) on compact data.

		Everything the builder cannot fully vouch for is NATIVE + needs_review: the compile
		is genuinely storable, but a human should confirm it before scheduling.
		"""
		compiled = _normalize_native(result.resolved)
		review_reasons = []

		if _has_negation(original):
			# Correct, and wider than it looks: the exclusion is applied after expansion, so
			# it does not narrow the compact events the way the positive terms do.
			review_reasons.append(
				"this alert uses NOT; the exclusion is applied after expansion, so the compact "
				"events are prefiltered by the positive terms only and the search scans wider "
				"than the same alert without the exclusion")

		if result.dml_truncated:
			# The builder leaves a keyword whose lookup was cut short out of the prefilter
			# entirely (a cut hash list can be relied on neither way), so the compiled search
			# is correct and wider than it could be.
			review_reasons.append(
				"the template lookup for at least one keyword was cut short (it ran out of time, "
				"or matched more message types than can be fetched); that keyword is left out of "
				"the prefilter, so the compiled search is correct but scans wider. Compiling again "
				"on a less busy instance may restore it")

		if result.no_prefilter:
			review_reasons.append(
				"none of this alert's keywords restricts the compact events (each is negated, "
				"or its template lookup was cut short), so the compiled search scans the entire "
				"compact sourcetype on every run and applies the keywords after expansion")
		elif not result.has_search_terms:
			# No keyword search terms at all (a field-only search like 'status=500', or no
			# filter beyond sourcetype) means no DML probe ever ran, so the compiled search
			# carries no hash prefilter - it scans the entire compact sourcetype every run.
			review_reasons.append(
				"this alert has no keyword search terms, so the compiled search has no hash "
				"prefilter and scans the entire compact sourcetype on every run")
		elif result.no_dml_results:
			review_reasons.append(
				"no message type currently matches these terms; this alert will only fire "
				"if a term appears as a variable value, not as template text. Confirm "
				"that is the intent, or recompile once a matching template exists")

		# Field conditions filter post-inflate via generic key=value extraction from the decoded
		# event text (logfmt-style, space-separated). That works, but it depends on the decoded
		# events actually carrying these as extractable fields: on a differently-shaped payload
		# (JSON, key:value, quoted values with spaces) the field may not extract and the alert
		# would silently never fire, or a bare key=value fragment elsewhere could over-match.
		# Flag for a human to confirm against real data rather than certifying it clean.
		if result.field_terms:
			review_reasons.append(
				"filters on field condition(s) {} via key=value extraction from the decoded event "
				"text; confirm those decode as fields (space-separated key=value). Other "
				"payload shapes may not extract, and the alert would then not fire".format(
					", ".join(result.field_terms)))

		if review_reasons:
			return AlertCompileResult(
				AlertStrategy.NATIVE, compiled, original, result.state,
				needs_review=True, reason="; ".join(review_reasons))

		return AlertCompileResult(AlertStrategy.NATIVE, compiled, original, result.state)

	def _compile_passthrough(self, original, result):
		"""
		Builds a PASSTHROUGH result for a search that resolved cleanly without engaging 10x.

		Usually that means the search doesn't target compact data and needs no rewriting - store
		what the user wrote. But the builder also passes a search through when it CANNOT
		confidently tell it targets compact data; if such a passthrough still selects a
		configured compact sourcetype/source, flag it rather than storing an alert that would run
		un-inflated.
		"""
		config = getattr(self.builder, 'tenx_config', None)
		referenced = _referenced_tenx_sources(original, config)

		if referenced:
			return AlertCompileResult(
				AlertStrategy.PASSTHROUGH, original, original, result.state,
				needs_review=True,
				reason=("search selects compact sourcetype/source {} but could not be compiled "
						"for expansion (too ambiguous to resolve safely); review before scheduling "
						"- it would otherwise alert on un-inflated compact events").format(
							", ".join(referenced)))

		return AlertCompileResult(AlertStrategy.PASSTHROUGH, original, original, result.state)
