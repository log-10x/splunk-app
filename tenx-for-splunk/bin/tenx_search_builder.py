"""
Tenx Search Builder Module
=========================

This module provides the core logic for converting user search queries into
10x-compatible searches that work on encoded data. It handles:

- Parsing SPL commands using Splunk's parser
- Identifying searches that target 10x-encoded sourcetypes
- Resolving search terms against the DML (template) data
- Building combined searches that cover both variable and template matches

Search Resolution Process
-------------------------
1. Parse user search via Splunk's /services/search/parser endpoint
2. For each 'search' command in the SPL chain:
   a. Check if it targets an 10x-encoded sourcetype/source
   b. Extract search terms (index expressions, field expressions)
   c. Compile the keyword terms into a PREFILTER over the compact events (see below)
3. Append tenx-inflate macro to decode results
4. Re-apply the user's own terms to the decoded events
5. Return the resolved search string

The prefilter
-------------
A compact event holds the template hash and the variable values; the template's constant
words are only in the dictionary (sourcetype tenx_dml_pure). So a word the user searched
for is in the original line if it is in the compact event's raw text OR in the text of the
event's template. The prefilter only has to be a SUPERSET of the true matches, because the
user's terms are applied again after expansion (step 4), which removes anything the
prefilter let through by accident.

Each keyword is first cut into PIECES at Splunk's own segmentation breakers, because the
engine splits values there too: an IP `192.168.45.200` is stored as four variables
`192,168,45,200` and a hostname `ip-192-168-42-205.ec2.internal` as the template
`ip$$$$.ec2.internal` plus `-192,-168,-42,-205`. Neither the compact event nor the template
contains the whole value as one token, so it has to be matched piece by piece. Each piece is
looked up in the dictionary, and then:

- a piece no template contains MUST be in the compact raw, so it is required there;
- a piece some templates contain is either in the raw or in one of those templates:
  ("piece" OR <those hashes>).

Boolean structure is compiled the same way: AND of supersets is a superset, OR of supersets
is a superset, and a negated term contributes nothing to the prefilter (its exclusion is
applied after expansion, where the words are back).

A hash is matched as the phrase "~<hash>" rather than tenx_hash="<hash>": the tilde is not
a breaker, so the indexed token is `~KC`, not `KC`, and a field predicate on the hash was
pushed down to the lexicon and found nothing for every hash containing a space (305 of 2,991)
or a `*` (372 of 2,991, since `*` is a live wildcard even inside quotes).

Example Resolution
------------------
Original:
    search index=main sourcetype=tenx_encoded error

After resolution:
    search index=main sourcetype=tenx_encoded ("error" OR ("~hash1" OR "~hash2"))
    | `tenx-inflate`
    | extract
    | search error

Classes
-------
TenxSearchBuilder
    Main entry point for search resolution.

TenxSplCommands
    Container for a chain of SPL commands.

TenxSearchCommand
    Represents a 'search' command with 10x resolution logic.

TenxSplCommand
    Base class for any SPL command (non-search commands pass through unchanged).

ResolvedState
    Enum tracking resolution status (SUCCESS, FAILURE, COMPLEX, PENDING).

Complexity Handling
-------------------
Some searches are too complex to safely modify (e.g., nested OR conditions
mixing sourcetype with other criteria). These are marked COMPLEX and passed
through unchanged.

See Also
--------
- tenx_spl_parser.py: SPL grammar and AST parsing
- tenx_search_manager.py: Search job management and DML queries
- macros.conf: tenx-inflate macro definition
"""

import logging

logger = logging.getLogger(__name__)

from parsimonious import ParseError

from enum import Enum, auto
import urllib.error

import tenx_util
import tenx_spl_parser
import tenx_search_manager


class ResolvedState(Enum):
	SUCCESS = auto()
	FAILURE = auto()
	COMPLEX = auto()
	PENDING = auto()


# Splunk's default segmenters (etc/system/default/segmenters.conf), major and minor
# breakers together, as single characters. '*' is a major breaker for the indexer but a live
# wildcard in a search term, so it stays attached to its piece. The multi-character majors
# ('--' and the %XX escapes) are covered by their single characters.
SEGMENT_BREAKERS = frozenset("[]<>(){}|!;,'\"\n\r\t &?+/:=@.-$#%\\_")

# A piece that matches more templates than this does not get its own ("piece" OR <hashes>)
# clause; every such piece shares one clause instead, so the compiled search does not
# repeat a long hash list once per piece. Either shape is a correct superset.
PER_PIECE_HASH_LIMIT = 500

# Total time one search may spend looking words up in the dictionary, and the most any
# single lookup may take. The budget is shared: a term cut into seven pieces is seven
# lookups. A freshly started Splunk can spend seconds on its first lookup; warm, a lookup
# takes about 0.3 seconds. A piece whose lookup does not fit in what is left is not used
# to narrow, which is correct and wider.
PROBE_BUDGET_MS = 30000
PROBE_MAX_MS = 10000

# A hash containing '*' cannot be matched as a whole phrase, because the '*' is a wildcard
# even inside quotes. The text before the first '*' is matched instead, when it is long
# enough to be a filter: "~-" matched 12,648 of 20,000 events and "~" matched 16,746.
HASH_PREFIX_MIN = 2


class DmlProbeFailed(Exception):
	"""The dictionary lookup for a piece did not complete (timeout, busy indexer, REST error)."""


def split_pieces(word):
	"""
	Cuts one search word into the pieces Splunk indexes it as: the runs between segment
	breakers. A piece made only of wildcards is dropped, since it matches everything.

	    split_pieces('192.168.45.200')                  -> ['192', '168', '45', '200']
	    split_pieces('ip-192-168-42-205.ec2.internal')  -> ['ip', '192', '168', '42', '205', 'ec2', 'internal']
	    split_pieces('err*')                            -> ['err*']
	"""
	pieces = []
	buf = []

	for ch in word:
		if ch in SEGMENT_BREAKERS:
			if buf:
				pieces.append(''.join(buf))
				buf = []
		else:
			buf.append(ch)

	if buf:
		pieces.append(''.join(buf))

	return [piece for piece in pieces if piece.strip('*')]


def quoted_term(text):
	"""A search term as a double-quoted SPL phrase. A '*' inside stays a wildcard."""
	return '"' + tenx_util.escape_spl_string_literal(text) + '"'


def hash_predicate(dml_hash):
	"""
	The SPL that selects the compact events of one template.

	Phrase "~<hash>" when the hash has no '*'; phrase "~<prefix>" for the text before the
	first '*' when that prefix is at least HASH_PREFIX_MIN characters (a superset, since other
	hashes may share the prefix); otherwise a field predicate, which Splunk answers by
	extraction rather than from the lexicon and which is itself a wildcard match. All three
	are supersets at worst, and the post-expansion search removes the excess. Measured
	coverage on 2,991 templates: 20,000 of 20,000 events.
	"""
	if '*' not in dml_hash:
		return quoted_term('~' + dml_hash)

	prefix = dml_hash.split('*', 1)[0]

	if len(prefix) >= HASH_PREFIX_MIN:
		return quoted_term('~' + prefix)

	return 'tenx_hash=' + quoted_term(dml_hash)


def hash_clause(hashes):
	"""
	One parenthesised OR over the predicates for a set of hashes, sorted and de-duplicated so
	the same template set always compiles to the same text (the compiled search is persisted
	in savedsearches.conf, and a recompile pass rewrites only when the text changed).
	"""
	return '(' + ' OR '.join(sorted(set(hash_predicate(dml_hash) for dml_hash in hashes))) + ')'


def conjoin(parts):
	"""
	The implicit-AND of the given prefilter parts. None means 'unrestricted' and is dropped;
	if nothing is left the whole conjunction is unrestricted (None).
	"""
	parts = [part for part in parts if part]

	if not parts:
		return None

	if len(parts) == 1:
		return parts[0]

	return ' AND '.join(part if is_wrapped(part) else '(' + part + ')' for part in parts)


def is_wrapped(text):
	"""Whether the text is one parenthesised group, so it needs no further parentheses."""
	if not (text.startswith('(') and text.endswith(')')):
		return False

	depth = 0

	for index, ch in enumerate(text):
		if ch == '(':
			depth += 1
		elif ch == ')':
			depth -= 1

			if depth == 0:
				return index == len(text) - 1

	return False


class BuildResult:
	"""
	Structured outcome of TenxSearchBuilder.build().

	Carries the resolved SPL together with the facts a save-time caller needs to decide
	policy, instead of forcing that caller to re-derive them by scanning the output text.

	Attributes
	----------
	state : ResolvedState
		Resolution state of the command chain.
	resolved : str
		The resolved SPL string (identical to what resolve() returns).
	engaged : bool
		True when the leading search actually compiled for 10x-compact data (i.e. the inflate
		macro was appended). Distinguishes a natively-compiled search from a passthrough
		without re-scanning the output for a macro name.
	field_terms : list of str
		The raw text of field conditions (e.g. 'status=500', 'level=error') on the leading
		search, so a caller can inspect them (a string-valued field compiles into a `| where`
		clause that may match nothing).
	retryable : bool
		True when the failure is a transient DML lookup failure rather than a permanent
		unparseable search - a save-time caller should retry rather than drop the alert.
	has_search_terms : bool
		True when the leading search had at least one keyword search term (as opposed to
		only field conditions). False for a field-only search like 'status=500', which
		never probes the DML and compiles with no hash prefilter at all - a full scan of
		the compact sourcetype on every run.
	no_dml_results : bool
		True when the leading search had keyword terms but none matched any template in the
		DML - the compile has no hash prefilter, only the raw keyword clause (which still
		catches a variable-value match).
	dml_truncated : bool
		True when a DML probe matched more rows than were fetched (see
		tenx_search_manager.DML_FETCH_LIMIT). A piece whose probe was truncated is left out
		of the prefilter altogether (the only safe treatment), so the compiled search is
		still correct but wider than it could be.
	no_prefilter : bool
		True when the leading search had keyword terms but none of them restricted the
		compact events at all, which happens when every keyword is negated: `NOT bootstrap`
		compiles to a full scan of the compact sourcetype, with the exclusion applied after
		expansion. Correct, and a scan.
	"""
	def __init__(self, state, resolved, engaged=False, field_terms=None, retryable=False,
				has_search_terms=False, no_dml_results=False, dml_truncated=False,
				no_prefilter=False):
		self.state = state
		self.resolved = resolved
		self.engaged = engaged
		self.field_terms = field_terms if field_terms is not None else []
		self.retryable = retryable
		self.has_search_terms = has_search_terms
		self.no_dml_results = no_dml_results
		self.dml_truncated = dml_truncated
		self.no_prefilter = no_prefilter


class TenxSplCommand:
	"""
	Class representing a single Splunk SPL command, exposing some parts for us as we work
	through them resolving the user searches and adapting them to search on 10x encoded data

	This base class does almost nothing, as the only command we actively need to work on
	is the search command, see TenxSearchCommand
	"""
	def __init__(self, raw_command, tenx_config, debug=False):
		self.raw_command = raw_command
		self.tenx_config = tenx_config

		self.debug = debug

	def resolved_state(self):
		"""
		Returns the current ResolvedState.

		For simple commands (any non-search ones), this is always ResolvedState.SUCCESS
		"""
		return ResolvedState.SUCCESS

	def simple_resolved(self):
		"""
		Returns the simple resolved value of the SPL command, which is identical to what it
		actually is, meaning the command name followed by the original arguments.
		"""
		result = self.raw_command['command']

		if self.raw_command['rawargs']:
			result += ' ' + self.raw_command['rawargs']

		return result

	def resolve(self):
		"""
		Resolves the command to work correctly on 10x encoded data.

		For simple commands (any non-search ones), nothing actually needs to be done.
		"""
		pass

	def resolved(self):
		"""
		Returns the proper resolved value of the commands, adapted to 10x encoded Data.

		For simple commands (any non-search ones), this is identical to simple_resolved.
		"""
		return self.simple_resolved()

	def command_name(self):
		"""
		Returns the command name
		"""
		return self.raw_command['command']


class TenxSearchCommand(TenxSplCommand):
	"""
	Class representing an SPL search command, used for resolving the actual search into one
	that can be run on encoded 10x data, if deemed necessary.

	The general idea is to run the user search on the 10x DML sourcetype, and from that search
	retrieve the matching 10x hashes that correspond to encoded templates which correlates to what
	the user searched for.

	Then, we alter to original search to *also* search for those hashes.
	The reason we're not searching for just the hashes, is because what the user searched for might
	appear in the variable portion of the events, which is in the original sourcetype the user is
	searching.

	Additionally, we chain a call to the 'tenx-inflate' macro, which as the name suggests is
	responsible to decoding the encoded data.
	"""
	def __init__(self, raw_command, server_connection, tenx_config, search_manager, force_tenx=False, debug=False):
		TenxSplCommand.__init__(self, raw_command, tenx_config, debug)

		self.search_manager = search_manager
		self.server_connection = server_connection
		self.too_complex = False
		self.needs_tenx = False
		self.force_tenx = force_tenx
		self.has_errors = False
		self.needs_original_search_check = False
		self.user_search_terms = []
		self.user_field_terms = []
		self.no_dml_results = False
		self.dml_search_failed = False
		self.dml_truncated = False
		self.parsed_command = None
		self.resolved_search = None
		self.resolved_done = False
		# Dictionary lookups by piece, shared across every term of this search: a piece the
		# user typed twice is probed once.
		self._probe_cache = {}
		self._template_hits = 0
		self._probe_deadline = None

		parsed_command = self._get_parsed_command()

		if parsed_command is None:
			return

		self.parsed_command = parsed_command

		self.too_complex = len(self.parsed_command.get_typed_children(tenx_spl_parser.SearchNodeType.COMPLEX)) > 0

		if self.too_complex:
			logger.info("search '{}' deemed too complex.".format(self.simple_resolved()))
			return

		self.needs_tenx = self.check_needs_tenx()

		if not self.needs_tenx:
			return

		self.user_search_terms = self.parsed_command.get_typed_children(tenx_spl_parser.SearchNodeType.INDEX)
		self.user_field_terms = self.parsed_command.get_typed_children(tenx_spl_parser.SearchNodeType.FIELD)

		# The prefilter is a superset, so the user's own terms are always re-applied to the
		# expanded events (see original_search_terms). The name is kept for its callers.
		self.needs_original_search_check = len(self.user_search_terms) > 0

	def _probe(self, piece):
		"""
		Returns (hashes, truncated) for the templates whose text contains the piece, via one
		dictionary search per distinct piece. Raises DmlProbeFailed when the lookup did not
		complete, which the caller turns into a retryable FAILURE rather than a guess.
		"""
		if piece not in self._probe_cache:
			remaining = PROBE_BUDGET_MS if self._probe_deadline is None else (
				self._probe_deadline - tenx_util.current_time_ms())

			if remaining <= 0:
				# The budget is spent. Do not dispatch: report the piece as unusable, which
				# leaves it out of the prefilter.
				logger.warning("Dictionary budget spent before probing {}.".format(piece))
				self._probe_cache[piece] = ([], True)
				return self._probe_cache[piece]

			hashes, incomplete = self.search_manager.run_dml_search(
				quoted_term(piece), min(remaining, PROBE_MAX_MS))

			# Specifically None check, as empty is ok
			#
			if hashes is None:
				if not incomplete:
					raise DmlProbeFailed(piece)

				# Did not finish in its budget. Correct to carry on without it.
				#
				hashes = []

			self._probe_cache[piece] = (hashes, incomplete)

		return self._probe_cache[piece]

	def _term_prefilter(self, term_text):
		"""
		The prefilter for one keyword term (a bare word or a quoted phrase).

		Every piece of every word must be present in the original line, so the pieces are
		conjoined. Each piece is either in the compact raw or in the template text:

		- no template contains it  -> it must be in the raw: required there
		- some templates contain it -> ("piece" OR <those templates' hashes>)

		Pieces that match many templates share one clause, ((p1 OR p2 ...) OR <hashes of the
		templates containing all of them>), which is the same superset argument applied to
		the group: if all of them are template text the hash clause selects it, otherwise at
		least one is in the raw and the OR of pieces selects it. A piece whose probe was
		truncated is left unrestricted, because a cut hash list cannot be relied on either way.
		"""
		pieces = []

		for word in tenx_util.strip_string(term_text).split():
			for piece in split_pieces(word):
				if piece not in pieces:
					pieces.append(piece)

		if not pieces:
			return None

		conjuncts = []
		shared_pieces = []
		shared_hashes = None

		for piece in pieces:
			hashes, truncated = self._probe(piece)

			if truncated:
				self.dml_truncated = True
				continue

			if not hashes:
				conjuncts.append(quoted_term(piece))
				continue

			self._template_hits += 1

			if len(hashes) <= PER_PIECE_HASH_LIMIT:
				conjuncts.append('(' + quoted_term(piece) + ' OR ' + hash_clause(hashes) + ')')
				continue

			shared_pieces.append(piece)
			shared_hashes = set(hashes) if shared_hashes is None else shared_hashes & set(hashes)

		if shared_pieces:
			shared = ' OR '.join(quoted_term(piece) for piece in shared_pieces)

			if shared_hashes:
				shared = '(' + shared + ') OR ' + hash_clause(shared_hashes)

			conjuncts.append('(' + shared + ')')

		return conjoin(conjuncts)

	def _prefilter(self, node):
		"""
		Compiles one node of the parsed search into its prefilter over compact events, or
		None when the node does not restrict them.

		Modifiers (index=, sourcetype=) are emitted separately by search_modifiers(). Field
		conditions are applied after expansion by field_search(). A negated term is
		unrestricted here and excluded after expansion by original_search_terms(): the
		prefilter is a superset, and the complement of a superset is not a superset.

		An OR node's children are its operands (the parser keeps Splunk's precedence, so
		`a OR b c` arrives as the OR of a and b, then c). An OR is unrestricted as soon as
		one operand is, since the OR of a superset with everything is everything.
		"""
		rule_type = node.rule_type

		if rule_type == 'index_expression':
			return self._term_prefilter(node.text)

		if rule_type in ('not_logical_expression', 'field_modifier', 'search_modifier'):
			return None

		if rule_type == 'or_expression':
			parts = [self._prefilter(child) for child in node.children]

			if any(part is None for part in parts):
				return None

			return ' OR '.join(part if is_wrapped(part) else '(' + part + ')' for part in parts)

		if node.children:
			# A parenthesised group, or any other grouping: an implicit AND of its children.
			#
			return conjoin([self._prefilter(child) for child in node.children])

		# A leaf this compiler does not know. Unrestricted is always safe here.
		#
		return None

	def _get_parsed_command(self):
		"""
		Extracts a structured ast from the given user search, using Splunk's bnf.

		Before parsing the command via BNF, resolve any internal subsearches to their actual value.
		"""
		search_string = "search "
		search_args = tenx_util.get_internal(self.raw_command, 'args', 'search')[:]  # Copy on purpose

		if search_args:
			for search_arg in search_args:
				arg_to_append = search_arg

				if search_arg.startswith('[') and search_arg.endswith(']'):
					resolved_subsearch = self._resolve_subsearch(search_arg)

					if not resolved_subsearch:
						logger.warning("Failed resolving subsearch {}".format(search_arg))
						self.has_errors = True
						return None

					arg_to_append = resolved_subsearch
					logger.info("Resolved subsearch {} ...xxx... {}".format(search_arg, arg_to_append))

				search_string += arg_to_append

		try:
			node = tenx_spl_parser.spl_grammar.parse(search_string.strip())
			return tenx_spl_parser.TenxSearchAstNodeFactory().build(node)

		except ParseError as pe:
			logger.warning("Failed parsing search - '{}' - {}".format(search_string, pe), exc_info=1)
		except Exception as e:
			logger.warning("Error building search ast - '{}' - {}.".format(search_string, e), exc_info=1)

		self.has_errors = True
		return None

	def _resolve_subsearch(self, subsearch):
		"""
		Resolves the provided subsearch, by first attempting to resolve it via a SearchBuilder,
		and then actually evaluate it's result by calling Splunks search parser endopint with
		the result.

		Returns None in case of failures.
		"""
		try:
			# Remove the leading and trailing brackets.
			#
			actual_subsearch = subsearch[1:-1]

			subsearch_builder = TenxSearchBuilder(
							server_connection=self.server_connection,
							tenx_config=self.tenx_config,
							search_manager=self.search_manager,
							force_tenx=self.force_tenx,
							debug=self.debug)

			resolved_subsearch = subsearch_builder.resolve(actual_subsearch)

			search_to_parse = "search [" + resolved_subsearch + "]"

			parsed_result = self.search_manager.parse_search_string(search_to_parse)

			parsed_args = tenx_util.get_internal(parsed_result, 'commands', 0, 'args', 'search')

			if not parsed_args:
				logger.warning("Didn't get parsed arguments for {}.".format(search_to_parse))
				return None

			if len(parsed_args) != 1:
				logger.warning("Got weird parsed args {} for search {}.".format(parsed_args, search_to_parse))
				return None

			return parsed_args[0]
		except Exception as e:
			logger.warning("Unexpected error resolving subsearch - {} - {}.".format(subsearch, e), exc_info=1)
			return None

	def resolve(self):
		"""
		Resolves the command to work correctly on 10x encoded data.

		Does so by running a search with the original user search terms on the DML sourcetype.
		
		From the results we then extract all the hashes matching the encoded events, and we
		create a new search which also searches for them in the encoded data.

		If we didn't get any results (it's possible the user searched for something that doesn't
		exist), we leave the original search terms as is.

		If we had any errors searching in the DML, we also do nothing, and mark it.
		"""
		if self.resolved_state() != ResolvedState.PENDING:
			# Nothing to do here.
			#
			return

		# The whole search body is an implicit AND of the root's children. Modifiers and
		# field conditions compile to None here and are emitted by their own methods.
		#
		self._probe_deadline = tenx_util.current_time_ms() + PROBE_BUDGET_MS

		try:
			self.resolved_search = conjoin([self._prefilter(child) for child in self.parsed_command.children])
		except DmlProbeFailed as e:
			# Logging already happens inside run_dml_search
			#
			logger.warning("Dictionary lookup did not complete for piece {} of '{}'.".format(e, self.simple_resolved()))
			self.has_errors = True
			# This is a transient lookup failure (job timeout/busy indexer), NOT a permanent
			# problem with the search itself. Save-time callers should retry, not drop the alert.
			#
			self.dml_search_failed = True
			return

		self.resolved_done = True
		# No template contained any piece the user typed: the search can only match on
		# variable values, and the compiled search says so by carrying no hash clause. A
		# truncated probe is not evidence either way, so it does not count as "none".
		#
		self.no_dml_results = (self._template_hits == 0 and not self.dml_truncated)

	def check_needs_tenx(self):
		"""
		Checks whether the given search needs a 10x resolving to run on encoded data.

		We define this as True if the search is explicitly running on at least one Splunk source/sourcetype
		which has encoded 10x data in it (i.e. not specifying ANY source/sourcetype is defined as not needing 10x)

		We determine which sources/sourcetypes have 10x encoded data by checking with our config.
		We identify sources/sourcetypes holding encoded data by them having a 10x field extraction defined in the
		props.conf file (see TenxConfig for more info on that)

		If a search contains a weirdly complex case of source/sourcetype statement where we can't determine
		if it's actually running on encoded data, like "search field=value OR sourcetype=my_sourcetype",
		we declare this to bee too complex, and return False.
		"""
		has_sourcetypes = self._check_needs_tenx('sourcetype_specifier', 'tenx_source_types', 'sourcetype')

		if has_sourcetypes:
			return True

		if self.too_complex:
			return False

		has_sources = self._check_needs_tenx('source_specifier', 'tenx_sources', 'source')

		if has_sources:
			return True

		if self.too_complex:
			return False

		return self.force_tenx

	def _check_needs_tenx(self, specifier, config_key_name, logging_str):
		passing_specifiers = self.parsed_command.get_passing_specifiers(specifier)

		if passing_specifiers is None:
			logger.info("Too complex {}s for {}.".format(logging_str, self.parsed_command.text))

			self.too_complex = True
			return False

		if len(passing_specifiers) == 0:
			logger.info("No tenx {}s for {}.".format(logging_str, self.parsed_command.text))

			return False

		for specifier in passing_specifiers:
			if specifier in self.tenx_config[config_key_name]:
				logger.info("Found tenx {} in {}.".format(logging_str, self.parsed_command.text))

				return True

		logger.info("No tenx {}s for {}.".format(logging_str, self.parsed_command.text))

		return False

	def resolved_state(self):
		"""
		Returns the current ResolvedState.

		If we don't actually need any resolving, either because the search doesn't run on encoded data,
		or the search doesn't need modification (see search_needs_modification), return ResolvedState.SUCCESS

		If we would want to resolve it, but can't because it's too complex, returns ResolvedState.COMPLEX

		If we encountered any errors that would prevent us from continueing, returns ResolvedState.FAILURE

		If we want and can resolve, returns ResolvedState.PENDING
		"""
		if not self.needs_tenx or self.parsed_command is None:
			# If we don't have a valid parsed command, we're still ready...
			#
			return ResolvedState.SUCCESS

		if self.too_complex:
			return ResolvedState.COMPLEX

		if len(self.user_search_terms) == 0:
			# Nothing to look up. The search still gets the inflate suffix (see resolved).
			#
			return ResolvedState.SUCCESS

		if self.has_errors:
			return ResolvedState.FAILURE

		if not self.resolved_done:
			return ResolvedState.PENDING

		return ResolvedState.SUCCESS

	def engaged_tenx(self):
		"""
		Returns whether this search actually compiled for 10x-compact data.

		True exactly when resolved() appends the inflate macro: the search targets compact
		data (needs_tenx), it was not too complex to modify, it had no errors, and it parsed.
		Save-time callers use this to tell a native compile from a passthrough without
		scanning the resolved text for a macro name.
		"""
		return bool(self.needs_tenx and not self.too_complex and not self.has_errors and self.parsed_command is not None)

	def has_dml_user_search_terms(self):
		"""
		Returns whether we have found any of the user search terms in the dml
		"""
		return len(self.user_search_terms) > 0 and not self.no_dml_results

	def has_user_field_terms(self):
		"""
		Returns if there are field terms in the user search
		"""
		return len(self.user_field_terms) > 0

	def search_needs_modification(self):
		"""
		Returns whether we need to actually modify the original user search.

		We need to modify it if we have any search terms found in the dml, or there are field terms
		"""
		return self.has_dml_user_search_terms() or self.has_user_field_terms()

	def search_modifiers(self):
		"""
		Returns the original search modifiers on the search, such as sourcetype, host, etc..
		"""
		result = ""

		for modifier in self.parsed_command.get_typed_children(tenx_spl_parser.SearchNodeType.MODIFIER):
			result += ' ' + modifier.text

		return result

	def inflate_suffix(self):
		"""
		Returns the suffix needed to chain into the 'tenx-inflate' macro, as well as chaining into SPL 'extract'
		so we will restore the user defined extractions after we decode, and 'spath' so a decoded JSON
		or XML line gets its structured fields back: 'extract' alone leaves them out, so a search for
		kubernetes.container_name=accounting after expansion found 0 of 69. On a plain-text line 'spath'
		extracts nothing and costs little.

		'extract' re-runs every search-time extraction of the compact sourcetype on the expanded line,
		including the compact-format one, whose regex matches any line containing a comma. That put a
		tenx_hash of '{"stream":"stdout"' and a tenx_vars of the rest of the line on every expanded
		event, in the field sidebar. Those three are removed again; tenx_expand_refused, which the
		macro keeps on purpose, is not.

		Different macro chosen if we're running in debug mode or not, either 'tenx-inflate' or 'tenx-inflate-debug'
		"""
		return (" | " + tenx_util.splunk_inflate_macro(self.debug)
				+ " | extract | spath | fields - tenx_hash, tenx_var_0, tenx_vars")

	def field_search(self):
		"""
		Returns the clause that filters on the field conditions the user requested.

		The decoded events carry the user's original key=value pairs, but the encoded sourcetype's
		own extraction is the compact comma form, which does not match the decoded text - so
		`| extract` alone leaves those fields unextracted. We force generic key=value extraction on
		the decoded _raw, then filter with search-command semantics (which is what the user wrote;
		unlike `| where`, `| search field=value` reads a bare value as a literal, not a field
		reference, so a string value like `level=error` matches instead of silently comparing two
		fields). This handles string and numeric values, and IN(...) lists, uniformly.
		"""
		return ' | extract kvdelim="=" pairdelim=" " | search ' + " ".join([item.text for item in self.user_field_terms])

	def original_search_terms(self):
		"""
		Returns a "search" on the original terms of the search query.

		This is needed to filter out stuff that doesn't actually match and may be here by accident.

		This can happen for complex queries as we interlace data from variables (encoded events) and
		templates (coming from the decoding against kvdml)
		"""
		return " | search " + " ".join([item.text for item in self.user_search_terms])

	def resolved(self):
		"""
		Returns the proper resolved value of the commands, adapted to 10x encoded Data.

		In any case we decided we won't/can't do anything, if the search command is too complex,
		has any errors, or simply doesn't need any special treatment, returns the simple_resolved
		value, which is equivalent to the original search the user attempted.

		Assuming we actually did some resolving, we return the matching search on 10x encoded data,
		and chain this into the 'tenx-inflate' macro, to decode it.
		"""
		if not self.needs_tenx or self.too_complex or self.has_errors or self.parsed_command is None:
			# If we don't have a valid parsed command, we're still ready...
			#
			return self.simple_resolved()

		if self.resolved_state() != ResolvedState.SUCCESS:
			logger.warning("Bad state {}, returning simple - {}.".format(self.resolved_state(), self.simple_resolved()))

			return self.simple_resolved()

		# Building the new resolved search starts here.
		#
		result = "search"

		result += self.search_modifiers()

		# This should always be True, but let's check just in case.
		#
		if self.resolved_search:
			result += ' ' + self.resolved_search

		# We still need to chain into the 'tenx-inflate' macro here, because even if the user didn't
		# actually specify any search terms (or none were found in the DML), we know we're working on
		# encoded data at this point (self.needs_tenx is True), so the data returned from Splunk will
		# be encoded, and needs decoding.
		#
		result += self.inflate_suffix()

		if len(self.user_field_terms) > 0:
			result += self.field_search()

		if self.needs_original_search_check:
			result += self.original_search_terms()

		return result


class TenxSplCommands:
	"""
	Class representing a chain of SPL commands
	"""
	def __init__(self, commands, debug=False):
		self.commands = commands
		self.debug = debug

	def resolved_state(self):
		"""
		Returns the current ResolvedState of the command chain.

		If all commands in the chain have their state as ResolvedState.SUCCESS, returns ResolvedState.SUCCESS

		Otherwise, returns the state of the first command which isn't in ResolvedState.SUCCESS 
		"""
		for command in self.commands:
			current_state = command.resolved_state()

			if current_state is not ResolvedState.SUCCESS:
				return current_state

		return ResolvedState.SUCCESS

	def resolve(self):
		"""
		Resolves all commands in the chain that are currently in a ResolvedState.PENDING state
		"""
		for command in self.commands:
			logger.debug("Command {} with state {}.".format(command.command_name(), command.resolved_state()))

			if command.resolved_state() == ResolvedState.PENDING:

				try:
					command.resolve()
				except Exception as e:
					logger.warning("Failed resolving command - {} - {}".format(command, e), exc_info=1)

	def resolved(self):
		"""
		Returns the full resolved value of the chain.

		This is just the resolved value of each individual command, preceeded by a pipe sign before each command.
		"""
		result = ""

		for command in self.commands:
			result += " | " + command.resolved()

		return result


class TenxSearchBuilder:
	"""
	Class for building a search on 10x encoded data from a given user search.

	Does so by expanding user searches with the matching 10x searches on encoded data.
	"""
	def __init__(self, server_connection, tenx_config, search_manager=None, force_tenx=False, debug=False):
		self.server_connection = server_connection
		self.tenx_config = tenx_config
		self.search_manager = search_manager

		if self.search_manager is None:
			self.search_manager = tenx_search_manager.TenxSearchManager(server_connection, tenx_config)

		self.force_tenx = force_tenx
		self.debug = debug

	def get_search_commands(self, search):
		"""
		Returns a list of commands parsed by Splunks parser endpoint for a given search.

		Explicitly ask for a parse_only from the endpoint, as we manually resolve subsearches
		in SplSearchCommand._resolve_subsearch
		
		In case of errors, returns None
		"""
		if not search.startswith('search') and not search.startswith('|'):
			search = "search " + search

		try:
			parsed_result = self.search_manager.parse_search_string(search, parse_only=True)
		except urllib.error.HTTPError as e:
			logger.warning("Failed parsing search - {} - {}.".format(search, e), exc_info=1)
			return None
		except Exception as e:
			logger.error("Error parsing search - {} - {}.".format(search, e), exc_info=1)
			return None

		if 'commands' not in parsed_result:
			logger.warning("Missing commands when parsing search - {}.".format(search))
			return None
		
		commands = parsed_result['commands']

		if len(commands) == 0:
			logger.warning("Empty commands when parsing search - {}.".format(search))
			return None

		return commands

	def build(self, base_search):
		"""
		Core resolution shared by resolve() (the interactive path) and the save-time
		alert compiler (see tenx_alert_compiler.py).

		Parses the search via Splunk's parser endpoint, creates TenxSplCommands, resolves
		them, and returns a BuildResult so callers can inspect the resolution state (and the
		engaged/field_terms/retryable facts) to decide policy - for example whether it is safe
		to persist the resolved search into a scheduled alert, or whether it is too complex and
		needs a fallback.

		On an unparseable search returns BuildResult(ResolvedState.FAILURE, base_search),
		mirroring resolve()'s historical "return the original untouched" behaviour.

		Unlike resolve(), this does NOT swallow unexpected exceptions - callers that want
		explicit failure handling (the compiler) can catch them; resolve() keeps its own
		catch-all for the interactive path.
		"""
		commands = self.get_search_commands(base_search.strip())

		if commands is None:
			# Logging already happens inside get_search_commands. An unparseable search is a
			# permanent problem (not retryable).
			#
			return BuildResult(ResolvedState.FAILURE, base_search)

		tenx_commands = []
		leading_search = None

		for raw_command in commands:
			tenx_command = None

			if raw_command['command'] == 'search' and leading_search is None:
				# We only need to decode the results coming from the first search.
				# Any other chained searches are now working on decoded data and can be left as is.
				#
				tenx_command = TenxSearchCommand(raw_command, self.server_connection, self.tenx_config, self.search_manager, self.force_tenx, self.debug)
				leading_search = tenx_command
			else:
				tenx_command = TenxSplCommand(raw_command, self.tenx_config, self.debug)

			tenx_commands.append(tenx_command)

		spl_commands = TenxSplCommands(tenx_commands, self.debug)
		spl_commands.resolve()

		engaged = leading_search.engaged_tenx() if leading_search is not None else False
		field_terms = [term.text for term in leading_search.user_field_terms] if leading_search is not None else []
		retryable = bool(leading_search is not None and leading_search.dml_search_failed)
		has_search_terms = bool(leading_search is not None and len(leading_search.user_search_terms) > 0)
		no_dml_results = bool(leading_search is not None and leading_search.no_dml_results)
		dml_truncated = bool(leading_search is not None and leading_search.dml_truncated)
		no_prefilter = bool(has_search_terms and leading_search.resolved_done and leading_search.resolved_search is None)

		return BuildResult(
			spl_commands.resolved_state(),
			spl_commands.resolved(),
			engaged=engaged,
			field_terms=field_terms,
			retryable=retryable,
			has_search_terms=has_search_terms,
			no_dml_results=no_dml_results,
			dml_truncated=dml_truncated,
			no_prefilter=no_prefilter)

	def resolve(self, base_search):
		"""
		Resolves a search to work on 10x encoded data.

		First parsing the search via Splunk's parser endpoint, then creating TenxSplCommands and resolve that.

		If the parser endpoint resulted in any failures, returns base_search.
		"""
		try:
			return self.build(base_search).resolved
		except Exception as e:
			logger.warning("Error while resolving {} - {}.".format(base_search, e), exc_info=1)
			return tenx_util.splunk_message_macro("Failed building tenx search")
