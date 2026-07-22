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
   c. Search the tenx_dml_pure sourcetype for matching template hashes
   d. Build new search: (original_terms OR tenx_hash IN ("hash1","hash2")) - each hash quoted
      and escaped, since real hashes are dense, punctuation-heavy strings
3. Append tenx-inflate macro to decode results
4. Return the resolved search string

Example Resolution
------------------
Original:
    search index=main sourcetype=tenx_encoded error

After resolution:
    search index=main sourcetype=tenx_encoded ((error) OR (tenx_hash IN ("hash1","hash2")))
    | `tenx-inflate`
    | extract

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
		True when the DML probe matched more rows than were fetched (see
		tenx_search_manager.DML_FETCH_LIMIT) - the hash set may be missing hashes that only
		appeared past that cap.
	"""
	def __init__(self, state, resolved, engaged=False, field_terms=None, retryable=False,
				has_search_terms=False, no_dml_results=False, dml_truncated=False):
		self.state = state
		self.resolved = resolved
		self.engaged = engaged
		self.field_terms = field_terms if field_terms is not None else []
		self.retryable = retryable
		self.has_search_terms = has_search_terms
		self.no_dml_results = no_dml_results
		self.dml_truncated = dml_truncated


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

		self.user_search_words = []

		for search_term in self.user_search_terms:
			self._fill_user_search_words(search_term)

	def _fill_user_search_words(self, search_term):
		if search_term.rule_type == 'binary_expression':
			self._fill_user_search_words(search_term.children[0])
			self._fill_user_search_words(search_term.children[2])
		elif search_term.rule_type == 'index_expression':
			text = tenx_util.strip_string(search_term.text)

			self.user_search_words.extend(text.split(' '))

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

		# Because the result can come from either the dml (pattern) or actual index (variables)
		# we need to perform an OR based search, and split any phrases
		#
		or_based_search = " OR ".join(self.user_search_words)
		base_user_terms = " ".join([item.text for item in self.user_search_terms])

		self.needs_original_search_check = (or_based_search != base_user_terms)

		# The DML PROBE uses the user's own conjunction (AND, via plain space-separation - the
		# same terms as typed), not an OR of every word. An OR probe matches every template
		# containing ANY single word, which can fan a multi-word search in to every unrelated
		# template sharing one common term and push the probe past DML_FETCH_LIMIT for no
		# benefit. Probing with AND loses no recall: if a word is absent from a template's
		# text it must be present as a VARIABLE VALUE for a real match, which the
		# or_based_search keyword clause below still catches.
		#
		# TODO - allow configurable timeouts for the dml search
		#
		dml_results, dml_truncated = self.search_manager.run_dml_search(base_user_terms)
		self.dml_truncated = dml_truncated

		# Specifically None check, as empty is ok
		#
		if dml_results is None:
			# Logging already happens inside run_dml_search
			#
			self.has_errors = True
			# This is a transient lookup failure (job timeout/busy indexer), NOT a permanent
			# problem with the search itself. Save-time callers should retry, not drop the alert.
			#
			self.dml_search_failed = True
			return

		if len(dml_results) == 0:
			self.no_dml_results = True
			self.resolved_search = or_based_search
			return

		# Build new search from the user terms and the dml_results. Hashes are quoted: real
		# 10x hashes are dense, punctuation-heavy strings (not plain alphanumeric), and an
		# unquoted hash containing e.g. '|' or '[' would corrupt or break the SPL the
		# compiled search dispatches.
		#
		quoted_hashes = ",".join(
			'"{}"'.format(tenx_util.escape_spl_string_literal(dml_hash)) for dml_hash in dml_results)
		dml_resolved_search = "tenx_hash IN (" + quoted_hashes + ")"

		self.resolved_search = "((" + or_based_search + ") OR (" + dml_resolved_search + "))"

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

		if not self.has_dml_user_search_terms():
			return ResolvedState.SUCCESS

		if self.has_errors:
			return ResolvedState.FAILURE

		if self.resolved_search is None:
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
		so we will restore the user defined extractions after we decode.

		Different macro chosen if we're running in debug mode or not, either 'tenx-inflate' or 'tenx-inflate-debug'
		"""
		return " | " + tenx_util.splunk_inflate_macro(self.debug) + " | extract"

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

		return BuildResult(
			spl_commands.resolved_state(),
			spl_commands.resolved(),
			engaged=engaged,
			field_terms=field_terms,
			retryable=retryable,
			has_search_terms=has_search_terms,
			no_dml_results=no_dml_results,
			dml_truncated=dml_truncated)

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
