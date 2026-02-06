"""
Tenx SPL Parser Module
=====================

This module provides a custom parser for Splunk Search Processing Language (SPL)
commands. It uses the parsimonious library to parse search commands and build
an Abstract Syntax Tree (AST) for analysis.

Purpose
-------
The parser enables 10x to:
- Understand the structure of user search queries
- Identify which sourcetypes/sources are being searched
- Extract search terms and field comparisons
- Determine if a search needs 10x resolution

Grammar
-------
The SPL grammar handles common search constructs:
- Search modifiers: index, sourcetype, host, source, eventtype
- Logical expressions: AND, OR, NOT
- Field comparisons: field=value, field!=value, field IN (...)
- Index expressions: unquoted or quoted search terms

The grammar is based on Splunk's BNF but simplified for 10x's needs.
Ideally, we would use `splunk btool searchbnf list` output directly,
but that requires handling left recursion that parsimonious doesn't support.

AST Classes
-----------
TenxAstNode
    Base AST node with text, position, and children.

TenxSearchAstNode
    Search-specific node with search_node_type classification.

TenxAstNodeFactory
    Factory for building AST from parse results.

TenxSearchAstNodeFactory
    Factory for search-specific AST with type classification.

SearchNodeType
    Enum categorizing AST nodes (INDEX, FIELD, MODIFIER, COMPLEX).

SpecifierFinder
    Utility to find all sourcetypes/sources that pass a search filter.

Usage
-----
    from tenx_spl_parser import spl_grammar, TenxSearchAstNodeFactory

    # Parse a search command
    parse_tree = spl_grammar.parse("search index=main error")

    # Build AST
    factory = TenxSearchAstNodeFactory()
    ast = factory.build(parse_tree)

    # Find sourcetypes in the search
    sourcetypes = ast.get_passing_specifiers('sourcetype_specifier')

See Also
--------
- tenx_search_builder.py: Uses this parser for search resolution
- parsimonious: PEG parsing library (https://github.com/erikrose/parsimonious)
"""

import logging

logger = logging.getLogger(__name__)

from enum import Enum, auto
from parsimonious import Grammar

import tenx_util

# Grammar for parsing a search command.
#
spl_grammar = Grammar(
	# TODO - add support for tag-specifier
	# TODO - allow STR_CHAR to also be #x5C (SPECIAL_CHAR | QOATATION_CHAR))
	"""
	search					= "search" (WS+ logical_expression)?

	logical_expression		= p_logical_expression / not_logical_expression / binary_expression / (t_logical_expression WS+ logical_expression) / t_logical_expression

	p_logical_expression	= ("(" logical_expression ")")
	t_logical_expression	= search_modifier / field_modifier / index_expression

	binary_expression		= (t_logical_expression / p_logical_expression) WS+ binary_operator WS+ logical_expression WS*
	binary_operator			= ("AND" / "OR")

	not_logical_expression	= "NOT" WS+ logical_expression
	index_expression		= (STR_CHAR+ / Q_STRING)

	field_modifier			= (field_cmp / field_in_list)

	field_cmp				= field_name WS* value_cmp WS* field_value
	field_in_list			= field_name WS+ "IN" WS+ "(" WS* field_value (WS* "," WS* field_value)* ")"

	field_name				= FIELD_CHAR+
	field_value				= (num / term)

	search_modifier			= (index_specifier / sourcetype_specifier / host_specifier / source_specifier / eventtype_specifier / eventtypetag_specifier / hosttag_specifier)

	index_specifier			= "index" value_separator term
	sourcetype_specifier	= "sourcetype" value_separator term
	host_specifier			= "host" value_separator term
	source_specifier		= "source" value_separator term
	eventtype_specifier		= "eventtype" value_separator term
	eventtypetag_specifier	= "eventtypetag" value_separator term
	hosttag_specifier		= "hosttag" value_separator term

	term_list			= term (WS+ term)*
	term				= (STR_CHAR+ / Q_STRING)

	value_cmp			= ("=" / "!=" / "<" / "<=" / ">" / ">=")

	value_separator		= WS* (equals / not_equals) WS*
	equals				= "="
	not_equals			= "!="

	num					= ("-"? ("0" / (NON_ZERO_DIG ANY_DIG*)) ("." ANY_DIG+)?)

	NON_ZERO_DIG		= ~"[1-9]"
	ANY_DIG				= ~"[0-9]"

	WS					= ~"[\x20\x09]+"

	Q_STRING			= QOATATION_CHAR (" " / SPECIAL_CHAR / STR_CHAR)* QOATATION_CHAR
	QOATATION_CHAR		= "\\\x22"

	STR_CHAR			= ("!" / ~r"[\\u0023-\\u0027]"u / ~r"[\\u002A-\\u005A]"u / ~r"[\\u005E-\\uFFFF]"u)
	SPECIAL_CHAR		= ( "(" / ")" / "[" / "]" / "\\\\")

	FIELD_CHAR			= ~"[a-zA-Z0-9_*-]"i
	""")


class TenxAstNode:
	"""
	Class representing a node in an AST tree, created from parsing via one our grammars.
	"""
	def __init__(self, rule_type, text, start=-1, end=-1, children=None, debug=False):
		self.rule_type = rule_type
		self.text = text
		self.start = start
		self.end = end
		self.children = children if children is not None else []
		self.debug = debug

	def _accumulate_leaves(self, result):
		"""
		Accumulates all leaves of this node and it's children.
		"""
		if len(self.children) == 0:
			result.append(self)
			return

		for child in self.children:
			child._accumulate_leaves(result)

	def get_leaves(self):
		"""
		Returns a list of all leaves of this node and it's children.
		"""
		result = []

		self._accumulate_leaves(result)

		return result

	def pretty(self, indent="", include_children=True):
		"""
		Returns a pretty representation of this node
		"""
		lines = ['%s%s - %s' % (indent, self.rule_type, self.text)]

		if include_children:
			for child in self.children:
				lines.append(child.pretty(indent + '\t'))

		return '\n'.join(lines)

	def __str__(self):
		return self.pretty(include_children=False)


class TenxAstNodeFactory:
	"""
	Factory class for building an TenxAstNode tree from a provided grammer parsed ast.
	"""
	def __init__(self, debug=False):
		self.debug = debug

	def is_relevant_node(self, node_name):
		"""
		Checks if a node is relevant, allowing us to prune some clutter from the raw ast.

		A node is defined as relevant if it has a non-empty lowercase name.
		"""
		return len(node_name) > 0 and node_name[0].islower()

	def create_node(self, parse_node, children):
		"""
		Returns a new ast node.
		"""
		return TenxAstNode(parse_node.expr.name, parse_node.text, parse_node.start, parse_node.end, children, self.debug)

	def post_process(self, ast_node):
		"""
		Runs a post process operation on the whole tree we created.
		"""
		pass

	def _build(self, parse_node):
		"""
		Recursively builds an TenxAstNode tree from the provided grammar parsed ast.

		Prunes away any non-relevant nodes, if possible.
		We only prune away non-relevant nodes if they have a single child (returning the child),
		or if they have no children at all (returning None)
		"""
		children = []

		if len(parse_node.children) > 0:
			for child in parse_node.children:
				child_ast = self._build(child)

				if child_ast:
					if self.is_relevant_node(child_ast.rule_type):
						children.append(child_ast)
					else:
						for child_ast_child in child_ast.children:
							children.append(child_ast_child)

		if len(children) >= 2 or self.is_relevant_node(parse_node.expr.name):
			return self.create_node(parse_node, children)

		if len(children) >= 1:
			return children[0]

		return None

	def build(self, parse_node):
		"""
		Recursively builds an TenxAstNode tree from the provided grammar parsed ast.

		Runs post_process on the resulting tree.
		"""
		result = self._build(parse_node)

		if result is not None:
			self.post_process(result)

		return result


class SearchNodeType(Enum):
	UNKNOWN = auto()
	INDEX = auto()
	FIELD = auto()
	MODIFIER = auto()
	COMPLEX = auto()
	IRRELEVANT = auto()


def intersect(specifier_lists):
	"""
	Returns the "intersection" between the lists of specifiers provided.

	Retains the notion that None is an "illegal state" of things, by returning None if even a single
	list in specifier_lists is None

	If only a single list in specifier_list contains actual values, while all others are empty, non-None
	lists, returns a copy of that single non-empty list.

	This is because in this case it's implied that the other items simply check different specifiers.
	"""
	result = []

	for specifier_list in specifier_lists:
		if specifier_list is None:
			return None

		if len(specifier_list) == 0:
			continue

		if len(result) > 0:
			result = list(set(result).intersection(specifier_list))
		else:
			# We clone the list as the result.
			# It's ok if we don't see any other list, if no other element in specifier_lists is None
			# we assume that they are all checking for other stuff, and this element is the only one
			# actually doing that specific specifier comparison, in which case it's the only value.
			#
			result = specifier_list[:]

	return result


def union(specifier_lists):
	"""
	Returns the "union" between the lists of specifiers provided.

	Retains the notion that None is an "illegal state" of things, by returning None if even a single
	list in specifier_lists is None
	"""
	result = []
	seen_non_empty_list = False

	for specifier_list in specifier_lists:
		if specifier_list is None:
			return None

		if len(specifier_list) == 0:
			if seen_non_empty_list:
				# We don't allow union with empty stuff, as this implies someone did some weird search like
				# "sourcetype=my_source OR index=my_index", in which case all specifiers are actually possible.
				#
				return None

			continue

		seen_non_empty_list = True

		if result:
			result.extend(specifier_list)
		else:
			result = specifier_list[:]

	return list(set(result))


class SpecifierFinder:
	"""
	Class for finding all the specifiers of a specific type (index, sourcetype, etc...) that will pass
	a certain search command.
	"""
	def __init__(self, target_specifier):
		self.target_specifier = target_specifier

	def process(self, search_ast_node):
		"""
		Returns a list of all the specifiers that pass the search command represented by search_ast_node.

		A result of None differs from an empty list in the sense that None means we encountered something
		that cannot reasonably be computed (i.e. "index != forbidden_index", as this is too broad)
		whereas an empty list means that either no specifier restrictions where found, or that the specifier
		restriction is effectively nothing is allowed (i.e. "sourcetype == source1 AND sourcetype == source2")
		"""
		if not search_ast_node or search_ast_node.rule_type != "search":
			# Must start at root...
			#
			return None

		if len(search_ast_node.children) == 0:
			return []

		child_results = [self._internal_process(child, False) for child in search_ast_node.children]

		# The child results are all immediate children of root, and there's an implied AND between them.
		#
		return intersect(child_results)

	def _internal_process(self, node, fail_on_contact):
		"""
		Does the actual processing of specifiers.

		fail_on_contact is used for cases where we're actually hoping to not find the specifier we're working with.
		This is used in NOT logical expressions, as we can't really handle them.
		"""
		if node.rule_type == "search_modifier":
			# We have a search modifier.
			#
			if len(node.children) == 1 and node.children[0].rule_type == self.target_specifier:
				# This is the droid we're looking for, but if we actually DON'T want it, we'll fail immediately.
				#
				if fail_on_contact:
					return None

				specifier_node = node.children[0]

				# Validate the node (shouldn't fail, but exceptions are bad)
				#
				if len(specifier_node.children) == 2 and specifier_node.children[0].rule_type == "value_separator" and specifier_node.children[1].rule_type == "term":
					if specifier_node.children[0].text == "!=":
						# We don't support cases where we check "all other sourcetypes except X"
						#
						return None

					# We actually found that specifier, return.
					#
					return [tenx_util.strip_string(specifier_node.children[1].text)]

			# Nothing was found, either because this wasn't the specific specifier we were searching, or node wasn't valid.
			#
			return []

		if node.rule_type == "not_logical_expression":
			# We have a NOT logical node.
			#
			# We validate the node (shouldn't fail, but exceptions are bad), but from here on we'll proceed with
			# the hopes that we actually don't find that specifier.
			#
			if len(node.children) == 1:
				# We don't allow "not" operation on source types, so we want to fail if we see one.
				#
				return self._internal_process(node.children[0], True)

			# Should never get here, but just in case.
			#
			return []

		if node.rule_type == "binary_expression":
			# We have a binary node.
			#
			# We validate the node (shouldn't fail, but exceptions are bad), and then proceed with either
			# doing a union or intersection on the result.
			#
			if len(node.children) == 3:
				first = self._internal_process(node.children[0], fail_on_contact)
				second = self._internal_process(node.children[2], fail_on_contact)

				binary_operator = node.children[1].text

				if binary_operator == "AND":
					return intersect([first, second])

				if binary_operator == "OR":
					return union([first, second])

				# Should never get here, but just in case.
				#
				return first

			# Should never get here, but just in case.
			#
			return []

		# Our node is of a type that simply doesn't concern us, yay.
		#
		return []


class TenxSearchAstNode(TenxAstNode):
	def __init__(self, rule_type, text, start=-1, end=-1, children=None, debug=False):
		TenxAstNode.__init__(self, rule_type, text, start, end, children, debug)

		self.search_node_type = SearchNodeType.UNKNOWN

	def _fill_search_node_type(self):
		"""
		Initializes the search_node_type field, based on this node and it's children.

		If this node has no children, or is a search_modifier/field_modifier node, we can directly set the
		search node type from the rule type.

		Otherwise, if all of this node's children have the same search node type, this node will have it to.

		If not (different types among children), this node will be SearchNodeType.COMPLEX
		"""
		if (len(self.children) == 0) or self.rule_type == "field_modifier" or self.rule_type == "search_modifier":
			self.search_node_type = {
				'index_expression':	SearchNodeType.INDEX,
				'field_modifier':	SearchNodeType.FIELD,
				'search_modifier':	SearchNodeType.MODIFIER,
				'binary_operator':	SearchNodeType.IRRELEVANT
			}.get(self.rule_type, SearchNodeType.UNKNOWN)

			return

		for child in self.children:
			child._fill_search_node_type()

		self.search_node_type = self.children[0].search_node_type

		for child in self.children[1:]:
			if self.search_node_type == SearchNodeType.IRRELEVANT:
				self.search_node_type = child.search_node_type
			elif child.search_node_type != SearchNodeType.IRRELEVANT and child.search_node_type != self.search_node_type:
				self.search_node_type = SearchNodeType.COMPLEX
				break

	def get_typed_children(self, child_type):
		"""
		Returns all children which have a specific search_node_type
		"""
		return [child for child in self.children if child.search_node_type == child_type]

	def get_passing_specifiers(self, specifier):
		"""
		Returns a list of the specific specifiers that the search represented by this ast might allow.

		See SpecifierFinder.process for more info.
		"""
		finder = SpecifierFinder(specifier)

		return finder.process(self)


class TenxSearchAstNodeFactory(TenxAstNodeFactory):
	"""
	Factory class for building an TenxSearchAstNode tree from a provided grammer parsed ast.
	"""
	def __init__(self, debug=False):
		TenxAstNodeFactory.__init__(self, debug)

	def is_relevant_node(self, node_name):
		"""
		Checks if a node is relevant, allowing us to prune some clutter from the raw ast.

		A node is defined as relevant if it has a non-empty lowercase name, and isn't a logical_expression node
		"""
		return super().is_relevant_node(node_name) and not node_name.endswith("logical_expression")

	def create_node(self, parse_node, children):
		"""
		Returns a new ast node.
		"""
		return TenxSearchAstNode(parse_node.expr.name, parse_node.text, parse_node.start, parse_node.end, children, self.debug)

	def post_process(self, ast_node):
		"""
		Fills the search node type for the given ast_node
		"""
		ast_node._fill_search_node_type()
