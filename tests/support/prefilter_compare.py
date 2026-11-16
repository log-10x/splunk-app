"""
Comparing two prefilters by what they select rather than by their text: a prefilter is a boolean
expression of TERM(...) atoms joined by AND and OR (tenx_prefilter_parser.prefilter), or None for no
restriction. selects_at_least(old, new) is True when every set of index terms that `old` selects is
also selected by `new`, checked on every assignment of the atoms when there are few, and on all-true,
all-false, each single atom true and each single atom false plus 2,000 seeded random assignments when
there are many. A prefilter may select too many events, never too few, so a change to the parser
must keep selects_at_least(shipped, changed) on every search.
"""
import itertools
import random
import re

TOKEN = re.compile(r'\s*(\(|\)|AND\b|OR\b|TERM\((?:[^()]|\([^()]*\))*\))')


def parse(text):
	"""The expression as nested ('and'|'or', [children]) and ('term', text) nodes."""
	tokens, i = [], 0
	while i < len(text):
		m = TOKEN.match(text, i)
		if not m:
			if text[i:].strip() == '':
				break
			raise ValueError('cannot read %r at %d' % (text, i))
		tokens.append(m.group(1))
		i = m.end()
	pos = [0]

	def expr():
		node = term()
		ops, kids = None, [node]
		while pos[0] < len(tokens) and tokens[pos[0]] in ('AND', 'OR'):
			op = tokens[pos[0]].lower()
			pos[0] += 1
			if ops is not None and op != ops:
				raise ValueError('mixed AND and OR without parentheses in %r' % text)
			ops = op
			kids.append(term())
		return (ops, kids) if ops else node

	def term():
		t = tokens[pos[0]]
		pos[0] += 1
		if t == '(':
			node = expr()
			assert tokens[pos[0]] == ')', text
			pos[0] += 1
			return node
		return ('term', t)

	return expr()


def atoms(node, out=None):
	out = set() if out is None else out
	if node[0] == 'term':
		out.add(node[1])
	else:
		for kid in node[1]:
			atoms(kid, out)
	return out


def holds(node, true):
	if node[0] == 'term':
		return node[1] in true
	values = [holds(kid, true) for kid in node[1]]
	return all(values) if node[0] == 'and' else any(values)


def selects_at_least(old, new):
	if new is None:
		return True
	if old is None:
		return False
	o, n = parse(old), parse(new)
	names = sorted(atoms(o) | atoms(n))
	if len(names) <= 12:
		assignments = (set(c for c, on in zip(names, bits) if on) for bits in itertools.product((0, 1), repeat=len(names)))
	else:
		rng = random.Random(15)
		fixed = [set(names), set()] + [{a} for a in names] + [set(names) - {a} for a in names]
		assignments = itertools.chain(fixed, (set(a for a in names if rng.random() < 0.5) for _ in range(2000)))
	for true in assignments:
		if holds(o, true) and not holds(n, true):
			return False
	return True
