"""
A small model of the SPL the field replay writes, for tests that check what a pipeline does to
an event rather than what its text looks like.

It runs a list of events (dicts) through a pipeline string. It knows only what the replay macro,
the `tx` macro and the search rewrite use: eval (if, case, coalesce, isnull, isnotnull, null,
true, mvindex, match, len, lower, substr, mvappend, mvjoin, mvdedup, mvsort; ==, !=, AND, OR, NOT), fields -, foreach,
rename (one literal name to another, on every event that has it), and stand-ins for extract, spath,
lookup, typer and tags supplied by the test.

Keys starting with two underscores belong to the test, not to the event: no command sees them.

Modelled behaviour, as observed on Splunk Enterprise 10.4.3:
- null: a comparison with null is null (isnull(a==1) is true); inside AND, OR and NOT a null is
  false, so NOT (a==1) is TRUE when a is null (not three-valued logic); if() and case() take a
  null condition as false; case() returns the value of the first true branch even when that
  value is null. An eval that yields null removes the field (fieldsummary count 0).
- fillnull value=<v> <names>: each named field set to <v> where it has no value (the model's only form); a
  name given twice is refused, as Splunk refuses the search.
- foreach <pattern>: the body runs once per field name that matches the pattern on any event of
  the result set (the whole list is one chunk), over every event, and not at all when none
  matches; fieldstr and matchstr rename the placeholders, and a nested foreach keeps its own.
  extract, eval and fields run inside a body.
- lookup: an event whose input field is null (absent) gets its OUTPUT fields removed (KV store
  and CSV lookups alike; implicit outputs too); with OUTPUTNEW it is left alone; OUTPUT with no
  match removes the outputs.
"""
import fnmatch
import re


class Unsupported(Exception):
	pass


def split_top(text, sep):
	"""Split at `sep` outside double quotes, single quotes and brackets."""
	out, buf, depth, i, n = [], [], 0, 0, len(text)
	while i < n:
		c = text[i]
		if c == '"':
			j = i + 1
			while j < n and text[j] != '"':
				j += 2 if text[j] == '\\' else 1
			buf.append(text[i:j + 1])
			i = j + 1
			continue
		if c == "'" and sep != "'":
			j = text.find("'", i + 1)
			j = n - 1 if j < 0 else j
			buf.append(text[i:j + 1])
			i = j + 1
			continue
		if c in '[(':
			depth += 1
		elif c in '])':
			depth -= 1
		if c == sep and depth == 0:
			out.append(''.join(buf))
			buf = []
		else:
			buf.append(c)
		i += 1
	out.append(''.join(buf))
	return [p.strip() for p in out]


TOKEN = re.compile(r'\s*(?:(?P<str>"(?:\\.|[^"\\])*")|(?P<ref>\'[^\']*\')|(?P<num>-?\d+(?:\.\d+)?)'
				   r'|(?P<op>==|!=|>=|<=|[(),<>])|(?P<name>[A-Za-z_][A-Za-z0-9_.:@{}]*))')


def tokens(expr):
	out, i = [], 0
	expr = expr.strip()
	while i < len(expr):
		m = TOKEN.match(expr, i)
		if not m or m.end() == i:
			if expr[i:].strip() == '':
				break
			raise Unsupported('cannot read %r at %d' % (expr, i))
		kind = m.lastgroup
		val = m.group(kind)
		if kind == 'str':
			val = re.sub(r'\\(.)', r'\1', val[1:-1])
		elif kind == 'ref':
			val = val[1:-1]
		out.append((kind, val))
		i = m.end()
	return out


class Expr(object):
	def __init__(self, text):
		self.toks = tokens(text)
		self.i = 0
		self.tree = self.or_()
		if self.i != len(self.toks):
			raise Unsupported('trailing text in %r' % text)

	def peek(self):
		return self.toks[self.i] if self.i < len(self.toks) else (None, None)

	def take(self):
		t = self.peek()
		self.i += 1
		return t

	def or_(self):
		node = self.and_()
		while self.peek() == ('name', 'OR'):
			self.take()
			node = ('or', node, self.and_())
		return node

	def and_(self):
		node = self.not_()
		while self.peek() == ('name', 'AND'):
			self.take()
			node = ('and', node, self.not_())
		return node

	def not_(self):
		if self.peek() == ('name', 'NOT'):
			self.take()
			return ('not', self.not_())
		return self.cmp()

	def cmp(self):
		node = self.atom()
		if self.peek()[0] == 'op' and self.peek()[1] in ('==', '!=', '>=', '<=', '<', '>'):
			op = self.take()[1]
			node = ('cmp', op, node, self.atom())
		return node

	def atom(self):
		kind, val = self.take()
		if kind == 'str':
			return ('lit', val)
		if kind == 'num':
			return ('lit', float(val) if '.' in val else int(val))
		if kind == 'ref':
			return ('field', val)
		if kind == 'op' and val == '(':
			node = self.or_()
			if self.take() != ('op', ')'):
				raise Unsupported('unbalanced')
			return node
		if kind == 'name':
			if self.peek() == ('op', '('):
				self.take()
				args = []
				if self.peek() != ('op', ')'):
					args.append(self.or_())
					while self.peek() == ('op', ','):
						self.take()
						args.append(self.or_())
				if self.take() != ('op', ')'):
					raise Unsupported('unbalanced call')
				return ('call', val, args)
			return ('field', val)
		raise Unsupported('unexpected %r' % ((kind, val),))


def truth(v):
	return None if v is None else bool(v)


def as_bool(v):
	"""A value inside AND, OR or NOT: null is false (measured)."""
	return bool(v) if v is not None else False


def evaluate(node, event):
	kind = node[0]
	if kind == 'lit':
		return node[1]
	if kind == 'field':
		return event.get(node[1])
	if kind == 'not':
		return not as_bool(evaluate(node[1], event))
	if kind in ('and', 'or'):
		a, b = as_bool(evaluate(node[1], event)), as_bool(evaluate(node[2], event))
		return (a and b) if kind == 'and' else (a or b)
	if kind == 'cmp':
		a, b = evaluate(node[2], event), evaluate(node[3], event)
		if a is None or b is None:
			return None
		if isinstance(a, (int, float)) != isinstance(b, (int, float)):
			a, b = str(a), str(b)
		return {'==': a == b, '!=': a != b, '>=': a >= b, '<=': a <= b, '<': a < b, '>': a > b}[node[1]]
	if kind == 'call':
		name, args = node[1], node[2]
		if name == 'if':
			return evaluate(args[1], event) if truth(evaluate(args[0], event)) else evaluate(args[2], event)
		if name == 'case':
			for c, v in zip(args[::2], args[1::2]):
				if truth(evaluate(c, event)):
					return evaluate(v, event)
			return None
		vals = [evaluate(a, event) for a in args]
		if name == 'null':
			return None
		if name == 'true':
			return True
		if name == 'isnull':
			return vals[0] is None
		if name == 'isnotnull':
			return vals[0] is not None
		if name == 'coalesce':
			return next((v for v in vals if v is not None), None)
		if name == 'mvindex':
			v = vals[0]
			return v[vals[1]] if isinstance(v, list) else v
		if name == 'len':
			return None if vals[0] is None else len(str(vals[0]))
		if name == 'lower':
			return None if vals[0] is None else str(vals[0]).lower()
		if name == 'substr':
			if vals[0] is None:
				return None
			text, start = str(vals[0]), int(vals[1]) - 1
			return text[start:] if len(vals) < 3 else text[start:start + int(vals[2])]
		if name == 'match':
			return None if vals[0] is None else re.search(vals[1], str(vals[0])) is not None
		if name == 'mvappend':
			out = []
			for v in vals:
				if v is not None:
					out.extend(v if isinstance(v, list) else [v])
			return out or None
		if name == 'mvjoin':
			v = vals[0]
			return None if v is None else str(vals[1]).join(str(x) for x in (v if isinstance(v, list) else [v]))
		if name == 'mvdedup':
			v = vals[0]
			return None if v is None else list(dict.fromkeys(v if isinstance(v, list) else [v]))
		if name == 'mvsort':
			v = vals[0]
			return None if v is None else sorted(v if isinstance(v, list) else [v])
		raise Unsupported('function %s' % name)
	raise Unsupported(kind)


# What `tenx-wild` stands for in a pipeline the model runs (see Model.step).
WILD_STEP = 'tenx_wild_step'


class Model(object):
	"""
	Runs pipelines. `commands` maps a command name (extract, spath, typer, tags) or a full
	command text to a function (event, command text) -> None that changes the event; every call
	is also logged on the event under the key '__log' as (command text, snapshot of the
	_raw, sourcetype, source and host it saw).
	"""

	def __init__(self, commands=None, lookups=None, macros=None, plan=None):
		self.commands = commands or {}
		self.lookups = lookups or {}
		self.macros = macros or {}
		# What the step before the replay of `txf` reads back from the job (macros.conf [tenx-replay-plan]):
		# the fields of a stored replay plan, or tenx_ndnoplan when none was stored.
		self.plan = plan or 'tenx_ndnoplan'

	def run(self, pipeline, events):
		for step in split_top(self.expand(pipeline), '|'):
			if step:
				self.step(step, events)
		return events

	def expand(self, text):
		for _ in range(5):
			new = re.sub(r'`([^`]+)`', lambda m: WILD_STEP if m.group(1) == 'tenx-wild' else (
				'fillnull value=1 tenx_ndnone ' + self.plan if m.group(1) == 'tenx-replay-plan' else self.macros[m.group(1)]), text)
			if new == text:
				return text
			text = new
		raise Unsupported('macro recursion')

	def step(self, step, events):
		if step == WILD_STEP:
			# The step before the final search of the tx macros (macros.conf [tenx-wild]): with no word
			# with a wildcard inside it, TERM() or CASE() that needs it, the prefilter stores nothing, and
			# the step marks nothing and searches `*`.
			return
		word = step.split(None, 1)[0]
		rest = step[len(word):].strip()
		if word == 'eval':
			assigns = []
			for part in split_top(rest, ','):
				m = re.match(r'^("(?:[^"\\]|\\.)*"|[^=\s]+)\s*=(?!=)\s*(.*)$', part, re.S)
				if not m:
					raise Unsupported('assignment %r' % part)
				name = m.group(1)
				name = name[1:-1] if name.startswith('"') else name
				if '{' in name:
					raise Unsupported('brace on the left: %r' % name)
				assigns.append((name, Expr(m.group(2))))
			for event in events:
				for name, expr in assigns:
					v = evaluate(expr.tree, event)
					if v is None:
						event.pop(name, None)
					else:
						event[name] = v
			return
		if word == 'fields':
			if not rest.startswith('-'):
				raise Unsupported(step)
			pats = [p.strip() for p in rest[1:].split(',') if p.strip()]
			for event in events:
				for f in list(event):
					if not f.startswith('__') and any(fnmatch.fnmatchcase(f, p) for p in pats):
						del event[f]
			return
		if word == 'fillnull':
			m = re.match(r'^value=(\S+)\s+(.+)$', rest)
			if not m:
				raise Unsupported(step)
			if len(set(m.group(2).split())) != len(m.group(2).split()):
				# Splunk Enterprise 10.4.3: "Error in 'fillnull' command: Field '<name>' cannot be specified
				# multiple times." (the search does not run)
				raise Unsupported('fillnull names a field twice: %r' % step)
			for event in events:
				for name in m.group(2).split():
					if event.get(name) is None:
						event[name] = m.group(1)
			return
		if word == 'foreach':
			# One pattern or several (`foreach a b c [...]`, the units' clearing step): the body
			# runs once per field name any of them matches.
			m = re.match(r'^((?:[^\s\[="]+\s+)*[^\s\[="]+)((?:\s+\w+="[^"]*")*)\s*\[(.*)\]$', rest, re.S)
			if not m:
				raise Unsupported(step)
			patterns, opts, body = m.group(1).split(), dict(re.findall(r'(\w+)="([^"]*)"', m.group(2))), m.group(3)
			fieldstr, matchstr = opts.get('fieldstr', '<<FIELD>>'), opts.get('matchstr', '<<MATCHSTR>>')
			names = sorted(set(f for e in events for f in e if not f.startswith('__') and
							   any(fnmatch.fnmatchcase(f, p) for p in patterns)))
			for name in names:
				pattern = next(p for p in patterns if fnmatch.fnmatchcase(name, p))
				prefix = pattern.split('*')[0]
				suffix = name[len(prefix):] if pattern.endswith('*') else name
				text = body.replace(fieldstr, name).replace(matchstr, suffix)
				for s in split_top(text, '|'):
					if s:
						self.step(s, events)
			return
		if word == 'lookup':
			self.lookup(rest, events)
			return
		if word == 'rename':
			m = re.match(r'^("(?:[^"\\]|\\.)*"|\S+)\s+AS\s+("(?:[^"\\]|\\.)*"|\S+)$', rest, re.S)
			if not m:
				raise Unsupported(step)
			old_name, new_name = [n[1:-1] if n.startswith('"') else n for n in m.groups()]
			if '*' in old_name or '*' in new_name:
				raise Unsupported('wildcard rename %r' % step)
			for event in events:
				if old_name in event:
					event[new_name] = event.pop(old_name)
			return
		fn = self.commands.get(step) or self.commands.get(word)
		if fn is None:
			raise Unsupported('command %r' % step)
		for event in events:
			event.setdefault('__log', []).append(
				(step, tuple(event.get(k) for k in ('_raw', 'sourcetype', 'source', 'host', '_kv'))))
			fn(event, step)

	def lookup(self, rest, events):
		toks = rest.replace(',', ' ').split()
		table = toks[0]
		rows = self.lookups[table]
		i, inputs, mode, outputs, target = 1, [], None, [], None
		target = inputs
		while i < len(toks):
			t = toks[i]
			if t in ('OUTPUT', 'OUTPUTNEW'):
				mode, target = t, outputs
				i += 1
				continue
			if i + 2 < len(toks) and toks[i + 1] == 'AS':
				target.append((t, toks[i + 2]))
				i += 3
			else:
				target.append((t, t))
				i += 1
		for event in events:
			if any(event.get(f) is None for _, f in inputs):
				if mode != 'OUTPUTNEW':
					outs = outputs or [(c, c) for c in (rows[0] if rows else {}) if c not in set(c for c, _ in inputs)]
					for _, fld in outs:
						event.pop(fld, None)
				continue
			row = next((r for r in rows if all(str(r.get(c)) == str(event.get(f)) for c, f in inputs)), None)
			outs = outputs or [(c, c) for c in (rows[0] if rows else {}) if c not in set(c for c, _ in inputs)]
			for col, fld in outs:
				if mode == 'OUTPUTNEW' and event.get(fld) is not None:
					continue
				v = None if row is None else row.get(col)
				if v is None:
					event.pop(fld, None)
				else:
					event[fld] = v


def visible(event):
	"""The event's fields, without the model's own keys (those starting with two underscores)."""
	return dict((k, v) for k, v in event.items() if not k.startswith('__'))
