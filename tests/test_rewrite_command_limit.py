"""
The search rewrite (`| tx`, `| tenxsearch`, the dashboard hook, compiled alerts) chains the units of the
sourcetypes recorded for the indexes a search names (compose_units()). Splunk refuses a search whose
pipeline holds more than 1,000 top-level commands, and nothing held the chain to that: on an estate whose
units together pass it, every such search was refused. A unit's command count is now in its
tenx_replay.conf stanza, and a chain past REPLAY_MAX_COMMANDS, or one the record cannot size, runs
`tenx-replay`, which keeps to its limits.

The rewrite reads the record through tenx_util.get_replay_coverage, which handed it `indexes` and `unit`
only, so the `left_out` a stanza recorded never reached it either.
"""
import json
import subprocess
import sys
import tempfile

import tenx_replay_builder as b
from test_replay_units import CHILD, ROOT


def record(**commands):
	return dict((st, {'indexes': 'x', 'unit': b.unit_macro(st), b.COMMANDS_KEY: str(n)})
				for st, n in commands.items())


class Stanza(object):
	def __init__(self, name, content):
		self.name, self.content = name, content


def service(conf):
	class Confs(object):
		def __getitem__(self, name):
			return [Stanza(n, c) for n, c in conf.items()]

	class Service(object):
		confs = Confs()
	return Service()


class TestTheRecordReachesTheRewrite:
	def test_left_out_and_the_command_count_are_read(self):
		import tenx_util
		conf = {'a': {'indexes': 'x', 'unit': b.unit_macro('a'), 'left_out': '', b.COMMANDS_KEY: '40', 'sources': 's'},
				'b': {'indexes': 'x', 'unit': b.unit_macro('b'), 'left_out': 'txf', b.COMMANDS_KEY: '30'}}
		covered = tenx_util.get_replay_coverage(service(conf))
		assert covered['b']['left_out'] == 'txf' and covered['a'][b.COMMANDS_KEY] == '40'
		# every sourcetype of the index is chosen, and the macro leaves b out: its unit replays it
		assert b.rewrite_replay(covered, ['x']) == b.compose_units(['a', 'b'])
		json.dumps(covered)


class TestTheChainKeepsToTheCommandLimit:
	def test_the_count_is_that_of_the_composed_search(self):
		tags = b.top_level_commands(' | '.join(b.TAGS_STEPS))
		for counts in ([7], [7, 12], [5, 9, 30]):
			sts = ['s%d' % i for i in range(len(counts))]
			text = b.compose_units(sts)
			for st, n in zip(sts, counts):
				text = text.replace('`%s`' % b.unit_macro(st), ' | '.join(['eval u=1'] * n))
			text = text.replace('`%s`' % b.TAGS_MACRO, ' | '.join(['eval t=1'] * tags))
			assert b.chained_commands(counts) == b.top_level_commands(text), counts

	def test_a_chain_past_the_limit_runs_the_macro(self):
		covered = record(a=500, b=500)
		covered['b']['left_out'] = 'txf'
		assert b.rewrite_replay(covered, ['x']) == b.FULL

	def test_a_chain_of_some_sourcetypes_past_the_limit_runs_the_macro(self):
		covered = record(a=10, b=600, c=600)
		covered['b']['indexes'] = covered['c']['indexes'] = 'y'
		assert b.rewrite_replay(covered, ['y']) == b.FULL
		covered['c'][b.COMMANDS_KEY] = '200'
		assert b.rewrite_replay(covered, ['y']) == b.compose_units(['b', 'c'])

	def test_a_chain_at_the_limit_is_composed(self):
		n = b.REPLAY_MAX_COMMANDS - b.chained_commands([0, 0])
		covered = record(a=n // 2, b=n - n // 2)
		covered['b']['left_out'] = 'txf'
		assert b.chained_commands([n // 2, n - n // 2]) == b.REPLAY_MAX_COMMANDS
		assert b.rewrite_replay(covered, ['x']) == b.compose_units(['a', 'b'])
		covered['a'][b.COMMANDS_KEY] = str(n // 2 + 1)
		assert b.rewrite_replay(covered, ['x']) == b.FULL

	def test_a_unit_the_record_does_not_size_runs_the_macro(self):
		covered = record(a=10, b=10)
		covered['b']['left_out'] = 'txf'
		for value in (None, '', 'many'):
			if value is None:
				del covered['a'][b.COMMANDS_KEY]
			else:
				covered['a'][b.COMMANDS_KEY] = value
			assert b.rewrite_replay(covered, ['x']) == b.FULL, value


SCENARIO = r'''
ROWS = [('app:kv', '/var/app/a.log', 'web-1', 50, 'app', True),
		('app:json', '/var/other/b.log', 'api-1', 3, 'shared', True)]
fake = FakeSplunk(ROWS)
run(fake)
B = tenxreplay.builder
out = dict((st, [fake.conf[st].get(B.COMMANDS_KEY), str(B.top_level_commands(fake.macros[B.unit_macro(st)]))])
		   for st in ('app:kv', 'app:json'))
run(fake)
out['second_writes'] = fake.writes
print(json.dumps(out))
'''


def test_the_rebuild_records_each_units_command_count():
	marker = '# (sourcetype, source, host, count, index, in the 7-day lookback)'
	assert marker in CHILD
	child = CHILD.split(marker)[0] + SCENARIO
	with tempfile.TemporaryDirectory() as home:
		proc = subprocess.run([sys.executable, '-c', child, ROOT, home], capture_output=True, text=True, timeout=300)
	assert proc.returncode == 0, proc.stderr[-3000:]
	out = json.loads(proc.stdout.strip().splitlines()[-1])
	for st in ('app:kv', 'app:json'):
		recorded, counted = out[st]
		assert recorded == counted and int(recorded) > 1, (st, out[st])
	assert out['second_writes'] == []
