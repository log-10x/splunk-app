"""
What bounds the `tenx-replay` macro that plain `txf` runs, and each unit.

Splunk sets no limit on the length of a macro or of the search it expands to, and refuses a search whose pipeline
holds more than 1,000 top-level commands (a foreach block counts once; a subsearch is a search of its own). So by
default (replay_max_macro_chars = 0) the macro holds every sourcetype that gets a unit, however long, and
build_capped() leaves out the least busy only past REPLAY_MAX_COMMANDS; replay_max_macro_chars still cuts it where
an instance sets it.
"""
import tenx_replay_builder as b


def stanza(name, **settings):
	return b.Stanza(name, dict(settings), {})


def estate(n, pad=2000):
	"""n original sourcetypes, each with a long calculated field, the first the busiest."""
	stanzas = [stanza('default')] + [stanza('st%02d' % i, **{'EVAL-v%d' % i: '"%s"' % ('x' * pad)}) for i in range(n)]
	present = [('st%02d' % i, '/var/log/a', 'h', n - i) for i in range(n)]
	return stanzas, present


class TestTopLevelCommands:
	def test_pipes_inside_brackets_and_quotes_do_not_count(self):
		assert b.top_level_commands('eval a=1') == 1
		assert b.top_level_commands('eval a=1 | foreach x* [eval b=1 | eval c=2] | fields - x') == 3
		assert b.top_level_commands('eval a="x | y [" | eval b="\\" | "') == 2
		assert b.top_level_commands('search [| makeresults | eval a=1] | stats count') == 2

	def test_a_block_counts_once(self):
		assert b.top_level_commands(b.block('tenx_gox', ['eval a=1'] * 50)) == 1


class TestTheMacroHoldsEverySourcetypeByDefault:
	def test_the_default_sets_no_character_limit(self):
		assert b.DEFAULT_SETTINGS['replay_max_macro_chars'] == 0

	def test_a_long_estate_is_written_whole(self):
		stanzas, present = estate(40, pad=10000)
		r = b.build_capped(stanzas, present)
		assert len(r.spl()) > 262144
		assert sorted(r.per_sourcetype) == sorted(p[0] for p in present) and r.dropped == []
		assert not [w for w in r.warnings if 'limits' in w]
		assert b.unit_sourcetypes(present) == [p[0] for p in present]

	def test_every_sourcetype_with_a_unit_is_in_the_macro(self):
		stanzas, present = estate(12, pad=30000)
		r = b.build_capped(stanzas, present)
		for st in b.unit_sourcetypes(present):
			assert b.left_out_value(st in r.per_sourcetype, False) == ''

	def test_a_unit_has_no_character_limit_by_default(self):
		stanzas, present = estate(1, pad=300000)
		unit = b.build_unit(stanzas, 'st00', {'sources': set(), 'hosts': set(), 'indexes': set()},
							limit=b.DEFAULT_SETTINGS['replay_max_macro_chars'])
		assert not getattr(unit, 'replays_nothing', False) and len(unit.spl()) > 300000


class TestTheCommandLimit:
	def test_past_it_the_least_busy_are_left_out(self, monkeypatch):
		stanzas, present = estate(10, pad=10)
		full = b.top_level_commands(b.build(stanzas, present).spl())
		monkeypatch.setattr(b, 'REPLAY_MAX_COMMANDS', full - 1)
		r = b.build_capped(stanzas, present)
		assert b.top_level_commands(r.spl()) <= full - 1
		assert r.dropped and r.dropped[0] == 'st09' and 'st00' in r.per_sourcetype
		assert any('commands' in w for w in r.warnings)

	def test_a_unit_over_it_replays_nothing(self, monkeypatch):
		stanzas, present = estate(1, pad=10)
		monkeypatch.setattr(b, 'REPLAY_MAX_COMMANDS', 1)
		unit = b.build_unit(stanzas, 'st00', {'sources': set(), 'hosts': set(), 'indexes': set()})
		assert unit.replays_nothing and 'commands' in unit.warnings[-1]

	def test_the_limit_leaves_room_for_txf_and_the_search_after_it(self):
		assert b.REPLAY_MAX_COMMANDS <= 1000 - 60

	def test_unit_dry_runs_are_batched_within_it(self, monkeypatch):
		stanzas, present = estate(6, pad=10)
		units = dict((st, b.build_unit(stanzas, st, {'sources': set(), 'hosts': set(), 'indexes': set()}))
					 for st, _, _, _ in present)
		one = max(b.top_level_commands(u.spl()) for u in units.values()) + 3
		monkeypatch.setattr(b, 'REPLAY_MAX_COMMANDS', 2 * one)
		searches = []

		def run(spl):
			searches.append(spl)
			return None
		assert b.failing_units(units, run, limit=10 ** 9) == {}
		assert len(searches) == 3


class TestASetCharacterLimitStillCuts:
	def test_replay_max_macro_chars(self):
		stanzas, present = estate(20, pad=200)
		full = len(b.build(stanzas, present).spl())
		r = b.build_capped(stanzas, present, settings=dict(b.DEFAULT_SETTINGS, replay_max_macro_chars=full // 2))
		assert len(r.spl()) <= full // 2 and 'st19' in r.dropped
