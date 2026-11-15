"""
Events that arrive whole (text that does not begin with "~", log10x-format S4.1) through the
field replay of `txf`, run through the SPL model (tests/support/spl_model.py). Splunk has read
such an event's own text under the sourcetype it was indexed with, so:

* read under the sourcetype whose rules it needs (a field map renames its compact sourcetype to
  the original): Splunk applied exactly those rules, and the event is left as read. Replayed, its
  extract added every field a second time (Splunk Enterprise 10.4.3, Windows Security XML: 570
  of 662 whole events, EventID ["4670", "4670"], 95 of 183 fields differed from raw);
* read under the compact sourcetype (tenx_encoded): the fields come from that sourcetype's
  automatic extraction, cut at limits.conf [kv] maxchars, and carry names taken from the data. The
  event is replayed like an expanded one, every field it was read with cleared first (10 whole
  CloudTrail events over 64 KB: not replayed before, sourcetype tenx_encoded, no aliases or tags,
  awsRegion ["us-east-1", "us-east-1"]).

The extract stand-in (see test_replay_indexed_per_sourcetype) adds each value it finds to a field
that exists already, as measured for an extraction with MV_ADD and for the automatic JSON
extraction.
"""
import tenx_replay_builder as b
from support.spl_model import visible
from test_replay_indexed_per_sourcetype import LOOKUP_FIELDS, PRESENT, STANZAS, model, run, txf_steps, unit_call, \
	win_compact


def whole_win():
	"""A Windows event that arrived whole through a field map: its compact sourcetype is renamed to
	the original, so Splunk read it with exactly that sourcetype's rules."""
	return {'_raw': '<Event>4670</Event>', 'sourcetype': 'win', 'source': 'XmlWinEventLog:Security', 'host': 'dc01',
			'tenx_sourcetype': 'win', 'tenx_compact_st': 'tenx_w', 'EventID': '4670', 'LogonType': '2',
			'app': 'win:local', 'k': 'win', 'eventtype': 'et_win', 'tag::eventtype': ['a'],
			'__by_st': {'win': {'EventID': '4670', 'LogonType': '2'}}}


def whole_ct():
	"""A CloudTrail event that arrived whole under the compact sourcetype: Splunk read it with
	tenx_encoded's rules, its automatic JSON extraction cut before the end of the text."""
	read = {'awsRegion': 'us-east-1', 'findings{}.name': ['n1', 'n2']}
	return dict({'_raw': '{"awsRegion":"us-east-1","findings":[{"name":"n1"},{"name":"n2"}],"eventID":"e1"}',
				 'sourcetype': 'tenx_encoded', 'source': 'ct.log', 'host': 'aws', 'tenx_sourcetype': 'ct', 'env': 'prod',
				 'tenx_hash': '{"awsRegion":"us-east-1"', 'tenx_var_0': '"findings":[{"name":"n1"}',
				 '__by_st': {'ct': dict(read, eventID='e1'), 'tenx_encoded': dict(read)}}, **read)


def ct_compact():
	"""A compact CloudTrail event in the same chunk, carrying an indexed field whose name holds braces."""
	return {'_raw': '~c,1', '__exp': '{"awsRegion":"eu-west-1"}', 'sourcetype': 'tenx_encoded', 'source': 'ct.log',
			'host': 'aws', '_kv': 1, 'tenx_sourcetype': 'ct', 'env': 'prod', 'x{}.y': ['p', 'q'],
			'__by_st': {'ct': {'awsRegion': 'eu-west-1'}}}


class TestEventsThatArriveWhole:
	def test_one_read_under_its_own_sourcetype_is_left_as_read(self):
		want = visible(whole_win())
		for replay in ('`tenx-replay`', unit_call('win')):
			out = run(evs=[whole_win(), win_compact()], replay=replay)
			assert out[0] == want, replay
			# the compact event of the same chunk is replayed as before
			assert out[1]['EventID'] == '4624' and out[1]['app'] == 'win:remote'
		ev = whole_win()
		model(b.build(STANZAS, PRESENT, LOOKUP_FIELDS).spl()).run(txf_steps('`tenx-replay`'), [ev])
		# extract saw it hidden: no text and a sourcetype no stanza names
		assert [s for s in ev['__log'] if s[0] == 'extract'] == [('extract', ('', b.PLACEHOLDER, b.PLACEHOLDER,
																			   b.PLACEHOLDER, None))]

	def test_one_read_under_the_compact_sourcetype_is_replayed_with_each_value_once(self):
		for replay in ('`tenx-replay`', unit_call('ct')):
			out = run(keep=('env',), evs=[whole_ct(), ct_compact()], replay=replay)
			got = out[0]
			assert got['sourcetype'] == 'ct' and got['k'] == 'ct' and got['region'] == 'us-east-1', replay
			assert got['awsRegion'] == 'us-east-1' and got['findings{}.name'] == ['n1', 'n2'] and got['eventID'] == 'e1'
			assert got['env'] == 'prod' and got['eventtype'] == 'et_ct'
			assert not [k for k in got if k.startswith(('tenx_hash', 'tenx_var', 'tenx_w', 'tenx_go'))]
			# the compact event of the chunk keeps its indexed fields, the one named with braces too
			assert out[1]['x{}.y'] == ['p', 'q'] and out[1]['env'] == 'prod' and out[1]['awsRegion'] == 'eu-west-1'

	def test_an_indexed_field_of_the_whole_event_survives_when_listed(self):
		out = run(evs=[whole_ct()])
		assert 'env' not in out[0]
		out = run(by_st={'ct': ['env'], 'win': [], 'fgt': []}, evs=[whole_ct()])
		assert out[0]['env'] == 'prod'

	def test_a_compact_event_without_its_template_is_not_replayed(self):
		e = win_compact()
		del e['__exp']
		out = run(evs=[e])
		assert out[0]['sourcetype'] == 'tenx_encoded' and out[0]['app'] == 'win:unknown' and 'k' not in out[0]

	def test_a_whole_event_without_tenx_sourcetype_is_handled_as_before(self):
		e = whole_win()
		del e['tenx_sourcetype']
		out = run(evs=[e])
		# not replayed, so extract runs on it as `tx` runs it, and adds what it extracts again
		assert out[0]['EventID'] == ['4670', '4670'] and out[0]['k'] == 'win'

	def test_the_search_rewrite_hides_it_once(self):
		full = b.build(STANZAS, PRESENT, LOOKUP_FIELDS).spl()
		ev = whole_win()
		out = model(full).run('eval tenx_compact_raw=_raw | eval tenx_hide_others=1 | %s | fields - tenx_hide_others' % full, [ev])
		assert (out[0]['_raw'], out[0]['sourcetype'], out[0]['source'], out[0]['host']) == (
			'<Event>4670</Event>', 'win', 'XmlWinEventLog:Security', 'dc01')
		assert out[0]['EventID'] == '4670' and 'tenx_rst' not in out[0]
		assert not [k for k in out[0] if k.startswith(('tenx_hk_', 'tenx_hx_', 'tenx_go'))]
