"""
tenxprefilter: the prefilter of the `tx` macro, built once per search.

`tx` expands to ((`tenx-events`) OR (`tenx-raw-events`)) [| tenxprefilter] | `tenx-inflate` | ... | search *, and the words
written after `tx` become the arguments of that last search. This command runs in the
subsearch: it reads the running job's own search text through the REST API, parses the words
after `tx` (tenx_prefilter_parser), asks the KV store of templates which templates carry each
word, and returns one row whose `search` field is the prefilter.

A field comparison (field=value, field IN (...)) narrows by tenx_config.conf [config] field_narrowing.
false (the default): no field comparison restricts the prefilter. splunk: the compact events must
hold the index terms Splunk itself requires of raw events for the comparison, read from a probe
job's base lispy (_splunk_terms); when they cannot be read, no field comparison restricts the
prefilter and the search shows a warning. true: like the value written as a word, once tenxreplay
has written the list of fields whose value is not text of the event, and the field is not on it.

The template dictionary (which templates carry each piece of the words) is read from the KV store the
expansion uses. The answer for each piece is kept in the tenx_dict_cache collection, and a later search
for the same pieces reads only the records written in the hours since, every record again once a day
(tenx_prefilter_parser.cache_hours, _dictionary).

When it cannot read the search (tx inside another subsearch, or wrapped in another macro) or
cannot parse the words, it returns `(*)`, so every compact event in range is expanded and the
words are applied to the expanded text: slower, never fewer results. It stops with an error
instead where the search would silently miss events: a time modifier after `tx`, an unquoted
comma after `tx`, and a sourcetype= term naming an original sourcetype, which the compact events
carry in tenx_sourcetype (they are indexed as the compact sourcetype).

Some words match other events in that final search, after a pipe, than on the index: a wildcard
inside a word (Se*Privilege is matched as its prefix alone), and TERM() or CASE() of some words
(tenx_prefilter_parser.wild_plan). For those, this command also stores on the running job two
custom fields, custom.tenx_wild_marks and custom.tenx_wild_search: the regular expressions that
find each such word as the index does (tenx_prefilter_parser.wild_marks), and the words with each
such word replaced by its mark. `tx` and `txf` read them back in the step before their final
search (macros.conf [tenx-wild]).

For a search that runs plain `txf` once, it also stores custom.tenx_replay_plan: the rules of the field
replay that feed the fields the rest of the search reads, which `txf` reads back right before the replay
(macros.conf [tenx-replay-plan]; tenx_replay_plan.py says when the whole replay runs instead).

It also warns, from the record tenxreplay keeps of the original sourcetypes (tenx_replay.conf), when
the search reads compact events whose original sourcetype the field replay of `txf` leaves out, and
when its indexes hold raw events of those sourcetypes, in its time range, that the tenx-raw-events
macro does not name (`tx` and `txf` then leave them out).

In the minutes after an install or an upgrade, on a search head with search peers, it first checks that
the template lookup runs on the indexers; until the knowledge bundle that carries it has reached them it
keeps the search on the search head and says so, where the search otherwise failed with a lookup error.

Every `tx` and `txf` of a search runs this command and reads the same search text. When the text
holds more than one, the words after the first would choose the compact events of every other one
(the second arm of a multisearch or union kept too few events), so this command then selects every
compact event in range and stores no word plan: each one's own words are applied to the expanded
text.
"""
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


APP_NAME = 'tenx-for-splunk'
# The app's own folder, wherever Splunk keeps it (etc/apps, or etc/peer-apps on an indexer cluster peer).
apphome = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(apphome, 'bin'))
sys.path.append(os.path.join(apphome, 'lib'))

from splunklib.searchcommands import dispatch, Configuration, GeneratingCommand

import tenx_prefilter_parser as parser
import tenx_replay_plan as replay_plan

# Splunk names a subsearch's job subsearch_<parent sid>_<epoch>.<n>.
# Matches every event like *, and gives Splunk Web no keyword to highlight (* lit every event).
EVERY_EVENT = "(*)"

# The tenx_replay.conf stanza tenxreplay writes: fields whose value is not text of the event.
NARROWING_STANZA = "tenx:narrowing"
# ... and the rule table of the field replay (tenx_replay_builder.Selection).
PLAN_STANZA = "tenx:plan"

SUBSEARCH_SID = re.compile(r"^subsearch_(.+)_\d+\.\d+$")
# A word plan not computed yet (_store_plans).
UNREAD = object()


def dictionary_failed(result):
	"""
	The first message of a oneshot answer that means its rows cannot be trusted as complete: an
	error (the KV store unavailable, the lookup missing) or a warning that rows were cut. None
	when there is none. A template the answer misses would select none of its events, so the
	prefilter then selects every compact event instead.
	"""
	for message in result.get("messages", []) or []:
		kind, text = str(message.get("type", "")).upper(), str(message.get("text", ""))
		if kind in ("ERROR", "FATAL") or (kind == "WARN" and any(w in text.lower() for w in ("truncat", "limit", "exceed"))):
			return "%s: %s" % (kind, text[:200])
	return None


@Configuration()
class TenxPrefilterCommand(GeneratingCommand):

	def _rest(self, path, data=None, answer=True, method=None):
		"""splunkd REST as the searching user: the JSON answer, its text (answer="text"), or None."""
		info = self._metadata.searchinfo
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		request = urllib.request.Request(
			info.splunkd_uri + path,
			data=urllib.parse.urlencode(data).encode() if data else None,
			method=method or ("POST" if data else "GET"),
			headers={"Authorization": "Splunk " + info.session_key})
		with urllib.request.urlopen(request, context=context, timeout=60) as response:
			body = response.read().decode("utf-8", "replace")
			return body if answer == "text" else json.loads(body) if answer else None

	def _search_text(self):
		match = SUBSEARCH_SID.match(self._metadata.searchinfo.sid or "")
		if not match:
			return None
		self.parent = match.group(1)
		job = self._rest("/services/search/jobs/%s?output_mode=json" % urllib.parse.quote(match.group(1), safe=""))
		search = job["entry"][0]["content"].get("search", "")
		# The whole search and the job's settings: the replay plan reads both (_replay_plan).
		self.search, self.job = search, job["entry"][0]["content"]
		# The app the search runs from: its aliases, event types and tags are the ones the probe of
		# _splunk_terms must see.
		self.parent_app = (job["entry"][0].get("acl") or {}).get("app") or APP_NAME
		self.before = parser.macro_call(search)
		self.calls = parser.macro_calls(search)
		return parser.text_after_macro(search)

	def _original_sourcetype_rows(self, tree):
		"""
		Compact events whose original sourcetype the search names where it can
		match none of them: before `tx` or `txf`, or after `tx`. None when it names none, or when the
		check could not run.
		"""
		before, macro = self.before if getattr(self, "before", None) else ("", "`tx`")
		sourcetypes = parser.named_sourcetypes(before, tree, after_counts=(macro == "`tx`"))
		probe = parser.original_sourcetype_probe(sourcetypes, parser.named_indexes(before))
		if probe is None:
			return None, macro
		info = self._metadata.searchinfo
		try:
			result = self._rest(
				"/servicesNS/%s/%s/search/jobs" % (urllib.parse.quote(info.username), APP_NAME),
				{"search": probe, "exec_mode": "oneshot", "output_mode": "json", "count": "0",
				 "earliest_time": str(info.earliest_time or "0"), "latest_time": str(info.latest_time or "now")})
		except Exception as e:
			self.logger.warning("tx: the original sourcetype check failed: %s", e)
			return None, macro
		return [r for r in result.get("results", []) if str(r.get("count", "0")) not in ("0", "")], macro

	def _record_checks(self, macro):
		"""
		Two warnings from tenxreplay's record of the original sourcetypes (tenx_replay.conf on disk, no
		REST read): `txf` or txf(<sourcetype>) whose field replay leaves events of a covered sourcetype
		without its rules (tenx_prefilter_parser.replay_left_out); and indexes that hold, in the search's
		time range, raw events of the original sourcetypes of its compact events that the tenx-raw-events
		macro does not name, which `tx` and `txf` leave out (one tstats, raw_history_probe, whose answer is
		kept in tenx_dict_cache: check_rows). Nothing when no compact event carries tenx_sourcetype, or when
		a check cannot run.
		"""
		before = self.before[0] if getattr(self, "before", None) else ""
		record = parser.replay_record_on_disk(apphome)
		if not record:
			return
		note = parser.replay_left_out(record, macro, parser.named_indexes(before))
		if note:
			self.write_warning(note)
		probe = parser.raw_history_probe(record, before)
		if probe is None:
			return
		info = self._metadata.searchinfo
		earliest, latest = str(info.earliest_time or "0"), str(info.latest_time or "now")
		try:
			kept = self._kv(parser.CACHE_PATH + "/" + parser.check_key(probe) + "?output_mode=json")
		except Exception:
			kept = None
		rows = parser.check_rows(kept, earliest, latest, time.time())
		if rows is None:
			try:
				result = self._rest(
					"/servicesNS/%s/%s/search/jobs" % (urllib.parse.quote(info.username), APP_NAME),
					{"search": probe, "exec_mode": "oneshot", "output_mode": "json", "count": "0",
					 "earliest_time": earliest, "latest_time": latest})
			except Exception as e:
				self.logger.warning("tx: the raw events check failed: %s", e)
				return
			rows = [r for r in result.get("results", []) if str(r.get("count", "0")) not in ("0", "")]
			try:
				self._kv(parser.CACHE_PATH + "/batch_save?output_mode=json",
						 [parser.check_record(probe, earliest, latest, rows, time.time())])
			except Exception as e:
				self.logger.info("tx: the raw events check was not kept: %s", e)
		if rows:
			self.write_warning(parser.raw_history_message(rows, macro))

	def _splunk_terms(self, text):
		"""
		The index terms Splunk derives for the words after the macro, as a parsed search to AND with
		them (tenx_prefilter_parser.lispy_tree), or None: then field comparisons narrow nothing, as
		before. One probe job over a time range that holds no event, in the app the search runs from;
		its search.log holds the base lispy. The job is removed afterwards.
		"""
		macro = self.before[1] if getattr(self, "before", None) else "`tx`"
		probe = parser.lispy_probe(text, macro)
		if probe is None:
			return None
		info = self._metadata.searchinfo
		app = getattr(self, "parent_app", None) or APP_NAME
		sid = None
		try:
			job = self._rest("/servicesNS/%s/%s/search/jobs" % (urllib.parse.quote(info.username, safe=""), urllib.parse.quote(app, safe="")),
							 {"search": probe, "exec_mode": "blocking", "earliest_time": "1", "latest_time": "2", "output_mode": "json"})
			sid = job.get("sid")
			log = self._rest("/services/search/jobs/%s/search.log" % urllib.parse.quote(sid, safe=""), answer="text")
			return parser.lispy_tree(parser.lispy_from_log(log))
		except Exception as e:
			self.logger.warning("tx: Splunk's index terms for the field comparisons could not be read: %s", e)
			return None
		finally:
			if sid:
				try:
					self._rest("/services/search/jobs/%s" % urllib.parse.quote(sid, safe=""), answer=False, method="DELETE")
				except Exception:
					pass

	def _text_field(self):
		"""
		Which field comparisons may narrow, or None for none: then no field comparison restricts
		the prefilter. Field narrowing is off unless tenx_config.conf [config] says
		field_narrowing = true, and needs the [tenx:narrowing] stanza the tenxreplay command
		writes (only while some compact event carries tenx_sourcetype). Anything unreadable
		means off. The setting is read from the app's conf files on disk, so with narrowing off
		this makes no REST call (a REST read of the setting cost 0.01 to 0.03 s per search with a
		field comparison, observed on Splunk Enterprise 10.4.3).
		"""
		if not parser.narrowing_on_disk(apphome):
			return None
		try:
			entry = self._rest("/servicesNS/nobody/%s/configs/conf-tenx_replay/%s?output_mode=json" % (
				APP_NAME, urllib.parse.quote(NARROWING_STANZA, safe="")))["entry"][0]["content"]
		except Exception:
			return None
		names = [n.strip() for n in str(entry.get("fields_not_in_text", "") or "").split(",") if n.strip()]
		return parser.text_field_predicate(names)

	def _raw_events(self):
		"""The definition of the tenx-raw-events macro as this search expands it, when the prefilter's text can hold it."""
		info = self._metadata.searchinfo
		app = getattr(self, "parent_app", None) or APP_NAME
		try:
			entry = self._rest("/servicesNS/%s/%s/configs/conf-macros/%s?output_mode=json" % (
				urllib.parse.quote(info.username, safe=""), urllib.parse.quote(app, safe=""), parser.RAW_EVENTS_NAME))
			return parser.usable_definition(entry["entry"][0]["content"])
		except Exception as e:
			self.logger.info("tx: the raw events macro could not be read: %s", e)
			return None

	def _without_words(self, prefilter):
		"""
		The prefilter, with an OR branch that reads the compact events indexed without words, which its terms
		cannot find: every one that holds no term starting with ~ (without_words_branch). When the definition of
		tenx-raw-events cannot be read, the groups of such events are found by one tstats (word_index_probe), and
		every compact event in range is expanded when that check cannot run either.
		"""
		raw = self._raw_events()
		if raw is not None:
			return parser.without_words_branch(prefilter, raw)
		before = self.before[0] if getattr(self, "before", None) else ""
		try:
			info = self._metadata.searchinfo
			result = self._rest(
				"/servicesNS/%s/%s/search/jobs" % (urllib.parse.quote(info.username), APP_NAME),
				{"search": parser.word_index_probe(before), "exec_mode": "oneshot", "output_mode": "json", "count": "0",
				 "earliest_time": str(info.earliest_time or "0"), "latest_time": str(info.latest_time or "now")})
			if dictionary_failed(result):
				raise RuntimeError(dictionary_failed(result))
		except Exception as e:
			self.logger.warning("tx: the word index check failed: %s", e)
			self.write_warning("tx: could not check that the compact events hold words; every compact event in range is expanded.")
			return EVERY_EVENT
		rows = result.get("results", [])
		return "(%s OR %s)" % (prefilter, parser.word_index_branch(rows)) if rows else prefilter

	def _replay_plan(self):
		"""
		For a search running plain `txf` once: which rules of the field replay it reads, as the fields the
		replay step puts on its events (tenx_replay_plan.plan_value), from the rule table tenxreplay wrote
		with the macro ([tenx:plan] in tenx_replay.conf, read from disk), and NOTAGS; NOTAGS alone, and the
		whole replay runs, when no table or rule set applies. None, and the whole replay runs with event
		types and tags, when what the search reads cannot be told (tenx_replay_plan.needed_fields) or when
		Splunk keeps the search's events (statusBuckets above 0, verbose mode: every field is shown).
		"""
		try:
			job = getattr(self, "job", None) or {}
			level = str((job.get("request") or {}).get("adhoc_search_level", "") or "").lower()
			if "statusBuckets" not in job or float(job.get("statusBuckets") or 0) > 0 or level == "verbose":
				return None
			macro = self.before[1] if getattr(self, "before", None) else ""
			if replay_plan.TXF_UNIT.match(macro):
				# txf(<sourcetype>): its unit runs whole; event types and tags are left out when nothing reads them
				return replay_plan.NOTAGS if replay_plan.tags_skipped(getattr(self, "search", None), parser) else None
			needed = replay_plan.needed_fields(getattr(self, "search", None), parser)
			if needed is None:
				return None
			stanzas = parser.conf_stanzas([os.path.join(apphome, d, "tenx_replay.conf") for d in ("default", "local")])
			before = self.before[0] if getattr(self, "before", None) else None
			present = replay_plan.searched_sourcetypes(stanzas, replay_plan.bounding_indexes(before, parser))
			value = replay_plan.plan_value(replay_plan.read_table(stanzas.get(PLAN_STANZA) or {}), needed, present)
			# needed_fields() is None for a search that reads an event type or a tag
			return replay_plan.NOTAGS if value is None else value + " " + replay_plan.NOTAGS
		except Exception as e:
			self.logger.info("tx: no replay plan: %s", e)
			return None

	def _store_plans(self, text):
		"""
		Stores on the running job what the tx macros read back before their last steps: for words that need
		it, the step before the final search (macros.conf [tenx-wild]: custom.tenx_wild_marks and
		custom.tenx_wild_search); for plain `txf`, the replay plan (macros.conf [tenx-replay-plan]:
		custom.tenx_replay_plan). One request, none when neither applies. If the word plan cannot be stored,
		such a word is matched as after any pipe; without a replay plan the whole replay runs.
		"""
		wild = UNREAD
		try:
			wild = parser.wild_marks(text)
			data = {}
			if wild is not None:
				data.update({"custom.tenx_wild_marks": wild[0], "custom.tenx_wild_search": wild[1]})
			replay = self._replay_plan()
			if replay is not None:
				data["custom.tenx_replay_plan"] = replay
			if not data:
				return
			self._rest("/services/search/jobs/%s?output_mode=json" % urllib.parse.quote(self.parent, safe=""),
					   data, answer=False)
		except Exception as e:
			self.logger.warning("tx: storing the search plans failed: %s", e)
			if wild is not None:
				# a word plan that was needed, or could not be computed
				self.write_warning("tx: a word with a wildcard inside it, TERM() or CASE() is matched in this search as after a "
								   "pipe, which can differ from the same search on the index: the step that matches it as the "
								   "index does could not be prepared.")

	def _store_check(self):
		"""
		Warns when the template store can lack templates the events need: Consume KV failed, is
		still loading, or has not run for fifteen minutes (tenx_prefilter_parser.store_warning).
		One read of one KV record; nothing when it cannot be read. In the minutes after an install or
		an upgrade (no record yet, or a new one), also checks that the template lookup runs on the
		indexers (_lookup_check). Returns False when it does not: the search then reads no indexer.
		"""
		try:
			state = self._rest(parser.STORE_STATE_PATH)
		except urllib.error.HTTPError as e:
			state = None if e.code == 404 else False
			if e.code == 503 and parser.KV_STARTING in (e.read().decode("utf-8", "replace") or ""):
				self.write_warning(parser.KV_NOT_READY)
		except Exception:
			state = False
		# The record also says since when the prefilter's kept template answers may be used (_dictionary).
		self.store_state = state if isinstance(state, dict) else None
		if state is not False:
			note = parser.store_warning(state, time.time())
			if note:
				self.write_warning(note)
			version = parser.conf_setting([os.path.join(apphome, "default", "app.conf")], "launcher", "version")
			if parser.new_version(state, version, time.time()):
				return self._lookup_check()
		return True

	def _lookup_check(self):
		"""
		False when this search head has search peers and the template lookup cannot run on them yet
		(LOOKUP_PROBE, one small search: tenx_prefilter_parser.lookup_failed), with the warning
		NOT_ON_INDEXERS; True otherwise, and whenever the check cannot run.
		"""
		try:
			if not self._rest(parser.PEERS_PATH).get("entry"):
				return True
			info = self._metadata.searchinfo
			try:
				result = self._rest(
					"/servicesNS/%s/%s/search/jobs" % (urllib.parse.quote(info.username), APP_NAME),
					{"search": parser.LOOKUP_PROBE, "exec_mode": "oneshot", "output_mode": "json", "count": "0",
					 "earliest_time": str(info.earliest_time or "0"), "latest_time": str(info.latest_time or "now")})
			except urllib.error.HTTPError as e:
				result = json.loads(e.read().decode() or "{}")
		except Exception as e:
			self.logger.warning("tx: the lookup check failed: %s", e)
			return True
		failed = parser.lookup_failed(result)
		if failed is None:
			return True
		self.logger.warning("tx: the template lookup does not run on the indexers yet: %s", failed)
		self.write_warning(parser.NOT_ON_INDEXERS)
		return False

	def _kv(self, path, records=None):
		"""The prefilter's KV store reads and writes as the searching user: JSON in, JSON out."""
		info = self._metadata.searchinfo
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		request = urllib.request.Request(
			info.splunkd_uri + path, data=json.dumps(records).encode() if records is not None else None,
			method="POST" if records is not None else "GET",
			headers={"Authorization": "Splunk " + info.session_key, "Content-Type": "application/json"})
		with urllib.request.urlopen(request, context=context, timeout=60) as response:
			return json.loads(response.read().decode() or "null")

	def _written_in(self, hours):
		"""Whether the template store holds a record stored in `hours`; True when that cannot be read."""
		try:
			return bool(self._kv(parser.written_in_path(hours)))
		except Exception as e:
			self.logger.info("tx: the recent template records could not be counted: %s", e)
			return True

	def _dictionary(self, pieces, formats):
		"""
		(the template dictionary of `pieces`, the stored timestamp formats or None), as
		tenx_prefilter_parser.dictionary_search() answers them over every record. With an earlier answer
		for every piece in tenx_dict_cache (cache_hours), only the records written in the hours since are
		read and added to it (cache_merge), and no search runs when the store holds none; otherwise every
		record is read and the answer is kept. A
		cache that cannot be read or written only means every record is read. Raises when the template
		lookup fails or reports cut rows.
		"""
		started = time.time()
		try:
			query = json.dumps({"_key": {"$in": parser.cache_keys(pieces, formats)}})
			found = self._kv(parser.CACHE_PATH + "?output_mode=json&query=" + urllib.parse.quote(query, safe=""))
			entries = dict((r.get("_key"), r) for r in (found or []) if isinstance(r, dict))
		except Exception as e:
			self.logger.info("tx: the kept template answers could not be read: %s", e)
			entries = {}
		hours = parser.cache_hours(entries, pieces, formats, started,
								   parser.cache_valid_from(getattr(self, "store_state", None)))
		if hours is not None and not self._written_in(hours):
			return parser.cache_merge(entries, {}, set(), pieces, formats)
		result = self._rest(
			"/servicesNS/%s/%s/search/jobs" % (urllib.parse.quote(self._metadata.searchinfo.username), APP_NAME),
			{"search": parser.dictionary_search(pieces, formats=formats, hours=hours), "exec_mode": "oneshot", "output_mode": "json",
			 "count": "0", "earliest_time": "0", "latest_time": "now"})
		if dictionary_failed(result):
			raise RuntimeError("the template lookup reported: %s" % dictionary_failed(result))
		rows = result.get("results", [])
		dictionary = parser.dictionary_from_rows(rows, pieces)
		if hours is not None:
			return parser.cache_merge(entries, dictionary, parser.format_keys_from_rows(rows), pieces, formats)
		try:
			self._kv(parser.CACHE_PATH + "/batch_save?output_mode=json",
					 parser.cache_records(dictionary, parser.format_keys_from_rows(rows), pieces, formats, started))
		except Exception as e:
			self.logger.info("tx: the template answer was not kept: %s", e)
		return dictionary, (parser.formats_from_rows(rows) if formats else None)

	def generate(self):
		if not self._store_check():
			yield {"search": parser.ON_SEARCH_HEAD}
			return
		try:
			text = self._search_text()
		except Exception as e:
			self.logger.warning("tx: reading the search failed: %s", e)
			text = None
		if text is None:
			self.write_warning("tx: could not read the search it is part of; every compact event in range is expanded.")
			yield {"search": EVERY_EVENT}
			return
		reader = parser.Parser(parser.tokenize(text))
		try:
			tree = reader.parse()
		except parser.Unparsed as e:
			self.write_warning("tx: could not read the words after tx as a search (%s); every compact event in range is expanded." % e)
			yield {"search": EVERY_EVENT}
			return
		if reader.time_modifier:
			self.error_exit(RuntimeError("time modifier after tx"),
				"tx: put earliest= and latest= before `tx`. After it they match no event, so this search was not run.")
		if reader.unquoted_comma:
			self.error_exit(RuntimeError("comma after tx"),
				"tx: a comma after `tx` is matched literally, so this search would miss events. Remove it, or put the text in quotes.")
		several = getattr(self, "calls", 1) > 1
		if not several:
			self._store_plans(text)
		rows, macro = self._original_sourcetype_rows(tree)
		if rows:
			self.error_exit(RuntimeError("original sourcetype"), parser.original_sourcetype_message(rows, macro))
		self._record_checks(macro)
		if several:
			self.write_warning("tx: this search holds more than one tx or txf; every compact event in range is expanded.")
			yield {"search": EVERY_EVENT}
			return
		# The setting is read only when it can change the prefilter (see narrowing_matters).
		text_field = self._text_field() if parser.narrowing_matters(tree) else None
		if text_field is None and parser.compares_fields(tree) and parser.narrowing_mode_on_disk(apphome) == parser.SPLUNK_MODE:
			# field_narrowing = splunk: a field comparison requires the index terms Splunk itself
			# requires of raw events for it, read as words (lookup_pieces, prefilter).
			terms = self._splunk_terms(text)
			if terms is None:
				self.write_warning(parser.SPLUNK_TERMS_UNREAD)
			elif terms != parser.TRUE:
				tree = ("and", [tree, terms])
		# Runs of digits are looked up like words; the same read of the KV store returns the stored
		# timestamp formats, which decide the runs that narrow (digit_pieces_cleared).
		candidates = parser.digit_candidates(tree, text_field)
		dictionary, digits = {}, frozenset()
		pieces = parser.lookup_pieces(tree, text_field=text_field, digits=candidates)
		if pieces:
			try:
				dictionary, formats = self._dictionary(pieces, bool(candidates))
				if candidates:
					digits = parser.digit_pieces_cleared(candidates, formats)
			except Exception as e:
				self.logger.warning("tx: the template lookup failed: %s", e)
				self.write_warning("tx: the template lookup did not complete; every compact event in range is expanded.")
				yield {"search": EVERY_EVENT}
				return
		prefilter = parser.prefilter(tree, dictionary, text_field, digits) or EVERY_EVENT
		yield {"search": prefilter if prefilter == EVERY_EVENT else self._without_words(prefilter)}


dispatch(TenxPrefilterCommand, sys.argv, sys.stdin, sys.stdout, __name__)
