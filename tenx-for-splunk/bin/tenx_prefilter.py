"""
tenxprefilter: the prefilter of the `tx` macro, built once per search.

`tx` expands to `tenx-events` [| tenxprefilter] | `tenx-inflate` | ... | search *, and the words
written after `tx` become the arguments of that last search. This command runs in the
subsearch: it reads the running job's own search text through the REST API, parses the words
after `tx` (tenx_prefilter_parser), asks the template dictionary which templates carry each
word, and returns one row whose `search` field is the prefilter.

A field comparison (field=value, field IN (...)) narrows only when tenx_config.conf [config] has
field_narrowing = true, tenxreplay has written the list of fields whose value is not text of the
event, and the field is not on it. Off (the default), no field comparison restricts the prefilter.

When it cannot read the search (tx inside another subsearch, or wrapped in another macro) or
cannot parse the words, it returns `(*)`, so every compact event in range is expanded and the
words are applied to the expanded text: slower, never fewer results. It stops with an error
instead where the search would silently miss events: a time modifier after `tx`, an unquoted
comma after `tx`, and a sourcetype= term naming an original sourcetype, which the compact events
carry in tenx_sourcetype (they are indexed as the compact sourcetype).

Some words match other events in that final search, after a pipe, than on the index: a wildcard
inside a word (Se*Privilege is matched as its prefix alone), and TERM() or CASE() of some words
(tenx_prefilter_parser.wild_plan). For those, this command also stores on the running job two
custom fields, custom.tenx_wild_eval and custom.tenx_wild_search: an eval that marks the events
holding each such word as the index does, and the words with each such word replaced by its mark.
`tx` and `txf` read them back in the step before their final search (macros.conf [tenx-wild]).
"""
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request


APP_NAME = 'tenx-for-splunk'
# The app's own folder, wherever Splunk keeps it (etc/apps, or etc/peer-apps on an indexer cluster peer).
apphome = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(apphome, 'bin'))
sys.path.append(os.path.join(apphome, 'lib'))

from splunklib.searchcommands import dispatch, Configuration, GeneratingCommand

import tenx_prefilter_parser as parser

# Splunk names a subsearch's job subsearch_<parent sid>_<epoch>.<n>.
# Matches every event like *, and gives Splunk Web no keyword to highlight (* lit every event).
EVERY_EVENT = "(*)"

# The tenx_replay.conf stanza tenxreplay writes: fields whose value is not text of the event.
NARROWING_STANZA = "tenx:narrowing"

SUBSEARCH_SID = re.compile(r"^subsearch_(.+)_\d+\.\d+$")


@Configuration()
class TenxPrefilterCommand(GeneratingCommand):

	def _rest(self, path, data=None, answer=True):
		info = self._metadata.searchinfo
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		request = urllib.request.Request(
			info.splunkd_uri + path,
			data=urllib.parse.urlencode(data).encode() if data else None,
			method="POST" if data else "GET",
			headers={"Authorization": "Splunk " + info.session_key})
		with urllib.request.urlopen(request, context=context, timeout=60) as response:
			body = response.read().decode()
			return json.loads(body) if answer else None

	def _search_text(self):
		match = SUBSEARCH_SID.match(self._metadata.searchinfo.sid or "")
		if not match:
			return None
		self.parent = match.group(1)
		job = self._rest("/services/search/jobs/%s?output_mode=json" % urllib.parse.quote(match.group(1), safe=""))
		search = job["entry"][0]["content"].get("search", "")
		self.before = parser.macro_call(search)
		return parser.text_after_macro(search)

	def _original_sourcetype_rows(self, tree):
		"""
		Compact events (not field-mapped) whose original sourcetype the search names where it can
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

	def _store_wild_plan(self, text):
		"""
		Stores on the running job what the step before the final search of `tx` and `txf` applies
		(macros.conf [tenx-wild]). Nothing when no word needs it: that step then marks nothing and
		searches `*`. If it cannot be stored, such a word is matched as after any pipe.
		"""
		try:
			plan = parser.wild_plan(text)
			if plan is None:
				return
			self._rest("/services/search/jobs/%s?output_mode=json" % urllib.parse.quote(self.parent, safe=""),
					   {"custom.tenx_wild_eval": plan[0], "custom.tenx_wild_search": plan[1]}, answer=False)
		except Exception as e:
			self.logger.warning("tx: storing the wildcard plan failed: %s", e)
			self.write_warning("tx: a word with a wildcard inside it, TERM() or CASE() is matched in this search as after a "
							   "pipe, which can differ from the same search on the index: the step that matches it as the "
							   "index does could not be prepared.")

	def generate(self):
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
		self._store_wild_plan(text)
		rows, macro = self._original_sourcetype_rows(tree)
		if rows:
			self.error_exit(RuntimeError("original sourcetype"), parser.original_sourcetype_message(rows, macro))
		# The setting is read only when it can change the prefilter (see narrowing_matters).
		text_field = self._text_field() if parser.narrowing_matters(tree) else None
		dictionary = {}
		pieces = parser.lookup_pieces(tree, text_field=text_field)
		if pieces:
			try:
				result = self._rest(
					"/servicesNS/%s/%s/search/jobs" % (urllib.parse.quote(self._metadata.searchinfo.username), APP_NAME),
					{"search": parser.dictionary_search(pieces), "exec_mode": "oneshot", "output_mode": "json",
					 "count": "0", "earliest_time": "0", "latest_time": "now"})
				dictionary = parser.dictionary_from_rows(result.get("results", []))
			except Exception as e:
				self.logger.warning("tx: the template lookup failed: %s", e)
				self.write_warning("tx: the template lookup did not complete; every compact event in range is expanded.")
				yield {"search": EVERY_EVENT}
				return
		yield {"search": parser.prefilter(tree, dictionary, text_field) or EVERY_EVENT}


dispatch(TenxPrefilterCommand, sys.argv, sys.stdin, sys.stdout, __name__)
