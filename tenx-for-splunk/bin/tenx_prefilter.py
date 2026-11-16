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
carry in tenx_sourcetype (they are indexed as the compact sourcetype). Called by
`txf(<sourcetype>)` for a sourcetype with no replay unit (missing_unit), it stops saying so.
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

from splunklib.searchcommands import dispatch, Configuration, GeneratingCommand, Option

import tenx_prefilter_parser as parser

# Splunk names a subsearch's job subsearch_<parent sid>_<epoch>.<n>.
# Matches every event like *, and gives Splunk Web no keyword to highlight (* lit every event).
EVERY_EVENT = "(*)"

# The tenx_replay.conf stanza tenxreplay writes: fields whose value is not text of the event.
NARROWING_STANZA = "tenx:narrowing"

SUBSEARCH_SID = re.compile(r"^subsearch_(.+)_\d+\.\d+$")


@Configuration()
class TenxPrefilterCommand(GeneratingCommand):

	# txf(<sourcetype>) on a sourcetype with no replay unit (tenx_replay_builder.TXF_ONE_MISSING):
	# stop with a message saying so, instead of Splunk's "macro cannot be found".
	missing_unit = Option(require=False, default=None)

	def _rest(self, path, data=None):
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
			return json.loads(response.read().decode())

	def _search_text(self):
		match = SUBSEARCH_SID.match(self._metadata.searchinfo.sid or "")
		if not match:
			return None
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

	def generate(self):
		if self.missing_unit:
			self.error_exit(RuntimeError("no replay unit"), parser.missing_unit_message(self.missing_unit))
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
