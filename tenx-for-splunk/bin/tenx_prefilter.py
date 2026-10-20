"""
tenxprefilter: the prefilter of the `tx` macro, built once per search.

`tx` expands to `tenx-events` [| tenxprefilter] | `tenx-inflate` | ... | search *, and the words
written after `tx` become the arguments of that last search. This command runs in the
subsearch: it reads the running job's own search text through the REST API, parses the words
after `tx` (tenx_prefilter_parser), asks the template dictionary which templates carry each
word, and returns one row whose `search` field is the prefilter.

When it cannot read the search (tx inside another subsearch, or wrapped in another macro) or
cannot parse the words, it returns `(*)`, so every compact event in range is expanded and the
words are applied to the expanded text: slower, never fewer results. Two things it stops with
an error instead, because the search after `tx` would silently match nothing: a time modifier
after `tx`, and an unquoted comma after `tx`.
"""
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request

from splunk.clilib.bundle_paths import get_base_path

APP_NAME = 'tenx-for-splunk'
apphome = os.path.join(get_base_path(), APP_NAME)
sys.path.append(os.path.join(apphome, 'bin'))
sys.path.append(os.path.join(apphome, 'lib'))

from splunklib.searchcommands import dispatch, Configuration, GeneratingCommand

import tenx_prefilter_parser as parser

# Splunk names a subsearch's job subsearch_<parent sid>_<epoch>.<n>.
# Matches every event like *, and gives Splunk Web no keyword to highlight (* lit every event).
EVERY_EVENT = "(*)"

SUBSEARCH_SID = re.compile(r"^subsearch_(.+)_\d+\.\d+$")


@Configuration()
class TenxPrefilterCommand(GeneratingCommand):

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
		return parser.text_after_macro(job["entry"][0]["content"].get("search", ""))

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
		dictionary = {}
		pieces = parser.lookup_pieces(tree)
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
		yield {"search": parser.prefilter(tree, dictionary) or EVERY_EVENT}


dispatch(TenxPrefilterCommand, sys.argv, sys.stdin, sys.stdout, __name__)
