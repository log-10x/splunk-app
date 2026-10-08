"""
tx: search compact events, written the way any search is written.

    | tx index=app_logs sourcetype=tenx_encoded "connection refused" NOT bootstrap

Everything after `tx` is the search, with no searchstring= wrapper and no outer quotes. It is
rewritten and expanded exactly as `| tenxsearch searchstring="..."` is.
"""

import os
import sys

from splunk.clilib.bundle_paths import get_base_path

APP_NAME = 'tenx-for-splunk'
apphome = os.path.join(get_base_path(), APP_NAME)
sys.path.append(os.path.join(apphome, 'bin'))
sys.path.append(os.path.join(apphome, 'lib'))

from splunklib.searchcommands import dispatch, Configuration

import tenxsearch


@Configuration()
class TxCommand(tenxsearch.TenxSearchCommandBase):
	"""
	| tx <search>
	"""

	def _protocol_v2_option_parser(self, arg):
		# Every argument is part of the search, including the ones shaped like name=value.
		return [arg]

	def search_text(self):
		# raw_args keeps each argument as written, quotes included; args strips them.
		return ' '.join(self._metadata.searchinfo.raw_args)


dispatch(TxCommand, sys.argv, sys.stdin, sys.stdout, __name__)
