"""
tenxcrprobe: a test-only generating command (tests/support/tx_cr_probe, never in the app package). It
writes known values with carriage returns as _raw through the tenx-for-splunk app's own vendored
splunklib, over the chunked protocol, as the app's `tx` and `tenxsearch` commands write their events.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# The tenx-for-splunk app beside this one: etc/apps, or etc/peer-apps on an indexer cluster peer.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "tenx-for-splunk", "lib"))

from splunklib.searchcommands import dispatch, Configuration, GeneratingCommand

from tenx_cr_cases import CASES


@Configuration()
class TenxCrProbe(GeneratingCommand):

	def generate(self):
		for case, value, _ in CASES:
			yield {"_time": 1794900000, "case": case, "_raw": value}


dispatch(TenxCrProbe, sys.argv, sys.stdin, sys.stdout, __name__)
