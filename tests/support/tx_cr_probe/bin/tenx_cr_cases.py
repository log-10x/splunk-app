"""
The values the CR probe writes out through a custom search command, and what a search reads back,
as measured on Splunk Enterprise 10.4.3 (chunked protocol, the app's vendored splunklib as shipped,
whose CSV rows end in CR LF). Shared by the probe command (tenxcrprobe.py), the live check
(tests/live_tx_command_cr.py) and the unit test (tests/test_tx_command_cr.py). Not part of the app
package: build.sh archives only tenx-for-splunk/.
"""

# (case, value written, value a search reads back)
CASES = (
	("crlf", "one\r\ntwo\r\n\r\nend", "one\ntwo\n\nend"),   # a CR before LF is dropped
	("endcr", "one two\r", "one two\r"),                    # a CR that ends the value is kept
	("lonecr", "one\rtwo", "one\rtwo"),                     # a lone CR inside the value is kept
	("crcr", "a\r\r\nb", "a\r\nb"),                         # of CR CR LF, the CR before LF is dropped: 1 of 2 kept
	("lf", "one\ntwo", "one\ntwo"),                         # a value without CR is unchanged
)

# The app README's sentence that states this (under "The `tx` and `tenxsearch` commands").
README_SENTENCE = "`| tx` and `| tenxsearch` return a CR LF line end as LF; the `tx` and `txf` macros keep it."


def as_read_back(value):
	"""The README sentence as a rule: each CR LF becomes LF, in one pass from the left; any other CR is kept."""
	return value.replace("\r\n", "\n")
