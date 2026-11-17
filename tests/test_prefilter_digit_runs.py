"""
A run of digits after `tx` narrows when no timestamp format of the stored templates can print it.

A token of an event that starts with a digit is never template text (FORMAT_SPEC.md S3.2, rule 2;
"-1" excepted, S2.2), so it is a value of the compact event, which Splunk indexes as a term. The one
digits an expanded event shows that its compact event does not hold are the ones tenx-inflate prints
for the timestamp. Without the stored formats every run of digits is refused (the shipped rule);
with them, a run no format can print is used like any other piece.

Measured on Splunk Enterprise 10.4.3 after a pipe, the way `tx` applies the words, on
`SystemTime='2023-06-01T12:46:25.1234567Z' ... cpu x86`: `46` and `25` match, `1234567` and `86` do
not (`1234567z` and `x86` do): a run that holds a letter is one run.
"""
import itertools

import tenx_prefilter_parser as p
from support.prefilter_compare import selects_at_least

WINDOWS = "%Y-%m-%dT%H:%M:%S.%7QZ"
FORTIGATE = "%H:%M:%S"
STORED = [(WINDOWS, False, False), ("%Y-%m-%dT%H:%M:%S.%9QZ", False, False), (FORTIGATE, False, False)]
D = {"error": (10, ["TERM(~e1)"]), "took": (3, ["TERM(~t1)"]), "ms": (3, ["TERM(~m1)"])}


def tree(text):
	return p.Parser(p.tokenize(text)).parse()


def plan(text, formats=STORED, text_field=None):
	t = tree(text)
	digits = p.digit_pieces_cleared(p.digit_candidates(t, text_field), formats)
	return p.prefilter(t, D, text_field, digits)


class TestWhatAFormatPrints:

	def test_the_windows_format(self):
		# %Y prints a year, %m %d %H %M %S two digits in their range; %dT%H and %7QZ hold a letter
		for piece in ("2023", "1999", "06", "12", "46", "59", "00"):
			assert p.timestamp_prints(piece, WINDOWS, False, False), piece
		for piece in ("4625", "54849625", "1234567", "60", "99", "5", "123", "13824", "2300", "1899"):
			assert not p.timestamp_prints(piece, WINDOWS, False, False), piece

	def test_the_fortigate_format(self):
		for piece in ("08", "23", "59"):
			assert p.timestamp_prints(piece, FORTIGATE, False, False), piece
		for piece in ("4625", "2023", "60", "8443", "1"):
			assert not p.timestamp_prints(piece, FORTIGATE, False, False), piece

	def test_fractions_zones_and_names(self):
		assert p.timestamp_prints("936", "%H:%M:%S.%3Q", False, False)
		assert not p.timestamp_prints("9361", "%H:%M:%S.%3Q", False, False)
		assert p.timestamp_prints("0000", "%d/%b/%Y:%H:%M:%S %z", False, False)
		assert p.timestamp_prints("00", "%Y-%m-%dT%H:%M:%S%:z", False, False)
		assert not p.timestamp_prints("1", "%b %d %Y %I:%M:%S %p", False, False)
		assert p.timestamp_prints("1", "%b %-d %Y", False, False)
		assert p.timestamp_prints("366", "%Y.%j", False, False) and not p.timestamp_prints("367", "%Y.%j", False, False)
		# digits that touch, with no breaker between: one run
		assert p.timestamp_prints("20240315", "%Y%m%d", False, False)
		assert not p.timestamp_prints("2024", "%Y%m%d", False, False)
		assert p.timestamp_prints("1430", "%H%M", False, False) and not p.timestamp_prints("2460", "%H%M", False, False)

	def test_a_directive_it_does_not_know_prints_any_digits(self):
		for piece in ("4625", "7", "123456789012"):
			assert p.timestamp_prints(piece, "%s", False, False), piece
			assert p.timestamp_prints(piece, "%H:%M:%S.%N", False, False), piece
		# two fractions print the digit count of the last one (tenx-inflate tenx_ts_n)
		assert p.timestamp_prints("4625", "%3Q %6Q", False, False)

	def test_digits_glued_to_the_timestamp(self):
		# a digit of the template text or a value right before or after the timestamp
		assert not p.timestamp_prints("4625", FORTIGATE, False, False)
		assert p.timestamp_prints("4625", FORTIGATE, False, True)   # 46 then glued digits
		assert p.timestamp_prints("4612", FORTIGATE, True, False)   # glued digits then 12
		assert not p.timestamp_prints("4625", FORTIGATE, True, False)
		assert p.timestamp_prints("12023", WINDOWS, True, False)
		# the right end of the Windows format holds a Z, so nothing glues to a digit there
		assert not p.timestamp_prints("1234567", WINDOWS, True, True)

	def test_an_epoch_written_back_as_it_is(self):
		# the printed text is the compact event's own value, a term of it, unless digits glue to it
		assert not p.timestamp_prints("1700000000", p.EPOCH_PASSTHROUGH, False, False)
		assert p.timestamp_prints("1700000000", p.EPOCH_PASSTHROUGH, True, False)
		assert p.timestamp_prints("17", p.EPOCH_PASSTHROUGH, False, True)

	def test_brute_force_two_and_four_digit_runs(self):
		# every value the zero-padded fields print, and no other, for the formats stored on the test Splunk
		hours, sixty, years = range(24), range(60), range(1900, 2300)
		printable_w = {"%02d" % v for v in sixty} | {"%02d" % v for v in range(1, 32)} | {str(v) for v in years}
		printable_f = {"%02d" % v for v in sixty}
		for n in (2, 4):
			for digits in itertools.product("0123456789", repeat=n):
				piece = "".join(digits)
				assert p.timestamp_prints(piece, WINDOWS, False, False) == (piece in printable_w), piece
				assert p.timestamp_prints(piece, FORTIGATE, False, False) == (piece in printable_f), piece
		assert {"%02d" % v for v in hours} <= printable_f


class TestThePrefilter:

	def test_a_run_no_format_prints_narrows(self):
		assert plan("4625") == "(TERM(4625))"
		assert plan('"took 1234 ms"') == "((TERM(took) OR TERM(~t1)) AND TERM(1234) AND (TERM(ms) OR TERM(~m1)))"
		assert plan("error 54849625") == "(((TERM(error) OR TERM(~e1))) AND (TERM(54849625)))"

	def test_a_run_a_format_prints_does_not(self):
		for text in ("2023", "12", "46"):
			assert plan(text) is None, text
		assert plan("error 46") == "(((TERM(error) OR TERM(~e1))))"
		assert plan("936", STORED + [("%H:%M:%S.%3Q", False, False)]) is None

	def test_without_the_formats_nothing_changes(self):
		# no formats read (failure or no template): every run of digits is refused, as before
		for text in ("4625", '"took 1234 ms"', "error 54849625", "EventCode=4625", "x IN (4624, 4625)"):
			assert plan(text, []) == p.prefilter(tree(text), D), text
		assert plan("4625", []) is None

	def test_the_template_dictionary_is_asked_about_a_run(self):
		# "-1" is template text (FORMAT_SPEC S2.2): a run is looked up like a word
		t = tree("1 error")
		digits = p.digit_pieces_cleared(p.digit_candidates(t), STORED)
		assert digits == {"1"}
		assert p.lookup_pieces(t, digits=digits) == {"1", "error"}
		assert p.prefilter(t, {"1": (2, ["TERM(~a)", "TERM(~b)"])}, None, digits) == \
			"(((TERM(1) OR TERM(~a) OR TERM(~b))) AND (TERM(error)))"

	def test_dates_and_times_written_in_the_search_still_place_no_restriction(self):
		for text in ('"20:11:45.936"', '"2025-11-12"', '20240315080000', '"12:46:25"'):
			assert plan(text) is None, text

	def test_addresses_keep_their_own_rule(self):
		assert plan("10.0.1.14") == p.prefilter(tree("10.0.1.14"), D)
		assert plan("10.0.1.14:8443") == ("(TERM(8443) AND (TERM(10) OR TERM(10.0.1.14)) AND (TERM(0) OR TERM(10.0.1.14))"
										" AND (TERM(1) OR TERM(10.0.1.14)) AND (TERM(14) OR TERM(10.0.1.14)))")

	def test_field_values_with_field_narrowing_on(self):
		text_field = p.text_field_predicate(["action"])
		assert plan("EventCode=4625", text_field=text_field) == "(TERM(4625))"
		assert plan("EventCode IN (4624, 4625)", text_field=text_field) == "((TERM(4624)) OR (TERM(4625)))"
		assert plan("action=4625", text_field=text_field) is None
		# off, a field comparison places no restriction, digits or not
		assert plan("EventCode=4625") is None

	def test_it_only_ever_narrows_what_the_shipped_rule_selected(self):
		# the shipped rule refused every run of digits, so its prefilter is implied by the new one:
		# every compact event the new prefilter selects, the shipped one selected
		for text in ("4625", "error 4625", "4625 OR error", "NOT 4625", '"took 1234 ms" error', "(4625 OR 4624) error",
					 "EventCode=4625", "4625 2023", "x=1 4625"):
			new, old = plan(text), p.prefilter(tree(text), D)
			assert selects_at_least(new, old), text


class TestTheFormatsComeWithTheDictionary:
	"""One read of the KV store answers both: which templates carry each piece, and every stored timestamp format."""

	def test_the_search_returns_the_formats_of_every_record(self):
		s = p.dictionary_search({"4625", "error"}, formats=True)
		assert s.startswith("| inputlookup tenx-dml-lookup ") and s.endswith(", values(tenx_fk) as tenx_formats")
		assert " | where " not in s  # every record reaches the stats, a record without the pieces too
		assert "timestamp_format, part_0, pattern_parts, pattern_terminator" in s
		assert p.FORMAT_KEY_STEPS in s
		# mvfilter() takes a single field: Splunk 10.4.3 rejects an expression of several (FATAL, invalid arguments)
		import re
		for arg in re.findall(r"mvfilter\((.*?)\)\)", s):
			assert len(set(re.findall(r"\b(?!match\b|len\b)[a-z_]+\b(?=[,)])", arg + ")"))) <= 1, arg
		assert 'mvfilter(match(tenx_tp, "__TENX_TS__"))' in s
		assert " | where " in p.dictionary_search({"error"}) and "tenx_formats" not in p.dictionary_search({"error"})

	def test_reading_the_formats_back(self):
		rows = [{"n0": "1", "hs0": "TERM(~a)", "tenx_formats": ["00|%H:%M:%S", "10|%Y-%m-%dT%H:%M:%S.%7QZ", "01|a|b"]}]
		assert p.formats_from_rows(rows) == [("%H:%M:%S", False, False), ("%Y-%m-%dT%H:%M:%S.%7QZ", True, False), ("a|b", False, True)]
		assert p.formats_from_rows([{"n0": "1", "tenx_formats": "00|%H:%M:%S"}]) == [("%H:%M:%S", False, False)]
		# no formats in the answer: not known, so no run of digits narrows
		assert p.formats_from_rows([{"n0": "1"}]) is None
		assert p.digit_pieces_cleared({"4625"}, p.formats_from_rows([{"n0": "1"}])) == frozenset()
		assert p.digit_pieces_cleared({"4625"}, p.formats_from_rows(rows)) == {"4625"}
