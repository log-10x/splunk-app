"""
Field comparisons written with spaces around the operator, as 13 of Splunk's 64 published CloudTrail
detections write them (`eventName = DeleteTrail`, `userAgent !=console.amazonaws.com`,
`src_ip !="guardduty.amazonaws.com"`, `requestParameters.launchPermission.add.items{}.userId = *`).
Read as words, the field name was a required piece, and a field name is template text that no compact
event carries as a value, so `tx` expanded none of the events. On Splunk Enterprise 10.4.3, with
25,576 compact CloudTrail events, 7 such detections counted 0 through `txf` against 1 to 17 on the raw
events, and the same counts as raw once the comparison was read as one.
"""
import tenx_prefilter_parser as p

D = {
	"error": (10, ["TERM(~e1)"]),
	"eventname": (1, ["TERM(~n1)"]),
}


def tree(text):
	return p.Parser(p.tokenize(text)).parse()


class TestSpacedComparisons:
	def test_spaces_on_both_sides(self):
		assert tree('eventName = DeleteTrail') == ('field', 'eventName', '=', 'DeleteTrail')

	def test_a_space_before_the_operator_only(self):
		assert tree('userAgent !=console.amazonaws.com') == ('field', 'userAgent', '!=', 'console.amazonaws.com')
		assert tree('src_ip !="guardduty.amazonaws.com"') == ('field', 'src_ip', '!=', 'guardduty.amazonaws.com')

	def test_a_quoted_value_after_a_spaced_operator(self):
		assert tree('user = "a b"') == ('field', 'user', '=', 'a b')
		assert tree('user = "a \\"b\\""') == ('field', 'user', '=', 'a "b"')

	def test_names_with_braces_and_every_operator(self):
		assert tree('requestParameters.launchPermission.add.items{}.userId = *') == (
			'field', 'requestParameters.launchPermission.add.items{}.userId', '=', '*')
		for op in ('!=', '<=', '>=', '<', '>'):
			assert tree('bytes %s 10' % op) == ('field', 'bytes', op, '10')

	def test_a_detection_as_written(self):
		node = tree('sourcetype=aws:cloudtrail eventName = DeleteTrail eventSource = cloudtrail.amazonaws.com '
			'userAgent !=console.amazonaws.com errorCode = success')
		assert [n[0] for n in node[1]] == ['field'] * 5
		assert p.prefilter(node, D) is None

	def test_the_field_name_is_no_longer_a_required_word(self):
		assert p.prefilter(tree('error eventName = X'), D) == "(((TERM(error) OR TERM(~e1))))"

	def test_words_and_unspaced_comparisons_are_unchanged(self):
		assert tree('error') == ('text', 'error')
		assert tree('eventName=X user') == ('and', [('field', 'eventName', '=', 'X'), ('text', 'user')])
		assert tree('a OR = b') == ('and', [('or', [('text', 'a'), ('text', '=')]), ('text', 'b')])
		assert tree('NOT = x') == ('and', [('not', ('text', '=')), ('text', 'x')])
