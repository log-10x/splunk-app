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
		# an operator word on its own is not a search word: it places no restriction
		assert tree('a OR = b') == ('and', [('or', [('text', 'a'), ('unknown', '=')]), ('text', 'b')])
		assert tree('NOT = x') == ('and', [('not', ('unknown', '=')), ('text', 'x')])


class TestAnOperatorAtTheEndOfTheFieldWord:
	"""
	`SignatureStatus!= Valid`, as a published Sysmon detection writes it: the operator ends the field
	word and the value follows after a space. Read as a comparison with no value, the next word became
	required text, and for != that is the value the search excludes: on Splunk Enterprise 10.4.3 with
	the Sysmon add-on, `SignatureStatus!= Valid` selected 108 events through `txf` against 259 when the
	same term filtered the expanded events, and the detection counted 43 against 139 on raw.
	"""
	DICT = {"valid": (3, ["TERM(~v1)"]), "two": (2, ["TERM(~t1)"]), "words": (2, ["TERM(~w1)"]),
			"signaturestatus": (40, ["TERM(~s1)"]), "root": (5, ["TERM(~r1)"])}

	def test_every_spelling_reads_as_one_comparison_and_places_no_restriction(self):
		cases = {
			'SignatureStatus!= Valid': ('SignatureStatus', '!=', 'Valid'),
			'SignatureStatus != Valid': ('SignatureStatus', '!=', 'Valid'),
			'SignatureStatus !=Valid': ('SignatureStatus', '!=', 'Valid'),
			'SignatureStatus!=Valid': ('SignatureStatus', '!=', 'Valid'),
			'SignatureStatus!="two words"': ('SignatureStatus', '!=', 'two words'),
			'SignatureStatus!= "two words"': ('SignatureStatus', '!=', 'two words'),
			'SignatureStatus != "two words"': ('SignatureStatus', '!=', 'two words'),
			'count>= 5': ('count', '>=', '5'),
			'count >= 5': ('count', '>=', '5'),
			'count < 5': ('count', '<', '5'),
			'count<5': ('count', '<', '5'),
			'count <5': ('count', '<', '5'),
			'count< 5': ('count', '<', '5'),
			'usr= root': ('usr', '=', 'root'),
			'usr = root': ('usr', '=', 'root'),
			'usr =root': ('usr', '=', 'root'),
		}
		for text, (field, op, value) in cases.items():
			assert tree(text) == ('field', field, op, value), text
			assert p.prefilter(tree(text), self.DICT) is None, text

	def test_not_with_a_comparison(self):
		assert tree('NOT SignatureStatus=Valid') == ('not', ('field', 'SignatureStatus', '=', 'Valid'))
		assert tree('NOT SignatureStatus= Valid') == ('not', ('field', 'SignatureStatus', '=', 'Valid'))
		assert p.prefilter(tree('NOT SignatureStatus= Valid'), self.DICT) is None

	def test_the_detection_as_written(self):
		node = tree('EventCode=7 Signed=false SignatureStatus!= Valid NOT (ImageLoaded IN ("C:\\\\Windows\\\\*"))')
		assert node[1][2] == ('field', 'SignatureStatus', '!=', 'Valid')
		assert p.prefilter(node, self.DICT) is None

	def test_the_words_around_it_still_narrow(self):
		assert p.prefilter(tree('root SignatureStatus!= Valid'), self.DICT) == "(((TERM(root) OR TERM(~r1))))"
		assert p.prefilter(tree('SignatureStatus!= Valid root'), self.DICT) == "(((TERM(root) OR TERM(~r1))))"

	def test_what_cannot_be_read_with_certainty_is_not_narrowed(self):
		# The operator at the end, followed by a group, a keyword or another operator: the whole
		# search is left unnarrowed (every compact event in range is expanded).
		for text in ('SignatureStatus!= (Valid OR x)', 'SignatureStatus!= OR x', 'SignatureStatus!= NOT x',
					 'SignatureStatus!= AND x', 'SignatureStatus!= =x', 'a (SignatureStatus!=) b'):
			try:
				tree(text)
			except p.Unparsed:
				continue
			raise AssertionError('read with certainty: %s' % text)

	def test_an_operator_at_the_very_end_is_a_comparison_with_no_value(self):
		assert tree('SignatureStatus!=') == ('field', 'SignatureStatus', '!=', '')
		assert tree('error SignatureStatus !=') == ('and', [('text', 'error'), ('field', 'SignatureStatus', '!=', '')])


class TestAQuotedFieldName:
	"""`"requestParameters.VersioningConfiguration.Status"=Suspended`, as a published CloudTrail detection
	writes it, and the same with != and spaces: read as text, the name and the value were required words,
	and for != the value is what the search excludes."""

	def test_each_spelling_is_one_comparison_with_no_restriction(self):
		cases = {'"usr"!=root': ('usr', '!=', 'root'), '"usr" != root': ('usr', '!=', 'root'),
				 '"usr"!= root': ('usr', '!=', 'root'), '"usr" !=root': ('usr', '!=', 'root'),
				 '"msg"!="a b"': ('msg', '!=', 'a b'), '"msg" != "a b"': ('msg', '!=', 'a b'),
				 '"requestParameters.VersioningConfiguration.Status"=Suspended':
					 ('requestParameters.VersioningConfiguration.Status', '=', 'Suspended'),
				 '"bytes" >= 5': ('bytes', '>=', '5')}
		for text, (field, op, value) in cases.items():
			assert tree(text) == ('field', field, op, value), text
			assert p.prefilter(tree(text), {"usr": (1, ["TERM(~u1)"]), "root": (1, ["TERM(~r1)"])}) is None, text

	def test_a_phrase_followed_by_a_word_is_still_text(self):
		assert tree('"error" code') == ('and', [('text', 'error'), ('text', 'code')])
		assert tree('"did login"') == ('text', 'did login')

	def test_what_cannot_be_read_with_certainty_is_not_narrowed(self):
		for text in ('"usr"!= (a OR b)', '"usr" != OR x', '"usr"= NOT x'):
			try:
				tree(text)
			except p.Unparsed:
				continue
			raise AssertionError('read with certainty: %s' % text)


class TestAQuotedFieldNameBeforeIn:
	"""`"user" IN (alice)`: read as text, the name, the keyword IN and each value were required words
	(Splunk Enterprise 10.4.3, the released package: `"user" IN (alice)` 43 events through tx against
	256 raw, `"host" IN (df-app01)` 0 against 10,000). Each form is one IN comparison, which places no
	restriction, as the unquoted name does."""

	def test_each_form(self):
		cases = {
			'"user" IN (alice)': ['alice'], '"level" IN (ERROR)': ['ERROR'], '"host" IN (df-app01)': ['df-app01'],
			'"user" IN ("alice" "bob")': ['alice', 'bob'], '"user" IN (alice, bob)': ['alice', 'bob'],
			'"user" IN (alice,bob)': ['alice', 'bob'], '"user" IN ("a b", c)': ['a b', 'c'], '"user" IN(alice)': ['alice'],
			'user IN (alice)': ['alice'], 'user IN (alice, "b c")': ['alice', 'b c']}
		for text, values in cases.items():
			field = text.split(' ')[0].strip('"')
			field = field.split('IN')[0].strip('"') if 'IN(' in field else field
			reader = p.Parser(p.tokenize(text))
			assert reader.parse() == ('in', field.strip('"'), values), text
			assert not reader.unquoted_comma, text
			assert p.prefilter(tree(text), {"alice": (1, ["TERM(~a1)"]), "user": (1, ["TERM(~u1)"])}) is None, text

	def test_not_before_it(self):
		assert tree('NOT "user" IN (alice)') == ('not', ('in', 'user', ['alice']))
		assert p.prefilter(tree('error NOT "user" IN (alice)'), {}) == "((TERM(error)))"

	def test_in_without_its_parentheses_is_not_read(self):
		for text in ('"user" IN alice', 'user IN alice', '"user" IN (alice', 'user IN (alice'):
			try:
				tree(text)
			except p.Unparsed:
				continue
			raise AssertionError('read with certainty: %s' % text)
