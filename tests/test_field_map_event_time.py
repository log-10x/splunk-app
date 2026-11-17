"""
Tests for the field map's event time rule (tenx_field_map, "Event time") and for three reader rules
read from raw events on Splunk Enterprise 10.4.3: JSON names with "-" and ":", empty JSON values, and
backslashes inside a quoted DELIMS value.

The time tests build small CloudTrail-shaped templates in the two forms the engine writes: eventTime as
the template's timestamp slot, and eventTime cut into plain values because the event's first timestamp
(creationDate) took the slot. In both, the text the rule reads the time from must equal the raw event's
text after TIME_PREFIX, cut to MAX_TIMESTAMP_LOOKAHEAD, which is what Splunk reads it from.
"""
import configparser
import io
import json
import os

import pytest

import tenx_dml_builder
import tenx_field_map as fm

M = fm.MARK

AWS = {'TIME_PREFIX': '\\"eventTime\\"\\s*\\:\\s*\\"', 'TIME_FORMAT': '%Y-%m-%dT%H:%M:%S%Z', 'MAX_TIMESTAMP_LOOKAHEAD': '28'}
SIX = '%Y-%m-%dT%H:%M:%S.%6N%Z'

# eventTime is the timestamp slot.
SLOT = ('k1', '{"eventVersion": "$.$", "eventTime": "$(yyyy-MM-dd\'T\'HH:mm:ss\'Z\')", "eventName": "$"}')
SLOT_LINE = '~k1,1794538800000,1,08,DeleteTrail'
SLOT_RAW = '{"eventVersion": "1.08", "eventTime": "2026-11-13T03:00:00Z", "eventName": "DeleteTrail"}'
# creationDate took the slot; eventTime is five plain values.
CUT = ('k2', '{"userIdentity": {"sessionContext": {"attributes": {"creationDate": "$(yyyy-MM-dd\'T\'HH:mm:ss\'Z\')"}}}, '
	'"eventTime": "$$-$:$:$", "eventName": "$"}')
CUT_LINE = '~k2,1794538800000,2026,-11,13T04,05,06Z,DeleteTrail'
CUT_RAW = ('{"userIdentity": {"sessionContext": {"attributes": {"creationDate": "2026-11-13T03:00:00Z"}}}, '
	'"eventTime": "2026-11-13T04:05:06Z", "eventName": "DeleteTrail"}')
# eventTime with six fraction digits as the slot (the engine stores nanoseconds).
MICRO = ('k3', '{"eventTime": "$(yyyy-MM-dd\'T\'HH:mm:ss.SSSSSS\'Z\')", "eventName": "$"}')
MICRO_LINE = '~k3,1793401650446822000,RunInstances'
MICRO_RAW = '{"eventTime": "2026-10-30T23:07:30.446822Z", "eventName": "RunInstances"}'
NONE = ('k4', '{"eventName": "$", "awsRegion": "$"}')


def templates(*pairs):
	builder = tenx_dml_builder.TenxDMLBuilder(timestamp_placeholder=fm.TIMESTAMP_PLACEHOLDER,
		variable_separator=fm.VARIABLE_SEPARATOR)
	out = [fm._from_template_line({'templateHash': h, 'template': t}, builder) for h, t in pairs]
	return dict((t.key, t) for t in out)


def aws_rule():
	return fm.make_time_rule(AWS, formats=[SIX])


def field_map(*pairs, rule=None):
	return fm.FieldMap(templates(*pairs), fm.JsonReader(), 'tenx_ct', timestamp_values='text', rules=fm.RULES_LOOKUP,
		time_rule=rule if rule is not None else aws_rule())


def row(f, key):
	return dict((t.key, t) for t in f.transforms)[key]


class TestTimeRule:
	def test_the_rule_takes_the_add_on_settings_and_the_extra_formats_after_them(self):
		rule = aws_rule()
		assert rule.prefix == AWS['TIME_PREFIX']
		assert rule.formats == ('%Y-%m-%dT%H:%M:%S%Z', SIX)
		assert (rule.lookahead, rule.max_days_ago, rule.max_days_hence) == (28, 2000, 2)

	def test_splunk_defaults_when_the_stanza_does_not_set_them(self):
		rule = fm.make_time_rule({'TIME_FORMAT': '%s'})
		assert (rule.prefix, rule.lookahead, rule.max_days_ago, rule.max_days_hence) == ('^', 128, 2000, 2)

	@pytest.mark.parametrize('settings, says', [
		(dict(AWS, DATETIME_CONFIG='CURRENT'), 'DATETIME_CONFIG'),
		(dict(AWS, TZ='America/New_York'), 'TZ'),
		({'TIME_PREFIX': '^'}, 'no TIME_FORMAT'),
		(dict(AWS, TIME_FORMAT='%Y "%m"'), 'double quote'),
	])
	def test_settings_the_rule_does_not_follow_are_refused(self, settings, says):
		with pytest.raises(ValueError, match=says):
			fm.make_time_rule(settings)

	def test_settings_are_read_from_default_then_the_stanza(self, tmp_path):
		props = tmp_path / 'props.conf'
		props.write_text('[default]\nMAX_DAYS_AGO = 100\nTIME_FORMAT = %s\n\n[aws:cloudtrail]\nTIME_PREFIX = \\"eventTime\\"\\s*\\:\\s*\\"\n'
			'TIME_FORMAT = %Y-%m-%dT%H:%M:%S%Z\nMAX_TIMESTAMP_LOOKAHEAD = 28\nKV_MODE = json\n\n[other]\nTIME_FORMAT = %d\n')
		assert fm.read_time_settings(str(props), 'aws:cloudtrail') == {'MAX_DAYS_AGO': '100',
			'TIME_PREFIX': AWS['TIME_PREFIX'], 'TIME_FORMAT': AWS['TIME_FORMAT'], 'MAX_TIMESTAMP_LOOKAHEAD': '28'}

	def test_a_pcre_named_group_compiles(self):
		rule = fm.make_time_rule({'TIME_PREFIX': '(?<k>time)=', 'TIME_FORMAT': '%H'})
		assert fm.time_text(rule, 'a time=12:00') == '12:00'

	def test_the_per_template_transforms_take_no_rule(self):
		with pytest.raises(ValueError, match='--rules lookup'):
			fm.FieldMap(templates(SLOT), fm.JsonReader(), 'p', rules=fm.RULES_TRANSFORMS, time_rule=aws_rule())


class TestTimeText:
	def test_eventtime_in_the_slot_is_its_rendered_text(self):
		f = field_map(SLOT)
		r = row(f, 'k1')
		# group n+1 is the timestamp text, which the row's t column has the rule render
		assert r.time_recipe.startswith('\\%d' % (r.value_count + 1)) and r.ts_format == '%Y-%m-%dT%H:%M:%SZ'
		assert fm.apply_lookup_time(r, SLOT_LINE, f.time_rule) == fm.time_text(f.time_rule, SLOT_RAW) == \
			'2026-11-13T03:00:00Z", "even'

	def test_eventtime_cut_into_values_is_rebuilt_from_them(self):
		f = field_map(CUT)
		r = row(f, 'k2')
		assert fm.apply_lookup_time(r, CUT_LINE, f.time_rule) == fm.time_text(f.time_rule, CUT_RAW) == \
			'2026-11-13T04:05:06Z", "even'

	def test_six_fraction_digits(self):
		f = field_map(MICRO)
		r = row(f, 'k3')
		assert fm.apply_lookup_time(r, MICRO_LINE, f.time_rule) == fm.time_text(f.time_rule, MICRO_RAW) == \
			'2026-10-30T23:07:30.446822Z"'

	def test_the_recipe_stops_after_the_lookahead_in_template_text(self):
		rule = fm.make_time_rule({'TIME_PREFIX': 'at ', 'TIME_FORMAT': '%H', 'MAX_TIMESTAMP_LOOKAHEAD': '4'})
		f = fm.FieldMap(templates(('h', 'x=$ at 1$-23456 y=$')), fm.KeyValueReader(), 'p', rules=fm.RULES_LOOKUP,
			time_rule=rule)
		# template text "1", value 1, then "-23" makes four characters of template text; the rest is not in
		# the recipe, and the rule keeps the first four characters of what it rebuilds
		assert row(f, 'h').time_recipe == '1\\2-23'
		assert fm.apply_lookup_time(row(f, 'h'), '~h,a,9,b', rule) == '19-2'

	def test_templates_without_a_rule_are_counted_by_reason(self):
		f = field_map(SLOT, NONE)
		assert row(f, 'k4').time_recipe == ''
		assert f.report()['event_time']['templates_with_rule'] == 1
		assert f.report()['event_time']['templates_without_rule'] == {fm.WHY_TIME_NO_PREFIX: 1}

	def test_a_prefix_whose_match_takes_in_a_value_is_refused(self):
		rule = fm.make_time_rule({'TIME_PREFIX': 'time=\\S*\\s', 'TIME_FORMAT': '%H'})
		f = fm.FieldMap(templates(('h', 'time=$ x=$')), fm.KeyValueReader(), 'p', rules=fm.RULES_LOOKUP, time_rule=rule)
		assert row(f, 'h').time_recipe == ''
		assert f.time_skipped == {fm.WHY_TIME_PREFIX_VALUE: 1}

	def test_the_fields_do_not_change_with_the_rule(self):
		with_rule = field_map(SLOT, CUT)
		without = fm.FieldMap(templates(SLOT, CUT), fm.JsonReader(), 'tenx_ct', timestamp_values='text',
			rules=fm.RULES_LOOKUP)
		assert [t.recipe for t in with_rule.transforms] == [t.recipe for t in without.transforms]
		assert [fm.apply_lookup_row(t, l) for t, l in zip(with_rule.transforms, (SLOT_LINE, CUT_LINE))] == \
			[fm.apply_lookup_row(t, l) for t, l in zip(without.transforms, (SLOT_LINE, CUT_LINE))]


class TestTimeRuleText:
	def test_without_a_rule_the_static_rule_is_as_before(self):
		text = fm.lookup_eval_text('t')
		assert text == fm.lookup_eval_text('t', None)
		assert '_time' not in text and 'json_array("n", "t", "f"))' in text
		f = fm.FieldMap(templates(SLOT), fm.JsonReader(), 'p', rules=fm.RULES_LOOKUP)
		assert fm.lookup_columns(f) == fm.LOOKUP_COLUMNS and len(fm.lookup_rows(f, None)[0]) == 5

	def test_the_rule_reads_column_w_and_sets_time_last(self):
		text = fm.lookup_eval_text('t', aws_rule())
		assert 'json_array("n", "t", "f", "w"))' in text
		assert '$pd:tenx_fm_w$=json_extract($pd:tenx_fm_row$, "w")' in text
		# only for an event whose fields were written, and a row with a recipe, cut to the lookahead
		assert ('$pd:tenx_fm_wt$=if(isnull($pd:tenx_fm_m$) OR $pd:tenx_fm_m$==$pd:tenx_fm_x$ OR '
			'coalesce(len($pd:tenx_fm_w$), 0)==0, null(), substr(replace($pd:tenx_fm_x$, ') in text
		assert ', $pd:tenx_fm_w$), 1, 28))' in text
		assert ('$pd:tenx_fm_tt$=if(isnull($pd:tenx_fm_wt$), null(), coalesce(strptime($pd:tenx_fm_wt$, '
			'"%Y-%m-%dT%H:%M:%S%Z"), strptime($pd:tenx_fm_wt$, "%Y-%m-%dT%H:%M:%S.%6N%Z")))') in text
		assert text.endswith('_time=if(tenx_time=="sender", _time, if(isnotnull($pd:tenx_fm_tt$) AND '
			'$pd:tenx_fm_tt$ >= time() - 172800000 AND $pd:tenx_fm_tt$ <= time() + 172800, $pd:tenx_fm_tt$, _time))')
		# Splunk 10.4.3 rejects now() in INGEST_EVAL and skips the whole transform
		assert 'now()' not in text
		# the lines the rule had before are all still there, in the same order
		before = fm.lookup_eval_text('t').replace('json_array("n", "t", "f"))', 'json_array("n", "t", "f", "w"))')
		assert text.startswith(before + ', ')

	def test_an_event_its_sender_marks_keeps_the_senders_time(self):
		# A heavy forwarder that reads the compact events back from files (the app's tenx-record-unwrap) marks each
		# tenx_time=sender with the _time it parsed for the raw event; the rule keeps it, as tenx-event-time does.
		# The comparison is the outer test: on an event without the field it is null, and if() then takes its
		# third argument, the rule as before.
		text = fm.lookup_eval_text('t', aws_rule())
		last = text.split(', _time=', 1)[1]
		assert last.startswith('if(tenx_time=="sender", _time, if(isnotnull($pd:tenx_fm_tt$)')
		assert text.count('tenx_time') == 1
		app = configparser.RawConfigParser(strict=False, interpolation=None)
		app.read(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'default', 'transforms.conf'))
		assert app.get('tenx-event-time', 'INGEST_EVAL').startswith('_time=if(tenx_time=="sender", _time, ')

	def test_one_format_is_read_by_strptime_alone(self):
		# Splunk Enterprise 10.4.3 refuses to compile coalesce() of one argument in an INGEST_EVAL
		text = fm.lookup_eval_text('t', fm.make_time_rule(AWS))
		assert ('$pd:tenx_fm_tt$=if(isnull($pd:tenx_fm_wt$), null(), strptime($pd:tenx_fm_wt$, '
			'"%Y-%m-%dT%H:%M:%S%Z"))') in text
		assert 'coalesce(strptime' not in text
		fgt = fm.make_time_rule({'TIME_PREFIX': '^'}, prefix='date=', formats=['%Y-%m-%d time=%H:%M:%S'])
		assert ', strptime($pd:tenx_fm_wt$, "%Y-%m-%d time=%H:%M:%S"))' in fm.lookup_eval_text('t', fgt)

	def test_two_formats_take_the_first_that_parses(self):
		assert fm.time_parse_text('x', ['%s', '%Y']) == 'coalesce(strptime(x, "%s"), strptime(x, "%Y"))'
		assert fm.time_parse_text('x', ['%s']) == 'strptime(x, "%s")'

	def test_rows_carry_the_recipe_in_a_sixth_column(self):
		f = field_map(SLOT, NONE)
		assert fm.lookup_columns(f) == fm.LOOKUP_COLUMNS + ('w',)
		rows = dict((r[0], r) for r in fm.lookup_rows(f, None))
		assert rows['k1'][5] == row(f, 'k1').time_recipe and rows['k4'][5] == ''

	def test_props_put_the_copied_transforms_first_in_the_generated_list(self):
		target = {'sourcetype': 'tenx_ct', 'rename': 'aws:cloudtrail', 'transforms_class': 'tenx_ct',
			'transform_prefix': 'tenx_ct', 'description': 'd'}
		settings = [('DATETIME_CONFIG', 'CURRENT'), ('TRANSFORMS-tenx_time', 'tenx-event-time')]
		timed = fm.props_text(target, field_map(SLOT), settings)
		assert 'TRANSFORMS-tenx_time' not in timed
		assert '\nTRANSFORMS-tenx_ct = tenx-event-time, tenx_ct_sourcetype, tenx_ct_fields_eval\n' in timed
		plain = fm.props_text(target, fm.FieldMap(templates(SLOT), fm.JsonReader(), 'tenx_ct', rules=fm.RULES_LOOKUP),
			settings)
		assert '\nTRANSFORMS-tenx_time = tenx-event-time\n' in plain
		assert '\nTRANSFORMS-tenx_ct = tenx_ct_sourcetype, tenx_ct_fields_eval\n' in plain


class TestGenAndVerify:
	def files(self, tmp_path):
		records = tmp_path / 'templates.json'
		records.write_text(''.join(json.dumps({'templateHash': h, 'template': t}) + '\n' for h, t in (SLOT, CUT, MICRO)))
		(tmp_path / 'encoded.log').write_text('\n'.join((SLOT_LINE, CUT_LINE, MICRO_LINE)) + '\n')
		(tmp_path / 'raw.log').write_text('\n'.join((SLOT_RAW, CUT_RAW, MICRO_RAW)) + '\n')
		props = tmp_path / 'props.conf'
		props.write_text('[aws:cloudtrail]\n' + ''.join('%s = %s\n' % kv for kv in AWS.items()))
		return ['--records', str(records), '--reader', 'json', '--sourcetype', 'tenx_ct', '--rename', 'aws:cloudtrail',
			'--rules', 'lookup', '--time-props', str(props), '--time-format', SIX]

	def test_gen_writes_the_rule_and_the_column(self, tmp_path):
		out = tmp_path / 'fm'
		assert fm.main(['gen'] + self.files(tmp_path) + ['--out', str(out)]) == 0
		transforms = (out / 'default' / 'transforms.conf').read_text()
		assert '_time=if(tenx_time=="sender", _time, if(isnotnull($pd:tenx_fm_tt$)' in transforms
		assert '\nTRANSFORMS-tenx_ct = tenx-event-time, tenx_ct_sourcetype, tenx_ct_fields_eval\n' in \
			(out / 'default' / 'props.conf').read_text()
		rows = fm.read_lookup_file(str(out / 'lookups' / 'tenx_ct_fields.csv.gz'))
		assert sorted(rows) == ['k1', 'k2', 'k3'] and all(r['w'] for r in rows.values())
		report = json.loads((tmp_path / 'fm_report.json').read_text())
		assert report['event_time']['templates_with_rule'] == 3

	def test_verify_compares_the_time_text_with_the_raw_event(self, tmp_path):
		argv = self.files(tmp_path) + ['--encoded', str(tmp_path / 'encoded.log'), '--raw', str(tmp_path / 'raw.log')]
		assert fm.main(['verify'] + argv) == 0
		args = fm.build_parser().parse_args(['verify'] + argv)
		_, templates_, f = fm._build(args)
		out = io.StringIO()
		result = fm.verify(templates_, f, args.encoded, args.raw, out=out)
		assert result['event_time_text'] == {'equal': 3}
		assert 'event time text: equal to the raw event\'s text after TIME_PREFIX on 3, differs on 0' in out.getvalue()

	def test_gen_stops_on_settings_the_rule_does_not_follow(self, tmp_path, capsys):
		argv = self.files(tmp_path)
		(tmp_path / 'props.conf').write_text('[aws:cloudtrail]\nTZ = UTC\nTIME_FORMAT = %s\n')
		assert fm.main(['gen'] + argv + ['--out', str(tmp_path / 'fm')]) == 2
		assert 'TZ = UTC' in capsys.readouterr().err and not (tmp_path / 'fm').exists()


class TestReaderRules:
	def test_json_names_with_a_dash_or_single_colons_are_field_names(self):
		name = fm.JsonReader.field_name
		for ok in ('requestParameters.x-amz-request-payer', 'requestParameters.encryptionContext.aws:lambda:FunctionArn',
				'additionalEventData.x-amz-id-2', 'a.b{}.c-d{}'):
			assert name.match(ok), ok
		for bad in ('a::b', 'a:', 'a.:b', '-a', 'a b', 'a.b:'):
			assert not name.match(bad), bad

	def test_such_names_are_written(self):
		t = ('h', '{"requestParameters": {"x-amz-request-payer": "$", "encryptionContext": {"aws:lambda:FunctionArn": "$"}}}')
		f = fm.FieldMap(templates(t), fm.JsonReader(), 'p', rules=fm.RULES_LOOKUP)
		assert fm.apply_lookup_row(row(f, 'h'), '~h,requester,arn') == [
			('requestParameters.x-amz-request-payer', 'requester'), ('requestParameters.encryptionContext.aws:lambda:FunctionArn', 'arn')]
		assert f.skipped == {}

	def test_an_empty_json_string_is_a_field_with_an_empty_value(self):
		t = ('h', '{"requestParameters": {"acl": "", "bucket": "$"}}')
		f = fm.FieldMap(templates(t), fm.JsonReader(), 'p', rules=fm.RULES_LOOKUP)
		assert fm.apply_lookup_row(row(f, 'h'), '~h,b1') == [('requestParameters.acl', ''), ('requestParameters.bucket', 'b1')]
		# per-template transforms write it the same way
		transforms = fm.FieldMap(templates(t), fm.JsonReader(), 'p')
		assert transforms.transforms[0].format == 'requestParameters.acl::"" requestParameters.bucket::"$1"'

	def test_the_key_value_reader_still_leaves_an_empty_value_out(self):
		f = fm.FieldMap(templates(('h', 'a= b=$')), fm.KeyValueReader(), 'p', rules=fm.RULES_LOOKUP)
		assert fm.apply_lookup_row(row(f, 'h'), '~h,1') == [('b', '1')]

	def test_a_backslash_escapes_the_next_character_inside_quotes(self):
		r = fm.DelimsReader()
		text = 'msg="a XSS\\\\" f="s\\\\t.xls" g="x\\"></y" r="c\\=d" e="" n=1'
		assert r.pairs(text) == [('msg', 'a XSS\\'), ('f', 's\\t.xls'), ('g', 'x"></y'), ('r', 'c\\=d'), ('e', ''), ('n', '1')]

	def test_a_backslash_before_a_value_stays(self):
		assert fm.DelimsReader().pairs('m="a\\' + M % 1 + '" n=' + M % 2) == [('m', 'a\\' + M % 1), ('n', M % 2)]

	def test_an_empty_value_without_quotes_is_left_out_as_before(self):
		assert fm.DelimsReader().pairs('a= b=1 c=""') == [('b', '1'), ('c', '')]

	def test_spaces_at_the_ends_of_a_quoted_value_go_and_an_empty_one_gives_no_field(self):
		# Splunk Enterprise 10.4.3, the FortiGate add-on's DELIMS extraction: msg=" Fortigate ..." gave "Fortigate ...",
		# user="" gave no value, "  a b  " gave "a b", " " gave no value.
		t = ('h', 'logid=$ msg=" Fortigate scheduled update $" user="" a="  a b  " s=" " v=" $ "')
		f = fm.FieldMap(templates(t), fm.DelimsReader(), 'p', rules=fm.RULES_LOOKUP)
		assert fm.apply_lookup_row(row(f, 'h'), '~h,1,fcni=yes,x') == [
			('logid', '1'), ('msg', 'Fortigate scheduled update fcni=yes'), ('a', 'a b'), ('v', 'x')]


class TestValueCount:
	def test_a_template_of_422_values_gets_a_row(self):
		# A CloudTrail UpdateSAMLProvider event of the sample has 422 values.
		text = ' '.join('k%d=$' % i for i in range(422))
		f = fm.FieldMap(templates(('h', text)), fm.KeyValueReader(), 'p', rules=fm.RULES_LOOKUP)
		pairs = fm.apply_lookup_row(row(f, 'h'), '~h,' + ','.join('v%d' % i for i in range(422)))
		assert len(pairs) == 422 and pairs[-1] == ('k421', 'v421') and pairs[100] == ('k100', 'v100')

	def test_more_than_the_maximum_is_refused(self):
		text = ' '.join('k%d=$' % i for i in range(fm.LOOKUP_MAX_VALUES + 1))
		f = fm.FieldMap(templates(('h', text)), fm.KeyValueReader(), 'p', rules=fm.RULES_LOOKUP)
		assert f.refused == {'h': fm.REFUSED_TOO_MANY % fm.LOOKUP_MAX_VALUES}
		# the largest group a reference names stays three digits
		assert fm.LOOKUP_MAX_VALUES + 1 + len(fm.LOOKUP_TAIL) <= 999


class TestRefusedTemplates:
	def test_a_template_with_two_timestamp_slots_gets_no_row_and_no_time(self):
		# The shape the engine wrote before timestamp.maxPerObject held: a 19-digit number read as an epoch,
		# then creationDate. The app does not expand it (tenx-inflate leaves the event compact and keeps
		# tenx_expand_refused), so the field map writes nothing for it either.
		t = ('h2', '{"principalId": "$:$(+%s)", "creationDate": "$(yyyy-MM-dd\'T\'HH:mm:ss\'Z\')", "eventName": "$"}')
		f = field_map(t)
		assert f.transforms == [] and f.refused == {'h2': fm.REFUSED_UNSAFE % 'multiple-timestamps'}
		assert f.report()['event_time']['templates_with_rule'] == 0
