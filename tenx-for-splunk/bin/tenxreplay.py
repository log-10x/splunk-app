"""
Tenx Replay Command
===================

    | tenxreplay              rebuild the field replay macros and the replay field lists
    | tenxreplay apply=false  report what it would write, and write nothing

`txf` expands a compact event and then runs the `tenx-replay` macro, which applies the search-time
rules of the event's original sourcetype: the indexed field tenx_sourcetype, set by the sender.
(`tx` runs no replay: Splunk reads a macro's whole text on every search, so the replay is only in
the searches that ask for it.) This command writes that macro from the running instance's own
configuration (see tenx_replay_builder.py for the rules and their order):

1. the original sourcetypes, sources, hosts and indexes present in the compact events, over the
   search's time range (`| tstats ... where `tenx-events` by tenx_sourcetype, source, host,
   index`), and over all time for a sourcetype the replay does not cover yet;
2. the props stanzas this app can see, as merged by Splunk, and the [default] stanza;
3. the lookup definitions this app can see, with their fields;
4. the indexed fields of the compact events, which the replay keeps when it clears the fields
   Splunk set on the unexpanded event (fields.conf INDEXED = true on every event, and the fields
   of a sample of compact events that tstats can count, per original sourcetype).

What the written replay already covers stays covered (see tenx_replay_builder.keep_covered and
coverage), so a sourcetype that stopped sending keeps its replay for searches over its older
events, and the sources, hosts and indexes recorded for a sourcetype accumulate until it expires.

It writes the macro; one unit per original sourcetype (tenx-replay-u<hash>: that sourcetype's
rules alone, limited to the source:: and host:: stanzas matching what was recorded for it), with
the alias tenx-replay-st-<sourcetype> that `txf(<sourcetype>)` calls; one tenx_replay.conf stanza
per original sourcetype listing the fields a calculated field or a lookup produces and the
sources, hosts and indexes recorded (the search rewrite reads `indexes` to pick the units a search
needs); and the stanza [tenx:narrowing]: every field whose value some props stanza takes from
somewhere other than the event's text, which the prefilter must not narrow on (see
tenx_prefilter_parser.py). Every rule, the macro and the units are run against this Splunk before
anything is written. Nothing is written when the result is unchanged. One row per original
sourcetype is returned. The "Rebuild Field Replay" saved search runs it hourly. "Rebuild Field
Replay When New" runs `| tenxreplay only_new=true` every five minutes over the last ten: one
tstats and one read of tenx_replay.conf, and a full rebuild over the last 7 days only when an
original sourcetype, or a sourcetype with a source, host or index, appears that the written
replay does not cover. (The template consumer cannot do this check: a template record holds
only the hash and the template text, not the sourcetype of the events that use it.)

A compiled alert stores the search rewrite's text, which names the replay units for the indexes
it searches, and "Recompile Compiled Alerts" rewrites it every 15 minutes. So that an alert does
not wait for that run, whenever this command changes what the rewrite chooses for an index (a
stanza's indexes or unit, a stanza added or removed, the negative record [tenx:nocarrier]) it
dispatches "Recompile Compiled Alerts" once, after its writes. A failed dispatch is logged and
changes nothing else: the scheduled run still comes.

Logging
-------
Logs to: $SPLUNK_HOME/var/log/splunk/tenx_replay_command.log
"""

import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from splunk.clilib.bundle_paths import get_base_path

APP_NAME = 'tenx-for-splunk'
apphome = os.path.join(get_base_path(), APP_NAME)
sys.path.append(os.path.join(apphome, 'bin'))
sys.path.append(os.path.join(apphome, 'lib'))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators

import tenx_util
import tenx_replay_builder as builder

tenx_util.setup_logger('tenx_replay_command', logging.INFO)

MACRO = 'tenx-replay'
CONF = 'tenx_replay'
# default/savedsearches.conf: rewrites every managed compiled alert whose compiled text changed.
RECOMPILE_SEARCH = 'Recompile Compiled Alerts'
SAMPLE_EVENTS = 1000


def shared_with_everyone(acl):
	"""Whether a macro listing's acl shares it with every app and lets every role read it."""
	acl = acl or {}
	read = (acl.get('perms') or {}).get('read') or []
	if isinstance(read, str):
		read = [r.strip() for r in read.split(',')]
	return acl.get('sharing') == 'global' and '*' in read


@Configuration()
class TenxReplayCommand(GeneratingCommand):

	apply = Option(require=False, validate=validators.Boolean(), default=True)
	# Check first: rebuild only when the compact events of the search's time range carry an
	# original sourcetype, or a sourcetype and source, that the written replay does not cover.
	only_new = Option(require=False, validate=validators.Boolean(), default=False)
	# Time range of the rebuild (present sourcetypes) when only_new finds something new.
	lookback = Option(require=False, default='-7d')

	def _rest(self, path, data=None, method=None):
		info = self._metadata.searchinfo
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		sep = '&' if '?' in path else '?'
		request = urllib.request.Request(
			info.splunkd_uri + path + sep + 'output_mode=json',
			data=urllib.parse.urlencode(data).encode() if data is not None else None,
			method=method or ('POST' if data is not None else 'GET'),
			headers={'Authorization': 'Splunk ' + info.session_key})
		with urllib.request.urlopen(request, context=context, timeout=120) as response:
			body = response.read().decode()
			return json.loads(body) if body.strip() else {}

	def _ns(self, path):
		return '/servicesNS/nobody/%s/%s' % (APP_NAME, path)

	def _oneshot(self, search, earliest, latest):
		result = self._rest('/servicesNS/%s/%s/search/jobs' % (
			urllib.parse.quote(self._metadata.searchinfo.username), APP_NAME),
			{'search': search, 'exec_mode': 'oneshot', 'count': '0',
			 'earliest_time': earliest, 'latest_time': latest})
		return result.get('results', [])

	def _time_range(self):
		info = self._metadata.searchinfo
		earliest = info.earliest_time if info.earliest_time not in (None, '', 0, '0') else '0'
		latest = info.latest_time if info.latest_time not in (None, '', 0, '0') else 'now'
		return str(earliest), str(latest)

	def _stanzas(self):
		default = dict((e['name'], e['content']) for e in
			self._rest(self._ns('properties/props/default?count=0')).get('entry', []))
		stanzas = [builder.Stanza('default', default)]
		entries, skipped = builder.shared_globally(self._rest(self._ns('configs/conf-props?count=0')).get('entry', []))
		if skipped:
			self.logger.warning("tenxreplay: props stanzas not shared with every app are not replayed "
								"(see tenx_replay_builder, one macro for every app): %s", builder._listed(skipped))
		for entry in entries:
			content = entry.get('content', {})
			if str(content.get('disabled', '0')).strip().lower() in ('1', 'true'):
				continue
			stanzas.append(builder.Stanza(entry['name'], content, default))
		return stanzas

	def _lookup_fields(self):
		fields = {}
		for entry in self._rest(self._ns('data/transforms/lookups?count=0')).get('entry', []):
			content = entry.get('content', {})
			cols = content.get('fields_array') or [c for c in str(content.get('fields_list') or '').split(',') if c]
			fields[entry['name']] = [c.strip() for c in cols]
		return fields

	def _transforms(self):
		return dict((e['name'], e.get('content', {})) for e in
			self._rest(self._ns('configs/conf-transforms?count=0')).get('entry', []))

	def _indexed_fields(self, earliest, latest):
		"""
		(every indexed field name of the compact events, the names declared indexed,
		{original sourcetype: the indexed fields of its compact events}).

		The first is what the prefilter must not narrow on (builder.fields_not_in_text): fields.conf
		INDEXED = true, and the fields of a sample of compact events that tstats can count over all
		compact events. The replay's clearing step keeps the second on every replayed event and the
		third per original sourcetype (builder.build keep_by_sourcetype), counted over the events the
		replay works on: those carrying tenx_sourcetype and not indexed with a field map (tenx_mapped,
		which tenx-mapped-hide keeps out of the replay). An indexed field one sender writes for one
		sourcetype (a field map's app on FortiGate events) is then no reason to keep the field of the
		same name that Splunk set on another sourcetype's compact events when it read them.
		"""
		declared = set()
		for entry in self._rest(self._ns('configs/conf-fields?count=0')).get('entry', []):
			if str(entry.get('content', {}).get('INDEXED', '')).strip().lower() in ('1', 'true'):
				declared.add(entry['name'])
		names = set(declared)
		by_sourcetype = {}
		rows = self._oneshot('search `tenx-events` | head %d | fieldsummary | fields field' % SAMPLE_EVENTS, earliest, latest)
		candidates = sorted(set(r.get('field') for r in rows if r.get('field')) - set(builder.DEFAULT_KEEP))
		candidates = [c for c in candidates if not c.startswith(('_', 'tenx_', 'date_')) and '"' not in c]
		if candidates:
			funcs = ', '.join('dc("%s") as f%d' % (c, n) for n, c in enumerate(candidates))
			counts = self._oneshot('| tstats %s where `tenx-events`' % funcs, earliest, latest)
			row = counts[0] if counts else {}
			names.update(c for n, c in enumerate(candidates) if str(row.get('f%d' % n, '0')) not in ('0', ''))
			for row in self._oneshot('| tstats %s where `tenx-events` NOT %s=* by %s' % (
					funcs, builder.MAPPED_FIELD, builder.CARRIER_FIELD), earliest, latest):
				st = row.get(builder.CARRIER_FIELD)
				if st:
					by_sourcetype.setdefault(st, set()).update(
						c for n, c in enumerate(candidates) if str(row.get('f%d' % n, '0')) not in ('0', ''))

		def usable(found):
			# Splunk's own fields.conf lists its default fields; those are kept anyway.
			return sorted(n for n in found if n not in builder.DEFAULT_KEEP and '*' not in n and '::' not in n
						  and not n.startswith(('_', 'tenx_', 'date_')))
		return usable(names), usable(declared), dict((st, usable(found)) for st, found in by_sourcetype.items())

	def _indexed_value_false(self):
		"""
		fields.conf stanzas whose INDEXED_VALUE is anything but true: Splunk does not look their
		value up as a term of the raw text, so the prefilter must not narrow on them either.
		"""
		names = []
		for entry in self._rest(self._ns('configs/conf-fields?count=0')).get('entry', []):
			value = str(entry.get('content', {}).get('INDEXED_VALUE', '') or '').strip().lower()
			if value not in ('', '1', 'true'):
				names.append(entry['name'])
		return names

	def _dry_run(self, spl):
		"""
		Runs `spl` as a oneshot job and returns None when it ran cleanly, else the error Splunk
		reported (builder.dry_run_error reads the reply). The checks against the running Splunk
		go through this one method: see builder.failing_rules and builder.macro_dry_run.
		"""
		try:
			body = self._rest('/servicesNS/%s/%s/search/jobs' % (
				urllib.parse.quote(self._metadata.searchinfo.username), APP_NAME),
				{'search': spl, 'exec_mode': 'oneshot', 'count': '1', 'earliest_time': '-1s', 'latest_time': 'now'})
			return builder.dry_run_error(200, body)
		except urllib.error.HTTPError as e:
			return builder.dry_run_error(e.code, e.read().decode('utf-8', 'replace'))

	def _lookup_problems(self):
		"""Lookups the replay must not write: see builder.lookup_problems."""
		definitions = self._rest(self._ns('data/transforms/lookups?count=0')).get('entry', [])
		files = self._rest('/servicesNS/nobody/-/data/lookup-table-files?count=0').get('entry', [])
		collections = self._rest('/servicesNS/nobody/-/storage/collections/config?count=0').get('entry', [])
		return builder.lookup_problems(definitions, files, collections)

	def _present(self, earliest, latest, sourcetypes=None):
		"""
		(original sourcetype, source, host, count, index) of the compact events in the time range,
		of every original sourcetype or only of `sourcetypes`.
		"""
		where = ''
		if sourcetypes:
			where = ' (%s)' % ' OR '.join('%s=%s' % (builder.CARRIER_FIELD, builder.spl_string(st)) for st in sorted(sourcetypes))
		rows = self._oneshot('| tstats count where `tenx-events`%s by %s, source, host, index' % (where, builder.CARRIER_FIELD),
			earliest, latest)
		return [(r[builder.CARRIER_FIELD], r.get('source', ''), r.get('host', ''), int(r.get('count', 0) or 0),
				 r.get('index', '')) for r in rows if r.get(builder.CARRIER_FIELD)]

	def _config(self):
		"""tenx_config.conf [config]: the replay limits and field_narrowing. Unreadable: the defaults."""
		try:
			return self._rest(self._ns('configs/conf-tenx_config/config')).get('entry', [{}])[0].get('content', {})
		except Exception as e:
			self.logger.warning("tenxreplay: could not read tenx_config.conf [config] (%s); using the defaults", e)
			return {}

	def _macro_path(self, name):
		return self._ns('configs/conf-macros/%s' % urllib.parse.quote(name, safe=''))

	def _write_units(self, units, keep=(), retired=None, now=None, settings=None):
		"""
		Writes each covered sourcetype's unit (`tenx-replay-u<hash>`) and the alias `txf(<name>)`
		calls (`tenx-replay-st-<name>`), and turns the unit of a sourcetype no longer covered into
		the no-op unit, so a saved search or compiled alert that names it keeps running (as `tx`)
		until it is recompiled. A new macro is shared with every app, readable by every role, as
		default.meta shares the shipped ones. Only definitions that change are written.
		"""
		existing, shared = {}, {}
		for entry in self._rest(self._ns('configs/conf-macros?count=0&search=%s' % urllib.parse.quote(
				builder.UNIT_PREFIX[:len('tenx-replay-')]))).get('entry', []):
			if entry['name'].startswith((builder.UNIT_PREFIX, builder.ALIAS_PREFIX)):
				existing[entry['name']] = entry.get('content', {}).get('definition')
				shared[entry['name']] = shared_with_everyone(entry.get('acl'))
		want = {}
		for st, unit in sorted(units.items()):
			want[builder.unit_macro(st)] = unit.spl()
			alias = builder.alias_macro(st)
			if alias:
				want[alias] = '`%s`' % builder.unit_macro(st)
		no_op = builder.no_op_unit().spl()
		no_op_names = set()
		for name in existing:
			# `keep`: the units of sourcetypes still covered whose new unit did not run; the
			# previous text stays (txf(<sourcetype>) keeps working as before).
			if name.startswith(builder.UNIT_PREFIX) and name not in want and name not in keep:
				no_op_names.add(name)
		settings = settings or builder.DEFAULT_SETTINGS
		self.retired, delete = builder.retire_units(
			no_op_names, retired or {}, time.time() if now is None else now,
			settings.get('replay_unit_grace_days', builder.DEFAULT_SETTINGS['replay_unit_grace_days']),
			settings.get('replay_max_sourcetypes', builder.DEFAULT_SETTINGS['replay_max_sourcetypes']))
		for name in self.retired:
			want[name] = no_op
		changed = []
		# A unit no-op past replay_unit_grace_days, or past the cap on no-op units, is deleted
		# with every alias naming it, so local/macros.conf does not grow with every
		# tenx_sourcetype value ever seen.
		for name in delete:
			for alias in sorted(n for n, d in existing.items() if n.startswith(builder.ALIAS_PREFIX) and d == '`%s`' % name):
				self._rest(self._macro_path(alias), method='DELETE')
				changed.append('-' + alias)
				del existing[alias]
			self._rest(self._macro_path(name), method='DELETE')
			changed.append('-' + name)
			del existing[name]
		# An alias whose name is not a valid macro name (Splunk refuses a colon in a macro name,
		# for example) can never be called: remove it.
		for name in sorted(existing):
			if name.startswith(builder.ALIAS_PREFIX) and not builder.ALIAS_NAME.match(name[len(builder.ALIAS_PREFIX):]):
				self._rest(self._macro_path(name), method='DELETE')
				changed.append('-' + name)
		# Units before aliases, so an alias never names a unit that is not written yet.
		for name, definition in sorted(want.items(), key=lambda kv: (not kv[0].startswith(builder.UNIT_PREFIX), kv[0])):
			if name not in existing:
				try:
					self._rest(self._ns('configs/conf-macros'), {'name': name, 'definition': definition})
				except urllib.error.HTTPError as e:
					if e.code != 409:
						raise
					# It exists after all (the listing missed it): update it instead.
					self._rest(self._macro_path(name), {'definition': definition})
				self._share(name)
				changed.append(name)
				continue
			if existing[name] != definition:
				self._rest(self._macro_path(name), {'definition': definition})
				changed.append(name)
			# Checked on every rebuild, not only after a create: an ACL write that failed once (the
			# rebuild stops there) left the macro shared with this app only, and the rewrite and
			# txf(<sourcetype>) in any other app would fail with "macro cannot be found".
			if not shared.get(name):
				self._share(name)
				changed.append('acl:' + name)
		return changed

	def _write_nocarrier(self, have, want):
		"""Writes the negative record [tenx:nocarrier] indexes = `want` (deleted when empty)."""
		path = self._ns('configs/conf-%s/%s' % (CONF, urllib.parse.quote(builder.NOCARRIER_STANZA, safe='')))
		if have is None:
			if not want:
				return []
			self._rest(self._ns('configs/conf-%s' % CONF), {'name': builder.NOCARRIER_STANZA, 'indexes': want})
		elif not want:
			self._rest(path, method='DELETE')
		elif str(have.get('indexes', '') or '') != want:
			self._rest(path, {'indexes': want})
		else:
			return []
		return ['nocarrier']

	def _compact_indexes(self, earliest, latest):
		"""{index: count} of every compact event in the time range, carrier or not."""
		rows = self._oneshot('| tstats count where `tenx-events` by index', earliest, latest)
		return dict((r.get('index', ''), int(r.get('count', 0) or 0)) for r in rows if r.get('index'))

	def _check_indexes(self, rows):
		"""
		The 5-minute check's own writes, made before any rebuild so the window in which a search can
		lack fields is this check's interval and no longer: an index that now holds carrier events
		leaves the negative record (the rewrite then runs the full replay there), and a covered
		sourcetype seen in an index its stanza does not list gets that index added (the rewrite then
		chains its unit there).
		"""
		try:
			entries = dict((e['name'], e.get('content', {})) for e in
						   self._rest(self._ns('configs/conf-%s?count=0' % CONF)).get('entry', []))
		except urllib.error.HTTPError:
			return []
		changed = []
		carriers = set((r[4] or '').lower() for r in rows if len(r) > 4 and r[4])
		have = entries.get(builder.NOCARRIER_STANZA)
		if have is not None:
			listed = builder.parse_listed(have.get('indexes', ''))
			if listed is not builder.ALL and carriers & set(i.lower() for i in listed):
				want = ','.join(sorted(i for i in listed if i.lower() not in carriers))
				changed += self._write_nocarrier(have, want)
		adds = {}
		for st, key, ix in builder.uncovered_values(rows, entries):
			if key == 'indexes':
				adds.setdefault(st, set()).add(ix)
		for st, ixs in sorted(adds.items()):
			listed = builder.parse_listed(entries[st].get('indexes', ''))
			if listed is builder.ALL or not listed:
				continue
			value = builder.listed_value(set(listed) | ixs)
			self._rest(self._ns('configs/conf-%s/%s' % (CONF, urllib.parse.quote(st, safe=''))), {'indexes': value})
			changed.append('indexes:' + st)
		self.rewrite_changed += changed
		return changed

	def _write_retired(self, had, want, exists):
		"""Writes [tenx:retired] (unit name = day it became the no-op unit); a key is removed by rewriting the stanza."""
		if had == want:
			return []
		path = self._ns('configs/conf-%s/%s' % (CONF, urllib.parse.quote(builder.RETIRED_STANZA, safe='')))
		if exists and (not want or set(had) - set(want)):
			self._rest(path, method='DELETE')
			exists = False
		if want and not exists:
			self._rest(self._ns('configs/conf-%s' % CONF), dict(want, name=builder.RETIRED_STANZA))
		elif want:
			self._rest(path, dict((k, v) for k, v in want.items() if had.get(k) != v))
		return ['retired']

	def _share(self, name):
		self._rest(self._macro_path(name) + '/acl', {'sharing': 'global', 'owner': 'nobody', 'perms.read': '*',
													 'perms.write': 'admin,sc_admin,power'})

	def _write(self, replay, not_in_text, last_seen, narrowing, units=None, cov=None, failed=(), now=None,
			   settings=None, nocarrier=None):
		try:
			existing = dict((e['name'], e.get('content', {})) for e in
				self._rest(self._ns('configs/conf-%s?count=0' % CONF)).get('entry', []))
		except urllib.error.HTTPError:
			existing = {}
		had = dict((k, str(v)) for k, v in (existing.get(builder.RETIRED_STANZA) or {}).items()
				   if k.startswith(builder.UNIT_PREFIX))
		# Units first: a tenx_replay.conf stanza tells the search rewrite that its unit exists.
		changed = self._write_units(units or {}, keep=set(builder.unit_macro(st) for st in failed), retired=had,
									now=now, settings=settings)
		changed += self._write_retired(had, dict((k, str(v)) for k, v in self.retired.items()),
									   builder.RETIRED_STANZA in existing)
		cov = cov or {}
		current = self._rest(self._ns('configs/conf-macros/%s' % urllib.parse.quote(MACRO, safe='')))
		definition = current.get('entry', [{}])[0].get('content', {}).get('definition')
		if definition != replay.spl():
			self._rest(self._ns('configs/conf-macros/%s' % urllib.parse.quote(MACRO, safe='')), {'definition': replay.spl()})
			changed.append(MACRO)
		for st, info in replay.per_sourcetype.items():
			seen = cov.get(st)
			want = {'computed_fields': ','.join(info['computed']), 'aliased_fields': ','.join(info['aliased']),
					'masked_at_index_time': ', '.join(info.get('masking', [])),
					'sources': builder.listed_value(seen['sources']) if seen else builder.sources_value(info['sources']),
					'last_seen': str(last_seen[st])}
			if seen:
				want.update(hosts=builder.listed_value(seen['hosts']), indexes=builder.listed_value(seen['indexes']),
							unit='' if st in failed else builder.unit_macro(st))
			have = existing.get(st)
			if have is None:
				self._rest(self._ns('configs/conf-%s' % CONF), dict(want, name=st))
				changed.append(st)
				self.rewrite_changed.append(st)
			elif any(have.get(k, '') != v for k, v in want.items()):
				self._rest(self._ns('configs/conf-%s/%s' % (CONF, urllib.parse.quote(st, safe=''))), want)
				changed.append(st)
				if any(k in want and have.get(k, '') != want[k] for k in ('indexes', 'unit')):
					self.rewrite_changed.append(st)
		if nocarrier is not None:
			moved = self._write_nocarrier(existing.get(builder.NOCARRIER_STANZA), nocarrier)
			changed += moved
			self.rewrite_changed += moved
		want = ','.join(not_in_text)
		have = existing.get(builder.NARROWING_STANZA)
		if not narrowing:
			# Field narrowing off, or no compact event carries tenx_sourcetype: no list, so no
			# field comparison restricts the prefilter.
			if have is not None:
				self._rest(self._ns('configs/conf-%s/%s' % (CONF, urllib.parse.quote(builder.NARROWING_STANZA, safe=''))),
						   method='DELETE')
				changed.append('-' + builder.NARROWING_STANZA)
		elif have is None:
			self._rest(self._ns('configs/conf-%s' % CONF), {'name': builder.NARROWING_STANZA, 'fields_not_in_text': want})
			changed.append(builder.NARROWING_STANZA)
		elif have.get('fields_not_in_text', '') != want:
			self._rest(self._ns('configs/conf-%s/%s' % (CONF, urllib.parse.quote(builder.NARROWING_STANZA, safe=''))),
				{'fields_not_in_text': want})
			changed.append(builder.NARROWING_STANZA)
		for st in existing:
			if st not in replay.per_sourcetype and st not in ('default', builder.NARROWING_STANZA, builder.RETIRED_STANZA,
															  builder.NOCARRIER_STANZA):
				self._rest(self._ns('configs/conf-%s/%s' % (CONF, urllib.parse.quote(st, safe=''))), method='DELETE')
				changed.append('-' + st)
				self.rewrite_changed.append('-' + st)
		return changed

	def _recompile_alerts(self):
		"""
		Dispatches "Recompile Compiled Alerts" when this run changed what the search rewrite chooses
		for an index, so a compiled alert on that index gets the new text now instead of at the
		next scheduled run (every 15 minutes). Returns whether it dispatched.
		"""
		if not (self.apply and self.rewrite_changed):
			return False
		changed, self.rewrite_changed = self.rewrite_changed, []
		try:
			self._rest(self._ns('saved/searches/%s/dispatch' % urllib.parse.quote(RECOMPILE_SEARCH, safe='')), {})
		except Exception as e:
			self.logger.warning("tenxreplay: the replay record changed (%s) but '%s' could not be dispatched (%s); "
								"compiled alerts get the new text at its next scheduled run", changed[:20],
								RECOMPILE_SEARCH, e)
			return False
		self.dispatched += changed
		self.logger.info("tenxreplay: the replay record changed (%s); dispatched '%s'", changed[:20], RECOMPILE_SEARCH)
		return True

	def _covered(self):
		try:
			entries = self._rest(self._ns('configs/conf-%s?count=0' % CONF)).get('entry', [])
		except urllib.error.HTTPError:
			return {}
		return dict((e['name'], dict((k, str(e.get('content', {}).get(k, '') or ''))
									 for k in ('sources', 'hosts', 'indexes', 'last_seen')))
					for e in entries if e['name'] not in ('default', builder.NARROWING_STANZA, builder.RETIRED_STANZA,
														  builder.NOCARRIER_STANZA))

	def generate(self):
		self.rewrite_changed, self.dispatched = [], []
		earliest, latest = self._time_range()
		if self.only_new:
			try:
				rows = self._present(earliest, latest)
				seen = [(r[0], r[1]) for r in rows]
				covered = self._covered()
				new = builder.uncovered(seen, covered) + builder.uncovered_values(rows, covered)
				if self.apply:
					self._check_indexes(rows)
					self._recompile_alerts()
			except Exception as e:
				self.logger.exception("tenxreplay: the coverage check failed")
				self.error_exit(e, "tenxreplay: could not check what the replay covers (%s); nothing was written." % e)
				return
			if not new:
				yield {'sourcetype': '', 'written': 'indexes recorded' if self.dispatched else 'no change',
					   'checked': len(seen), 'recompile_dispatched': 'yes' if self.dispatched else 'no',
					   'warnings': ['every original sourcetype and source in this time range is covered']}
				return
			self.logger.info("tenxreplay: not covered %s; rebuilding over %s", new[:20], self.lookback)
			earliest, latest = self.lookback, 'now'
		try:
			config = self._config()
			settings = builder.replay_settings(config)
			now = time.time()
			covered, expired = builder.expire_covered(self._covered(), now, settings['replay_expire_days'])
			if expired:
				self.logger.warning("tenxreplay: no compact event carried %s for more than replay_expire_days = %d days; "
									"their replay is removed", builder._listed(expired), settings['replay_expire_days'])
			rows = self._present(earliest, latest)
			# A sourcetype the replay does not cover yet has its sources, hosts and indexes read over
			# all time, so its unit (txf(<sourcetype>), the search rewrite) has the source:: and
			# host:: rules of its older events too; afterwards each rebuild adds what it sees.
			first = sorted(set(r[0] for r in rows if builder.usable_sourcetype(r[0])) - set(covered))
			if first and str(earliest) not in ('0', ''):
				rows += [r[:3] + (0,) + r[4:] for r in self._present('0', 'now', first)]
			present = [tuple(p) + (0,) * (4 - len(p)) for p in
					   builder.keep_covered([r[:4] for r in rows], covered)]
			cov = builder.coverage(rows, covered)
			# indexes holding carrier events: seen now, or recorded for a sourcetype (a list that is *
			# names none, and that sourcetype is chained for every index anyway)
			carrier_ix = set(r[4] for r in rows if len(r) > 4 and r[4])
			for value in cov.values():
				if value['indexes'] is not builder.ALL:
					carrier_ix |= set(value['indexes'])
			nocarrier = builder.nocarrier_value(self._compact_indexes(earliest, latest), carrier_ix)
			stanzas = self._stanzas()
			lookups = self._lookup_fields()
			keep_all, keep, keep_by_st = self._indexed_fields(earliest, latest)
			not_raw = self._indexed_value_false()
			transforms = self._transforms()
		except Exception as e:
			self.logger.exception("tenxreplay: reading the configuration failed")
			self.error_exit(e, "tenxreplay: could not read the instance's configuration (%s); nothing was written." % e)
			return
		last_seen = builder.last_seen_of(present, covered, now)
		replay = builder.build_capped(stanzas, present, lookups, keep, settings, last_seen, transforms=transforms,
									  keep_by_sourcetype=keep_by_st)
		units, failed = {}, set()
		if replay.per_sourcetype:
			# Check every rule against this Splunk before writing, so one rule it cannot run
			# is left out (and named in the log) instead of failing every `tx` search.
			try:
				bad_lookups = self._lookup_problems()
				replay = builder.build_capped(stanzas, present, lookups, keep, settings, last_seen,
											  bad_lookups=bad_lookups, transforms=transforms, keep_by_sourcetype=keep_by_st)
				units = builder.build_units(stanzas, cov, replay.per_sourcetype, lookups, keep, settings,
											bad_lookups=bad_lookups, transforms=transforms, keep_by_sourcetype=keep_by_st)
				rejected = builder.failing_rules(builder.all_rules(replay, units), self._dry_run)
				if rejected:
					replay = builder.build_capped(stanzas, present, lookups, keep, settings, last_seen,
												  rejected=rejected, bad_lookups=bad_lookups, transforms=transforms,
												  keep_by_sourcetype=keep_by_st)
					units = builder.build_units(stanzas, cov, replay.per_sourcetype, lookups, keep, settings,
												rejected=rejected, bad_lookups=bad_lookups, transforms=transforms,
												keep_by_sourcetype=keep_by_st)
				error = self._dry_run(builder.macro_dry_run(replay))
				bad_units = {} if error else builder.failing_units(units, self._dry_run, settings['replay_max_macro_chars'] or 262144)
			except Exception as e:
				self.logger.exception("tenxreplay: checking the rules against Splunk failed")
				self.error_exit(e, "tenxreplay: could not check the rules against Splunk (%s); nothing was written." % e)
				return
			# A unit that does not run is left out alone: the others, the full macro and every
			# stanza (with its sources, hosts and indexes) are still written. Its stanza says
			# `unit =` (blank), so the search rewrite runs `tenx-replay` for a search that needs
			# it (tenx_replay_builder.rewrite_replay), and its previous unit, if any, is kept.
			for st, why in sorted(bad_units.items()):
				self.logger.warning("tenxreplay: the unit of %s does not run (%s); it is not written, and the search "
									"rewrite runs %s where that sourcetype is needed", st, why, MACRO)
				units.pop(st, None)
				failed.add(st)
			if not error:
				self.logger.info("tenxreplay: %d rules checked against Splunk, %d refused, %d lookups not runnable by "
								 "every user; the generated macro and %d units ran cleanly on made-up events",
								 len(builder.all_rules(replay, units)), len(rejected), len(bad_lookups), len(units))
			if error:
				self.logger.error("tenxreplay: the generated macro does not run: %s", error)
				self.error_exit(RuntimeError(error), "tenxreplay: the generated macro does not run (%s); the "
								"previous macros are kept and nothing was written." % error)
				return
		if expired:
			replay.warnings.insert(0, 'expired after replay_expire_days = %d: %s' % (settings['replay_expire_days'], builder._listed(expired)))
		for note in replay.warnings + [w for st in sorted(units) for w in units[st].warnings if 'replays nothing' in w]:
			self.logger.warning("tenxreplay: %s", note)
		for st, info in sorted(replay.per_sourcetype.items()):
			if info.get('masking'):
				self.logger.warning("tenxreplay: original sourcetype %s is masked at index time (%s); its compact events "
									"hold those values unmasked", st, ', '.join(info['masking']))
		not_in_text = builder.fields_not_in_text(stanzas, transforms, lookups, keep_all, not_raw)
		written = []
		if self.apply:
			try:
				written = self._write(replay, not_in_text, last_seen, builder.narrowing_wanted(config, replay), units, cov,
									  failed, now, settings, nocarrier)
			except Exception as e:
				self.logger.exception("tenxreplay: writing the macro failed")
				self._recompile_alerts()
				self.error_exit(e, "tenxreplay: could not write the %s macro (%s)." % (MACRO, e))
				return
			self._recompile_alerts()
		self.logger.info("tenxreplay: %d sourcetypes, %d steps, written %s, warnings %s",
			len(replay.per_sourcetype), len(replay.steps), written, replay.warnings)
		events = {}
		for st, _, _, count in present:
			events[st] = events.get(st, 0) + count
		for st, info in sorted(replay.per_sourcetype.items()):
			row = {
				'sourcetype': st,
				'compact_events': events.get(st, 0),
				'stanzas': info['stanzas'],
				'aliases': info['aliases'],
				'calculated_fields': info['calculated'],
				'lookups': info['lookups'],
				'computed_fields': info['computed'],
				'masked_at_index_time': info.get('masking', []),
				'warnings': info['warnings'] + replay.warnings,
				'kept_indexed_fields': sorted(set(keep) | set(keep_by_st.get(st, ()))),
				'fields_not_in_text': len(not_in_text),
				'macro_chars': len(replay.spl()),
				'unit': builder.unit_macro(st),
				'unit_chars': len(units[st].spl()) if st in units else 0,
				'txf': 'txf(%s)' % st,
				'indexes': builder.listed_value(cov.get(st, {}).get('indexes', set())),
				'written': 'yes' if written else ('no change' if self.apply else 'dry run'),
				'recompile_dispatched': 'yes' if self.dispatched else 'no',
			}
			if not self.apply:
				row['definition'] = replay.spl()
				row['unit_definition'] = units[st].spl() if st in units else ''
			yield row
		if not replay.per_sourcetype:
			yield {'sourcetype': '', 'compact_events': 0,
				   'warnings': ['no compact event in this time range carries %s' % builder.CARRIER_FIELD],
				   'written': 'yes' if written else 'no change', 'recompile_dispatched': 'yes' if self.dispatched else 'no'}

dispatch(TenxReplayCommand, sys.argv, sys.stdin, sys.stdout, __name__)
