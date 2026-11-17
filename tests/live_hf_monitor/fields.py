#!/usr/bin/env python3
"""
fields.py <work folder> <search head address> <label> <key fields> <raw search> <compact search> [earliest] [latest]
          [allowed differences, comma-separated]

Field parity, event by event: each event of the two searches is keyed by the key fields (_rawmd5 is md5 of the
text, computed by both searches), and every other field is compared, a multivalue field as a sorted list. Left out:
the fields Splunk computes from where the text sits or from the index (linecount, punct, date_*, positions), and
the app's own markers. Prints one PASS or FAIL line (to <work folder>/res/summary.txt too): PASS when every event
of each side is matched and every field that differs is in the allowed list. The details go to
res/fields_<label>.json. The login is read from <work folder>/secret/admin.pw and never printed.
"""
import base64
import collections
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request

W, HOST, LABEL, KEYS, RAW, COMPACT = sys.argv[1:7]
ET = sys.argv[7] if len(sys.argv) > 7 else '0'
LT = sys.argv[8] if len(sys.argv) > 8 else '+10y'
ALLOWED = set(x for x in (sys.argv[9] if len(sys.argv) > 9 else '').split(',') if x)
SKIP = {'_raw', '_bkt', '_cd', '_si', '_serial', '_indextime', '_sourcetype', '_eventtype_color', '_kv', 'index',
	'splunk_server', 'splunk_server_group', 'linecount', 'punct', 'timestartpos', 'timeendpos', 'date_hour', 'date_mday',
	'date_minute', 'date_month', 'date_second', 'date_wday', 'date_year', 'date_zone', 'eventtype_color', 'sourcetype',
	'tenx_sourcetype', 'tenx_compact_st', 'tenx_mapped', 'tenx_unmapped', 'tenx_hash', 'tenx_vars', 'tenx_var_0',
	'tenx_compact_raw', 'tenx_log_parts', 'tenx_rst', 'tenx_gox', 'tenx_gow', 'tenx_expand_refused', '_time_raw',
	'tenx_time'}
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
with open(os.path.join(W, 'secret', 'admin.pw')) as f:
	AUTH = 'Basic ' + base64.b64encode(('admin:%s' % f.read().strip()).encode()).decode()


def export(spl):
	data = urllib.parse.urlencode({'search': spl + ' | fields *', 'output_mode': 'json', 'earliest_time': ET,
		'latest_time': LT, 'count': 0}).encode()
	req = urllib.request.Request('https://%s:8089/servicesNS/admin/tenx-for-splunk/search/jobs/export' % HOST, data=data)
	req.add_header('Authorization', AUTH)
	rows, msgs = [], []
	with urllib.request.urlopen(req, context=CTX, timeout=7200) as res:
		for line in res:
			if line.strip():
				o = json.loads(line)
				if o.get('result') is not None and not o.get('preview'):
					rows.append(o['result'])
				msgs += [m.get('text', '')[:200] for m in (o.get('messages') or []) if m.get('type') in ('ERROR', 'FATAL')]
	return rows, msgs


def by_key(rows, keys):
	out, dup = {}, 0
	for r in rows:
		k = tuple(str(r.get(x)) for x in keys)
		dup += k in out
		out[k] = r
	return out, dup


def norm(v, name=''):
	if name == '_subsecond':
		# Splunk prints the same fraction with or without its trailing zeros (.10639, .106390)
		try:
			return (round(float(v), 9),)
		except (TypeError, ValueError):
			pass
	return tuple(sorted(v)) if isinstance(v, list) else (v,)


keys = KEYS.split(',')
raw, raw_msgs = export(RAW)
compact, compact_msgs = export(COMPACT)
ri, rdup = by_key(raw, keys)
ci, cdup = by_key(compact, keys)
common = [k for k in ri if k in ci]
fields = sorted((set().union(*[ri[k].keys() for k in common]) | set().union(*[ci[k].keys() for k in common]))
	- SKIP - set(keys)) if common else []
diff, only_raw, only_compact, example = collections.Counter(), collections.Counter(), collections.Counter(), {}
for k in common:
	a, b = ri[k], ci[k]
	for name in fields:
		va, vb = a.get(name), b.get(name)
		if va is None and vb is None:
			continue
		if va is None:
			only_compact[name] += 1
		elif vb is None:
			only_raw[name] += 1
		elif norm(va, name) == norm(vb, name):
			continue
		else:
			diff[name] += 1
		example.setdefault(name, [str(va)[:120], str(vb)[:120]])
bad = sorted(set(diff) | set(only_raw) | set(only_compact))
out = {'label': LABEL, 'raw_events': len(raw), 'compact_events': len(compact), 'raw_dup_keys': rdup,
	'compact_dup_keys': cdup, 'matched': len(common), 'fields_compared': len(fields),
	'fields_equal_on_every_event': len(fields) - len(bad), 'allowed': sorted(ALLOWED),
	'differ': {n: {'values_differ': diff[n], 'only_raw': only_raw[n], 'only_compact': only_compact[n]} for n in bad},
	'messages': sorted(set(raw_msgs + compact_msgs))[:5]}
with open(os.path.join(W, 'res', 'fields_%s.json' % LABEL), 'w') as f:
	json.dump(dict(out, examples={n: example[n] for n in bad}), f, indent=1)
passed = (len(raw) > 0 and len(raw) == len(compact) and len(ri) == len(ci) == len(common) and rdup == cdup
	and set(bad) <= ALLOWED and not out['messages'])
line = '%s fields %s: %d raw, %d compact, %d matched; %d of %d fields equal on every event; differ: %s' % (
	'PASS' if passed else 'FAIL', LABEL, len(raw), len(compact), len(common), out['fields_equal_on_every_event'],
	len(fields), ', '.join('%s (%d)' % (n, diff[n] + only_raw[n] + only_compact[n]) for n in bad) or 'none')
print(line)
with open(os.path.join(W, 'res', 'summary.txt'), 'a') as f:
	f.write(line + '\n')
