#!/usr/bin/env python3
"""
Live check of what a search reads back from the `tx` and `tenxsearch` commands' way of writing
events: a custom generating command, over the chunked protocol, through this app's vendored
splunklib as shipped. Splunk Enterprise 10.4.3 drops a CR before LF and keeps every other CR; the
app README states it as a limit of the two commands (README_SENTENCE in
tests/support/tx_cr_probe/bin/tenx_cr_cases.py). This pins that behaviour, so a Splunk or SDK
change shows up here first, in either direction.

It installs the test-only probe app (tests/support/tx_cr_probe, never in the app package), runs
its command, compares each value read back with the measured one, and removes the probe app. The
instance needs tenx-for-splunk installed, whose splunklib the probe imports.

    python3 tests/live_tx_command_cr.py \
        --url https://localhost:8089 --user admin --password '...' --container splunk

--container copies the probe package into that Docker container; --server-path writes it to a
path on this host, for a run on the Splunk host itself. Exits non-zero on any failed check, and
prints one line per check either way.
"""

import argparse
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE_DIR = os.path.join(HERE, 'support', 'tx_cr_probe')
PROBE_APP = 'tenx_cr_probe'
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(PROBE_DIR, 'bin'))

from live_endpoints import CheckFailed, Splunk, json_or_fail, results_of, wait_for_job  # noqa: E402
from tenx_cr_cases import CASES  # noqa: E402


def probe_package():
	"""The probe app as a .tar.gz, its folder named PROBE_APP; compiled files left out."""
	data = io.BytesIO()
	with tarfile.open(fileobj=data, mode='w:gz') as tar:
		for root, dirs, files in os.walk(PROBE_DIR):
			dirs[:] = [d for d in dirs if d != '__pycache__']
			for name in sorted(files):
				if name.endswith('.pyc'):
					continue
				path = os.path.join(root, name)
				tar.add(path, arcname=os.path.join(PROBE_APP, os.path.relpath(path, PROBE_DIR)))
	return data.getvalue()


def place_package(container, server_path):
	"""Puts the probe package where splunkd can read it; returns that path."""
	package = probe_package()
	if container:
		target = '/tmp/%s.tar.gz' % PROBE_APP
		with tempfile.NamedTemporaryFile(suffix='.tar.gz') as local:
			local.write(package)
			local.flush()
			subprocess.run(['docker', 'cp', local.name, '%s:%s' % (container, target)], check=True)
		subprocess.run(['docker', 'exec', '-u', 'root', container, 'chmod', '644', target], check=True)
		return target
	with open(server_path, 'wb') as out:
		out.write(package)
	os.chmod(server_path, 0o644)
	return server_path


def install(splunk, path):
	status, body = splunk.call('%s/services/apps/local' % splunk.url,
	                           {'name': path, 'filename': 'true', 'update': 'true'}, absolute=True)
	if status not in (200, 201):
		raise CheckFailed('installing the probe app returned %s: %s' % (status, body[:300]))
	# A newly installed app's commands.conf is read on the next search; the reload makes it explicit.
	splunk.call('%s/servicesNS/nobody/%s/configs/conf-commands/_reload' % (splunk.url, PROBE_APP), absolute=True)
	return 'installed from %s (HTTP %s)' % (path, status)


def run_probe(splunk):
	status, body = splunk.call('%s/servicesNS/%s/%s/search/jobs?output_mode=json' % (splunk.url, splunk.owner, PROBE_APP),
	                           {'search': '| tenxcrprobe', 'earliest_time': '0', 'latest_time': 'now'}, absolute=True)
	if status not in (200, 201):
		raise CheckFailed('dispatching | tenxcrprobe returned %s: %s' % (status, body[:300]))
	sid = json_or_fail(body, 'dispatch')['sid']
	job = wait_for_job(splunk, sid)
	messages = [m for m in (job.get('messages') or []) if isinstance(m, dict) and m.get('type') in ('FATAL', 'ERROR')]
	if messages:
		raise CheckFailed('| tenxcrprobe: %s' % messages[:2])
	return {row.get('case'): row.get('_raw') for row in results_of(splunk, sid)}


def remove(splunk):
	status, body = splunk.call('%s/services/apps/local/%s' % (splunk.url, urllib.parse.quote(PROBE_APP)),
	                           method='DELETE', absolute=True)
	if status not in (200, 201):
		raise CheckFailed('removing the probe app returned %s: %s' % (status, body[:300]))
	return 'removed (HTTP %s)' % status


def main():
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('--url', default='https://localhost:8089')
	parser.add_argument('--user', default='admin')
	parser.add_argument('--password')
	parser.add_argument('--password-file', help='read the password from this file, to keep it out of the process list')
	parser.add_argument('--owner', default='admin')
	where = parser.add_mutually_exclusive_group(required=True)
	where.add_argument('--container', help='the Docker container that runs splunkd')
	where.add_argument('--server-path', help='a path on this host, which is the Splunk host, to write the package to')
	parser.add_argument('--keep', action='store_true', help='leave the probe app installed')
	args = parser.parse_args()
	if args.password_file:
		with open(args.password_file) as f:
			args.password = f.read().strip()
	if not args.password:
		parser.error('give --password or --password-file')

	splunk = Splunk(args.url, args.user, args.password, PROBE_APP, args.owner)
	failed, checks = 0, 0

	def report(label, ok, detail):
		nonlocal failed, checks
		checks += 1
		failed += 0 if ok else 1
		print('  %s  %-14s %s' % ('PASS' if ok else 'FAIL', label, detail))

	try:
		report('install', True, install(splunk, place_package(args.container, args.server_path)))
		got = run_probe(splunk)
		for case, written, read_back in CASES:
			value = got.get(case)
			report(case, value == read_back, 'wrote %s, read %s, measured %s' % (
				json.dumps(written), json.dumps(value), json.dumps(read_back)))
	except (CheckFailed, subprocess.CalledProcessError, OSError) as error:
		report('probe', False, error)
	finally:
		if not args.keep:
			try:
				report('remove', True, remove(splunk))
			except CheckFailed as error:
				report('remove', False, error)

	print('%d of %d checks passed' % (checks - failed, checks))
	return 1 if failed else 0


if __name__ == '__main__':
	sys.exit(main())
