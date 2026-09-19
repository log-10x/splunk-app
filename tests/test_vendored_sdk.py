"""
The vendored Splunk SDK has to be one the app can actually run.

Two separate traps, both found the hard way against a live Splunk 10.4.3, and both
invisible to the rest of this suite because it stubs splunklib.

1. **Package metadata.** Splunk SDK 3.x calls `importlib.metadata.version("splunk-sdk")`
   inside `binding.py` when it builds a request. A pip install answers that from the
   metadata pip writes; a copy of the package into `lib/`, which is how a Splunk app
   ships it, does not, and the call raises `PackageNotFoundError` on the first REST call.
   Every use of `splunklib.client` then dies. On the live instance the KV store alert
   could not read the app's own configuration, silently fell back to its built-in
   defaults, posted to a collection name that does not exist and logged HTTP 404 for all
   2,991 templates while the unit suite stayed green.

2. **The Python floor.** SDK 3.0.1 declares `Requires-Python: >=3.13`. This app is listed
   for Splunk 9.4 through 10.4, and 9.4 does not ship a 3.13 interpreter, so 3.x cannot be
   the vendored copy while 9.4 is claimed. The 2.x line declares no floor, carries its
   version in the package itself rather than in metadata, and imports cleanly on 3.13.

So these tests do not pin a version. They pin the two rules: the SDK is new enough for
AppInspect, and whatever mechanism it uses to find its own version works from `lib/`.
"""

import os
import re

import pytest

LIB = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'lib'))
SPLUNKLIB = os.path.join(LIB, 'splunklib')

# AppInspect rejects anything older.
MINIMUM = (2, 0, 2)


def vendored_version():
	"""The version the SDK reports about itself, from the package."""
	init = os.path.join(SPLUNKLIB, '__init__.py')
	text = open(init, encoding='utf-8').read()
	match = re.search(r'__version_info__\s*=\s*\(([^)]*)\)', text)

	if not match:
		return None

	return tuple(int(part.strip()) for part in match.group(1).split(',') if part.strip())


def sdk_asks_importlib_for_its_version():
	"""True when the vendored SDK resolves its own version through package metadata."""
	for root, _dirs, names in os.walk(SPLUNKLIB):
		for name in names:
			if not name.endswith('.py'):
				continue

			body = open(os.path.join(root, name), encoding='utf-8', errors='replace').read()

			if 'importlib.metadata' in body and 'splunk-sdk' in body:
				return True

	return False


def test_the_sdk_is_vendored():
	assert os.path.isdir(SPLUNKLIB), 'no splunklib under %s' % LIB


def test_the_version_is_new_enough_for_appinspect():
	version = vendored_version()

	if version is None and sdk_asks_importlib_for_its_version():
		pytest.skip('version lives in package metadata; the next test covers that case')

	assert version is not None, (
		'the vendored SDK reports no __version_info__, and AppInspect reads its version '
		'from there. A version it cannot find is a version it will reject.')
	assert version >= MINIMUM, (
		'vendored SDK %s is older than the %s AppInspect requires'
		% ('.'.join(map(str, version)), '.'.join(map(str, MINIMUM))))


def test_an_sdk_that_needs_metadata_ships_it():
	"""
	The rule, not the current state. If a future upgrade brings back an SDK that resolves
	its version through importlib.metadata, the wheel's .dist-info has to be vendored
	beside it or every REST call raises PackageNotFoundError at runtime.
	"""
	if not sdk_asks_importlib_for_its_version():
		return

	dist_info = [name for name in os.listdir(LIB) if name.endswith('.dist-info')]

	assert dist_info, (
		'the vendored SDK asks importlib.metadata for "splunk-sdk" but no .dist-info is '
		'vendored in %s, so the first REST call will raise PackageNotFoundError' % LIB)

	import importlib.metadata

	names = {d.metadata['Name'] for d in importlib.metadata.distributions(path=[LIB])}

	assert 'splunk-sdk' in names, (
		'a .dist-info is present but importlib.metadata cannot resolve splunk-sdk from '
		'%s alone. Found: %s' % (LIB, sorted(names)))


def test_the_python_floor_does_not_exclude_the_versions_this_app_claims():
	"""
	The app declares support for Splunk 9.4 through 10.4. 9.4 does not ship Python 3.13,
	so an SDK requiring it cannot be vendored while 9.4 is claimed.
	"""
	floors = []

	for name in os.listdir(LIB):
		if not name.endswith('.dist-info'):
			continue

		metadata = os.path.join(LIB, name, 'METADATA')

		if not os.path.exists(metadata):
			continue

		for line in open(metadata, encoding='utf-8', errors='replace'):
			if line.lower().startswith('requires-python:'):
				floors.append((name, line.split(':', 1)[1].strip()))

	for name, floor in floors:
		match = re.search(r'>=\s*3\.(\d+)', floor)

		if match and int(match.group(1)) >= 13:
			pytest.fail(
				'%s declares %r. Splunk 9.4 has no 3.13 interpreter, so either the SDK '
				'goes back to the 2.x line or the listing stops claiming 9.4.'
				% (name, floor))
