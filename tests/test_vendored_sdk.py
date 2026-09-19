"""
The vendored Splunk SDK has to be able to find its own version.

Splunk SDK 3.x calls importlib.metadata.version("splunk-sdk") inside binding.py when it
builds a request. A pip install satisfies that from the package metadata pip writes; a
copy of the package into lib/ does not, and the call raises PackageNotFoundError.

That is not a cosmetic failure. It is raised on the first REST call the app makes, so
every use of splunklib.client dies with it: on a live Splunk 10.4.3 the KV store alert
fell back to its built-in defaults, posted to a collection name that does not exist and
logged HTTP 404 for every one of the 2,991 templates, while the unit suite stayed green
because it stubs splunklib.

So the wheel's .dist-info directory is vendored beside the package, and this pins it.
"""

import importlib.metadata
import os
import sys

import pytest

LIB = os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'lib')


def test_the_metadata_directory_is_vendored():
	entries = os.listdir(LIB)
	dist_info = [name for name in entries if name.endswith('.dist-info')]

	assert dist_info, (
		'no .dist-info beside the vendored splunklib in %s. Splunk SDK 3.x asks '
		'importlib.metadata for its own version and cannot answer without it.' % LIB)


def test_the_version_resolves_from_the_vendored_copy():
	# Resolve against lib/ alone, so a splunk-sdk that happens to be pip installed in the
	# environment running the tests cannot make this pass.
	found = importlib.metadata.distributions(path=[LIB])
	names = {dist.metadata['Name'] for dist in found if dist.metadata['Name']}

	assert 'splunk-sdk' in names, (
		'importlib.metadata cannot see splunk-sdk under %s, so binding.py will raise '
		'PackageNotFoundError on the first REST call. Found: %s' % (LIB, sorted(names)))


def test_the_version_matches_the_package_it_sits_beside():
	found = {d.metadata['Name']: d.version for d in importlib.metadata.distributions(path=[LIB])}
	version = found.get('splunk-sdk')

	assert version is not None
	# AppInspect rejects anything before 2.0.2.
	major = int(version.split('.')[0])
	assert major >= 2, 'vendored SDK %s is older than the 2.0.2 AppInspect requires' % version
