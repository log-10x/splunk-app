"""
Shared pytest setup for the tenx-for-splunk test suite.

Puts the app's bin/ on sys.path and installs a tiny offline stub for splunklib.

Why the stub: the app bundles splunklib for Splunk's Python 3.7 under tenx-for-splunk/lib/,
and the compiler dependency chain (tenx_util) imports `splunklib.client`/`splunklib.six` at
module load time. That vendored copy doesn't import under a modern interpreter, and nothing
in the code paths under test actually calls into Splunk (tests inject a local search-manager
double), so a minimal stub is enough to let the modules import offline. The stub is installed
into sys.modules before any test imports the app, and only exposes the two symbols tenx_util
references.

The bundled parsimonious is likewise 3.7-era; tests rely on a modern parsimonious from
requirements-test.txt instead (the grammar source is identical and parses under both).
"""
import os
import sys
import types


def _install_splunklib_stub():
	if 'splunklib' in sys.modules:
		return

	splunklib = types.ModuleType('splunklib')

	six = types.ModuleType('splunklib.six')
	six.string_types = (str,)
	six.iterkeys = lambda d: iter(d.keys())
	six.itervalues = lambda d: iter(d.values())
	six.iteritems = lambda d: iter(d.items())

	client = types.ModuleType('splunklib.client')

	def _connect(*args, **kwargs):
		raise RuntimeError("splunklib.client.connect is stubbed offline in tests")

	client.connect = _connect

	splunklib.six = six
	splunklib.client = client

	sys.modules['splunklib'] = splunklib
	sys.modules['splunklib.six'] = six
	sys.modules['splunklib.client'] = client


_install_splunklib_stub()

_BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'bin'))
if _BIN not in sys.path:
	sys.path.insert(0, _BIN)

# Path to the demo template CSV, used by the compiler tests as a real template store.
DEMO_TEMPLATES_CSV = os.path.abspath(
	os.path.join(os.path.dirname(__file__), '..', 'demo', 'tenx_templates_demo.csv'))
