"""
Shared pytest setup for the tenx-for-splunk test suite.

Puts the app's bin/ on sys.path and installs a tiny offline stub for splunklib.

Why the stub: the compiler dependency chain (tenx_util) imports `splunklib.client` at module
load time, and nothing in the code paths under test actually calls into Splunk (tests inject
a local search-manager double). A minimal stub keeps these tests offline and independent of
which SDK version is vendored. It is installed into sys.modules before any test imports the
app and exposes only the symbol tenx_util references.

An earlier version of this note said the vendored splunklib and parsimonious do not import
under a modern interpreter. That was checked and is not true: both import under Python 3.13,
and the app now vendors Splunk SDK 3.0.1. The stub is here to keep the unit tests off the
network and off the SDK, not because the SDK cannot be loaded. What the stub cannot do is
tell you whether the real SDK works; tests/live_endpoints.py against a running Splunk is
what does that.

Tests still rely on a modern parsimonious from requirements-test.txt rather than the bundled
one, so a grammar change is caught against the library the app will meet on a current
interpreter.
"""
import os
import sys
import types


def _install_splunklib_stub():
	if 'splunklib' in sys.modules:
		return

	splunklib = types.ModuleType('splunklib')

	client = types.ModuleType('splunklib.client')

	def _connect(*args, **kwargs):
		raise RuntimeError("splunklib.client.connect is stubbed offline in tests")

	client.connect = _connect

	splunklib.client = client

	sys.modules['splunklib'] = splunklib
	sys.modules['splunklib.client'] = client


def _install_splunk_platform_stub():
	"""
	Offline stubs for the Splunk-runtime modules the persistent REST handler imports at load
	time (splunk.clilib, splunk.persistconn) plus a throwaway SPLUNK_HOME so its
	module-level setup_logger() can create its log file. Lets tenx_alert_handler import under a
	plain interpreter so its pure orchestration (write ordering, failure handling) is testable.
	"""
	if 'splunk' in sys.modules:
		return

	splunk = types.ModuleType('splunk')
	clilib = types.ModuleType('splunk.clilib')
	bundle_paths = types.ModuleType('splunk.clilib.bundle_paths')
	bundle_paths.get_base_path = lambda: '/tmp/tenx_test_apphome'
	persistconn = types.ModuleType('splunk.persistconn')
	application = types.ModuleType('splunk.persistconn.application')

	class _PersistentServerConnectionApplication(object):
		def __init__(self, *args, **kwargs):
			pass

	application.PersistentServerConnectionApplication = _PersistentServerConnectionApplication
	clilib.bundle_paths = bundle_paths
	splunk.clilib = clilib
	persistconn.application = application
	splunk.persistconn = persistconn

	sys.modules.update({
		'splunk': splunk, 'splunk.clilib': clilib, 'splunk.clilib.bundle_paths': bundle_paths,
		'splunk.persistconn': persistconn, 'splunk.persistconn.application': application,
	})

	# setup_logger() writes to $SPLUNK_HOME/var/log/splunk/<name>.log at import time.
	home = '/tmp/tenx_test_splunk_home'
	os.makedirs(os.path.join(home, 'var', 'log', 'splunk'), exist_ok=True)
	os.environ.setdefault('SPLUNK_HOME', home)


_install_splunklib_stub()
_install_splunk_platform_stub()

_BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tenx-for-splunk', 'bin'))
if _BIN not in sys.path:
	sys.path.insert(0, _BIN)

# Path to the demo template CSV, used by the compiler tests as a real template store.
DEMO_TEMPLATES_CSV = os.path.abspath(
	os.path.join(os.path.dirname(__file__), '..', 'demo', 'tenx_templates_demo.csv'))
