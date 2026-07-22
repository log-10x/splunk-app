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


def _install_splunk_platform_stub():
	"""
	Offline stubs for the Splunk-runtime modules the persistent REST handler imports at load
	time (future, splunk.clilib, splunk.persistconn) plus a throwaway SPLUNK_HOME so its
	module-level setup_logger() can create its log file. Lets tenx_alert_handler import under a
	plain interpreter so its pure orchestration (write ordering, failure handling) is testable.
	"""
	if 'splunk' in sys.modules:
		return

	future = types.ModuleType('future')
	standard_library = types.ModuleType('future.standard_library')
	standard_library.install_aliases = lambda: None
	future.standard_library = standard_library
	sys.modules['future'] = future
	sys.modules['future.standard_library'] = standard_library

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
