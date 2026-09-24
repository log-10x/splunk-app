"""
Tenx Recompile Command
======================

    | tenxrecompile

Recompiles every alert compiled through the app, for every user, so each picks up templates
that appeared after it was compiled. Saved searches written with `| tenxsearch` are left as
they are. The "Recompile Compiled Alerts" saved search runs it on a
schedule; it can also be run by hand. Returns one row summarising the pass. See
tenx_alert_recompile.py.

Logging
-------
Logs to: $SPLUNK_HOME/var/log/splunk/tenx_recompile_command.log
"""

import os
import sys
import logging

from splunk.clilib.bundle_paths import get_base_path

APP_NAME = 'tenx-for-splunk'
apphome = os.path.join(get_base_path(), APP_NAME)
sys.path.append(os.path.join(apphome, 'bin'))
sys.path.append(os.path.join(apphome, 'lib'))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration

import tenx_util
import tenx_search_manager
import tenx_search_builder
import tenx_alert_compiler
import tenx_alert_recompile

tenx_util.setup_logger('tenx_recompile_command', logging.INFO)


@Configuration()
class TenxRecompileCommand(GeneratingCommand):
	"""Runs the recompile pass over every user's compiled alerts and reports what it did."""

	def generate(self):
		server_uri = self._metadata.searchinfo.splunkd_uri
		token = self._metadata.searchinfo.session_key

		tenx_config = tenx_util.get_tenx_config(server_uri=server_uri, token=token)

		if not tenx_config.get(tenx_util.CONFIG_LOADED, True):
			self.write_error("10x: the app's configuration could not be read, so no alert was recompiled. "
				"See tenx_recompile_command.log.")
			return

		server_connection = tenx_util.ServerConnection(
			server_uri=server_uri,
			user=self._metadata.searchinfo.username,
			auth={'session_key': token})

		search_manager = tenx_search_manager.TenxSearchManager(
			server_connection=server_connection,
			tenx_config=tenx_config,
			app=self._metadata.searchinfo.app)

		compiler = tenx_alert_compiler.TenxAlertCompiler(tenx_search_builder.TenxSearchBuilder(
			server_connection=server_connection,
			tenx_config=tenx_config,
			search_manager=search_manager))

		summary = tenx_alert_recompile.recompile_all(
			server_connection, tenx_alert_recompile.ALL_OWNERS, compiler, migrate_legacy=False)

		self.logger.info("Recompile pass - {}".format(summary))

		row = dict((key, value) for key, value in summary.items() if key != 'updated')
		row['updated'] = ', '.join(summary['updated'])

		yield row


dispatch(TenxRecompileCommand, sys.argv, sys.stdin, sys.stdout, __name__)
