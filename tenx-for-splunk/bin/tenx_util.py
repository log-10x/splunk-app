"""
Tenx Utility Module
==================

This module provides common utility functions and classes used throughout the
tenx-for-splunk Splunk app. It includes:

- Configuration loading from tenx_config.conf
- Logging setup for Splunk app scripts
- REST API client for Splunk endpoints
- URL manipulation helpers
- SPL macro generation helpers

Classes
-------
ServerConnection
    Authenticated REST client for Splunk's management API.

Functions
---------
get_tenx_config(service=None, server_uri=None, token=None)
    Load app configuration from tenx_config.conf with defaults fallback.

setup_logger(logger_name, level)
    Configure rotating file handler for Splunk logging.

get_app_service(server_uri, token)
    Create splunklib service connection.

splunk_inflate_macro(debug=False)
    Return SPL string for tenx-inflate macro call.

Configuration
-------------
Configuration is loaded from default/tenx_config.conf and merged with defaults
from tenx_consts.DEFAULT_CONFIG. The function also scans props.conf to discover
which sourcetypes/sources use 10x field extraction.

Logging
-------
Logs are written to $SPLUNK_HOME/var/log/splunk/<logger_name>.log with:
- Rotating files (max 25MB, 5 backups)
- Format: timestamp level message

See Also
--------
- tenx_consts.py: Default configuration values
- tenx_config.conf: App configuration file
"""

import logging

logger = logging.getLogger(__name__)

import os
import json
import time
import logging.handlers
import urllib.request
import urllib.parse

from splunklib import client, six

import tenx_consts


# ============================================================================
# Splunk Service Connection
# ============================================================================


def get_app_service(server_uri, token):
	"""
	Returns a new splunk service for the provided uri and token.

	Basically wraps a call to client.connect
	"""
	host = urllib.parse.urlparse(server_uri)

	return client.connect(
		host=host.hostname,
		port=host.port,
		token=token,
		app='tenx-for-splunk',
		sharing='app')


SPLUNK_SOURCE_PREFIX = 'source::'


def get_tenx_config(service=None, server_uri=None, token=None):
	"""
	Builds the config needed by 10x to work, from the tenx_config.conf and props.conf files.

	In case or errors (or missing data), values are filled with defaults, meaning we always get
	a valid config object as a result of this method.
	"""

	try:
		if service is None:
			service = get_app_service(server_uri, token)

		config_stanza = {}

		try:
			config_stanza = service.confs['tenx_config']['config'].content
		except Exception as e:
			logger.warning("Failed loading config stanza from tenx_config - {}".format(e), exc_info=1)

		result = {}

		for key in six.iterkeys(tenx_consts.DEFAULT_CONFIG):
			result[key] = config_stanza.get(key, tenx_consts.DEFAULT_CONFIG.get(key))

		props_conf = service.confs['props']

		for stanza in props_conf:
			for key, value in six.iteritems(stanza.content):
				if key == result[tenx_consts.TENX_EXTRACTION_NAME] and value == result[tenx_consts.TENX_EXTRACTION]:
					# The stanza name is the name of the source/sourcetype
					#
					if stanza.name.startswith(SPLUNK_SOURCE_PREFIX):
						result['tenx_sources'].append(stanza.name[len(SPLUNK_SOURCE_PREFIX):])
					else:
						# TODO - check this is actually a sourcetype
						#
						result['tenx_source_types'].append(stanza.name)

		return result

	except Exception as e:
		logger.warning("Unexpected error getting tenx config - {}".format(e), exc_info=1)
		return tenx_consts.DEFAULT_CONFIG


def splunk_home():
	"""
	Returns the value of SPLUNK_HOME environment variable.
	"""
	return os.environ['SPLUNK_HOME']


def setup_logger(logger_name, level):
	"""
	Setups the logger associated with the current process to emit itself into splunk's var/log/splunk folder.
	"""
	main_logger = logging.getLogger()  # no name to affect main logger
	main_logger.propagate = False  # Prevent the log messages from being duplicated in the python.log file
	main_logger.setLevel(level)
	
	file_handler = logging.handlers.RotatingFileHandler(
		splunk_home() + '/var/log/splunk/' + logger_name + '.log', maxBytes=25000000, backupCount=5)

	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	file_handler.setFormatter(formatter)
	main_logger.addHandler(file_handler)


def add_url_params(url, params):
	"""
	Adds the provided params to the given url as url params.
	Note: Do NOT unquote the URL path as it may contain encoded characters
	(e.g., template hashes with spaces, special chars) that must stay encoded.
	"""
	if not params:
		return url

	# Parse without unquoting to preserve encoded characters in the path
	parsed_url = urllib.parse.urlparse(url)
	# Only unquote the query string, not the path
	get_args = urllib.parse.unquote(parsed_url.query) if parsed_url.query else ""

	parsed_get_args = dict(urllib.parse.parse_qsl(get_args))
	parsed_get_args.update(params)

	parsed_get_args.update(
		{k: json.dumps(v) for k, v in parsed_get_args.items() if isinstance(v, (bool, dict))}
	)

	encoded_get_args = urllib.parse.urlencode(parsed_get_args, doseq=True)

	new_url = urllib.parse.ParseResult(
		parsed_url.scheme, parsed_url.netloc, parsed_url.path,
		parsed_url.params, encoded_get_args, parsed_url.fragment
	).geturl()

	return new_url


class ServerConnection:
	"""
	Utility class for making authenticated rest calls into Splunk.
	"""
	def __init__(self, server_uri, user, auth, ctx=None):
		self.server_uri = server_uri
		self.user = user
		self.auth = auth
		self.ctx = ctx

		self.headers = {'Content-Type': 'application/json'}

		if 'session_key' in self.auth:
			self.headers['Authorization'] = 'Splunk %s' % auth['session_key']
		elif 'bearer_token' in self.auth:
			self.headers['Authorization'] = 'Bearer %s' % auth['bearer_token']

	def get(self, url, params=None, output_mode="json"):
		"""
		Runs a get operation on the given url.
		"""
		if params is None:
			params = {}

		if output_mode:
			params["output_mode"] = output_mode

		full_url = self.server_uri + add_url_params(url, params)

		req = urllib.request.Request(full_url, method='GET', headers=self.headers)
		res = urllib.request.urlopen(req, context=self.ctx)

		return json.loads(res.read())

	def post(self, url, data, params=None, output_mode="json", read_result=True):
		"""
		Runs a post operation on the given url.

		read_result can be set to False if we want to handle reading the results ourselves from the outside.
		"""
		if params is None:
			params = {}

		if output_mode:
			params["output_mode"] = output_mode

		full_url = self.server_uri + add_url_params(url, params)
		
		if isinstance(data, str):
			encoded_data = data.encode()
		else:
			encoded_data = urllib.parse.urlencode(data).encode()

		req = urllib.request.Request(full_url, method='POST', headers=self.headers)
		res = urllib.request.urlopen(req, data=encoded_data, context=self.ctx)

		if read_result:
			return json.loads(res.read())

		return res


def get_internal(obj, *args):
	"""
	Method for returning a deep member of a json based object recursively.
	"""
	if not obj or len(args) <= 0:
		return obj

	arg = args[0]

	if isinstance(arg, int):
		if not isinstance(obj, list):
			return None

		if arg < 0 or arg >= len(obj):
			return None

		return get_internal(obj[arg], *args[1:])

	if isinstance(arg, str):
		if not isinstance(obj, dict):
			return None

		return get_internal(obj.get(arg), *args[1:])

	return None


def current_time_ms():
	"""
	Returns the current system time in ms.
	"""
	return time.time_ns() // 1_000_000


def sleep_ms(ms):
	"""
	Sleeps for the given number of ms.
	"""
	time.sleep(ms / 1000.0)


def splunk_message_macro(message):
	"""
	Returns an SPL macro call for the tenx-message macro.
	"""
	return '`tenx-message(' + message + ')`'


def splunk_inflate_macro(debug=False):
	"""
	Returns an SPL macro call for the tenx-inflate macro.
	"""
	if debug:
		return '`tenx-inflate-debug`'

	return '`tenx-inflate`'


def strip_string(val):
	"""
	Util method to strip a value from quotation marks, so we have a uniform result
	"""
	if val.startswith('"') and val.endswith('"'):
		return val[1:-1]

	return val


def escape_spl_string_literal(value):
	"""
	Escapes a string for embedding inside a double-quoted SPL string literal (e.g. a quoted
	value in `IN ("a","b")`, or a quoted option value like `searchstring="..."`).

	SPL uses backslash escaping inside double quotes, so a literal backslash becomes '\\\\'
	and a literal double quote becomes '\\"'. Backslashes are escaped first so we don't
	double-escape the backslash we introduce for the quotes.
	"""
	return value.replace('\\', '\\\\').replace('"', '\\"')
