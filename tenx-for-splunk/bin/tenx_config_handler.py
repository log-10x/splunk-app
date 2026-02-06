from future import standard_library
standard_library.install_aliases()

import os
import sys
import logging
import json

from splunk.clilib.bundle_paths import get_base_path
from splunk.persistconn.application import PersistentServerConnectionApplication

# Library-loading boilerplate
APP_NAME = 'tenx-for-splunk'
apphome = os.path.join(get_base_path(), APP_NAME)
sys.path.append(os.path.join(apphome, 'bin'))
sys.path.append(os.path.join(apphome, 'lib'))

import tenx_util
import tenx_consts

from splunklib import six

tenx_util.setup_logger('tenx_config_handler', logging.INFO)
logger = logging.getLogger(__name__)


class TenxConfigHandler(PersistentServerConnectionApplication):
	"""
	Rest api handler for interacting with the 10x app configuration

	Supports the following:

	GET / - returns a json of the current 10x app config.
	POST /<sourcetype> - marks <sourcetype> as one containing 10x encoded events.
	DELETE /<sourcetype> - unmarks <sourcetype> as one containing 10x encoded events.
	"""
	def __init__(self, command_line, command_arg):
		PersistentServerConnectionApplication.__init__(self)

		self.service = None

	def init_service(self, in_string_json):
		if self.service:
			return

		self.service = tenx_util.get_app_service(
			in_string_json.get('server', {}).get('rest_uri'),
			in_string_json.get('session', {}).get('authtoken'))

	def result(self, payload, status):
		if status >= 400:
			logger.warning(payload)

		return {'payload': payload, 'status': status}

	def ok(self, message):
		return self.result(message, 200)

	def created(self, message):
		return self.result(message, 201)

	def bad_request(self, message):
		return self.result(message, 400)

	def not_found(self, message):
		return self.result(message, 404)

	def method_not_allowed(self, in_string_json):
		method = in_string_json.get("method")
		message = "Unsupported method {}.".format(method)

		return self.result(message, 405)

	def conflict(self, message):
		return self.result(message, 409)

	def get(self, in_string_json):
		sub_path = in_string_json.get('path_info')

		if sub_path:
			return self.bad_request("Only root path supported for GET")

		logger.info("Got GET request")

		self.init_service(in_string_json)

		tenx_config = tenx_util.get_tenx_config(service=self.service)
		logger.info("Loaded config - {}".format(json.dumps(tenx_config)))

		return self.ok(tenx_config)

	def _bad_source_sourcetype(self, request_type):
		return self.bad_request("Need to specify /source or /sourcetype for {}".format(request_type))

	def post(self, in_string_json):
		path_parts = in_string_json.get('path_info').split('/')

		if len(path_parts) != 2:
			return self._bad_source_sourcetype('POST')

		if path_parts[0] == 'sourcetype':
			return self._post(in_string_json, path_parts[1], path_parts[0])
		elif path_parts[0] == 'source':
			return self._post(in_string_json, tenx_util.SPLUNK_SOURCE_PREFIX + path_parts[1], path_parts[0])

		return self._bad_source_sourcetype('POST')

	def _post(self, in_string_json, name, logging_str):
		logger.info("Got POST request with {} - {}.".format(logging_str, name))

		self.init_service(in_string_json)

		tenx_config = tenx_util.get_tenx_config(service=self.service)
		logger.info("Loaded config - {}".format(json.dumps(tenx_config)))

		props_conf = self.service.confs['props']

		if name not in props_conf:
			logger.info("Going to create stanza for {} {} in props.conf.".format(logging_str, name))
			props_conf.create(name)
			logger.info("Created stanza for {} {} in props.conf.".format(logging_str, name))

		stanza = props_conf[name]

		for key, value in six.iteritems(stanza.content):
			if key == tenx_config.get(tenx_consts.TENX_EXTRACTION_NAME) and value:
				message = "Already have tenx extraction defined for {} - {}.".format(logging_str, name)

				return self.conflict(message)

		logger.info("Going to create tenx extraction in stanza for {} {} in props.conf.".format(logging_str, name))

		stanza.submit({
			tenx_config.get(tenx_consts.TENX_EXTRACTION_NAME): tenx_config.get(tenx_consts.TENX_EXTRACTION)
		})

		message = "Created tenx extraction in stanza for {} {} in props.conf.".format(logging_str, name)
		logger.info(message)

		return self.created(message)

	def delete(self, in_string_json):
		path_parts = in_string_json.get('path_info').split('/')

		if len(path_parts) != 2:
			return self._bad_source_sourcetype('DELETE')

		if path_parts[0] == 'sourcetype':
			return self._delete(in_string_json, path_parts[1], path_parts[0])
		elif path_parts[0] == 'source':
			return self._delete(in_string_json, tenx_util.SPLUNK_SOURCE_PREFIX + path_parts[1], path_parts[0])

		return self._bad_source_sourcetype('DELETE')

	def _delete(self, in_string_json, name, logging_str):
		logger.info("Got DELETE request with {} - {}.".format(logging_str, name))

		self.init_service(in_string_json)

		tenx_config = tenx_util.get_tenx_config(service=self.service)
		logger.info("Loaded config - {}".format(json.dumps(tenx_config)))

		props_conf = self.service.confs['props']

		if name not in props_conf:
			message = "No stanza for {} {} in props.conf.".format(logging_str, name)

			return self.not_found(message)

		stanza = props_conf[name]
		
		for key, value in six.iteritems(stanza.content):
			if key == tenx_config.get(tenx_consts.TENX_EXTRACTION_NAME) and value:
				logger.info("Going to delete tenx extraction in stanza for {} {} in props.conf.".format(logging_str, name))

				# Couldn't find a way to actually remove the attribute without removing the entire stanza.
				# Seems like Splunk's UI does the same thing though...
				#
				stanza.submit({tenx_config.get(tenx_consts.TENX_EXTRACTION_NAME): ''})

				message = "Deleted tenx extraction in stanza for {} {} in props.conf.".format(logging_str, name)
				logger.info(message)

				return self.ok(message)

		message = "No tenx extraction defined for {} {} in props.conf.".format(logging_str, name)

		return self.not_found(message)

	def handle(self, in_string):
		start_time = tenx_util.current_time_ms()

		try:
			in_string_json = json.loads(in_string)

			logger.warning(in_string_json)

			method = in_string_json.get("method")

			return {
				'GET': self.get,
				'POST': self.post,
				'DELETE': self.delete,
			}.get(method, self.method_not_allowed)(in_string_json)
			
		except Exception as e:
			logger.error("Unexpected error in tenx config handler - {}.".format(e), exc_info=1)
			return {'payload': str(e), 'status': 500}
		finally:
			logger.info("Total runtime - {}ms".format(tenx_util.current_time_ms() - start_time))
