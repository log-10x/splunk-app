//# sourceURL=tenx_search_page.js

define(function(require, exports, module) {
	var mvc = require('splunkjs/mvc');

	const APP_NAME = 'tenx-for-splunk';

	var displayConfigWarning = function() {
		$(".search-title").append('<h2 style="color:red;">Warning, no tenx source/sourcetype defined. See documentation on how to add one</h2>')
	}

	var checkConfig = function() {
		var namespace = {
			app: APP_NAME,
			sharing: "app",
		};

		var service = mvc.createService(namespace);

		if (!service) {
			return;
		}

		service.get('tenx-config', null, function(err, response) {
			if ((err) ||
				(!response) ||
				(!response.data)) {

				return;
			}

			var tenxConfig = response.data;

			if ((tenxConfig.tenx_source_types.length == 0) &&
				(tenxConfig.tenx_sources.length == 0)) {

				displayConfigWarning();
			}
		});
	};

	exports.checkConfig = checkConfig;

	return exports;
});
