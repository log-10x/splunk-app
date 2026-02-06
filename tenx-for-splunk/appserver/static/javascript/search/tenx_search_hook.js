//# sourceURL=tenx_search_hook.js

/*
 * Module for turning all searches done into 10x searches.
 * Does so by redirecting all calls into the base search endpoint to our own.
 *
*/
define(function(require, exports, module) {
	var mvc = require('splunkjs/mvc');

	var execute = function(restartSearchManagers) {
		const originalSearchType = "POST";
		const originalSearchPath = "/search/jobs";

		const newSearchPath = "/tenx-search";

		$.ajaxSetup({
			beforeSend: function (xhr, settings) {
				if ((settings.type == originalSearchType) &&
					(settings.url.endsWith(originalSearchPath))) {

					// Remove the original search path, and add our own instead.
					//
					var baseUrl = settings.url.substring(0, settings.url.length - originalSearchPath.length);
					settings.url = baseUrl + newSearchPath;
				}
			}
		});

		if (restartSearchManagers) {
			var components = mvc.Components.getInstances();

			for (var i = 0; i < components.length; i++) {
				var current = components[i];

				if (current.moduleId == "splunkjs/mvc/searchmanager") {
					// Restarts any searches already in progress,
					// so they'll be re-captured by our hook.
					//
					current.startSearch({refresh: true});
				}
			}
		}
	};

	exports.execute = execute;

	return exports;
});
