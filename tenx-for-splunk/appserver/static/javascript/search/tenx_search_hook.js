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
		// Splunk 9 and later create search jobs at /search/v2/jobs; older Splunk Web used
		// /search/jobs.
		const originalSearchPaths = ["/search/v2/jobs", "/search/jobs"];

		const newSearchPath = "/tenx-search";

		$.ajaxSetup({
			beforeSend: function (xhr, settings) {
				if (settings.type != originalSearchType) {
					return;
				}

				for (var i = 0; i < originalSearchPaths.length; i++) {
					var path = originalSearchPaths[i];

					if (settings.url.endsWith(path)) {
						// Remove the original search path, and add our own instead.
						//
						var baseUrl = settings.url.substring(0, settings.url.length - path.length);
						settings.url = baseUrl + newSearchPath;
						return;
					}
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
