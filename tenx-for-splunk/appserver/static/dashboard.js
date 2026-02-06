/*
10x Search Hook for Dashboards
==============================

Copying this dashboard.js file to an app will apply the 10x search hook into all dashboards
in that app, as a 'dashboard.js' file placed in the root 'appserver/static' folder gets loaded
for every dashboard in the app.

How it works:
- Intercepts all POST requests to /search/jobs
- Redirects them to /tenx-search endpoint
- The tenx_search_handler.py transforms the search to include `tenx-inflate` macro
- This allows encoded log data to be searched and displayed transparently

Alternatively, the code can be added independently to any dashboard it's required in.

Note that if there are non-dashboard pages in an app which still require 10x search capabilities,
they also need to have the 'tenx_search_hook.js' include and 'TenxSearchHook.execute' call to be done
manually in their code.

An example of this is the way the '10x Search' tab works in the 10x app, which is defined by the
following files: search.xml, tenx_template_slim.html, and tenx_search.js
*/
require([
	"/static/app/tenx-for-splunk/javascript/search/tenx_search_hook.js",
	"splunkjs/mvc/simplexml/ready!"
], function(
	TenxSearchHook
) {
	// Passing 'true' here makes sure that any search managers that already started
	// working before this got executed will restart their search, making sure we
	// capture it and route to our endpoint.
	//
	// See tenx_search_hook.js for more info.
	//
	TenxSearchHook.execute(true);
});
