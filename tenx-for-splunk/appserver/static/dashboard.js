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

Every page this app ships is a dashboard, including the '10x Search' tab (search.xml, a classic
form), so this file is the only place the hook is installed. It used to be loaded by hand on that
tab from a Mako template; Splunk 10.4 deprecates app-shipped Mako templates, and the by-hand
include was where the tab's 404 lived, so the tab became a dashboard and inherits the hook from
here like the others. A non-dashboard page would have to load 'tenx_search_hook.js' and call
'TenxSearchHook.execute' itself, and there is no supported way left to ship one.
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
