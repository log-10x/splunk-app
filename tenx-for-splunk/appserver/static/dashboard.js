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

The app's own Analytics and Diagnostics dashboards are left out on purpose: their
panels read the compact form, counting events and templates and measuring compact bytes, and
expand explicitly where they need the original line. Routed through the rewrite, every event
would be expanded first, the compact sizes would be measured on expanded lines, and the
template fields those panels group by would be dropped.
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
	var compactFormViews = ["tenx_dashboard", "tenx_diagnostics"];
	var view = window.location.pathname.replace(/\/+$/, "").split("/").pop();

	if (compactFormViews.indexOf(view) !== -1) {
		return;
	}

	TenxSearchHook.execute(true);
});
