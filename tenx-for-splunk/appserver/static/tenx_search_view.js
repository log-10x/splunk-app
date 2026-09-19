//# sourceURL=tenx_search_view.js

/*
 * The 10x Search view, as a classic dashboard rather than a Mako page.
 *
 * dashboard.js already routes every search on every dashboard in this app through
 * the expansion endpoint, so the hook is not installed here a second time. What this
 * file adds is the configuration warning the Mako page used to append to Splunk's own
 * search title: on a dashboard that element does not exist, so the warning goes into
 * the panel reserved for it below the search input.
 */
require([
	"splunkjs/mvc",
	"/static/app/tenx-for-splunk/javascript/views/tenx_search_page.js",
	"splunkjs/mvc/simplexml/ready!"
], function(mvc, TenxSearchPage) {
	TenxSearchPage.checkConfig("#tenx-search-notice");
});
