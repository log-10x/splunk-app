/* tenx_search.js */

//# sourceURL=tenx_search.js

require([
	"/static/app/tenx-for-splunk/javascript/search/tenx_search_hook.js",
	"/static/app/tenx-for-splunk/javascript/views/tenx_search_page.js"
], function(
	TenxSearchHook,
	TenxSearchPage
) {
	TenxSearchHook.execute();
	TenxSearchPage.checkConfig();
});
