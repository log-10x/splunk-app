/* tenx_setup.js */

//# sourceURL=tenx_setup.js

require.config({
	paths: {
		react: "../app/tenx-for-splunk/javascript/react/react.production.min",
		ReactDOM: "../app/tenx-for-splunk/javascript/react/react-dom.production.min",
	},
	scriptType: "module",
});

require([
	"react", // this needs to be lowercase because ReactDOM refers to it as lowercase
	"ReactDOM",
	"/static/app/tenx-for-splunk/javascript/views/tenx_setup_page.js",
], function(react, ReactDOM, setup_page) {
	ReactDOM.render(setup_page, document.getElementById('main_container'));
});
