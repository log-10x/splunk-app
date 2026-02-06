/* tenx_setup_page.js */

//# sourceURL=tenx_setup_page.js

define(function(require, exports, module) {
	var react = require('react');
	var mvc = require('splunkjs/mvc/mvc');

	var Config = require('../util/tenx_config.js');
	
	const APP_NAME = 'tenx-for-splunk';

	var reloadAndRedirect = async function(service) {
		var apps = service.apps();
		await apps.fetch();

		var app = apps.item(APP_NAME);
		await app.fetch();
		await app.reload();

		setTimeout(() => {
			window.location.href = '/app/' + APP_NAME;
		}, 800); // wait 800ms and redirect
	}

	var performSetup = async function() {
		var namespace = {
			app: APP_NAME,
			sharing: "app",
		};

		var service = mvc.createService(namespace);

		var config = Config.create(service, namespace);

		const valid = await config.validate();

		if (!valid) {
			console.warn(APP_NAME + " failed config validation, this is weird...");
			return;
		}

		if (await config.isConfigured()) {
			console.warn(APP_NAME + " is already configured, reloading and redirecting...");

			await reloadAndRedirect(service);
			
			return;
		}

		await config.markConfigured();

		await reloadAndRedirect(service);
	}

	const e = react.createElement;

	class SetupPage extends react.Component {
		constructor(props) {
			super(props);

			this.state = {
				token: ''
			};

			this.handleChange = this.handleChange.bind(this);
			this.handleSubmit = this.handleSubmit.bind(this);
		}

		handleChange(event) {
			this.setState({ ...this.state, [event.target.name]: event.target.value})
		}

		async handleSubmit(event) {
			event.preventDefault();

			await performSetup();
		}

		render() {
			return e("div", null, [
				e("h2", null,	"Welcome to the 10x for Splunk app"),
				e("div", null,	"In order to fully use the app, you need to configure which sourcetypes have tenx encoded data in them"),
				e("div", null,	"This is done via a POST rest call to the /tenx-config/<sourcetype> and will mark the <sourcetype> as one with encoded data"),
				e("div", null,	"The full path probably looks something like https://my-splunk-hostname:8089/services/tenx-config/my_source_type"),
				e("div", null, [
					e("form", { onSubmit: this.handleSubmit }, [
						e("input", { type: "submit", value: "Got it :)" })
					])
				])
			]);
		}
	}

	return e(SetupPage);
});
