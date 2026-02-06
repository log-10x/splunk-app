/* tenx_config.js */

//# sourceURL=tenx_config.js

define(function(require, exports, module) {
	var _ = require('underscore');

	// Class for wrapping a stanza in a .conf file, allowing easy manipulation of it.
	//
	var TenxConfFileStanza = function(configurationsFileAccessor, stanzaName, namespace) {
		this.configurationsFileAccessor = configurationsFileAccessor;
		this.stanzaName = stanzaName;
		this.namespace = namespace;

		this.exists = false;
		this._configurationsStanzaAccessor = null;
	};

	_.extend(TenxConfFileStanza.prototype, {
		_refreshConfigurations: async function() {
			await this.configurationsFileAccessor.fetch();
		},
		_refreshStanzaConfigurations: async function() {
			var accessor = await this.configurationsStanzaAccessor();

			await accessor.fetch();
		},
		configurationsStanzaAccessor: async function() {
			if (!this._configurationsStanzaAccessor) {
				this._configurationsStanzaAccessor = this.configurationsFileAccessor.item(this.stanzaName);

				await this._configurationsStanzaAccessor.fetch();
			}

			return this._configurationsStanzaAccessor;
		},
		checkExists: async function(force) {
			if ((this.exists) && (!force)) {
				return this.exists;
			}

			await this._refreshConfigurations();

			var stanzas = this.configurationsFileAccessor.list();
			this.exists = false;

			for (var i = 0; i < stanzas.length; i++) {
				if (stanzas[i].name === this.stanzaName) {
					var stanzaNamespace = stanzas[i].namespace || {};

					if (this.namespace.app == stanzaNamespace.app) {
						this.exists = true;
						break;
					}
				}
			}

			return this.exists;
		},
		create: async function() {
			var doesExist = await this.checkExists();

			if (doesExist) {
				return;
			}

			await this.configurationsFileAccessor.create(this.stanzaName, function(errorResponse, createdStanza) {
				if (errorResponse) {
					console.warn(errorResponse);
				}
			});

			await this._refreshConfigurations();
		},
		v: async function(propertyName, refreshFirst) {
			return await this.propertyValue(propertyName, refreshFirst);
		},
		propertyValue: async function(propertyName, refreshFirst) {
			if (refreshFirst) {
				await this._refreshStanzaConfigurations();
			}

			var accessor = await this.configurationsStanzaAccessor();

			for (const [key, value] of Object.entries(accessor.properties())) {
				if (key === propertyName) {
					return value;
				}
			}

			return null;
		},
		u: async function(propertyName, propertyValue) {
			await this.updateProperty(propertyName, propertyValue);
		},
		updateProperty: async function(propertyName, propertyValue) {
			var properties = {};
			properties[propertyName] = propertyValue;

			await this.updateProperties(properties);
		},
		updateProperties: async function(properties) {
			var accessor = await this.configurationsStanzaAccessor();

			await accessor.update(properties, function(errorResponse, entity) {
				if (errorResponse) {
					console.warn(errorResponse);
				}
			});

			await this._refreshStanzaConfigurations();
		},
	});

	// Class for wrapping a .conf file, allowing easy manipulation of it.
	//
	var TenxConfFile = function(configurationsAccessor, confFileName, namespace) {
		this.configurationsAccessor = configurationsAccessor;
		this.confFileName = confFileName;
		this.namespace = namespace;

		this.exists = false;
		this._configurationsFileAccessor = null;
	};

	_.extend(TenxConfFile.prototype, {
		_refreshConfigurations: async function() {
			await this.configurationsAccessor.fetch();
		},
		configurationsFileAccessor: async function() {
			if (!this._configurationsFileAccessor) {
				this._configurationsFileAccessor = this.configurationsAccessor.item(this.confFileName);

				await this._configurationsFileAccessor.fetch();
			}

			return this._configurationsFileAccessor;
		},
		checkExists: async function(force) {
			if ((this.exists) && (!force)) {
				return this.exists;
			}

			await this._refreshConfigurations();

			var configFiles = this.configurationsAccessor.list();
			this.exists = false;

			for (var i = 0; i < configFiles.length; i++) {
				if (configFiles[i].name === this.confFileName) {
					this.exists = true;
					break;
				}
			}

			return this.exists;
		},
		create: async function() {
			var doesExist = await this.checkExists();

			if (doesExist) {
				return;
			}

			await this.configurationsAccessor.create(this.confFileName, function(errorResponse, createdFile) {
				if (errorResponse) {
					console.warn(errorResponse);
				}
			});

			await this._refreshConfigurations();
		},
		stanza: async function(stanzaName) {
			var doesExist = await this.checkExists();

			if (!doesExist) {
				return null;
			}

			return new TenxConfFileStanza(await this.configurationsFileAccessor(), stanzaName, this.namespace);
		},
		stanzas: async function() {
			var doesExist = await this.checkExists();

			if (!doesExist) {
				return [];
			}

			var accessor = await this.configurationsFileAccessor();
			await accessor.fetch();

			var stanzas = accessor.list();

			var that = this;

			return stanzas.filter(function(stanza) {
				var stanzaNamespace = stanza.namespace || {};

				return (that.namespace.app == stanzaNamespace.app);
			}).map(stanza => new TenxConfFileStanza(accessor, stanza.name, that.namespace));
		},
	});

	// Class representing the application config
	//
	var AppConfig = function(appFile) {
		this.appFile = appFile;
		this._installStanza = null;
	}

	_.extend(AppConfig.prototype, {
		validate: async function() {
			return await this.appFile.checkExists();
		},
		_getInstallStanza: async function() {
			if (!this._installStanza) {
				this._installStanza = this.appFile.stanza("install");
			}

			return this._installStanza;
		},
		_isTrue: function(v) {
			if (typeof(v) === typeof(true)) return v;
			if (typeof(v) === typeof(1)) return v!==0;

			if (typeof(v) === typeof('true')) {
				if (v.toLowerCase() === 'true') return true;
				if (v === 't') return true;
				if (v === '1') return true;
			}

			return false;
		},
		isConfigured: async function() {
			const stanza = await this._getInstallStanza();
			const isConfigured = await stanza.v("is_configured");

			return this._isTrue(isConfigured);
		},
		markConfigured: async function() {
			const stanza = await this._getInstallStanza();

			await stanza.u("is_configured", 1);
		},
	});

	return {
		create: function(service, namespace) {
			var configurationsAccessor = service.configurations(namespace);

			return new AppConfig(new TenxConfFile(configurationsAccessor, "app", namespace));
		}
	};
});
