//# sourceURL=tenx_alert_compile.js
//
// Dashboard behaviour for the "10x Compile Alert" view (tenx_alert_compile.xml).
// Compiles a search via the /tenx-alert REST handler and surfaces the classification
// (strategy / needs_review / reason / compiled_search), so a human confirms a flagged or
// rejected result before it is scheduled. Also triggers the bulk recompile/migrate pass.
//
// Uses the same SplunkJS service pattern as the interactive search page: mvc.createService
// with the app namespace, then service.post to the app-scoped custom endpoint (CSRF handled
// by SplunkJS).

require([
	'jquery',
	'splunkjs/mvc',
	'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
	var APP_NAME = 'tenx-for-splunk';
	var service = mvc.createService({ app: APP_NAME, sharing: 'app' });
	var $result = $('#tenx-alert-result');

	function escapeHtml(value) {
		return String(value == null ? '' : value).replace(/[&<>"]/g, function(c) {
			return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
		});
	}

	// The persistent handler returns its payload as the response body for every status; SplunkJS
	// hands 2xx bodies to `response.data` and non-2xx bodies to `err.data`, so a REJECTED (422) or
	// RETRYABLE (503) lands in the error branch. Both shapes are the same compile-result dict.
	function payloadOf(errOrResponse) {
		if (!errOrResponse) { return null; }
		if (errOrResponse.data) { return errOrResponse.data; }
		return null;
	}

	function renderResult(data) {
		if (data == null) { $result.html('<span style="color:#a00;">No response.</span>'); return; }

		// 400/405/500 responses carry a plain string body (e.g. "Missing required 'search'"),
		// not a compile-result object. Render it as an error rather than a blank box.
		if (typeof data !== 'object') {
			$result.html('<span style="color:#a00;">' + escapeHtml(data) + '</span>');
			return;
		}

		var badge = escapeHtml(data.strategy) + (data.needs_review ? ' <span style="color:#b58900;">(needs review)</span>' : '');
		var html = '<div><b>Strategy:</b> ' + badge + '</div>';
		html += '<div><b>Applied:</b> ' + (data.applied ? 'yes' : 'no') + '</div>';

		if (data.reason) {
			html += '<div><b>Reason:</b> ' + escapeHtml(data.reason) + '</div>';
		}
		if (data.compiled_search) {
			html += '<div style="margin-top:4px;"><b>Compiled search:</b><br/><code style="white-space:pre-wrap;">' +
				escapeHtml(data.compiled_search) + '</code></div>';
		}
		if (data.saved_search_error) {
			html += '<div style="color:#a00;"><b>Save failed:</b> ' + escapeHtml(data.saved_search_error) + '</div>';
		}
		// A storable-but-flagged result was returned, not applied: offer to confirm and schedule.
		if (data.needs_review && !data.applied && data.storable) {
			html += '<button id="tenx-alert-confirm" class="btn btn-primary" style="margin-top:8px;">Confirm and schedule</button>';
		}

		$result.html(html);
		$('#tenx-alert-confirm').on('click', function() { compile(true); });
	}

	function compile(confirm) {
		var search = $.trim($('#tenx-alert-search').val());
		var name = $.trim($('#tenx-alert-name').val());

		if (!search) { $result.html('<span style="color:#a00;">Enter a search.</span>'); return; }

		var params = { search: search };
		if (name) { params.name = name; }
		if (confirm) { params.confirm = 'true'; }

		$result.text('Compiling...');

		service.post('tenx-alert', params, function(err, response) {
			renderResult(payloadOf(err) || payloadOf(response));
		});
	}

	function recompileAll() {
		$result.text('Recompiling all managed alerts...');

		service.post('tenx-alert', { action: 'recompile' }, function(err, response) {
			var data = payloadOf(err) || payloadOf(response);
			if (!data) { $result.html('<span style="color:#a00;">No response.</span>'); return; }
			$result.html('<b>Recompile summary:</b><br/><code style="white-space:pre-wrap;">' +
				escapeHtml(JSON.stringify(data, null, 2)) + '</code>');
		});
	}

	$('#tenx-alert-compile').on('click', function() { compile(false); });
	$('#tenx-alert-recompile').on('click', recompileAll);
});
