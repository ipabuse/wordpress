( function () {
	'use strict';

	var form = document.getElementById( 'ipabuse-lookup-form' );
	if ( ! form ) {
		return;
	}

	var input   = document.getElementById( 'lookup_ip' );
	var result  = document.getElementById( 'ipabuse-lookup-result' );
	var spinner = form.querySelector( '.ipabuse-lookup-spinner' );
	var submit  = form.querySelector( 'input[type="submit"]' );

	/** Escape text for safe insertion as HTML content. */
	function escapeHtml( str ) {
		var div = document.createElement( 'div' );
		div.textContent = String( str );
		return div.innerHTML;
	}

	function renderError( message ) {
		result.innerHTML = '<p>' + escapeHtml( message ) + '</p>';
	}

	function post( action, ip, extra ) {
		var data = new FormData();
		data.append( 'action', action );
		data.append( 'nonce', IPAbuseLookup.nonce );
		data.append( 'ip', ip );
		if ( extra ) {
			Object.keys( extra ).forEach( function ( key ) {
				data.append( key, extra[ key ] );
			} );
		}
		return fetch( IPAbuseLookup.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: data } )
			.then( function ( response ) { return response.json(); } );
	}

	function renderResult( d ) {
		var categoryOptions = IPAbuseLookup.categories.map( function ( cat ) {
			var selected = cat === d.category ? ' selected' : '';
			return '<option value="' + escapeHtml( cat ) + '"' + selected + '>' + escapeHtml( cat ) + '</option>';
		} ).join( '' );

		result.innerHTML =
			'<table class="widefat striped ipabuse-lookup-result">' +
				'<tr><th>' + escapeHtml( IPAbuseLookup.labels.ip ) + '</th><td>' + escapeHtml( d.ip ) + '</td></tr>' +
				'<tr><th>' + escapeHtml( IPAbuseLookup.labels.score ) + '</th><td><span class="ipabuse-badge ' + escapeHtml( d.badge ) + '">' + escapeHtml( d.score ) + '</span></td></tr>' +
				'<tr><th>' + escapeHtml( IPAbuseLookup.labels.category ) + '</th><td>' + escapeHtml( d.category ) + '</td></tr>' +
				'<tr><th>' + escapeHtml( IPAbuseLookup.labels.reports ) + '</th><td>' + escapeHtml( d.reports ) + '</td></tr>' +
				'<tr><th>' + escapeHtml( IPAbuseLookup.labels.country ) + '</th><td>' + escapeHtml( d.country ) + '</td></tr>' +
			'</table>' +
			'<div class="ipabuse-lookup-actions">' +
				'<button type="button" class="button" id="ipabuse-block-btn">' + escapeHtml( IPAbuseLookup.labels.blockThisIp ) + '</button>' +
			'</div>' +
			'<div class="ipabuse-lookup-actions ipabuse-report-form">' +
				'<select id="ipabuse-report-category">' + categoryOptions + '</select>' +
				'<input type="text" id="ipabuse-report-description" placeholder="' + escapeHtml( IPAbuseLookup.labels.descriptionPlaceholder ) + '" class="regular-text" />' +
				'<button type="button" class="button" id="ipabuse-report-btn">' + escapeHtml( IPAbuseLookup.labels.reportToIpabuse ) + '</button>' +
			'</div>' +
			'<div id="ipabuse-lookup-action-notice"></div>';

		document.getElementById( 'ipabuse-block-btn' ).addEventListener( 'click', function () {
			if ( ! window.confirm( IPAbuseLookup.labels.confirmBlock ) ) {
				return;
			}
			this.disabled = true;
			post( 'ipabuse_manual_block', d.ip ).then( function ( response ) {
				var notice = document.getElementById( 'ipabuse-lookup-action-notice' );
				if ( response && response.success ) {
					notice.innerHTML = '<p>' + escapeHtml( response.data.message ) + '</p>';
				} else {
					notice.innerHTML = '<p>' + escapeHtml( ( response && response.data && response.data.message ) || IPAbuseLookup.labels.requestFailed ) + '</p>';
				}
			} );
		} );

		document.getElementById( 'ipabuse-report-btn' ).addEventListener( 'click', function () {
			var button = this;
			button.disabled = true;
			var category    = document.getElementById( 'ipabuse-report-category' ).value;
			var description = document.getElementById( 'ipabuse-report-description' ).value;
			post( 'ipabuse_manual_report', d.ip, { category: category, description: description } ).then( function ( response ) {
				var notice = document.getElementById( 'ipabuse-lookup-action-notice' );
				button.disabled = false;
				if ( response && response.success ) {
					notice.innerHTML = '<p>' + escapeHtml( response.data.message ) + '</p>';
				} else {
					notice.innerHTML = '<p>' + escapeHtml( ( response && response.data && response.data.message ) || IPAbuseLookup.labels.requestFailed ) + '</p>';
				}
			} );
		} );
	}

	form.addEventListener( 'submit', function ( event ) {
		event.preventDefault();

		var ip = input.value.trim();
		result.innerHTML = '';
		if ( ! ip ) {
			return;
		}

		submit.disabled = true;
		if ( spinner ) {
			spinner.classList.add( 'is-active' );
		}

		post( 'ipabuse_lookup', ip )
			.then( function ( response ) {
				if ( response && response.success ) {
					renderResult( response.data );
				} else {
					renderError( ( response && response.data && response.data.message ) || IPAbuseLookup.labels.requestFailed );
				}
			} )
			.catch( function () {
				renderError( IPAbuseLookup.labels.requestFailed );
			} )
			.finally( function () {
				submit.disabled = false;
				if ( spinner ) {
					spinner.classList.remove( 'is-active' );
				}
			} );
	} );
} )();
