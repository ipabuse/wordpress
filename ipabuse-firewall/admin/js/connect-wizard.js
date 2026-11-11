( function () {
	'use strict';

	var modal = document.getElementById( 'ipabuse-connect-modal' );
	if ( ! modal || typeof IPAbuseConnect === 'undefined' ) {
		return;
	}

	var formStep    = modal.querySelector( '[data-step="form"]' );
	var doneStep    = modal.querySelector( '[data-step="done"]' );
	var emailInput  = document.getElementById( 'ipabuse-connect-email' );
	var errorBox    = modal.querySelector( '.ipabuse-connect-error' );
	var successBox  = modal.querySelector( '.ipabuse-connect-success' );
	var submitBtn   = document.getElementById( 'ipabuse-connect-submit' );
	var closeBtn    = modal.querySelector( '.ipabuse-modal-close' );

	/** Escape text for safe insertion as HTML content. */
	function escapeHtml( str ) {
		var div = document.createElement( 'div' );
		div.textContent = String( str );
		return div.innerHTML;
	}

	function openModal() {
		errorBox.textContent = '';
		formStep.hidden = false;
		doneStep.hidden = true;
		modal.hidden = false;
	}

	function closeModal() {
		modal.hidden = true;
	}

	document.querySelectorAll( '.ipabuse-connect-trigger' ).forEach( function ( btn ) {
		btn.addEventListener( 'click', openModal );
	} );

	closeBtn.addEventListener( 'click', closeModal );
	modal.addEventListener( 'click', function ( e ) {
		if ( e.target === modal ) {
			closeModal();
		}
	} );
	document.addEventListener( 'keydown', function ( e ) {
		if ( 'Escape' === e.key && ! modal.hidden ) {
			closeModal();
		}
	} );

	submitBtn.addEventListener( 'click', function () {
		var email = emailInput.value.trim();
		errorBox.textContent = '';

		if ( ! email ) {
			errorBox.textContent = IPAbuseConnect.labels.emailRequired;
			return;
		}

		submitBtn.disabled = true;
		submitBtn.textContent = IPAbuseConnect.labels.connecting;

		var data = new FormData();
		data.append( 'action', 'ipabuse_connect_account' );
		data.append( 'nonce', IPAbuseConnect.nonce );
		data.append( 'email', email );

		fetch( IPAbuseConnect.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: data } )
			.then( function ( response ) { return response.json(); } )
			.then( function ( json ) {
				submitBtn.disabled = false;
				submitBtn.textContent = IPAbuseConnect.labels.createAccount;

				if ( ! json.success ) {
					errorBox.textContent = ( json.data && json.data.message ) || IPAbuseConnect.labels.requestFailed;
					return;
				}

				successBox.innerHTML = escapeHtml( json.data.message );
				formStep.hidden = true;
				doneStep.hidden = false;
			} )
			.catch( function () {
				submitBtn.disabled = false;
				submitBtn.textContent = IPAbuseConnect.labels.createAccount;
				errorBox.textContent = IPAbuseConnect.labels.requestFailed;
			} );
	} );
} )();
