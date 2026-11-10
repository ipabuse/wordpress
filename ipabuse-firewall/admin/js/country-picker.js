( function () {
	'use strict';

	var picker = document.querySelector( '.ipabuse-country-picker' );
	if ( ! picker ) {
		return;
	}

	var hiddenInput = document.getElementById( 'ipabuse_blocked_countries' );
	var chipsBox    = document.getElementById( 'ipabuse-country-chips' );
	var searchInput = document.getElementById( 'ipabuse-country-search' );
	var list        = document.getElementById( 'ipabuse-country-list' );
	var checkboxes  = list.querySelectorAll( '.ipabuse-country-checkbox' );

	function selectedCodes() {
		var codes = [];
		checkboxes.forEach( function ( box ) {
			if ( box.checked ) {
				codes.push( box.value );
			}
		} );
		return codes;
	}

	function render() {
		var codes = selectedCodes();
		hiddenInput.value = codes.join( ', ' );

		chipsBox.innerHTML = '';
		codes.forEach( function ( code ) {
			var chip = document.createElement( 'span' );
			chip.className = 'ipabuse-country-chip';
			chip.textContent = code + ' ';

			var remove = document.createElement( 'button' );
			remove.type = 'button';
			remove.className = 'ipabuse-country-chip-remove';
			remove.setAttribute( 'aria-label', 'Remove ' + code );
			remove.textContent = '×';
			remove.addEventListener( 'click', function () {
				var box = list.querySelector( '.ipabuse-country-checkbox[value="' + code + '"]' );
				if ( box ) {
					box.checked = false;
					render();
				}
			} );

			chip.appendChild( remove );
			chipsBox.appendChild( chip );
		} );
	}

	checkboxes.forEach( function ( box ) {
		box.addEventListener( 'change', render );
	} );

	searchInput.addEventListener( 'input', function () {
		var query = searchInput.value.trim().toLowerCase();
		list.querySelectorAll( '.ipabuse-country-option' ).forEach( function ( option ) {
			var matches = '' === query
				|| option.dataset.name.indexOf( query ) !== -1
				|| option.dataset.code.toLowerCase().indexOf( query ) !== -1;
			option.style.display = matches ? '' : 'none';
		} );
	} );

	render();
} )();
