( function () {
	'use strict';

	var selectAll = document.getElementById( 'ipabuse-select-all' );
	if ( ! selectAll ) {
		return;
	}

	selectAll.addEventListener( 'change', function () {
		var checkboxes = document.querySelectorAll( '.ipabuse-row-checkbox' );
		checkboxes.forEach( function ( checkbox ) {
			checkbox.checked = selectAll.checked;
		} );
	} );
} )();
