/**
 * Under Attack mode - Proof of Work challenge solver
 *
 * Reads challenge parameters from the form data attributes
 * and solves the SHA-256 proof-of-work before auto-submitting.
 *
 * @package Vigilante
 */
(function() {
    'use strict';

    var form = document.getElementById( 'ua-form' );
    if ( ! form ) {
        return;
    }

    var nonce = form.getAttribute( 'data-nonce' );
    var difficulty = parseInt( form.getAttribute( 'data-difficulty' ), 10 );

    if ( ! nonce || ! difficulty ) {
        return;
    }

    var prefix = '';
    for ( var p = 0; p < difficulty; p++ ) {
        prefix += '0';
    }

    /**
     * Find a valid proof-of-work solution using SubtleCrypto SHA-256
     */
    async function findSolution() {
        var encoder = new TextEncoder();
        var c = 0;

        while ( true ) {
            var attempt = c.toString( 36 );
            var data = encoder.encode( nonce + attempt );
            var hashBuffer = await crypto.subtle.digest( 'SHA-256', data );
            var hashArray = new Uint8Array( hashBuffer );
            var hex = '';

            for ( var j = 0; j < hashArray.length; j++ ) {
                hex += ( '0' + hashArray[j].toString( 16 ) ).slice( -2 );
            }

            if ( hex.substring( 0, difficulty ) === prefix ) {
                document.getElementById( 'ua-response' ).value = attempt;
                form.submit();
                return;
            }

            c++;

            // Yield every 1000 iterations to keep UI responsive
            if ( c % 1000 === 0 ) {
                await new Promise( function( r ) { setTimeout( r, 0 ); } );
            }
        }
    }

    // Start after a small delay for visual feedback
    setTimeout( findSolution, 500 );
})();