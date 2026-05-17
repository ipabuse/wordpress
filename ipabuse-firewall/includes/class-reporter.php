<?php
/**
 * IPAbuse Firewall — Reporter
 * Submits abuse events to the ipabuse.org API asynchronously using
 * WordPress's non-blocking HTTP requests.
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

class IPAbuse_Reporter {

	/**
	 * Report a failed login attempt.
	 *
	 * @param string $ip       Attacker's IP address.
	 * @param string $username Attempted username.
	 */
	public static function report_failed_login( string $ip, string $username ): void {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}
		// Skip private/loopback ranges.
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false ) {
			return;
		}

		$api_key = ipabuse_opt( 'api_key', '' );
		if ( ! $api_key ) {
			return;
		}

		$client = new IPAbuse_Api_Client( $api_key );
		// Fire-and-forget using a short timeout.
		wp_remote_post( IPABUSE_API_BASE . '/report', [
			'timeout'   => 3,
			'blocking'  => false, // non-blocking
			'headers'   => [
				'X-API-Key'    => $api_key,
				'Content-Type' => 'application/json',
			],
			'body'      => wp_json_encode( [
				'ip'          => $ip,
				'category'    => 'BRUTE_FORCE',
				'description' => sprintf( 'WordPress login failure for user "%s"', sanitize_text_field( $username ) ),
				'severity'    => 3,
			] ),
		] );
	}
}
