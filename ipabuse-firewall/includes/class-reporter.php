<?php
/**
 * IPAbuse Firewall — Reporter
 * Submits abuse events to the ipabuse.org API asynchronously using
 * WordPress's non-blocking HTTP requests.
 *
 * Deduplication: each unique (IP, category) pair is reported at most once
 * per DEDUP_TTL seconds using a WordPress transient, so that sustained
 * abuse from one IP doesn't generate thousands of API calls. Deduping per
 * category (not globally per IP) means an IP already reported for
 * BRUTE_FORCE can still be separately reported for SCANNING — different
 * abuse types are independently worth recording.
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

class IPAbuse_Reporter {

	/** Seconds before the same (IP, category) pair can be reported again. */
	private const DEDUP_TTL = HOUR_IN_SECONDS;

	/**
	 * Report a failed login attempt. Thin wrapper around report_abuse() that
	 * just builds the description.
	 *
	 * @param string $ip       Attacker's IP address.
	 * @param string $username Attempted username.
	 * @param string $context  'login' (wp-login.php) or 'xmlrpc' (xmlrpc.php).
	 */
	public static function report_failed_login( string $ip, string $username, string $context = 'login' ): void {
		$description = 'xmlrpc' === $context
			? sprintf( 'WordPress XML-RPC login failure for user "%s"', sanitize_text_field( $username ) )
			: sprintf( 'WordPress login failure for user "%s"', sanitize_text_field( $username ) );

		self::report_abuse( $ip, 'BRUTE_FORCE', $description );
	}

	/**
	 * Report any abuse event to ipabuse.org. Shared by every detector
	 * (failed logins, comment spam, 404 scanning, manual reports from the
	 * admin UI/CLI) so gating (enabled, reporting toggle, API key,
	 * allowlist) and dedup logic live in exactly one place.
	 *
	 * @param string $ip
	 * @param string $category    One of the categories ipabuse.org accepts
	 *                            (SPAM, MALWARE, PHISHING, BRUTE_FORCE, DDoS,
	 *                            BOT, SCANNING, FRAUD, OTHER). An invalid
	 *                            value is rejected API-side and falls back
	 *                            to OTHER there, not here.
	 * @param string $description
	 * @param int    $severity    1–5.
	 */
	public static function report_abuse( string $ip, string $category, string $description, int $severity = 3 ): void {
		// Only valid, non-private/loopback IPs with reporting enabled, an API
		// key configured, and not already reported for this category in the
		// current dedup window are worth sending.
		$is_reportable = '1' === ipabuse_opt( 'enable_reporting', '1' )
			&& filter_var( $ip, FILTER_VALIDATE_IP )
			&& false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE )
			&& '' !== ipabuse_opt( 'api_key', '' )
			&& ! IPAbuse_Blocker::is_allowlisted( $ip );

		if ( ! $is_reportable ) {
			return;
		}

		$transient_key = 'ipabuse_reported_' . $category . '_' . wp_hash( $ip );
		if ( get_transient( $transient_key ) ) {
			return;
		}

		// Mark the IP as reported before dispatch: a non-blocking call returns
		// immediately without a real response (is_wp_error() is essentially
		// never true for it), so there's no delivery confirmation to gate on.
		// Dedup is therefore applied on attempt, not on confirmed delivery.
		set_transient( $transient_key, 1, self::DEDUP_TTL );

		$api_key = ipabuse_opt( 'api_key', '' );

		// Fire-and-forget: non-blocking so the triggering request isn't slowed down.
		wp_remote_post(
			IPABUSE_API_BASE . '/report',
			[
				'timeout'  => 3,
				'blocking' => false,
				'headers'  => [
					'X-API-Key'    => $api_key,
					'Content-Type' => 'application/json',
					'Accept'       => 'application/json',
				],
				'body'     => wp_json_encode( [
					'ip'           => $ip,
					'category'     => $category,
					'description'  => $description,
					'severity'     => $severity,
					'pluginSource' => 'WORDPRESS',
				] ),
			]
		);
	}
}
