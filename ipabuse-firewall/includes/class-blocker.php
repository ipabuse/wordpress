<?php
/**
 * IPAbuse Firewall — IP Blocker
 * Stores blocked IPs in the database and provides helper methods.
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

class IPAbuse_Blocker {

	/** Return the current visitor's real IP. */
	public static function get_client_ip(): string {
		$candidates = [
			'HTTP_CF_CONNECTING_IP', // Cloudflare
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		];
		foreach ( $candidates as $key ) {
			$val = $_SERVER[ $key ] ?? '';
			$ip  = filter_var( trim( explode( ',', $val )[0] ), FILTER_VALIDATE_IP );
			if ( $ip ) {
				return $ip;
			}
		}
		return '0.0.0.0';
	}

	/** Check if the given IP is in the blocked list. */
	public static function is_blocked( string $ip ): bool {
		// Whitelist: never block loopback or admin's own IP.
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false ) {
			return false;
		}

		global $wpdb;
		$table  = $wpdb->prefix . 'ipabuse_blocked';
		$exists = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM `{$table}` WHERE ip = %s LIMIT 1", $ip ) ); // phpcs:ignore
		return ! empty( $exists );
	}

	/**
	 * Block a single IP.
	 *
	 * @param string $ip
	 * @param int    $score  0–100
	 */
	public static function block( string $ip, int $score = 0 ): void {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'ipabuse_blocked';
		$wpdb->query( $wpdb->prepare(
			"INSERT INTO `{$table}` (ip, score, blocked_at) VALUES (%s, %d, NOW()) ON DUPLICATE KEY UPDATE score = VALUES(score)", // phpcs:ignore
			$ip,
			$score
		) );
	}

	/** Bulk-block IPs from an API blocklist response. */
	public static function bulk_block( array $items ): void {
		foreach ( $items as $item ) {
			$ip    = is_string( $item ) ? $item : ( $item['ipAddress'] ?? '' );
			$score = is_array( $item ) ? (int) ( $item['reputationScore'] ?? 0 ) : 0;
			self::block( $ip, $score );
		}
	}

	/** Unblock a single IP. */
	public static function unblock( string $ip ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'ipabuse_blocked';
		$wpdb->delete( $table, [ 'ip' => $ip ], [ '%s' ] );
	}

	/** Return total blocked IP count. */
	public static function count(): int {
		global $wpdb;
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM `' . $wpdb->prefix . 'ipabuse_blocked`' ); // phpcs:ignore
	}
}
