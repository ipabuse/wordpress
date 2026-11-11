<?php
/**
 * IPAbuse Firewall — WP-CLI Commands
 *
 * `wp ipabuse block <ip>`
 * `wp ipabuse unblock <ip>`
 * `wp ipabuse sync`
 * `wp ipabuse status`
 * `wp ipabuse clear-cache`
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

/**
 * Manage the IPAbuse Firewall blocklist from the command line.
 */
class IPAbuse_CLI_Command {

	/**
	 * Block an IP address permanently.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address to block.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ipabuse block 203.0.113.5
	 */
	public function block( array $args ): void {
		[ $ip ] = $args;
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			WP_CLI::error( "Invalid IP address: {$ip}" );
		}
		IPAbuse_Blocker::block( $ip, 100, 0 );
		WP_CLI::success( "Blocked {$ip}." );
	}

	/**
	 * Unblock an IP address.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address to unblock.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ipabuse unblock 203.0.113.5
	 */
	public function unblock( array $args ): void {
		[ $ip ] = $args;
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			WP_CLI::error( "Invalid IP address: {$ip}" );
		}
		IPAbuse_Blocker::unblock( $ip );
		WP_CLI::success( "Unblocked {$ip}." );
	}

	/**
	 * Report an IP address to ipabuse.org.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address to report.
	 *
	 * [--category=<category>]
	 * : Abuse category. One of: SPAM, MALWARE, PHISHING, BRUTE_FORCE, DDoS, BOT, SCANNING, FRAUD, OTHER.
	 * ---
	 * default: OTHER
	 * ---
	 *
	 * [--description=<description>]
	 * : Optional description of the abuse.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ipabuse report 203.0.113.5 --category=SCANNING --description="Probing wp-config.php.bak"
	 */
	public function report( array $args, array $assoc_args ): void {
		[ $ip ] = $args;
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			WP_CLI::error( "Invalid IP address: {$ip}" );
		}

		$api_key = ipabuse_opt( 'api_key', '' );
		if ( ! $api_key ) {
			WP_CLI::error( 'No API key configured.' );
		}

		$category = $assoc_args['category'] ?? 'OTHER';
		if ( ! in_array( $category, ipabuse_report_categories(), true ) ) {
			WP_CLI::error( 'Invalid category. Must be one of: ' . implode( ', ', ipabuse_report_categories() ) );
		}

		$client = new IPAbuse_Api_Client( $api_key );
		$r      = $client->report( $ip, $category, $assoc_args['description'] ?? 'Manually reported via WP-CLI', 3 );

		if ( ! $r['ok'] ) {
			WP_CLI::error( 'Report failed: ' . ( $r['error'] ?? 'unknown error' ) );
		}

		WP_CLI::success( "Reported {$ip} as {$category}." );
	}

	/**
	 * Run a blocklist sync against ipabuse.org now.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ipabuse sync
	 */
	public function sync(): void {
		// Runs the same full sync routine as the cron job and the "Sync Now"
		// button: fetch, bulk-block, prune missing/expired, country blocklist.
		$r = ipabuse_run_sync();

		if ( ! $r['ok'] ) {
			WP_CLI::error( 'Sync failed: ' . $r['error'] );
		}

		WP_CLI::success( sprintf( 'Synced %d IPs.', count( $r['items'] ) ) );
	}

	/**
	 * Show current plugin status.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ipabuse status
	 */
	public function status(): void {
		WP_CLI\Utils\format_items( 'table', [ [
			'enabled'       => '1' === ipabuse_opt( 'enabled', '1' ) ? 'yes' : 'no',
			'blocking'      => '1' === ipabuse_opt( 'enable_blocking', '1' ) ? 'yes' : 'no',
			'reporting'     => '1' === ipabuse_opt( 'enable_reporting', '1' ) ? 'yes' : 'no',
			'api_connected' => '' !== ipabuse_opt( 'api_key', '' ) ? 'yes' : 'no',
			'blocked_count' => IPAbuse_Blocker::count(),
			'last_sync'     => ( (int) ipabuse_opt( 'last_sync', 0 ) ) > 0
				? gmdate( 'Y-m-d H:i:s', (int) ipabuse_opt( 'last_sync', 0 ) ) . ' UTC'
				: 'never',
		] ], [ 'enabled', 'blocking', 'reporting', 'api_connected', 'blocked_count', 'last_sync' ] );
	}

	/**
	 * Flush this plugin's object cache (is_blocked() results and the total
	 * blocked-IP count). Useful after restoring a DB backup or switching
	 * object-cache backends, when the cache may no longer match the DB.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ipabuse clear-cache
	 */
	public function clear_cache(): void {
		IPAbuse_Blocker::clear_cache();
		WP_CLI::success( 'Cache cleared.' );
	}
}

WP_CLI::add_command( 'ipabuse', 'IPAbuse_CLI_Command' );
