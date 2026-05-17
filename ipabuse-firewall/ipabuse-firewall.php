<?php
/**
 * Plugin Name: IPAbuse Firewall
 * Plugin URI:  https://ipabuse.org
 * Description: Automatically blocks malicious IPs using the ipabuse.org reputation database. Reports brute-force logins and syncs a daily blocklist.
 * Version:     1.0.0
 * Author:      ipabuse.org
 * Author URI:  https://ipabuse.org
 * License:     GPL-2.0-or-later
 * Text Domain: ipabuse-firewall
 * Requires PHP: 7.4
 * Requires at least: 5.9
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

define( 'IPABUSE_VERSION', '1.0.0' );
define( 'IPABUSE_PLUGIN_FILE', __FILE__ );
define( 'IPABUSE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'IPABUSE_API_BASE', 'https://api.ipabuse.org/v1/plugin' );
define( 'IPABUSE_OPT_PREFIX', 'ipabuse_' );

// ── Autoload classes ──────────────────────────────────────────────────────────
require_once IPABUSE_PLUGIN_DIR . 'includes/class-api-client.php';
require_once IPABUSE_PLUGIN_DIR . 'includes/class-blocker.php';
require_once IPABUSE_PLUGIN_DIR . 'includes/class-reporter.php';
require_once IPABUSE_PLUGIN_DIR . 'admin/settings-page.php';

// ── Activation / deactivation ─────────────────────────────────────────────────
register_activation_hook( __FILE__, 'ipabuse_activate' );
register_deactivation_hook( __FILE__, 'ipabuse_deactivate' );

function ipabuse_activate(): void {
	// Create DB table for blocked IPs.
	global $wpdb;
	$table   = $wpdb->prefix . 'ipabuse_blocked';
	$charset = $wpdb->get_charset_collate();
	$sql     = "CREATE TABLE IF NOT EXISTS {$table} (
		id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		ip          VARCHAR(45)     NOT NULL,
		score       TINYINT UNSIGNED NOT NULL DEFAULT 0,
		blocked_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		UNIQUE KEY ip (ip)
	) {$charset};";
	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	dbDelta( $sql );

	// Schedule cron.
	if ( ! wp_next_scheduled( 'ipabuse_sync_cron' ) ) {
		wp_schedule_event( time(), 'ipabuse_15min', 'ipabuse_sync_cron' );
	}
}

function ipabuse_deactivate(): void {
	wp_clear_scheduled_hook( 'ipabuse_sync_cron' );
}

// ── Custom cron interval (15 minutes) ────────────────────────────────────────
add_filter( 'cron_schedules', function ( array $schedules ): array {
	$schedules['ipabuse_15min'] = [
		'interval' => 900,
		'display'  => __( 'Every 15 Minutes', 'ipabuse-firewall' ),
	];
	return $schedules;
} );

// ── Block incoming IPs on init ────────────────────────────────────────────────
add_action( 'init', function (): void {
	if ( ! ipabuse_opt( 'enabled', '1' ) || ! ipabuse_opt( 'enable_blocking', '1' ) ) {
		return;
	}
	$ip = IPAbuse_Blocker::get_client_ip();
	if ( IPAbuse_Blocker::is_blocked( $ip ) ) {
		wp_die(
			esc_html__( 'Your IP address has been blocked due to suspicious activity.', 'ipabuse-firewall' ),
			esc_html__( 'Access Denied', 'ipabuse-firewall' ),
			[ 'response' => 403 ]
		);
	}
}, 1 );

// ── Report failed logins ──────────────────────────────────────────────────────
add_action( 'wp_login_failed', function ( string $username ): void {
	if ( ! ipabuse_opt( 'enabled', '1' ) || ! ipabuse_opt( 'enable_reporting', '1' ) ) {
		return;
	}
	$ip = IPAbuse_Blocker::get_client_ip();
	IPAbuse_Reporter::report_failed_login( $ip, $username );
}, 10, 1 );

// ── Cron: sync blocklist ──────────────────────────────────────────────────────
add_action( 'ipabuse_sync_cron', function (): void {
	if ( ! ipabuse_opt( 'enabled', '1' ) || ! ipabuse_opt( 'enable_blocking', '1' ) ) {
		return;
	}
	$api_key   = ipabuse_opt( 'api_key', '' );
	$min_score = (int) ipabuse_opt( 'min_score', 75 );
	$limit     = (int) ipabuse_opt( 'limit', 1000 );

	if ( ! $api_key ) {
		return;
	}

	$client = new IPAbuse_Api_Client( $api_key );
	$result = $client->blocklist( $min_score, $limit );

	if ( ! $result['ok'] || empty( $result['data'] ) ) {
		return;
	}

	IPAbuse_Blocker::bulk_block( $result['data'] );
} );

// ── Admin ────────────────────────────────────────────────────────────────────
add_action( 'admin_menu', function (): void {
	add_options_page(
		__( 'IPAbuse Firewall', 'ipabuse-firewall' ),
		__( 'IPAbuse Firewall', 'ipabuse-firewall' ),
		'manage_options',
		'ipabuse-firewall',
		'ipabuse_settings_page'
	);
} );

add_action( 'admin_init', 'ipabuse_register_settings' );

// ── Helpers ───────────────────────────────────────────────────────────────────
function ipabuse_opt( string $key, $default = '' ) {
	return get_option( IPABUSE_OPT_PREFIX . $key, $default );
}
