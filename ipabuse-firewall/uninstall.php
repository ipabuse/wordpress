<?php
/**
 * IPAbuse Firewall — Uninstall Script
 * Runs automatically when the plugin is deleted from wp-admin.
 *
 * @package IPAbuse_Firewall
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Remove all plugin options.
$opts = [
	'api_key', 'enabled', 'enable_blocking', 'enable_reporting',
	'min_score', 'limit',
];
foreach ( $opts as $key ) {
	delete_option( 'ipabuse_' . $key );
}

// Drop the blocked IPs table.
global $wpdb;
$wpdb->query( 'DROP TABLE IF EXISTS `' . $wpdb->prefix . 'ipabuse_blocked`' ); // phpcs:ignore

// Clear any scheduled cron events.
wp_clear_scheduled_hook( 'ipabuse_sync_cron' );
