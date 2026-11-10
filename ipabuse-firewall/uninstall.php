<?php
/**
 * IPAbuse Firewall — Uninstall Script
 * Runs automatically when the plugin is deleted from wp-admin.
 *
 * @package IPAbuse_Firewall
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/** Remove this plugin's options, table, and cron event for the current site. */
function ipabuse_uninstall_site(): void {
	$opts = [
		'api_key', 'enabled', 'enable_blocking', 'enable_reporting', 'enable_alerts',
		'min_score', 'limit', 'allowlist', 'last_sync', 'retention_days', 'blocked_countries',
		'db_version',
	];
	foreach ( $opts as $key ) {
		delete_option( 'ipabuse_' . $key );
	}

	global $wpdb;
	$wpdb->query( 'DROP TABLE IF EXISTS `' . $wpdb->prefix . 'ipabuse_blocked`' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	$wpdb->query( 'DROP TABLE IF EXISTS `' . $wpdb->prefix . 'ipabuse_block_history`' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

	wp_clear_scheduled_hook( 'ipabuse_sync_cron' );
}

if ( is_multisite() ) {
	$site_ids = get_sites( [ 'fields' => 'ids' ] );
	foreach ( $site_ids as $site_id ) {
		switch_to_blog( $site_id );
		ipabuse_uninstall_site();
		restore_current_blog();
	}
} else {
	ipabuse_uninstall_site();
}
