<?php
/**
 * IPAbuse Firewall — REST API Status Endpoint
 *
 * Exposes GET /wp-json/ipabuse-firewall/v1/status for external monitoring
 * (uptime checks, dashboards) to confirm the plugin is active and healthy
 * without needing admin UI access.
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

add_action( 'rest_api_init', 'ipabuse_register_rest_routes' );

/** Register the plugin's REST API routes. */
function ipabuse_register_rest_routes(): void {
	register_rest_route( 'ipabuse-firewall/v1', '/status', [
		'methods'             => 'GET',
		'callback'            => 'ipabuse_rest_status',
		'permission_callback' => fn() => current_user_can( 'manage_options' ),
	] );
}

/**
 * REST callback: current plugin status for monitoring.
 *
 * @param  WP_REST_Request $request
 * @return WP_REST_Response
 */
function ipabuse_rest_status( WP_REST_Request $request ): WP_REST_Response {
	return rest_ensure_response( [
		'enabled'          => '1' === ipabuse_opt( 'enabled', '1' ),
		'blocking_enabled' => '1' === ipabuse_opt( 'enable_blocking', '1' ),
		'reporting_enabled' => '1' === ipabuse_opt( 'enable_reporting', '1' ),
		'api_connected'    => '' !== ipabuse_opt( 'api_key', '' ),
		'blocked_count'    => IPAbuse_Blocker::count(),
		'last_sync'        => (int) ipabuse_opt( 'last_sync', 0 ),
	] );
}
