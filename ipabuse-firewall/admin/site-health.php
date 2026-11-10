<?php
/**
 * IPAbuse Firewall — Site Health Integration
 *
 * Surfaces plugin status under Tools → Site Health → Info, so support and
 * debugging don't require visiting the plugin's own admin pages.
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

add_filter( 'debug_information', 'ipabuse_site_health_debug_info' );

/**
 * Add an "IPAbuse Firewall" section to Site Health → Info.
 *
 * @param  array $info
 * @return array
 */
function ipabuse_site_health_debug_info( array $info ): array {
	$last_sync = (int) ipabuse_opt( 'last_sync', 0 );

	$info['ipabuse-firewall'] = [
		'label'  => __( 'IPAbuse Firewall', 'ipabuse-firewall' ),
		'fields' => [
			'version'          => [
				'label' => __( 'Plugin version', 'ipabuse-firewall' ),
				'value' => IPABUSE_VERSION,
			],
			'enabled'          => [
				'label' => __( 'Protection enabled', 'ipabuse-firewall' ),
				'value' => '1' === ipabuse_opt( 'enabled', '1' ) ? __( 'Yes', 'ipabuse-firewall' ) : __( 'No', 'ipabuse-firewall' ),
			],
			'api_connected'    => [
				'label' => __( 'API key configured', 'ipabuse-firewall' ),
				'value' => '' !== ipabuse_opt( 'api_key', '' ) ? __( 'Yes', 'ipabuse-firewall' ) : __( 'No', 'ipabuse-firewall' ),
			],
			'blocking'         => [
				'label' => __( 'Auto-blocking enabled', 'ipabuse-firewall' ),
				'value' => '1' === ipabuse_opt( 'enable_blocking', '1' ) ? __( 'Yes', 'ipabuse-firewall' ) : __( 'No', 'ipabuse-firewall' ),
			],
			'reporting'        => [
				'label' => __( 'Report failed logins', 'ipabuse-firewall' ),
				'value' => '1' === ipabuse_opt( 'enable_reporting', '1' ) ? __( 'Yes', 'ipabuse-firewall' ) : __( 'No', 'ipabuse-firewall' ),
			],
			'blocked_count'    => [
				'label' => __( 'IPs currently blocked', 'ipabuse-firewall' ),
				'value' => number_format_i18n( IPAbuse_Blocker::count() ),
			],
			'last_sync'        => [
				'label' => __( 'Last blocklist sync', 'ipabuse-firewall' ),
				'value' => $last_sync > 0
					? gmdate( 'Y-m-d H:i:s', $last_sync ) . ' UTC'
					: __( 'Never', 'ipabuse-firewall' ),
			],
			'retention_days'   => [
				'label' => __( 'Retention period (days)', 'ipabuse-firewall' ),
				'value' => ipabuse_opt( 'retention_days', '365' ),
			],
			'cron_scheduled'   => [
				'label' => __( 'Sync cron scheduled', 'ipabuse-firewall' ),
				'value' => wp_next_scheduled( 'ipabuse_sync_cron' )
					? __( 'Yes', 'ipabuse-firewall' )
					: __( 'No', 'ipabuse-firewall' ),
			],
		],
	];

	return $info;
}
