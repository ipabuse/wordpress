<?php
/**
 * IPAbuse Firewall — wp-admin Dashboard Widget
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

add_action( 'wp_dashboard_setup', 'ipabuse_register_dashboard_widget' );

/** Register the "IPAbuse Firewall" summary widget on the main wp-admin dashboard. */
function ipabuse_register_dashboard_widget(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	wp_add_dashboard_widget(
		'ipabuse_dashboard_widget',
		__( 'IPAbuse Firewall', 'ipabuse-firewall' ),
		'ipabuse_render_dashboard_widget'
	);
}

/** Render the dashboard widget content. */
function ipabuse_render_dashboard_widget(): void {
	$is_enabled    = '1' === ipabuse_opt( 'enabled', '1' );
	$has_api_key   = '' !== ipabuse_opt( 'api_key', '' );
	$blocked_count = IPAbuse_Blocker::count();
	$last_sync     = (int) ipabuse_opt( 'last_sync', 0 );
	?>
	<div class="ipabuse-widget">
		<div class="ipabuse-widget-status <?php echo $is_enabled ? 'is-active' : 'is-inactive'; ?>">
			<span class="dashicons dashicons-<?php echo $is_enabled ? 'yes-alt' : 'warning'; ?>" aria-hidden="true"></span>
			<?php echo $is_enabled
				? esc_html__( 'Protection Active', 'ipabuse-firewall' )
				: esc_html__( 'Protection Disabled', 'ipabuse-firewall' ); ?>
		</div>

		<ul class="ipabuse-widget-stats">
			<li>
				<span class="ipabuse-widget-stat-value"><?php echo esc_html( number_format_i18n( $blocked_count ) ); ?></span>
				<span class="ipabuse-widget-stat-label"><?php esc_html_e( 'IPs Blocked', 'ipabuse-firewall' ); ?></span>
			</li>
			<li>
				<span class="ipabuse-widget-stat-value">
					<?php echo $has_api_key ? esc_html__( 'Yes', 'ipabuse-firewall' ) : esc_html__( 'No', 'ipabuse-firewall' ); ?>
				</span>
				<span class="ipabuse-widget-stat-label"><?php esc_html_e( 'API Connected', 'ipabuse-firewall' ); ?></span>
			</li>
			<li>
				<span class="ipabuse-widget-stat-value">
					<?php echo $last_sync > 0
						? esc_html( human_time_diff( $last_sync, time() ) . ' ' . __( 'ago', 'ipabuse-firewall' ) )
						: esc_html__( 'Never', 'ipabuse-firewall' ); ?>
				</span>
				<span class="ipabuse-widget-stat-label"><?php esc_html_e( 'Last Synced', 'ipabuse-firewall' ); ?></span>
			</li>
		</ul>

		<div class="ipabuse-widget-trend">
			<span class="ipabuse-widget-trend-label"><?php esc_html_e( 'Blocks, last 24h', 'ipabuse-firewall' ); ?></span>
			<?php echo ipabuse_render_sparkline( IPAbuse_Blocker::hourly_block_counts( 24 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- geometry only, built from integers in ipabuse_render_sparkline(). ?>
		</div>

		<p class="ipabuse-widget-footer">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . IPABUSE_MENU_SLUG ) ); ?>" class="button button-primary">
				<?php esc_html_e( 'View Dashboard', 'ipabuse-firewall' ); ?>
			</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . IPABUSE_MENU_SLUG . '-blocked' ) ); ?>">
				<?php esc_html_e( 'Blocked IPs', 'ipabuse-firewall' ); ?>
			</a>
		</p>
	</div>
	<?php
}
