<?php
/**
 * IPAbuse Firewall — Dashboard Page
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

/** Render the dashboard page: status, quick actions, and recently blocked IPs. */
function ipabuse_dashboard_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	$notice      = '';
	$synced_rows = [];

	if ( isset( $_POST['ipabuse_action'] ) && check_admin_referer( 'ipabuse_action' ) ) {
		$api_key = ipabuse_opt( 'api_key', '' );
		$client  = new IPAbuse_Api_Client( $api_key );
		$action  = sanitize_key( $_POST['ipabuse_action'] );

		if ( 'test' === $action ) {
			$r = $client->verify();
			$notice = $r['ok']
				? '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Connection successful!', 'ipabuse-firewall' ) . '</p></div>'
				: '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Error:', 'ipabuse-firewall' ) . ' ' . esc_html( $r['error'] ?? 'Unknown' ) . '</p></div>';
		} elseif ( 'sync' === $action ) {
			// Runs the exact same full sync routine as the 15-minute cron
			// (fetch, bulk-block, prune missing/expired, country blocklist),
			// not a partial subset of it.
			$r = ipabuse_run_sync();
			if ( $r['ok'] ) {
				/* translators: %d = number of IPs processed */
				$notice = '<div class="notice notice-success is-dismissible"><p>' . esc_html( sprintf( __( 'Sync complete. %d IPs processed.', 'ipabuse-firewall' ), count( $r['items'] ) ) ) . '</p></div>';

				// Show exactly which IPs this sync touched, not just a count.
				foreach ( array_slice( $r['items'], 0, 20 ) as $item ) {
					$ip    = is_string( $item ) ? $item : ( $item['ipAddress'] ?? '' );
					$score = is_array( $item ) ? (int) ( $item['reputationScore'] ?? 0 ) : 0;
					if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
						$synced_rows[] = [ 'ip' => $ip, 'score' => $score ];
					}
				}
			} else {
				$notice = '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Sync failed:', 'ipabuse-firewall' ) . ' ' . esc_html( $r['error'] ?? 'Unknown' ) . '</p></div>';
			}
		}
	}

	$recent = IPAbuse_Blocker::list_blocked( 10, 1 );
	?>
	<div class="wrap ipabuse-wrap">
		<?php
		ipabuse_render_page_header( __( 'IPAbuse Firewall', 'ipabuse-firewall' ) );
		echo wp_kses_post( $notice );
		ipabuse_render_status_banner();
		?>

		<div class="ipabuse-card">
			<h2 class="ipabuse-card-title">
				<span class="dashicons dashicons-admin-network" aria-hidden="true"></span>
				<?php esc_html_e( 'Connection', 'ipabuse-firewall' ); ?>
			</h2>
			<div class="ipabuse-actions-row">
				<form method="post">
					<?php wp_nonce_field( 'ipabuse_action' ); ?>
					<input type="hidden" name="ipabuse_action" value="test" />
					<?php submit_button( __( 'Test Connection', 'ipabuse-firewall' ), 'secondary', 'submit', false ); ?>
				</form>
				<form method="post">
					<?php wp_nonce_field( 'ipabuse_action' ); ?>
					<input type="hidden" name="ipabuse_action" value="sync" />
					<?php submit_button( __( 'Sync Now', 'ipabuse-firewall' ), 'secondary', 'submit', false ); ?>
				</form>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . IPABUSE_MENU_SLUG . '-settings' ) ); ?>" class="button">
					<?php esc_html_e( 'Settings', 'ipabuse-firewall' ); ?>
				</a>
			</div>

			<?php if ( ! empty( $synced_rows ) ) : ?>
				<h3><?php esc_html_e( 'IPs processed in this sync', 'ipabuse-firewall' ); ?></h3>
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'IP', 'ipabuse-firewall' ); ?></th>
							<th><?php esc_html_e( 'Score', 'ipabuse-firewall' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $synced_rows as $row ) : ?>
							<tr>
								<td><?php echo wp_kses_post( ipabuse_ip_lookup_link( $row['ip'] ) ); ?></td>
								<td>
									<span class="ipabuse-badge <?php echo esc_attr( ipabuse_score_badge_class( $row['score'] ) ); ?>">
										<?php echo esc_html( (string) $row['score'] ); ?>
									</span>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<p class="description">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . IPABUSE_MENU_SLUG . '-blocked' ) ); ?>">
						<?php esc_html_e( 'View all blocked IPs →', 'ipabuse-firewall' ); ?>
					</a>
				</p>
			<?php endif; ?>
		</div>

		<div class="ipabuse-card">
			<h2 class="ipabuse-card-title">
				<span class="dashicons dashicons-list-view" aria-hidden="true"></span>
				<?php esc_html_e( 'Recently Blocked IPs', 'ipabuse-firewall' ); ?>
			</h2>
			<?php if ( empty( $recent['items'] ) ) : ?>
				<p class="description"><?php esc_html_e( 'No IPs are currently blocked.', 'ipabuse-firewall' ); ?></p>
			<?php else : ?>
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'IP', 'ipabuse-firewall' ); ?></th>
							<th><?php esc_html_e( 'Score', 'ipabuse-firewall' ); ?></th>
							<th><?php esc_html_e( 'Blocked At (UTC)', 'ipabuse-firewall' ); ?></th>
							<th><?php esc_html_e( 'Expires (UTC)', 'ipabuse-firewall' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $recent['items'] as $row ) : ?>
							<tr>
								<td><?php echo wp_kses_post( ipabuse_ip_lookup_link( $row['ip'] ) ); ?></td>
								<td>
									<span class="ipabuse-badge <?php echo esc_attr( ipabuse_score_badge_class( (int) $row['score'] ) ); ?>">
										<?php echo esc_html( $row['score'] ); ?>
									</span>
								</td>
								<td><?php echo esc_html( $row['blocked_at'] ); ?></td>
								<td>
									<?php echo '0000-00-00 00:00:00' === $row['expires_at']
										? esc_html__( 'Permanent', 'ipabuse-firewall' )
										: esc_html( $row['expires_at'] ); ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<p class="description">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . IPABUSE_MENU_SLUG . '-blocked' ) ); ?>">
						<?php esc_html_e( 'View all blocked IPs →', 'ipabuse-firewall' ); ?>
					</a>
				</p>
			<?php endif; ?>
		</div>
	</div>
	<?php
}
