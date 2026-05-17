<?php
/**
 * IPAbuse Firewall — Admin Settings Page
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

/** Register all plugin settings. */
function ipabuse_register_settings(): void {
	$opts = [
		'api_key'          => '',
		'enabled'          => '1',
		'enable_blocking'  => '1',
		'enable_reporting' => '1',
		'min_score'        => '75',
		'limit'            => '1000',
	];
	foreach ( $opts as $key => $default ) {
		register_setting(
			'ipabuse_settings',
			IPABUSE_OPT_PREFIX . $key,
			[ 'sanitize_callback' => 'sanitize_text_field', 'default' => $default ]
		);
	}
}

/** Render the settings page. */
function ipabuse_settings_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	// Handle AJAX-style test/sync actions.
	$notice = '';
	if ( isset( $_POST['ipabuse_action'] ) && check_admin_referer( 'ipabuse_action' ) ) {
		$api_key = ipabuse_opt( 'api_key', '' );
		$client  = new IPAbuse_Api_Client( $api_key );
		$action  = sanitize_key( $_POST['ipabuse_action'] );

		if ( $action === 'test' ) {
			$r = $client->verify();
			$notice = $r['ok']
				? '<div class="notice notice-success"><p>Connection successful!</p></div>'
				: '<div class="notice notice-error"><p>Error: ' . esc_html( $r['error'] ?? 'Unknown' ) . '</p></div>';
		} elseif ( $action === 'sync' ) {
			$r = $client->blocklist( (int) ipabuse_opt( 'min_score', 75 ), (int) ipabuse_opt( 'limit', 1000 ) );
			if ( $r['ok'] && ! empty( $r['data'] ) ) {
				IPAbuse_Blocker::bulk_block( $r['data'] );
				$notice = '<div class="notice notice-success"><p>Sync complete. ' . esc_html( count( $r['data'] ) ) . ' IPs processed.</p></div>';
			} else {
				$notice = '<div class="notice notice-error"><p>Sync failed: ' . esc_html( $r['error'] ?? 'Unknown' ) . '</p></div>';
			}
		}
	}
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'IPAbuse Firewall', 'ipabuse-firewall' ); ?></h1>
		<?php echo wp_kses_post( $notice ); ?>

		<div style="display:flex;gap:20px;margin-bottom:16px;align-items:center">
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
			<span>
				<?php /* translators: %d = count */ ?>
				<?php printf( esc_html__( 'Currently blocking %d IPs.', 'ipabuse-firewall' ), IPAbuse_Blocker::count() ); ?>
			</span>
		</div>

		<form method="post" action="options.php">
			<?php settings_fields( 'ipabuse_settings' ); ?>
			<table class="form-table" role="presentation">

				<tr>
					<th scope="row"><label for="ipabuse_api_key"><?php esc_html_e( 'API Key', 'ipabuse-firewall' ); ?></label></th>
					<td>
						<input name="ipabuse_api_key" id="ipabuse_api_key" type="text"
							value="<?php echo esc_attr( ipabuse_opt( 'api_key' ) ); ?>"
							class="regular-text" placeholder="<?php esc_attr_e( 'Enter your ipabuse.org API key', 'ipabuse-firewall' ); ?>" />
						<p class="description">
							<a href="https://ipabuse.org/api-keys" target="_blank" rel="noopener"><?php esc_html_e( 'Generate an API key', 'ipabuse-firewall' ); ?></a>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Enable Plugin', 'ipabuse-firewall' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="ipabuse_enabled" value="1"
								<?php checked( ipabuse_opt( 'enabled', '1' ), '1' ); ?> />
							<?php esc_html_e( 'Master enable/disable switch', 'ipabuse-firewall' ); ?>
						</label>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Auto-Block IPs', 'ipabuse-firewall' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="ipabuse_enable_blocking" value="1"
								<?php checked( ipabuse_opt( 'enable_blocking', '1' ), '1' ); ?> />
							<?php esc_html_e( 'Block IPs from the daily reputation blocklist', 'ipabuse-firewall' ); ?>
						</label>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Report Failed Logins', 'ipabuse-firewall' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="ipabuse_enable_reporting" value="1"
								<?php checked( ipabuse_opt( 'enable_reporting', '1' ), '1' ); ?> />
							<?php esc_html_e( 'Report brute-force login attempts to ipabuse.org', 'ipabuse-firewall' ); ?>
						</label>
					</td>
				</tr>

				<tr>
					<th scope="row"><label for="ipabuse_min_score"><?php esc_html_e( 'Minimum Reputation Score', 'ipabuse-firewall' ); ?></label></th>
					<td>
						<input type="number" name="ipabuse_min_score" id="ipabuse_min_score"
							min="0" max="100" value="<?php echo esc_attr( ipabuse_opt( 'min_score', '75' ) ); ?>" />
						<p class="description"><?php esc_html_e( '0–100. IPs scoring at or above this threshold will be blocked. Default: 75.', 'ipabuse-firewall' ); ?></p>
					</td>
				</tr>

				<tr>
					<th scope="row"><label for="ipabuse_limit"><?php esc_html_e( 'IPs per Sync', 'ipabuse-firewall' ); ?></label></th>
					<td>
						<input type="number" name="ipabuse_limit" id="ipabuse_limit"
							min="100" max="10000" value="<?php echo esc_attr( ipabuse_opt( 'limit', '1000' ) ); ?>" />
					</td>
				</tr>

			</table>
			<?php submit_button(); ?>
		</form>

		<hr />
		<h2><?php esc_html_e( 'IP Reputation Lookup', 'ipabuse-firewall' ); ?></h2>
		<form method="post" id="ipabuse-lookup-form" style="display:flex;gap:10px;align-items:center;margin-bottom:10px">
			<?php wp_nonce_field( 'ipabuse_lookup' ); ?>
			<input type="text" name="lookup_ip" id="lookup_ip" placeholder="1.2.3.4"
				value="<?php echo esc_attr( sanitize_text_field( $_POST['lookup_ip'] ?? '' ) ); ?>"
				style="width:200px" class="regular-text" />
			<input type="submit" class="button button-secondary"
				value="<?php esc_attr_e( 'Lookup', 'ipabuse-firewall' ); ?>" />
		</form>
		<?php
		if ( isset( $_POST['lookup_ip'] ) && check_admin_referer( 'ipabuse_lookup' ) ) {
			$lookup_ip = sanitize_text_field( $_POST['lookup_ip'] );
			if ( filter_var( $lookup_ip, FILTER_VALIDATE_IP ) ) {
				$client = new IPAbuse_Api_Client( ipabuse_opt( 'api_key', '' ) );
				$r      = $client->lookup( $lookup_ip );
				if ( $r['ok'] && ! empty( $r['data'] ) ) {
					$d = $r['data'];
					?>
					<table class="widefat" style="max-width:500px">
						<tr><th><?php esc_html_e( 'IP', 'ipabuse-firewall' ); ?></th><td><?php echo esc_html( $lookup_ip ); ?></td></tr>
						<tr><th><?php esc_html_e( 'Score', 'ipabuse-firewall' ); ?></th><td><?php echo esc_html( $d['reputationScore'] ?? 'N/A' ); ?></td></tr>
						<tr><th><?php esc_html_e( 'Category', 'ipabuse-firewall' ); ?></th><td><?php echo esc_html( $d['category'] ?? 'N/A' ); ?></td></tr>
						<tr><th><?php esc_html_e( 'Reports', 'ipabuse-firewall' ); ?></th><td><?php echo esc_html( $d['totalReports'] ?? 0 ); ?></td></tr>
						<tr><th><?php esc_html_e( 'Country', 'ipabuse-firewall' ); ?></th><td><?php echo esc_html( $d['countryCode'] ?? '—' ); ?></td></tr>
					</table>
					<?php
				} else {
					echo '<p>' . esc_html( $r['error'] ?? __( 'IP not found in database.', 'ipabuse-firewall' ) ) . '</p>';
				}
			} else {
				echo '<p class="description">' . esc_html__( 'Please enter a valid IP address.', 'ipabuse-firewall' ) . '</p>';
			}
		}
		?>
	</div>
	<?php
}
