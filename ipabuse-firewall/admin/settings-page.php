<?php
/**
 * IPAbuse Firewall — Settings Page
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

add_action( 'admin_post_ipabuse_clear_all', 'ipabuse_handle_clear_all' );

/** Handle the "Clear All Blocked IPs" danger-zone action. */
function ipabuse_handle_clear_all(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Permission denied.', 'ipabuse-firewall' ), '', [ 'response' => 403 ] );
	}
	check_admin_referer( 'ipabuse_clear_all' );

	$count = 0;
	if ( isset( $_POST['ipabuse_confirm_clear_all'] ) ) {
		$count = IPAbuse_Blocker::clear_all();
	}

	$redirect = add_query_arg( 'ipabuse_cleared', $count, admin_url( 'admin.php?page=' . IPABUSE_MENU_SLUG . '-settings' ) );
	wp_safe_redirect( $redirect );
	exit;
}

add_action( 'admin_post_ipabuse_clear_cache', 'ipabuse_handle_clear_cache' );

/** Handle the "Clear Cache" danger-zone action. */
function ipabuse_handle_clear_cache(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Permission denied.', 'ipabuse-firewall' ), '', [ 'response' => 403 ] );
	}
	check_admin_referer( 'ipabuse_clear_cache' );

	IPAbuse_Blocker::clear_cache();

	$redirect = add_query_arg( 'ipabuse_cache_cleared', '1', admin_url( 'admin.php?page=' . IPABUSE_MENU_SLUG . '-settings' ) );
	wp_safe_redirect( $redirect );
	exit;
}

/** Register all plugin settings. */
function ipabuse_register_settings(): void {
	$opts = [
		'enabled'          => '1',
		'enable_blocking'  => '1',
		'enable_reporting' => '1',
		'enable_alerts'    => '1',
		'min_score'        => '75',
		'limit'            => '1000',
		'retention_days'   => '365',
	];
	foreach ( $opts as $key => $default ) {
		register_setting(
			'ipabuse_settings',
			IPABUSE_OPT_PREFIX . $key,
			[ 'sanitize_callback' => 'sanitize_text_field', 'default' => $default ]
		);
	}

	register_setting(
		'ipabuse_settings',
		IPABUSE_OPT_PREFIX . 'api_key',
		[ 'sanitize_callback' => 'ipabuse_sanitize_api_key', 'default' => '' ]
	);

	register_setting(
		'ipabuse_settings',
		IPABUSE_OPT_PREFIX . 'allowlist',
		[ 'sanitize_callback' => 'ipabuse_sanitize_allowlist', 'default' => '' ]
	);

	register_setting(
		'ipabuse_settings',
		IPABUSE_OPT_PREFIX . 'blocked_countries',
		[ 'sanitize_callback' => 'ipabuse_sanitize_country_list', 'default' => '' ]
	);
}

/**
 * Sanitize a comma-separated list of ISO 3166-1 alpha-2 country codes into
 * a normalized, deduplicated, comma-separated uppercase string.
 *
 * @param  string $raw
 * @return string
 */
function ipabuse_sanitize_country_list( string $raw ): string {
	$codes = array_map( 'trim', explode( ',', strtoupper( $raw ) ) );
	$valid = array_unique( array_filter( $codes, fn( $code ) => (bool) preg_match( '/^[A-Z]{2}$/', $code ) ) );
	return implode( ', ', $valid );
}

/** List of option keys included in settings export/import. Deliberately excludes api_key. */
function ipabuse_exportable_option_keys(): array {
	return [
		'enabled', 'enable_blocking', 'enable_reporting', 'enable_alerts',
		'min_score', 'limit', 'retention_days', 'allowlist', 'blocked_countries',
	];
}

add_action( 'admin_post_ipabuse_export_settings', 'ipabuse_export_settings' );

/** Stream the plugin's settings (excluding the API key) as a downloadable JSON file. */
function ipabuse_export_settings(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Permission denied.', 'ipabuse-firewall' ), '', [ 'response' => 403 ] );
	}
	check_admin_referer( 'ipabuse_export_settings' );

	$data = [];
	foreach ( ipabuse_exportable_option_keys() as $key ) {
		$data[ $key ] = ipabuse_opt( $key, '' );
	}

	nocache_headers();
	header( 'Content-Type: application/json; charset=utf-8' );
	header( 'Content-Disposition: attachment; filename=ipabuse-firewall-settings-' . gmdate( 'Y-m-d' ) . '.json' );
	// Not HTML — this is a downloadable JSON file, so esc_html() would corrupt
	// it. Content is wp_json_encode() of this plugin's own stored option
	// values only (no api_key, no user input), so there is no injection surface.
	echo wp_json_encode( $data, JSON_PRETTY_PRINT ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	exit;
}

/**
 * Import settings from an uploaded JSON file (as produced by ipabuse_export_settings()).
 * Only keys in ipabuse_exportable_option_keys() are accepted; everything else
 * (including any api_key the file might contain) is ignored.
 *
 * @return string  Empty on success, otherwise a human-readable error.
 */
function ipabuse_import_settings_from_upload(): string {
	// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- nonce already verified by check_admin_referer( 'ipabuse_import_settings' ) in the only caller, before this function runs; is_uploaded_file() below is the real safeguard against an arbitrary path.
	$tmp_name = $_FILES['ipabuse_import_file']['tmp_name'] ?? '';
	if ( empty( $tmp_name ) || ! is_uploaded_file( $tmp_name ) ) {
		return __( 'Please choose a settings file to upload.', 'ipabuse-firewall' );
	}
	// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- same as above; size is only ever compared numerically.
	if ( (int) ( $_FILES['ipabuse_import_file']['size'] ?? 0 ) > 100 * 1024 ) {
		return __( 'File is too large to be a valid settings export.', 'ipabuse-firewall' );
	}

	$contents = file_get_contents( $tmp_name ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- tmp_name is PHP's own validated upload path (is_uploaded_file() above), not user-supplied.
	$data     = json_decode( (string) $contents, true );

	if ( ! is_array( $data ) ) {
		return __( 'That file is not a valid IPAbuse Firewall settings export.', 'ipabuse-firewall' );
	}

	$sanitizers = [
		'enabled'           => 'sanitize_text_field',
		'enable_blocking'   => 'sanitize_text_field',
		'enable_reporting'  => 'sanitize_text_field',
		'enable_alerts'     => 'sanitize_text_field',
		'min_score'         => fn( $v ) => (string) max( 0, min( 100, (int) $v ) ),
		'limit'             => fn( $v ) => (string) max( 100, min( 10000, (int) $v ) ),
		'retention_days'    => fn( $v ) => (string) max( 0, min( 3650, (int) $v ) ),
		'allowlist'         => 'ipabuse_sanitize_allowlist',
		'blocked_countries' => 'ipabuse_sanitize_country_list',
	];

	foreach ( ipabuse_exportable_option_keys() as $key ) {
		if ( ! array_key_exists( $key, $data ) || ! is_scalar( $data[ $key ] ) ) {
			continue;
		}
		$sanitizer = $sanitizers[ $key ];
		update_option( IPABUSE_OPT_PREFIX . $key, call_user_func( $sanitizer, (string) $data[ $key ] ) );
	}

	return '';
}

/**
 * Sanitize the API key field, preserving the existing stored key when the
 * field is submitted empty (e.g. the settings form was saved without
 * re-entering it) rather than overwriting it with a blank value.
 *
 * @param  string $raw
 * @return string
 */
function ipabuse_sanitize_api_key( string $raw ): string {
	$raw = sanitize_text_field( $raw );
	return '' !== $raw ? $raw : ipabuse_opt( 'api_key', '' );
}

/**
 * Sanitize the allowlist textarea into one valid IP per line.
 * Invalid lines (bad IPs, blanks) are silently dropped.
 *
 * @param  string $raw
 * @return string
 */
function ipabuse_sanitize_allowlist( string $raw ): string {
	$lines = array_filter( array_map( 'trim', explode( "\n", $raw ) ) );
	$valid = array_filter( $lines, fn( $line ) => false !== filter_var( $line, FILTER_VALIDATE_IP ) );
	return implode( "\n", $valid );
}

/** Render the Settings page: API key, protection toggles, allowlist, and data tools. */
function ipabuse_settings_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	$import_notice = '';
	if ( isset( $_POST['ipabuse_import_submit'] ) && check_admin_referer( 'ipabuse_import_settings' ) ) {
		$error = ipabuse_import_settings_from_upload();
		$import_notice = $error
			? '<div class="notice notice-error is-dismissible"><p>' . esc_html( $error ) . '</p></div>'
			: '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Settings imported successfully.', 'ipabuse-firewall' ) . '</p></div>';
	}

	$cleared_notice = '';
	if ( isset( $_GET['ipabuse_cleared'] ) ) {
		$cleared = (int) $_GET['ipabuse_cleared'];
		$cleared_notice = $cleared > 0
			/* translators: %d = number of IPs unblocked */
			? '<div class="notice notice-success is-dismissible"><p>' . esc_html( sprintf( __( 'Cleared %d blocked IPs.', 'ipabuse-firewall' ), $cleared ) ) . '</p></div>'
			: '<div class="notice notice-warning is-dismissible"><p>' . esc_html__( 'Nothing was cleared — confirmation checkbox was not checked.', 'ipabuse-firewall' ) . '</p></div>';
	}

	$cache_cleared_notice = isset( $_GET['ipabuse_cache_cleared'] )
		? '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Cache cleared.', 'ipabuse-firewall' ) . '</p></div>'
		: '';
	?>
	<div class="wrap ipabuse-wrap">
		<?php
		ipabuse_render_page_header( __( 'IPAbuse Firewall Settings', 'ipabuse-firewall' ), 'admin-generic' );
		echo wp_kses_post( $import_notice );
		echo wp_kses_post( $cleared_notice );
		echo wp_kses_post( $cache_cleared_notice );
		if ( '' === ipabuse_opt( 'api_key', '' ) ) {
			ipabuse_render_connect_wizard_modal();
		}
		?>

		<form method="post" action="options.php">
			<?php settings_fields( 'ipabuse_settings' ); ?>

			<div class="ipabuse-card">
				<h2 class="ipabuse-card-title">
					<span class="dashicons dashicons-admin-generic" aria-hidden="true"></span>
					<?php esc_html_e( 'API & Protection Settings', 'ipabuse-firewall' ); ?>
				</h2>
				<table class="form-table" role="presentation">

					<tr>
						<th scope="row"><label for="ipabuse_api_key"><?php esc_html_e( 'API Key', 'ipabuse-firewall' ); ?></label></th>
						<td>
							<input name="ipabuse_api_key" id="ipabuse_api_key" type="password" autocomplete="off"
								value="<?php echo esc_attr( ipabuse_opt( 'api_key' ) ); ?>"
								class="regular-text" placeholder="<?php esc_attr_e( 'Enter your ipabuse.org API key', 'ipabuse-firewall' ); ?>" />
							<p class="description">
								<a href="https://www.ipabuse.org/settings?tab=api" target="_blank" rel="noopener"><?php esc_html_e( 'Generate an API key', 'ipabuse-firewall' ); ?></a>
								<?php if ( '' === ipabuse_opt( 'api_key', '' ) ) : ?>
									&mdash;
									<?php esc_html_e( "don't have an account yet?", 'ipabuse-firewall' ); ?>
									<button type="button" class="button-link ipabuse-connect-trigger"><?php esc_html_e( 'Connect Your Account', 'ipabuse-firewall' ); ?></button>
								<?php endif; ?>
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
						<th scope="row"><?php esc_html_e( 'Email Attack Alerts', 'ipabuse-firewall' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="ipabuse_enable_alerts" value="1"
									<?php checked( ipabuse_opt( 'enable_alerts', '1' ), '1' ); ?> />
								<?php esc_html_e( 'Email the site admin when a possible coordinated brute-force attack is detected', 'ipabuse-firewall' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'Sent at most once every 6 hours, to the WordPress admin email address.', 'ipabuse-firewall' ); ?></p>
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
			</div>

			<div class="ipabuse-card">
				<h2 class="ipabuse-card-title">
					<span class="dashicons dashicons-database" aria-hidden="true"></span>
					<?php esc_html_e( 'Data Retention', 'ipabuse-firewall' ); ?>
				</h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="ipabuse_retention_days"><?php esc_html_e( 'Retention Period (days)', 'ipabuse-firewall' ); ?></label></th>
						<td>
							<input type="number" name="ipabuse_retention_days" id="ipabuse_retention_days"
								min="0" max="3650" value="<?php echo esc_attr( ipabuse_opt( 'retention_days', '365' ) ); ?>" />
							<p class="description"><?php esc_html_e( 'Blocked-IP records older than this are automatically deleted on the next sync, regardless of whether they\'re still active. Set to 0 to keep records indefinitely. Default: 365.', 'ipabuse-firewall' ); ?></p>
						</td>
					</tr>
				</table>
			</div>

			<div class="ipabuse-card">
				<h2 class="ipabuse-card-title">
					<span class="dashicons dashicons-groups" aria-hidden="true"></span>
					<?php esc_html_e( 'Trusted IPs (Allowlist)', 'ipabuse-firewall' ); ?>
				</h2>
				<label for="ipabuse_allowlist" class="screen-reader-text"><?php esc_html_e( 'Trusted IPs (Allowlist)', 'ipabuse-firewall' ); ?></label>
				<textarea name="ipabuse_allowlist" id="ipabuse_allowlist" rows="5"
					class="large-text code"><?php echo esc_textarea( ipabuse_opt( 'allowlist', '' ) ); ?></textarea>
				<p class="description"><?php esc_html_e( 'One IP address per line. These IPs are never blocked or reported, even if flagged by ipabuse.org or local rate-limiting.', 'ipabuse-firewall' ); ?></p>
			</div>

			<div class="ipabuse-card">
				<h2 class="ipabuse-card-title">
					<span class="dashicons dashicons-admin-site-alt3" aria-hidden="true"></span>
					<?php esc_html_e( 'Country Blocklist', 'ipabuse-firewall' ); ?>
				</h2>
				<?php
				$selected_countries = array_filter( array_map( 'trim', explode( ',', ipabuse_opt( 'blocked_countries', '' ) ) ) );
				?>
				<div class="ipabuse-country-picker" data-field-id="ipabuse_blocked_countries">
					<input type="hidden" name="ipabuse_blocked_countries" id="ipabuse_blocked_countries"
						value="<?php echo esc_attr( implode( ', ', $selected_countries ) ); ?>" />

					<div class="ipabuse-country-chips" id="ipabuse-country-chips" aria-live="polite"></div>

					<label for="ipabuse-country-search" class="screen-reader-text"><?php esc_html_e( 'Search countries', 'ipabuse-firewall' ); ?></label>
					<input type="text" id="ipabuse-country-search" class="regular-text"
						placeholder="<?php esc_attr_e( 'Search countries…', 'ipabuse-firewall' ); ?>" />

					<ul class="ipabuse-country-list" id="ipabuse-country-list">
						<?php foreach ( ipabuse_country_list() as $code => $name ) : ?>
							<li class="ipabuse-country-option" data-code="<?php echo esc_attr( $code ); ?>" data-name="<?php echo esc_attr( strtolower( $name ) ); ?>">
								<label>
									<input type="checkbox" class="ipabuse-country-checkbox" value="<?php echo esc_attr( $code ); ?>"
										<?php checked( in_array( $code, $selected_countries, true ) ); ?> />
									<?php echo esc_html( $name ); ?> <span class="ipabuse-country-code">(<?php echo esc_html( $code ); ?>)</span>
								</label>
							</li>
						<?php endforeach; ?>
					</ul>
				</div>
				<p class="description">
					<?php esc_html_e( 'Any IP ipabuse.org already has data on, from a selected country, is blocked regardless of its reputation score.', 'ipabuse-firewall' ); ?>
					<strong><?php esc_html_e( 'Note:', 'ipabuse-firewall' ); ?></strong>
					<?php esc_html_e( 'this only covers IPs already known to ipabuse.org — it cannot identify the country of a first-time visitor, since that requires a local GeoIP database this lightweight plugin does not ship.', 'ipabuse-firewall' ); ?>
				</p>
			</div>

			<?php submit_button(); ?>
		</form>

		<div class="ipabuse-card">
			<h2 class="ipabuse-card-title">
				<span class="dashicons dashicons-upload" aria-hidden="true"></span>
				<?php esc_html_e( 'Import / Export Settings', 'ipabuse-firewall' ); ?>
			</h2>
			<p class="description"><?php esc_html_e( 'Useful for applying the same configuration across multiple sites. The API key is never included in the export — re-enter it manually after importing.', 'ipabuse-firewall' ); ?></p>
			<div class="ipabuse-actions-row">
				<a class="button" href="<?php echo esc_url( wp_nonce_url( add_query_arg( 'action', 'ipabuse_export_settings', admin_url( 'admin-post.php' ) ), 'ipabuse_export_settings' ) ); ?>">
					<?php esc_html_e( 'Export Settings (JSON)', 'ipabuse-firewall' ); ?>
				</a>
				<form method="post" enctype="multipart/form-data" class="ipabuse-inline-form">
					<?php wp_nonce_field( 'ipabuse_import_settings' ); ?>
					<label for="ipabuse_import_file" class="screen-reader-text"><?php esc_html_e( 'Settings file to import', 'ipabuse-firewall' ); ?></label>
					<input type="file" name="ipabuse_import_file" id="ipabuse_import_file" accept="application/json" required />
					<?php submit_button( __( 'Import', 'ipabuse-firewall' ), 'secondary', 'ipabuse_import_submit', false ); ?>
				</form>
			</div>
		</div>

		<div class="ipabuse-card ipabuse-danger-zone">
			<h2 class="ipabuse-card-title">
				<span class="dashicons dashicons-warning" aria-hidden="true"></span>
				<?php esc_html_e( 'Danger Zone', 'ipabuse-firewall' ); ?>
			</h2>
			<p class="description"><?php esc_html_e( 'Unblocks every currently-blocked IP. This cannot be undone — IPs will only be re-blocked on the next sync or if they trigger local rate-limiting again.', 'ipabuse-firewall' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'ipabuse_clear_all' ); ?>
				<input type="hidden" name="action" value="ipabuse_clear_all" />
				<label>
					<input type="checkbox" name="ipabuse_confirm_clear_all" value="1" required />
					<?php esc_html_e( 'I understand this will unblock every IP currently blocked by this plugin.', 'ipabuse-firewall' ); ?>
				</label>
				<p>
					<?php submit_button( __( 'Clear All Blocked IPs', 'ipabuse-firewall' ), 'delete', 'submit', false ); ?>
				</p>
			</form>

			<hr />

			<p class="description"><?php esc_html_e( 'Flushes this plugin\'s cached data (block-status lookups and the blocked-IP count). Does not change any blocked IPs. Useful after restoring a database backup or switching object-cache backends.', 'ipabuse-firewall' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'ipabuse_clear_cache' ); ?>
				<input type="hidden" name="action" value="ipabuse_clear_cache" />
				<p>
					<?php submit_button( __( 'Clear Cache', 'ipabuse-firewall' ), 'secondary', 'submit', false ); ?>
				</p>
			</form>
		</div>
	</div>
	<?php
}
