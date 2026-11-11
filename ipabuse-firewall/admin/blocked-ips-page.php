<?php
/**
 * IPAbuse Firewall — Blocked IPs Page
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

add_action( 'admin_post_ipabuse_export_csv', 'ipabuse_export_blocked_csv' );

/**
 * Build one RFC 4180 CSV row from an array of field values.
 *
 * @param  array $fields
 * @return string
 */
function ipabuse_csv_row( array $fields ): string {
	$escaped = array_map( function ( $field ) {
		$field = (string) $field;
		if ( false !== strpbrk( $field, ",\"\n\r" ) ) {
			$field = '"' . str_replace( '"', '""', $field ) . '"';
		}
		return $field;
	}, $fields );
	return implode( ',', $escaped ) . "\r\n";
}

/** Stream all (optionally search-filtered) blocked IPs as a CSV download. */
function ipabuse_export_blocked_csv(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Permission denied.', 'ipabuse-firewall' ), '', [ 'response' => 403 ] );
	}
	check_admin_referer( 'ipabuse_export_csv' );

	$search = sanitize_text_field( wp_unslash( $_GET['s'] ?? '' ) );
	$result = IPAbuse_Blocker::list_blocked( PHP_INT_MAX, 1, $search );

	$csv = ipabuse_csv_row( [ 'IP', 'Score', 'Country', 'Blocked At (UTC)', 'Expires At (UTC)' ] );
	foreach ( $result['items'] as $row ) {
		$csv .= ipabuse_csv_row( [
			$row['ip'],
			$row['score'],
			$row['country'] ?? '',
			$row['blocked_at'],
			'0000-00-00 00:00:00' === $row['expires_at'] ? 'Permanent' : $row['expires_at'],
		] );
	}

	nocache_headers();
	header( 'Content-Type: text/csv; charset=utf-8' );
	header( 'Content-Disposition: attachment; filename=ipabuse-blocked-ips-' . gmdate( 'Y-m-d' ) . '.csv' );
	// Not HTML — escaping this as HTML would corrupt the CSV (e.g. "&" -> "&amp;").
	// Content is built entirely from validated IPs, ints, regex-checked country
	// codes, and DB datetime columns, so there is no injection surface here.
	echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	exit;
}

/**
 * Handle the bulk-action form (currently just "Unblock selected") submitted
 * from the Blocked IPs table.
 *
 * @return string  Notice HTML, or empty string if nothing was processed.
 */
function ipabuse_handle_bulk_action(): string {
	if ( ! isset( $_POST['ipabuse_bulk_action'] ) || ! check_admin_referer( 'ipabuse_bulk_action' ) ) {
		return '';
	}

	$action = sanitize_key( $_POST['ipabuse_bulk_action'] );
	$ips    = array_map( 'sanitize_text_field', wp_unslash( (array) ( $_POST['ipabuse_bulk_ips'] ?? [] ) ) );
	$ips    = array_filter( $ips, fn( $ip ) => false !== filter_var( $ip, FILTER_VALIDATE_IP ) );

	if ( empty( $ips ) ) {
		return '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'No valid IPs were selected.', 'ipabuse-firewall' ) . '</p></div>';
	}

	if ( 'unblock' === $action ) {
		foreach ( $ips as $ip ) {
			IPAbuse_Blocker::unblock( $ip );
		}
		/* translators: %d = number of IPs unblocked */
		return '<div class="notice notice-success is-dismissible"><p>' . esc_html( sprintf( _n( '%d IP unblocked.', '%d IPs unblocked.', count( $ips ), 'ipabuse-firewall' ), count( $ips ) ) ) . '</p></div>';
	}

	return '';
}

/** Render the Blocked IPs listing page: search, pagination, bulk unblock, and history. */
function ipabuse_blocked_ips_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified inside ipabuse_handle_bulk_action() itself before it acts on $_POST.
	$notice = isset( $_POST['ipabuse_bulk_action'] ) ? ipabuse_handle_bulk_action() : '';

	$per_page = 20;
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read-only pagination (GET); (int) cast is itself a complete, safe sanitizer.
	$page     = max( 1, (int) ( $_GET['paged'] ?? 1 ) );
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only search filter (GET); already properly sanitized via sanitize_text_field( wp_unslash( ... ) ).
	$search   = sanitize_text_field( wp_unslash( $_GET['s'] ?? '' ) );

	$result      = IPAbuse_Blocker::list_blocked( $per_page, $page, $search );
	$total       = $result['total'];
	$total_pages = (int) max( 1, ceil( $total / $per_page ) );
	$base_url    = admin_url( 'admin.php?page=' . IPABUSE_MENU_SLUG . '-blocked' );

	$export_url = add_query_arg( 'action', 'ipabuse_export_csv', admin_url( 'admin-post.php' ) );
	if ( '' !== $search ) {
		$export_url = add_query_arg( 's', rawurlencode( $search ), $export_url );
	}
	$export_url = wp_nonce_url( $export_url, 'ipabuse_export_csv' );

	$history = IPAbuse_Blocker::get_history( 20 );
	?>
	<div class="wrap ipabuse-wrap">
		<?php
		ipabuse_render_page_header( __( 'Blocked IPs', 'ipabuse-firewall' ), 'list-view' );
		echo wp_kses_post( $notice );
		?>

		<div class="ipabuse-card">
			<form method="get" class="ipabuse-search-form">
				<input type="hidden" name="page" value="<?php echo esc_attr( IPABUSE_MENU_SLUG . '-blocked' ); ?>" />
				<label for="ipabuse-search-s" class="screen-reader-text"><?php esc_html_e( 'Search blocked IPs', 'ipabuse-firewall' ); ?></label>
				<input type="text" name="s" id="ipabuse-search-s" value="<?php echo esc_attr( $search ); ?>"
					placeholder="<?php esc_attr_e( 'Search by IP…', 'ipabuse-firewall' ); ?>" class="regular-text" />
				<?php submit_button( __( 'Search', 'ipabuse-firewall' ), 'secondary', 'submit', false ); ?>
				<?php if ( '' !== $search ) : ?>
					<a href="<?php echo esc_url( $base_url ); ?>" class="button-link"><?php esc_html_e( 'Clear', 'ipabuse-firewall' ); ?></a>
				<?php endif; ?>
				<a href="<?php echo esc_url( $export_url ); ?>" class="button">
					<?php esc_html_e( 'Export CSV', 'ipabuse-firewall' ); ?>
				</a>
			</form>

			<?php if ( empty( $result['items'] ) ) : ?>
				<p class="description"><?php esc_html_e( 'No blocked IPs found.', 'ipabuse-firewall' ); ?></p>
			<?php else : ?>
				<form method="post">
					<?php wp_nonce_field( 'ipabuse_bulk_action' ); ?>
					<div class="ipabuse-bulk-actions-bar">
						<label for="ipabuse-bulk-action-select" class="screen-reader-text"><?php esc_html_e( 'Bulk action', 'ipabuse-firewall' ); ?></label>
						<select name="ipabuse_bulk_action" id="ipabuse-bulk-action-select">
							<option value=""><?php esc_html_e( 'Bulk actions', 'ipabuse-firewall' ); ?></option>
							<option value="unblock"><?php esc_html_e( 'Unblock', 'ipabuse-firewall' ); ?></option>
						</select>
						<?php submit_button( __( 'Apply', 'ipabuse-firewall' ), 'secondary', 'submit', false ); ?>
					</div>

					<table class="widefat striped">
						<thead>
							<tr>
								<td class="check-column"><input type="checkbox" id="ipabuse-select-all" /></td>
								<th><?php esc_html_e( 'IP', 'ipabuse-firewall' ); ?></th>
								<th><?php esc_html_e( 'Score', 'ipabuse-firewall' ); ?></th>
								<th><?php esc_html_e( 'Country', 'ipabuse-firewall' ); ?></th>
								<th><?php esc_html_e( 'Blocked At (UTC)', 'ipabuse-firewall' ); ?></th>
								<th><?php esc_html_e( 'Expires (UTC)', 'ipabuse-firewall' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $result['items'] as $row ) : ?>
								<tr>
									<td class="check-column">
										<input type="checkbox" name="ipabuse_bulk_ips[]" value="<?php echo esc_attr( $row['ip'] ); ?>" class="ipabuse-row-checkbox" />
									</td>
									<td><?php echo wp_kses_post( ipabuse_ip_lookup_link( $row['ip'] ) ); ?></td>
									<td>
										<span class="ipabuse-badge <?php echo esc_attr( ipabuse_score_badge_class( (int) $row['score'] ) ); ?>">
											<?php echo esc_html( $row['score'] ); ?>
										</span>
									</td>
									<td><?php echo esc_html( $row['country'] ?? '—' ); ?></td>
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
				</form>

				<?php if ( $total_pages > 1 ) : ?>
					<div class="ipabuse-pagination">
						<?php
						echo wp_kses_post( paginate_links( [
							'base'      => add_query_arg( 'paged', '%#%', $base_url . ( '' !== $search ? '&s=' . rawurlencode( $search ) : '' ) ),
							'format'    => '',
							'current'   => $page,
							'total'     => $total_pages,
							'prev_text' => __( '&laquo; Previous', 'ipabuse-firewall' ),
							'next_text' => __( 'Next &raquo;', 'ipabuse-firewall' ),
						] ) );
						?>
					</div>
				<?php endif; ?>
			<?php endif; ?>
		</div>

		<div class="ipabuse-card">
			<h2 class="ipabuse-card-title">
				<span class="dashicons dashicons-backup" aria-hidden="true"></span>
				<?php esc_html_e( 'Recent Block History', 'ipabuse-firewall' ); ?>
			</h2>
			<?php if ( empty( $history ) ) : ?>
				<p class="description"><?php esc_html_e( 'No block/unblock events recorded yet.', 'ipabuse-firewall' ); ?></p>
			<?php else : ?>
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'IP', 'ipabuse-firewall' ); ?></th>
							<th><?php esc_html_e( 'Action', 'ipabuse-firewall' ); ?></th>
							<th><?php esc_html_e( 'Reason', 'ipabuse-firewall' ); ?></th>
							<th><?php esc_html_e( 'When (UTC)', 'ipabuse-firewall' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $history as $row ) : ?>
							<tr>
								<td><?php echo wp_kses_post( ipabuse_ip_lookup_link( $row['ip'] ) ); ?></td>
								<td><?php echo esc_html( $row['action'] ); ?></td>
								<td><?php echo esc_html( $row['reason'] ); ?></td>
								<td><?php echo esc_html( $row['created_at'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
	</div>
	<?php
}
