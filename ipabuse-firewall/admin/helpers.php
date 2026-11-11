<?php
/**
 * IPAbuse Firewall — Shared Admin Helpers
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

/**
 * Map a reputation score to a CSS modifier class for the score badge.
 *
 * @param  int $score 0–100
 * @return string
 */
function ipabuse_score_badge_class( int $score ): string {
	if ( $score >= 75 ) {
		return 'ipabuse-badge--high';
	}
	if ( $score >= 40 ) {
		return 'ipabuse-badge--medium';
	}
	return 'ipabuse-badge--low';
}

/** Render the shared status banner showing protection state, blocked count, and API key state. */
function ipabuse_render_status_banner(): void {
	$is_enabled    = '1' === ipabuse_opt( 'enabled', '1' );
	$has_api_key   = '' !== ipabuse_opt( 'api_key', '' );
	$blocked_count = IPAbuse_Blocker::count();
	?>
	<div class="ipabuse-status-banner <?php echo $is_enabled ? 'is-active' : 'is-inactive'; ?>">
		<span class="dashicons dashicons-<?php echo $is_enabled ? 'yes-alt' : 'warning'; ?>" aria-hidden="true"></span>
		<strong>
			<?php echo $is_enabled
				? esc_html__( 'Protection Active', 'ipabuse-firewall' )
				: esc_html__( 'Protection Disabled', 'ipabuse-firewall' ); ?>
		</strong>
		<span class="ipabuse-status-sep" aria-hidden="true">&bull;</span>
		<span>
			<?php
			echo esc_html( sprintf(
				/* translators: %d = number of currently blocked IPs */
				_n( 'Blocking %d IP', 'Blocking %d IPs', $blocked_count, 'ipabuse-firewall' ),
				$blocked_count
			) );
			?>
		</span>
		<span class="ipabuse-status-sep" aria-hidden="true">&bull;</span>
		<span>
			<?php
			echo $has_api_key
				? esc_html__( 'API key configured', 'ipabuse-firewall' )
				: esc_html__( 'API key not set', 'ipabuse-firewall' );
			?>
			<?php if ( ! $has_api_key ) : ?>
				<button type="button" class="button button-small ipabuse-connect-trigger">
					<?php esc_html_e( 'Connect Your Account', 'ipabuse-firewall' ); ?>
				</button>
			<?php endif; ?>
		</span>
	</div>
	<?php
	if ( ! $has_api_key ) {
		ipabuse_render_connect_wizard_modal();
	}
}

/**
 * Render the (initially hidden) "Connect Your Account" setup wizard modal.
 * Opened by any `.ipabuse-connect-trigger` button via connect-wizard.js.
 * Only ever collects site URL (fixed, from this site) + admin email — never
 * a password, and the response never contains an API key; the admin always
 * gets that by logging into ipabuse.org themselves and pasting it in below.
 */
function ipabuse_render_connect_wizard_modal(): void {
	?>
	<div id="ipabuse-connect-modal" class="ipabuse-modal-overlay" hidden>
		<div class="ipabuse-modal" role="dialog" aria-modal="true" aria-labelledby="ipabuse-connect-modal-title">
			<button type="button" class="ipabuse-modal-close" aria-label="<?php esc_attr_e( 'Close', 'ipabuse-firewall' ); ?>">&times;</button>
			<h2 id="ipabuse-connect-modal-title">
				<span class="dashicons dashicons-admin-network" aria-hidden="true"></span>
				<?php esc_html_e( 'Connect Your Account', 'ipabuse-firewall' ); ?>
			</h2>
			<div class="ipabuse-connect-step" data-step="form">
				<p class="description">
					<?php esc_html_e( 'This creates (or finds) your ipabuse.org account for this site. No password is set here — you\'ll verify your email and sign in at ipabuse.org to get your API key.', 'ipabuse-firewall' ); ?>
				</p>
				<p>
					<label for="ipabuse-connect-site-url"><strong><?php esc_html_e( 'Site URL', 'ipabuse-firewall' ); ?></strong></label><br />
					<input type="text" id="ipabuse-connect-site-url" class="regular-text" value="<?php echo esc_attr( home_url( '/' ) ); ?>" readonly />
				</p>
				<p>
					<label for="ipabuse-connect-email"><strong><?php esc_html_e( 'Admin Email', 'ipabuse-firewall' ); ?></strong></label><br />
					<input type="email" id="ipabuse-connect-email" class="regular-text" value="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" />
				</p>
				<p class="ipabuse-connect-error" role="alert"></p>
				<p>
					<button type="button" class="button button-primary" id="ipabuse-connect-submit">
						<?php esc_html_e( 'Create My Account', 'ipabuse-firewall' ); ?>
					</button>
				</p>
			</div>
			<div class="ipabuse-connect-step" data-step="done" hidden>
				<p class="ipabuse-connect-success"></p>
				<p>
					<a class="button button-primary" href="https://www.ipabuse.org/settings?tab=api" target="_blank" rel="noopener">
						<?php esc_html_e( 'Open ipabuse.org to Get My API Key', 'ipabuse-firewall' ); ?>
					</a>
				</p>
				<p class="description">
					<?php esc_html_e( 'Once you have your key, paste it into the API Key field on this plugin\'s Settings page.', 'ipabuse-firewall' ); ?>
				</p>
			</div>
		</div>
	</div>
	<?php
}

/**
 * Render an inline SVG sparkline for a series of non-negative integers.
 * All geometry is computed server-side from numeric data only, so the
 * output is safe to echo directly.
 *
 * @param  array<int, int> $values
 * @param  int              $width
 * @param  int              $height
 * @return string
 */
function ipabuse_render_sparkline( array $values, int $width = 280, int $height = 40 ): string {
	if ( empty( $values ) ) {
		return '';
	}

	$max    = max( 1, max( $values ) );
	$count  = count( $values );
	$step   = $count > 1 ? $width / ( $count - 1 ) : 0;
	$points = [];

	foreach ( $values as $i => $value ) {
		$x = round( $i * $step, 2 );
		$y = round( $height - ( $value / $max ) * $height, 2 );
		$points[] = "{$x},{$y}";
	}

	$points_attr = implode( ' ', $points );

	return sprintf(
		'<svg class="ipabuse-sparkline" viewBox="0 0 %d %d" preserveAspectRatio="none" aria-hidden="true"><polyline points="%s" fill="none" stroke="currentColor" stroke-width="2" /></svg>',
		$width,
		$height,
		esc_attr( $points_attr )
	);
}

/**
 * Render an IP address as a link to its public ipabuse.org lookup page,
 * opening in a new tab. Falls back to plain escaped text if $ip isn't a
 * valid IP (defensive — callers should already only pass validated IPs).
 *
 * @param  string $ip
 * @return string
 */
function ipabuse_ip_lookup_link( string $ip ): string {
	if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
		return esc_html( $ip );
	}
	$url = 'https://www.ipabuse.org/lookup?ip=' . rawurlencode( $ip );
	return sprintf(
		'<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
		esc_url( $url ),
		esc_html( $ip )
	);
}

/**
 * Render the shared page header (icon + title) for any IPAbuse Firewall admin page.
 *
 * @param string $title
 * @param string $dashicon Dashicon slug without the "dashicons-" prefix.
 */
function ipabuse_render_page_header( string $title, string $dashicon = 'shield-alt' ): void {
	?>
	<h1>
		<span class="dashicons dashicons-<?php echo esc_attr( $dashicon ); ?>" aria-hidden="true"></span>
		<?php echo esc_html( $title ); ?>
	</h1>
	<?php
}
