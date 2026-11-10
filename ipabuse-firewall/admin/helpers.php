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
		</span>
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
