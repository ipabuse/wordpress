<?php
/**
 * IPAbuse Firewall — IP Lookup Page
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

/** Render the standalone IP Reputation Lookup page (AJAX-driven). */
function ipabuse_lookup_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	?>
	<div class="wrap ipabuse-wrap">
		<?php ipabuse_render_page_header( __( 'IP Reputation Lookup', 'ipabuse-firewall' ), 'search' ); ?>

		<div class="ipabuse-card">
			<form method="post" id="ipabuse-lookup-form" class="ipabuse-lookup-form">
				<label for="lookup_ip" class="screen-reader-text"><?php esc_html_e( 'IP address to look up', 'ipabuse-firewall' ); ?></label>
				<input type="text" name="lookup_ip" id="lookup_ip" placeholder="1.2.3.4"
					class="regular-text ipabuse-lookup-input" />
				<input type="submit" class="button button-secondary"
					value="<?php esc_attr_e( 'Lookup', 'ipabuse-firewall' ); ?>" />
				<span class="spinner ipabuse-lookup-spinner" aria-hidden="true"></span>
			</form>
			<div id="ipabuse-lookup-result" aria-live="polite"></div>
		</div>
	</div>
	<?php
}
