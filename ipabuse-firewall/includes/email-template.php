<?php
/**
 * IPAbuse Firewall — Branded HTML Email Template
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

/**
 * Wrap a notification body in a simple, table-based branded HTML email
 * shell (inline CSS, email-client-safe). Inputs are treated as pre-escaped
 * HTML fragments — callers are responsible for escaping any dynamic values
 * before passing them in.
 *
 * @param  string $heading      Short heading shown in the colored banner.
 * @param  string $body_html    Main message body (HTML, already escaped).
 * @param  string $cta_text     Optional button label.
 * @param  string $cta_url      Optional button URL.
 * @return string Full HTML document for wp_mail().
 */
function ipabuse_render_email_html( string $heading, string $body_html, string $cta_text = '', string $cta_url = '' ): string {
	$site_name = esc_html( get_bloginfo( 'name' ) );
	$site_url  = esc_url( home_url( '/' ) );
	$heading   = esc_html( $heading );

	$cta_html = '';
	if ( '' !== $cta_text && '' !== $cta_url ) {
		$cta_html = sprintf(
			'<tr><td style="padding:24px 32px 8px;"><a href="%s" style="display:inline-block;background:#2271b1;color:#ffffff;text-decoration:none;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:14px;font-weight:600;padding:11px 22px;border-radius:4px;">%s</a></td></tr>',
			esc_url( $cta_url ),
			esc_html( $cta_text )
		);
	}

	return '<!DOCTYPE html>'
		. '<html lang="en">'
		. '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>'
		. '<body style="margin:0;padding:0;background:#f0f0f1;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">'
		. '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f0f0f1;padding:32px 16px;">'
		. '<tr><td align="center">'
		. '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:6px;overflow:hidden;border:1px solid #e0e0e0;">'
		. '<tr><td style="background:#1d2327;padding:20px 32px;">'
		. '<span style="color:#ffffff;font-size:16px;font-weight:700;">&#128737;&nbsp; IPAbuse Firewall</span>'
		. '</td></tr>'
		. '<tr><td style="padding:28px 32px 4px;">'
		. '<h1 style="margin:0 0 12px;font-size:18px;color:#d63638;">' . $heading . '</h1>'
		. '<div style="font-size:14px;line-height:1.6;color:#1d2327;">' . $body_html . '</div>'
		. '</td></tr>'
		. $cta_html
		. '<tr><td style="padding:24px 32px 28px;">'
		. '<p style="margin:0;font-size:12px;color:#646970;">'
		. 'This alert was sent by the IPAbuse Firewall plugin on '
		. '<a href="' . $site_url . '" style="color:#2271b1;">' . $site_name . '</a>. '
		. 'You can turn off these emails in <strong>IPAbuse Firewall &rarr; Settings &rarr; Email Attack Alerts</strong>.'
		. '</p>'
		. '</td></tr>'
		. '</table>'
		. '</td></tr>'
		. '</table>'
		. '</body>'
		. '</html>';
}
