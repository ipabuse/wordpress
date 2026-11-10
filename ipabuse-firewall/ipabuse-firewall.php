<?php
/**
 * Plugin Name: IPAbuse Firewall
 * Plugin URI:  https://developer.ipabuse.org/docs/plugins/wordpress
 * Description: Automatically blocks malicious IPs using the ipabuse.org reputation database. Reports brute-force logins and syncs a daily blocklist.
 * Version:     1.5.0
 * Author:      ipabuse.org
 * Author URI:  https://ipabuse.org
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: ipabuse-firewall
 * Requires PHP: 7.4
 * Requires at least: 5.9
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

define( 'IPABUSE_VERSION', '1.5.0' );
define( 'IPABUSE_PLUGIN_FILE', __FILE__ );
define( 'IPABUSE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'IPABUSE_API_BASE', 'https://api.ipabuse.org/v1/plugin' );
define( 'IPABUSE_OPT_PREFIX', 'ipabuse_' );

// ── Autoload classes ──────────────────────────────────────────────────────────
require_once IPABUSE_PLUGIN_DIR . 'includes/class-api-client.php';
require_once IPABUSE_PLUGIN_DIR . 'includes/class-blocker.php';
require_once IPABUSE_PLUGIN_DIR . 'includes/class-reporter.php';
require_once IPABUSE_PLUGIN_DIR . 'includes/email-template.php';
require_once IPABUSE_PLUGIN_DIR . 'includes/rest-api.php';
require_once IPABUSE_PLUGIN_DIR . 'includes/cli.php';
require_once IPABUSE_PLUGIN_DIR . 'admin/helpers.php';
require_once IPABUSE_PLUGIN_DIR . 'admin/country-list.php';
require_once IPABUSE_PLUGIN_DIR . 'admin/dashboard-page.php';
require_once IPABUSE_PLUGIN_DIR . 'admin/blocked-ips-page.php';
require_once IPABUSE_PLUGIN_DIR . 'admin/lookup-page.php';
require_once IPABUSE_PLUGIN_DIR . 'admin/settings-page.php';
require_once IPABUSE_PLUGIN_DIR . 'admin/dashboard-widget.php';
require_once IPABUSE_PLUGIN_DIR . 'admin/site-health.php';

// ── Activation / deactivation ─────────────────────────────────────────────────
define( 'IPABUSE_DB_VERSION', '1.4.2' );

register_activation_hook( __FILE__, 'ipabuse_activate' );
register_deactivation_hook( __FILE__, 'ipabuse_deactivate' );

/**
 * Create/alter the plugin's tables via dbDelta(). Safe to call repeatedly —
 * dbDelta() only applies the changes a table actually needs.
 */
function ipabuse_run_db_upgrade(): void {
	global $wpdb;
	$table   = $wpdb->prefix . 'ipabuse_blocked';
	$charset = $wpdb->get_charset_collate();
	$sql     = "CREATE TABLE {$table} (
		id          BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
		ip          VARCHAR(45)      NOT NULL,
		score       TINYINT UNSIGNED NOT NULL DEFAULT 0,
		country     CHAR(2)          NULL,
		blocked_at  DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at  DATETIME         NOT NULL DEFAULT '0000-00-00 00:00:00',
		PRIMARY KEY (id),
		UNIQUE KEY ip (ip),
		KEY expires_at (expires_at),
		KEY blocked_at (blocked_at)
	) {$charset};";

	$history_table = $wpdb->prefix . 'ipabuse_block_history';
	$history_sql   = "CREATE TABLE {$history_table} (
		id          BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
		ip          VARCHAR(45)      NOT NULL,
		action      VARCHAR(20)      NOT NULL,
		reason      VARCHAR(30)      NOT NULL,
		score       TINYINT UNSIGNED NOT NULL DEFAULT 0,
		created_at  DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		KEY ip (ip),
		KEY created_at (created_at)
	) {$charset};";

	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	dbDelta( $sql );
	dbDelta( $history_sql );

	update_option( IPABUSE_OPT_PREFIX . 'db_version', IPABUSE_DB_VERSION );
}

// register_activation_hook() only fires on activate/reactivate — it does NOT
// re-run when plugin files are simply updated in place while already active,
// so schema changes (like the country column / history table) would never
// reach an already-active install without this version-gated runtime check.
add_action( 'plugins_loaded', function (): void {
	if ( ipabuse_opt( 'db_version', '' ) !== IPABUSE_DB_VERSION ) {
		ipabuse_run_db_upgrade();
	}
} );

function ipabuse_activate(): void {
	ipabuse_run_db_upgrade();

	// Schedule cron.
	if ( ! wp_next_scheduled( 'ipabuse_sync_cron' ) ) {
		wp_schedule_event( time(), 'ipabuse_15min', 'ipabuse_sync_cron' );
	}
}

function ipabuse_deactivate(): void {
	wp_clear_scheduled_hook( 'ipabuse_sync_cron' );
}

// ── Custom cron interval (15 minutes) ────────────────────────────────────────
add_filter( 'cron_schedules', function ( array $schedules ): array {
	$schedules['ipabuse_15min'] = [
		'interval' => 900,
		'display'  => __( 'Every 15 Minutes', 'ipabuse-firewall' ),
	];
	return $schedules;
} );

// ── Block incoming IPs on init ────────────────────────────────────────────────
add_action( 'init', function (): void {
	if ( ! ipabuse_opt( 'enabled', '1' ) || ! ipabuse_opt( 'enable_blocking', '1' ) ) {
		return;
	}
	$ip = IPAbuse_Blocker::get_client_ip();
	if ( IPAbuse_Blocker::is_blocked( $ip ) ) {
		wp_die(
			esc_html__( 'Your IP address has been blocked due to suspicious activity.', 'ipabuse-firewall' ),
			esc_html__( 'Access Denied', 'ipabuse-firewall' ),
			[ 'response' => 403 ]
		);
	}
}, 1 );

// ── Report / rate-limit failed logins (wp-login.php and xmlrpc.php) ───────────

/**
 * Shared handler for a failed-login-style event: report it to ipabuse.org
 * and/or count it toward the local rate-limit threshold.
 *
 * @param string $username Attempted username.
 * @param string $context  'login' or 'xmlrpc', used only for the report description.
 */
function ipabuse_handle_failed_login( string $username, string $context = 'login' ): void {
	if ( ! ipabuse_opt( 'enabled', '1' ) ) {
		return;
	}

	$ip = IPAbuse_Blocker::get_client_ip();

	// report_failed_login() checks the "Report Failed Logins" toggle itself.
	IPAbuse_Reporter::report_failed_login( $ip, $username, $context );

	// Locally block repeat offenders immediately, rather than waiting for the
	// next synced ipabuse.org blocklist to catch up. Attempts against a
	// username that doesn't exist count double — that's a stronger signal of
	// enumeration/credential-stuffing than a real user mistyping a password.
	if ( ipabuse_opt( 'enable_blocking', '1' ) ) {
		$weight = username_exists( $username ) ? 1 : 2;
		IPAbuse_Blocker::record_local_failure( $ip, $weight );
	}
}

add_action( 'wp_login_failed', function ( string $username ): void {
	ipabuse_handle_failed_login( $username, 'login' );
}, 10, 1 );

// xmlrpc.php is a classic brute-force/amplification vector (e.g. system.multicall
// batching many login attempts into one request) — covered with the same
// reporting/rate-limiting path as wp-login.php.
add_action( 'xmlrpc_login_error', function ( $error, $user ): void {
	ipabuse_handle_failed_login( is_string( $user ) ? $user : '', 'xmlrpc' );
}, 10, 2 );

// ── Report comment spam (SPAM category) ────────────────────────────────────────
// Covers both: a comment created directly as spam (Akismet or another spam
// filter rejecting it on submission) and a comment later moved to spam by a
// moderator. report_abuse() dedupes per (IP, category), so both hooks firing
// for the same event is harmless.
add_action( 'wp_insert_comment', function ( int $comment_id, $comment ): void {
	if ( ! ipabuse_opt( 'enabled', '1' ) || 'spam' !== $comment->comment_approved ) {
		return;
	}
	$ip = filter_var( $comment->comment_author_IP, FILTER_VALIDATE_IP );
	if ( $ip ) {
		IPAbuse_Reporter::report_abuse( $ip, 'SPAM', 'WordPress comment spam' );
	}
}, 10, 2 );

add_action( 'transition_comment_status', function ( string $new_status, string $old_status, $comment ): void {
	if ( ! ipabuse_opt( 'enabled', '1' ) || 'spam' !== $new_status || 'spam' === $old_status ) {
		return;
	}
	$ip = filter_var( $comment->comment_author_IP, FILTER_VALIDATE_IP );
	if ( $ip ) {
		IPAbuse_Reporter::report_abuse( $ip, 'SPAM', 'WordPress comment manually marked as spam' );
	}
}, 10, 3 );

// ── Detect 404 scanning/probing (SCANNING category) ─────────────────────────────
// A burst of requests for nonexistent pages (wp-config.php.bak, old plugin
// paths, etc.) is a common pre-attack reconnaissance signal distinct from
// brute-force login attempts.
add_action( 'template_redirect', function (): void {
	if ( ! ipabuse_opt( 'enabled', '1' ) || ! ipabuse_opt( 'enable_blocking', '1' ) || ! is_404() ) {
		return;
	}
	IPAbuse_Blocker::record_scan_attempt( IPAbuse_Blocker::get_client_ip() );
} );

// ── Sync: shared by the cron job, the "Sync Now" button, and `wp ipabuse sync` ─

/**
 * Run a full blocklist sync: fetch, bulk-block, prune stale/missing entries,
 * and apply the country blocklist. Used everywhere a sync can be triggered
 * from, so they all behave identically rather than drifting into partial
 * duplicates of each other.
 *
 * @return array{ ok: bool, error?: string, items?: array }
 */
function ipabuse_run_sync(): array {
	$api_key   = ipabuse_opt( 'api_key', '' );
	$min_score = (int) ipabuse_opt( 'min_score', 75 );
	$limit     = (int) ipabuse_opt( 'limit', 1000 );

	if ( ! $api_key ) {
		return [ 'ok' => false, 'error' => __( 'No API key configured.', 'ipabuse-firewall' ) ];
	}

	$client = new IPAbuse_Api_Client( $api_key );
	$result = $client->blocklist( $min_score, $limit );

	if ( ! $result['ok'] || empty( $result['data'] ) ) {
		return [ 'ok' => false, 'error' => $result['error'] ?? __( 'Unknown error', 'ipabuse-firewall' ) ];
	}

	$items = $result['data']['ips'] ?? $result['data'];
	IPAbuse_Blocker::bulk_block( $items );
	// Only prune IPs absent from the response when the response wasn't truncated
	// by $limit — otherwise "missing" just means it didn't make this page, not
	// that its score improved, and we'd unblock still-malicious IPs.
	if ( count( $items ) < $limit ) {
		IPAbuse_Blocker::purge_missing( $items );
	}
	IPAbuse_Blocker::purge_expired();

	// Country blocklist: a second, lower-threshold fetch so IPs from flagged
	// countries are blocked even if they don't clear the configured min_score
	// (this only covers IPs ipabuse.org already has data on — see
	// enforce_country_blocklist() docblock for why it can't cover first-time
	// visitors without a GeoIP database).
	$blocked_countries = array_filter( array_map( 'trim', explode( ',', ipabuse_opt( 'blocked_countries', '' ) ) ) );
	if ( ! empty( $blocked_countries ) ) {
		$country_result = $client->blocklist( 0, $limit );
		if ( $country_result['ok'] && ! empty( $country_result['data'] ) ) {
			$country_items = $country_result['data']['ips'] ?? $country_result['data'];
			IPAbuse_Blocker::enforce_country_blocklist( $country_items, $blocked_countries );
		}
	}

	update_option( IPABUSE_OPT_PREFIX . 'last_sync', time() );

	return [ 'ok' => true, 'items' => $items ];
}

// ── Cron: sync blocklist ──────────────────────────────────────────────────────
add_action( 'ipabuse_sync_cron', function (): void {
	// Data-retention cleanup runs regardless of whether blocking/sync is enabled,
	// so stale rows don't linger indefinitely if the admin later turns syncing off.
	$retention_days = (int) ipabuse_opt( 'retention_days', 365 );
	IPAbuse_Blocker::purge_older_than( $retention_days );
	IPAbuse_Blocker::purge_history_older_than( $retention_days );

	if ( ! ipabuse_opt( 'enabled', '1' ) || ! ipabuse_opt( 'enable_blocking', '1' ) ) {
		return;
	}

	ipabuse_run_sync();
} );

// ── Admin menu ─────────────────────────────────────────────────────────────────
define( 'IPABUSE_MENU_SLUG', 'ipabuse-firewall' );

add_action( 'admin_menu', function (): void {
	add_menu_page(
		__( 'IPAbuse Firewall', 'ipabuse-firewall' ),
		__( 'IPAbuse Firewall', 'ipabuse-firewall' ),
		'manage_options',
		IPABUSE_MENU_SLUG,
		'ipabuse_dashboard_page',
		'dashicons-shield-alt',
		65
	);
	add_submenu_page(
		IPABUSE_MENU_SLUG,
		__( 'Dashboard', 'ipabuse-firewall' ),
		__( 'Dashboard', 'ipabuse-firewall' ),
		'manage_options',
		IPABUSE_MENU_SLUG,
		'ipabuse_dashboard_page'
	);
	add_submenu_page(
		IPABUSE_MENU_SLUG,
		__( 'Blocked IPs', 'ipabuse-firewall' ),
		__( 'Blocked IPs', 'ipabuse-firewall' ),
		'manage_options',
		IPABUSE_MENU_SLUG . '-blocked',
		'ipabuse_blocked_ips_page'
	);
	add_submenu_page(
		IPABUSE_MENU_SLUG,
		__( 'IP Lookup', 'ipabuse-firewall' ),
		__( 'IP Lookup', 'ipabuse-firewall' ),
		'manage_options',
		IPABUSE_MENU_SLUG . '-lookup',
		'ipabuse_lookup_page'
	);
	add_submenu_page(
		IPABUSE_MENU_SLUG,
		__( 'Settings', 'ipabuse-firewall' ),
		__( 'Settings', 'ipabuse-firewall' ),
		'manage_options',
		IPABUSE_MENU_SLUG . '-settings',
		'ipabuse_settings_page'
	);
} );

add_action( 'admin_init', 'ipabuse_register_settings' );

add_action( 'admin_enqueue_scripts', function ( string $hook ): void {
	$ipabuse_hooks = [
		'toplevel_page_' . IPABUSE_MENU_SLUG,
		IPABUSE_MENU_SLUG . '_page_' . IPABUSE_MENU_SLUG . '-blocked',
		IPABUSE_MENU_SLUG . '_page_' . IPABUSE_MENU_SLUG . '-lookup',
		IPABUSE_MENU_SLUG . '_page_' . IPABUSE_MENU_SLUG . '-settings',
		'index.php', // wp-admin main dashboard, for the IPAbuse Firewall widget.
	];
	if ( ! in_array( $hook, $ipabuse_hooks, true ) ) {
		return;
	}

	wp_enqueue_style(
		'ipabuse-firewall-admin',
		plugins_url( 'admin/css/admin.css', IPABUSE_PLUGIN_FILE ),
		[],
		IPABUSE_VERSION
	);

	if ( IPABUSE_MENU_SLUG . '_page_' . IPABUSE_MENU_SLUG . '-blocked' === $hook ) {
		wp_enqueue_script(
			'ipabuse-firewall-blocked-ips',
			plugins_url( 'admin/js/blocked-ips.js', IPABUSE_PLUGIN_FILE ),
			[],
			IPABUSE_VERSION,
			true
		);
	}

	if ( IPABUSE_MENU_SLUG . '_page_' . IPABUSE_MENU_SLUG . '-settings' === $hook ) {
		wp_enqueue_script(
			'ipabuse-firewall-country-picker',
			plugins_url( 'admin/js/country-picker.js', IPABUSE_PLUGIN_FILE ),
			[],
			IPABUSE_VERSION,
			true
		);
	}

	if ( IPABUSE_MENU_SLUG . '_page_' . IPABUSE_MENU_SLUG . '-lookup' !== $hook ) {
		return;
	}

	wp_enqueue_script(
		'ipabuse-firewall-lookup',
		plugins_url( 'admin/js/lookup.js', IPABUSE_PLUGIN_FILE ),
		[],
		IPABUSE_VERSION,
		true
	);
	wp_localize_script( 'ipabuse-firewall-lookup', 'IPAbuseLookup', [
		'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
		'nonce'      => wp_create_nonce( 'ipabuse_lookup' ),
		'categories' => ipabuse_report_categories(),
		'labels'     => [
			'ip'             => __( 'IP', 'ipabuse-firewall' ),
			'score'          => __( 'Score', 'ipabuse-firewall' ),
			'category'       => __( 'Category', 'ipabuse-firewall' ),
			'reports'        => __( 'Reports', 'ipabuse-firewall' ),
			'country'        => __( 'Country', 'ipabuse-firewall' ),
			'requestFailed'  => __( 'Request failed. Please try again.', 'ipabuse-firewall' ),
			'blockThisIp'    => __( 'Block This IP', 'ipabuse-firewall' ),
			'reportToIpabuse' => __( 'Report to ipabuse.org', 'ipabuse-firewall' ),
			'descriptionPlaceholder' => __( 'Optional description…', 'ipabuse-firewall' ),
			'confirmBlock'   => __( 'Block this IP permanently?', 'ipabuse-firewall' ),
		],
	] );
} );

add_action( 'wp_ajax_ipabuse_lookup', 'ipabuse_ajax_lookup_ip' );

/** AJAX handler for the admin "IP Reputation Lookup" tool. */
function ipabuse_ajax_lookup_ip(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( [ 'message' => __( 'Permission denied.', 'ipabuse-firewall' ) ], 403 );
	}
	check_ajax_referer( 'ipabuse_lookup', 'nonce' );

	$ip = sanitize_text_field( wp_unslash( $_POST['ip'] ?? '' ) );
	if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
		wp_send_json_error( [ 'message' => __( 'Please enter a valid IP address.', 'ipabuse-firewall' ) ] );
	}

	$client = new IPAbuse_Api_Client( ipabuse_opt( 'api_key', '' ) );
	$r      = $client->lookup( $ip );

	if ( ! $r['ok'] || empty( $r['data'] ) ) {
		wp_send_json_error( [ 'message' => $r['error'] ?? __( 'IP not found in database.', 'ipabuse-firewall' ) ] );
	}

	$d     = $r['data'];
	$score = (int) ( $d['reputationScore'] ?? 0 );

	wp_send_json_success( [
		'ip'       => $ip,
		'score'    => $d['reputationScore'] ?? 'N/A',
		'badge'    => ipabuse_score_badge_class( $score ),
		'category' => $d['category'] ?? 'N/A',
		'reports'  => (int) ( $d['totalReports'] ?? 0 ),
		'country'  => $d['countryCode'] ?? '—',
	] );
}

/** Abuse categories accepted by the ipabuse.org report endpoint. */
function ipabuse_report_categories(): array {
	return [ 'SPAM', 'MALWARE', 'PHISHING', 'BRUTE_FORCE', 'DDoS', 'BOT', 'SCANNING', 'FRAUD', 'OTHER' ];
}

add_action( 'wp_ajax_ipabuse_manual_block', 'ipabuse_ajax_manual_block' );

/** AJAX handler: manually block an IP (same nonce/context as the lookup tool). */
function ipabuse_ajax_manual_block(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( [ 'message' => __( 'Permission denied.', 'ipabuse-firewall' ) ], 403 );
	}
	check_ajax_referer( 'ipabuse_lookup', 'nonce' );

	$ip = sanitize_text_field( wp_unslash( $_POST['ip'] ?? '' ) );
	if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
		wp_send_json_error( [ 'message' => __( 'Please enter a valid IP address.', 'ipabuse-firewall' ) ] );
	}

	IPAbuse_Blocker::block( $ip, 100, 0 );

	/* translators: %s = blocked IP address */
	wp_send_json_success( [ 'message' => sprintf( __( '%s has been blocked.', 'ipabuse-firewall' ), $ip ) ] );
}

add_action( 'wp_ajax_ipabuse_manual_report', 'ipabuse_ajax_manual_report' );

/** AJAX handler: manually report an IP to ipabuse.org. */
function ipabuse_ajax_manual_report(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( [ 'message' => __( 'Permission denied.', 'ipabuse-firewall' ) ], 403 );
	}
	check_ajax_referer( 'ipabuse_lookup', 'nonce' );

	$ip = sanitize_text_field( wp_unslash( $_POST['ip'] ?? '' ) );
	if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
		wp_send_json_error( [ 'message' => __( 'Please enter a valid IP address.', 'ipabuse-firewall' ) ] );
	}

	$api_key = ipabuse_opt( 'api_key', '' );
	if ( ! $api_key ) {
		wp_send_json_error( [ 'message' => __( 'No API key configured.', 'ipabuse-firewall' ) ] );
	}

	$category = sanitize_text_field( wp_unslash( $_POST['category'] ?? 'OTHER' ) );
	if ( ! in_array( $category, ipabuse_report_categories(), true ) ) {
		$category = 'OTHER';
	}
	$description = sanitize_textarea_field( wp_unslash( $_POST['description'] ?? '' ) );
	if ( '' === $description ) {
		$description = 'Manually reported via wp-admin';
	}

	$client = new IPAbuse_Api_Client( $api_key );
	$r      = $client->report( $ip, $category, $description, 3 );

	if ( ! $r['ok'] ) {
		wp_send_json_error( [ 'message' => $r['error'] ?? __( 'Report failed.', 'ipabuse-firewall' ) ] );
	}

	/* translators: %s = reported IP address */
	wp_send_json_success( [ 'message' => sprintf( __( '%s has been reported to ipabuse.org.', 'ipabuse-firewall' ), $ip ) ] );
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function ipabuse_opt( string $key, $default = '' ) {
	return get_option( IPABUSE_OPT_PREFIX . $key, $default );
}
