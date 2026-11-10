<?php
/**
 * IPAbuse Firewall — IP Blocker
 * Stores blocked IPs in the database and provides helper methods.
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

class IPAbuse_Blocker {

	/** Number of IPs to INSERT per query during bulk_block(). */
	private const BATCH_SIZE = 200;

	/** MySQL DATETIME format, always computed/compared in UTC. */
	private const MYSQL_DATETIME = 'Y-m-d H:i:s';

	/** Failed logins within LOCAL_RATE_WINDOW that trigger a local temporary block. */
	private const LOCAL_RATE_THRESHOLD = 5;

	/** Rolling window (seconds) in which failures are counted toward the threshold. */
	private const LOCAL_RATE_WINDOW = 10 * MINUTE_IN_SECONDS;

	/** How long a locally rate-limited IP stays blocked (seconds). */
	private const LOCAL_RATE_BLOCK_TTL = HOUR_IN_SECONDS;

	/** Distinct IPs locally rate-limited within SPIKE_WINDOW that trigger an admin alert. */
	private const SPIKE_THRESHOLD = 5;

	/** Rolling window (seconds) in which local rate-limit blocks are counted toward the spike threshold. */
	private const SPIKE_WINDOW = HOUR_IN_SECONDS;

	/** Minimum time (seconds) between spike alert emails. */
	private const SPIKE_ALERT_COOLDOWN = 6 * HOUR_IN_SECONDS;

	/** 404 requests within SCAN_WINDOW that trigger a local block + SCANNING report. */
	private const SCAN_THRESHOLD = 10;

	/** Rolling window (seconds) in which 404s are counted toward the scan threshold. */
	private const SCAN_WINDOW = 5 * MINUTE_IN_SECONDS;

	/** How long an IP caught scanning stays blocked (seconds). */
	private const SCAN_BLOCK_TTL = HOUR_IN_SECONDS;

	/** Object cache group for is_blocked() results. */
	private const CACHE_GROUP = 'ipabuse_firewall';

	/**
	 * How long an is_blocked() result is cached. Short enough that a manual
	 * unblock (which also explicitly clears the cache) or clear_all() (which
	 * doesn't — see its docblock) is only stale for a bounded window; long
	 * enough to meaningfully cut DB load from repeat requests by the same
	 * IP during an active attack, on sites running a persistent object cache
	 * (Redis/Memcached). A no-op without one, since WP's default object
	 * cache doesn't persist across requests.
	 */
	private const CACHE_TTL = 60;

	/** @return string Cache key for is_blocked() results for a given IP. */
	private static function cache_key( string $ip ): string {
		return 'blocked_' . md5( $ip );
	}

	/**
	 * Return the current visitor's real IP.
	 *
	 * HTTP_X_FORWARDED_FOR is deliberately excluded: unlike CF-Connecting-IP or
	 * X-Real-IP (only present when a trusted reverse proxy sets them),
	 * X-Forwarded-For is attacker-controlled on any origin not behind a proxy
	 * that strips/overwrites it, letting a client spoof an IP to dodge its own
	 * block or get an innocent IP blocked/reported.
	 */
	public static function get_client_ip(): string {
		$candidates = [
			'HTTP_CF_CONNECTING_IP', // Cloudflare
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		];
		foreach ( $candidates as $key ) {
			$val = $_SERVER[ $key ] ?? '';
			$ip  = filter_var( trim( explode( ',', $val )[0] ), FILTER_VALIDATE_IP );
			if ( $ip ) {
				return $ip;
			}
		}
		return '0.0.0.0';
	}

	/** Check whether the given IP is on the admin-configured allowlist. */
	public static function is_allowlisted( string $ip ): bool {
		$allowlist = ipabuse_opt( 'allowlist', '' );
		if ( '' === $allowlist ) {
			return false;
		}
		$ips = array_map( 'trim', explode( "\n", $allowlist ) );
		return in_array( $ip, $ips, true );
	}

	/** Check if the given IP is in the blocked list. */
	public static function is_blocked( string $ip ): bool {
		// Never block loopback or private ranges, or admin-allowlisted IPs.
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return false;
		}
		if ( self::is_allowlisted( $ip ) ) {
			return false;
		}

		$cache_key = self::cache_key( $ip );
		$cached    = wp_cache_get( $cache_key, self::CACHE_GROUP, false, $found );
		if ( $found ) {
			return (bool) $cached;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'ipabuse_blocked';
		$now   = gmdate( self::MYSQL_DATETIME );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$exists = $wpdb->get_var( $wpdb->prepare(
			"SELECT id FROM `{$table}` WHERE ip = %s AND (expires_at = '0000-00-00 00:00:00' OR expires_at > %s) LIMIT 1",
			$ip,
			$now
		) );

		$is_blocked = ! empty( $exists );
		wp_cache_set( $cache_key, $is_blocked, self::CACHE_GROUP, self::CACHE_TTL );

		return $is_blocked;
	}

	/**
	 * Block a single IP.
	 *
	 * @param string      $ip
	 * @param int         $score    0–100
	 * @param int         $ttl      Seconds until expiry; 0 = permanent.
	 * @param string|null $country  ISO 3166-1 alpha-2 country code, if known.
	 */
	public static function block( string $ip, int $score = 0, int $ttl = 0, ?string $country = null ): void {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}

		global $wpdb;
		$table      = $wpdb->prefix . 'ipabuse_blocked';
		$expires_at = $ttl > 0
			? gmdate( self::MYSQL_DATETIME, time() + $ttl )
			: '0000-00-00 00:00:00';

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare(
			"INSERT INTO `{$table}` (ip, score, country, blocked_at, expires_at) VALUES (%s, %d, %s, NOW(), %s)
			 ON DUPLICATE KEY UPDATE score = VALUES(score), country = VALUES(country), blocked_at = NOW(), expires_at = VALUES(expires_at)",
			$ip,
			$score,
			$country,
			$expires_at
		) );

		wp_cache_set( self::cache_key( $ip ), true, self::CACHE_GROUP, self::CACHE_TTL );
	}

	/**
	 * Bulk-block IPs from an API blocklist response using batched INSERTs.
	 *
	 * @param array $items  Array of IP strings or objects with ipAddress/reputationScore/country.
	 * @param int   $ttl    Seconds until expiry; 0 = permanent.
	 */
	public static function bulk_block( array $items, int $ttl = 0 ): void {
		$pairs = self::normalize_items( $items );
		if ( empty( $pairs ) ) {
			return;
		}

		global $wpdb;
		$table      = $wpdb->prefix . 'ipabuse_blocked';
		$expires_at = $ttl > 0
			? gmdate( self::MYSQL_DATETIME, time() + $ttl )
			: '0000-00-00 00:00:00';

		// Process in batches to avoid hitting query size limits.
		foreach ( array_chunk( $pairs, self::BATCH_SIZE ) as $batch ) {
			$placeholders = [];
			$values       = [];
			foreach ( $batch as $row ) {
				$placeholders[] = '(%s, %d, %s, NOW(), %s)';
				$values[]       = $row['ip'];
				$values[]       = $row['score'];
				$values[]       = $row['country'];
				$values[]       = $expires_at;
			}
			$sql = "INSERT INTO `{$table}` (ip, score, country, blocked_at, expires_at) VALUES "
				. implode( ', ', $placeholders )
				. ' ON DUPLICATE KEY UPDATE score = VALUES(score), country = VALUES(country), blocked_at = NOW(), expires_at = VALUES(expires_at)';

			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$wpdb->query( $wpdb->prepare( $sql, $values ) );
		}

		foreach ( $pairs as $row ) {
			wp_cache_set( self::cache_key( $row['ip'] ), true, self::CACHE_GROUP, self::CACHE_TTL );
		}
	}

	/**
	 * Force-block any already-known IP whose country matches the admin's
	 * country blocklist, regardless of its reputation score. Intended to be
	 * called with a lower-threshold blocklist fetch (e.g. min_score=0) so
	 * IPs that wouldn't otherwise clear the configured score threshold are
	 * still blocked when they originate from a flagged country.
	 *
	 * Only covers IPs ipabuse.org already has data on — it cannot identify
	 * the country of a first-time visitor with no prior reputation history,
	 * since that would require a local GeoIP database or a per-request
	 * remote lookup, neither of which this plugin does.
	 *
	 * @param  array           $items          Same format as bulk_block().
	 * @param  array<int,string> $country_codes  Uppercase ISO 3166-1 alpha-2 codes.
	 * @return int Number of IPs blocked.
	 */
	public static function enforce_country_blocklist( array $items, array $country_codes ): int {
		if ( empty( $country_codes ) ) {
			return 0;
		}

		$country_codes = array_map( 'strtoupper', $country_codes );
		$matched       = array_filter(
			self::normalize_items( $items ),
			fn( $row ) => $row['country'] && in_array( $row['country'], $country_codes, true )
		);

		foreach ( $matched as $row ) {
			self::block( $row['ip'], 100, 0, $row['country'] );
		}

		return count( $matched );
	}

	/**
	 * Normalize a blocklist API response into (ip, score, country) rows,
	 * dropping anything without a valid IP.
	 *
	 * @param  array $items
	 * @return array<int, array{ ip: string, score: int, country: string|null }>
	 */
	private static function normalize_items( array $items ): array {
		$pairs = [];
		foreach ( $items as $item ) {
			$ip      = is_string( $item ) ? $item : ( $item['ipAddress'] ?? '' );
			$score   = is_array( $item ) ? (int) ( $item['reputationScore'] ?? 0 ) : 0;
			$country = is_array( $item ) && ! empty( $item['country'] ) ? strtoupper( (string) $item['country'] ) : null;
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$pairs[] = [ 'ip' => $ip, 'score' => $score, 'country' => $country ];
			}
		}
		return $pairs;
	}

	/**
	 * Count a failed login against an IP and locally block it once it exceeds
	 * LOCAL_RATE_THRESHOLD failures within LOCAL_RATE_WINDOW. This covers the
	 * window before a brute-forcing IP would otherwise appear in the next
	 * synced ipabuse.org blocklist.
	 *
	 * @param string $ip
	 * @param int    $weight  How much this failure counts toward the threshold
	 *                        (e.g. 2 for a username that doesn't exist, since
	 *                        that's a stronger signal of enumeration/guessing
	 *                        than a real user mistyping their password).
	 */
	public static function record_local_failure( string $ip, int $weight = 1 ): void {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return;
		}
		if ( self::is_allowlisted( $ip ) ) {
			return;
		}

		$key   = 'ipabuse_local_fails_' . wp_hash( $ip );
		$count = (int) get_transient( $key ) + max( 1, $weight );
		set_transient( $key, $count, self::LOCAL_RATE_WINDOW );

		if ( $count >= self::LOCAL_RATE_THRESHOLD ) {
			self::block( $ip, 100, self::LOCAL_RATE_BLOCK_TTL );
			self::log_history( $ip, 'BLOCKED', 'LOCAL_RATE_LIMIT', 100 );
			delete_transient( $key );
			self::maybe_alert_spike();
		}
	}

	/**
	 * Record a block/unblock event in the history log. Only called for
	 * lower-frequency, higher-signal events (local rate-limit blocks, manual
	 * unblocks) — not for every synced-blocklist IP, which would make the
	 * log grow unboundedly every 15 minutes for no real benefit, since that
	 * activity is already visible on the Dashboard and Blocked IPs pages.
	 *
	 * @param string $ip
	 * @param string $action  'BLOCKED' or 'UNBLOCKED'
	 * @param string $reason  'LOCAL_RATE_LIMIT', 'MANUAL', etc.
	 * @param int    $score
	 */
	private static function log_history( string $ip, string $action, string $reason, int $score = 0 ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'ipabuse_block_history';
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare(
			"INSERT INTO `{$table}` (ip, action, reason, score, created_at) VALUES (%s, %s, %s, %d, NOW())",
			$ip,
			$action,
			$reason,
			$score
		) );
	}

	/**
	 * Most recent block/unblock history entries, newest first.
	 *
	 * @param  int $limit
	 * @return array<int, array{ ip: string, action: string, reason: string, score: int, created_at: string }>
	 */
	public static function get_history( int $limit = 20 ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'ipabuse_block_history';
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT ip, action, reason, score, created_at FROM `{$table}` ORDER BY created_at DESC LIMIT %d", $limit ),
			ARRAY_A
		);
		return $rows ?: [];
	}

	/**
	 * Data-retention cleanup for the history log.
	 *
	 * @param  int $days  0 disables retention cleanup entirely.
	 * @return int Rows deleted.
	 */
	public static function purge_history_older_than( int $days ): int {
		if ( $days <= 0 ) {
			return 0;
		}

		global $wpdb;
		$table  = $wpdb->prefix . 'ipabuse_block_history';
		$cutoff = gmdate( self::MYSQL_DATETIME, time() - $days * DAY_IN_SECONDS );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->query( $wpdb->prepare(
			"DELETE FROM `{$table}` WHERE created_at <= %s",
			$cutoff
		) );
	}

	/**
	 * Email the site admin once if SPIKE_THRESHOLD distinct IPs have been
	 * locally rate-limited within SPIKE_WINDOW, indicating a possible
	 * coordinated brute-force attack. Rate-limited to one email per
	 * SPIKE_ALERT_COOLDOWN to avoid flooding the admin's inbox.
	 */
	private static function maybe_alert_spike(): void {
		if ( '1' !== ipabuse_opt( 'enable_alerts', '1' ) ) {
			return;
		}

		$spike_key = 'ipabuse_spike_count';
		$count     = (int) get_transient( $spike_key ) + 1;
		set_transient( $spike_key, $count, self::SPIKE_WINDOW );

		if ( $count < self::SPIKE_THRESHOLD ) {
			return;
		}
		if ( get_transient( 'ipabuse_spike_alert_sent' ) ) {
			return;
		}
		set_transient( 'ipabuse_spike_alert_sent', 1, self::SPIKE_ALERT_COOLDOWN );

		$admin_email = get_option( 'admin_email' );
		if ( ! $admin_email ) {
			return;
		}

		$blocked_url = admin_url( 'admin.php?page=' . IPABUSE_MENU_SLUG . '-blocked' );

		$subject = sprintf(
			/* translators: %s = site name */
			__( '[%s] IPAbuse Firewall: possible brute-force attack detected', 'ipabuse-firewall' ),
			get_bloginfo( 'name' )
		);
		$body_html = sprintf(
			/* translators: %d = number of IPs blocked in the last hour */
			esc_html__( '%d IP addresses were automatically blocked for repeated failed logins within the last hour. This may indicate a coordinated brute-force attack against your site.', 'ipabuse-firewall' ),
			$count
		);
		$html = ipabuse_render_email_html(
			__( 'Possible brute-force attack detected', 'ipabuse-firewall' ),
			'<p style="margin:0;">' . $body_html . '</p>',
			__( 'View Blocked IPs', 'ipabuse-firewall' ),
			$blocked_url
		);

		wp_mail( $admin_email, $subject, $html, [ 'Content-Type: text/html; charset=UTF-8' ] );
	}

	/**
	 * Count a 404 request against an IP and, once it exceeds SCAN_THRESHOLD
	 * within SCAN_WINDOW, locally block it and report it to ipabuse.org as
	 * SCANNING. A single 404 is meaningless (every site gets stray ones from
	 * normal visitors/crawlers) — only a sustained burst is worth acting on,
	 * unlike failed logins where every single attempt is already suspicious.
	 *
	 * @param string $ip
	 */
	public static function record_scan_attempt( string $ip ): void {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return;
		}
		if ( self::is_allowlisted( $ip ) ) {
			return;
		}

		$key   = 'ipabuse_scan_' . wp_hash( $ip );
		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, self::SCAN_WINDOW );

		if ( $count >= self::SCAN_THRESHOLD ) {
			self::block( $ip, 100, self::SCAN_BLOCK_TTL );
			self::log_history( $ip, 'BLOCKED', 'SCANNING', 100 );
			delete_transient( $key );

			IPAbuse_Reporter::report_abuse(
				$ip,
				'SCANNING',
				sprintf(
					'%d requests for nonexistent pages within %d minutes',
					$count,
					self::SCAN_WINDOW / MINUTE_IN_SECONDS
				)
			);
		}
	}

	/**
	 * Hourly count of IPs blocked over the last $hours, oldest first, with
	 * hours that had no blocks filled in as 0. Used for the dashboard widget
	 * sparkline.
	 *
	 * @param  int $hours
	 * @return array<int, int>
	 */
	public static function hourly_block_counts( int $hours = 24 ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'ipabuse_blocked';
		$since = gmdate( self::MYSQL_DATETIME, time() - $hours * HOUR_IN_SECONDS );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE_FORMAT( blocked_at, '%%Y-%%m-%%d %%H:00:00' ) AS hour_bucket, COUNT(*) AS cnt
				 FROM `{$table}`
				 WHERE blocked_at >= %s
				 GROUP BY hour_bucket",
				$since
			),
			ARRAY_A
		);

		$by_hour = [];
		foreach ( (array) $rows as $row ) {
			$by_hour[ $row['hour_bucket'] ] = (int) $row['cnt'];
		}

		$series = [];
		for ( $i = $hours - 1; $i >= 0; $i-- ) {
			$bucket    = gmdate( 'Y-m-d H:00:00', time() - $i * HOUR_IN_SECONDS );
			$series[] = $by_hour[ $bucket ] ?? 0;
		}
		return $series;
	}

	/**
	 * Paginated listing of currently-blocked IPs (excluding expired entries),
	 * most recently blocked first, optionally filtered by IP substring.
	 *
	 * @param  int    $per_page
	 * @param  int    $page     1-indexed.
	 * @param  string $search   Optional IP substring filter.
	 * @return array{ items: array<int, array{ ip: string, score: int, country: string|null, blocked_at: string, expires_at: string }>, total: int }
	 */
	public static function list_blocked( int $per_page = 20, int $page = 1, string $search = '' ): array {
		global $wpdb;
		$table  = $wpdb->prefix . 'ipabuse_blocked';
		$now    = gmdate( self::MYSQL_DATETIME );
		$offset = max( 0, ( max( 1, $page ) - 1 ) * $per_page );

		$where  = '(expires_at = \'0000-00-00 00:00:00\' OR expires_at > %s)';
		$values = [ $now ];

		if ( '' !== $search ) {
			$where   .= ' AND ip LIKE %s';
			$values[] = '%' . $wpdb->esc_like( $search ) . '%';
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared
		$total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$table}` WHERE {$where}", $values ) );

		$values[] = $per_page;
		$values[] = $offset;

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared
		$items = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip, score, country, blocked_at, expires_at FROM `{$table}` WHERE {$where} ORDER BY blocked_at DESC LIMIT %d OFFSET %d",
				$values
			),
			ARRAY_A
		);

		return [ 'items' => $items ?: [], 'total' => $total ];
	}

	/** Unblock a single IP. */
	public static function unblock( string $ip ): void {
		global $wpdb;
		$table   = $wpdb->prefix . 'ipabuse_blocked';
		$deleted = $wpdb->delete( $table, [ 'ip' => $ip ], [ '%s' ] );
		if ( $deleted ) {
			wp_cache_delete( self::cache_key( $ip ), self::CACHE_GROUP );
			self::log_history( $ip, 'UNBLOCKED', 'MANUAL' );
		}
	}

	/**
	 * Unblock every currently-blocked IP. Logged as a single history entry
	 * rather than one per IP, since a clear-all is one admin action, not N.
	 *
	 * Does not explicitly clear per-IP is_blocked() cache entries — there's
	 * no bounded way to enumerate which IPs might be cached without a
	 * persistent-cache-specific API. Any stale "still blocked" cache entry
	 * self-expires within CACHE_TTL (60s), and clear_all() is a rare,
	 * deliberate admin action, not something that needs to take effect
	 * instantaneously for every in-flight request.
	 *
	 * @return int Rows deleted.
	 */
	public static function clear_all(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'ipabuse_blocked';
		// TRUNCATE always reports 0 affected rows in $wpdb->query(), so count first.
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		if ( $count > 0 ) {
			$wpdb->query( "TRUNCATE TABLE `{$table}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			self::log_history( '*', 'UNBLOCKED', 'MANUAL_CLEAR_ALL' );
		}
		return $count;
	}

	/** Return total blocked IP count (excluding expired entries). */
	public static function count(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'ipabuse_blocked';
		$now   = gmdate( self::MYSQL_DATETIME );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM `{$table}` WHERE expires_at = '0000-00-00 00:00:00' OR expires_at > %s",
			$now
		) );
	}

	/**
	 * Remove IPs whose TTL has elapsed.
	 *
	 * @return int Rows deleted.
	 */
	public static function purge_expired(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'ipabuse_blocked';
		$now   = gmdate( self::MYSQL_DATETIME );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->query( $wpdb->prepare(
			"DELETE FROM `{$table}` WHERE expires_at != '0000-00-00 00:00:00' AND expires_at <= %s",
			$now
		) );
	}

	/**
	 * Data-retention cleanup: remove blocked-IP rows older than $days, regardless
	 * of their expiry status. Guards against permanently-blocked rows (e.g. from
	 * local rate-limiting re-marked permanent, or a stopped sync) accumulating
	 * indefinitely.
	 *
	 * @param  int $days  0 disables retention cleanup entirely.
	 * @return int Rows deleted.
	 */
	public static function purge_older_than( int $days ): int {
		if ( $days <= 0 ) {
			return 0;
		}

		global $wpdb;
		$table  = $wpdb->prefix . 'ipabuse_blocked';
		$cutoff = gmdate( self::MYSQL_DATETIME, time() - $days * DAY_IN_SECONDS );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->query( $wpdb->prepare(
			"DELETE FROM `{$table}` WHERE blocked_at <= %s",
			$cutoff
		) );
	}

	/**
	 * Remove IPs not present in the latest blocklist response.
	 * Called after bulk_block() during a cron sync so IPs that improved
	 * their score below the threshold are automatically unblocked.
	 *
	 * @param  array $items  Same format as bulk_block().
	 * @return int   Rows deleted.
	 */
	public static function purge_missing( array $items ): int {
		$current_ips = array_values( array_filter( array_map(
			fn( $item ) => is_string( $item ) ? $item : ( $item['ipAddress'] ?? '' ),
			$items
		) ) );

		if ( empty( $current_ips ) ) {
			return 0;
		}

		global $wpdb;
		$table        = $wpdb->prefix . 'ipabuse_blocked';
		$placeholders = implode( ', ', array_fill( 0, count( $current_ips ), '%s' ) );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared
		return (int) $wpdb->query( $wpdb->prepare(
			"DELETE FROM `{$table}` WHERE ip NOT IN ({$placeholders})",
			$current_ips
		) );
	}
}
