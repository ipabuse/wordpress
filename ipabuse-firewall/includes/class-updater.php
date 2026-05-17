<?php
/**
 * IPAbuse Firewall — Auto-Updater
 *
 * Hooks into WordPress's transient-based update system to surface new plugin
 * versions from ipabuse.org without requiring the plugin to be listed on
 * wordpress.org.
 *
 * How it works:
 * 1. WordPress calls `pre_set_site_transient_update_plugins` when it checks for
 *    updates (roughly every 12 h, or manually via Dashboard → Updates).
 * 2. This class fetches version metadata from GET /v1/plugin/version (public,
 *    no API key required) and caches the response for 12 hours.
 * 3. If the remote version is newer than IPABUSE_VERSION, the update object is
 *    injected into the transient so WordPress shows the "Update Available" notice
 *    and handles the download / install automatically.
 * 4. The `plugins_api` filter powers the "View Details" modal in wp-admin.
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

class IPAbuse_Updater {

	private const VERSION_URL   = IPABUSE_API_BASE . '/version';
	private const CACHE_TIMEOUT = 12 * HOUR_IN_SECONDS;
	private const CACHE_KEY     = 'ipabuse_remote_version';
	private const PLUGIN_SLUG   = 'ipabuse-firewall';

	private string $plugin_basename;

	public function __construct( string $plugin_file ) {
		$this->plugin_basename = plugin_basename( $plugin_file );

		add_filter( 'pre_set_site_transient_update_plugins', [ $this, 'check_update' ] );
		add_filter( 'plugins_api', [ $this, 'plugin_info' ], 10, 3 );
		add_action( 'upgrader_process_complete', [ $this, 'purge_cache' ], 10, 2 );
	}

	/**
	 * Inject update info into the WP update transient when a newer version exists.
	 *
	 * @param  object $transient The WP update transient.
	 * @return object
	 */
	public function check_update( object $transient ): object {
		// WP populates $transient->checked once it has version data for all plugins.
		if ( empty( $transient->checked ) ) {
			return $transient;
		}

		$remote = $this->fetch_remote_version();
		if ( ! $remote ) {
			return $transient;
		}

		if ( version_compare( $remote->version, IPABUSE_VERSION, '>' ) ) {
			$update                  = new \stdClass();
			$update->id              = self::PLUGIN_SLUG;
			$update->slug            = self::PLUGIN_SLUG;
			$update->plugin          = $this->plugin_basename;
			$update->new_version     = $remote->version;
			$update->url             = $remote->details_url ?? 'https://ipabuse.org/plugins/wordpress';
			$update->package         = $remote->download_url ?? '';
			$update->requires        = $remote->requires_wp  ?? '5.9';
			$update->tested          = $remote->tested_wp    ?? '6.7';
			$update->requires_php    = $remote->requires_php ?? '7.4';
			$update->upgrade_notice  = $remote->upgrade_notice ?? '';

			$transient->response[ $this->plugin_basename ] = $update;
		} else {
			// Mark as "no update" so WP doesn't keep hitting our server redundantly.
			$no_update          = new \stdClass();
			$no_update->id      = self::PLUGIN_SLUG;
			$no_update->slug    = self::PLUGIN_SLUG;
			$no_update->plugin  = $this->plugin_basename;
			$no_update->new_version = $remote->version;
			$no_update->url     = $remote->details_url ?? 'https://ipabuse.org/plugins/wordpress';

			$transient->no_update[ $this->plugin_basename ] = $no_update;
		}

		return $transient;
	}

	/**
	 * Supply plugin metadata for the "View Details" modal in wp-admin.
	 *
	 * @param  mixed  $result Default result (false if not yet handled).
	 * @param  string $action The API action being performed.
	 * @param  object $args   Plugin arguments, including $args->slug.
	 * @return mixed
	 */
	public function plugin_info( mixed $result, string $action, object $args ): mixed {
		if ( $action !== 'plugin_information' || ( $args->slug ?? '' ) !== self::PLUGIN_SLUG ) {
			return $result;
		}

		$remote = $this->fetch_remote_version();
		if ( ! $remote ) {
			return $result;
		}

		$info                = new \stdClass();
		$info->name          = 'IPAbuse Firewall';
		$info->slug          = self::PLUGIN_SLUG;
		$info->version       = $remote->version;
		$info->author        = '<a href="https://ipabuse.org">ipabuse.org</a>';
		$info->homepage      = 'https://ipabuse.org/plugins/wordpress';
		$info->requires      = $remote->requires_wp  ?? '5.9';
		$info->tested        = $remote->tested_wp    ?? '6.7';
		$info->requires_php  = $remote->requires_php ?? '7.4';
		$info->download_link = $remote->download_url ?? '';
		$info->last_updated  = $remote->released_at  ?? '';
		$info->sections      = [
			'description' => '<p>Automatically blocks malicious IPs using the <a href="https://ipabuse.org">ipabuse.org</a> reputation database. Reports brute-force logins and syncs the blocklist every 15 minutes.</p>',
			'changelog'   => wpautop( $remote->changelog ?? 'See <a href="https://ipabuse.org/plugins/wordpress#changelog">ipabuse.org</a>.' ),
		];

		return $info;
	}

	/**
	 * Purge the cached version info after a plugin update completes so the
	 * next check always fetches fresh data.
	 *
	 * @param  mixed $upgrader Upgrader instance.
	 * @param  array $options  Upgrade options.
	 */
	public function purge_cache( mixed $upgrader, array $options ): void {
		if (
			isset( $options['action'], $options['type'] ) &&
			$options['action'] === 'update' &&
			$options['type']   === 'plugin'
		) {
			delete_transient( self::CACHE_KEY );
		}
	}

	// ── Private ────────────────────────────────────────────────────────────────

	/**
	 * Fetch (and cache for 12 h) version metadata from the ipabuse.org API.
	 *
	 * @return \stdClass|null
	 */
	private function fetch_remote_version(): ?\stdClass {
		$cached = get_transient( self::CACHE_KEY );
		if ( $cached instanceof \stdClass ) {
			return $cached;
		}

		$response = wp_remote_get(
			self::VERSION_URL,
			[
				'timeout'    => 10,
				'user-agent' => 'IPAbuse-Firewall/' . IPABUSE_VERSION . '; WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' ),
				'sslverify'  => true,
			]
		);

		if ( is_wp_error( $response ) ) {
			return null;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			return null;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ) );
		if ( ! $body || empty( $body->data ) || ! is_object( $body->data ) ) {
			return null;
		}

		set_transient( self::CACHE_KEY, $body->data, self::CACHE_TIMEOUT );
		return $body->data;
	}
}
