<?php
/**
 * IPAbuse Firewall — API Client
 * Wraps all HTTP calls to the ipabuse.org plugin API using WordPress's HTTP API.
 *
 * @package IPAbuse_Firewall
 */

defined( 'ABSPATH' ) || exit;

class IPAbuse_Api_Client {

	private string $api_key;
	private string $base_url;
	private int    $timeout;

	public function __construct( string $api_key, string $base_url = IPABUSE_API_BASE, int $timeout = 10 ) {
		$this->api_key  = $api_key;
		$this->base_url = rtrim( $base_url, '/' );
		$this->timeout  = $timeout;
	}

	/** Verify the API key is valid. */
	public function verify(): array {
		return $this->get( '/verify' );
	}

	/**
	 * Fetch the blocklist.
	 *
	 * @param int $min_score  0–100
	 * @param int $limit      max IPs
	 * @return array{ ok: bool, data?: array, error?: string }
	 */
	public function blocklist( int $min_score = 75, int $limit = 1000 ): array {
		return $this->get( '/blocklist', [
			'min_score' => $min_score,
			'format'    => 'json',
			'limit'     => $limit,
		] );
	}

	/** Look up reputation of a single IP. */
	public function lookup( string $ip ): array {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return [ 'ok' => false, 'error' => 'Invalid IP address' ];
		}
		return $this->get( '/lookup/' . rawurlencode( $ip ) );
	}

	/** Submit an abuse report. Tagged with pluginSource=WORDPRESS so reports are attributable by origin. */
	public function report( string $ip, string $category = 'BRUTE_FORCE', string $description = '', int $severity = 3 ): array {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return [ 'ok' => false, 'error' => 'Invalid IP address' ];
		}
		return $this->post( '/report', [
			'ip'           => $ip,
			'category'     => $category,
			'description'  => $description,
			'severity'     => $severity,
			'pluginSource' => 'WORDPRESS',
		] );
	}

	/**
	 * Start account creation on ipabuse.org for the setup wizard. Unauthenticated
	 * (there's no API key yet — that's the point) and deliberately never returns
	 * anything beyond ok/error: the API key itself is only ever issued after the
	 * admin verifies their email and logs in at ipabuse.org/settings?tab=api.
	 *
	 * @param  string $email     Site admin email, prefilled from WordPress.
	 * @param  string $site_url  This site's URL, prefilled from WordPress.
	 * @return array{ ok: bool, error?: string }
	 */
	public static function register_account( string $email, string $site_url ): array {
		$response = wp_remote_post( rtrim( IPABUSE_API_BASE, '/' ) . '/register-account', [
			'timeout' => 10,
			'headers' => [
				'Content-Type' => 'application/json',
				'Accept'       => 'application/json',
			],
			'body'    => wp_json_encode( [ 'email' => $email, 'siteUrl' => $site_url ] ),
		] );
		return self::parse_response( $response );
	}

	// ── Private ───────────────────────────────────────────────────────────────

	private function get( string $path, array $query = [] ): array {
		$url = $this->base_url . $path;
		if ( ! empty( $query ) ) {
			$url .= '?' . http_build_query( $query );
		}
		$response = wp_remote_get( $url, [
			'timeout' => $this->timeout,
			'headers' => $this->headers(),
		] );
		return self::parse_response( $response );
	}

	private function post( string $path, array $body ): array {
		$response = wp_remote_post( $this->base_url . $path, [
			'timeout' => $this->timeout,
			'headers' => $this->headers(),
			'body'    => wp_json_encode( $body ),
		] );
		return self::parse_response( $response );
	}

	private function headers(): array {
		return [
			'X-API-Key'    => $this->api_key,
			'Content-Type' => 'application/json',
			'Accept'       => 'application/json',
		];
	}

	private static function parse_response( $response ): array {
		if ( is_wp_error( $response ) ) {
			return [ 'ok' => false, 'error' => $response->get_error_message() ];
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) ) {
			return [ 'ok' => false, 'error' => 'Invalid JSON response', 'http_code' => $code ];
		}

		if ( $code >= 400 ) {
			return [ 'ok' => false, 'error' => $data['error'] ?? 'API error', 'http_code' => $code ];
		}

		return [ 'ok' => true, 'data' => $data['data'] ?? $data, 'http_code' => $code ];
	}
}
