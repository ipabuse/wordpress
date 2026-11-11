=== IPAbuse Firewall ===
Contributors: ipabuse
Tags: security, firewall, brute force, ip blocking, login protection
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.6.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Automatically blocks malicious IPs using the ipabuse.org reputation database, and reports brute-force logins back to it.

== Description ==

IPAbuse Firewall protects your site against brute-force login attempts and known-malicious visitors by syncing with the [ipabuse.org](https://ipabuse.org) IP reputation database.

**Features:**

* Automatically blocks visitors whose IP address meets or exceeds a reputation score threshold you choose.
* Syncs the blocklist from ipabuse.org every 15 minutes via WP-Cron.
* Reports failed WordPress logins to ipabuse.org so the community blocklist improves over time.
* Dashboard with live protection status, recent sync results, and recently blocked IPs.
* Dedicated Blocked IPs page with search, pagination, and one-click unblock.
* AJAX-powered IP reputation lookup tool — no page reload.
* Local rate-limiting: temporarily blocks an IP after repeated failed logins, before the next ipabuse.org sync.
* Trusted IP allowlist — exempt specific IPs from blocking, reporting, and rate-limiting.
* Test-connection and manual-sync buttons for quick diagnostics.
* wp-admin Dashboard widget with a 24-hour block-activity sparkline.
* Email alerts when a possible coordinated brute-force attack is detected.
* CSV export of blocked IPs.
* REST API status endpoint for external monitoring.

An ipabuse.org account and API key are required. [Generate a free API key](https://ipabuse.org/api-keys) to get started.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/ipabuse-firewall` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Go to the **IPAbuse Firewall** menu in the admin sidebar → **Settings**, and enter your ipabuse.org API key.
4. Configure the minimum reputation score and sync limit, then save.

== Frequently Asked Questions ==

= Does this plugin require an account? =

Yes. You need a free ipabuse.org account and API key to fetch the blocklist and submit reports.

= What data is sent to ipabuse.org? =

When "Report Failed Logins" is enabled (on by default), the plugin automatically reports: failed wp-login.php/XML-RPC login attempts (BRUTE_FORCE), comment spam (SPAM), and sustained bursts of requests for nonexistent pages (SCANNING). Each report includes the IP address, category, and a generic description — the attempted username is never included. Private/loopback IP ranges, and any IP on your allowlist, are never reported. Disable the "Report Failed Logins" option on the plugin's Settings page to turn off all automatic reporting. You can also manually block or report any IP from the IP Lookup page or via WP-CLI, independent of this setting.

= Will this plugin block my own IP? =

No. Private and loopback IP ranges are never blocked or reported.

== Changelog ==

= 1.6.0 =
* Added a "Connect Your Account" setup wizard (Dashboard and Settings pages): prefills this site's URL and admin email, starts account creation on ipabuse.org, and tells you to verify your email there. The API key itself still has to be generated and pasted in by hand — the wizard never receives or stores it on your behalf.

= 1.5.2 =
* Added an object-cache layer for the blocked-IP count, invalidated automatically whenever the blocklist changes.
* Added a "Clear Cache" action — a Settings page button and a `wp ipabuse clear-cache` CLI command — to flush the plugin's cache on demand (e.g. after restoring a database backup).

= 1.5.1 =
* Now requires WordPress 6.2+ (up from 5.9), so all custom-table queries can bind table names through `$wpdb->prepare()`'s `%i` identifier placeholder instead of raw string interpolation.

= 1.5.0 =
* Added manual IP blocking and manual reporting to ipabuse.org, from the IP Lookup page (Block This IP / Report to ipabuse.org with a category picker) and via new `wp ipabuse block|report` CLI commands.
* Added automatic detection and reporting for two more abuse categories beyond BRUTE_FORCE:
  * **SPAM** — comment spam (Akismet-rejected or manually moderated) now reports the commenter's IP.
  * **SCANNING** — a burst of requests for nonexistent pages (10+ within 5 minutes) now blocks the IP and reports it, catching reconnaissance/probing before a real attack.
* Reporting logic was consolidated into one shared, deduped, toggle-respecting method (`IPAbuse_Reporter::report_abuse()`) used by every detector and by the new manual actions, instead of duplicating gating/dedup logic per feature.

= 1.4.2 =
* Added a `blocked_at` index to the blocked-IPs table — it's used in sorting/filtering on the Blocked IPs page, the dashboard sparkline, and retention cleanup, and was previously unindexed.
* `is_blocked()` is now cached per-IP for 60 seconds (invalidated on block/unblock), cutting repeat database hits on sites running a persistent object cache (Redis/Memcached) — most valuable exactly when it matters most: sustained traffic from an actively-blocked IP.
* Country Blocklist is now a searchable, checkbox-based country picker (with removable chips for selections) instead of a free-text ISO-code field.
* **Bugfix:** the internal schema-version constant wasn't bumped alongside the `blocked_at` index, so the index would have silently never applied on sites that had already run the 1.4.1 upgrade. Fixed.
* The "Sync Now" button and `wp ipabuse sync` now run the exact same full sync routine as the 15-minute cron (prune missing/expired, apply country blocklist) instead of a partial subset of it.

= 1.4.1 =
* **Bugfix:** sites that already had the plugin active when the `country` column / block-history table were introduced never received that schema change, since `register_activation_hook()` only fires on activate/reactivate, not on a simple file update. This silently broke new blocks and the Blocked IPs/Dashboard listings (visible as a blocked-IP count that stopped updating) while `dbDelta()`-based inserts failed. Fixed with a version-gated upgrade check on `plugins_loaded` that self-heals the schema automatically — no manual action needed.
* Added `wp ipabuse block|unblock|sync|status` WP-CLI commands.
* Added XML-RPC brute-force detection (`xmlrpc_login_error`), using the same reporting/local-rate-limit path as wp-login.php.
* Added a Site Health → Info section showing plugin status for easier support/debugging.
* Added a "Danger Zone" Clear All Blocked IPs action on the Settings page, with a required confirmation checkbox.
* Blocked-IP table entries and the Dashboard's recent-blocks table now link each IP to its public ipabuse.org lookup page (opens in a new tab).
* The attack-alert email is now a branded HTML template instead of plain text.

= 1.4.0 =
* Local rate-limiting now weighs failed logins against nonexistent usernames more heavily than against real accounts, catching enumeration/credential-stuffing faster.
* Added a block/unblock history log (visible on the Blocked IPs page) so you can see why and when an IP was blocked or removed.
* Added bulk "Unblock" on the Blocked IPs page (select multiple IPs, apply once).
* Added Import/Export for plugin settings (JSON), excluding the API key, for applying the same configuration across multiple sites.
* Added an optional Country Blocklist: IPs ipabuse.org already has data on, from configured countries, are blocked regardless of reputation score. Does not cover first-time visitors, since that needs a local GeoIP database this plugin doesn't ship.
* Blocked-IP records now store country (where known) and display it on the Blocked IPs page and in CSV exports.

= 1.3.0 =
* Added a wp-admin Dashboard widget showing protection status, blocked-IP count, API connection state, last sync time, and a 24-hour block-activity sparkline.
* Added email alerts to the site admin when multiple IPs are locally rate-limited within an hour (possible coordinated brute-force attack), capped at one email every 6 hours.
* Added CSV export on the Blocked IPs page.
* Added a REST API status endpoint (`GET /wp-json/ipabuse-firewall/v1/status`) for external monitoring, gated by the `manage_options` capability.
* Added a configurable data retention setting: blocked-IP records older than N days are automatically removed on the next sync (default 365 days; 0 disables cleanup).
* Reports sent to ipabuse.org are now tagged with their originating plugin, matching the cPanel plugin's existing reporting behavior.

= 1.2.0 =
* Moved from a single Settings submenu to a top-level "IPAbuse Firewall" sidebar menu with Dashboard, Blocked IPs, IP Lookup, and Settings pages.
* New Blocked IPs page: search, pagination, and per-row unblock.
* Dashboard now shows the specific IPs processed by the last sync, not just a count, plus a recently-blocked-IPs table.
* IP Lookup tool converted to AJAX — no more full-page reload.
* Added local rate-limiting: an IP is temporarily blocked after repeated failed logins, independent of the ipabuse.org sync schedule.
* Added a Trusted IPs (Allowlist) setting exempting specific IPs from all blocking/reporting/rate-limiting.
* API key field is now masked and no longer wiped if the settings form is saved without re-entering it.

= 1.1.0 =
* Removed self-hosted update checker in favor of standard WordPress.org plugin updates.
* Fixed blocklist sync incorrectly unblocking still-malicious IPs when the remote list was larger than the configured sync limit.
* Fixed block-expiry comparisons to use UTC consistently, avoiding early/late unblocks on non-UTC sites.
* Removed `X-Forwarded-For` from trusted IP sources to prevent spoofing.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.1.0 =
This release fixes an IP-spoofing issue and a blocklist sync bug. Upgrading is recommended for all users.
