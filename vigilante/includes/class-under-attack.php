<?php
/**
 * Under Attack Mode
 *
 * Emergency mode with JavaScript challenge and aggressive restrictions.
 * Temporarily blocks automated traffic while allowing real browsers through.
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Under_Attack
 *
 * Provides temporary emergency protection against active attacks
 */
class Vigilante_Under_Attack {

    /**
     * Option name for Under Attack mode state
     */
    const OPTION_NAME = 'vigilante_under_attack_mode';

    /**
     * Cookie name for JS challenge verification
     */
    const COOKIE_NAME = 'vigilante_ua_verified';

    /**
     * Default duration in seconds (4 hours)
     */
    const DEFAULT_DURATION = 14400;

    /**
     * Challenge difficulty (number of leading zeros in hash)
     */
    const CHALLENGE_DIFFICULTY = 4;

    /**
     * Challenge nonce TTL in seconds (15 minutes).
     *
     * Long enough to tolerate slow Proof-of-Work on weak CPUs and short tab
     * idle, but not so long that abandoned challenges accumulate transients.
     */
    const NONCE_TTL = 900;

    /**
     * .htaccess block markers for cache bypass
     */
    const HTACCESS_MARKER_START = '# BEGIN Vigilante Under Attack';
    const HTACCESS_MARKER_END   = '# END Vigilante Under Attack';

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Activity log instance
     *
     * @var Vigilante_Activity_Log
     */
    private $activity_log;

    /**
     * Cached mode status
     *
     * @var array|null
     */
    private $status = null;

    /**
     * Constructor
     *
     * Hooks are registered on wp_loaded/template_redirect to avoid
     * the init-within-init timing issue where callbacks registered
     * during init execution are silently skipped by WordPress.
     *
     * @param Vigilante_Settings     $settings     Settings instance.
     * @param Vigilante_Activity_Log $activity_log Activity log instance.
     */
    public function __construct( $settings, $activity_log ) {
        $this->settings     = $settings;
        $this->activity_log = $activity_log;

        // Apply restrictions when active (is_active() auto-deactivates if expired)
        if ( $this->is_active() ) {
            // JS challenge for frontend visitors + challenge response handler
            add_action( 'template_redirect', array( $this, 'maybe_serve_challenge' ), 1 );

            // Override rate limiting to aggressive values
            add_filter( 'vigilante_rate_limit_requests', array( $this, 'aggressive_rate_limit' ) );
            add_filter( 'vigilante_rate_limit_duration', array( $this, 'aggressive_block_duration' ) );

            // Verified visitors bypass rate limiting — once a human passed the JS challenge
            // they should not be capped at the aggressive 30 req/min limit while loading
            // a page with many image/asset requests served through WordPress.
            add_filter( 'vigilante_skip_rate_limit', array( $this, 'maybe_skip_rate_limit' ) );

            // Block restricted HTTP methods and empty user agents (wp_loaded fires after init)
            add_action( 'wp_loaded', array( $this, 'restrict_http_methods' ) );
            add_action( 'wp_loaded', array( $this, 'block_empty_user_agent' ) );

            // Block XML-RPC completely
            add_filter( 'xmlrpc_enabled', '__return_false' );
            add_filter( 'xmlrpc_methods', '__return_empty_array' );

            // Restrict REST API to authenticated users only at the network layer.
            // (vigilante_options is also forced to authenticated_only via the snapshot,
            //  but this filter is stricter — it doesn't allow the public endpoints
            //  that the regular module's "selective" mode exposes.)
            add_filter( 'rest_authentication_errors', array( $this, 'restrict_rest_api' ), 99 );

            // Pause new user registrations regardless of WP core setting.
            add_filter( 'pre_option_users_can_register', '__return_zero' );

            // Force every new comment to moderation queue.
            add_filter( 'pre_comment_approved', array( $this, 'force_comment_moderation' ), 99 );

            // Tell caching plugins to stop serving cached pages
            $this->send_nocache_headers_for_plugins();
        }
    }

    /**
     * Check if Under Attack mode is currently active
     *
     * Self-correcting: if the mode has expired, it deactivates automatically
     * and returns false. This replaces the old check_expiration hook that
     * never fired due to the init-within-init timing issue.
     *
     * @return bool
     */
    public function is_active() {
        $status = $this->get_status();

        if ( empty( $status['active'] ) ) {
            return false;
        }

        // Auto-deactivate if expired
        $expires_at = ( $status['activated_at'] ?? 0 ) + ( $status['duration'] ?? 0 );

        if ( $expires_at <= time() ) {
            $this->deactivate( 'expired' );
            return false;
        }

        return true;
    }

    /**
     * Get current mode status
     *
     * @return array Status array with keys: active, activated_at, duration, secret.
     */
    public function get_status() {
        if ( null === $this->status ) {
            $this->status = get_option( self::OPTION_NAME, array(
                'active'           => false,
                'activated_at'     => 0,
                'duration'         => self::DEFAULT_DURATION,
                'secret'           => '',
                'previous_options' => null,
                'previous_preset'  => null,
            ) );
        }
        return $this->status;
    }

    /**
     * Get remaining time in seconds
     *
     * @return int Seconds remaining, 0 if not active or expired.
     */
    public function get_remaining_time() {
        $status = $this->get_status();

        if ( empty( $status['active'] ) || empty( $status['activated_at'] ) ) {
            return 0;
        }

        $expires_at = $status['activated_at'] + $status['duration'];
        $remaining  = $expires_at - time();

        return max( 0, $remaining );
    }

    /**
     * Activate Under Attack mode
     *
     * @param int $duration Duration in seconds. Default 4 hours.
     * @return bool Success.
     */
    public function activate( $duration = 0 ) {
        if ( $duration <= 0 ) {
            $duration = self::DEFAULT_DURATION;
        }

        // Snapshot the user's current configuration so we can restore it on
        // deactivate. We snapshot BEFORE applying the hardened config — any
        // changes the user makes to vigilante_options while the mode is active
        // will be reverted when the mode ends. The admin UI shows a banner
        // warning about this.
        $previous_options = get_option( Vigilante_Settings::OPTION_NAME, array() );
        $previous_preset  = get_option( 'vigilante_active_preset', '' );

        // Generate a secret for HMAC cookie signing
        $secret = wp_generate_password( 64, true, true );

        $status = array(
            'active'           => true,
            'activated_at'     => time(),
            'duration'         => absint( $duration ),
            'secret'           => $secret,
            'previous_options' => $previous_options,
            'previous_preset'  => $previous_preset,
        );

        $result = update_option( self::OPTION_NAME, $status );
        $this->status = null;

        if ( $result ) {
            // Apply the hardened configuration: Maximum preset + Under Attack overrides.
            $this->apply_hardened_options( $previous_options );

            // Refresh the Security Analyzer score so the dashboard reflects the
            // hardened config instead of the snapshot of the previous one.
            //
            // 1) Run the 'fast' phase synchronously (sub-second, offline checks
            //    like filesystem, options, WP version, modules) so the dashboard
            //    has at least the cheap checks refreshed when the AJAX returns
            //    and the page reloads.
            // 2) Schedule a full ('all') scan in the background to also refresh
            //    the slow HTTP-probe checks. The page reload triggers wp-cron,
            //    which picks up the one-shot event.
            $this->run_analyzer_scan( 'fast' );
            if ( ! wp_next_scheduled( 'vigilante_under_attack_post_scan' ) ) {
                wp_schedule_single_event( time() + 5, 'vigilante_under_attack_post_scan' );
            }

            // Cache bypass - best-effort, must not break activation AJAX response
            $this->safe_manage_cache( 'activate' );

            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'security',
                    'under_attack_activated',
                    sprintf(
                        /* translators: %s: Duration in hours */
                        __( 'Under Attack mode activated for %s hours', 'vigilante' ),
                        round( $duration / 3600, 1 )
                    ),
                    array( 'duration' => $duration ),
                    'warning'
                );
            }
        }

        // Send notification email
        $this->send_notification( 'activated', $duration );

        return $result;
    }

    /**
     * Deactivate Under Attack mode
     *
     * @param string $reason Reason for deactivation.
     * @return bool Success.
     */
    public function deactivate( $reason = 'manual' ) {
        // Restore the user's previous configuration BEFORE clearing the snapshot —
        // if the restore fails for any reason we want the snapshot to remain so
        // the next activation can recover.
        $current_status   = $this->get_status();
        $previous_options = $current_status['previous_options'] ?? null;
        $previous_preset  = $current_status['previous_preset'] ?? null;

        if ( is_array( $previous_options ) && ! empty( $previous_options ) ) {
            update_option( Vigilante_Settings::OPTION_NAME, $previous_options );
        }
        if ( null !== $previous_preset ) {
            if ( '' === $previous_preset ) {
                delete_option( 'vigilante_active_preset' );
            } else {
                update_option( 'vigilante_active_preset', $previous_preset );
            }
        }

        $status = array(
            'active'           => false,
            'activated_at'     => 0,
            'duration'         => self::DEFAULT_DURATION,
            'secret'           => '',
            'previous_options' => null,
            'previous_preset'  => null,
        );

        $result = update_option( self::OPTION_NAME, $status );
        $this->status = null;

        if ( $result ) {
            // Remove cache bypass rules - best-effort
            $this->safe_manage_cache( 'deactivate' );

            // Refresh the Security Analyzer with a full scan so the dashboard
            // reflects the restored configuration (including the slow HTTP/header
            // probes that we couldn't run safely while UA was active). Schedule
            // it for ~10 seconds out so the AJAX response returns immediately
            // and the WP cache layer has time to settle.
            if ( ! wp_next_scheduled( 'vigilante_under_attack_post_scan' ) ) {
                wp_schedule_single_event( time() + 10, 'vigilante_under_attack_post_scan' );
            }

            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'security',
                    'under_attack_deactivated',
                    sprintf(
                        /* translators: %s: Reason */
                        __( 'Under Attack mode deactivated (%s)', 'vigilante' ),
                        $reason
                    ),
                    array( 'reason' => $reason ),
                    'info'
                );
            }
        }

        // Send notification email
        $this->send_notification( 'deactivated' );

        return $result;
    }

    /**
     * Run the Security Analyzer and persist its results.
     *
     * Used by activate() (fast phase only — offline checks) and by the cron
     * hook scheduled at deactivate() (full scan — fast + slow). Lazy-loads the
     * analyzer the same way vigilante.php does for the weekly scan, so the
     * extra classes only get loaded when actually needed.
     *
     * @param string $phase 'fast' | 'slow' | 'all'.
     * @return void
     */
    public function run_analyzer_scan( $phase = 'all' ) {
        if ( ! class_exists( 'Vigilante_Security_Analyzer' ) ) {
            $analyzer_file = VIGILANTE_INCLUDES_DIR . 'class-security-analyzer.php';
            if ( ! file_exists( $analyzer_file ) ) {
                return;
            }
            require_once $analyzer_file;
        }

        try {
            $analyzer = new Vigilante_Security_Analyzer( $this->settings, $this->activity_log );
            // run_scan() persists the report internally via persist_scan(),
            // so the dashboard widget will read fresh data on the next page load.
            $analyzer->run_scan( $phase );

            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'security',
                    'under_attack_scan_completed',
                    sprintf(
                        /* translators: %s: phase name (fast / slow / all) */
                        __( 'Security Analyzer refresh after Under Attack mode change (phase: %s)', 'vigilante' ),
                        $phase
                    ),
                    array( 'phase' => $phase ),
                    'info'
                );
            }
        } catch ( \Throwable $e ) {
            // Best-effort: never let a scan failure block UA activation/deactivation.
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'security',
                    'under_attack_scan_failed',
                    $e->getMessage(),
                    array( 'phase' => $phase ),
                    'warning'
                );
            }
        }
    }

    /**
     * Build and persist the hardened vigilante_options for Under Attack mode.
     *
     * Layered: Maximum preset overrides on top of the user's current config,
     * then Under Attack-specific overrides (stricter login, all activity log
     * events, all modules forced on) on top of that. Any setting not touched
     * by either layer keeps the user's original value.
     *
     * @param array $base_options User's current vigilante_options (snapshot).
     */
    private function apply_hardened_options( $base_options ) {
        if ( ! is_array( $base_options ) ) {
            $base_options = array();
        }

        $presets        = $this->settings->get_presets();
        $maximum_preset = $presets['maximum'] ?? array();
        // Drop the metadata fields ('name', 'description') that the preset array carries.
        unset( $maximum_preset['name'], $maximum_preset['description'] );

        // Activity Log retention: don't downgrade if the user already keeps
        // logs for longer, but bump it up if they have a tight retention that
        // would lose visibility during an attack. Same logic for max_entries.
        $current_log     = $base_options['activity_log'] ?? array();
        $current_days    = isset( $current_log['retention_days'] ) ? absint( $current_log['retention_days'] ) : 30;
        $current_entries = isset( $current_log['max_entries'] ) ? absint( $current_log['max_entries'] ) : 10000;
        $forced_days     = max( $current_days, 30 );
        $forced_entries  = max( $current_entries, 10000 );

        // Under Attack-specific overrides on top of Maximum.
        $ua_overrides = array(
            // All security modules forced on regardless of user's config.
            'modules' => array(
                'firewall'          => true,
                'security_headers'  => true,
                'login_security'    => true,
                'rest_api_security' => true,
                'user_security'     => true,
                'wp_hardening'      => true,
                'file_integrity'    => true,
                'activity_log'      => true,
            ),
            // Login: stricter than Maximum (2 attempts vs Maximum's 3).
            'login_security' => array(
                'max_attempts' => 2,
            ),
            // File Integrity: full scope plus daily auto-scan (Maximum already
            // forces these, but we restate them here in case Maximum is edited
            // in the future and to make the UA contract explicit).
            'file_integrity' => array(
                'scan_core'            => true,
                'scan_plugins'         => true,
                'scan_themes'          => true,
                'scan_uploads'         => true,
                'scan_critical_config' => true,
                'auto_scan'            => true,
                'scan_frequency'       => 'daily',
            ),
            // Activity Log: bump retention to default if user has it lower.
            'activity_log' => array(
                'retention_days' => $forced_days,
                'max_entries'    => $forced_entries,
            ),
        );

        $hardened = array_replace_recursive( $base_options, $maximum_preset, $ua_overrides );

        update_option( Vigilante_Settings::OPTION_NAME, $hardened );
        $this->settings->clear_cache();

        // Drop any lingering active preset marker — under-attack is not a preset
        // and the previous preset is already saved in our own status option.
        delete_option( 'vigilante_active_preset' );
    }

    // =========================================================================
    // CACHE MANAGEMENT
    // =========================================================================

    /**
     * Safely run cache operations without breaking the calling flow
     *
     * Wraps cache operations in output buffering and try/catch to prevent
     * WP_Filesystem credential forms or PHP errors from corrupting
     * AJAX responses.
     *
     * @param string $action Either 'activate' or 'deactivate'.
     */
    private function safe_manage_cache( $action ) {
        ob_start();
        try {
            if ( 'activate' === $action ) {
                $this->add_cache_bypass_rules();
                $this->purge_page_caches();
            } else {
                $this->remove_cache_bypass_rules();
            }
        } catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
            // Cache operations are best-effort, must not break activation/deactivation
        }
        ob_end_clean();
    }

    /**
     * Add .htaccess rules to bypass full-page caching during Under Attack mode
     *
     * Uses direct file I/O instead of WP_Filesystem to avoid the credential
     * form issue that causes silent failures during AJAX requests.
     * The .htaccess must be writable by the web server for WordPress rewrite
     * rules to work, so direct PHP writes are safe here.
     */
    private function add_cache_bypass_rules() {
        $htaccess_path = ABSPATH . '.htaccess';

        // Only proceed if .htaccess exists and is writable
        // Direct I/O used because WP_Filesystem requires credentials form in AJAX context.
        if ( ! file_exists( $htaccess_path ) || ! is_writable( $htaccess_path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- WP_Filesystem fails in AJAX context (credential form)
            return;
        }

        $content = file_get_contents( $htaccess_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

        if ( false === $content ) {
            return;
        }

        // Remove existing block if present (avoid duplicates)
        $content = $this->remove_htaccess_block( $content );

        // Build the cache bypass block
        $block  = self::HTACCESS_MARKER_START . "\n";
        $block .= '<IfModule mod_headers.c>' . "\n";
        $block .= '    Header set Cache-Control "no-store, no-cache, must-revalidate, max-age=0"' . "\n";
        $block .= '    Header set Pragma "no-cache"' . "\n";
        $block .= '</IfModule>' . "\n";
        $block .= '<IfModule LiteSpeed>' . "\n";
        $block .= '    CacheDisable public /' . "\n";
        $block .= '</IfModule>' . "\n";
        $block .= self::HTACCESS_MARKER_END;

        // Insert at top
        $new_content = $block . "\n\n" . ltrim( $content );

        file_put_contents( $htaccess_path, $new_content, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
    }

    /**
     * Remove .htaccess cache bypass rules when mode is deactivated
     *
     * Uses direct file I/O for the same reasons as add_cache_bypass_rules().
     */
    private function remove_cache_bypass_rules() {
        $htaccess_path = ABSPATH . '.htaccess';

        if ( ! file_exists( $htaccess_path ) || ! is_writable( $htaccess_path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- WP_Filesystem fails in AJAX context (credential form)
            return;
        }

        $content = file_get_contents( $htaccess_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

        if ( false === $content ) {
            return;
        }

        // Only write if block actually exists
        if ( false === strpos( $content, self::HTACCESS_MARKER_START ) ) {
            return;
        }

        $new_content = $this->remove_htaccess_block( $content );

        file_put_contents( $htaccess_path, $new_content, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
    }

    /**
     * Remove the Under Attack block from .htaccess content string
     *
     * @param string $content Current .htaccess content.
     * @return string Content without the Under Attack block.
     */
    private function remove_htaccess_block( $content ) {
        if ( false === strpos( $content, self::HTACCESS_MARKER_START ) ) {
            return $content;
        }

        $lines      = explode( "\n", $content );
        $new_lines  = array();
        $inside     = false;

        foreach ( $lines as $line ) {
            if ( trim( $line ) === self::HTACCESS_MARKER_START ) {
                $inside = true;
                continue;
            }

            if ( trim( $line ) === self::HTACCESS_MARKER_END ) {
                $inside = false;
                continue;
            }

            if ( ! $inside ) {
                $new_lines[] = $line;
            }
        }

        // Clean up multiple empty lines
        $result = implode( "\n", $new_lines );
        $result = preg_replace( '/\n{3,}/', "\n\n", $result );

        return trim( $result ) . "\n";
    }

    /**
     * Purge known page caches so existing cached pages are cleared
     *
     * Fires hooks and calls functions for common caching plugins.
     * Failures are silently ignored (cache purge is best-effort).
     */
    private function purge_page_caches() {
        // WordPress object cache
        wp_cache_flush();

        // Third-party cache plugin hooks - these are the official hook names
        // defined by each plugin, not ours to prefix.

        // LiteSpeed Cache
        if ( has_action( 'litespeed_purge_all' ) ) {
            do_action( 'litespeed_purge_all' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Third-party hook
        }

        // WP Super Cache
        if ( function_exists( 'wp_cache_clear_cache' ) ) {
            wp_cache_clear_cache();
        }

        // W3 Total Cache
        if ( function_exists( 'w3tc_flush_all' ) ) {
            w3tc_flush_all();
        }

        // WP Rocket
        if ( function_exists( 'rocket_clean_domain' ) ) {
            rocket_clean_domain();
        }

        // WP Fastest Cache
        if ( has_action( 'wpfc_clear_all_cache' ) ) {
            do_action( 'wpfc_clear_all_cache' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Third-party hook
        }

        // Autoptimize
        if ( class_exists( 'autoptimizeCache' ) && method_exists( 'autoptimizeCache', 'clearall' ) ) {
            autoptimizeCache::clearall();
        }

        // SG Optimizer / Speed Optimizer (SiteGround) - multiple purge methods
        // Public API function (purges Dynamic + File-based + Object caches)
        if ( function_exists( 'sg_cachepress_purge_cache' ) ) {
            sg_cachepress_purge_cache();
        }

        // Modern SG Optimizer (7.x+) internal Supercacher class
        if ( class_exists( '\SiteGround_Optimizer\Supercacher\Supercacher' ) ) {
            if ( method_exists( '\SiteGround_Optimizer\Supercacher\Supercacher', 'purge_cache' ) ) {
                \SiteGround_Optimizer\Supercacher\Supercacher::purge_cache();
            }
            if ( method_exists( '\SiteGround_Optimizer\Supercacher\Supercacher', 'delete_assets' ) ) {
                \SiteGround_Optimizer\Supercacher\Supercacher::delete_assets();
            }
        }

        // SG file-based cache directory cleanup
        $sg_file_cache_dir = WP_CONTENT_DIR . '/cache/sg-optimizer';
        if ( is_dir( $sg_file_cache_dir ) ) {
            $this->recursive_delete_dir( $sg_file_cache_dir );
        }

        // Hummingbird
        if ( has_action( 'wphb_clear_page_cache' ) ) {
            do_action( 'wphb_clear_page_cache' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Third-party hook
        }

        // Cache Enabler
        if ( has_action( 'ce_clear_cache' ) ) {
            do_action( 'ce_clear_cache' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Third-party hook
        }

        // Breeze (Cloudways)
        if ( has_action( 'breeze_clear_all_cache' ) ) {
            do_action( 'breeze_clear_all_cache' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Third-party hook
        }

        // Generic hook used by some plugins
        if ( has_action( 'cachify_flush_cache' ) ) {
            do_action( 'cachify_flush_cache' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Third-party hook
        }
    }

    /**
     * Set constants and headers that tell caching plugins to skip caching
     *
     * Called during constructor when mode is active, so every PHP request
     * signals to caching layers not to serve or store cached responses.
     */
    private function send_nocache_headers_for_plugins() {
        // Standard cache-control constants recognized by caching plugins.

        // DONOTCACHEPAGE is respected by WP Super Cache, W3TC, WP Rocket, Batcache and others
        if ( ! defined( 'DONOTCACHEPAGE' ) ) {
            define( 'DONOTCACHEPAGE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Industry-standard constant
        }

        // DONOTCACHEOBJECT is respected by W3TC
        if ( ! defined( 'DONOTCACHEOBJECT' ) ) {
            define( 'DONOTCACHEOBJECT', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Industry-standard constant
        }

        // DONOTCACHEDB is respected by W3TC
        if ( ! defined( 'DONOTCACHEDB' ) ) {
            define( 'DONOTCACHEDB', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Industry-standard constant
        }

        // LiteSpeed Cache
        if ( ! defined( 'LSCACHE_NO_CACHE' ) ) {
            define( 'LSCACHE_NO_CACHE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- LiteSpeed standard constant
        }

        // Send nocache headers early for any PHP-served response
        if ( ! headers_sent() ) {
            nocache_headers();
            // NGINX reverse proxy directive - do not cache this response
            header( 'X-Accel-Expires: 0' );
            // Generic CDN/reverse proxy directive
            header( 'Surrogate-Control: no-store' );
        }

        // SG Optimizer: register our verification cookie as bypass cookie
        // When a verified visitor has this cookie, SG NGINX skips its cache
        // and lets PHP handle the request (where has_valid_cookie() returns true)
        add_filter( 'sgo_bypass_cookies', array( $this, 'add_sg_bypass_cookie' ) );
    }

    /**
     * Add Vigilante verification cookie to SG Optimizer bypass list
     *
     * When SG NGINX sees this cookie in a request, it bypasses its cache
     * and lets PHP handle the request directly.
     *
     * @param array $cookies Existing bypass cookies.
     * @return array Modified bypass cookies.
     */
    public function add_sg_bypass_cookie( $cookies ) {
        $cookies[] = self::COOKIE_NAME;
        return $cookies;
    }

    // =========================================================================
    // JS CHALLENGE
    // =========================================================================

    /**
     * Serve JS challenge page if visitor is not verified
     *
     * Also handles challenge response POST inline to avoid
     * the init-within-init timing issue.
     */
    public function maybe_serve_challenge() {
        // Never challenge logged-in users
        if ( is_user_logged_in() ) {
            return;
        }

        // Never challenge admin/login/cron/AJAX
        if ( is_admin() || wp_doing_cron() || wp_doing_ajax() ) {
            return;
        }

        // Check if request is for wp-login.php
        if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
            return;
        }

        // Handle challenge response POST first (before serving a new challenge)
        if ( $this->process_challenge_response() ) {
            return;
        }

        // Check if visitor has valid verification cookie
        if ( $this->has_valid_cookie() ) {
            return;
        }

        // Check if IP is whitelisted in firewall settings
        if ( $this->is_ip_whitelisted() ) {
            return;
        }

        // Serve the challenge page
        $this->render_challenge_page();
        exit;
    }

    /**
     * Process challenge response POST
     *
     * Called from maybe_serve_challenge() to handle the proof-of-work
     * response inline at template_redirect, avoiding the init timing issue.
     *
     * @return bool True if response was valid and redirect happened.
     */
    private function process_challenge_response() {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] || empty( $_POST['vigilante_ua_response'] ) ) {
            return false;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $response  = sanitize_text_field( wp_unslash( $_POST['vigilante_ua_response'] ) );
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $nonce_val = sanitize_text_field( wp_unslash( $_POST['vigilante_ua_nonce'] ?? '' ) );
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $redirect  = esc_url_raw( wp_unslash( $_POST['vigilante_ua_redirect'] ?? '' ) );

        // Verify the challenge nonce (stored as transient)
        $stored_nonce = get_transient( 'vigilante_ua_nonce_' . $this->get_visitor_ip_hash() );

        if ( ! $stored_nonce || ! hash_equals( $stored_nonce, $nonce_val ) ) {
            return false;
        }

        // Delete used nonce
        delete_transient( 'vigilante_ua_nonce_' . $this->get_visitor_ip_hash() );

        // Verify the proof-of-work response
        if ( $this->verify_challenge( $response, $nonce_val ) ) {
            $this->set_verification_cookie();

            // Redirect to the original URL
            if ( empty( $redirect ) || ! wp_validate_redirect( $redirect ) ) {
                $redirect = home_url( '/' );
            }

            wp_safe_redirect( $redirect );
            exit;
        }

        return false;
    }

    /**
     * Verify the proof-of-work challenge response
     *
     * @param string $response The nonce value found by the client.
     * @param string $nonce    The challenge nonce.
     * @return bool
     */
    private function verify_challenge( $response, $nonce ) {
        $hash = hash( 'sha256', $nonce . $response );
        $prefix = str_repeat( '0', self::CHALLENGE_DIFFICULTY );

        return 0 === strpos( $hash, $prefix );
    }

    /**
     * Check if visitor has a valid verification cookie
     *
     * Public so other modules (firewall) can grant verified visitors
     * bypass on rate-limit checks.
     *
     * @return bool
     */
    public function has_valid_cookie() {
        if ( ! isset( $_COOKIE[ self::COOKIE_NAME ] ) ) {
            return false;
        }

        $cookie = sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE_NAME ] ) );
        $parts  = explode( '|', $cookie );

        if ( count( $parts ) !== 3 ) {
            return false;
        }

        list( $ip_hash, $expires, $signature ) = $parts;

        // Check expiration
        if ( (int) $expires < time() ) {
            return false;
        }

        // Verify HMAC signature
        $status   = $this->get_status();
        $expected = hash_hmac( 'sha256', $ip_hash . '|' . $expires, $status['secret'] );

        if ( ! hash_equals( $expected, $signature ) ) {
            return false;
        }

        // Verify IP matches (prevents cookie theft)
        $current_ip_hash = $this->get_visitor_ip_hash();
        if ( ! hash_equals( $ip_hash, $current_ip_hash ) ) {
            return false;
        }

        return true;
    }

    /**
     * Set the verification cookie after passing the challenge
     */
    private function set_verification_cookie() {
        $status  = $this->get_status();
        $ip_hash = $this->get_visitor_ip_hash();

        // Cookie expires when the mode expires
        $expires = $status['activated_at'] + $status['duration'];

        // HMAC signature
        $signature = hash_hmac( 'sha256', $ip_hash . '|' . $expires, $status['secret'] );

        $cookie_value = $ip_hash . '|' . $expires . '|' . $signature;

        // Set cookie - secure flags
        $secure   = is_ssl();
        $httponly  = true;
        $samesite = 'Lax';

        if ( PHP_VERSION_ID >= 70300 ) {
            setcookie( self::COOKIE_NAME, $cookie_value, array(
                'expires'  => $expires,
                'path'     => COOKIEPATH,
                'domain'   => COOKIE_DOMAIN,
                'secure'   => $secure,
                'httponly'  => $httponly,
                'samesite' => $samesite,
            ) );
        } else {
            setcookie(
                self::COOKIE_NAME,
                $cookie_value,
                $expires,
                COOKIEPATH . '; SameSite=' . $samesite,
                COOKIE_DOMAIN,
                $secure,
                $httponly
            );
        }
    }

    /**
     * Render the JS challenge page
     *
     * Uses external CSS/JS files for CSP compatibility.
     */
    private function render_challenge_page() {
        $site_name = get_bloginfo( 'name' );

        // Reuse an existing nonce if one is still valid for this visitor.
        // Without reuse, a refresh while the JS solver is running invalidates
        // the in-flight nonce and the visitor gets stuck in a challenge loop.
        $transient_key   = 'vigilante_ua_nonce_' . $this->get_visitor_ip_hash();
        $challenge_nonce = get_transient( $transient_key );

        if ( ! $challenge_nonce ) {
            $challenge_nonce = wp_generate_password( 32, false );
            set_transient( $transient_key, $challenge_nonce, self::NONCE_TTL );
        }

        // Get current URL for redirect after verification
        $current_url = ( is_ssl() ? 'https' : 'http' ) . '://' . sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ?? '' ) ) . sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ?? '/' ) );

        // Asset URLs (external files for CSP compatibility)
        $css_url = VIGILANTE_ASSETS_URL . 'css/under-attack-challenge.css?ver=' . VIGILANTE_VERSION;
        $js_url  = VIGILANTE_ASSETS_URL . 'js/under-attack-challenge.js?ver=' . VIGILANTE_VERSION;

        status_header( 503 );
        header( 'Retry-After: 5' );
        header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
        header( 'Pragma: no-cache' );

        ?><!DOCTYPE html>
<html lang="<?php echo esc_attr( get_bloginfo( 'language' ) ); ?>">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo esc_html( $site_name ); ?></title>
    <?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet -- Standalone challenge page served with exit, outside WP enqueue cycle. ?>
    <link rel="stylesheet" href="<?php echo esc_url( $css_url ); ?>">
</head>
<body>
    <div class="challenge-container">
        <div class="site-name"><?php echo esc_html( $site_name ); ?></div>
        <div class="spinner" id="spinner"></div>
        <p class="message" id="msg"><?php esc_html_e( 'Checking your connection before proceeding', 'vigilante' ); ?></p>
        <p class="message-sub"><?php esc_html_e( 'This process is automatic. You will be redirected shortly.', 'vigilante' ); ?></p>
        <noscript>
            <div class="error-msg">
                <?php esc_html_e( 'Please enable JavaScript to access this website.', 'vigilante' ); ?>
            </div>
        </noscript>
    </div>

    <form id="ua-form" method="POST" style="display:none" data-nonce="<?php echo esc_attr( $challenge_nonce ); ?>" data-difficulty="<?php echo absint( self::CHALLENGE_DIFFICULTY ); ?>">
        <input type="hidden" name="vigilante_ua_nonce" value="<?php echo esc_attr( $challenge_nonce ); ?>">
        <input type="hidden" name="vigilante_ua_response" id="ua-response" value="">
        <input type="hidden" name="vigilante_ua_redirect" value="<?php echo esc_attr( esc_url( $current_url ) ); ?>">
    </form>

    <?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript -- Standalone challenge page served with exit, outside WP enqueue cycle. ?>
    <script src="<?php echo esc_url( $js_url ); ?>"></script>
</body>
</html>
        <?php
    }

    // =========================================================================
    // RATE LIMITING AND RESTRICTIONS
    // =========================================================================

    /**
     * Override rate limiting to aggressive values
     *
     * @param int $requests Original requests per minute.
     * @return int Aggressive limit.
     */
    public function aggressive_rate_limit( $requests ) {
        return 30;
    }

    /**
     * Skip rate limiting for visitors who already passed the JS challenge.
     *
     * Without this bypass, a verified human loading a normal page (with 20-30
     * images/scripts served through WordPress) burns the aggressive 30 req/min
     * cap and gets a 429 — which used to look like the challenge was failing.
     *
     * @param bool $skip Current value passed by the filter chain.
     * @return bool True to skip the check, otherwise the value passed in.
     */
    public function maybe_skip_rate_limit( $skip ) {
        if ( $skip ) {
            return true;
        }
        return $this->has_valid_cookie();
    }

    /**
     * Override block duration to aggressive value
     *
     * @param int $duration Original block duration.
     * @return int Aggressive duration (15 minutes).
     */
    public function aggressive_block_duration( $duration ) {
        return 900;
    }

    /**
     * Send every comment to moderation while Under Attack is active.
     *
     * @param int|string|WP_Error $approved Original approval status.
     * @return int|string|WP_Error Forced 0 (moderation), unless WP itself
     *                              flagged spam/error which we keep.
     */
    public function force_comment_moderation( $approved ) {
        if ( is_wp_error( $approved ) || 'spam' === $approved || 'trash' === $approved ) {
            return $approved;
        }
        return 0;
    }

    /**
     * Restrict HTTP methods to GET, POST, HEAD only
     */
    public function restrict_http_methods() {
        if ( is_admin() || wp_doing_cron() || wp_doing_ajax() ) {
            return;
        }

        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';

        $allowed = array( 'GET', 'POST', 'HEAD' );

        if ( ! in_array( $method, $allowed, true ) ) {
            status_header( 405 );
            header( 'Allow: GET, POST, HEAD' );
            wp_die(
                esc_html__( 'Method not allowed.', 'vigilante' ),
                esc_html__( 'Method Not Allowed', 'vigilante' ),
                array( 'response' => 405 )
            );
        }
    }

    /**
     * Block requests with empty user agent
     */
    public function block_empty_user_agent() {
        if ( is_admin() || wp_doing_cron() || wp_doing_ajax() ) {
            return;
        }

        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

        if ( empty( trim( $user_agent ) ) ) {
            status_header( 403 );
            wp_die(
                esc_html__( 'Access denied.', 'vigilante' ),
                esc_html__( 'Forbidden', 'vigilante' ),
                array( 'response' => 403 )
            );
        }
    }

    /**
     * Restrict REST API to authenticated users only
     *
     * @param WP_Error|null|true $result Current auth result.
     * @return WP_Error|null|true
     */
    public function restrict_rest_api( $result ) {
        if ( is_user_logged_in() ) {
            return $result;
        }

        return new WP_Error(
            'rest_under_attack',
            __( 'REST API access temporarily restricted.', 'vigilante' ),
            array( 'status' => 503 )
        );
    }

    // =========================================================================
    // HELPER METHODS
    // =========================================================================

    /**
     * Check if IP is in the firewall whitelist
     *
     * @return bool
     */
    private function is_ip_whitelisted() {
        $firewall_options = $this->settings->get_section( 'firewall' );
        $whitelist        = $firewall_options['ip_whitelist'] ?? array();

        if ( empty( $whitelist ) ) {
            return false;
        }

        $ip = $this->get_visitor_ip();

        foreach ( $whitelist as $whitelisted_ip ) {
            if ( $ip === trim( $whitelisted_ip ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get visitor IP address
     *
     * @return string
     */
    private function get_visitor_ip() {
        $ip = '';

        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
            $ip  = trim( $ips[0] );
        } elseif ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
        } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }

        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
    }

    /**
     * Get hashed visitor IP for privacy-safe comparisons
     *
     * @return string
     */
    private function get_visitor_ip_hash() {
        return hash( 'sha256', $this->get_visitor_ip() . wp_salt( 'auth' ) );
    }

    /**
     * Recursively delete contents of a directory (files and subdirectories)
     *
     * Used for cleaning file-based cache directories.
     * Only deletes contents, preserves the top-level directory.
     *
     * @param string $dir Directory path to clean.
     */
    private function recursive_delete_dir( $dir ) {
        if ( ! is_dir( $dir ) ) {
            return;
        }

        $items = scandir( $dir );

        if ( false === $items ) {
            return;
        }

        foreach ( $items as $item ) {
            if ( '.' === $item || '..' === $item ) {
                continue;
            }

            $path = $dir . '/' . $item;

            if ( is_dir( $path ) ) {
                $this->recursive_delete_dir( $path );
                @rmdir( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir, WordPress.PHP.NoSilencedErrors.Discouraged -- No WP equivalent for rmdir
            } else {
                wp_delete_file( $path );
            }
        }
    }

    /**
     * Send email notification when mode is activated/deactivated
     *
     * @param string $action   Either 'activated' or 'deactivated'.
     * @param int    $duration Duration in seconds (only for activation).
     */
    private function send_notification( $action, $duration = 0 ) {
        // Use centralized notification recipients
        $recipients = Vigilante_Email_Template::get_admin_recipients();

        if ( empty( $recipients ) ) {
            return;
        }

        $site_name = get_bloginfo( 'name' );

        if ( 'activated' === $action ) {
            $subject = sprintf(
                /* translators: %s: Site name */
                __( '[%s] Under Attack mode activated', 'vigilante' ),
                $site_name
            );

            $hours = round( $duration / 3600, 1 );
            $body  = Vigilante_Email_Template::alert_box( __( 'Under Attack mode has been activated.', 'vigilante' ) );
            $body .= Vigilante_Email_Template::data_table( array(
                __( 'Duration', 'vigilante' ) => $hours . ' ' . __( 'hours', 'vigilante' ),
            ) );
            $body .= Vigilante_Email_Template::p( __( 'The mode will automatically deactivate when the timer expires. You can manually deactivate it from the Vigilant dashboard.', 'vigilante' ) );
            $body .= Vigilante_Email_Template::button( admin_url( 'admin.php?page=vigilante' ), __( 'Go to dashboard', 'vigilante' ) );

            $title = __( 'Under Attack mode activated', 'vigilante' );
            $alert = true;
        } else {
            $subject = sprintf(
                /* translators: %s: Site name */
                __( '[%s] Under Attack mode deactivated', 'vigilante' ),
                $site_name
            );

            $body  = Vigilante_Email_Template::success_box( __( 'Under Attack mode has been deactivated. Your site is now operating with normal security settings.', 'vigilante' ) );

            $title = __( 'Under Attack mode deactivated', 'vigilante' );
            $alert = false;
        }

        // Send to centralized recipients
        Vigilante_Email_Template::send( $recipients, $subject, $title, $body, $alert );
    }
}