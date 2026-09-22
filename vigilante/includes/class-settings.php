<?php
/**
 * Settings Class
 *
 * Centralized settings management with default values
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Settings
 *
 * Handles all plugin settings with defaults, getters and setters
 */
class Vigilante_Settings {

    /**
     * Option name in database
     */
    const OPTION_NAME = 'vigilante_options';

    /**
     * Cached options
     *
     * @var array|null
     */
    private $options = null;

    /**
     * Default options structure
     *
     * @var array
     */
    private $defaults;

    /**
     * Constructor
     */
    public function __construct() {
        $this->defaults = $this->get_default_options();
    }

    /**
     * Get all default options
     *
     * @return array Complete default options array
     */
    public function get_default_options() {
        return array(
            // Module toggles - 8 modules that match tabs
            'modules' => array(
                'firewall'         => true,
                'security_headers' => true,
                'login_security'   => true,
                'rest_api_security'=> true,
                'user_security'    => true,
                'wp_hardening'     => true,
                'file_integrity'   => true,
                'activity_log'     => true,
            ),

            // Firewall settings (includes htaccess, rate limiting, file protection)
            'firewall' => array(
                // Request filtering (PHP-based)
                'block_bad_query_strings'   => true,
                'block_sql_injection'       => true,
                'block_xss_attacks'         => true,
                'block_file_inclusion'      => true,
                'block_directory_traversal' => true,
                
                // Bot protection
                'block_bad_bots'            => true,
                'block_empty_user_agent'    => false,

                // Rate limiting
                'rate_limiting'             => array(
                    'enabled'             => true,
                    'requests_per_minute' => 120,
                    'block_duration'      => 300,
                    'progressive'         => false,
                    'max_block_duration'  => 86400,
                ),
                
                // IP management
                'ip_whitelist'              => array(),
                'ip_blacklist'              => array(),

                // Proxy / CDN: forwarded header to trust for the visitor IP.
                // Empty = trust only REMOTE_ADDR (the real connection, unspoofable).
                'trusted_proxy_header'      => '',

                // Proxy / CDN: IPs or CIDR ranges the forwarded header is accepted
                // from. Empty = accept it only from your own network, and, for
                // CF-Connecting-IP, Cloudflare's own ranges. Since 2.11.9, so a
                // header cannot be forged by a visitor reaching the origin directly.
                'trusted_proxies'           => array(),

                // User-Agent management
                'ua_whitelist'              => array(),
                'ua_blacklist'              => array(),
                
                // File protection (htaccess-based)
                'disable_directory_browsing' => true,
                'protect_wp_config'          => true,
                'protect_wp_includes'        => true,
                'protect_uploads_php'        => true,
                'protect_sensitive_files'    => true,
                // Off by default — only safe when host has a real server-side cron job
                // calling wp-cron.php; otherwise scheduled tasks stop running silently.
                'protect_wp_cron'            => false,
                'block_php_in_plugins'       => false,
                'block_php_in_themes'        => false,
                'limit_http_methods'         => true,
                // All methods needed for WordPress core, Gutenberg, REST API, and page builders
                'allowed_http_methods'       => array( 'GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE' ),
            ),

            // Security Headers settings (includes HTTPS enforcer)
            'security_headers' => array(
                'enabled'                 => true,
                
                // Basic headers
                'x_frame_options'         => 'SAMEORIGIN',
                'x_content_type_options'  => true,
                'referrer_policy'         => 'strict-origin-when-cross-origin',
                
                // HSTS
                'hsts'                    => array(
                    'enabled'            => false,
                    'max_age'            => 31536000,
                    'include_subdomains' => false,
                    'preload'            => false,
                ),
                
                // Permissions Policy
                'permissions_policy'      => array(
                    'enabled'      => true,
                    'geolocation'  => '()',
                    'microphone'   => '()',
                    'camera'       => '()',
                    'payment'      => '(self)',
                    'usb'          => '()',
                ),
                
                // CSP - WordPress/Gutenberg compatible defaults
                // Note: blob: is required in frame-src and worker-src for the block editor,
                // and in connect-src for the client-side media processing WordPress 7.1
                // introduced: @wordpress/vips puts its WebAssembly binary in a blob: URL and
                // fetches it, and fetch() is governed by connect-src, where 'self' does not
                // cover blob:. Without it the editor cannot process images before upload.
                'csp'                     => array(
                    'enabled'     => true,
                    'report_only' => false,
                    'report_uri'  => '',
                    'directives'  => array(
                        'default-src'              => "'self'",
                        'script-src'               => "'self' 'unsafe-inline' 'unsafe-eval' https:",
                        'style-src'                => "'self' 'unsafe-inline' https:",
                        'img-src'                  => "'self' data: https: blob:",
                        'font-src'                 => "'self' data: https:",
                        'connect-src'              => "'self' https: wss: blob:",
                        'media-src'                => "'self' https: blob:",
                        'frame-src'                => "'self' https: blob:",
                        'frame-ancestors'          => "'self'",
                        'base-uri'                 => "'self'",
                        'form-action'              => "'self' https:",
                        'object-src'               => "'none'",
                        'worker-src'               => "'self' blob:",
                        'upgrade-insecure-requests'=> true,
                    ),
                ),
                
                // Cross-origin policies
                'cross_origin_policies'   => array(
                    'embedder_policy'  => 'unsafe-none',
                    'opener_policy'    => 'same-origin-allow-popups',
                    'resource_policy'  => 'cross-origin',
                ),
                
                // HTTPS Enforcer (moved from separate module)
                //
                // force_https rewrites siteurl/home to https on activation, so it
                // ships off: a site without working HTTPS would end up pointing at
                // an address that does not answer. It is an opt-in decision per
                // site, made from the Security Headers tab. Sites whose URLs a
                // previous version already rewrote keep them; nothing reverts them.
                'force_https'               => false,
                // Off by default for the same reason as force_https above: the
                // plugin does not decide that a site is on HTTPS. It only
                // redirects when the site's own home URL already says https, so
                // shipping it on was harmless in practice, but it is still a
                // decision that belongs to the site owner, not to us. Sites that
                // already have it on keep it.
                'redirect_http_to_https'    => false,
                // Rewrites http:// URLs of this same site to https://, and only
                // on a site already served over HTTPS, so it cannot reach a third
                // party and cannot make a resource fail. It still ships off: a
                // setting whose own description says it rewrites http to https
                // does not belong in the factory configuration of a plugin that
                // deliberately does not decide whether a site is on HTTPS. Every
                // https-related setting here is the owner's call, and this one is
                // one click away for anyone who has just migrated and wants their
                // old content rewritten.
                'fix_mixed_content'         => false,
                // The Content-Security-Policy directive that tells the browser to
                // upgrade every http:// request, including the ones pointing at
                // other people's servers. If any of those has no HTTPS the
                // resource simply stops loading, so this is the one piece of
                // mixed content handling that can break a page, and it is off by
                // default like everything else here that forces HTTPS. It used to
                // ride along with fix_mixed_content with no way to separate them.
                'upgrade_insecure_requests' => false,

                // Server Protection (moved from firewall in v2.0.0)
                'hide_server_signature'         => true,
                'remove_fingerprinting_headers' => true,
            ),

            // Login Security settings
            'login_security' => array(
                'enabled'                     => true,
                'max_attempts'                => 5,
                'lockout_duration'            => 1800,
                'lockout_increment'           => true,
                'max_lockout_duration'        => 86400,
                'hide_login_errors'           => true,
                // XML-RPC se movio a wp_hardening en la 2.9.7; lo resuelve
                // Vigilante_Comment_Security::resolve_xmlrpc_mode(), que
                // sustituye a las dos casillas anteriores (disable_xmlrpc y
                // disable_xmlrpc_pingback), que podian estar activas a la vez y
                // contradecirse. A proposito NO se declara aqui ningun default: si se
                // declarara, el merge con los defaults lo rellenaria siempre y taparia el
                // respaldo que lee el ajuste antiguo de los sitios que aun no han vuelto a
                // guardar la pestana. Sin nada guardado, el resolutor devuelve 'full', que
                // es lo que hacia el default anterior.
                'disable_application_passwords' => false,
                'notify_on_lockout'           => false,
                'notify_on_admin_login'       => false,
                'ip_whitelist'                => array(),
                'custom_login_url'            => '',
                'notify_on_login_url_change'  => true,
                // Two-Factor Authentication
                'two_factor'                  => array(
                    'enabled'              => false,
                    'method'               => 'email',
                    'enforced_roles'       => array( 'administrator', 'editor' ),
                    'excluded_users'       => array(),
                    'remember_device_days' => 30,
                    'allow_remember_device' => false,
                    'code_expiry_minutes'  => 10,
                    'max_attempts'         => 3,
                    'email_from_name'      => '',
                    'notify_on_enable'     => true,
                    'grace_period_days'    => 3,
                ),
            ),

            // REST API Security settings
            'rest_api_security' => array(
                'enabled'                => true,
                'mode'                   => 'selective',
                'block_user_enumeration' => true,
                'disable_jsonp'          => true,
                // Empty by default: /wp/v2/users used to live here, but that
                // duplicated the dedicated "Block user enumeration" toggle.
                // Now there is one knob = one behaviour. If you want to
                // protect additional endpoints in selective mode, add them
                // explicitly via this setting (or via a filter).
                'protected_endpoints'    => array(),
                'allowed_public_endpoints' => array(
                    '/wp/v2/posts',
                    '/wp/v2/pages',
                    '/wp/v2/categories',
                    '/wp/v2/tags',
                    '/oembed/',
                ),
                'plugin_compatibility'   => array(
                    'woocommerce'         => true,
                    'contact_form_7'      => true,
                    'elementor'           => true,
                ),
            ),

            // User Security settings
            'user_security' => array(
                'enabled'                 => true,
                'block_insecure_usernames'=> true,
                'insecure_usernames'      => array(
                    'admin', 'administrator', 'user', 'test', 'guest',
                    'info', 'root', 'adm', 'sysadmin', 'support',
                    'webmaster', 'master', 'owner', 'manager', 'demo',
                ),
                'block_author_scanning'   => true,
                'force_strong_passwords'  => true,
                'min_password_length'     => 12,

                // Granular password policy. Applies only while
                // force_strong_passwords is on. The defaults follow current
                // guidance (NIST SP 800-63B): what makes a password weak is being
                // guessable, not lacking a symbol, and composition rules push
                // people towards predictable substitutions and towards writing
                // the password down. So out of the box only the two rules that
                // block genuinely guessable passwords are on, and the four
                // character-class requirements ship off for anyone to turn on.
                // Existing sites keep whatever they have stored.
                // affected_roles empty = all roles.
                'password_policy'         => array(
                    'require_uppercase' => false,
                    'require_lowercase' => false,
                    'require_number'    => false,
                    'require_special'   => false,
                    'block_common'      => true,
                    'block_username'    => true,
                    'affected_roles'    => array(),
                ),

                'prevent_display_name_login_match' => true,
                
                // Admin monitoring
                // The two alerts that report someone gaining power ship on: a
                // new administrator and a role being raised are the signature of
                // an account takeover, and they are rare enough not to be noise.
                // The other two are ordinary admin housekeeping and stay opt-in.
                'admin_monitoring'        => array(
                    'alert_new_admin'              => true,
                    'alert_admin_email_change'     => false,
                    'alert_permission_elevation'   => true,
                    'alert_admin_password_change'  => false,
                ),
                
                // Force password reset (no options, uses native WordPress flow)

                // Registration approval
                'registration_approval'   => array(
                    'enabled'           => false,
                    'notify_admin'      => false,
                    'auto_reject_days'  => 0,
                    'affected_roles'    => array( 'subscriber' ),
                ),

                // Session management
                'session_management'      => array(
                    'enabled'           => true,
                    'show_in_profile'   => true,
                ),

                // Session limits
                'session_limits'          => array(
                    'enabled'           => true,
                    'max_sessions'      => 3,
                    'behavior'          => 'close_oldest',
                    'exclude_admins'    => false,
                ),

                // Password expiration ships OFF. Forced rotation is no longer
                // recommended (NIST SP 800-63B advises against it) and it is by
                // far the biggest source of support here: people locked out mid
                // task, cron reminders that never arrive, roles nobody meant to
                // include. The feature stays for anyone who has to comply with a
                // policy that still demands it, and the Configuration Score keeps
                // pointing at it, which is what that score is for.
                'password_expiration'     => array(
                    'enabled'           => false,
                    'expire_days'       => 90,
                    'warning_days'      => 14,
                    'affected_roles'    => array( 'administrator', 'editor' ),
                    'excluded_users'    => array(),
                    'password_history'  => 3,
                    'send_reminder'     => false,
                ),

                // Email verification
                'email_verification'      => array(
                    'enabled'               => false,
                    'token_expiry_hours'    => 24,
                    'allow_resend'          => true,
                    'auto_delete_days'      => 7,
                ),
            ),

            // WordPress Hardening (combines wp-config, comments, feeds, head cleaner)
            'wp_hardening' => array(
                'enabled'               => true,
                
                // wp-config security
                'disallow_file_edit'    => true,
                'disallow_file_mods'    => false,
                // Off by default. This one writes FORCE_SSL_ADMIN into
                // wp-config.php, and it used to do so on activation with no
                // check that the site answers over HTTPS at all, which locks the
                // owner out of their own admin. Forcing HTTPS is an opt-in
                // decision per site, consistent with force_https and with HSTS,
                // both of which already ship off.
                'force_ssl_admin'       => false,
                'wp_debug'              => true,
                // Off by default — only safe when host has a real server-side cron job;
                // pairs with firewall.protect_wp_cron to block both internal triggering
                // (this constant) and external HTTP abuse (the .htaccess rule).
                'disable_wp_cron'       => false,
                
                // Comment security
                'disable_pingbacks'       => true,
                'disable_trackbacks'      => true,
                'require_comment_moderation' => true,
                'close_old_comments'      => false,
                'close_comments_after_days' => 30,
                'honeypot_comments'       => true,
                
                // Head cleaner
                'remove_wp_generator'      => true,
                'remove_wp_version_assets' => false,
                'remove_rsd_link'          => true,
                'remove_wlw_manifest'      => true,
                'remove_shortlink'         => true,
                'remove_rest_api_link'     => false,
                
                // Feed manager
                'disable_feeds'          => false,
                'disable_if_no_content'  => true,
                'remove_feed_version'    => true,
            ),

            // File Integrity settings
            'file_integrity' => array(
                'enabled'                 => true,
                'scan_core'               => true,
                'scan_plugins'            => true,
                'scan_themes'             => true,
                'scan_uploads'            => true,
                'scan_critical_config'    => true,
                'check_closed_plugins'    => true,
                'auto_scan'               => true,
                'scan_frequency'          => 'daily',
                'notify_level'            => 'suspicious_only',
                'instant_alert'           => false,
                'excluded_paths'          => array(
                    'wp-content/cache',
                ),
                'excluded_extensions'     => array(
                    // Translations (regenerated per-locale, never in checksums).
                    '.po', '.mo', '.pot',
                    // Binary images (cosmetic, not executable; often rewritten by image-optimizer plugins).
                    '.jpg', '.jpeg', '.png', '.gif', '.ico', '.webp', '.avif',
                    // Stylesheets: frequently rewritten by themes and optimizer
                    // plugins, a common source of post-update false positives.
                    // Strict-mode users can remove it (CSS injection is still a
                    // vector, defended primarily by CSP in the headers module).
                    '.css',
                ),
            ),

            // Activity Log settings
            'activity_log' => array(
                'retention_days'       => 30,
                'max_entries'          => 10000,
                'log_logins'           => true,
                'log_failed_logins'    => true,
                'log_user_changes'     => true,
                'log_post_changes'     => true,
                'log_plugin_changes'   => true,
                'log_theme_changes'    => true,
                'log_option_changes'   => false,
                'log_file_changes'     => true,
                'log_comments'         => true,
                'log_media'            => true,
                'excluded_users'       => array(),
                'excluded_ips'         => array(),
                'tracked_options'      => array(),
            ),

            // Backup settings
            'backup' => array(
                'keep_backups'           => 5,
            ),

            // Notification settings (centralized recipients for all admin emails)
            'email' => array(
                'send_to_admin_email'      => true,
                'additional_recipients'    => array(),
                'send_deactivation_email'  => true,
            ),

            // Advanced settings
            'advanced' => array(
                'remove_readme'          => true,
                'remove_license'         => true,
            ),

            // Security Analyzer (v2.1.0) — on-demand + weekly Security Check
            'security_analyzer' => array(
                'weekly_scan_enabled' => true,
                'email_on_regression' => false,
            ),

            // Audit Alerts (v2.8.0) — alerting layer on top of Security Audit.
            // The engine subscribes to logged events and only runs when the
            // Security Audit (activity_log) module is enabled. Opt-in: both
            // legs start OFF so it never duplicates the per-module emails that
            // already exist (User Security admin monitoring, Plugin Status...).
            'audit_alerts' => array(
                // Shared anti-repeat cooldown (minutes). After an alert, do not
                // send another about the same thing (same event type for
                // immediate, same category for threshold) until this passes.
                // Prevents a flood during a sustained attack.
                'cooldown_minutes' => 60,
                // #38 Immediate alerts: selected event types email right away.
                'immediate' => array(
                    'enabled'      => false,
                    // Alert on any logged event at or above this severity. A new
                    // admin, a closed plugin or a privilege escalation are all
                    // logged as "critical", so "critical" already covers them.
                    'min_severity' => 'critical', // 'critical' | 'warning'
                ),
                // #10 Threshold alerts: N events of a category within a window.
                'threshold' => array(
                    'enabled'    => false,
                    'window'     => '1h', // 30m | 1h | 6h | 24h
                    // Per-category trigger counts (warning/critical events only);
                    // 0 disables that category. Covers every event type that can
                    // log a warning or critical. Keep in sync with
                    // Vigilante_Audit_Alerts::category_labels().
                    'categories' => array(
                        'firewall' => 50,
                        'login'    => 20,
                        'user'     => 5,
                        'plugin'   => 0,
                        'file'     => 0,
                        'security' => 0,
                        'system'   => 0,
                        'settings' => 0,
                        'theme'    => 0,
                        'content'  => 0,
                        'comment'  => 0,
                        'media'    => 0,
                    ),
                ),
            ),
        );
    }

    /**
     * Get all options (merged with defaults)
     *
     * @return array All options
     */
    public function get_all_options() {
        if ( null === $this->options ) {
            $saved = get_option( self::OPTION_NAME, array() );
            $this->options = $this->array_merge_deep( $this->get_default_options(), $saved );
        }
        return $this->options;
    }

    /**
     * Deep merge arrays
     *
     * Associative arrays are merged key by key, because that is what lets a
     * saved option keep working when a release adds a setting. Lists are
     * replaced whole, and that part is not cosmetic: merging a list key by key
     * means index by index, so a stored list shorter than the default came back
     * with the default's tail glued to it. Saving "administrator" alone into
     * enforced_roles (default administrator, editor) was read back as
     * administrator, editor, and unchecking every role was read back as the two
     * defaults, so three role pickers could not be narrowed at all. It is the
     * same bug merge_preset() was given its own merge for in 2.9.8; the fix
     * never reached this one or the one in the admin save.
     *
     * An empty saved list therefore means empty, not "fall back to the default".
     * That is the honest reading of what was saved, and the save path is what
     * makes sure a list only becomes empty when somebody emptied it: a list the
     * form did not carry is left alone rather than blanked.
     *
     * Which of the two happens is decided by the DEFAULT, never by what was
     * saved. Deciding by what was saved looks equivalent and is not: an empty
     * array is a list by any definition, so a section stored as array() would
     * have replaced a whole group of settings instead of merging into it, and
     * every key of that group would have come back missing. Found by the third
     * cross review of this release, measured on rest_api_security (7 keys to 0)
     * and on registration_approval (4 to 0, including its enabled flag).
     *
     * @since 3.0.1 Lists replace instead of merging index by index.
     *
     * @param array $defaults Default values.
     * @param array $saved    Saved values.
     * @return array Merged array.
     */
    private function array_merge_deep( $defaults, $saved ) {
        $result = $defaults;

        foreach ( $saved as $key => $value ) {
            if ( is_array( $value ) && isset( $result[ $key ] ) && is_array( $result[ $key ] ) && ! self::is_list( $result[ $key ] ) ) {
                $result[ $key ] = $this->array_merge_deep( $result[ $key ], $value );
            } else {
                $result[ $key ] = $value;
            }
        }

        return $result;
    }

    /**
     * Get a specific section
     *
     * @param string $section Section name.
     * @return array Section options.
     */
    public function get_section( $section ) {
        $options = $this->get_all_options();
        return isset( $options[ $section ] ) ? $options[ $section ] : array();
    }

    /**
     * Get a specific option
     *
     * @param string $section Section name.
     * @param string $key     Option key.
     * @param mixed  $default Default value.
     * @return mixed Option value.
     */
    public function get_option( $section, $key, $default = null ) {
        $options = $this->get_all_options();
        
        if ( isset( $options[ $section ][ $key ] ) ) {
            return $options[ $section ][ $key ];
        }
        
        return $default;
    }

    /**
     * Check if a module is enabled
     *
     * @param string $module Module name.
     * @return bool Whether module is enabled.
     */
    public function is_module_enabled( $module ) {
        $options = $this->get_all_options();
        return ! empty( $options['modules'][ $module ] );
    }

    /**
     * Save options
     *
     * @param array $options Options to save.
     * @return bool Success status.
     */
    public function save_options( $options ) {
        $this->options = null;
        return update_option( self::OPTION_NAME, $options );
    }

    /**
     * Update a section
     *
     * @param string $section Section name.
     * @param array  $data    Section data.
     * @return bool Success status.
     */
    public function update_section( $section, $data ) {
        $options = get_option( self::OPTION_NAME, array() );
        $options[ $section ] = $data;
        $this->options = null;
        return update_option( self::OPTION_NAME, $options );
    }

    /**
     * Update multiple sections at once
     *
     * @param array $sections Associative array of section => data.
     * @return bool Success status.
     */
    public function update_options( $sections ) {
        $options = get_option( self::OPTION_NAME, array() );
        
        foreach ( $sections as $section => $data ) {
            $options[ $section ] = $data;
        }
        
        $this->options = null;
        return update_option( self::OPTION_NAME, $options );
    }

    /**
     * Clear the options cache
     */
    public function clear_cache() {
        $this->options = null;
        wp_cache_delete( self::OPTION_NAME, 'options' );
    }

    /**
     * Whether this context is allowed to write the files a network shares
     *
     * wp-config.php and the root .htaccess are single files for the whole
     * network, while Vigilant's settings are per site. Without a gate, every
     * save, activation and deactivation from any site rewrites those files from
     * that site's own options, so the last one to save wins and silently undoes
     * the rest. Measured on a real network: the main site enables "disable file
     * editing", a subsite admin presses Save on their own screen without
     * touching it, and the constant disappears from wp-config.php while the main
     * site's screen keeps showing the box ticked.
     *
     * So on a network only the main site decides, and only a network
     * administrator. WP-CLI on the main site counts too: there is no user to ask
     * there, but the site is the right one, and a network admin running
     * `wp plugin activate --network` expects the files to be written.
     *
     * On a single site this is always true and nothing changes.
     *
     * @since 2.9.8
     *
     * @return bool
     */
    /**
     * Whether this site is the one that owns the files a network shares.
     *
     * Pure site identity, with no capability in it, and that is the point. A
     * refresh that Vigilant performs by itself, such as rewriting its own
     * .htaccess block after an update, decides nothing: the content comes from
     * this site's own options whoever happens to be visiting. What must not
     * happen is a *different* site writing the shared file, and that is exactly
     * what this answers.
     *
     * can_write_shared_files() below adds the capability on top, and is the
     * right question for anything a person initiates from a settings screen.
     *
     * @since 2.10.1
     * @return bool
     */
    public static function owns_shared_files() {
        // One wp-config.php and one root .htaccess per installation, even with
        // several networks in it: is_main_site() alone is true on the main site
        // of every network. Since 2.11.8, found by the audit of the network.
        return ! is_multisite() || ( is_main_site() && is_main_network() );
    }

    public static function can_write_shared_files() {
        if ( ! is_multisite() ) {
            return true;
        }

        // See owns_shared_files(): the main site of a secondary network, and
        // its network administrator, do not own the installation's files.
        if ( ! is_main_site() || ! is_main_network() ) {
            return false;
        }

        // WP-CLI with nobody logged in: there is no user to ask, and the site is
        // the right one, so a network admin running `wp plugin activate --network`
        // gets the files written. With a user set (wp --user=...) the capability
        // is checked like anywhere else, so the gate cannot be side-stepped by
        // running as a subsite administrator.
        if ( defined( 'WP_CLI' ) && WP_CLI && ! get_current_user_id() ) {
            return true;
        }

        return current_user_can( 'manage_network_options' );
    }

    /**
     * The one message shown wherever a shared-file setting is out of reach
     *
     * Deliberately a single string reused by every section, instead of one per
     * section: it says the same thing everywhere and there is no reason to make
     * translators write it four times.
     *
     * @since 2.9.8
     *
     * @return string
     */
    public static function get_shared_files_notice() {
        return __( 'These settings are written to wp-config.php and .htaccess, files the whole network shares. So that one site cannot overwrite another, they are managed from the main site of the network by a network administrator.', 'vigilante' );
    }

    /**
     * Apply the tweaks a brand new installation gets on top of the raw defaults
     *
     * A few keys are deliberately missing from get_default_options() because
     * declaring them would break something else. XML-RPC is the one case today:
     * declaring wp_hardening.xmlrpc_mode would make the defaults merge fill it in
     * always and hide the fallback that reads the old pair of settings on sites
     * that have not re-saved the tab. With nothing stored the resolver answers
     * 'full', which blocks XML-RPC completely, and that is not what we want a new
     * site to get.
     *
     * Everything that seeds a clean configuration has to run this: the activation
     * hook, the per-section reset and the global reset to defaults. Otherwise the
     * defaults you get by pressing a button are not the defaults you get by
     * installing the plugin, which is exactly what happened until 2.9.8.
     *
     * @since 2.9.8
     *
     * @param array $options Options array to adjust.
     * @return array
     */
    public static function apply_install_tweaks( $options ) {
        if ( ! isset( $options['wp_hardening'] ) || ! is_array( $options['wp_hardening'] ) ) {
            $options['wp_hardening'] = array();
        }

        $options['wp_hardening']['xmlrpc_mode'] = 'pingback';

        return $options;
    }

    /**
     * Keys that hold what the site owner typed in, never wiped by a restore
     *
     * Putting the security posture back to its defaults is one thing; deleting
     * an IP whitelist, the secret login address, the two factor setup or the
     * addresses that receive the alerts is another, and nobody presses a button
     * called "restore defaults" expecting that. Both the Standard preset and the
     * two reset buttons leave these alone.
     *
     * Read from outside the plugin: the third-party network plugin Vigilante
     * Network Sync calls this from its 2.0.3 to decide what NOT to copy between
     * the sites of a network, so a key it does not know about is preserved per
     * site instead of overwritten. Adding keys here is safe and helps it;
     * renaming or removing the method, or changing the shape of what it returns,
     * silently changes what that plugin replicates across a whole network.
     *
     * @since 2.9.8
     *
     * @return array<string,string[]>
     */
    public static function get_user_data_keys() {
        return array(
            'firewall'       => array( 'ip_whitelist', 'ip_blacklist', 'ua_whitelist', 'ua_blacklist', 'trusted_proxy_header', 'trusted_proxies' ),
            'login_security' => array( 'ip_whitelist', 'custom_login_url', 'two_factor' ),
            'user_security'  => array( 'insecure_usernames' ),
            'file_integrity' => array( 'excluded_paths', 'excluded_extensions' ),
            'email'          => array( 'additional_recipients' ),
        );
    }

    /**
     * Settings whose only effect is written to a file the network shares
     *
     * true for a whole section, or the list of keys inside it. Used to keep a
     * subsite from resetting settings it does not control: the file is written
     * from the main site, so resetting the local copy would only make the two
     * disagree.
     *
     * Note this is not every setting that reaches .htaccess. Blocking bad bots
     * or empty user agents also runs in PHP, per site, so those stay editable on
     * a subsite: the PHP half protects that site and the .htaccess half is
     * refused, leaving the main site's rules standing. On the main site they
     * are locked too, see get_main_site_file_settings().
     *
     * The PHP blocks for plugins and themes have no field on the settings
     * screen, but an imported file carries them, and readme.html and
     * license.txt are removed from the root the whole network shares.
     *
     * @since 2.9.8
     *
     * @return array<string,true|string[]>
     */
    public static function get_shared_file_settings() {
        return array(
            'security_headers' => true,
            'wp_hardening'     => array( 'disallow_file_edit', 'disallow_file_mods', 'force_ssl_admin', 'force_ssl_login', 'wp_debug', 'disable_wp_cron' ),
            'firewall'         => array( 'disable_directory_browsing', 'protect_wp_config', 'protect_wp_includes', 'protect_uploads_php', 'protect_sensitive_files', 'protect_wp_cron', 'limit_http_methods', 'block_php_in_plugins', 'block_php_in_themes' ),
            'advanced'         => array( 'remove_readme', 'remove_license' ),
        );
    }

    /**
     * Settings the shared files are built from that also act on the site storing them
     *
     * get_shared_file_settings() lists what does nothing but end up in a shared
     * file. These do both: blocking bad bots and bad query strings, the visitor
     * IP detection and the two whitelists run in PHP for the site that stores
     * them, and on the main site of a network they are also what the .htaccess
     * rules of every site are generated from; the three writing module switches
     * (firewall, security_headers, wp_hardening) decide whether the .htaccess
     * blocks and the wp-config.php constants exist at all.
     *
     * Since 2.11.8 it also locks what decides whether the shared files are
     * WATCHED, not built: the File Integrity module and its scan_critical_config
     * switch. On the main site the critical-file scan is the network's canary
     * for a change to wp-config.php or the root .htaccess, which only a network
     * administrator can approve, so a main-site administrator without network
     * rights must not be able to silence it by turning either one off. Closing
     * the ignore list and the clear-results button in 2.11.8 left these two as
     * the remaining routes; found by the audit of the admin surface.
     *
     * Since 3.0.0 the self-check has no setting at all, so there is nothing to lock: Vigilant's own
     * files are shared by every site, and on the main site the self-check is
     * the one that reports a change to them for the whole network.
     *
     * On a subsite all of them only act on that site, so they stay editable
     * there (get_locked_file_settings() adds this set only when owns_shared_files()).
     *
     * Until 2.11.6 an administrator of the main site without network rights
     * could change any of them, and the file-only ones too: the write to the
     * file was refused at that moment, but the value stayed stored, and the
     * refresh after the next update, or the next save by a network
     * administrator, published it to the whole network.
     *
     * @since 2.11.6
     * @since 2.11.8 The file_integrity module and scan_critical_config.
     *
     * @return array<string,string[]>
     */
    /**
     * The two factor policy that governs this installation
     *
     * On a network the answer must not depend on which site the login happens to
     * arrive at, because the cookie WordPress issues does not: COOKIEHASH comes
     * from the network siteurl (wp-includes/default-constants.php) and
     * COOKIE_DOMAIN covers every host of the network
     * (wp-includes/ms-default-constants.php). Until 2.11.10 the settings, the
     * enforced roles and the TOTP table were all read per site, so somebody
     * holding the password of an administrator protected by 2FA on the main site
     * posted the login to a subsite where that account has no role, was never
     * asked for a code, and came out with a session valid across the network.
     * Measured on the Multisite install on 12 sep 2026 (user_requires_2fa true on
     * the main site, false on demo2 for the same account) and found by the
     * file-by-file review of 2.11.10.
     *
     * So the policy of the main site governs the whole network. On a single site
     * this is the site's own configuration and nothing changes.
     *
     * @since 2.11.10
     *
     * @return array The two_factor section that applies.
     */
    public static function two_factor_policy() {
        $options = is_multisite()
            ? get_blog_option( get_main_site_id(), self::OPTION_NAME, array() )
            : get_option( self::OPTION_NAME, array() );

        if ( ! is_array( $options ) ) {
            return array();
        }

        $login = isset( $options['login_security'] ) && is_array( $options['login_security'] )
            ? $options['login_security']
            : array();

        return ( isset( $login['two_factor'] ) && is_array( $login['two_factor'] ) ) ? $login['two_factor'] : array();
    }

    /**
     * Whether two factor is required for this account, anywhere in the network
     *
     * Union, and deliberately so. Reading the policy only from the main site,
     * which is what this release did at first, would have switched two factor off
     * for every network that has it configured per subsite, which until now was
     * the only way it could be configured at all: a silent downgrade of the very
     * protection being fixed. Found by the cross review of 2.11.10. So the
     * question is asked of every site the account belongs to, plus the main site,
     * each with its own enforced roles and exclusions, and one yes is enough.
     *
     * That also closes the bypass: the settings, the roles and the enrolment used
     * to be read from whichever site the login arrived at, while the cookie
     * WordPress issues is valid across the whole network (COOKIEHASH comes from
     * the network siteurl and COOKIE_DOMAIN covers every host of it), so an
     * account protected on one site could log in through another and come out
     * with a session valid everywhere.
     *
     * @since 2.11.10
     *
     * @param WP_User $user User being authenticated.
     * @return bool
     */
    public static function two_factor_required_for( $user ) {
        return array() !== self::two_factor_demands_for( $user );
    }

    /**
     * Which second factor methods this account is asked for, across the network
     *
     * Empty when nothing asks. On a network there can be more than one, because
     * each site keeps its own settings and the requirement is the union of them.
     *
     * @since 2.11.10
     *
     * @param WP_User $user User being authenticated.
     * @return string[] Methods asked for, without repeats.
     */
    public static function two_factor_methods_for( $user ) {
        $methods = array();

        foreach ( self::two_factor_demands_for( $user ) as $settings ) {
            $method = isset( $settings['method'] ) ? (string) $settings['method'] : 'email';

            // A method this version does not know is read as the default rather
            // than left to fall through. Registering nothing at all is how the
            // second factor of a whole network went quiet in silence: a saved
            // value of '' (which validate_section() lets through on an import,
            // since only the tab has an allowlist) matched neither class, so no
            // filter was registered anywhere while every screen still said two
            // factor was on. Found by the third cross review of 2.11.10.
            $methods[] = in_array( $method, array( 'email', 'totp' ), true ) ? $method : 'email';
        }

        return array_values( array_unique( $methods ) );
    }

    /**
     * Which of the two second factor classes handles this login
     *
     * The method cannot be read from one site's settings, and reading it from the
     * main site was the hole the third cross review of 2.11.10 found: with the
     * main site on totp and a subsite asking for a code by email, the class that
     * registered was TOTP, the account had no enrolment, and the "not set up yet"
     * branch let the login through. In 2.11.9 that same login was asked for its
     * emailed code. So the question is asked per account, not per site.
     *
     * The order is what keeps it closed at both ends:
     *
     * 1. An enrolment already made wins while some site asking for a second
     *    factor asks for an authenticator app. It is the strongest factor the
     *    account has and it is ready to use, wherever in the network it was set
     *    up.
     * 2. Otherwise, if any site asking for a second factor asks for email, email
     *    handles it. Email needs no enrolment, so it can never fall into the
     *    branch that lets a login through for lack of one.
     * 3. Only when every site asking wants an authenticator app does TOTP handle
     *    it, which is the case the grace period was written for.
     *
     * The condition on the first step came in 2.11.11. Without it an enrolment
     * left from a time when the site asked for an app outranked the method the
     * site asks for now: a single site set to email asked those accounts for an
     * authenticator code, which 2.11.9 never did and which locks out whoever
     * removed the app after the switch. Dropping that enrolment opens nothing,
     * because the account then goes to email, which needs no enrolment.
     *
     * @since 2.11.10
     * @since 2.11.11 An enrolment only wins while an authenticator app is asked for.
     *
     * @param WP_User $user       User being authenticated.
     * @param bool    $enrolled   Whether the account has a TOTP enrolment anywhere.
     * @return string 'email', 'totp', or '' when nothing asks.
     */
    public static function two_factor_handler_for( $user, $enrolled ) {
        $methods = self::two_factor_methods_for( $user );

        if ( ! $methods ) {
            return '';
        }

        if ( $enrolled && in_array( 'totp', $methods, true ) ) {
            return 'totp';
        }

        return in_array( 'email', $methods, true ) ? 'email' : 'totp';
    }

    /**
     * The two factor settings of every site that asks this account for one
     *
     * @since 2.11.10
     *
     * @param WP_User $user User being authenticated.
     * @return array[] The two_factor section of each site that asks.
     */
    private static function two_factor_demands_for( $user ) {
        if ( empty( $user->ID ) ) {
            return array();
        }

        if ( ! is_multisite() ) {
            $roles  = ( isset( $user->roles ) && is_array( $user->roles ) ) ? $user->roles : array();
            $policy = self::two_factor_policy();

            return self::two_factor_site_requires( $policy, $user, $roles ) ? array( $policy ) : array();
        }

        $demands  = array();
        $blog_ids = array( (int) get_main_site_id() );

        /*
         * A super administrator is a member of almost no site (measured on the
         * Multisite install: of three sites, the network owner belongs to one),
         * yet can log in through any of them and the cookie is valid everywhere.
         * Asking only the sites they belong to left the account with the most
         * power in the network outside the policy, which is the bypass upside
         * down. So for them every site of the network is consulted. There are
         * few super administrators. It does not only run at login, though, which
         * this note claimed until 2.11.11: the dashboard hooks of the TOTP class
         * ask it on every admin screen of every site of a network, at least once
         * per hook.
         */
        if ( is_super_admin( $user->ID ) ) {
            $blog_ids = array_merge( $blog_ids, get_sites( array( 'fields' => 'ids', 'number' => 200 ) ) );
        }

        foreach ( get_blogs_of_user( $user->ID ) as $blog ) {
            if ( ! empty( $blog->userblog_id ) ) {
                $blog_ids[] = (int) $blog->userblog_id;
            }
        }

        foreach ( array_unique( $blog_ids ) as $blog_id ) {
            $options = get_blog_option( $blog_id, self::OPTION_NAME, array() );

            if ( ! is_array( $options ) || empty( $options['login_security']['two_factor'] ) ) {
                continue;
            }

            /*
             * A site whose Login Security module is off asks for nothing, and
             * reading only the sub-setting made it ask anyway: a subsite that had
             * switched the whole module off, leaving an orphan two_factor.enabled
             * behind, imposed a second factor on every account of the network,
             * with no screen anywhere explaining why. It is the two-level toggle
             * trap of this plugin read upside down. Found by the third cross
             * review of 2.11.10.
             */
            if ( empty( $options['modules']['login_security'] ) ) {
                continue;
            }

            $elsewhere = new WP_User( $user->ID );
            $elsewhere->for_site( $blog_id );

            // A super administrator can hold no role row anywhere, and is judged
            // as an administrator so the strictest policy of the network reaches
            // the account with the most power in it.
            $roles = ( isset( $elsewhere->roles ) && is_array( $elsewhere->roles ) && $elsewhere->roles )
                ? $elsewhere->roles
                : ( is_super_admin( $user->ID ) ? array( 'administrator' ) : array() );

            if ( self::two_factor_site_requires( $options['login_security']['two_factor'], $user, $roles ) ) {
                $demands[] = $options['login_security']['two_factor'];
            }
        }

        return $demands;
    }

    /**
     * Whether one site's two factor settings cover this account
     *
     * @since 2.11.10
     *
     * @param array    $settings The two_factor section of one site.
     * @param WP_User  $user     User being authenticated.
     * @param string[] $roles    Roles the account holds on that site.
     * @return bool
     */
    private static function two_factor_site_requires( $settings, $user, $roles ) {
        if ( ! is_array( $settings ) || empty( $settings['enabled'] ) ) {
            return false;
        }

        $excluded = isset( $settings['excluded_users'] ) ? array_map( 'absint', (array) $settings['excluded_users'] ) : array();

        if ( in_array( (int) $user->ID, $excluded, true ) ) {
            return false;
        }

        $enforced = isset( $settings['enforced_roles'] ) ? (array) $settings['enforced_roles'] : array( 'administrator', 'editor' );

        return (bool) array_intersect( (array) $roles, $enforced );
    }

    /**
     * Settings that only a network administrator may change on the main site
     *
     * @return array<string,string[]>
     */
    public static function get_main_site_file_settings() {
        return array(
            'modules'        => array( 'firewall', 'security_headers', 'wp_hardening', 'file_integrity' ),
            // trusted_proxies goes with trusted_proxy_header, and leaving it out
            // was a hole: the header decides which address the firewall of the
            // whole installation acts on, and this list decides which peers may
            // set that header. An administrator of the main site without network
            // rights who could edit only this half turned every visitor into a
            // trusted proxy. Found by the file-by-file review of 2.11.10.
            'firewall'       => array( 'block_bad_bots', 'block_bad_query_strings', 'trusted_proxy_header', 'trusted_proxies', 'ip_whitelist', 'ua_whitelist' ),
            'file_integrity' => array( 'scan_critical_config' ),
        );
    }

    /**
     * Shared file settings the current user may not change on this site
     *
     * Empty when the user can write the shared files. Otherwise the file-only
     * settings on every site, plus, on the main site, the ones it also builds
     * the shared files from.
     *
     * @since 2.11.6
     *
     * @return array<string,true|string[]>
     */
    public static function get_locked_file_settings() {
        if ( self::can_write_shared_files() ) {
            return array();
        }

        $locked = self::get_shared_file_settings();

        if ( self::owns_shared_files() ) {
            foreach ( self::get_main_site_file_settings() as $section => $keys ) {
                if ( ! isset( $locked[ $section ] ) ) {
                    $locked[ $section ] = $keys;
                } elseif ( is_array( $locked[ $section ] ) ) {
                    $locked[ $section ] = array_values( array_unique( array_merge( $locked[ $section ], $keys ) ) );
                }
            }
        }

        return $locked;
    }

    /**
     * Put back the stored value of every shared file setting the user may not change
     *
     * For every writer of the whole configuration: saving a tab, importing a
     * file, applying a preset, restoring the defaults. Hiding a field on the
     * screen decides nothing, because the request can carry the key anyway. A
     * key that was not stored is dropped, so its default keeps applying.
     *
     * @since 2.11.6
     *
     * @param array $options Configuration about to be stored.
     * @param array $stored  Configuration stored now, as read from the option.
     * @return array
     */
    public static function keep_locked_file_settings( $options, $stored ) {
        $options = is_array( $options ) ? $options : array();
        $stored  = is_array( $stored ) ? $stored : array();
        $locked  = self::get_locked_file_settings();

        if ( ! $locked ) {
            return $options;
        }

        /*
         * A key that was never stored takes its default, which is what it was
         * worth before. Until 2.11.8 it was dropped instead, and the sanitize
         * callback of the option filled it in again, but validate_options()
         * fills a missing module switch with false, not with its default.
         */
        $instance = new self();
        $defaults = $instance->get_default_options();

        foreach ( $locked as $section => $keys ) {
            if ( true === $keys ) {
                if ( array_key_exists( $section, $stored ) ) {
                    $options[ $section ] = $stored[ $section ];
                } elseif ( isset( $defaults[ $section ] ) ) {
                    $options[ $section ] = $defaults[ $section ];
                } else {
                    unset( $options[ $section ] );
                }
                continue;
            }

            $stored_section  = ( isset( $stored[ $section ] ) && is_array( $stored[ $section ] ) ) ? $stored[ $section ] : array();
            $default_section = ( isset( $defaults[ $section ] ) && is_array( $defaults[ $section ] ) ) ? $defaults[ $section ] : array();

            foreach ( $keys as $key ) {
                if ( array_key_exists( $key, $stored_section ) ) {
                    $value = $stored_section[ $key ];
                } elseif ( array_key_exists( $key, $default_section ) ) {
                    $value = $default_section[ $key ];
                } else {
                    if ( isset( $options[ $section ] ) && is_array( $options[ $section ] ) ) {
                        unset( $options[ $section ][ $key ] );
                    }
                    continue;
                }

                if ( ! isset( $options[ $section ] ) || ! is_array( $options[ $section ] ) ) {
                    $options[ $section ] = array();
                }
                $options[ $section ][ $key ] = $value;
            }
        }

        return $options;
    }

    /**
     * Take a lock kept as a row of the options table, or report that another request holds it
     *
     * add_option() cannot be a lock: it runs INSERT ... ON DUPLICATE KEY UPDATE
     * (wp-includes/option.php:1142 in WP 7.1), so two requests that both find
     * the option missing both "create" it and both believe they hold it. INSERT
     * IGNORE creates the row for exactly one of them, which is what core does in
     * WP_Upgrader::create_lock() (wp-admin/includes/class-wp-upgrader.php:1065).
     * A lock older than the timeout counts as abandoned, by a fatal error between
     * taking and releasing it, and only one request takes it over.
     *
     * @since 2.11.8
     *
     * @param string $name    Option name of the lock, in the current site's table.
     * @param int    $timeout Seconds after which a held lock counts as abandoned.
     * @return bool True if this request now holds the lock.
     */
    public static function acquire_option_lock( $name, $timeout ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- an atomic lock needs INSERT IGNORE, which the options API does not offer; same query as WP_Upgrader::create_lock().
        if ( $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} ( option_name, option_value, autoload ) VALUES ( %s, %s, 'no' )", $name, (string) time() ) ) ) {
            wp_cache_delete( $name, 'options' );
            return true;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- the lock row as stored right now, not a cached copy.
        $held = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $name ) );

        if ( null === $held || ( time() - (int) $held ) < $timeout ) {
            return false;
        }

        // Abandoned: the delete only matches the value that was read, and only one
        // request wins the insert that follows.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- removes an abandoned lock row.
        $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s", $name, $held ) );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- same atomic insert as above.
        return (bool) $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} ( option_name, option_value, autoload ) VALUES ( %s, %s, 'no' )", $name, (string) time() ) );
    }

    /**
     * Release a lock taken with acquire_option_lock()
     *
     * @since 2.11.8
     *
     * @param string $name Option name of the lock.
     */
    public static function release_option_lock( $name ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- removes the row acquire_option_lock() inserted.
        $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", $name ) );
        wp_cache_delete( $name, 'options' );
    }

    /**
     * Put a configuration back to the defaults without deleting what the owner typed
     *
     * @since 2.9.8
     *
     * @param array $current Configuration being replaced.
     * @return array
     */
    public static function get_defaults_preserving_user_data( $current ) {
        $instance = new self();
        $defaults = self::apply_install_tweaks( $instance->get_default_options() );

        foreach ( self::get_user_data_keys() as $section => $keys ) {
            foreach ( $keys as $key ) {
                if ( isset( $current[ $section ] ) && array_key_exists( $key, (array) $current[ $section ] ) ) {
                    $defaults[ $section ][ $key ] = $current[ $section ][ $key ];
                }
            }
        }

        return $defaults;
    }

    /**
     * The values the Standard preset applies
     *
     * Standard is the configuration a new installation gets, with every module
     * on. It is built from the defaults rather than written out by hand, because
     * a hand-written copy drifts: until 2.9.8 Standard named a dozen fields and
     * left everything else alone, so applying it after Maximum kept Maximum's
     * password rules, its administrator alerts, its session limits and its
     * password expiry, and the preset that says it applies sensible defaults
     * applied almost none of them.
     *
     * The only thing it does not touch is what the site owner typed in: IP and
     * user agent lists, the custom login address, two factor configuration, the
     * integrity scan exclusions and the extra notification recipients. Putting
     * the security posture back to the defaults is one thing, throwing away
     * someone's whitelist is another, and "Reset to Defaults" is right there for
     * that.
     *
     * @since 2.9.8
     *
     * @return array
     */
    private function get_standard_preset_values() {
        $values = self::apply_install_tweaks( $this->get_default_options() );

        foreach ( array_keys( $values['modules'] ) as $module ) {
            $values['modules'][ $module ] = true;
        }

        foreach ( self::get_user_data_keys() as $section => $keys ) {
            foreach ( $keys as $key ) {
                unset( $values[ $section ][ $key ] );
            }
        }

        unset( $values['user_security']['password_expiration']['excluded_users'] );

        return $values;
    }

    /**
     * Merge a preset over a configuration
     *
     * Not array_replace_recursive(), which is wrong for this in two ways. A list
     * of roles in the preset is merged position by position instead of replacing
     * the stored one, so applying Standard over Maximum turned the two roles
     * Standard expires passwords for into Maximum's five with the first two
     * overwritten. And an empty list in the preset clears nothing at all,
     * because there is no element to replace with.
     *
     * So: associative arrays are merged key by key, and lists and scalars are
     * replaced outright.
     *
     * @since 2.9.8
     *
     * @param array $base    Current configuration.
     * @param array $overlay Preset values.
     * @return array
     */
    public static function merge_preset( $base, $overlay ) {
        foreach ( $overlay as $key => $value ) {
            if ( is_array( $value ) && isset( $base[ $key ] ) && is_array( $base[ $key ] ) && ! self::is_list( $value ) ) {
                $base[ $key ] = self::merge_preset( $base[ $key ], $value );
                continue;
            }

            $base[ $key ] = $value;
        }

        return $base;
    }

    /**
     * A stored list, or the shipped one when it arrives empty
     *
     * For the four lists that have NO field on any screen: the allowed HTTP
     * methods, the insecure usernames, the public REST endpoints and the roles
     * of registration approval. Nobody can empty those from the interface, so
     * an empty one is a leftover, and every version up to 3.0.0 produced them:
     * saving any tab wrote array() over every list of that section whose key the
     * form did not carry, which for these four was always. Reading the settings
     * hid it by merging the shipped values on top, and 3.0.1 stops doing that,
     * because a stored empty list is what makes unticking every role work.
     *
     * The migration in vigilante.php removes those keys once. This is the line
     * of defence for every other route, including Under Attack, which
     * photographs the raw option when it is switched on and puts it back whole
     * when it expires, after the migration has already marked itself done.
     *
     * It goes through every reader of those four lists, the ones that enforce
     * and the ones that only report, because a screen that says "no insecure
     * user" while the check is blocking them is its own kind of wrong. The
     * shipped value is read from get_default_options() rather than written out
     * again here: a second copy of a list drifts from the first.
     *
     * @since 3.0.1
     *
     * @param mixed    $value Stored value, as the caller already has it.
     * @param string[] $path  Path of the setting in the options array.
     * @return array
     */
    public static function list_or_shipped( $value, $path ) {
        if ( is_array( $value ) && array() !== $value ) {
            return $value;
        }

        $instance = new self();
        $shipped  = $instance->get_default_options();

        foreach ( (array) $path as $key ) {
            if ( ! is_array( $shipped ) || ! array_key_exists( $key, $shipped ) ) {
                return array();
            }
            $shipped = $shipped[ $key ];
        }

        return is_array( $shipped ) ? $shipped : array();
    }

    /**
     * Whether an array is a plain list (0..n-1 keys)
     *
     * array_is_list() is PHP 8.1 and this plugin supports 7.4.
     *
     * @since 2.9.8
     *
     * Public since 3.0.1 because the admin save path needs the same answer: the
     * two places that used to merge lists index by index have to agree on what
     * a list is, or they disagree on a different subset of the settings.
     *
     * @param array $value Array to inspect.
     * @return bool
     */
    public static function is_list( $value ) {
        if ( array() === $value ) {
            return true;
        }

        return array_keys( $value ) === range( 0, count( $value ) - 1 );
    }

    /**
     * Get presets with descriptions
     *
     * @return array Presets configuration.
     */
    public function get_presets() {
        return array(
            'standard' => array_merge(
                array(
                    'name'        => __( 'Standard', 'vigilante' ),
                    'description' => __( 'Balanced security suitable for most websites. Enables every module and puts every setting back to the value a new installation gets.', 'vigilante' ),
                ),
                $this->get_standard_preset_values()
            ),

            'maximum' => array(
                'name'        => __( 'Maximum Security', 'vigilante' ),
                'description' => __( 'Strictest settings for high-security sites. CSP is set to report-only mode to prevent breaking the admin interface.', 'vigilante' ),
                'modules' => array(
                    'firewall'         => true,
                    'security_headers' => true,
                    'login_security'   => true,
                    'rest_api_security'=> true,
                    'user_security'    => true,
                    'wp_hardening'     => true,
                    'file_integrity'   => true,
                    'activity_log'     => true,
                ),
                'firewall' => array(
                    'block_bad_query_strings'   => true,
                    'block_sql_injection'       => true,
                    'block_xss_attacks'         => true,
                    'block_file_inclusion'      => true,
                    'block_directory_traversal' => true,
                    'block_bad_bots'            => true,
                    'block_empty_user_agent'    => true,
                    'rate_limiting' => array(
                        'enabled'             => true,
                        'requests_per_minute' => 60,
                        'block_duration'      => 600,
                        'progressive'         => true,
                        'max_block_duration'  => 86400,
                    ),
                ),
                'security_headers' => array(
                    'x_frame_options' => 'DENY',
                    // HSTS is intentionally NOT enabled by Maximum: forcing HSTS on a site
                    // that doesn't have a healthy HTTPS setup (or temporarily falls back to
                    // HTTP) locks visitors out for the full max_age. Leaving HSTS off keeps
                    // it as an explicit opt-in decision per site.
                    'csp' => array(
                        'enabled'     => true,
                        'report_only' => false,
                        'directives'  => array(
                            'default-src'     => "'self'",
                            'script-src'      => "'self' 'unsafe-inline' 'unsafe-eval'",
                            'style-src'       => "'self' 'unsafe-inline'",
                            'img-src'         => "'self' data: https: blob:",
                            'font-src'        => "'self' data:",
                            'connect-src'     => "'self' https: blob:",
                            'frame-src'       => "'self' blob:",
                            'frame-ancestors' => "'none'",
                            'worker-src'      => "'self' blob:",
                            'object-src'      => "'none'",
                            'base-uri'        => "'self'",
                        ),
                    ),
                ),
                'rest_api_security' => array(
                    'mode' => 'authenticated_only',
                ),
                'login_security' => array(
                    'max_attempts'        => 3,
                    'lockout_duration'    => 3600,
                    'lockout_increment'   => true,
                    'notify_on_lockout'   => true,
                    'notify_on_admin_login' => true,
                ),
                'wp_hardening' => array(
                    'xmlrpc_mode'        => 'full',
                    'disallow_file_edit' => true,
                    'disallow_file_mods' => true,
                    // close_old_comments is intentionally NOT touched by Maximum:
                    // it would unilaterally close discussion on every old post,
                    // which is a content decision, not a security one.
                ),
                'user_security' => array(
                    'prevent_display_name_login_match' => true,
                    'min_password_length'              => 16,
                    'password_policy' => array(
                        'require_uppercase' => true,
                        'require_lowercase' => true,
                        'require_number'    => true,
                        'require_special'   => true,
                        'block_common'      => true,
                        'block_username'    => true,
                        'affected_roles'    => array(),
                    ),
                    'admin_monitoring' => array(
                        'alert_new_admin'              => true,
                        'alert_admin_email_change'     => true,
                        'alert_permission_elevation'   => true,
                        'alert_admin_password_change'  => true,
                    ),
                    'registration_approval' => array(
                        'enabled'           => true,
                        'notify_admin'      => true,
                        'auto_reject_days'  => 7,
                        'affected_roles'    => array( 'subscriber', 'contributor', 'author', 'editor' ),
                    ),
                    'session_limits' => array(
                        'enabled'           => true,
                        'max_sessions'      => 1,
                        'behavior'          => 'close_oldest',
                        'exclude_admins'    => false,
                    ),
                    'password_expiration' => array(
                        'enabled'           => true,
                        'expire_days'       => 30,
                        'warning_days'      => 7,
                        'affected_roles'    => array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' ),
                        'password_history'  => 5,
                        'send_reminder'     => true,
                    ),
                    'email_verification' => array(
                        'enabled'               => true,
                        'token_expiry_hours'    => 24,
                        'allow_resend'          => true,
                        'auto_delete_days'      => 3,
                    ),
                ),
                'file_integrity' => array(
                    'scan_core'            => true,
                    'scan_plugins'         => true,
                    'scan_themes'          => true,
                    'scan_uploads'         => true,
                    'scan_critical_config' => true,
                    'auto_scan'            => true,
                    'scan_frequency'       => 'daily',
                    'notify_level'         => 'all',
                    'instant_alert'        => true,
                ),
                // A configuration called Maximum Security that never tells you
                // anything happened is half a product, so the audit alerts ship
                // on with it. The shared cooldown keeps a sustained attack from
                // turning into a flood. Under Attack mode builds on this preset,
                // so it inherits them for as long as it is on and gives them back
                // when it is switched off.
                'audit_alerts' => array(
                    'immediate' => array(
                        'enabled'      => true,
                        'min_severity' => 'critical',
                    ),
                    'threshold' => array(
                        'enabled' => true,
                    ),
                ),
                'activity_log' => array(
                    'log_logins'         => true,
                    'log_failed_logins'  => true,
                    'log_user_changes'   => true,
                    'log_post_changes'   => true,
                    'log_plugin_changes' => true,
                    'log_theme_changes'  => true,
                    'log_option_changes' => true,
                    'log_file_changes'   => true,
                    'log_comments'       => true,
                    'log_media'          => true,
                ),
            ),
        );
    }

    /**
     * Get module labels for display
     *
     * @return array Module labels.
     */
    public function get_module_labels() {
        return array(
            'firewall'         => __( 'Firewall', 'vigilante' ),
            'security_headers' => __( 'Security Headers', 'vigilante' ),
            'login_security'   => __( 'Login Security', 'vigilante' ),
            'rest_api_security'=> __( 'REST API Security', 'vigilante' ),
            'user_security'    => __( 'User Security', 'vigilante' ),
            'wp_hardening'     => __( 'WordPress Hardening', 'vigilante' ),
            'file_integrity'   => __( 'File Integrity', 'vigilante' ),
            'activity_log'     => __( 'Security Audit', 'vigilante' ),
        );
    }

    /**
     * Get module descriptions for display
     *
     * @return array Module descriptions.
     */
    public function get_module_descriptions() {
        return array(
            'firewall'         => __( 'Blocks malicious requests, SQL injection, XSS attacks, and bad bots. Includes rate limiting and file protection.', 'vigilante' ),
            'security_headers' => __( 'Adds HTTP security headers like CSP, HSTS, X-Frame-Options. Forces HTTPS and fixes mixed content.', 'vigilante' ),
            'login_security'   => __( 'Brute force protection, 2FA, login attempt limits, XML-RPC control, and notifications.', 'vigilante' ),
            'rest_api_security'=> __( 'Controls REST API access, blocks user enumeration, and protects sensitive endpoints.', 'vigilante' ),
            'user_security'    => __( 'Blocks insecure usernames, enforces strong passwords, and prevents author scanning.', 'vigilante' ),
            'wp_hardening'     => __( 'Hardens wp-config.php, manages comments, cleans header output, and controls feeds.', 'vigilante' ),
            'file_integrity'   => __( 'Scans WordPress core, plugins, and themes for unauthorized changes and suspicious code.', 'vigilante' ),
            'activity_log'     => __( 'Records user actions, logins, content changes, and security events for security auditing.', 'vigilante' ),
        );
    }

    /**
     * Validate options before saving
     *
     * @param array $input Raw input to validate.
     * @return array Validated options.
     */
    public function validate_options( $input ) {
        $validated = array();
        $defaults  = $this->get_default_options();

        // Validate each section that exists in input
        foreach ( $input as $section => $data ) {
            if ( ! is_array( $data ) ) {
                continue;
            }
            
            if ( 'modules' === $section ) {
                // Validate modules (booleans)
                foreach ( $defaults['modules'] as $module => $default_value ) {
                    $validated['modules'][ $module ] = isset( $data[ $module ] ) 
                        ? (bool) $data[ $module ] 
                        : false;
                }
            } elseif ( isset( $defaults[ $section ] ) ) {
                // Validate other sections using generic validator
                $validated[ $section ] = $this->validate_section( $data, $defaults[ $section ] );

                // The few keys that live outside get_default_options() on
                // purpose (see apply_install_tweaks()) survive with their own
                // validation, or an import would silently lose them and the
                // XML-RPC resolver would fall back to blocking everything.
                foreach ( self::undeclared_keys( $section ) as $key => $type ) {
                    if ( ! array_key_exists( $key, $data ) ) {
                        continue;
                    }
                    if ( 'bool' === $type ) {
                        $validated[ $section ][ $key ] = (bool) $data[ $key ];
                    } elseif ( is_array( $type ) && in_array( $data[ $key ], $type, true ) ) {
                        $validated[ $section ][ $key ] = $data[ $key ];
                    }
                }
            }
        }

        /*
         * The lock on the settings the shared files are built from is NOT applied
         * here, and that is a decision, not an oversight. The second cross review
         * of 2.11.10 raised that register_setting( 'vigilante_options', ... )
         * declares this as its sanitize callback with no lock in it, so anything
         * reaching options.php with that option group would write the whole
         * option. The chain does not close: the plugin prints no settings_fields()
         * for that group anywhere, so the nonce it would need is not obtainable,
         * and the five places that do save (saving a tab, importing, a preset,
         * restoring the defaults, resetting a section) all apply
         * keep_locked_file_settings() themselves.
         *
         * Putting it here instead would be worse than the door it closes. A
         * register_setting() callback runs on EVERY update_option() of this
         * option, so it would also lock the writes with no user behind them: the
         * expiry of Under Attack restoring what it hardened, WP-CLI and cron.
         * Those are already covered by matriz-red-ajustes-compartidos.sh, which
         * is where such a change would show up as a row that stopped passing.
         */

        return apply_filters( 'vigilante_validate_options', $validated, $input );
    }

    /**
     * Keys deliberately absent from get_default_options(), with how to validate them
     *
     * Declaring them as defaults would break the fallback they exist for (see
     * apply_install_tweaks()), but the validator still has to know them, or a
     * settings import drops them (found in the 2.11.0 cross review).
     *
     * @since 2.11.0
     *
     * @param string $section Section name.
     * @return array key => 'bool' or list of allowed values.
     */
    private static function undeclared_keys( $section ) {
        $keys = array(
            'wp_hardening'   => array( 'xmlrpc_mode' => array( 'full', 'pingback', 'none' ) ),
            'login_security' => array(
                'disable_xmlrpc'          => 'bool',
                'disable_xmlrpc_pingback' => 'bool',
            ),
        );

        return isset( $keys[ $section ] ) ? $keys[ $section ] : array();
    }

    /**
     * Whether a default value describes a free list rather than a schema
     *
     * An empty array or sequential numeric keys (an IP whitelist, a list of
     * roles) is a list: every entry the user typed is kept. Anything else is a
     * schema: only its keys survive validation.
     *
     * @since 2.11.0
     *
     * @param array $defaults Default value of a setting.
     * @return bool
     */
    private function is_list_default( $defaults ) {
        if ( array() === $defaults ) {
            return true;
        }

        return array_keys( $defaults ) === range( 0, count( $defaults ) - 1 );
    }

    /**
     * Validate a section based on defaults
     *
     * Since 2.11.0 the result only holds keys the defaults know. The loop that
     * used to reincorporate unknown keys "sanitized" meant a settings import
     * could merge any key it liked into vigilante_options (S7 of the 28 Aug
     * 2026 audit). Lists are the exception, handled first: their entries are
     * data, not keys.
     *
     * @param array $input    Input values.
     * @param array $defaults Default values.
     * @return array Validated values.
     */
    private function validate_section( $input, $defaults ) {
        $validated = array();

        if ( $this->is_list_default( $defaults ) ) {
            if ( ! is_array( $input ) ) {
                return array();
            }

            $list = array();
            foreach ( $input as $value ) {
                if ( is_scalar( $value ) ) {
                    $list[] = sanitize_text_field( (string) $value );
                } elseif ( is_array( $value ) ) {
                    $list[] = map_deep( $value, 'sanitize_text_field' );
                }
            }

            return $list;
        }

        foreach ( $defaults as $key => $default_value ) {
            if ( ! isset( $input[ $key ] ) ) {
                $validated[ $key ] = $default_value;
                continue;
            }

            $value = $input[ $key ];

            if ( is_bool( $default_value ) ) {
                $validated[ $key ] = (bool) $value;
            } elseif ( is_int( $default_value ) ) {
                $validated[ $key ] = intval( $value );
            } elseif ( is_array( $default_value ) ) {
                if ( is_array( $value ) ) {
                    $validated[ $key ] = $this->validate_section( $value, $default_value );
                } else {
                    $validated[ $key ] = $default_value;
                }
            } else {
                $validated[ $key ] = sanitize_text_field( $value );
            }
        }

        // Keys the defaults do not declare are dropped on purpose (S7).

        return $validated;
    }
}