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
                'block_http_1_0'            => false,
                
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

                // User-Agent management
                'ua_whitelist'              => array(),
                'ua_blacklist'              => array(),
                'country_blocking'          => array(
                    'enabled'   => false,
                    'mode'      => 'blacklist',
                    'countries' => array(),
                ),
                
                // File protection (htaccess-based)
                'disable_directory_browsing' => true,
                'protect_wp_config'          => true,
                'protect_htaccess'           => true,
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
                'protected_file_extensions'  => array(
                    'htaccess', 'htpasswd', 'ini', 'log', 'sql', 
                    'bak', 'old', 'tmp', 'swp', 'save', 'backup'
                ),
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
                // Note: blob: is required in frame-src and worker-src for the block editor
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
                        'connect-src'              => "'self' https: wss:",
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
                'force_https'               => true,
                'redirect_http_to_https'    => true,
                'fix_mixed_content'         => true,

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
                'disable_xmlrpc'              => true,
                'disable_xmlrpc_pingback'     => true,
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
                'warn_existing_insecure'  => true,
                'block_author_scanning'   => true,
                'force_strong_passwords'  => true,
                'min_password_length'     => 12,

                // Granular password policy. Applies only while
                // force_strong_passwords is on. Defaults reproduce the previous
                // all-requirements behaviour so existing sites keep the same
                // rules until the admin relaxes them. block_username is the only
                // new opt-in rule (off by default to avoid rejecting passwords
                // that were valid before). affected_roles empty = all roles.
                'password_policy'         => array(
                    'require_uppercase' => true,
                    'require_lowercase' => true,
                    'require_number'    => true,
                    'require_special'   => true,
                    'block_common'      => true,
                    'block_username'    => false,
                    'affected_roles'    => array(),
                ),

                'prevent_display_name_login_match' => true,
                
                // Admin monitoring
                'admin_monitoring'        => array(
                    'alert_new_admin'              => false,
                    'alert_admin_email_change'     => false,
                    'alert_permission_elevation'   => false,
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
                    'enabled'           => false,
                    'max_sessions'      => 3,
                    'behavior'          => 'close_oldest',
                    'exclude_admins'    => false,
                ),

                // Password expiration
                'password_expiration'     => array(
                    'enabled'           => true,
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
                'force_ssl_admin'       => true,
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
                'suspicious_patterns'     => array(
                    'eval(',
                    'base64_decode(',
                    'gzinflate(',
                    'str_rot13(',
                    'exec(',
                    'shell_exec(',
                    'system(',
                    'passthru(',
                    'assert(',
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
                'auto_backup'            => true,
                'backup_before_update'   => true,
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
                'block_author_archives'  => false,
                'disable_embeds'         => false,
                'uninstall_cleanup'      => true,
                'debug_mode'             => false,
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
     * @param array $defaults Default values.
     * @param array $saved    Saved values.
     * @return array Merged array.
     */
    private function array_merge_deep( $defaults, $saved ) {
        $result = $defaults;
        
        foreach ( $saved as $key => $value ) {
            if ( is_array( $value ) && isset( $result[ $key ] ) && is_array( $result[ $key ] ) ) {
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
     * Get presets with descriptions
     *
     * @return array Presets configuration.
     */
    public function get_presets() {
        return array(
            'standard' => array(
                'name'        => __( 'Standard', 'vigilante' ),
                'description' => __( 'Balanced security suitable for most websites. Enables all modules with sensible defaults.', 'vigilante' ),
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
                    'rate_limiting' => array(
                        'enabled'             => true,
                        'requests_per_minute' => 120,
                    ),
                ),
                'login_security' => array(
                    'max_attempts'     => 5,
                    'lockout_duration' => 1800,
                    'disable_xmlrpc'   => true,
                ),
                'rest_api_security' => array(
                    'mode' => 'selective',
                ),
                'user_security' => array(
                    'prevent_display_name_login_match' => true,
                ),
                'file_integrity' => array(
                    'notify_level' => 'suspicious_only',
                ),
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
                            'connect-src'     => "'self' https:",
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
                    'disable_xmlrpc'      => true,
                    'notify_on_lockout'   => true,
                    'notify_on_admin_login' => true,
                ),
                'wp_hardening' => array(
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
            }
        }

        return apply_filters( 'vigilante_validate_options', $validated, $input );
    }

    /**
     * Validate a section based on defaults
     *
     * @param array $input    Input values.
     * @param array $defaults Default values.
     * @return array Validated values.
     */
    private function validate_section( $input, $defaults ) {
        $validated = array();

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

        // Include any extra keys from input
        foreach ( $input as $key => $value ) {
            if ( ! isset( $validated[ $key ] ) ) {
                if ( is_array( $value ) ) {
                    $validated[ $key ] = array_map( 'sanitize_text_field', $value );
                } else {
                    $validated[ $key ] = sanitize_text_field( $value );
                }
            }
        }

        return $validated;
    }
}