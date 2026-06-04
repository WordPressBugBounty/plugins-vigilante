<?php
/**
 * Activator Class
 *
 * Handles plugin activation tasks
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Activator
 *
 * Fired during plugin activation
 */
class Vigilante_Activator {

    /**
     * Run activation tasks
     */
    public static function activate() {
        // Start output buffering to prevent any accidental output
        ob_start();

        // Check requirements first
        if ( ! self::check_requirements() ) {
            ob_end_clean();
            return;
        }

        // Create database tables
        $database = new Vigilante_Database();
        $database->create_tables();

        // Initialize default settings
        $settings = new Vigilante_Settings();
        $current_options = get_option( Vigilante_Settings::OPTION_NAME );
        
        if ( false === $current_options ) {
            // First installation - set defaults
            update_option( Vigilante_Settings::OPTION_NAME, $settings->get_default_options() );
            // Refresh settings instance to get new values
            $settings->clear_cache();
            $settings = new Vigilante_Settings();
        } else {
            // Existing installation - run idempotent migrations
            if ( self::run_migrations( $current_options ) ) {
                $settings->clear_cache();
                $settings = new Vigilante_Settings();
            }
        }

        // Create backup of current files FIRST (before any modifications)
        self::create_activation_backup( $settings );

        // Apply htaccess protection (part of firewall module)
        if ( $settings->is_module_enabled( 'firewall' ) ) {
            self::apply_htaccess_protection( $settings );
        }

        // Apply security headers to htaccess
        if ( $settings->is_module_enabled( 'security_headers' ) ) {
            self::apply_security_headers( $settings );
        }

        // Apply wp-config security (part of wp_hardening module)
        if ( $settings->is_module_enabled( 'wp_hardening' ) ) {
            self::apply_wpconfig_security( $settings );
        }

        // Update WordPress options for HTTPS (part of security_headers module)
        if ( $settings->is_module_enabled( 'security_headers' ) ) {
            self::enforce_https( $settings );
        }

        // Apply comment security settings (part of wp_hardening module)
        if ( $settings->is_module_enabled( 'wp_hardening' ) ) {
            self::apply_comment_security( $settings );
        }

        // Remove sensitive files
        self::remove_sensitive_files( $settings );

        // Generate critical config files baseline (after all Vigilante writes above)
        self::generate_critical_baseline( $settings );

        // Schedule cron events
        self::schedule_events();

        // Set activation transient for admin notice
        set_transient( 'vigilante_activated', true, 30 );

        // Store activation time
        update_option( 'vigilante_activated_time', time() );

        // Send activation email if enabled
        self::send_activation_email( $settings );

        // Flush rewrite rules
        flush_rewrite_rules();

        // Clean any output that may have been generated
        ob_end_clean();
    }

    /**
     * Idempotent migrations for existing installations.
     *
     * @param array $current_options Current vigilante_options array.
     * @return bool True if any migration changed the stored option.
     */
    private static function run_migrations( $current_options ) {
        $changed = false;

        // Migration: rest_api_security.mode legacy value 'authenticated'
        // (UI bug shipped a <select> value that did not match the backend
        // string 'authenticated_only', so manual saves wrote a value the
        // module ignored). Normalise so the option is honoured again.
        if ( isset( $current_options['rest_api_security']['mode'] )
            && 'authenticated' === $current_options['rest_api_security']['mode'] ) {
            $current_options['rest_api_security']['mode'] = 'authenticated_only';
            $changed = true;
        }

        // Migration: rest_api_security.protected_endpoints used to default to
        // ['/wp/v2/users'], which duplicated the "Block user enumeration"
        // toggle and confused users (turning that toggle off didn't unblock
        // /users because protected_endpoints kept it locked in selective
        // mode). If the saved list is still the legacy single-element default,
        // empty it out so there is one knob per behaviour. Custom lists
        // (anything other than exactly ['/wp/v2/users']) are left untouched.
        if ( isset( $current_options['rest_api_security']['protected_endpoints'] )
            && is_array( $current_options['rest_api_security']['protected_endpoints'] )
            && array( '/wp/v2/users' ) === array_values( $current_options['rest_api_security']['protected_endpoints'] ) ) {
            $current_options['rest_api_security']['protected_endpoints'] = array();
            $changed = true;
        }

        // Migration: section-level 'enabled' flag wrongly stored as false.
        // Earlier 2.4.x betas had a UI save handler that treated the absence
        // of a field in the form as "checkbox unchecked" — including the
        // top-level 'enabled' master flag, which has no checkbox in any
        // section form. This left modules silently disabled even though the
        // Dashboard master toggle was on. Restore the flag where it makes
        // sense (master toggle on + flag false).
        $sections = array(
            'firewall',
            'security_headers',
            'login_security',
            'rest_api_security',
            'user_security',
            'wp_hardening',
            'file_integrity',
            'activity_log',
        );
        foreach ( $sections as $section_name ) {
            if ( ! empty( $current_options['modules'][ $section_name ] )
                && isset( $current_options[ $section_name ] )
                && is_array( $current_options[ $section_name ] )
                && array_key_exists( 'enabled', $current_options[ $section_name ] )
                && empty( $current_options[ $section_name ]['enabled'] ) ) {
                $current_options[ $section_name ]['enabled'] = true;
                $changed = true;
            }
        }

        if ( $changed ) {
            update_option( Vigilante_Settings::OPTION_NAME, $current_options );
        }

        return $changed;
    }

    /**
     * Check minimum requirements
     *
     * @return bool
     */
    private static function check_requirements() {
        // PHP version check
        if ( version_compare( PHP_VERSION, '7.4', '<' ) ) {
            add_action( 'admin_notices', function() {
                printf(
                    '<div class="notice notice-error"><p>%s</p></div>',
                    esc_html__( 'Vigilant requires PHP 7.4 or higher.', 'vigilante' )
                );
            });
            return false;
        }

        // WordPress version check
        global $wp_version;
        if ( version_compare( $wp_version, '5.0', '<' ) ) {
            add_action( 'admin_notices', function() {
                printf(
                    '<div class="notice notice-error"><p>%s</p></div>',
                    esc_html__( 'Vigilant requires WordPress 5.0 or higher.', 'vigilante' )
                );
            });
            return false;
        }

        return true;
    }

    /**
     * Create backup of important files
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    private static function create_activation_backup( $settings ) {
        require_once VIGILANTE_INCLUDES_DIR . 'class-backup-manager.php';
        
        $backup_manager = new Vigilante_Backup_Manager();
        $result = $backup_manager->create_backups();

        if ( is_wp_error( $result ) ) {
            // Store error for admin notice
            set_transient( 'vigilante_backup_error', $result->get_error_message(), 60 );
        }
    }

    /**
     * Apply htaccess protection
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    private static function apply_htaccess_protection( $settings ) {
        // Only apply if Apache server
        if ( ! self::is_apache() ) {
            return;
        }

        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-protection.php';
        
        $htaccess = new Vigilante_Htaccess_Protection( $settings );
        $htaccess->apply_rules();
    }

    /**
     * Apply security headers to htaccess
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    private static function apply_security_headers( $settings ) {
        // Only apply if Apache server
        if ( ! self::is_apache() ) {
            return;
        }

        require_once VIGILANTE_INCLUDES_DIR . 'class-security-headers.php';
        
        $security_headers = new Vigilante_Security_Headers( $settings );
        $security_headers->apply_rules();
    }

    /**
     * Apply wp-config security
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    private static function apply_wpconfig_security( $settings ) {
        require_once VIGILANTE_INCLUDES_DIR . 'class-wpconfig-security.php';
        
        $wpconfig = new Vigilante_Wpconfig_Security( $settings );
        $wpconfig->apply_security_constants();
    }

    /**
     * Enforce HTTPS in WordPress settings
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    private static function enforce_https( $settings ) {
        $options = $settings->get_section( 'security_headers' );

        if ( empty( $options['force_https'] ) ) {
            return;
        }

        // Check if already HTTPS
        $site_url = get_option( 'siteurl' );
        $home_url = get_option( 'home' );

        // Update to HTTPS if not already
        if ( strpos( $site_url, 'https://' ) === false ) {
            update_option( 'siteurl', str_replace( 'http://', 'https://', $site_url ) );
        }

        if ( strpos( $home_url, 'https://' ) === false ) {
            update_option( 'home', str_replace( 'http://', 'https://', $home_url ) );
        }
    }

    /**
     * Remove sensitive files from WordPress root
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    private static function remove_sensitive_files( $settings ) {
        $advanced = $settings->get_section( 'advanced' );

        // Remove readme.html
        if ( ! empty( $advanced['remove_readme'] ) ) {
            $readme_path = ABSPATH . 'readme.html';
            if ( file_exists( $readme_path ) ) {
                wp_delete_file( $readme_path );
            }
        }

        // Remove license.txt / licencia.txt (Spanish locale)
        if ( ! empty( $advanced['remove_license'] ) ) {
            $license_files = array( 'license.txt', 'licencia.txt' );
            foreach ( $license_files as $license_file ) {
                $license_path = ABSPATH . $license_file;
                if ( file_exists( $license_path ) ) {
                    wp_delete_file( $license_path );
                }
            }
        }
    }

    /**
     * Generate initial baseline hashes for critical config files
     *
     * Called once during activation, after Vigilante has written its own
     * blocks to wp-config.php and .htaccess. The baseline stores the
     * normalized hash (excluding Vigilante blocks) so that subsequent
     * scans can detect unauthorized external modifications.
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    private static function generate_critical_baseline( $settings ) {
        if ( ! class_exists( 'Vigilante_File_Integrity' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-file-integrity.php';
        }

        $database     = new Vigilante_Database();
        $activity_log = null; // Not needed for baseline generation

        $fi = new Vigilante_File_Integrity( $settings, $database, $activity_log );
        $fi->regenerate_all_baselines();
    }

    /**
     * Schedule cron events
     */
    private static function schedule_events() {
        // Daily maintenance
        if ( ! wp_next_scheduled( 'vigilante_daily_maintenance' ) ) {
            wp_schedule_event( time(), 'daily', 'vigilante_daily_maintenance' );
        }

        // Hourly checks
        if ( ! wp_next_scheduled( 'vigilante_hourly_checks' ) ) {
            wp_schedule_event( time(), 'hourly', 'vigilante_hourly_checks' );
        }

        // Weekly security analyzer scan
        if ( ! wp_next_scheduled( 'vigilante_analyzer_weekly_scan' ) ) {
            wp_schedule_event( time() + DAY_IN_SECONDS, 'weekly', 'vigilante_analyzer_weekly_scan' );
        }

        // Daily plugin status check (closed-in-wp.org detection)
        if ( ! wp_next_scheduled( 'vigilante_plugin_status_check' ) ) {
            wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'vigilante_plugin_status_check' );
        }
    }

    /**
     * Send activation notification email
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    private static function send_activation_email( $settings ) {
        $email_settings = $settings->get_section( 'email' );

        if ( empty( $email_settings['send_activation_email'] ) ) {
            return;
        }

        if ( ! class_exists( 'Vigilante_Email_Template' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-email-template.php';
        }

        $to = Vigilante_Email_Template::get_admin_recipients();

        $site_name = get_bloginfo( 'name' );
        $site_url = get_site_url();

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Vigilant Activated', 'vigilante' ),
            $site_name
        );

        $body  = Vigilante_Email_Template::p( __( 'Vigilant has been activated on your website. All security modules are now enabled with default settings.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::data_table( array(
            __( 'Site', 'vigilante' )   => $site_name,
            __( 'URL', 'vigilante' )    => $site_url,
            __( 'Date', 'vigilante' )   => wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ),
        ) );
        $body .= Vigilante_Email_Template::info_box( __( 'Please review the settings in your WordPress admin panel.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::button( admin_url( 'admin.php?page=vigilante' ), __( 'Go to Vigilant', 'vigilante' ) );

        Vigilante_Email_Template::send( $to, $subject, __( 'Plugin activated', 'vigilante' ), $body );
    }

    /**
     * Apply comment security settings to WordPress options
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    private static function apply_comment_security( $settings ) {
        $options = $settings->get_section( 'wp_hardening' );

        // Disable pingbacks
        if ( ! empty( $options['disable_pingbacks'] ) ) {
            update_option( 'default_pingback_flag', 0 );
            update_option( 'default_ping_status', 'closed' );
        }

        // Disable trackbacks
        if ( ! empty( $options['disable_trackbacks'] ) ) {
            update_option( 'default_ping_status', 'closed' );
        }

        // Require comment moderation
        if ( ! empty( $options['require_comment_moderation'] ) ) {
            update_option( 'comment_moderation', 1 );
        }
    }

    /**
     * Check if server is Apache
     *
     * @return bool
     */
    private static function is_apache() {
        if ( ! function_exists( 'apache_get_modules' ) ) {
            // Check server software
            $server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '';
            return stripos( $server, 'apache' ) !== false || stripos( $server, 'litespeed' ) !== false;
        }
        return true;
    }
}