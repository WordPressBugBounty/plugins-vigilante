<?php
/**
 * Plugin Name: Vigilant
 * Plugin URI: https://servicios.ayudawp.com
 * Description: Complete security solution for WordPress. Firewall, 2FA, security headers, login protection, file integrity monitoring, activity logging and more.
 * Version: 2.9.1
 * Author: Fernando Tellado
 * Author URI: https://ayudawp.com
 * Text Domain: vigilante
 * Requires at least: 6.2
 * Tested up to: 7.0
 * Requires PHP: 7.4
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Plugin constants
 */
define( 'VIGILANTE_VERSION', '2.9.1' );
define( 'VIGILANTE_PLUGIN_FILE', __FILE__ );
define( 'VIGILANTE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'VIGILANTE_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'VIGILANTE_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'VIGILANTE_INCLUDES_DIR', VIGILANTE_PLUGIN_DIR . 'includes/' );
define( 'VIGILANTE_ADMIN_DIR', VIGILANTE_PLUGIN_DIR . 'admin/' );
define( 'VIGILANTE_ASSETS_URL', VIGILANTE_PLUGIN_URL . 'assets/' );

// Backup directory outside plugin folder (persists through updates)
define( 'VIGILANTE_BACKUP_DIR', WP_CONTENT_DIR . '/vigilante-backups/' );

// Minimum requirements
define( 'VIGILANTE_MIN_PHP_VERSION', '7.4' );
define( 'VIGILANTE_MIN_WP_VERSION', '5.0' );

/**
 * Check minimum requirements before loading
 *
 * @return bool True if requirements are met
 */
function vigilante_check_requirements() {
    $meets_requirements = true;

    // Check PHP version
    if ( version_compare( PHP_VERSION, VIGILANTE_MIN_PHP_VERSION, '<' ) ) {
        $meets_requirements = false;
    }

    // Check WordPress version
    global $wp_version;
    if ( version_compare( $wp_version, VIGILANTE_MIN_WP_VERSION, '<' ) ) {
        $meets_requirements = false;
    }

    if ( ! $meets_requirements ) {
        add_action( 'admin_notices', 'vigilante_requirements_notice' );
    }

    return $meets_requirements;
}

/**
 * Display requirements notice - called at admin_notices (after init)
 */
function vigilante_requirements_notice() {
    global $wp_version;
    $errors = array();

    if ( version_compare( PHP_VERSION, VIGILANTE_MIN_PHP_VERSION, '<' ) ) {
        $errors[] = sprintf(
            /* translators: 1: Current PHP version, 2: Required PHP version */
            __( 'Vigilant requires PHP %2$s or higher. You are running PHP %1$s.', 'vigilante' ),
            PHP_VERSION,
            VIGILANTE_MIN_PHP_VERSION
        );
    }

    if ( version_compare( $wp_version, VIGILANTE_MIN_WP_VERSION, '<' ) ) {
        $errors[] = sprintf(
            /* translators: 1: Current WordPress version, 2: Required WordPress version */
            __( 'Vigilant requires WordPress %2$s or higher. You are running WordPress %1$s.', 'vigilante' ),
            $wp_version,
            VIGILANTE_MIN_WP_VERSION
        );
    }

    foreach ( $errors as $error ) {
        printf(
            '<div class="notice notice-error"><p>%s</p></div>',
            esc_html( $error )
        );
    }
}

/**
 * Load plugin files
 */
function vigilante_load_plugin() {
    // Check requirements first
    if ( ! vigilante_check_requirements() ) {
        return;
    }

    // Load core classes (no translations used in these)
    require_once VIGILANTE_INCLUDES_DIR . 'class-database.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-settings.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-ip-utils.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-backup-manager.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-activator.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-deactivator.php';

    // Load security module files (just loading, not initializing)
    require_once VIGILANTE_INCLUDES_DIR . 'class-firewall.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-security-headers.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-protection.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-wpconfig-security.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-https-enforcer.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-rest-api-security.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-user-security.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-login-security.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-two-factor-email.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-two-factor-totp.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-email-template.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-comment-security.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-head-cleaner.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-feed-manager.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-activity-log.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-audit-alerts.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-file-integrity.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-plugin-status.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-under-attack.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-database-backup.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-database-prefix.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-security-analyzer.php';

    // Load admin classes
    if ( is_admin() ) {
        require_once VIGILANTE_ADMIN_DIR . 'class-admin-analyzer-ajax.php';
        require_once VIGILANTE_ADMIN_DIR . 'class-admin-audit-alerts-ajax.php';
        require_once VIGILANTE_ADMIN_DIR . 'class-admin.php';
    }

    // Weekly Security Analyzer cron (registered even outside admin so it fires on cron hit).
    add_action( 'vigilante_analyzer_weekly_scan', 'vigilante_run_analyzer_cron' );

    // Daily plugin status check (closed-in-wp.org detection).
    add_action( 'vigilante_plugin_status_check', 'vigilante_run_plugin_status_check' );

    // Post-Under Attack scan (one-shot, scheduled by Vigilante_Under_Attack::deactivate).
    add_action( 'vigilante_under_attack_post_scan', 'vigilante_run_post_under_attack_scan' );

    // Initialize core components only - modules will be initialized at init
    add_action( 'init', 'vigilante_init_plugin', 1 );
}

/**
 * Initialize plugin at init hook (translations are ready)
 */
function vigilante_init_plugin() {
    Vigilante_Main::get_instance();
}

/**
 * Main plugin class - Singleton pattern
 */
final class Vigilante_Main {

    /**
     * Single instance of the class
     *
     * @var Vigilante_Main|null
     */
    private static $instance = null;

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    public $settings;

    /**
     * Database instance
     *
     * @var Vigilante_Database
     */
    public $database;

    /**
     * Activity log instance
     *
     * @var Vigilante_Activity_Log
     */
    public $activity_log;

    /**
     * Get single instance of the class
     *
     * @return Vigilante_Main
     */
    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor - private to enforce singleton
     */
    private function __construct() {
        $this->init_core();
        $this->init_modules();
        $this->init_hooks();
    }

    /**
     * Prevent cloning
     */
    private function __clone() {}

    /**
     * Prevent unserializing
     *
     * @throws Exception Always throws exception.
     */
    public function __wakeup() {
        throw new Exception( 'Cannot unserialize singleton' );
    }

    /**
     * Initialize core components
     */
    private function init_core() {
        $this->database     = new Vigilante_Database();
        $this->settings     = new Vigilante_Settings();
        $this->activity_log = new Vigilante_Activity_Log( $this->settings, $this->database );

        // Auto-create/update tables when DB version is outdated (handles file-only updates)
        if ( $this->database->needs_update() ) {
            $this->database->create_tables();
        }

        // One-time cleanup: versions before 2.7.0 wrote config backups (including
        // wp-config.php) as files under wp-content/vigilante-backups/. Those now
        // live in the database, so remove anything left on disk.
        if ( ! get_option( 'vigilante_legacy_backups_cleaned' ) ) {
            Vigilante_Backup_Manager::cleanup_legacy_files();
            update_option( 'vigilante_legacy_backups_cleaned', 1, false );
        }

        // One-time migration (2.9.0): add '.css' to File Integrity's excluded
        // extensions on existing installs. Stylesheets are rewritten so often by
        // themes and optimizer plugins that they were the main post-update false
        // positive. New installs get it from the defaults; this brings existing
        // sites in line without touching any other setting. Additive, idempotent.
        if ( ! get_option( 'vigilante_css_exclusion_migrated' ) ) {
            $fi = $this->settings->get_section( 'file_integrity' );
            if ( is_array( $fi ) ) {
                $ext = ( isset( $fi['excluded_extensions'] ) && is_array( $fi['excluded_extensions'] ) )
                    ? $fi['excluded_extensions']
                    : array();
                if ( ! in_array( '.css', $ext, true ) ) {
                    $ext[]                     = '.css';
                    $fi['excluded_extensions'] = $ext;
                    $this->settings->update_section( 'file_integrity', $fi );
                }
            }
            update_option( 'vigilante_css_exclusion_migrated', 1, false );
        }

        // One-time on upgrade to 2.9.0: drop any cached WordPress.org checksum
        // manifests. The new comparison is array-aware and self-corrects a cached
        // array-md5 value, but a manifest cached by an older version while wp.org
        // was still propagating a new release could otherwise keep producing
        // false "modified" results until it expires (up to 24h). Flushing on
        // upgrade guarantees a clean slate on the very release that fixes them;
        // the next scan refetches fresh manifests. One-time, bulk, no caching.
        if ( ! get_option( 'vigilante_checksum_cache_flushed_290' ) ) {
            global $wpdb;
            $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-time 2.9.0 migration dropping stale checksum transients so the new comparison starts clean.
                "DELETE FROM {$wpdb->options}
                WHERE option_name LIKE '\\_transient\\_vigilante\\_plugin\\_checksums\\_%'
                OR option_name LIKE '\\_transient\\_timeout\\_vigilante\\_plugin\\_checksums\\_%'
                OR option_name LIKE '\\_transient\\_vigilante\\_theme\\_checksums\\_%'
                OR option_name LIKE '\\_transient\\_timeout\\_vigilante\\_theme\\_checksums\\_%'
                OR option_name LIKE '\\_transient\\_vigilante\\_core\\_checksums\\_%'
                OR option_name LIKE '\\_transient\\_timeout\\_vigilante\\_core\\_checksums\\_%'"
            );
            update_option( 'vigilante_checksum_cache_flushed_290', 1, false );
        }
    }

    /**
     * Initialize security modules based on settings
     */
    private function init_modules() {
        $options = $this->settings->get_all_options();

        // Self-heal: a UI bug in earlier 2.4.x betas could leave a section's
        // top-level 'enabled' flag set to false because the section forms do
        // not render a checkbox for that field — saving any tab caused the
        // generic save handler to treat the missing field as "unchecked" and
        // store it as false. If the master module toggle on the Dashboard is
        // on but the section flag is off, restore it here so the module's
        // hooks can attach. Idempotent: noop on healthy installs.
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
        $heal_changed = false;
        foreach ( $sections as $section_name ) {
            if ( ! empty( $options['modules'][ $section_name ] )
                && isset( $options[ $section_name ] )
                && is_array( $options[ $section_name ] )
                && array_key_exists( 'enabled', $options[ $section_name ] )
                && empty( $options[ $section_name ]['enabled'] ) ) {
                $options[ $section_name ]['enabled'] = true;
                $heal_changed = true;
            }
        }
        if ( $heal_changed ) {
            update_option( Vigilante_Settings::OPTION_NAME, $options );
            $this->settings->clear_cache();
            $options = $this->settings->get_all_options();
        }

        // Firewall - runs early to block threats
        if ( ! empty( $options['modules']['firewall'] ) ) {
            new Vigilante_Firewall( $this->settings, $this->activity_log );
        }

        // Security Headers - rules are applied via .htaccess, no runtime hooks needed
        // HTTPS Enforcer still needs runtime hooks
        if ( ! empty( $options['modules']['security_headers'] ) ) {
            new Vigilante_Https_Enforcer( $this->settings );
        }

        // REST API Security
        if ( ! empty( $options['modules']['rest_api_security'] ) ) {
            new Vigilante_Rest_Api_Security( $this->settings );
        }

        // User Security
        if ( ! empty( $options['modules']['user_security'] ) ) {
            new Vigilante_User_Security( $this->settings, $this->activity_log );
        }

        // Login Security
        if ( ! empty( $options['modules']['login_security'] ) ) {
            $login_security = new Vigilante_Login_Security( $this->settings, $this->database, $this->activity_log );
            
            // Two-Factor Authentication (only if login security module is active)
            new Vigilante_Two_Factor_Email( $this->settings, $this->database, $this->activity_log, $login_security );
            new Vigilante_Two_Factor_TOTP( $this->settings, $this->database, $this->activity_log, $login_security );
        }

        // WordPress Hardening (includes comments, head cleaner, feeds)
        if ( ! empty( $options['modules']['wp_hardening'] ) ) {
            new Vigilante_Comment_Security( $this->settings );
            new Vigilante_Head_Cleaner( $this->settings );
            new Vigilante_Feed_Manager( $this->settings );
        }

        // File Integrity Scanner
        if ( ! empty( $options['modules']['file_integrity'] ) ) {
            new Vigilante_File_Integrity( $this->settings, $this->database, $this->activity_log );
            new Vigilante_Plugin_Status( $this->settings, $this->activity_log );
        }

        // Activity Log is always initialized (core component)
        // Logging is gated by the modules.activity_log toggle and per-type flags

        // Audit Alerts engine - an alerting layer on top of Security Audit.
        // Only instantiated when Security Audit is on, because it reacts to the
        // events the activity log records (a passive subscriber, no per-module
        // coupling). Both alert legs are opt-in, off by default.
        if ( ! empty( $options['modules']['activity_log'] ) ) {
            new Vigilante_Audit_Alerts( $this->settings, $this->activity_log );
        }

        // Under Attack mode - always loaded (independent of modules)
        new Vigilante_Under_Attack( $this->settings, $this->activity_log );

        // Admin interface
        if ( is_admin() ) {
            new Vigilante_Admin( $this->settings, $this->database, $this->activity_log );
        }
    }

    /**
     * Initialize WordPress hooks
     */
    private function init_hooks() {
        // Plugin action links
        add_filter( 'plugin_action_links_' . VIGILANTE_PLUGIN_BASENAME, array( $this, 'add_action_links' ) );

        // Scheduled tasks
        add_action( 'vigilante_daily_maintenance', array( $this, 'daily_maintenance' ) );
        add_action( 'vigilante_hourly_checks', array( $this, 'hourly_checks' ) );

        // AJAX handlers
        add_action( 'wp_ajax_vigilante_dismiss_notice', array( $this, 'ajax_dismiss_notice' ) );

        // Regenerate critical file baseline after Vigilante modifies wp-config.php or .htaccess
        add_action( 'vigilante_critical_file_written', array( $this, 'on_critical_file_written' ) );
    }

    /**
     * Update the critical file baseline after Vigilante writes to a monitored file
     *
     * @param string $filename File that was modified (e.g. 'wp-config.php').
     */
    public function on_critical_file_written( $filename ) {
        if ( ! class_exists( 'Vigilante_File_Integrity' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-file-integrity.php';
        }

        $fi = new Vigilante_File_Integrity( $this->settings, $this->database, $this->activity_log );
        $fi->update_critical_file_baseline( $filename );
    }

    /**
     * Add plugin action links
     *
     * @param array $links Existing links.
     * @return array Modified links.
     */
    public function add_action_links( $links ) {
        $plugin_links = array(
            '<a href="' . esc_url( admin_url( 'admin.php?page=vigilante' ) ) . '">' . esc_html__( 'Security Settings', 'vigilante' ) . '</a>',
        );
        return array_merge( $plugin_links, $links );
    }

    /**
     * Daily maintenance tasks
     */
    public function daily_maintenance() {
        // Clean old activity logs
        $this->activity_log->cleanup_old_logs();

        // Clean old login attempts
        $this->database->cleanup_old_login_attempts();

        // Clean expired 2FA codes and trusted devices
        $this->database->cleanup_expired_2fa_codes();
        $this->database->cleanup_expired_trusted_devices();

        // Remove sensitive files (readme.html, license.txt, licencia.txt)
        // WordPress core updates recreate these files, so we clean them daily
        $advanced = $this->settings->get_section( 'advanced' );
        if ( ! empty( $advanced['remove_readme'] ) ) {
            $readme_path = ABSPATH . 'readme.html';
            if ( file_exists( $readme_path ) ) {
                wp_delete_file( $readme_path );
            }
        }
        if ( ! empty( $advanced['remove_license'] ) ) {
            $license_files = array( 'license.txt', 'licencia.txt' );
            foreach ( $license_files as $license_file ) {
                $license_path = ABSPATH . $license_file;
                if ( file_exists( $license_path ) ) {
                    wp_delete_file( $license_path );
                }
            }
        }

        // Log maintenance
        $this->activity_log->log( 'system', 'maintenance', __( 'Daily maintenance completed', 'vigilante' ) );
    }

    /**
     * Hourly checks
     */
    public function hourly_checks() {
        // File integrity scans are handled by the File_Integrity class own cron schedule
        // based on the configured scan_frequency (daily/weekly).
    }

    /**
     * AJAX handler for dismissing notices
     */
    public function ajax_dismiss_notice() {
        check_ajax_referer( 'vigilante_dismiss_notice', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( -1 );
        }

        $notice_id = isset( $_POST['notice_id'] ) ? sanitize_key( $_POST['notice_id'] ) : '';

        if ( $notice_id ) {
            $dismissed = get_option( 'vigilante_dismissed_notices', array() );
            $dismissed[ $notice_id ] = time();
            update_option( 'vigilante_dismissed_notices', $dismissed );
        }

        wp_send_json_success();
    }
}

/**
 * Cron handler for the weekly Security Analyzer scan.
 *
 * Resolves the shared Vigilante_Security_Analyzer (lazily; no cost when the
 * cron is not firing) and lets it run the scan + regression email logic.
 */
function vigilante_run_analyzer_cron() {
    if ( ! class_exists( 'Vigilante_Security_Analyzer' ) ) {
        require_once VIGILANTE_INCLUDES_DIR . 'class-security-analyzer.php';
    }
    if ( ! class_exists( 'Vigilante_Settings' ) ) {
        require_once VIGILANTE_INCLUDES_DIR . 'class-settings.php';
    }

    $settings     = new Vigilante_Settings();
    $activity_log = null;
    if ( class_exists( 'Vigilante_Activity_Log' ) && class_exists( 'Vigilante_Database' ) ) {
        $database     = new Vigilante_Database();
        $activity_log = new Vigilante_Activity_Log( $settings, $database );
    }

    $analyzer = new Vigilante_Security_Analyzer( $settings, $activity_log );
    $analyzer->cron_weekly_scan();
}

/**
 * Cron handler for the daily plugin status check.
 *
 * Resolves the shared Vigilante_Plugin_Status lazily so the daily cron has no
 * cost while it is not firing.
 */
function vigilante_run_plugin_status_check() {
    if ( ! class_exists( 'Vigilante_Plugin_Status' ) ) {
        require_once VIGILANTE_INCLUDES_DIR . 'class-plugin-status.php';
    }
    if ( ! class_exists( 'Vigilante_Settings' ) ) {
        require_once VIGILANTE_INCLUDES_DIR . 'class-settings.php';
    }

    $settings     = new Vigilante_Settings();
    $activity_log = null;
    if ( class_exists( 'Vigilante_Activity_Log' ) && class_exists( 'Vigilante_Database' ) ) {
        $database     = new Vigilante_Database();
        $activity_log = new Vigilante_Activity_Log( $settings, $database );
    }

    $checker = new Vigilante_Plugin_Status( $settings, $activity_log );
    $checker->run_scheduled_check();
}

/**
 * Run a Security Analyzer full scan after Under Attack mode deactivates.
 *
 * Scheduled one-shot from Vigilante_Under_Attack::deactivate() so the dashboard
 * reflects the restored configuration with the slow HTTP/header probes the
 * mode prevented from running safely while it was active.
 */
function vigilante_run_post_under_attack_scan() {
    if ( ! class_exists( 'Vigilante_Under_Attack' ) ) {
        require_once VIGILANTE_INCLUDES_DIR . 'class-under-attack.php';
    }
    if ( ! class_exists( 'Vigilante_Settings' ) ) {
        require_once VIGILANTE_INCLUDES_DIR . 'class-settings.php';
    }

    $settings     = new Vigilante_Settings();
    $activity_log = null;
    if ( class_exists( 'Vigilante_Activity_Log' ) && class_exists( 'Vigilante_Database' ) ) {
        $database     = new Vigilante_Database();
        $activity_log = new Vigilante_Activity_Log( $settings, $database );
    }

    $under_attack = new Vigilante_Under_Attack( $settings, $activity_log );
    $under_attack->run_analyzer_scan( 'all' );
}

/**
 * Plugin activation hook
 */
function vigilante_activate() {
    require_once VIGILANTE_INCLUDES_DIR . 'class-database.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-settings.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-backup-manager.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-activator.php';

    Vigilante_Activator::activate();
}
register_activation_hook( __FILE__, 'vigilante_activate' );

/**
 * Plugin deactivation hook
 */
function vigilante_deactivate() {
    require_once VIGILANTE_INCLUDES_DIR . 'class-database.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-settings.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-backup-manager.php';
    require_once VIGILANTE_INCLUDES_DIR . 'class-deactivator.php';

    Vigilante_Deactivator::deactivate();
}
register_deactivation_hook( __FILE__, 'vigilante_deactivate' );

/**
 * Initialize plugin after WordPress loads
 */
add_action( 'plugins_loaded', 'vigilante_load_plugin' );

/**
 * Helper function to get plugin instance
 *
 * @return Vigilante_Main
 */
function vigilante() {
    return Vigilante_Main::get_instance();
}