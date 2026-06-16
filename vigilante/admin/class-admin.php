<?php
/**
 * Admin Class
 *
 * Handles admin interface and settings page
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Load AJAX trait
require_once VIGILANTE_ADMIN_DIR . 'class-admin-ajax.php';

// Load promotional banner class
require_once VIGILANTE_INCLUDES_DIR . 'class-ayudawp-promo-banner.php';

/**
 * Class Vigilante_Admin
 *
 * Manages the admin settings interface
 */
class Vigilante_Admin {

    use Vigilante_Admin_Ajax;
    use Vigilante_Admin_Analyzer_Ajax;

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Database instance
     *
     * @var Vigilante_Database
     */
    private $database;

    /**
     * Activity log instance
     *
     * @var Vigilante_Activity_Log
     */
    private $activity_log;

    /**
     * Current tab
     *
     * @var string
     */
    private $current_tab = 'dashboard';

    /**
     * Available tabs
     *
     * @var array
     */
    private $tabs = array();

    /**
     * Constructor
     *
     * @param Vigilante_Settings     $settings     Settings instance.
     * @param Vigilante_Database     $database     Database instance.
     * @param Vigilante_Activity_Log $activity_log Activity log instance.
     */
    public function __construct( $settings, $database, $activity_log ) {
        $this->settings     = $settings;
        $this->database     = $database;
        $this->activity_log = $activity_log;

        $this->setup_tabs();
        $this->init_hooks();
    }

    /**
     * Setup available tabs
     */
    private function setup_tabs() {
        $this->tabs = array(
            'dashboard'      => __( 'Dashboard', 'vigilante' ),
            'firewall'       => __( 'Firewall', 'vigilante' ),
            'headers'        => __( 'Security Headers', 'vigilante' ),
            'login'          => __( 'Login Security', 'vigilante' ),
            'rest-api'       => __( 'REST API', 'vigilante' ),
            'users'          => __( 'User Security', 'vigilante' ),
            'wp-hardening'   => __( 'WP Hardening', 'vigilante' ),
            'file-integrity' => __( 'File Integrity', 'vigilante' ),
            'activity-log'   => __( 'Security Audit', 'vigilante' ),
            'tools'          => __( 'Settings & Tools', 'vigilante' ),
        );
    }

    /**
     * Initialize hooks
     */
    private function init_hooks() {
        add_action( 'admin_menu', array( $this, 'add_menu' ) );
        add_action( 'admin_init', array( $this, 'redirect_submenu_shortcuts' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
        add_action( 'admin_notices', array( $this, 'show_admin_notices' ) );

        // Highlight correct submenu based on active tab
        add_filter( 'submenu_file', array( $this, 'highlight_submenu_tab' ) );

        // Set browser tab title to show plugin name and active tab
        add_filter( 'admin_title', array( $this, 'set_admin_page_title' ), 10, 2 );

        // AJAX handlers
        add_action( 'wp_ajax_vigilante_save_settings', array( $this, 'ajax_save_settings' ) );
        add_action( 'wp_ajax_vigilante_apply_preset', array( $this, 'ajax_apply_preset' ) );
        add_action( 'wp_ajax_vigilante_reset_section', array( $this, 'ajax_reset_section' ) );
        add_action( 'wp_ajax_vigilante_clear_lockouts', array( $this, 'ajax_clear_lockouts' ) );
        add_action( 'wp_ajax_vigilante_clear_logs', array( $this, 'ajax_clear_logs' ) );
        add_action( 'wp_ajax_vigilante_run_scan', array( $this, 'ajax_run_scan' ) );
        add_action( 'wp_ajax_vigilante_clear_scan', array( $this, 'ajax_clear_scan' ) );
        add_action( 'wp_ajax_vigilante_ignore_file', array( $this, 'ajax_ignore_file' ) );
        add_action( 'wp_ajax_vigilante_unignore_file', array( $this, 'ajax_unignore_file' ) );
        add_action( 'wp_ajax_vigilante_bulk_ignore_files', array( $this, 'ajax_bulk_ignore_files' ) );
        add_action( 'wp_ajax_vigilante_bulk_unignore_files', array( $this, 'ajax_bulk_unignore_files' ) );
        add_action( 'wp_ajax_vigilante_clear_ignored', array( $this, 'ajax_clear_ignored' ) );
        add_action( 'wp_ajax_vigilante_ignore_closed_plugin', array( $this, 'ajax_ignore_closed_plugin' ) );
        add_action( 'wp_ajax_vigilante_unignore_closed_plugin', array( $this, 'ajax_unignore_closed_plugin' ) );
        add_action( 'wp_ajax_vigilante_clear_ignored_closed_plugins', array( $this, 'ajax_clear_ignored_closed_plugins' ) );
        add_action( 'wp_ajax_vigilante_approve_critical_file', array( $this, 'ajax_approve_critical_file' ) );
        add_action( 'wp_ajax_vigilante_export_settings', array( $this, 'ajax_export_settings' ) );
        add_action( 'wp_ajax_vigilante_import_settings', array( $this, 'ajax_import_settings' ) );
        add_action( 'wp_ajax_vigilante_get_logs', array( $this, 'ajax_get_logs' ) );
        add_action( 'wp_ajax_vigilante_test_headers', array( $this, 'ajax_test_headers' ) );
        add_action( 'wp_ajax_vigilante_create_backup', array( $this, 'ajax_create_backup' ) );
        
        // 2FA AJAX handlers
        add_action( 'wp_ajax_vigilante_search_users_2fa', array( $this, 'ajax_search_users_2fa' ) );
        add_action( 'wp_ajax_vigilante_send_2fa_notification', array( $this, 'ajax_send_2fa_notification' ) );
        add_action( 'wp_ajax_vigilante_search_totp_users', array( $this, 'ajax_search_totp_users' ) );
        add_action( 'wp_ajax_vigilante_reset_totp_users', array( $this, 'ajax_reset_totp_users' ) );
        add_action( 'wp_ajax_vigilante_totp_get_setup', array( $this, 'ajax_totp_get_setup' ) );
        add_action( 'wp_ajax_vigilante_notify_login_url', array( $this, 'ajax_notify_login_url' ) );

        // Password Reset AJAX handlers
        add_action( 'wp_ajax_vigilante_search_users_password_reset', array( $this, 'ajax_search_users_password_reset' ) );
        add_action( 'wp_ajax_vigilante_force_password_reset', array( $this, 'ajax_force_password_reset' ) );
        add_action( 'wp_ajax_vigilante_force_password_reset_all', array( $this, 'ajax_force_password_reset_all' ) );
        add_action( 'wp_ajax_vigilante_force_password_reset_by_role', array( $this, 'ajax_force_password_reset_by_role' ) );

        // User approval AJAX handlers
        add_action( 'wp_ajax_vigilante_approve_user', array( $this, 'ajax_approve_user' ) );
        add_action( 'wp_ajax_vigilante_reject_user', array( $this, 'ajax_reject_user' ) );

        // Session management AJAX handlers
        add_action( 'wp_ajax_vigilante_get_user_sessions', array( $this, 'ajax_get_user_sessions' ) );
        add_action( 'wp_ajax_vigilante_revoke_session', array( $this, 'ajax_revoke_session' ) );
        add_action( 'wp_ajax_vigilante_revoke_all_sessions', array( $this, 'ajax_revoke_all_sessions' ) );

        // Under Attack mode AJAX handlers
        add_action( 'wp_ajax_vigilante_activate_under_attack', array( $this, 'ajax_activate_under_attack' ) );
        add_action( 'wp_ajax_vigilante_deactivate_under_attack', array( $this, 'ajax_deactivate_under_attack' ) );
        add_action( 'wp_ajax_vigilante_under_attack_status', array( $this, 'ajax_under_attack_status' ) );

        // Database backup AJAX handlers
        add_action( 'wp_ajax_vigilante_get_db_tables', array( $this, 'ajax_get_db_tables' ) );
        add_action( 'wp_ajax_vigilante_download_db_backup', array( $this, 'ajax_download_db_backup' ) );

        // Database prefix AJAX handlers
        add_action( 'wp_ajax_vigilante_generate_prefix', array( $this, 'ajax_generate_prefix' ) );
        add_action( 'wp_ajax_vigilante_change_prefix', array( $this, 'ajax_change_prefix' ) );

        // Firewall list management from activity log popup
        add_action( 'wp_ajax_vigilante_add_to_firewall_list', array( $this, 'ajax_add_to_firewall_list' ) );
        add_action( 'wp_ajax_vigilante_unblock_firewall_ip', array( $this, 'ajax_unblock_firewall_ip' ) );

        // Security Analyzer AJAX handlers (v2.1.0)
        add_action( 'wp_ajax_vigilante_analyzer_run', array( $this, 'ajax_analyzer_run' ) );
        add_action( 'wp_ajax_vigilante_analyzer_history', array( $this, 'ajax_analyzer_history' ) );
        add_action( 'wp_ajax_vigilante_analyzer_dismiss_notice', array( $this, 'ajax_analyzer_dismiss_notice' ) );
        add_action( 'wp_ajax_vigilante_analyzer_save_settings', array( $this, 'ajax_analyzer_save_settings' ) );

        // Run migrations on admin load
        add_action( 'admin_init', array( $this, 'run_migrations' ) );
    }

    /**
     * Run database migrations based on stored version
     */
    public function run_migrations() {
        $db_version = get_option( 'vigilante_db_version', '0' );

        // 1.2.3: Fix IP lists corrupted by sanitize_text_field stripping newlines
        if ( version_compare( $db_version, '1.2.3', '<' ) ) {
            $this->migrate_fix_ip_lists();
            update_option( 'vigilante_db_version', '1.2.3' );
        }

        // 1.3.0: Add request_method column to activity log table
        if ( version_compare( $db_version, '1.3.0', '<' ) ) {
            $this->database->run_migrations();
        }

        // 1.9.0: Re-apply wp-config constants (performance constants removed from managed list)
        if ( version_compare( $db_version, '1.9.0', '<' ) ) {
            if ( $this->settings->is_module_enabled( 'wp_hardening' ) ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-wpconfig-security.php';
                $wpconfig = new Vigilante_Wpconfig_Security( $this->settings );
                $wpconfig->apply_security_constants();
            }
            update_option( 'vigilante_db_version', '1.9.0' );
        }

        // 1.10.0: Clean up orphaned email fields (centralized notification recipients)
        if ( version_compare( $db_version, '1.10.0', '<' ) ) {
            $this->migrate_cleanup_email_fields();
            update_option( 'vigilante_db_version', '1.10.0' );
        }

        // 1.11.0: Remove stale 'enabled' key from activity_log settings
        // + Convert additional_recipients from string to array
        if ( version_compare( $db_version, '1.11.0', '<' ) ) {
            $options = get_option( Vigilante_Settings::OPTION_NAME, array() );
            $changed = false;

            if ( isset( $options['activity_log']['enabled'] ) ) {
                unset( $options['activity_log']['enabled'] );
                $changed = true;
            }

            // Convert corrupted string to array for additional_recipients
            if ( isset( $options['email']['additional_recipients'] ) && is_string( $options['email']['additional_recipients'] ) ) {
                $raw = trim( $options['email']['additional_recipients'] );
                if ( ! empty( $raw ) ) {
                    $emails = array_filter( array_map( 'trim', preg_split( '/[\r\n,; ]+/', $raw ) ) );
                    $options['email']['additional_recipients'] = array_values( array_filter( $emails, 'is_email' ) );
                } else {
                    $options['email']['additional_recipients'] = array();
                }
                $changed = true;
            }

            if ( $changed ) {
                update_option( Vigilante_Settings::OPTION_NAME, $options );
            }
            update_option( 'vigilante_db_version', '1.11.0' );
        }

        // 1.12.1: Regenerate htaccess (WooCommerce IPN exclusion in bot blocking rule)
        if ( version_compare( $db_version, '1.12.1', '<' ) ) {
            if ( ! empty( $this->settings->get_section( 'firewall' )['block_bad_bots'] ) ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-protection.php';
                $htaccess = new Vigilante_Htaccess_Protection( $this->settings );
                $htaccess->apply_rules();
            }
            update_option( 'vigilante_db_version', '1.12.1' );
        }

        // 1.14.0: Generate critical config files baseline (wp-config.php, .htaccess)
        if ( version_compare( $db_version, '1.14.0', '<' ) ) {
            if ( ! class_exists( 'Vigilante_File_Integrity' ) ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-file-integrity.php';
            }
            $fi = new Vigilante_File_Integrity( $this->settings, $this->database, $this->activity_log );
            $fi->regenerate_all_baselines();
            update_option( 'vigilante_db_version', '1.14.0' );
        }

        // 2.0.0: Move hide_server_signature and remove_fingerprinting_headers
        // from firewall section to security_headers section
        if ( version_compare( $db_version, '2.0.0', '<' ) ) {
            $options = get_option( Vigilante_Settings::OPTION_NAME, array() );
            $changed = false;

            foreach ( array( 'hide_server_signature', 'remove_fingerprinting_headers' ) as $key ) {
                if ( isset( $options['firewall'][ $key ] ) ) {
                    if ( ! isset( $options['security_headers'][ $key ] ) ) {
                        $options['security_headers'][ $key ] = $options['firewall'][ $key ];
                    }
                    unset( $options['firewall'][ $key ] );
                    $changed = true;
                }
            }

            if ( $changed ) {
                update_option( Vigilante_Settings::OPTION_NAME, $options );
            }
            update_option( 'vigilante_db_version', '2.0.0' );
        }

        // 2.6.1: Two things happen here.
        //
        // 1. Re-apply wp-config constants so the block is rewritten with
        //    "if ( ! defined() )" guards around every define(). Without guards,
        //    non-standard setups that pre-define WordPress constants outside
        //    wp-config.php (custom bootstraps that load constants from .env or
        //    similar) hit a fatal "Constant already defined" when wp-config.php
        //    is parsed and reaches our block.
        //
        // 2. Drop the cached Security Check report. The cached "max" per
        //    category was frozen at scan time; with the internal category
        //    bumping from 22 to 28 points (closed_plugins added in 2.6.0),
        //    the cached report would keep displaying 22/22 until the next
        //    full scan. Clearing it forces a fresh scan with the new caps.
        if ( version_compare( $db_version, '2.6.1', '<' ) ) {
            if ( $this->settings->is_module_enabled( 'wp_hardening' ) ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-wpconfig-security.php';
                $wpconfig = new Vigilante_Wpconfig_Security( $this->settings );
                $wpconfig->apply_security_constants();
            }
            delete_option( 'vigilante_analyzer_last_scan' );

            // Schedule an immediate background scan so the dashboard widget
            // doesn't display "Last scan: never" right after the upgrade.
            // Reuses the same hook the post-Under-Attack flow uses.
            if ( ! wp_next_scheduled( 'vigilante_under_attack_post_scan' ) ) {
                wp_schedule_single_event( time() + 5, 'vigilante_under_attack_post_scan' );
            }

            update_option( 'vigilante_db_version', '2.6.1' );
        }
    }

    /**
     * Migration: Remove orphaned email fields from saved options
     *
     * v1.10.0 centralized notification recipients into email section.
     * Old per-module notify_email fields and dead email section fields
     * are removed to avoid confusion.
     */
    private function migrate_cleanup_email_fields() {
        $options = get_option( Vigilante_Settings::OPTION_NAME, array() );
        $modified = false;

        // Remove orphaned fields from email section
        $dead_email_keys = array( 'enabled', 'from_name', 'from_email', 'admin_email', 'send_activation_email', 'custom_email' );
        if ( isset( $options['email'] ) && is_array( $options['email'] ) ) {
            foreach ( $dead_email_keys as $key ) {
                if ( array_key_exists( $key, $options['email'] ) ) {
                    unset( $options['email'][ $key ] );
                    $modified = true;
                }
            }
            // Ensure new fields exist with defaults
            if ( ! array_key_exists( 'send_to_admin_email', $options['email'] ) ) {
                $options['email']['send_to_admin_email'] = true;
                $modified = true;
            }
            if ( ! array_key_exists( 'additional_recipients', $options['email'] ) ) {
                $options['email']['additional_recipients'] = '';
                $modified = true;
            }
        }

        // Remove notify_email from login_security
        if ( isset( $options['login_security']['notify_email'] ) ) {
            unset( $options['login_security']['notify_email'] );
            $modified = true;
        }

        // Remove notify_email from file_integrity
        if ( isset( $options['file_integrity']['notify_email'] ) ) {
            unset( $options['file_integrity']['notify_email'] );
            $modified = true;
        }

        if ( $modified ) {
            update_option( Vigilante_Settings::OPTION_NAME, $options );
            // Clear settings cache so the plugin uses clean data immediately
            $this->settings->clear_cache();
        }
    }

    /**
     * Migration: Fix IP whitelist/blacklist entries merged into single line
     *
     * Prior to 1.2.3, sanitize_text_field() stripped newlines from textarea data,
     * causing multiple IPs to be stored as a single space-separated string.
     */
    private function migrate_fix_ip_lists() {
        $options = get_option( Vigilante_Settings::OPTION_NAME, array() );
        $fixed   = false;

        foreach ( array( 'ip_whitelist', 'ip_blacklist' ) as $key ) {
            if ( ! empty( $options['firewall'][ $key ] ) && is_array( $options['firewall'][ $key ] ) ) {
                $new_list = array();
                foreach ( $options['firewall'][ $key ] as $entry ) {
                    // Split entries that were joined by spaces
                    $parts = preg_split( '/\s+/', trim( $entry ) );
                    foreach ( $parts as $part ) {
                        $part = trim( $part );
                        if ( '' !== $part ) {
                            $new_list[] = $part;
                        }
                    }
                }
                if ( count( $new_list ) !== count( $options['firewall'][ $key ] ) ) {
                    $options['firewall'][ $key ] = array_unique( $new_list );
                    $fixed = true;
                }
            }
        }

        if ( $fixed ) {
            update_option( Vigilante_Settings::OPTION_NAME, $options );
            // Clear settings cache so changes take effect immediately
            $this->settings->clear_cache();
        }
    }

    /**
     * Add admin menu page in last position
     */
    public function add_menu() {
        $menu_title = __( 'Vigilant', 'vigilante' );
        
        // Count pending approvals (separate concern, always red if present)
        $pending_count = $this->get_pending_approvals_count();
        
        // Get security issues with severity
        $security_status = $this->get_security_status_for_badge();
        
        // Total count for badge
        $total_badge = $pending_count + $security_status['count'];
        
        if ( $total_badge > 0 ) {
            // Determine badge color:
            // - Red (awaiting-mod): pending approvals OR critical modules disabled
            // - Orange (update-plugins): only non-critical modules disabled
            if ( $pending_count > 0 || $security_status['has_critical'] ) {
                $badge_class = 'awaiting-mod';
            } else {
                $badge_class = 'update-plugins vigilante-badge-warning';
            }
            
            $menu_title .= sprintf(
                ' <span class="%s count-%d"><span class="pending-count">%d</span></span>',
                esc_attr( $badge_class ),
                $total_badge,
                $total_badge
            );
        }

        add_menu_page(
            __( 'Vigilant', 'vigilante' ),
            $menu_title,
            'manage_options',
            'vigilante',
            array( $this, 'render_settings_page' ),
            'dashicons-shield',
            999
        );

        // Rename auto-generated first submenu to "Dashboard"
        add_submenu_page(
            'vigilante',
            __( 'Dashboard', 'vigilante' ),
            __( 'Dashboard', 'vigilante' ),
            'manage_options',
            'vigilante',
            array( $this, 'render_settings_page' )
        );

        // Security Audit shortcut
        add_submenu_page(
            'vigilante',
            __( 'Security Audit', 'vigilante' ),
            __( 'Security Audit', 'vigilante' ),
            'manage_options',
            'vigilante-activity-log',
            array( $this, 'redirect_to_tab' )
        );

        // File Integrity shortcut
        add_submenu_page(
            'vigilante',
            __( 'File Integrity', 'vigilante' ),
            __( 'File Integrity', 'vigilante' ),
            'manage_options',
            'vigilante-file-integrity',
            array( $this, 'redirect_to_tab' )
        );
    }

    /**
     * Redirect submenu shortcuts early, before headers are sent
     */
    public function redirect_submenu_shortcuts() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Just reading page slug for redirect
        $page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : '';

        $tab_map = array(
            'vigilante-activity-log'   => 'activity-log',
            'vigilante-file-integrity' => 'file-integrity',
        );

        if ( isset( $tab_map[ $page ] ) ) {
            wp_safe_redirect( admin_url( 'admin.php?page=vigilante&tab=' . $tab_map[ $page ] ) );
            exit;
        }
    }

    /**
     * Fallback redirect for submenu shortcuts (JS-based)
     */
    public function redirect_to_tab() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Just reading page slug for redirect
        $page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : '';

        $tab_map = array(
            'vigilante-activity-log'   => 'activity-log',
            'vigilante-file-integrity' => 'file-integrity',
        );

        if ( isset( $tab_map[ $page ] ) ) {
            $url = admin_url( 'admin.php?page=vigilante&tab=' . $tab_map[ $page ] );
            echo '<script>window.location.replace(' . wp_json_encode( esc_url( $url ) ) . ');</script>';
        }
    }

    /**
     * Highlight the correct submenu item based on active tab
     *
     * @param string $submenu_file Current submenu file.
     * @return string
     */
    public function highlight_submenu_tab( $submenu_file ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading tab for menu highlight only
        $page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $tab  = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : '';

        if ( 'vigilante' !== $page || empty( $tab ) ) {
            return $submenu_file;
        }

        $tab_to_submenu = array(
            'activity-log'   => 'vigilante-activity-log',
            'file-integrity' => 'vigilante-file-integrity',
        );

        if ( isset( $tab_to_submenu[ $tab ] ) ) {
            return $tab_to_submenu[ $tab ];
        }

        return $submenu_file;
    }

    /**
     * Set browser tab title to show plugin name and active tab
     *
     * Changes "Dashboard ‹ Site Name — WordPress" to
     * "Vigilant > Dashboard ‹ Site Name — WordPress"
     *
     * @param string $admin_title Full admin title.
     * @param string $title       Page title from add_menu_page/add_submenu_page.
     * @return string Modified title.
     */
    public function set_admin_page_title( $admin_title, $title ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading page slug for title only
        $page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : '';

        // Only modify on Vigilante pages
        if ( 0 !== strpos( $page, 'vigilante' ) ) {
            return $admin_title;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'dashboard';

        if ( isset( $this->tabs[ $tab ] ) ) {
            $tab_label = $this->tabs[ $tab ];
        } else {
            $tab_label = __( 'Dashboard', 'vigilante' );
        }

        $plugin_title = __( 'Vigilant', 'vigilante' ) . ' &rsaquo; ' . $tab_label;

        // Replace the original page title portion
        return str_replace( $title, $plugin_title, $admin_title );
    }

    /**
     * Get count of users pending approval
     *
     * @return int Count of pending users.
     */
    private function get_pending_approvals_count() {
        // Prevent early execution before WordPress is ready
        if ( ! did_action( 'plugins_loaded' ) ) {
            return 0;
        }
        
        $registration_approval = $this->settings->get_section( 'user_security' );
        $approval_settings = $registration_approval['registration_approval'] ?? array();
        
        if ( empty( $approval_settings['enabled'] ) ) {
            return 0;
        }

        // phpcs:disable WordPress.DB.SlowDBQuery.slow_db_query_meta_key, WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- Limited results in admin context.
        $pending_users = get_users( array(
            'meta_key'   => 'vigilante_pending_approval',
            'meta_value' => '1',
            'fields'     => 'ID',
        ) );
        // phpcs:enable WordPress.DB.SlowDBQuery.slow_db_query_meta_key, WordPress.DB.SlowDBQuery.slow_db_query_meta_value

        return count( $pending_users );
    }

    /**
     * Calculate comprehensive security score (0-100)
     *
     * @param array $options Plugin options.
     * @return int Security score.
     */
    private function calculate_security_score( $options ) {
        $score = 0;
        $max_score = 0;

        // Module scores (60 points total)
        $module_weights = array(
            'firewall'          => 10,
            'security_headers'  => 8,
            'login_security'    => 10,
            'rest_api_security' => 6,
            'user_security'     => 8,
            'wp_hardening'      => 8,
            'file_integrity'    => 5,
            'activity_log'      => 5,
        );

        foreach ( $module_weights as $module => $weight ) {
            $max_score += $weight;
            if ( ! empty( $options['modules'][ $module ] ) ) {
                $score += $weight;
            }
        }

        // Firewall details (10 points)
        if ( ! empty( $options['modules']['firewall'] ) ) {
            $firewall = $options['firewall'] ?? array();
            $max_score += 10;
            
            $firewall_checks = array(
                'block_sql_injection',
                'block_xss_attacks',
                'block_bad_query_strings',
                'block_file_inclusion',
                'block_directory_traversal',
            );
            
            $firewall_enabled = 0;
            foreach ( $firewall_checks as $check ) {
                if ( ! empty( $firewall[ $check ] ) ) {
                    $firewall_enabled++;
                }
            }
            $score += min( 10, $firewall_enabled * 2 );
        }

        // Login security details (10 points)
        if ( ! empty( $options['modules']['login_security'] ) ) {
            $login = $options['login_security'] ?? array();
            $max_score += 10;
            
            // Max attempts configured
            if ( isset( $login['max_attempts'] ) && $login['max_attempts'] <= 5 ) {
                $score += 3;
            }
            // XML-RPC disabled
            if ( ! empty( $login['disable_xmlrpc'] ) ) {
                $score += 3;
            }
            // 2FA enabled
            if ( ! empty( $login['two_factor']['enabled'] ) ) {
                $score += 4;
            }
        }

        // Security headers details (10 points)
        if ( ! empty( $options['modules']['security_headers'] ) ) {
            $headers = $options['security_headers'] ?? array();
            $max_score += 10;
            
            if ( ! empty( $headers['x_frame_options'] ) ) {
                $score += 2;
            }
            if ( ! empty( $headers['x_content_type_options'] ) ) {
                $score += 2;
            }
            if ( ! empty( $headers['hsts']['enabled'] ) ) {
                $score += 3;
            }
            if ( ! empty( $headers['csp']['enabled'] ) ) {
                $score += 3;
            }
        }

        // User security details (10 points)
        if ( ! empty( $options['modules']['user_security'] ) ) {
            $user = $options['user_security'] ?? array();
            $max_score += 10;
            
            if ( ! empty( $user['block_insecure_usernames'] ) ) {
                $score += 3;
            }
            if ( ! empty( $user['force_strong_passwords'] ) ) {
                $score += 3;
            }
            if ( ! empty( $user['password_expiration']['enabled'] ) ) {
                $score += 2;
            }
            if ( ! empty( $user['email_verification']['enabled'] ) ) {
                $score += 2;
            }
        }

        // Environment checks (8 points) - penalize insecure server configuration
        $max_score += 8;
        $env_score = 8;

        // WP_DEBUG active in production is a security risk (exposes paths, errors)
        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            $env_score -= 5;
        }

        // Accounts with insecure usernames (targeted by brute force attacks)
        $insecure_admins = $this->get_insecure_admin_usernames();
        if ( ! empty( $insecure_admins ) ) {
            $env_score -= 3;
        }

        $score += max( 0, $env_score );

        return $max_score > 0 ? round( ( $score / $max_score ) * 100 ) : 0;
    }

    /**
     * Get security recommendations based on current settings
     *
     * @param array $options Plugin options.
     * @return array Array of recommendations.
     */
    private function get_security_recommendations( $options ) {
        $recommendations = array();

        // Critical: Firewall disabled
        if ( empty( $options['modules']['firewall'] ) ) {
            $recommendations[] = array(
                'icon'     => 'warning',
                'priority' => 'critical',
                'message'  => __( 'Enable Firewall to protect against common attacks.', 'vigilante' ),
            );
        }

        // Critical: Login security disabled
        if ( empty( $options['modules']['login_security'] ) ) {
            $recommendations[] = array(
                'icon'     => 'warning',
                'priority' => 'critical',
                'message'  => __( 'Enable Login Security to prevent brute force attacks.', 'vigilante' ),
            );
        }

        // High: Security headers disabled
        if ( empty( $options['modules']['security_headers'] ) ) {
            $recommendations[] = array(
                'icon'     => 'admin-generic',
                'priority' => 'high',
                'message'  => __( 'Enable Security Headers to protect against clickjacking and XSS.', 'vigilante' ),
            );
        }

        // High: User security disabled
        if ( empty( $options['modules']['user_security'] ) ) {
            $recommendations[] = array(
                'icon'     => 'admin-users',
                'priority' => 'high',
                'message'  => __( 'Enable User Security to enforce password policies and username protection.', 'vigilante' ),
            );
        }

        // High: 2FA not enabled (only if login security is active)
        $login = $options['login_security'] ?? array();
        if ( ! empty( $options['modules']['login_security'] ) && empty( $login['two_factor']['enabled'] ) ) {
            $recommendations[] = array(
                'icon'     => 'shield',
                'priority' => 'high',
                'message'  => __( 'Enable Two-Factor Authentication for enhanced login security.', 'vigilante' ),
                'tab'      => 'login',
            );
        }

        // Medium: REST API security disabled
        if ( empty( $options['modules']['rest_api_security'] ) ) {
            $recommendations[] = array(
                'icon'     => 'rest-api',
                'priority' => 'medium',
                'message'  => __( 'Enable REST API Security to control API access and prevent enumeration.', 'vigilante' ),
            );
        }

        // Medium: WP Hardening disabled
        if ( empty( $options['modules']['wp_hardening'] ) ) {
            $recommendations[] = array(
                'icon'     => 'lock',
                'priority' => 'medium',
                'message'  => __( 'Enable WP Hardening to remove version info and protect core files.', 'vigilante' ),
            );
        }

        // Medium: File integrity disabled
        if ( empty( $options['modules']['file_integrity'] ) ) {
            $recommendations[] = array(
                'icon'     => 'media-text',
                'priority' => 'medium',
                'message'  => __( 'Enable File Integrity to detect unauthorized file changes.', 'vigilante' ),
            );
        }

        // Medium: Security Audit disabled
        if ( empty( $options['modules']['activity_log'] ) ) {
            $recommendations[] = array(
                'icon'     => 'list-view',
                'priority' => 'medium',
                'message'  => __( 'Enable Security Audit to track security events.', 'vigilante' ),
            );
        }

        // Low: XML-RPC enabled (only if login security is active)
        if ( ! empty( $options['modules']['login_security'] ) && empty( $login['disable_xmlrpc'] ) ) {
            $recommendations[] = array(
                'icon'     => 'info',
                'priority' => 'low',
                'message'  => __( 'Disable XML-RPC if not needed (reduces attack surface).', 'vigilante' ),
                'tab'      => 'login',
            );
        }

        // Low: Strong passwords not enforced (only if user security is active)
        $user = $options['user_security'] ?? array();
        if ( ! empty( $options['modules']['user_security'] ) && empty( $user['force_strong_passwords'] ) ) {
            $recommendations[] = array(
                'icon'     => 'admin-users',
                'priority' => 'low',
                'message'  => __( 'Enforce strong passwords for all users.', 'vigilante' ),
                'tab'      => 'users',
            );
        }

        // High: WP_DEBUG active in production (regardless of Vigilante settings)
        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            $recommendations[] = array(
                'icon'     => 'warning',
                'priority' => 'high',
                'message'  => __( 'WP_DEBUG is active. Debug mode exposes sensitive information and should be disabled in production.', 'vigilante' ),
                'tab'      => 'wp-hardening',
            );
        }

        // Low: Users with display name matching login username (only if user security active)
        if ( ! empty( $options['modules']['user_security'] ) ) {
            $exposed_users = $this->get_users_with_exposed_login();
            if ( ! empty( $exposed_users ) ) {
                $recommendations[] = array(
                    'icon'     => 'admin-users',
                    'priority' => 'low',
                    'message'  => sprintf(
                        /* translators: %s: Comma-separated list of usernames */
                        __( 'These users have their login username as display name (publicly visible): %s', 'vigilante' ),
                        implode( ', ', $exposed_users )
                    ),
                    'tab'      => 'users',
                );
            }
        }

        // High: Accounts with insecure usernames (regardless of module status)
        $insecure_admins = $this->get_insecure_admin_usernames();
        if ( ! empty( $insecure_admins ) ) {
            $recommendations[] = array(
                'icon'     => 'warning',
                'priority' => 'high',
                'message'  => sprintf(
                    /* translators: %s: Comma-separated list of usernames */
                    __( 'Insecure usernames detected: %s. These are commonly targeted in brute force attacks. Create new accounts with unique usernames and remove these.', 'vigilante' ),
                    implode( ', ', $insecure_admins )
                ),
            );
        }

        // Critical: Closed or removed plugins detected by the daily check.
        // Reads from the cached state map populated by Vigilante_Plugin_Status, so
        // there is no extra HTTP call here. Ignored slugs are filtered out so the
        // recommendation respects the user's per-slug Ignore decisions.
        if ( ! empty( $options['modules']['file_integrity'] ) && ! empty( $options['file_integrity']['check_closed_plugins'] ) ) {
            if ( ! class_exists( 'Vigilante_Plugin_Status' ) ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-plugin-status.php';
            }
            $closed_checker = new Vigilante_Plugin_Status( $this->settings, $this->activity_log );
            $closed_active  = $closed_checker->get_closed_plugins();
            if ( ! empty( $closed_active ) ) {
                $names = array();
                foreach ( $closed_active as $slug => $entry ) {
                    $names[] = isset( $entry['name'] ) ? $entry['name'] : $slug;
                }
                $recommendations[] = array(
                    'icon'     => 'warning',
                    'priority' => 'critical',
                    'message'  => sprintf(
                        /* translators: 1: count, 2: comma-separated plugin names */
                        _n(
                            '%1$d closed plugin detected on this site: %2$s. Closures in WordPress.org usually indicate malware, security issues or supply chain compromises. Uninstall and replace as soon as possible.',
                            '%1$d closed plugins detected on this site: %2$s. Closures in WordPress.org usually indicate malware, security issues or supply chain compromises. Uninstall and replace as soon as possible.',
                            count( $closed_active ),
                            'vigilante'
                        ),
                        count( $closed_active ),
                        implode( ', ', $names )
                    ),
                    'tab'      => 'file-integrity',
                );
            }
        }

        // Sort by priority
        $priority_order = array( 'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3 );
        usort( $recommendations, function( $a, $b ) use ( $priority_order ) {
            return ( $priority_order[ $a['priority'] ] ?? 99 ) - ( $priority_order[ $b['priority'] ] ?? 99 );
        } );

        return $recommendations;
    }

    /**
     * Get users whose display name matches their login username
     *
     * Limited to administrators and editors for performance and relevance.
     * Cached with transient to avoid repeated queries on every dashboard load.
     *
     * @return array Array of usernames with exposed login.
     */
    private function get_users_with_exposed_login() {
        $cache_key = 'vigilante_exposed_display_names';
        $cached = get_transient( $cache_key );

        if ( false !== $cached ) {
            return $cached;
        }

        $exposed = array();
        $users = get_users( array(
            'role__in' => array( 'administrator', 'editor' ),
            'fields'   => array( 'ID', 'user_login', 'display_name' ),
        ) );

        foreach ( $users as $user ) {
            if ( strcasecmp( $user->display_name, $user->user_login ) === 0 ) {
                $exposed[] = $user->user_login;
            }
        }

        // Cache for 12 hours
        set_transient( $cache_key, $exposed, 12 * HOUR_IN_SECONDS );

        return $exposed;
    }

    /**
     * Get accounts with insecure usernames
     *
     * Checks for common default usernames that are targeted by brute force attacks.
     * Detects any user regardless of role (consistent with username creation blocking).
     * Uses WordPress object cache via get_user_by() so no transient needed.
     *
     * @return array Array of insecure usernames found.
     */
    private function get_insecure_admin_usernames() {
        $priority_usernames = array( 'admin', 'administrator', 'root', 'test', 'user', 'guest', 'info', 'sysadmin', 'webmaster' );
        $found = array();

        foreach ( $priority_usernames as $username ) {
            $user = get_user_by( 'login', $username );
            if ( $user ) {
                $found[] = $username;
            }
        }

        return $found;
    }

    /**
     * Get security status for menu badge
     * 
     * Returns count of disabled modules and whether there are critical issues.
     * Critical = Firewall or Login Security disabled.
     *
     * @return array Array with 'count' and 'has_critical'.
     */
    public function get_security_status_for_badge() {
        $options = $this->settings->get_all_options();
        $modules = $options['modules'] ?? array();
        
        // Count disabled modules
        $disabled_count = 0;
        $has_critical = false;
        
        // Critical modules - if disabled, badge is red
        $critical_modules = array( 'firewall', 'login_security' );
        
        foreach ( $modules as $module => $enabled ) {
            // Handle both boolean and string values ('1', '0', true, false)
            $is_enabled = filter_var( $enabled, FILTER_VALIDATE_BOOLEAN );
            
            if ( ! $is_enabled ) {
                $disabled_count++;
                
                // Check if this is a critical module
                if ( in_array( $module, $critical_modules, true ) ) {
                    $has_critical = true;
                }
            }
        }
        
        return array(
            'count'        => $disabled_count,
            'has_critical' => $has_critical,
        );
    }

    /**
     * Get count of security issues for menu badge (deprecated, use get_security_status_for_badge)
     *
     * @return int Count of critical/high issues.
     */
    public function get_security_issues_count() {
        $status = $this->get_security_status_for_badge();
        return $status['count'];
    }

    /**
     * Register settings
     */
    public function register_settings() {
        register_setting(
            'vigilante_options',
            Vigilante_Settings::OPTION_NAME,
            array( $this->settings, 'validate_options' )
        );
    }

    /**
     * Build the settings search index
     *
     * Flat list of searchable entries consumed by the client-side search.
     * Each entry contains tab + section metadata, a translated label and an
     * English fallback so locales with partial translation still match.
     *
     * @return array
     */
    private function get_search_index() {
        return array(
            // Firewall - Main
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Firewall Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-main', 'label' => __( 'Block bad bots', 'vigilante' ), 'label_en' => 'Block bad bots', 'keywords' => 'bots robots malos bloquear bad block crawlers arañas scrapers' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Firewall Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-main', 'label' => __( 'Block malicious requests', 'vigilante' ), 'label_en' => 'Block malicious requests', 'keywords' => 'malicioso maliciosas peticiones ataques sqli xss rfi lfi ataque exploit injection inyección' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Firewall Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-main', 'label' => __( 'Rate limiting', 'vigilante' ), 'label_en' => 'Rate limiting', 'keywords' => 'limitar tasa velocidad throttle peticiones minuto abuso flood' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Firewall Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-main', 'label' => __( 'Brute force protection', 'vigilante' ), 'label_en' => 'Brute force protection', 'keywords' => 'fuerza bruta brute force contraseñas ataque login diccionario' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Firewall Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-main', 'label' => __( 'IP Whitelist', 'vigilante' ), 'label_en' => 'IP Whitelist', 'keywords' => 'lista blanca permitida permitidas whitelist allowlist ip direcciones permitir' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Firewall Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-main', 'label' => __( 'IP Blacklist', 'vigilante' ), 'label_en' => 'IP Blacklist', 'keywords' => 'lista negra bloqueada bloqueadas blacklist blocklist denylist ip direcciones bloquear' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Firewall Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-main', 'label' => __( 'User-Agent Whitelist', 'vigilante' ), 'label_en' => 'User-Agent Whitelist', 'keywords' => 'ua user agent agente usuario navegador lista blanca permitida whitelist allowlist' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Firewall Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-main', 'label' => __( 'User-Agent Blacklist', 'vigilante' ), 'label_en' => 'User-Agent Blacklist', 'keywords' => 'ua user agent agente usuario navegador lista negra bloqueada blacklist blocklist denylist' ),
            // Firewall - Server Protection
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Server Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-server', 'label' => __( 'Directory Browsing', 'vigilante' ), 'label_en' => 'Directory Browsing', 'keywords' => 'directorio navegación listado listing indexing indexado carpetas' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Server Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-server', 'label' => __( 'Protect wp-config.php', 'vigilante' ), 'label_en' => 'Protect wp-config.php', 'keywords' => 'proteger wp-config configuración config archivo' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Server Protection', 'vigilante' ), 'anchor' => 'field-protect-wp-cron', 'label' => __( 'Protect wp-cron.php', 'vigilante' ), 'label_en' => 'Protect wp-cron.php', 'keywords' => 'proteger wp-cron cron tareas programadas scheduled tasks bloquear block dos abuse spam htaccess' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Server Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-server', 'label' => __( 'Protect wp-includes', 'vigilante' ), 'label_en' => 'Protect wp-includes', 'keywords' => 'proteger wp-includes includes core núcleo archivos' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Server Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-server', 'label' => __( 'PHP in Uploads', 'vigilante' ), 'label_en' => 'PHP in Uploads', 'keywords' => 'php uploads subidas archivos bloquear ejecución' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Server Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-server', 'label' => __( 'Sensitive Files', 'vigilante' ), 'label_en' => 'Sensitive Files', 'keywords' => 'sensibles sensitive files archivos readme license htaccess log' ),
            array( 'tab' => 'firewall', 'tab_label' => __( 'Firewall', 'vigilante' ), 'section' => __( 'Server Protection', 'vigilante' ), 'anchor' => 'vigilante-section-firewall-server', 'label' => __( 'Limit HTTP Methods', 'vigilante' ), 'label_en' => 'Limit HTTP Methods', 'keywords' => 'métodos http limit limitar trace options put delete verbs verbos' ),
            // Security Headers
            array( 'tab' => 'headers', 'tab_label' => __( 'Security Headers', 'vigilante' ), 'section' => __( 'Security Headers', 'vigilante' ), 'anchor' => 'vigilante-section-headers-main', 'label' => __( 'X-Frame-Options', 'vigilante' ), 'label_en' => 'X-Frame-Options', 'keywords' => 'xframe clickjacking iframe cabeceras headers' ),
            array( 'tab' => 'headers', 'tab_label' => __( 'Security Headers', 'vigilante' ), 'section' => __( 'Security Headers', 'vigilante' ), 'anchor' => 'vigilante-section-headers-main', 'label' => __( 'X-Content-Type-Options', 'vigilante' ), 'label_en' => 'X-Content-Type-Options', 'keywords' => 'mime sniffing nosniff content type cabeceras headers' ),
            array( 'tab' => 'headers', 'tab_label' => __( 'Security Headers', 'vigilante' ), 'section' => __( 'Security Headers', 'vigilante' ), 'anchor' => 'vigilante-section-headers-main', 'label' => __( 'Referrer-Policy', 'vigilante' ), 'label_en' => 'Referrer-Policy', 'keywords' => 'referer referrer política privacidad cabeceras headers' ),
            array( 'tab' => 'headers', 'tab_label' => __( 'Security Headers', 'vigilante' ), 'section' => __( 'HSTS', 'vigilante' ), 'anchor' => 'vigilante-section-headers-main', 'label' => __( 'HSTS', 'vigilante' ), 'label_en' => 'HSTS', 'keywords' => 'strict transport security ssl tls https forzar cabeceras headers' ),
            array( 'tab' => 'headers', 'tab_label' => __( 'Security Headers', 'vigilante' ), 'section' => __( 'Content Security Policy', 'vigilante' ), 'anchor' => 'vigilante-section-headers-main', 'label' => __( 'Content Security Policy', 'vigilante' ), 'label_en' => 'Content Security Policy', 'keywords' => 'csp política seguridad contenido xss scripts inline eval cabeceras headers' ),
            array( 'tab' => 'headers', 'tab_label' => __( 'Security Headers', 'vigilante' ), 'section' => __( 'Server Identity', 'vigilante' ), 'anchor' => 'vigilante-section-headers-main', 'label' => __( 'Server Signature', 'vigilante' ), 'label_en' => 'Server Signature', 'keywords' => 'firma servidor server signature identidad apache nginx ocultar hide fingerprint protección servidor' ),
            array( 'tab' => 'headers', 'tab_label' => __( 'Security Headers', 'vigilante' ), 'section' => __( 'Server Identity', 'vigilante' ), 'anchor' => 'vigilante-section-headers-main', 'label' => __( 'Remove Fingerprinting Headers', 'vigilante' ), 'label_en' => 'Remove Fingerprinting Headers', 'keywords' => 'fingerprint huella identificación cabeceras headers x-powered-by server ocultar eliminar protección servidor' ),
            // Login Security
            array( 'tab' => 'login', 'tab_label' => __( 'Login Security', 'vigilante' ), 'section' => __( 'Login Protection', 'vigilante' ), 'anchor' => 'vigilante-section-login-main', 'label' => __( 'Custom login URL', 'vigilante' ), 'label_en' => 'Custom login URL', 'keywords' => 'url personalizada login acceso entrar wp-login wp-admin slug ocultar esconder' ),
            array( 'tab' => 'login', 'tab_label' => __( 'Login Security', 'vigilante' ), 'section' => __( 'Login Protection', 'vigilante' ), 'anchor' => 'vigilante-section-login-main', 'label' => __( 'Two-Factor Authentication', 'vigilante' ), 'label_en' => 'Two-Factor Authentication', 'keywords' => '2fa doble factor autenticación totp google authenticator mfa' ),
            array( 'tab' => 'login', 'tab_label' => __( 'Login Security', 'vigilante' ), 'section' => __( 'Login Protection', 'vigilante' ), 'anchor' => 'vigilante-section-login-main', 'label' => __( '2FA', 'vigilante' ), 'label_en' => '2FA', 'keywords' => '2fa doble factor autenticación totp google authenticator mfa two factor' ),
            array( 'tab' => 'login', 'tab_label' => __( 'Login Security', 'vigilante' ), 'section' => __( 'Login Protection', 'vigilante' ), 'anchor' => 'vigilante-section-login-main', 'label' => __( 'Failed login attempts', 'vigilante' ), 'label_en' => 'Failed login attempts', 'keywords' => 'intentos fallidos login acceso failed attempts bloqueo bloqueos contraseña errónea' ),
            array( 'tab' => 'login', 'tab_label' => __( 'Login Security', 'vigilante' ), 'section' => __( 'Login Protection', 'vigilante' ), 'anchor' => 'vigilante-section-login-main', 'label' => __( 'Lockout', 'vigilante' ), 'label_en' => 'Lockout', 'keywords' => 'bloqueo bloqueado lockout baneo ban duración login' ),
            // REST API
            array( 'tab' => 'rest-api', 'tab_label' => __( 'REST API', 'vigilante' ), 'section' => __( 'REST API Security', 'vigilante' ), 'anchor' => 'vigilante-section-rest-api-main', 'label' => __( 'Access Mode', 'vigilante' ), 'label_en' => 'Access Mode', 'keywords' => 'modo acceso rest api público privado autenticado' ),
            array( 'tab' => 'rest-api', 'tab_label' => __( 'REST API', 'vigilante' ), 'section' => __( 'REST API Security', 'vigilante' ), 'anchor' => 'vigilante-section-rest-api-main', 'label' => __( 'Block User Enumeration', 'vigilante' ), 'label_en' => 'Block User Enumeration', 'keywords' => 'enumeración usuarios users block bloquear autores author slug ?author' ),
            array( 'tab' => 'rest-api', 'tab_label' => __( 'REST API', 'vigilante' ), 'section' => __( 'REST API Security', 'vigilante' ), 'anchor' => 'vigilante-section-rest-api-main', 'label' => __( 'Disable JSONP', 'vigilante' ), 'label_en' => 'Disable JSONP', 'keywords' => 'jsonp desactivar deshabilitar disable callback' ),
            // User Security
            array( 'tab' => 'users', 'tab_label' => __( 'User Security', 'vigilante' ), 'section' => __( 'Username & password protection', 'vigilante' ), 'anchor' => 'vigilante-section-users-password', 'label' => __( 'Username protection', 'vigilante' ), 'label_en' => 'Username protection', 'keywords' => 'nombre usuario username admin reservado prohibido protección' ),
            array( 'tab' => 'users', 'tab_label' => __( 'User Security', 'vigilante' ), 'section' => __( 'Username & password protection', 'vigilante' ), 'anchor' => 'vigilante-section-users-password', 'label' => __( 'Password strength', 'vigilante' ), 'label_en' => 'Password strength', 'keywords' => 'fortaleza fuerza contraseña password débil fuerte complejidad requisitos' ),
            array( 'tab' => 'users', 'tab_label' => __( 'User Security', 'vigilante' ), 'section' => __( 'Admin monitoring', 'vigilante' ), 'anchor' => 'vigilante-section-users-admin-monitoring', 'label' => __( 'Admin monitoring', 'vigilante' ), 'label_en' => 'Admin monitoring', 'keywords' => 'monitorización administradores admin supervisión alertas cambios' ),
            array( 'tab' => 'users', 'tab_label' => __( 'User Security', 'vigilante' ), 'section' => __( 'Registration approval', 'vigilante' ), 'anchor' => 'vigilante-section-users-registration', 'label' => __( 'Registration approval', 'vigilante' ), 'label_en' => 'Registration approval', 'keywords' => 'aprobación registro registration moderación nuevos usuarios signup' ),
            array( 'tab' => 'users', 'tab_label' => __( 'User Security', 'vigilante' ), 'section' => __( 'Session limits', 'vigilante' ), 'anchor' => 'vigilante-section-users-sessions', 'label' => __( 'Session limits', 'vigilante' ), 'label_en' => 'Session limits', 'keywords' => 'sesiones limits límite concurrentes sessions simultáneas' ),
            array( 'tab' => 'users', 'tab_label' => __( 'User Security', 'vigilante' ), 'section' => __( 'Password expiration', 'vigilante' ), 'anchor' => 'vigilante-section-users-password-exp', 'label' => __( 'Password expiration', 'vigilante' ), 'label_en' => 'Password expiration', 'keywords' => 'expiración caducidad contraseña password cambiar renovar rotación' ),
            array( 'tab' => 'users', 'tab_label' => __( 'User Security', 'vigilante' ), 'section' => __( 'Email verification', 'vigilante' ), 'anchor' => 'vigilante-section-users-email-verify', 'label' => __( 'Email verification', 'vigilante' ), 'label_en' => 'Email verification', 'keywords' => 'verificación correo email confirmación validación' ),
            // WP Hardening
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'Database Hardening', 'vigilante' ), 'anchor' => 'vigilante-section-hardening-database', 'label' => __( 'Database Hardening', 'vigilante' ), 'label_en' => 'Database Hardening', 'keywords' => 'base datos database db mysql fortalecer hardening endurecer' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'Database Hardening', 'vigilante' ), 'anchor' => 'vigilante-section-hardening-database', 'label' => __( 'Database prefix', 'vigilante' ), 'label_en' => 'Database prefix', 'keywords' => 'prefijo base datos database db mysql tabla tablas wp_ cambiar renombrar' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'wp-config.php Security', 'vigilante' ), 'anchor' => 'vigilante-section-hardening-wpconfig', 'label' => __( 'Disable file editing', 'vigilante' ), 'label_en' => 'Disable file editing', 'keywords' => 'desactivar deshabilitar disable edición editor archivos file edit disallow' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'wp-config.php Security', 'vigilante' ), 'anchor' => 'vigilante-section-hardening-wpconfig', 'label' => __( 'Disable plugin/theme installation', 'vigilante' ), 'label_en' => 'Disable plugin/theme installation', 'keywords' => 'desactivar deshabilitar disable instalación plugins temas themes install disallow' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'wp-config.php Security', 'vigilante' ), 'anchor' => 'vigilante-section-hardening-wpconfig', 'label' => __( 'Force SSL admin', 'vigilante' ), 'label_en' => 'Force SSL admin', 'keywords' => 'forzar ssl tls https admin administración certificado' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'wp-config.php Security', 'vigilante' ), 'anchor' => 'field-disable-wp-cron', 'label' => __( 'Disable WP Cron', 'vigilante' ), 'label_en' => 'Disable WP Cron', 'keywords' => 'desactivar deshabilitar disable wp cron tareas programadas scheduled real server crontab pseudo' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'Comment Security', 'vigilante' ), 'anchor' => 'vigilante-section-hardening-comments', 'label' => __( 'Comment Security', 'vigilante' ), 'label_en' => 'Comment Security', 'keywords' => 'comentarios comments spam protección honeypot autores url' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'Header Cleanup', 'vigilante' ), 'anchor' => 'vigilante-section-hardening-headers', 'label' => __( 'Header Cleanup', 'vigilante' ), 'label_en' => 'Header Cleanup', 'keywords' => 'limpieza cabeceras headers meta tags wordpress generator rsd wlwmanifest' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'Header Cleanup', 'vigilante' ), 'anchor' => 'vigilante-section-hardening-headers', 'label' => __( 'Remove WordPress version', 'vigilante' ), 'label_en' => 'Remove WordPress version', 'keywords' => 'eliminar quitar versión wordpress wp generator meta ocultar hide' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'Header Cleanup', 'vigilante' ), 'anchor' => 'field-remove-wp-version-assets', 'label' => __( 'Remove version from assets', 'vigilante' ), 'label_en' => 'Remove version from assets', 'keywords' => 'eliminar quitar versión wordpress wp ver query string assets recursos urls scripts styles css js cache busting' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'Header Cleanup', 'vigilante' ), 'anchor' => 'vigilante-section-hardening-headers', 'label' => __( 'Disable XML-RPC', 'vigilante' ), 'label_en' => 'Disable XML-RPC', 'keywords' => 'xmlrpc xml-rpc desactivar deshabilitar disable pingback trackback' ),
            array( 'tab' => 'wp-hardening', 'tab_label' => __( 'WP Hardening', 'vigilante' ), 'section' => __( 'RSS Feed Settings', 'vigilante' ), 'anchor' => 'vigilante-section-hardening-rss', 'label' => __( 'RSS Feed Settings', 'vigilante' ), 'label_en' => 'RSS Feed Settings', 'keywords' => 'rss feed sindicación feeds ajustes configuración' ),
            // File Integrity
            array( 'tab' => 'file-integrity', 'tab_label' => __( 'File Integrity', 'vigilante' ), 'section' => __( 'File Integrity Monitoring', 'vigilante' ), 'anchor' => 'vigilante-section-fi-monitoring', 'label' => __( 'File Integrity Monitoring', 'vigilante' ), 'label_en' => 'File Integrity Monitoring', 'keywords' => 'integridad archivos monitorización supervisión hash checksum malware cambios' ),
            array( 'tab' => 'file-integrity', 'tab_label' => __( 'File Integrity', 'vigilante' ), 'section' => __( 'File Integrity Monitoring', 'vigilante' ), 'anchor' => 'vigilante-section-fi-monitoring', 'label' => __( 'Scan schedule', 'vigilante' ), 'label_en' => 'Scan schedule', 'keywords' => 'escaneo escáner programación planificación horario frecuencia cron' ),
            array( 'tab' => 'file-integrity', 'tab_label' => __( 'File Integrity', 'vigilante' ), 'section' => __( 'File Integrity Monitoring', 'vigilante' ), 'anchor' => 'vigilante-section-fi-monitoring', 'label' => __( 'Instant alert', 'vigilante' ), 'label_en' => 'Instant alert', 'keywords' => 'alerta instantánea inmediata notificación aviso email tiempo real' ),
            array( 'tab' => 'file-integrity', 'tab_label' => __( 'File Integrity', 'vigilante' ), 'section' => __( 'Ignored Files', 'vigilante' ), 'anchor' => 'vigilante-section-fi-ignored', 'label' => __( 'Ignored Files', 'vigilante' ), 'label_en' => 'Ignored Files', 'keywords' => 'ignorados ignorar excluir exclusiones archivos ignored exclude' ),
            // Security Audit
            array( 'tab' => 'activity-log', 'tab_label' => __( 'Security Audit', 'vigilante' ), 'section' => __( 'Security Audit Settings', 'vigilante' ), 'anchor' => 'vigilante-section-audit-settings', 'label' => __( 'Retention', 'vigilante' ), 'label_en' => 'Retention', 'keywords' => 'retención días log registro conservación purga auditoría' ),
            array( 'tab' => 'activity-log', 'tab_label' => __( 'Security Audit', 'vigilante' ), 'section' => __( 'Security Audit Settings', 'vigilante' ), 'anchor' => 'vigilante-section-audit-settings', 'label' => __( 'Events to Log', 'vigilante' ), 'label_en' => 'Events to Log', 'keywords' => 'eventos log registro auditoría registrar capturar' ),
            array( 'tab' => 'activity-log', 'tab_label' => __( 'Security Audit', 'vigilante' ), 'section' => __( 'Security Audit Settings', 'vigilante' ), 'anchor' => 'vigilante-section-audit-settings', 'label' => __( 'Option Tracking', 'vigilante' ), 'label_en' => 'Option Tracking', 'keywords' => 'opciones seguimiento rastreo cambios ajustes options tracking' ),
            array( 'tab' => 'activity-log', 'tab_label' => __( 'Security Audit', 'vigilante' ), 'section' => __( 'Security Audit Settings', 'vigilante' ), 'anchor' => 'vigilante-section-audit-settings', 'label' => __( 'Exclusions', 'vigilante' ), 'label_en' => 'Exclusions', 'keywords' => 'exclusiones excluir ignorar usuarios roles ip filtros' ),
            array( 'tab' => 'activity-log', 'tab_label' => __( 'Security Audit', 'vigilante' ), 'section' => __( 'Recent Activity', 'vigilante' ), 'anchor' => 'vigilante-section-audit-recent', 'label' => __( 'Recent Activity', 'vigilante' ), 'label_en' => 'Recent Activity', 'keywords' => 'actividad reciente log registro eventos últimos historial' ),
            // Settings & Tools
            array( 'tab' => 'tools', 'tab_label' => __( 'Settings & Tools', 'vigilante' ), 'section' => __( 'Notification settings', 'vigilante' ), 'anchor' => 'vigilante-section-tools-notifications', 'label' => __( 'Notification settings', 'vigilante' ), 'label_en' => 'Notification settings', 'keywords' => 'notificaciones ajustes settings email correo avisos alertas' ),
            array( 'tab' => 'tools', 'tab_label' => __( 'Settings & Tools', 'vigilante' ), 'section' => __( 'Notification settings', 'vigilante' ), 'anchor' => 'vigilante-section-tools-notifications', 'label' => __( 'Additional Recipients', 'vigilante' ), 'label_en' => 'Additional Recipients', 'keywords' => 'destinatarios adicionales correo email cc copia recipients' ),
            array( 'tab' => 'tools', 'tab_label' => __( 'Settings & Tools', 'vigilante' ), 'section' => __( 'Tools', 'vigilante' ), 'anchor' => 'vigilante-section-tools-main', 'label' => __( 'Export Settings', 'vigilante' ), 'label_en' => 'Export Settings', 'keywords' => 'exportar export ajustes configuración settings json' ),
            array( 'tab' => 'tools', 'tab_label' => __( 'Settings & Tools', 'vigilante' ), 'section' => __( 'Tools', 'vigilante' ), 'anchor' => 'vigilante-section-tools-main', 'label' => __( 'Import Settings', 'vigilante' ), 'label_en' => 'Import Settings', 'keywords' => 'importar import ajustes configuración settings json' ),
            array( 'tab' => 'tools', 'tab_label' => __( 'Settings & Tools', 'vigilante' ), 'section' => __( 'Tools', 'vigilante' ), 'anchor' => 'vigilante-section-tools-main', 'label' => __( 'Reset to Defaults', 'vigilante' ), 'label_en' => 'Reset to Defaults', 'keywords' => 'restablecer resetear reset defaults predeterminados valores originales fábrica' ),
            array( 'tab' => 'tools', 'tab_label' => __( 'Settings & Tools', 'vigilante' ), 'section' => __( 'Tools', 'vigilante' ), 'anchor' => 'vigilante-section-tools-main', 'label' => __( 'Create Backup', 'vigilante' ), 'label_en' => 'Create Backup', 'keywords' => 'copia seguridad backup crear generar respaldo' ),
            array( 'tab' => 'tools', 'tab_label' => __( 'Settings & Tools', 'vigilante' ), 'section' => __( 'Tools', 'vigilante' ), 'anchor' => 'vigilante-section-tools-main', 'label' => __( 'Database Backup', 'vigilante' ), 'label_en' => 'Database Backup', 'keywords' => 'base datos database db mysql copia seguridad backup respaldo tablas exportar' ),
        );
    }

    /**
     * Enqueue admin assets
     *
     * @param string $hook Current admin page.
     */
    public function enqueue_assets( $hook ) {
        // toplevel_page_vigilante for top-level menu page
        if ( 'toplevel_page_vigilante' !== $hook ) {
            return;
        }

        // Load thickbox for plugin install modals.
        add_thickbox();

        wp_enqueue_style(
            'vigilante-admin',
            VIGILANTE_ASSETS_URL . 'css/admin.css',
            array(),
            VIGILANTE_VERSION
        );

        wp_enqueue_script(
            'vigilante-admin',
            VIGILANTE_ASSETS_URL . 'js/admin.js',
            array( 'jquery' ),
            VIGILANTE_VERSION,
            true
        );

        wp_localize_script( 'vigilante-admin', 'vigilanteAdmin', array(
            'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
            'nonce'         => wp_create_nonce( 'vigilante_admin_nonce' ),
            'currentUserId' => get_current_user_id(),
            'logoutUrl'     => wp_logout_url( wp_login_url() ),
            'adminUrl'      => admin_url( 'admin.php?page=vigilante' ),
            'searchIndex'   => $this->get_search_index(),
            'underAttack'   => array(
                'active'    => ( new Vigilante_Under_Attack( $this->settings, $this->activity_log ) )->is_active(),
                'remaining' => ( new Vigilante_Under_Attack( $this->settings, $this->activity_log ) )->get_remaining_time(),
            ),
            'strings'       => array(
                'saving'              => __( 'Saving...', 'vigilante' ),
                'saved'               => __( 'Settings saved', 'vigilante' ),
                'error'               => __( 'Error saving settings', 'vigilante' ),
                'confirm'             => __( 'Are you sure?', 'vigilante' ),
                'scanning'            => __( 'Scanning...', 'vigilante' ),
                'scanComplete'        => __( 'Scan complete', 'vigilante' ),
                'loading'             => __( 'Loading...', 'vigilante' ),
                'searching'           => __( 'Searching...', 'vigilante' ),
                'noUsersFound'        => __( 'No users found', 'vigilante' ),
                'searchError'         => __( 'Error searching users', 'vigilante' ),
                'sending'             => __( 'Sending...', 'vigilante' ),
                'sendNotification'    => __( 'Send notification now', 'vigilante' ),
                'notificationsSent'   => __( 'notifications sent', 'vigilante' ),
                'skipped'             => __( 'skipped', 'vigilante' ),
                'failed'              => __( 'failed', 'vigilante' ),
                'customConfig'        => __( 'Custom Configuration', 'vigilante' ),
                // Header tester strings
                'testHeaders'         => __( 'Test Headers', 'vigilante' ),
                'testing'             => __( 'Testing...', 'vigilante' ),
                'score'               => __( 'Score', 'vigilante' ),
                'enabledHeaders'      => __( 'Enabled headers', 'vigilante' ),
                'missingHeaders'      => __( 'Missing headers', 'vigilante' ),
                'warnings'            => __( 'Warnings', 'vigilante' ),
                // File integrity scan results strings
                'scanResults'         => __( 'Scan Results', 'vigilante' ),
                'ok'                  => __( 'OK', 'vigilante' ),
                'modified'            => __( 'Modified', 'vigilante' ),
                'suspicious'          => __( 'Suspicious', 'vigilante' ),
                'totalScanned'        => __( 'Total Scanned', 'vigilante' ),
                'suspiciousFiles'     => __( 'Suspicious Files', 'vigilante' ),
                'suspiciousWarning'   => __( 'These files may contain malicious code or are in unexpected locations. Review immediately!', 'vigilante' ),
                'file'                => __( 'File', 'vigilante' ),
                'reason'              => __( 'Reason', 'vigilante' ),
                'type'                => __( 'Type', 'vigilante' ),
                'unknown'             => __( 'Unknown', 'vigilante' ),
                'modifiedFiles'       => __( 'Modified Files', 'vigilante' ),
                'modifiedDescription' => __( 'These files (apparently) differ from the original WordPress or plugin versions.', 'vigilante' ),
                'extraFiles'          => __( 'Extra Files', 'vigilante' ),
                'extra'               => __( 'Extra', 'vigilante' ),
                'ignored'             => __( 'Ignored', 'vigilante' ),
                'extraDescription'    => __( 'PHP files found in plugins or themes that are not part of the original distribution from WordPress.org.', 'vigilante' ),
                'actions'             => __( 'Actions', 'vigilante' ),
                'ignore'              => __( 'Ignore', 'vigilante' ),
                'ignoring'            => __( 'Ignoring...', 'vigilante' ),
                'fileIgnored'         => __( 'File added to ignored list.', 'vigilante' ),
                'fileUnignored'       => __( 'File removed from ignored list.', 'vigilante' ),
                'confirmClearIgnored' => __( 'Remove all files from the ignored list? They will appear in scan results again.', 'vigilante' ),
                'ignoredCleared'      => __( 'Ignored files list cleared. Page will reload...', 'vigilante' ),
                'selectAll'           => __( 'Select all', 'vigilante' ),
                'bulkIgnoreSelected'  => __( 'Ignore selected', 'vigilante' ),
                'bulkUnignoreSelected'=> __( 'Stop ignoring selected', 'vigilante' ),
                'bulkNoSelection'     => __( 'Select at least one file first.', 'vigilante' ),
                'bulkConfirmIgnore'   => __( 'Ignore the selected files? They will be hidden from future scan results until you remove them from the ignored list.', 'vigilante' ),
                'bulkConfirmUnignore' => __( 'Remove the selected files from the ignored list? They will appear in scan results again.', 'vigilante' ),
                'bulkProcessing'      => __( 'Processing...', 'vigilante' ),
                /* translators: %d: number of files selected for bulk action. */
                'bulkSelectedCount'   => __( '%d selected', 'vigilante' ),
                'allClear'            => __( 'All files verified - no issues found!', 'vigilante' ),
                'criticalConfigTitle' => __( 'Critical config files modified', 'vigilante' ),
                'criticalConfigDesc'  => __( 'These files are common targets for code injection. Review the changes and approve if they are legitimate. Vigilant\'s own blocks are excluded from this check.', 'vigilante' ),
                'approve'             => __( 'Approve', 'vigilante' ),
                'approving'           => __( 'Approving...', 'vigilante' ),
                'criticalApproved'    => __( 'Change approved. Next scan will use the current state as baseline.', 'vigilante' ),
                'reviewChanges'       => __( 'Review changes', 'vigilante' ),
                'hideChanges'         => __( 'Hide changes', 'vigilante' ),
                'changes'             => __( 'Changes', 'vigilante' ),
                'diffUnavailable'     => __( 'Diff not available for this file (baseline was created before diff tracking was added). Approve to enable diff on future changes.', 'vigilante' ),
                'diffEmpty'           => __( 'No line-level changes detected (may be whitespace or reordering).', 'vigilante' ),
                'diffLines'           => __( 'lines', 'vigilante' ),
                // Under Attack mode strings
                'underAttackConfirmActivate'   => __( 'Activate Under Attack mode? All visitors will see a verification page for the next 4 hours.', 'vigilante' ),
                'underAttackConfirmDeactivate' => __( 'Deactivate Under Attack mode?', 'vigilante' ),
                'underAttackActivating'        => __( 'Activating...', 'vigilante' ),
                'underAttackDeactivating'      => __( 'Deactivating...', 'vigilante' ),
                // Database backup strings
                'dbBackupDownloading'          => __( 'Generating backup...', 'vigilante' ),
                'dbBackupNoTables'             => __( 'Please select at least one table.', 'vigilante' ),
                'dbBackupSuccess'              => __( 'Database backup downloaded successfully.', 'vigilante' ),
                // Firewall unblock
                'confirmUnblockIp'             => __( 'Unblock this IP from firewall rate limiting?', 'vigilante' ),
                // Database prefix strings
                'dbPrefixConfirm'              => __( 'This operation will change your database prefix. It is irreversible. Make sure you have a current database backup before proceeding.', 'vigilante' ),
                'dbPrefixChanging'             => __( 'Changing prefix...', 'vigilante' ),
                'dbPrefixSuccess'              => __( 'Database prefix changed successfully. The page will reload now.', 'vigilante' ),
                'dbPrefixCheckbox'             => __( 'You must confirm that you have a database backup.', 'vigilante' ),
                /* translators: 1: Hours, 2: Minutes */
                'underAttackRemaining'         => __( '%1$dh %2$dm remaining', 'vigilante' ),
                'underAttackLabel'             => __( 'Under Attack', 'vigilante' ),
                'standardLabel'                => __( 'Standard', 'vigilante' ),
                'maximumLabel'                 => __( 'Maximum Security', 'vigilante' ),
                'deactivate'                   => __( 'Deactivate', 'vigilante' ),
                'underAttackActivate'          => __( 'Activate for 4 hours', 'vigilante' ),
                // Settings strings
                'saveSettings'                 => __( 'Save Settings', 'vigilante' ),
                'settingsResetDefaults'        => __( 'Settings reset to defaults.', 'vigilante' ),
                'confirmOverwrite'             => __( 'This will overwrite your current settings.', 'vigilante' ),
                'importFailed'                 => __( 'Could not import settings. Check the file and try again.', 'vigilante' ),
                /* translators: 1: tests passed, 2: total tests in this category */
                'testsCounter'                 => __( '%1$d/%2$d tests', 'vigilante' ),
                'confirmResetAll'              => __( 'This will reset ALL settings to defaults.', 'vigilante' ),
                'couldNotDetermineSection'     => __( 'Could not determine section.', 'vigilante' ),
                'confirmResetSection'          => __( 'Reset this section to default values? This cannot be undone.', 'vigilante' ),
                'sectionResetDefaults'         => __( 'Section reset to defaults.', 'vigilante' ),
                /* translators: %s: preset name */
                'confirmApplyPreset'           => __( 'Apply the "%s" preset?', 'vigilante' ),
                // Scan strings
                'scanFailed'                   => __( 'Scan failed', 'vigilante' ),
                /* translators: %s: error message */
                'scanError'                    => __( 'Scan error: %s', 'vigilante' ),
                'runScanNow'                   => __( 'Run Scan Now', 'vigilante' ),
                'confirmClearScan'             => __( 'Are you sure you want to clear all scan results?', 'vigilante' ),
                'clearing'                     => __( 'Clearing...', 'vigilante' ),
                'scanResultsCleared'           => __( 'Scan results cleared. Page will reload...', 'vigilante' ),
                'failedClearResults'           => __( 'Failed to clear results', 'vigilante' ),
                /* translators: %s: error message */
                'ajaxError'                    => __( 'AJAX Error: %s', 'vigilante' ),
                // Activity log popup strings
                'logRequest'                   => __( 'Request', 'vigilante' ),
                'logDate'                      => __( 'Date', 'vigilante' ),
                'logMethod'                    => __( 'Method', 'vigilante' ),
                'logType'                      => __( 'Type', 'vigilante' ),
                'logAction'                    => __( 'Action', 'vigilante' ),
                'logSeverity'                  => __( 'Severity', 'vigilante' ),
                'logMessage'                   => __( 'Message', 'vigilante' ),
                'logClient'                    => __( 'Client', 'vigilante' ),
                'logUser'                      => __( 'User', 'vigilante' ),
                'logIpAddress'                 => __( 'IP Address', 'vigilante' ),
                'logUserAgent'                 => __( 'User Agent', 'vigilante' ),
                'logIpLabel'                   => __( 'IP:', 'vigilante' ),
                'logUaLabel'                   => __( 'UA:', 'vigilante' ),
                'logWhitelist'                 => __( 'Whitelist', 'vigilante' ),
                'logBlacklist'                 => __( 'Blacklist', 'vigilante' ),
                'logInWhitelist'               => __( 'In whitelist', 'vigilante' ),
                'logInBlacklist'               => __( 'In blacklist', 'vigilante' ),
                'logAdded'                     => __( 'Added!', 'vigilante' ),
                'logErrorAddingToList'         => __( 'Error adding to list', 'vigilante' ),
                'logRequestFailed'             => __( 'Request failed', 'vigilante' ),
                // Activity log table strings
                'noLogEntries'                 => __( 'No log entries found.', 'vigilante' ),
                'view'                         => __( 'View', 'vigilante' ),
                'confirmClearLogs'             => __( 'This will delete all audit logs.', 'vigilante' ),
                // Export logs strings
                'exporting'                    => __( 'Exporting...', 'vigilante' ),
                /* translators: %d: number of entries */
                'logsExported'                 => __( 'Logs exported (%d entries)', 'vigilante' ),
                'noLogsToExport'               => __( 'No logs to export', 'vigilante' ),
                'exportFailed'                 => __( 'Export failed', 'vigilante' ),
                'exportLogs'                   => __( 'Export Logs', 'vigilante' ),
                // Backup strings
                'backupCreated'                => __( 'Backup created successfully.', 'vigilante' ),
                'createBackupNow'              => __( 'Create Backup Now', 'vigilante' ),
                'downloadBackup'               => __( 'Download Backup (.zip)', 'vigilante' ),
                /* translators: %d: number of tables */
                'tablesCount'                  => __( '%d tables', 'vigilante' ),
                /* translators: 1: table count, 2: human-readable size */
                'dbTablesTotal'                => __( '%1$d tables total (%2$s)', 'vigilante' ),
                /* translators: 1: selected count, 2: human-readable size */
                'dbTablesSelected'             => __( '%1$d tables selected (%2$s)', 'vigilante' ),
                // Settings search strings
                'searchNoResults'              => __( 'No matching settings found.', 'vigilante' ),
                'searchInTab'                  => __( 'in', 'vigilante' ),
                // Modules string
                /* translators: 1: enabled count, 2: total count */
                'modulesEnabled'               => __( '%1$d / %2$d modules enabled', 'vigilante' ),
                // Activity log label maps for JS rendering
                'eventTypeLabels'              => array(
                    'login'    => __( 'Login', 'vigilante' ),
                    'user'     => __( 'User', 'vigilante' ),
                    'content'  => __( 'Content', 'vigilante' ),
                    'plugin'   => __( 'Plugin', 'vigilante' ),
                    'theme'    => __( 'Theme', 'vigilante' ),
                    'settings' => __( 'Settings', 'vigilante' ),
                    'comment'  => __( 'Comment', 'vigilante' ),
                    'media'    => __( 'Media', 'vigilante' ),
                    'firewall' => __( 'Firewall', 'vigilante' ),
                    'file'     => __( 'File', 'vigilante' ),
                    'security' => __( 'Security', 'vigilante' ),
                    'system'   => __( 'System', 'vigilante' ),
                ),
                'severityLabels'               => array(
                    'info'     => __( 'Info', 'vigilante' ),
                    'warning'  => __( 'Warning', 'vigilante' ),
                    'critical' => __( 'Critical', 'vigilante' ),
                ),
                // Password reset strings
                'noUsersFoundSearch'           => __( 'No users found', 'vigilante' ),
                /* translators: %d: number of users */
                'confirmForceReset'            => __( 'Force password reset for %d user(s)? A password reset email will be sent to each user.', 'vigilante' ),
                'warningResettingSelf'         => __( 'WARNING: You are including yourself. Your session will end and you will need to set a new password.', 'vigilante' ),
                'processing'                   => __( 'Processing...', 'vigilante' ),
                'anErrorOccurred'              => __( 'An error occurred', 'vigilante' ),
                'forceResetSelected'           => __( 'Force Reset for Selected Users', 'vigilante' ),
                'confirmForceResetAll'         => __( 'This will force ALL users to reset their password. All users will receive a password reset email. Are you sure you want to continue?', 'vigilante' ),
                'warningResettingSelfAll'      => __( 'WARNING: You are including yourself. Your session will end immediately.', 'vigilante' ),
                'forceResetAll'                => __( 'Force Reset for ALL Users', 'vigilante' ),
                // Role-based password reset strings
                /* translators: %d: number of users */
                'confirmForceResetByRole'      => __( 'Force password reset for %d user(s) with the selected roles? A password reset email will be sent to each user.', 'vigilante' ),
                'noRolesSelected'              => __( 'Please select at least one role.', 'vigilante' ),
                'forceResetByRole'             => __( 'Force Reset for Selected Roles', 'vigilante' ),
                // User approval strings
                'confirmApprove'               => __( 'Approve this user?', 'vigilante' ),
                'approve'                      => __( 'Approve', 'vigilante' ),
                'rejectReason'                 => __( 'Enter rejection reason (optional):', 'vigilante' ),
                'reject'                       => __( 'Reject', 'vigilante' ),
                'noPending'                    => __( 'No pending registrations.', 'vigilante' ),
                // Session management strings
                'confirmRevoke'                => __( 'Revoke this session?', 'vigilante' ),
                'confirmRevokeAll'             => __( 'Revoke all other sessions?', 'vigilante' ),
                'revokeOthers'                 => __( 'Revoke All Other Sessions', 'vigilante' ),
                'confirmRevokeAllUser'         => __( 'Revoke ALL sessions for this user? They will be logged out everywhere.', 'vigilante' ),
                'sessionsFor'                  => __( 'Sessions for:', 'vigilante' ),
                'noSessions'                   => __( 'No active sessions', 'vigilante' ),
                'revoke'                       => __( 'Revoke', 'vigilante' ),
                'noUsers'                      => __( 'No users found', 'vigilante' ),
                // Time ago strings
                'timeYear'                     => __( 'year', 'vigilante' ),
                'timeYears'                    => __( 'years', 'vigilante' ),
                'timeMonth'                    => __( 'month', 'vigilante' ),
                'timeMonths'                   => __( 'months', 'vigilante' ),
                'timeDay'                      => __( 'day', 'vigilante' ),
                'timeDays'                     => __( 'days', 'vigilante' ),
                'timeHour'                     => __( 'hour', 'vigilante' ),
                'timeHours'                    => __( 'hours', 'vigilante' ),
                'timeMinute'                   => __( 'minute', 'vigilante' ),
                'timeMinutes'                  => __( 'minutes', 'vigilante' ),
                /* translators: %1$d: count, %2$s: time unit */
                'timeAgo'                      => __( '%1$d %2$s ago', 'vigilante' ),
                'justNow'                      => __( 'Just now', 'vigilante' ),
                // Pagination strings
                /* translators: 1: first item number, 2: last item number, 3: total items */
                'paginationOf'                 => __( '%1$d–%2$d of %3$d', 'vigilante' ),
                'paginationEmpty'              => __( '0 items', 'vigilante' ),
                // Security Analyzer strings
                'analyzerScanNow'              => __( 'Scan now', 'vigilante' ),
                'analyzerScanning'             => __( 'Scanning…', 'vigilante' ),
                'analyzerFastPhase'            => __( 'Running fast checks…', 'vigilante' ),
                'analyzerSlowPhase'            => __( 'Running remote checks…', 'vigilante' ),
                'analyzerScanComplete'         => __( 'Security scan complete.', 'vigilante' ),
                'analyzerScanFailed'           => __( 'Security scan failed.', 'vigilante' ),
                'analyzerShowDetails'          => __( 'Show detailed breakdown', 'vigilante' ),
                'analyzerHideDetails'          => __( 'Hide detailed breakdown', 'vigilante' ),
                'analyzerGoToSetting'          => __( 'Go to setting', 'vigilante' ),
                'analyzerNoData'               => __( 'No data yet — run a scan to populate this category.', 'vigilante' ),
                'analyzerJustNow'              => __( 'just now', 'vigilante' ),
                'analyzerAgo'                  => __( 'ago', 'vigilante' ),
                'analyzerSettingsSaved'        => __( 'Analyzer settings saved.', 'vigilante' ),
                'analyzerLastScanJustNow'      => __( 'Last scan just now', 'vigilante' ),
                'analyzerQualityExcellent'     => __( 'Excellent', 'vigilante' ),
                'analyzerQualityGood'          => __( 'Good', 'vigilante' ),
                'analyzerQualityFair'          => __( 'Fair', 'vigilante' ),
                'analyzerQualityPoor'          => __( 'Poor', 'vigilante' ),
                'analyzerQualityCritical'      => __( 'Critical', 'vigilante' ),
                'analyzerPts'                  => __( 'pts', 'vigilante' ),
                'analyzerLearnMore'            => __( 'Learn more', 'vigilante' ),
                'analyzerInfoAllClear'         => __( 'All clear', 'vigilante' ),
                /* translators: %d: number of findings in an info-only category */
                'analyzerInfoFindings'         => __( '%d findings', 'vigilante' ),
            ),
        ) );

        // 2FA Admin assets
        wp_enqueue_style(
            'vigilante-2fa-admin',
            VIGILANTE_ASSETS_URL . 'css/two-factor-admin.css',
            array( 'vigilante-admin' ),
            VIGILANTE_VERSION
        );

        wp_enqueue_script(
            'vigilante-2fa-admin',
            VIGILANTE_ASSETS_URL . 'js/two-factor-admin.js',
            array( 'jquery', 'vigilante-admin' ),
            VIGILANTE_VERSION,
            true
        );
    }

    /**
     * Show admin notices
     */
    public function show_admin_notices() {
        // Activation notice
        if ( get_transient( 'vigilante_activated' ) ) {
            ?>
            <div class="notice notice-success is-dismissible vigilante-activation-notice">
                <p>
                    <span class="dashicons dashicons-shield vigilante-notice-icon"></span>
                    <strong><?php esc_html_e( 'Vigilant activated successfully!', 'vigilante' ); ?></strong>
                    <?php esc_html_e( 'Security protection is now active.', 'vigilante' ); ?>
                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=vigilante' ) ); ?>">
                        <?php esc_html_e( 'Configure settings', 'vigilante' ); ?>
                    </a>
                </p>
            </div>
            <?php
            delete_transient( 'vigilante_activated' );
        }

        // Under Attack mode notice (non-dismissible, shown on all admin pages)
        $ua_status = get_option( Vigilante_Under_Attack::OPTION_NAME, array() );
        if ( ! empty( $ua_status['active'] ) ) {
            $ua_remaining = ( $ua_status['activated_at'] + $ua_status['duration'] ) - time();
            if ( $ua_remaining > 0 ) {
                $ua_hours = floor( $ua_remaining / 3600 );
                $ua_mins  = floor( ( $ua_remaining % 3600 ) / 60 );
                $dashboard_url = admin_url( 'admin.php?page=vigilante' );
                ?>
                <div class="notice notice-warning vigilante-ua-notice">
                    <p>
                        <span class="dashicons dashicons-shield"></span>
                        <strong><?php esc_html_e( 'Under Attack mode is active', 'vigilante' ); ?></strong>
                        &mdash;
                        <?php
                        printf(
                            /* translators: 1: Hours, 2: Minutes */
                            esc_html__( '%1$dh %2$dm remaining.', 'vigilante' ),
                            absint( $ua_hours ),
                            absint( $ua_mins )
                        );
                        ?>
                        <a href="<?php echo esc_url( $dashboard_url ); ?>">
                            <?php esc_html_e( 'Go to Vigilant dashboard', 'vigilante' ); ?>
                        </a>
                    </p>
                    <p>
                        <em><?php esc_html_e( 'Vigilant has applied the Maximum preset plus extra hardening on top of your previous configuration. Any changes you make to Vigilant settings while this mode is active will be reverted when it ends.', 'vigilante' ); ?></em>
                    </p>
                </div>
                <?php
            }
        }
    }

    /**
     * Render settings page
     */
    public function render_settings_page() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $this->current_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'dashboard';

        if ( ! array_key_exists( $this->current_tab, $this->tabs ) ) {
            $this->current_tab = 'dashboard';
        }
        ?>
        <div class="wrap vigilante-admin-wrap">
            <div class="vigilante-header-row">
                <h1 class="vigilante-page-title">
                    <img src="<?php echo esc_url( VIGILANTE_ASSETS_URL . 'images/icon.png' ); ?>" alt="Vigilante" class="vigilante-title-icon">
                    <?php esc_html_e( 'Vigilant', 'vigilante' ); ?>
                    <span class="vigilante-version">v<?php echo esc_html( VIGILANTE_VERSION ); ?></span>
                </h1>
                <div class="vigilante-search-wrapper">
                    <div class="vigilante-search-input-wrap">
                        <span class="vigilante-search-icon dashicons dashicons-search" aria-hidden="true"></span>
                        <input type="search" id="vigilante-settings-search" class="vigilante-settings-search" placeholder="<?php esc_attr_e( 'Search settings…', 'vigilante' ); ?>" autocomplete="off">
                        <span class="vigilante-search-shortcut" aria-hidden="true">/</span>
                    </div>
                    <div id="vigilante-settings-search-results" class="vigilante-search-results" hidden role="listbox"></div>
                </div>
            </div>

            <?php $this->render_tabs(); ?>

            <div class="vigilante-content">
                <div class="vigilante-main">
                    <?php $this->render_tab_content(); ?>
                </div>
                <div class="vigilante-sidebar">
                    <?php $this->render_sidebar(); ?>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render tabs navigation
     */
    private function render_tabs() {
        $options = $this->settings->get_all_options();
        
        // Map tabs to modules
        $tab_to_module = array(
            'firewall'       => 'firewall',
            'headers'        => 'security_headers',
            'login'          => 'login_security',
            'rest-api'       => 'rest_api_security',
            'users'          => 'user_security',
            'wp-hardening'   => 'wp_hardening',
            'file-integrity' => 'file_integrity',
            'activity-log'   => 'activity_log',
        );
        ?>
        <nav class="nav-tab-wrapper vigilante-nav-tabs">
            <?php foreach ( $this->tabs as $tab_id => $tab_name ) : 
                $is_disabled = false;
                $module = isset( $tab_to_module[ $tab_id ] ) ? $tab_to_module[ $tab_id ] : null;
                if ( $module && empty( $options['modules'][ $module ] ) ) {
                    $is_disabled = true;
                }
                ?>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=vigilante&tab=' . $tab_id ) ); ?>"
                   class="nav-tab <?php echo $this->current_tab === $tab_id ? 'nav-tab-active' : ''; ?> <?php echo $is_disabled ? 'vigilante-tab-disabled' : ''; ?>"
                   <?php if ( $is_disabled ) : ?>title="<?php esc_attr_e( 'Module Disabled', 'vigilante' ); ?>"<?php endif; ?>>
                    <?php echo esc_html( $tab_name ); ?>
                    <?php if ( $is_disabled ) : ?><span class="vigilante-tab-off">OFF</span><?php endif; ?>
                </a>
            <?php endforeach; ?>
        </nav>
        <?php
    }

    /**
     * Render current tab content
     */
    private function render_tab_content() {
        $method = 'render_tab_' . str_replace( '-', '_', $this->current_tab );

        if ( method_exists( $this, $method ) ) {
            $this->$method();
        } else {
            $this->render_tab_coming_soon();
        }
    }

    /**
     * Render coming soon placeholder
     */
    private function render_tab_coming_soon() {
        ?>
        <div class="vigilante-settings-section">
            <h2><?php esc_html_e( 'Coming Soon', 'vigilante' ); ?></h2>
            <p><?php esc_html_e( 'This section is under development.', 'vigilante' ); ?></p>
        </div>
        <?php
    }

    /**
     * Check if module is disabled and render warning
     *
     * @param string $module_key Module key.
     * @return bool True if disabled.
     */
    private function render_module_disabled_notice( $module_key ) {
        if ( $this->settings->is_module_enabled( $module_key ) ) {
            return false;
        }
        
        $module_labels = $this->settings->get_module_labels();
        $module_name = isset( $module_labels[ $module_key ] ) ? $module_labels[ $module_key ] : $module_key;
        ?>
        <div class="notice notice-warning vigilante-module-disabled-notice">
            <p>
                <strong><?php esc_html_e( 'Module Disabled', 'vigilante' ); ?></strong> - 
                <?php 
                printf(
                    /* translators: %s: Module name */
                    esc_html__( 'The %s module is currently disabled. Enable it from the Dashboard to use these settings.', 'vigilante' ),
                    esc_html( $module_name )
                );
                ?>
            </p>
            <p>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=vigilante&tab=dashboard' ) ); ?>" class="button">
                    <?php esc_html_e( 'Go to Dashboard', 'vigilante' ); ?>
                </a>
            </p>
        </div>
        <?php
        return true;
    }

    /**
     * Render the Security Analyzer (Security Check) widget + expandable full report.
     *
     * Lives in the Dashboard tab between the Configuration Score status card and
     * the modules grid. Uses the last persisted scan to hydrate server-side so the
     * first paint shows real data; "Scan now" runs the 2-phase AJAX to refresh.
     *
     * @param array $last_scan      Result of Vigilante_Security_Analyzer::get_last_scan().
     * @param array $history        Score history (oldest first).
     * @param array $categories_def Category metadata (slug => label/max).
     * @param array $analyzer_settings Settings subsection for weekly cron + email.
     */
    private function render_analyzer_widget( $last_scan, $history, $categories_def, $analyzer_settings ) {
        $has_data       = ! empty( $last_scan['ran_at'] );
        $score          = isset( $last_scan['score'] ) ? (int) $last_scan['score'] : 0;
        $grade          = isset( $last_scan['grade'] ) ? (string) $last_scan['grade'] : '';
        $counts         = isset( $last_scan['counts'] ) && is_array( $last_scan['counts'] ) ? $last_scan['counts'] : array();
        $ran_at_human   = $has_data
            ? sprintf(
                /* translators: %s: relative time like "2 hours" */
                __( 'Last scan %s ago', 'vigilante' ),
                human_time_diff( (int) $last_scan['ran_at'], time() )
            )
            : __( 'Never scanned', 'vigilante' );
        $categories     = isset( $last_scan['categories'] ) && is_array( $last_scan['categories'] ) ? $last_scan['categories'] : array();
        $weekly_enabled = ! isset( $analyzer_settings['weekly_scan_enabled'] ) || ! empty( $analyzer_settings['weekly_scan_enabled'] );
        $email_enabled  = ! empty( $analyzer_settings['email_on_regression'] );

        $quality = self::analyzer_quality_tag( $score );
        ?>
        <div class="vigilante-analyzer" id="vigilante-analyzer"
             data-has-data="<?php echo $has_data ? '1' : '0'; ?>">
            <div class="vigilante-analyzer-header">
                <div class="vigilante-analyzer-title">
                    <h2>
                        <span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>
                        <?php esc_html_e( 'Security Check', 'vigilante' ); ?>
                    </h2>
                    <p class="description">
                        <?php esc_html_e( 'On-demand audit of what an attacker would see right now, plus 13 internal checks impossible from the outside.', 'vigilante' ); ?>
                    </p>
                    <p class="vigilante-analyzer-last-scan" data-role="ran-at">
                        <span class="dashicons dashicons-clock" aria-hidden="true"></span>
                        <?php echo esc_html( $ran_at_human ); ?>
                    </p>
                </div>
                <div class="vigilante-analyzer-actions">
                    <button type="button" class="button button-primary" id="vigilante-analyzer-scan">
                        <span class="dashicons dashicons-update" aria-hidden="true"></span>
                        <?php esc_html_e( 'Scan now', 'vigilante' ); ?>
                    </button>
                </div>
            </div>

            <div class="vigilante-analyzer-summary">
                <div class="vigilante-analyzer-score-card">
                    <?php if ( $has_data && $grade ) : ?>
                        <div class="vigilante-score-circle vigilante-grade-<?php echo esc_attr( strtolower( $grade ) ); ?>">
                            <span class="vigilante-grade"><?php echo esc_html( $grade ); ?></span>
                            <span class="vigilante-score-text"><?php echo esc_html( $score ); ?>%</span>
                        </div>
                    <?php else : ?>
                        <div class="vigilante-score-circle vigilante-grade-empty">
                            <span class="vigilante-grade">—</span>
                            <span class="vigilante-score-text"><?php esc_html_e( 'N/A', 'vigilante' ); ?></span>
                        </div>
                    <?php endif; ?>
                    <div class="vigilante-analyzer-score-meta">
                        <p class="vigilante-analyzer-score-label">
                            <?php esc_html_e( 'Security Score', 'vigilante' ); ?>
                        </p>
                        <span class="vigilante-analyzer-quality-tag vigilante-analyzer-quality-<?php echo esc_attr( $quality['slug'] ); ?>"
                              data-role="quality-tag">
                            <?php echo esc_html( $quality['label'] ); ?>
                        </span>
                    </div>
                </div>

                <div class="vigilante-analyzer-counts">
                    <span class="vigilante-analyzer-count vigilante-analyzer-count--pass">
                        <span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
                        <strong data-role="pass"><?php echo esc_html( isset( $counts['pass'] ) ? $counts['pass'] : 0 ); ?></strong>
                        <span class="vigilante-analyzer-count-label"><?php esc_html_e( 'Passed', 'vigilante' ); ?></span>
                    </span>
                    <span class="vigilante-analyzer-count vigilante-analyzer-count--warn">
                        <span class="dashicons dashicons-warning" aria-hidden="true"></span>
                        <strong data-role="warn"><?php echo esc_html( isset( $counts['warn'] ) ? $counts['warn'] : 0 ); ?></strong>
                        <span class="vigilante-analyzer-count-label"><?php esc_html_e( 'Warnings', 'vigilante' ); ?></span>
                    </span>
                    <span class="vigilante-analyzer-count vigilante-analyzer-count--fail">
                        <span class="dashicons dashicons-dismiss" aria-hidden="true"></span>
                        <strong data-role="fail"><?php echo esc_html( isset( $counts['fail'] ) ? $counts['fail'] : 0 ); ?></strong>
                        <span class="vigilante-analyzer-count-label"><?php esc_html_e( 'Failing', 'vigilante' ); ?></span>
                    </span>
                </div>

                <?php
                // Sparkline of recent scores. Require at least 3 data points so the trend
                // is meaningful (2 points is just a line between dots, no real trend).
                $hist_points = array();
                foreach ( $history as $h ) {
                    $hist_points[] = (int) $h['score'];
                }
                $hist_count = count( $hist_points );
                if ( $hist_count >= 3 ) :
                    $current_score  = (int) end( $hist_points );
                    $previous_score = (int) $hist_points[ $hist_count - 2 ];
                    $delta          = $current_score - $previous_score;
                    $delta_class    = $delta > 0 ? 'vigilante-analyzer-delta--up' : ( $delta < 0 ? 'vigilante-analyzer-delta--down' : 'vigilante-analyzer-delta--flat' );
                    $delta_icon     = $delta > 0 ? 'arrow-up-alt' : ( $delta < 0 ? 'arrow-down-alt' : 'minus' );
                    if ( 0 === $delta ) {
                        $delta_text = __( 'No change', 'vigilante' );
                    } else {
                        $delta_text = sprintf(
                            /* translators: %s: signed delta, e.g. "+3" or "-5" */
                            _n( '%s pt vs. previous scan', '%s pts vs. previous scan', abs( $delta ), 'vigilante' ),
                            ( $delta > 0 ? '+' : '' ) . (int) $delta
                        );
                    }
                    ?>
                    <div class="vigilante-analyzer-sparkline-wrap">
                        <div class="vigilante-analyzer-sparkline-head">
                            <span class="vigilante-analyzer-sparkline-label">
                                <?php
                                echo esc_html( sprintf(
                                    /* translators: %d: number of scans */
                                    _n( 'Score trend (last %d scan)', 'Score trend (last %d scans)', $hist_count, 'vigilante' ),
                                    $hist_count
                                ) );
                                ?>
                            </span>
                            <span class="vigilante-analyzer-delta <?php echo esc_attr( $delta_class ); ?>">
                                <span class="dashicons dashicons-<?php echo esc_attr( $delta_icon ); ?>" aria-hidden="true"></span>
                                <?php echo esc_html( $delta_text ); ?>
                            </span>
                        </div>
                        <div class="vigilante-analyzer-sparkline" data-role="sparkline"
                             data-points="<?php echo esc_attr( wp_json_encode( $hist_points ) ); ?>">
                            <?php echo self::sparkline_svg( $hist_points ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Safe SVG from helper ?>
                        </div>
                    </div>
                <?php elseif ( $has_data ) : ?>
                    <div class="vigilante-analyzer-sparkline-wrap vigilante-analyzer-sparkline-wrap--placeholder">
                        <span class="vigilante-analyzer-sparkline-label">
                            <?php esc_html_e( 'Score trend', 'vigilante' ); ?>
                        </span>
                        <p class="vigilante-analyzer-sparkline-hint">
                            <span class="dashicons dashicons-chart-line" aria-hidden="true"></span>
                            <?php
                            $needed = 3 - $hist_count;
                            echo esc_html( sprintf(
                                /* translators: %d: number of additional scans needed */
                                _n( '%d more scan needed to show a trend.', '%d more scans needed to show a trend.', $needed, 'vigilante' ),
                                $needed
                            ) );
                            ?>
                        </p>
                    </div>
                <?php endif; ?>
            </div>

            <div class="vigilante-analyzer-toggle-row">
                <button type="button" class="button-link vigilante-analyzer-toggle" aria-expanded="false">
                    <?php esc_html_e( 'Show detailed breakdown', 'vigilante' ); ?>
                    <span class="vigilante-analyzer-toggle-chevron" aria-hidden="true"></span>
                </button>
            </div>

            <div class="vigilante-analyzer-details" hidden>
                <div class="vigilante-analyzer-categories" data-role="categories">
                    <?php foreach ( $categories_def as $slug => $meta ) :
                        $cat         = isset( $categories[ $slug ] ) ? $categories[ $slug ] : array();
                        $earned      = isset( $cat['earned'] ) ? (int) $cat['earned'] : 0;
                        // Always use the declared meta as the source of truth for the maximum.
                        // The cached scan may carry an old max if a check was added/removed
                        // between releases (see 2.6.1: closed_plugins raised internal from 22 to 28
                        // but cached scans still reported max=22 until reset).
                        $cat_max     = (int) $meta['max'];
                        $info_only   = ! empty( $meta['info_only'] ) || 0 === (int) $meta['max'];
                        $cat_pct     = $cat_max > 0 ? (int) round( ( $earned / $cat_max ) * 100 ) : 0;
                        $checks      = isset( $cat['checks'] ) ? (array) $cat['checks'] : array();
                        $cat_counts  = isset( $cat['counts'] ) && is_array( $cat['counts'] ) ? $cat['counts'] : array( 'pass' => 0, 'warn' => 0, 'fail' => 0, 'info' => 0 );
                        $cat_quality = self::analyzer_quality_tag( $cat_pct );
                        $info_count  = isset( $cat_counts['info'] ) ? (int) $cat_counts['info'] : 0;
                        ?>
                        <details class="vigilante-analyzer-category<?php echo $info_only ? ' vigilante-analyzer-category--info' : ''; ?>"
                                 data-category="<?php echo esc_attr( $slug ); ?>"
                                 data-info-only="<?php echo $info_only ? '1' : '0'; ?>">
                            <summary class="vigilante-analyzer-category-summary">
                                <span class="vigilante-analyzer-category-chevron" aria-hidden="true"></span>
                                <span class="vigilante-analyzer-category-label"><?php echo esc_html( $meta['label'] ); ?></span>
                                <?php if ( $info_only ) : ?>
                                    <span class="vigilante-analyzer-category-quality vigilante-analyzer-quality-info"
                                          data-role="category-quality"
                                          title="<?php esc_attr_e( 'Informational — does not affect the security score.', 'vigilante' ); ?>">
                                        <span class="dashicons dashicons-info-outline" aria-hidden="true"></span>
                                        <?php esc_html_e( 'Informational', 'vigilante' ); ?>
                                    </span>
                                <?php else :
                                    $passed_count = (int) ( $cat_counts['pass'] ?? 0 );
                                    $scored_total = $passed_count
                                        + (int) ( $cat_counts['warn'] ?? 0 )
                                        + (int) ( $cat_counts['fail'] ?? 0 );
                                    ?>
                                    <span class="vigilante-analyzer-category-quality vigilante-analyzer-quality-<?php echo esc_attr( $cat_quality['slug'] ); ?>"
                                          data-role="category-quality">
                                        <span data-role="category-quality-label"><?php echo esc_html( $cat_quality['label'] ); ?></span>
                                        <span class="vigilante-analyzer-category-quality-sep" aria-hidden="true">·</span>
                                        <span class="vigilante-analyzer-category-tests" data-role="category-tests"
                                              data-passed="<?php echo esc_attr( $passed_count ); ?>"
                                              data-total="<?php echo esc_attr( $scored_total ); ?>">
                                            <?php
                                            echo esc_html( sprintf(
                                                /* translators: 1: tests passed, 2: total tests in this category */
                                                __( '%1$d/%2$d tests', 'vigilante' ),
                                                $passed_count,
                                                $scored_total
                                            ) );
                                            ?>
                                        </span>
                                    </span>
                                <?php endif; ?>
                                <?php if ( $info_only ) : ?>
                                    <span class="vigilante-analyzer-category-states" data-role="category-states">
                                        <?php if ( $info_count > 0 ) : ?>
                                            <span class="vigilante-analyzer-category-state vigilante-analyzer-category-state--info" title="<?php esc_attr_e( 'Informational', 'vigilante' ); ?>">
                                                <span data-role="state-info"><?php echo esc_html( $info_count ); ?></span><span class="dashicons dashicons-info-outline" aria-hidden="true"></span>
                                            </span>
                                        <?php endif; ?>
                                    </span>
                                <?php endif; ?>
                                <?php if ( ! $info_only ) : ?>
                                    <span class="vigilante-analyzer-category-score">
                                        <span data-role="earned"><?php echo esc_html( $earned ); ?></span><span class="vigilante-analyzer-category-score-sep">/</span><?php echo esc_html( $cat_max ); ?>
                                        <span class="vigilante-analyzer-category-score-unit"><?php esc_html_e( 'pts', 'vigilante' ); ?></span>
                                    </span>
                                    <span class="vigilante-analyzer-category-bar" aria-hidden="true">
                                        <span class="vigilante-analyzer-category-bar-fill vigilante-analyzer-category-bar-fill--<?php echo esc_attr( $cat_quality['slug'] ); ?>"
                                              style="width: <?php echo esc_attr( $cat_pct ); ?>%"
                                              data-role="category-bar"></span>
                                    </span>
                                <?php else :
                                    $info_warn = isset( $cat_counts['warn'] ) ? (int) $cat_counts['warn'] : 0;
                                    $info_fail = isset( $cat_counts['fail'] ) ? (int) $cat_counts['fail'] : 0;
                                    $info_issues = $info_warn + $info_fail;
                                    if ( $info_issues > 0 ) : ?>
                                        <span class="vigilante-analyzer-category-status vigilante-analyzer-category-status--attention" data-role="info-status">
                                            <span class="dashicons dashicons-warning" aria-hidden="true"></span>
                                            <?php
                                            echo esc_html( sprintf(
                                                /* translators: %d: number of findings */
                                                _n( '%d finding', '%d findings', $info_issues, 'vigilante' ),
                                                $info_issues
                                            ) );
                                            ?>
                                        </span>
                                    <?php else : ?>
                                        <span class="vigilante-analyzer-category-status vigilante-analyzer-category-status--clear" data-role="info-status">
                                            <span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
                                            <?php esc_html_e( 'All clear', 'vigilante' ); ?>
                                        </span>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </summary>
                            <ul class="vigilante-analyzer-check-list" data-role="check-list">
                                <?php if ( empty( $checks ) ) : ?>
                                    <li class="vigilante-analyzer-check-empty">
                                        <?php esc_html_e( 'No data yet — run a scan to populate this category.', 'vigilante' ); ?>
                                    </li>
                                <?php else : ?>
                                    <?php foreach ( $checks as $c ) : ?>
                                        <?php echo self::render_analyzer_check_row( $c ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped inside helper ?>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </ul>
                        </details>
                    <?php endforeach; ?>
                </div>

                <div class="vigilante-analyzer-weekly">
                    <h3><?php esc_html_e( 'Automatic weekly scan', 'vigilante' ); ?></h3>
                    <p class="description">
                        <?php esc_html_e( 'Vigilante runs this check once a week in the background. Enable email alerts to be notified if the score drops by 10 points or more, or if a new critical check starts failing.', 'vigilante' ); ?>
                    </p>
                    <label class="vigilante-analyzer-toggle-option">
                        <input type="checkbox"
                               name="security_analyzer[weekly_scan_enabled]"
                               value="1"
                               <?php checked( $weekly_enabled ); ?>>
                        <?php esc_html_e( 'Run a weekly automatic scan', 'vigilante' ); ?>
                    </label>
                    <label class="vigilante-analyzer-toggle-option">
                        <input type="checkbox"
                               name="security_analyzer[email_on_regression]"
                               value="1"
                               <?php checked( $email_enabled ); ?>>
                        <?php esc_html_e( 'Email me when the score drops significantly', 'vigilante' ); ?>
                    </label>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Map a 0-100 percentage to a quality tag { label, slug } aligned with the
     * Dashboard grade palette (a/b/c/d/e).
     *
     * @param int $pct 0..100.
     * @return array{label:string,slug:string}
     */
    public static function analyzer_quality_tag( $pct ) {
        $pct = max( 0, min( 100, (int) $pct ) );
        // "Excellent" is reserved for a perfect score — a single missing point drops to Good.
        if ( 100 === $pct ) {
            return array( 'label' => __( 'Excellent', 'vigilante' ), 'slug' => 'a' );
        }
        if ( $pct >= 70 ) {
            return array( 'label' => __( 'Good', 'vigilante' ), 'slug' => 'b' );
        }
        if ( $pct >= 50 ) {
            return array( 'label' => __( 'Fair', 'vigilante' ), 'slug' => 'c' );
        }
        if ( $pct >= 30 ) {
            return array( 'label' => __( 'Poor', 'vigilante' ), 'slug' => 'd' );
        }
        return array( 'label' => __( 'Critical', 'vigilante' ), 'slug' => 'e' );
    }

    /**
     * Render a single analyzer check row (used both server-side and via JS template).
     *
     * @param array $check Check result array (from Vigilante_SA_Check_Result::to_array()).
     * @return string HTML (escaped).
     */
    private static function render_analyzer_check_row( $check ) {
        $id       = isset( $check['id'] ) ? $check['id'] : '';
        $state    = isset( $check['state'] ) ? $check['state'] : 'skip';
        $label    = isset( $check['label'] ) ? $check['label'] : '';
        $detail   = isset( $check['detail'] ) ? $check['detail'] : '';
        $score    = isset( $check['score'] ) ? (int) $check['score'] : 0;
        $max      = isset( $check['max'] ) ? (int) $check['max'] : 0;
        $fix_link = isset( $check['fix_link'] ) ? $check['fix_link'] : '';

        $icons = array(
            'pass' => 'yes-alt',
            'warn' => 'warning',
            'fail' => 'dismiss',
            'info' => 'info',
            'skip' => 'minus',
        );
        $icon = isset( $icons[ $state ] ) ? $icons[ $state ] : 'minus';

        $html  = '<li class="vigilante-analyzer-check vigilante-analyzer-check--' . esc_attr( $state ) . '"';
        $html .= ' data-check-id="' . esc_attr( $id ) . '">';
        $html .= '<span class="vigilante-analyzer-check-icon dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span>';
        $html .= '<div class="vigilante-analyzer-check-body">';
        $html .= '<div class="vigilante-analyzer-check-label">';
        $html .= '<span>' . esc_html( $label ) . '</span>';
        if ( $max > 0 && 'info' !== $state && 'skip' !== $state ) {
            $html .= '<span class="vigilante-analyzer-check-score">'
                  . esc_html( $score . '/' . $max )
                  . ' <span class="vigilante-analyzer-check-score-unit">' . esc_html__( 'pts', 'vigilante' ) . '</span>'
                  . '</span>';
        }
        $html .= '</div>';
        if ( $detail ) {
            $html .= '<p class="vigilante-analyzer-check-detail">' . esc_html( $detail ) . '</p>';
        }
        if ( $fix_link && in_array( $state, array( 'fail', 'warn' ), true ) ) {
            $html .= '<a href="' . esc_url( $fix_link ) . '" class="vigilante-analyzer-fix-link">'
                  . esc_html__( 'Go to setting', 'vigilante' )
                  . '<span class="vigilante-analyzer-fix-arrow" aria-hidden="true">&rarr;</span></a>';
        } elseif ( $fix_link && 'info' === $state ) {
            // Info rows (e.g. DNSBL lookups) get an external "Learn more" link instead.
            $is_external = 0 === strpos( $fix_link, 'http' );
            $html .= '<a href="' . esc_url( $fix_link ) . '" class="vigilante-analyzer-fix-link"'
                  . ( $is_external ? ' target="_blank" rel="noopener noreferrer"' : '' ) . '>'
                  . esc_html__( 'Learn more', 'vigilante' )
                  . '<span class="vigilante-analyzer-fix-arrow" aria-hidden="true">&rarr;</span></a>';
        }
        $html .= '</div>';
        $html .= '</li>';
        return $html;
    }

    /**
     * Build a minimal SVG sparkline for the score history.
     *
     * @param int[] $points Score values (0..100), oldest to newest.
     * @return string SVG markup.
     */
    private static function sparkline_svg( $points ) {
        $points = array_map( 'intval', (array) $points );
        $count  = count( $points );
        if ( $count < 2 ) {
            return '';
        }
        $width   = 280;
        $height  = 60;
        $padding = 4;

        $usable_w = $width - ( $padding * 2 );
        $usable_h = $height - ( $padding * 2 );

        $step = $usable_w / max( 1, $count - 1 );
        $max  = 100; // Fixed scale — scores are 0..100.

        $coords = array();
        foreach ( $points as $i => $v ) {
            $x        = $padding + ( $i * $step );
            $y        = $padding + ( $usable_h - ( ( $v / $max ) * $usable_h ) );
            $coords[] = round( $x, 2 ) . ',' . round( $y, 2 );
        }
        $path     = 'M ' . implode( ' L ', $coords );
        $last     = end( $points );
        $last_x   = $padding + ( ( $count - 1 ) * $step );
        $last_y   = $padding + ( $usable_h - ( ( $last / $max ) * $usable_h ) );

        $svg  = '<svg viewBox="0 0 ' . $width . ' ' . $height . '" preserveAspectRatio="none" role="img" aria-label="' . esc_attr__( 'Security Score history', 'vigilante' ) . '" focusable="false">';
        $svg .= '<path d="' . esc_attr( $path ) . '" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>';
        $svg .= '<circle cx="' . esc_attr( round( $last_x, 2 ) ) . '" cy="' . esc_attr( round( $last_y, 2 ) ) . '" r="3" fill="currentColor"/>';
        $svg .= '</svg>';
        return $svg;
    }

    /**
     * Render dashboard tab
     */
    private function render_tab_dashboard() {
        $options = $this->settings->get_all_options();
        $module_labels = $this->settings->get_module_labels();
        $module_descriptions = $this->settings->get_module_descriptions();
        $presets = $this->settings->get_presets();
        $active_preset = get_option( 'vigilante_active_preset', '' );

        // Calculate security score with more factors
        $security_score = $this->calculate_security_score( $options );

        // Security Analyzer (v2.1.0) — hydrate widget with the last persisted scan, if any.
        if ( ! class_exists( 'Vigilante_Security_Analyzer' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-security-analyzer.php';
        }
        $analyzer_instance       = new Vigilante_Security_Analyzer( $this->settings, $this->activity_log );
        $analyzer_last_scan      = $analyzer_instance->get_last_scan();
        $analyzer_history        = $analyzer_instance->get_score_history();
        $analyzer_categories_def = Vigilante_Security_Analyzer::get_categories();
        $analyzer_settings       = isset( $options['security_analyzer'] ) ? $options['security_analyzer'] : array();
        ?>
        <div class="vigilante-dashboard">
            <div class="vigilante-status-card">
                <h2><?php esc_html_e( 'Configuration Score', 'vigilante' ); ?></h2>
                <p class="vigilante-score-kind description">
                    <?php esc_html_e( 'How well Vigilante is configured right now. Pair it with the Security Check below to see the real-world result.', 'vigilante' ); ?>
                </p>
                <div class="vigilante-security-score">
                    <?php
                    // Grade thresholds: A (90+), B (70-89), C (50-69), D (30-49), E (0-29)
                    if ( $security_score >= 90 ) {
                        $grade = 'A';
                    } elseif ( $security_score >= 70 ) {
                        $grade = 'B';
                    } elseif ( $security_score >= 50 ) {
                        $grade = 'C';
                    } elseif ( $security_score >= 30 ) {
                        $grade = 'D';
                    } else {
                        $grade = 'E';
                    }
                    ?>
                    <div class="vigilante-score-circle vigilante-grade-<?php echo esc_attr( strtolower( $grade ) ); ?>">
                        <span class="vigilante-grade"><?php echo esc_html( $grade ); ?></span>
                        <span class="vigilante-score-text"><?php echo esc_html( $security_score ); ?>%</span>
                    </div>
                    <div class="vigilante-config-status">
                        <?php if ( $active_preset && isset( $presets[ $active_preset ] ) ) : ?>
                            <span class="vigilante-preset-badge vigilante-preset-<?php echo esc_attr( $active_preset ); ?>">
                                <?php echo esc_html( $presets[ $active_preset ]['name'] ); ?>
                            </span>
                        <?php else : ?>
                            <span class="vigilante-preset-badge vigilante-preset-custom">
                                <?php esc_html_e( 'Custom Configuration', 'vigilante' ); ?>
                            </span>
                        <?php endif; ?>
                    </div>
                </div>
                
                <?php 
                $recommendations = $this->get_security_recommendations( $options );
                if ( ! empty( $recommendations ) ) : 
                ?>
                <div class="vigilante-recommendations">
                    <h4><?php esc_html_e( 'Recommendations', 'vigilante' ); ?></h4>
                    <ul class="vigilante-recommendations-grid">
                        <?php foreach ( $recommendations as $rec ) : ?>
                        <li>
                            <span class="dashicons dashicons-<?php echo esc_attr( $rec['icon'] ); ?> vigilante-priority-<?php echo esc_attr( $rec['priority'] ); ?>"></span>
                            <?php echo esc_html( $rec['message'] ); ?>
                            <?php if ( ! empty( $rec['tab'] ) ) : ?>
                                <a href="<?php echo esc_url( admin_url( 'admin.php?page=vigilante&tab=' . $rec['tab'] ) ); ?>" class="vigilante-rec-link" title="<?php esc_attr_e( 'Go to settings', 'vigilante' ); ?>"><span class="dashicons dashicons-arrow-right-alt2"></span></a>
                            <?php endif; ?>
                        </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
                <?php endif; ?>
            </div>

            <?php $this->render_analyzer_widget( $analyzer_last_scan, $analyzer_history, $analyzer_categories_def, $analyzer_settings ); ?>

            <div class="vigilante-modules-grid">
                <h2><?php esc_html_e( 'Security Modules', 'vigilante' ); ?></h2>
                <p class="description"><?php esc_html_e( 'Enable or disable security modules. Each module controls a tab with detailed settings.', 'vigilante' ); ?></p>
                <div class="vigilante-modules-list">
                    <?php foreach ( $options['modules'] as $module => $enabled ) :
                        $label = isset( $module_labels[ $module ] ) ? $module_labels[ $module ] : ucwords( str_replace( '_', ' ', $module ) );
                        $description = isset( $module_descriptions[ $module ] ) ? $module_descriptions[ $module ] : '';
                        ?>
                        <div class="vigilante-module-item <?php echo $enabled ? 'enabled' : 'disabled'; ?>">
                            <div class="vigilante-module-header">
                                <span class="vigilante-module-status"></span>
                                <span class="vigilante-module-name"><?php echo esc_html( $label ); ?></span>
                                <label class="vigilante-toggle">
                                    <input type="checkbox" 
                                           name="modules[<?php echo esc_attr( $module ); ?>]" 
                                           value="1" 
                                           <?php checked( $enabled ); ?>
                                           data-module="<?php echo esc_attr( $module ); ?>">
                                    <span class="vigilante-toggle-slider"></span>
                                </label>
                            </div>
                            <?php if ( $description ) : ?>
                            <p class="vigilante-module-desc"><?php echo esc_html( $description ); ?></p>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <div class="vigilante-presets-card">
                <h2><?php esc_html_e( 'Quick Configuration Presets', 'vigilante' ); ?></h2>
                <p><?php esc_html_e( 'Apply a preset to quickly set up recommended settings for standard or maximum security level.', 'vigilante' ); ?></p>
                <div class="vigilante-presets-grid">
                    <?php foreach ( $presets as $preset_id => $preset ) : 
                        $is_active = ( $active_preset === $preset_id );
                    ?>
                    <div class="vigilante-preset-card <?php echo $is_active ? 'vigilante-preset-active' : ''; ?>">
                        <?php if ( $is_active ) : ?>
                        <span class="vigilante-active-indicator"><?php esc_html_e( 'Active', 'vigilante' ); ?></span>
                        <?php endif; ?>
                        <h3><?php echo esc_html( $preset['name'] ); ?></h3>
                        <p><?php echo esc_html( $preset['description'] ); ?></p>
                        <button type="button" class="button vigilante-preset-btn <?php echo $is_active ? 'button-primary' : ''; ?>" data-preset="<?php echo esc_attr( $preset_id ); ?>">
                            <?php esc_html_e( 'Apply Preset', 'vigilante' ); ?>
                        </button>
                    </div>
                    <?php endforeach; ?>

                    <?php
                    // Under Attack mode card
                    $under_attack        = new Vigilante_Under_Attack( $this->settings, $this->activity_log );
                    $ua_active           = $under_attack->is_active();
                    $ua_remaining        = $under_attack->get_remaining_time();
                    $ua_remaining_hours  = floor( $ua_remaining / 3600 );
                    $ua_remaining_mins   = floor( ( $ua_remaining % 3600 ) / 60 );
                    ?>
                    <div class="vigilante-preset-card vigilante-under-attack-card <?php echo $ua_active ? 'vigilante-under-attack-active' : ''; ?>">
                        <h3>
                            <span class="dashicons dashicons-shield"></span>
                            <?php esc_html_e( 'Under Attack', 'vigilante' ); ?>
                        </h3>
                        <p><?php esc_html_e( 'Emergency mode. JavaScript challenge for all visitors, aggressive rate limiting, and restricted access. Auto-deactivates after 4 hours.', 'vigilante' ); ?></p>
                        <?php if ( $ua_active ) : ?>
                        <div class="vigilante-ua-countdown" data-expires="<?php echo esc_attr( $under_attack->get_status()['activated_at'] + $under_attack->get_status()['duration'] ); ?>">
                            <span class="dashicons dashicons-clock"></span>
                            <span class="vigilante-ua-time">
                                <?php
                                printf(
                                    /* translators: 1: Hours, 2: Minutes */
                                    esc_html__( '%1$dh %2$dm remaining', 'vigilante' ),
                                    absint( $ua_remaining_hours ),
                                    absint( $ua_remaining_mins )
                                );
                                ?>
                            </span>
                        </div>
                        <button type="button" class="button vigilante-ua-btn vigilante-ua-deactivate">
                            <?php esc_html_e( 'Deactivate', 'vigilante' ); ?>
                        </button>
                        <?php else : ?>
                        <button type="button" class="button vigilante-ua-btn vigilante-ua-activate">
                            <?php esc_html_e( 'Activate for 4 hours', 'vigilante' ); ?>
                        </button>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render tools tab
     */
    private function render_tab_tools() {
        // Get current settings for notification summary
        $email_options     = $this->settings->get_section( 'email' );
        $login_options     = $this->settings->get_section( 'login_security' );
        $user_options      = $this->settings->get_section( 'user_security' );
        $fi_options        = $this->settings->get_section( 'file_integrity' );
        $monitoring        = $user_options['admin_monitoring'] ?? array();
        $registration      = $user_options['registration_approval'] ?? array();
        $current_admin     = get_option( 'admin_email' );
        $send_to_admin     = ! isset( $email_options['send_to_admin_email'] ) || ! empty( $email_options['send_to_admin_email'] );
        $additional_raw    = $email_options['additional_recipients'] ?? array();
        $additional        = is_array( $additional_raw ) ? implode( "\n", $additional_raw ) : trim( $additional_raw );
        ?>

        <!-- Notification Settings -->
        <div id="vigilante-section-tools-notifications" class="vigilante-settings-section vigilante-notification-section">
            <h2><?php esc_html_e( 'Notification settings', 'vigilante' ); ?></h2>
            <p><?php esc_html_e( 'Configure who receives all administrative email notifications from Vigilant. Individual notifications are enabled in their respective tabs.', 'vigilante' ); ?></p>

            <div class="vigilante-notification-layout">

                <!-- Left column: Recipients settings -->
                <div class="vigilante-notification-settings">
                    <form class="vigilante-settings-form" data-section="email">

                        <table class="form-table vigilante-compact-form">
                            <tr>
                                <th scope="row"><?php esc_html_e( 'WordPress Admin Email', 'vigilante' ); ?></th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="email[send_to_admin_email]" value="1" <?php checked( $send_to_admin ); ?>>
                                        <?php
                                        printf(
                                            /* translators: %s: Admin email address */
                                            esc_html__( 'Send to admin email (%s)', 'vigilante' ),
                                            '<code>' . esc_html( $current_admin ) . '</code>'
                                        );
                                        ?>
                                    </label>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row"><?php esc_html_e( 'Additional Recipients', 'vigilante' ); ?></th>
                                <td>
                                    <textarea name="email[additional_recipients]" rows="3" class="large-text code" placeholder="maintenance@example.com&#10;security@example.com"><?php echo esc_textarea( $additional ); ?></textarea>
                                    <p class="description"><?php esc_html_e( 'One email per line.', 'vigilante' ); ?></p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row"><?php esc_html_e( 'Plugin Deactivation', 'vigilante' ); ?></th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="email[send_deactivation_email]" value="1" <?php checked( ! empty( $email_options['send_deactivation_email'] ) ); ?>>
                                        <?php esc_html_e( 'Send email when Vigilant is deactivated', 'vigilante' ); ?>
                                    </label>
                                </td>
                            </tr>
                        </table>

                        <p class="submit vigilante-notification-submit">
                            <button type="submit" class="button button-primary vigilante-save-btn" data-original-text="<?php esc_attr_e( 'Save Settings', 'vigilante' ); ?>">
                                <?php esc_html_e( 'Save Settings', 'vigilante' ); ?>
                            </button>
                        </p>

                    </form>
                </div>

                <!-- Right column: Active notifications summary -->
                <div class="vigilante-notification-summary">
                    <h4><?php esc_html_e( 'Active notifications', 'vigilante' ); ?></h4>

                    <table class="widefat striped">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'Notification', 'vigilante' ); ?></th>
                                <th style="width: 1%; white-space: nowrap; text-align: center;"><?php esc_html_e( 'Status', 'vigilante' ); ?></th>
                                <th style="width: 50px; text-align: center;"></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            $notifications = array(
                                array(
                                    'label'  => __( 'Login lockout', 'vigilante' ),
                                    'active' => ! empty( $login_options['notify_on_lockout'] ),
                                    'tab'    => 'login',
                                ),
                                array(
                                    'label'  => __( 'Administrator login', 'vigilante' ),
                                    'active' => ! empty( $login_options['notify_on_admin_login'] ),
                                    'tab'    => 'login',
                                ),
                                array(
                                    'label'  => __( 'New administrator created', 'vigilante' ),
                                    'active' => ! empty( $monitoring['alert_new_admin'] ),
                                    'tab'    => 'users',
                                ),
                                array(
                                    'label'  => __( 'Administrator email changed', 'vigilante' ),
                                    'active' => ! empty( $monitoring['alert_admin_email_change'] ),
                                    'tab'    => 'users',
                                ),
                                array(
                                    'label'  => __( 'Permission elevation', 'vigilante' ),
                                    'active' => ! empty( $monitoring['alert_permission_elevation'] ),
                                    'tab'    => 'users',
                                ),
                                array(
                                    'label'  => __( 'Admin password changed', 'vigilante' ),
                                    'active' => ! empty( $monitoring['alert_admin_password_change'] ),
                                    'tab'    => 'users',
                                ),
                                array(
                                    'label'  => __( 'Registration pending approval', 'vigilante' ),
                                    'active' => ! empty( $registration['enabled'] ) && ! empty( $registration['notify_admin'] ),
                                    'tab'    => 'users',
                                ),
                                array(
                                    'label'  => __( 'File integrity scan report', 'vigilante' ),
                                    'active' => ( $fi_options['notify_level'] ?? 'disabled' ) !== 'disabled',
                                    'tab'    => 'file-integrity',
                                ),
                                array(
                                    'label'  => __( 'File integrity instant alert', 'vigilante' ),
                                    'active' => ! empty( $fi_options['instant_alert'] ),
                                    'tab'    => 'file-integrity',
                                ),
                                array(
                                    'label'  => __( 'Under Attack mode', 'vigilante' ),
                                    'active' => true,
                                    'tab'    => '',
                                    'note'   => __( 'Always active', 'vigilante' ),
                                ),
                                array(
                                    'label'  => __( 'Plugin deactivation', 'vigilante' ),
                                    'active' => ! empty( $email_options['send_deactivation_email'] ),
                                    'tab'    => 'tools',
                                ),
                            );

                            foreach ( $notifications as $notif ) :
                                $status_class = $notif['active'] ? 'vigilante-status-active' : 'vigilante-status-inactive';
                                $status_label = $notif['active'] ? __( 'Active', 'vigilante' ) : __( 'Inactive', 'vigilante' );
                                if ( ! empty( $notif['note'] ) ) {
                                    $status_label = $notif['note'];
                                }
                            ?>
                            <tr>
                                <td><?php echo esc_html( $notif['label'] ); ?></td>
                                <td style="text-align: center; white-space: nowrap;">
                                    <span class="<?php echo esc_attr( $status_class ); ?>"><?php echo esc_html( $status_label ); ?></span>
                                </td>
                                <td style="text-align: center;">
                                    <?php if ( ! empty( $notif['tab'] ) ) : ?>
                                        <a href="<?php echo esc_url( admin_url( 'admin.php?page=vigilante&tab=' . $notif['tab'] ) ); ?>" class="button button-small">
                                            <span class="dashicons dashicons-admin-generic" style="font-size: 14px; line-height: 1.8;"></span>
                                        </a>
                                    <?php else : ?>
                                        &mdash;
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

            </div>
        </div>

        <h2 id="vigilante-section-tools-main" class="vigilante-tools-heading"><?php esc_html_e( 'Tools', 'vigilante' ); ?></h2>

        <?php
        // Warn that during Under Attack mode the export/import operate against
        // the temporary hardened config and any imported changes will be
        // reverted when the mode ends.
        $ua_status = get_option( Vigilante_Under_Attack::OPTION_NAME, array() );
        if ( ! empty( $ua_status['active'] ) ) :
            ?>
            <div class="vigilante-ua-tools-notice-wrap">
                <div class="notice notice-warning inline vigilante-ua-tools-notice">
                    <p>
                        <strong><?php esc_html_e( 'Under Attack mode is active.', 'vigilante' ); ?></strong>
                        <?php esc_html_e( 'Exports will reflect the temporary hardened configuration, not your saved one. Imports will apply on top of the hardened config and will be reverted when the mode ends. Consider waiting until you deactivate Under Attack before exporting or importing settings.', 'vigilante' ); ?>
                    </p>
                </div>
            </div>
            <?php
        endif;
        ?>

        <div class="vigilante-tools-grid">
            <div class="vigilante-tool-card">
                <h3><?php esc_html_e( 'Export Settings', 'vigilante' ); ?></h3>
                <p><?php esc_html_e( 'Download your current security settings as a JSON file.', 'vigilante' ); ?></p>
                <button type="button" class="button vigilante-export-settings">
                    <?php esc_html_e( 'Export Settings', 'vigilante' ); ?>
                </button>
            </div>

            <div class="vigilante-tool-card">
                <h3><?php esc_html_e( 'Import Settings', 'vigilante' ); ?></h3>
                <p><?php esc_html_e( 'Import settings from a previously exported JSON file.', 'vigilante' ); ?></p>
                <input type="file" id="vigilante-import-file" accept=".json" style="display: none;">
                <button type="button" class="button vigilante-import-settings">
                    <?php esc_html_e( 'Import Settings', 'vigilante' ); ?>
                </button>
            </div>

            <div class="vigilante-tool-card">
                <h3><?php esc_html_e( 'Reset to Defaults', 'vigilante' ); ?></h3>
                <p><?php esc_html_e( 'Reset all the Vigilant security settings to default values.', 'vigilante' ); ?></p>
                <button type="button" class="button vigilante-reset-settings" style="color: #a00;">
                    <?php esc_html_e( 'Reset All Settings', 'vigilante' ); ?>
                </button>
            </div>

            <div class="vigilante-tool-card">
                <h3><?php esc_html_e( 'Create Backup', 'vigilante' ); ?></h3>
                <p><?php esc_html_e( 'Create a backup of .htaccess and wp-config.php files before making security changes. Backups are stored in wp-content/vigilante-backups/ and will be deleted if the plugin is uninstalled.', 'vigilante' ); ?></p>
                <button type="button" class="button vigilante-create-backup">
                    <?php esc_html_e( 'Create Backup Now', 'vigilante' ); ?>
                </button>
            </div>

            <div class="vigilante-tool-card vigilante-tool-card-wide">
                <h3><?php esc_html_e( 'Database Backup', 'vigilante' ); ?></h3>
                <p><?php esc_html_e( 'Download a backup of your database as a ZIP file. Select which tables to include.', 'vigilante' ); ?></p>
                <button type="button" class="button vigilante-db-backup-toggle">
                    <?php esc_html_e( 'Download Database Backup', 'vigilante' ); ?>
                </button>

                <div class="vigilante-db-backup-panel" style="display: none;">
                    <div class="vigilante-db-tables-loading">
                        <span class="spinner is-active"></span>
                        <?php esc_html_e( 'Loading tables...', 'vigilante' ); ?>
                    </div>

                    <div class="vigilante-db-tables-content" style="display: none;">
                        <div class="vigilante-db-tables-controls">
                            <label>
                                <input type="checkbox" id="vigilante-db-select-all" checked>
                                <strong><?php esc_html_e( 'Select / deselect all', 'vigilante' ); ?></strong>
                            </label>
                            <span class="vigilante-db-tables-info"></span>
                        </div>

                        <div class="vigilante-db-tables-group">
                            <h4><?php esc_html_e( 'WordPress core tables', 'vigilante' ); ?></h4>
                            <div class="vigilante-db-tables-list" id="vigilante-db-core-tables"></div>
                        </div>

                        <div class="vigilante-db-tables-group" id="vigilante-db-other-group" style="display: none;">
                            <h4><?php esc_html_e( 'Plugin and custom tables', 'vigilante' ); ?></h4>
                            <div class="vigilante-db-tables-list" id="vigilante-db-other-tables"></div>
                        </div>

                        <div class="vigilante-db-backup-actions">
                            <button type="button" class="button button-primary vigilante-db-backup-download">
                                <?php esc_html_e( 'Download Backup (.zip)', 'vigilante' ); ?>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render firewall tab
     */
    private function render_tab_firewall() {
        $is_disabled = $this->render_module_disabled_notice( 'firewall' );
        $options = $this->settings->get_section( 'firewall' );
        ?>
        <form class="vigilante-settings-form <?php echo $is_disabled ? 'vigilante-form-disabled' : ''; ?>" data-section="firewall" <?php echo $is_disabled ? 'inert' : ''; ?>>
            <div id="vigilante-section-firewall-main" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Firewall Protection', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'PHP-based request filtering. Analyzes each request before WordPress loads.', 'vigilante' ); ?></p>
                <div class="notice notice-info inline" style="margin:10px 0 16px;padding:8px 12px;">
                    <p style="margin:0;">
                        <?php esc_html_e( 'Full page caching systems that serve cached pages before PHP executes (Varnish, LiteSpeed Cache, NGINX FastCGI Cache, Cloudflare APO) may bypass PHP-level firewall rules for cached requests. The .htaccess rules will still apply on Apache/LiteSpeed servers.', 'vigilante' ); ?>
                    </p>
                </div>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Block Bad Query Strings', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[block_bad_query_strings]" value="1" <?php checked( ! empty( $options['block_bad_query_strings'] ) ); ?>>
                                <?php esc_html_e( 'Block malicious query string patterns', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'SQL Injection Protection', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[block_sql_injection]" value="1" <?php checked( ! empty( $options['block_sql_injection'] ) ); ?>>
                                <?php esc_html_e( 'Block SQL injection attempts', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'XSS Protection', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[block_xss_attacks]" value="1" <?php checked( ! empty( $options['block_xss_attacks'] ) ); ?>>
                                <?php esc_html_e( 'Block cross-site scripting attacks', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'File Inclusion Protection', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[block_file_inclusion]" value="1" <?php checked( ! empty( $options['block_file_inclusion'] ) ); ?>>
                                <?php esc_html_e( 'Block local/remote file inclusion attempts', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Directory Traversal Protection', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[block_directory_traversal]" value="1" <?php checked( ! empty( $options['block_directory_traversal'] ) ); ?>>
                                <?php esc_html_e( 'Block path traversal attempts', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Block Bad Bots', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[block_bad_bots]" value="1" <?php checked( ! empty( $options['block_bad_bots'] ) ); ?>>
                                <?php esc_html_e( 'Block known malicious bots and scanners', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e( 'Rate Limiting', 'vigilante' ); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable Rate Limiting', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[rate_limiting][enabled]" value="1" <?php checked( ! empty( $options['rate_limiting']['enabled'] ) ); ?>>
                                <?php esc_html_e( 'Limit requests per IP address', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Requests per Minute', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="firewall[rate_limiting][requests_per_minute]" value="<?php echo esc_attr( $options['rate_limiting']['requests_per_minute'] ?? 120 ); ?>" min="10" max="500" class="small-text">
                            <p class="description">
                                <?php esc_html_e( 'Counts only PHP requests to WordPress (pages, admin-ajax, REST, login) from a single IP, not static assets like images, CSS or JS. 120/min suits most sites; sustained traffic above that from one IP is usually a bot. To allow a legitimate service, whitelist its IP instead of raising the limit.', 'vigilante' ); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Block Duration (seconds)', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="firewall[rate_limiting][block_duration]" value="<?php echo esc_attr( $options['rate_limiting']['block_duration'] ?? 300 ); ?>" min="60" max="3600" class="small-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Progressive Blocking', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[rate_limiting][progressive]" value="1" <?php checked( ! empty( $options['rate_limiting']['progressive'] ) ); ?>>
                                <?php esc_html_e( 'Double block duration on each repeat offense', 'vigilante' ); ?>
                            </label>
                            <p class="description">
                                <?php
                                $base = absint( $options['rate_limiting']['block_duration'] ?? 300 );
                                printf(
                                    /* translators: 1: First block duration, 2: Second, 3: Third */
                                    esc_html__( 'Example: %1$s → %2$s → %3$s and so on, up to the maximum.', 'vigilante' ),
                                    esc_html( human_time_diff( 0, $base ) ),
                                    esc_html( human_time_diff( 0, $base * 2 ) ),
                                    esc_html( human_time_diff( 0, $base * 4 ) )
                                );
                                ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Maximum Block Duration', 'vigilante' ); ?></th>
                        <td>
                            <select name="firewall[rate_limiting][max_block_duration]">
                                <?php
                                $max_options = array(
                                    3600   => __( '1 hour', 'vigilante' ),
                                    21600  => __( '6 hours', 'vigilante' ),
                                    43200  => __( '12 hours', 'vigilante' ),
                                    86400  => __( '24 hours', 'vigilante' ),
                                    604800 => __( '7 days', 'vigilante' ),
                                );
                                $current_max = absint( $options['rate_limiting']['max_block_duration'] ?? 86400 );
                                foreach ( $max_options as $val => $label ) :
                                    ?>
                                    <option value="<?php echo esc_attr( $val ); ?>" <?php selected( $current_max, $val ); ?>>
                                        <?php echo esc_html( $label ); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                            <p class="description"><?php esc_html_e( 'Upper limit for progressive blocking.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                </table>

                <?php
                // Currently blocked IPs from rate limiting
                $active_blocks = Vigilante_Firewall::get_active_blocks();
                if ( ! empty( $active_blocks ) ) :
                ?>
                <div class="vigilante-settings-section vigilante-lockout-section" style="margin-top:20px;">
                    <h3><?php esc_html_e( 'Currently Blocked IPs', 'vigilante' ); ?></h3>
                    <table class="wp-list-table widefat fixed striped" style="max-width:800px;">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'IP Address', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Blocked', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Expires in', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Strikes', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Action', 'vigilante' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $active_blocks as $blocked_ip => $block_data ) : ?>
                                <tr>
                                    <td><code><?php echo esc_html( $blocked_ip ); ?></code></td>
                                    <td><?php echo esc_html( human_time_diff( $block_data['blocked_at'] ) . ' ' . __( 'ago', 'vigilante' ) ); ?></td>
                                    <td><?php echo esc_html( human_time_diff( time(), $block_data['expires'] ) ); ?></td>
                                    <td><?php echo esc_html( $block_data['strikes'] ?? 1 ); ?></td>
                                    <td>
                                        <button type="button" class="button button-small vigilante-unblock-firewall-ip"
                                            data-ip="<?php echo esc_attr( $blocked_ip ); ?>">
                                            <?php esc_html_e( 'Unblock', 'vigilante' ); ?>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <?php endif; ?>

                <h3><?php esc_html_e( 'IP Lists', 'vigilante' ); ?></h3>
                <p class="description">
                    <?php
                    printf(
                        /* translators: %s: Current visitor IP address */
                        esc_html__( 'Your current IP address: %s', 'vigilante' ),
                        '<code>' . esc_html( $this->database->get_client_ip() ) . '</code>'
                    );
                    ?>
                </p>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'IP Whitelist', 'vigilante' ); ?></th>
                        <td>
                            <textarea name="firewall[ip_whitelist]" rows="4" class="large-text code" placeholder="192.168.1.50&#10;192.168.1.0/24&#10;192.168.1.*"><?php echo esc_textarea( implode( "\n", $options['ip_whitelist'] ?? array() ) ); ?></textarea>
                            <p class="description">
                                <?php esc_html_e( 'One IP per line. These IPs will bypass firewall checks.', 'vigilante' ); ?>
                                <br>
                                <?php
                                printf(
                                    /* translators: 1: opening <code>, 2: closing </code>. Placeholders wrap the IP, CIDR and wildcard examples. */
                                    esc_html__( 'Accepts exact IPs (%1$s192.168.1.50%2$s), CIDR ranges (%1$s192.168.1.0/24%2$s, IPv4 only), and wildcards with %1$s*%2$s (e.g. %1$s192.168.1.*%2$s).', 'vigilante' ),
                                    '<code>',
                                    '</code>'
                                ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML tags are hardcoded.
                                ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'IP Blacklist', 'vigilante' ); ?></th>
                        <td>
                            <textarea name="firewall[ip_blacklist]" rows="4" class="large-text code" placeholder="203.0.113.42&#10;203.0.113.0/24&#10;203.0.113.*"><?php echo esc_textarea( implode( "\n", $options['ip_blacklist'] ?? array() ) ); ?></textarea>
                            <p class="description">
                                <?php esc_html_e( 'One IP per line. These IPs will be blocked immediately.', 'vigilante' ); ?>
                                <br>
                                <?php
                                printf(
                                    /* translators: 1: opening <code>, 2: closing </code>. Placeholders wrap the IP, CIDR and wildcard examples. */
                                    esc_html__( 'Accepts exact IPs (%1$s203.0.113.42%2$s), CIDR ranges (%1$s203.0.113.0/24%2$s, IPv4 only), and wildcards with %1$s*%2$s (e.g. %1$s203.0.113.*%2$s).', 'vigilante' ),
                                    '<code>',
                                    '</code>'
                                ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML tags are hardcoded.
                                ?>
                            </p>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e( 'User-Agent Lists', 'vigilante' ); ?></h3>
                <p><?php esc_html_e( 'Partial matching: enter a keyword and any User-Agent containing it will be matched.', 'vigilante' ); ?></p>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'User-Agent Whitelist', 'vigilante' ); ?></th>
                        <td>
                            <textarea name="firewall[ua_whitelist]" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", $options['ua_whitelist'] ?? array() ) ); ?></textarea>
                            <p class="description"><?php esc_html_e( 'One User-Agent per line. These will bypass all firewall checks. Example: ManageWP, MainWP, UptimeRobot.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'User-Agent Blacklist', 'vigilante' ); ?></th>
                        <td>
                            <textarea name="firewall[ua_blacklist]" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", $options['ua_blacklist'] ?? array() ) ); ?></textarea>
                            <p class="description"><?php esc_html_e( 'One User-Agent per line. These will be blocked immediately.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <div id="vigilante-section-firewall-server" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Server Protection', 'vigilante' ); ?>
                    <span class="vigilante-method-badge htaccess"><?php esc_html_e( 'HTACCESS', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Server-level rules for Apache/LiteSpeed. These rules are processed before PHP.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr id="field-disable-directory-browsing">
                        <th scope="row"><?php esc_html_e( 'Directory Browsing', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[disable_directory_browsing]" value="1" <?php checked( ! empty( $options['disable_directory_browsing'] ) ); ?>>
                                <?php esc_html_e( 'Disable directory listing (Options -Indexes)', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Protect wp-config.php', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[protect_wp_config]" value="1" <?php checked( ! empty( $options['protect_wp_config'] ) ); ?>>
                                <?php esc_html_e( 'Block direct HTTP access to wp-config.php', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr id="field-protect-wp-cron">
                        <th scope="row"><?php esc_html_e( 'Protect wp-cron.php', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[protect_wp_cron]" value="1" <?php checked( ! empty( $options['protect_wp_cron'] ) ); ?>>
                                <?php esc_html_e( 'Block direct HTTP access to wp-cron.php (prevents cron-spam DoS abuse)', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php
                                printf(
                                    /* translators: 1: opening <strong>, 2: closing </strong> */
                                    esc_html__( '%1$sWarning:%2$s Only enable if your host runs a real server-side cron job calling wp-cron.php (most managed WordPress hosts do; check with your provider). Otherwise scheduled tasks — publishing, updates, emails, backups — stop running. Pair with %3$sDISABLE_WP_CRON%4$s in WP Hardening for full coverage.', 'vigilante' ),
                                    '<strong>',
                                    '</strong>',
                                    '<code>',
                                    '</code>'
                                ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML tags are hardcoded.
                            ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Protect wp-includes', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[protect_wp_includes]" value="1" <?php checked( ! empty( $options['protect_wp_includes'] ) ); ?>>
                                <?php esc_html_e( 'Block direct access to PHP files in wp-includes', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'PHP in Uploads', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[protect_uploads_php]" value="1" <?php checked( ! empty( $options['protect_uploads_php'] ) ); ?>>
                                <?php esc_html_e( 'Block PHP execution in wp-content/uploads', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Sensitive Files', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[protect_sensitive_files]" value="1" <?php checked( ! empty( $options['protect_sensitive_files'] ) ); ?>>
                                <?php esc_html_e( 'Block access to .sql, .bak, .log, .ini, readme.html, license.txt, licencia.txt', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Limit HTTP Methods', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="firewall[limit_http_methods]" value="1" <?php checked( ! empty( $options['limit_http_methods'] ) ); ?>>
                                <?php esc_html_e( 'Allow only GET, POST, HEAD (blocks PUT, DELETE, TRACE, etc.)', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <p class="submit vigilante-submit-buttons">
                <button type="submit" class="button button-primary vigilante-save-btn" data-original-text="<?php esc_attr_e( 'Save Settings', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Save Settings', 'vigilante' ); ?>
                </button>
                <button type="button" class="button vigilante-reset-section-btn" data-original-text="<?php esc_attr_e( 'Reset to Defaults', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Reset to Defaults', 'vigilante' ); ?>
                </button>
            </p>
        </form>
        <?php
    }

    /**
     * Render login security tab
     */
    private function render_tab_login() {
        $is_disabled = $this->render_module_disabled_notice( 'login_security' );
        $options = $this->settings->get_section( 'login_security' );
        $lockouts = $this->database->get_active_lockouts();
        ?>
        <form class="vigilante-settings-form <?php echo $is_disabled ? 'vigilante-form-disabled' : ''; ?>" data-section="login_security" <?php echo $is_disabled ? 'inert' : ''; ?>>
            <div id="vigilante-section-login-main" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Login Protection', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                    <span class="vigilante-method-badge database"><?php esc_html_e( 'Database', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Brute force protection and WordPress login hardening.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr id="field-max-attempts">
                        <th scope="row"><?php esc_html_e( 'Max Login Attempts', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="login_security[max_attempts]" value="<?php echo esc_attr( $options['max_attempts'] ?? 5 ); ?>" min="1" max="20" class="small-text">
                            <p class="description"><?php esc_html_e( 'Number of failed attempts before lockout.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Lockout Duration', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="login_security[lockout_duration]" value="<?php echo esc_attr( ( $options['lockout_duration'] ?? 1800 ) / 60 ); ?>" min="1" max="1440" class="small-text">
                            <?php esc_html_e( 'minutes', 'vigilante' ); ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Progressive Lockout', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="login_security[lockout_increment]" value="1" <?php checked( ! empty( $options['lockout_increment'] ) ); ?>>
                                <?php esc_html_e( 'Double lockout duration for repeat offenders', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Hide Login Errors', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="login_security[hide_login_errors]" value="1" <?php checked( ! empty( $options['hide_login_errors'] ) ); ?>>
                                <?php esc_html_e( 'Show generic error message instead of specific errors', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr id="field-disable-xmlrpc">
                        <th scope="row"><?php esc_html_e( 'Disable XML-RPC', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="login_security[disable_xmlrpc]" value="1" <?php checked( ! empty( $options['disable_xmlrpc'] ) ); ?>>
                                <?php esc_html_e( 'Completely disable XML-RPC functionality', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Disable Application Passwords', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="login_security[disable_application_passwords]" value="1" <?php checked( ! empty( $options['disable_application_passwords'] ) ); ?>>
                                <?php esc_html_e( 'Disable WordPress application passwords feature', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e( 'Custom Login URL', 'vigilante' ); ?></h3>
                <table class="form-table">
                    <tr id="field-custom-login-url">
                        <th scope="row"><?php esc_html_e( 'Login URL Slug', 'vigilante' ); ?></th>
                        <td>
                            <code><?php echo esc_url( home_url( '/' ) ); ?></code>
                            <input type="text" name="login_security[custom_login_url]" id="vigilante_custom_login_url" value="<?php echo esc_attr( $options['custom_login_url'] ?? '' ); ?>" class="regular-text" placeholder="<?php esc_attr_e( 'my-secret-login', 'vigilante' ); ?>">
                            <p class="description">
                                <?php esc_html_e( '&#9432; Leave empty to use default wp-login.php. Use only lowercase letters, numbers and hyphens.', 'vigilante' ); ?>
                            </p>
                            <div class="vigilante-login-url-preview" <?php echo empty( $options['custom_login_url'] ) ? 'style="display:none;"' : ''; ?>>
                                <p class="description">
                                    <strong><?php esc_html_e( 'Your login URL:', 'vigilante' ); ?></strong> 
                                    <code class="vigilante-login-url-display"><?php echo esc_url( home_url( sanitize_title( $options['custom_login_url'] ?? '' ) . '/' ) ); ?></code>
                                </p>
                                <p class="description">
                                    <?php esc_html_e( 'Direct access to wp-login.php and wp-admin will return a 404 error for non-logged users.', 'vigilante' ); ?>
                                </p>
                            </div>
                        </td>
                    </tr>
                </table>

                <div class="vigilante-login-url-notify-wrapper <?php echo empty( $options['custom_login_url'] ) ? 'vigilante-login-url-notify-disabled' : ''; ?>">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Notify users', 'vigilante' ); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="login_security[notify_on_login_url_change]" id="vigilante_notify_login_url_change" value="1" <?php checked( $options['notify_on_login_url_change'] ?? true ); ?>>
                                    <?php esc_html_e( 'Notify affected users when the login URL changes', 'vigilante' ); ?>
                                </label>
                                <div class="vigilante-login-url-send-notification" style="margin-top:12px;">
                                    <button type="button" id="vigilante_notify_login_url" class="button">
                                        <?php esc_html_e( 'Send notification now', 'vigilante' ); ?>
                                    </button>
                                    <span class="vigilante-login-url-notify-status"></span>
                                    <p class="description"><?php esc_html_e( 'Sends the new URL to administrators, editors, authors, and contributors.', 'vigilante' ); ?></p>
                                </div>
                            </td>
                        </tr>
                    </table>
                </div>

                <?php $this->render_2fa_settings( $options ); ?>

                <h3><?php esc_html_e( 'Notifications', 'vigilante' ); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Notify on Lockout', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="login_security[notify_on_lockout]" value="1" <?php checked( ! empty( $options['notify_on_lockout'] ) ); ?>>
                                <?php esc_html_e( 'Send email when an IP is locked out', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Notify on Admin Login', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="login_security[notify_on_admin_login]" value="1" <?php checked( ! empty( $options['notify_on_admin_login'] ) ); ?>>
                                <?php esc_html_e( 'Send email when an administrator logs in', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <p class="description">
                    <?php
                    printf(
                        /* translators: %s: Link to notification settings */
                        esc_html__( '&#9432; Notifications are sent to the recipients configured in %s.', 'vigilante' ),
                        '<a href="' . esc_url( admin_url( 'admin.php?page=vigilante&tab=tools' ) ) . '">' . esc_html__( 'Settings & Tools', 'vigilante' ) . '</a>'
                    );
                    ?>
                </p>
            </div>

            <p class="submit vigilante-submit-buttons">
                <button type="submit" class="button button-primary vigilante-save-btn" data-original-text="<?php esc_attr_e( 'Save Settings', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Save Settings', 'vigilante' ); ?>
                </button>
                <button type="button" class="button vigilante-reset-section-btn" data-original-text="<?php esc_attr_e( 'Reset to Defaults', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Reset to Defaults', 'vigilante' ); ?>
                </button>
            </p>
        </form>

        <?php $this->render_lockout_info_section( $options, $lockouts ); ?>
        <?php
    }

    /**
     * Render lockout information and blocked IPs section
     *
     * @param array $options  Login security options.
     * @param array $lockouts Currently locked out IPs.
     */
    private function render_lockout_info_section( $options, $lockouts ) {
        $max_attempts      = absint( $options['max_attempts'] ?? 5 );
        $lockout_duration  = absint( $options['lockout_duration'] ?? 1800 );
        $lockout_increment = ! empty( $options['lockout_increment'] );
        $max_lockout       = absint( $options['max_lockout_duration'] ?? 86400 );
        $two_factor        = $options['two_factor'] ?? array();
        $two_factor_enabled = ! empty( $two_factor['enabled'] );
        ?>
        <div class="vigilante-settings-section vigilante-lockout-section">
            <h2><?php esc_html_e( 'Login Protection Status', 'vigilante' ); ?></h2>
            
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e( 'Current settings', 'vigilante' ); ?></th>
                    <td>
                        <?php 
                        printf(
                            /* translators: 1: Maximum login attempts, 2: Lockout duration in minutes */
                            esc_html__( 'After %1$d failed login attempts, the IP address is blocked for %2$d minutes.', 'vigilante' ),
                            absint( $max_attempts ),
                            absint( ceil( $lockout_duration / 60 ) )
                        );
                        
                        if ( $lockout_increment ) {
                            echo '<br>';
                            printf(
                                /* translators: %d: Maximum lockout duration in hours */
                                esc_html__( 'Progressive lockout enabled (max: %d hours).', 'vigilante' ),
                                absint( ceil( $max_lockout / 3600 ) )
                            );
                        }
                        
                        if ( $two_factor_enabled ) {
                            echo '<br>';
                            esc_html_e( 'Failed 2FA codes also count toward the lockout limit.', 'vigilante' );
                        }
                        ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Blocked IPs', 'vigilante' ); ?></th>
                    <td>
                        <?php if ( ! empty( $lockouts ) ) : ?>
                        <div class="vigilante-paginated-section">
                        <div class="vigilante-fi-pagination-wrap"></div>
                        <table class="wp-list-table widefat fixed striped vigilante-fi-paginated">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e( 'IP Address', 'vigilante' ); ?></th>
                                    <th><?php esc_html_e( 'Attempts', 'vigilante' ); ?></th>
                                    <th><?php esc_html_e( 'Blocked Until', 'vigilante' ); ?></th>
                                    <th><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ( $lockouts as $lockout ) : 
                                    $lockout_time = strtotime( $lockout->locked_until );
                                    $remaining_seconds = $lockout_time - time();
                                    $remaining_text = $this->format_remaining_time( $remaining_seconds );
                                ?>
                                <tr>
                                    <td><code><?php echo esc_html( $lockout->ip_address ); ?></code></td>
                                    <td><?php echo esc_html( $lockout->attempts ); ?></td>
                                    <td>
                                        <?php echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $lockout_time ) ); ?>
                                        <br>
                                        <small class="description">
                                            <?php 
                                            printf(
                                                /* translators: %s: Remaining time */
                                                esc_html__( '%s remaining', 'vigilante' ),
                                                esc_html( $remaining_text )
                                            ); 
                                            ?>
                                        </small>
                                    </td>
                                    <td>
                                        <button type="button" class="button button-small vigilante-clear-lockout" data-ip="<?php echo esc_attr( $lockout->ip_address ); ?>">
                                            <?php esc_html_e( 'Unblock', 'vigilante' ); ?>
                                        </button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                        </div>
                        <p class="description" style="margin-top: 10px;">
                            <button type="button" class="button vigilante-clear-all-lockouts">
                                <?php esc_html_e( 'Unblock All IPs', 'vigilante' ); ?>
                            </button>
                            <span style="margin-left: 10px;">
                                <?php 
                                printf(
                                    /* translators: %d: Number of blocked IPs */
                                    esc_html( _n( '%d IP currently blocked', '%d IPs currently blocked', count( $lockouts ), 'vigilante' ) ),
                                    count( $lockouts )
                                ); 
                                ?>
                            </span>
                        </p>
                        <?php else : ?>
                        <span class="dashicons dashicons-yes-alt" style="color: #00a32a; font-size: 20px; width: 20px; height: 20px; vertical-align: middle;"></span>
                        <span style="vertical-align: middle; margin-left: 5px;"><?php esc_html_e( 'No IPs are currently blocked. All clear!', 'vigilante' ); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
            </table>
        </div>
        <?php
    }

    /**
     * Format remaining lockout time in human readable format
     *
     * @param int $seconds Remaining seconds.
     * @return string Formatted time string.
     */
    private function format_remaining_time( $seconds ) {
        if ( $seconds <= 0 ) {
            return __( 'expired', 'vigilante' );
        }

        if ( $seconds < 60 ) {
            return sprintf(
                /* translators: %d: Number of seconds */
                _n( '%d second', '%d seconds', $seconds, 'vigilante' ),
                $seconds
            );
        }

        if ( $seconds < 3600 ) {
            $minutes = ceil( $seconds / 60 );
            return sprintf(
                /* translators: %d: Number of minutes */
                _n( '%d minute', '%d minutes', $minutes, 'vigilante' ),
                $minutes
            );
        }

        $hours = floor( $seconds / 3600 );
        $remaining_minutes = ceil( ( $seconds % 3600 ) / 60 );
        
        if ( $remaining_minutes > 0 ) {
            return sprintf(
                /* translators: 1: Number of hours, 2: Number of minutes */
                __( '%1$d hours %2$d minutes', 'vigilante' ),
                $hours,
                $remaining_minutes
            );
        }

        return sprintf(
            /* translators: %d: Number of hours */
            _n( '%d hour', '%d hours', $hours, 'vigilante' ),
            $hours
        );
    }

    /**
     * Render 2FA settings section
     *
     * @param array $options Login security options.
     */
    private function render_2fa_settings( $options ) {
        $two_factor = $options['two_factor'] ?? array();
        $all_roles  = wp_roles()->roles;
        $enforced   = $two_factor['enforced_roles'] ?? array( 'administrator', 'editor' );
        $excluded   = $two_factor['excluded_users'] ?? array();
        $method     = $two_factor['method'] ?? 'email';
        $grace_days = $two_factor['grace_period_days'] ?? 3;
        ?>
        <h3>
            <?php esc_html_e( 'Two-Factor Authentication (2FA)', 'vigilante' ); ?>
            <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
            <span class="vigilante-method-badge database"><?php esc_html_e( 'Database', 'vigilante' ); ?></span>
        </h3>
        <p class="description"><?php esc_html_e( 'Require a second verification step after password. Choose between email codes or an authenticator app (TOTP).', 'vigilante' ); ?></p>
        
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Enable 2FA', 'vigilante' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="login_security[two_factor][enabled]" id="vigilante_2fa_enabled" value="1" <?php checked( ! empty( $two_factor['enabled'] ) ); ?>>
                        <?php esc_html_e( 'Enable two-factor authentication', 'vigilante' ); ?>
                    </label>
                </td>
            </tr>
        </table>

        <div class="vigilante-2fa-settings-wrapper <?php echo empty( $two_factor['enabled'] ) ? 'vigilante-2fa-settings-disabled' : ''; ?>">
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e( 'Verification method', 'vigilante' ); ?></th>
                    <td>
                        <fieldset class="vigilante-2fa-method-selector">
                            <label class="vigilante-2fa-method-option <?php echo 'email' === $method ? 'selected' : ''; ?>">
                                <input type="radio" name="login_security[two_factor][method]" value="email" <?php checked( $method, 'email' ); ?>>
                                <span class="dashicons dashicons-email"></span>
                                <span class="method-info">
                                    <strong><?php esc_html_e( 'Email code', 'vigilante' ); ?></strong>
                                    <span><?php esc_html_e( 'Users receive a 6-digit code via email after entering their password.', 'vigilante' ); ?></span>
                                </span>
                            </label>
                            <label class="vigilante-2fa-method-option <?php echo 'totp' === $method ? 'selected' : ''; ?>">
                                <input type="radio" name="login_security[two_factor][method]" value="totp" <?php checked( $method, 'totp' ); ?>>
                                <span class="dashicons dashicons-smartphone"></span>
                                <span class="method-info">
                                    <strong><?php esc_html_e( 'Authenticator app (TOTP)', 'vigilante' ); ?></strong>
                                    <span><?php esc_html_e( 'Users verify with a time-based code from Google Authenticator, Authy, etc.', 'vigilante' ); ?></span>
                                </span>
                            </label>
                        </fieldset>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Enforce for roles', 'vigilante' ); ?></th>
                    <td>
                        <div class="vigilante-2fa-roles">
                            <?php foreach ( $all_roles as $role_slug => $role_data ) : 
                                $user_count = count( get_users( array( 'role' => $role_slug, 'fields' => 'ID' ) ) );
                            ?>
                            <label>
                                <input type="checkbox" 
                                       name="login_security[two_factor][enforced_roles][]" 
                                       value="<?php echo esc_attr( $role_slug ); ?>"
                                       <?php checked( in_array( $role_slug, $enforced, true ) ); ?>>
                                <span class="role-name"><?php echo esc_html( translate_user_role( $role_data['name'] ) ); ?></span>
                                <span class="role-count">(<?php echo esc_html( $user_count ); ?>)</span>
                            </label>
                            <?php endforeach; ?>
                        </div>
                        <p class="description"><?php esc_html_e( 'Users with these roles will be required to verify with the selected method.', 'vigilante' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Exclude specific users', 'vigilante' ); ?></th>
                    <td>
                        <div class="vigilante-2fa-user-search-container">
                            <div class="vigilante-2fa-user-search">
                                <span class="search-icon"></span>
                                <input type="text" 
                                       id="vigilante_2fa_user_search" 
                                       placeholder="<?php esc_attr_e( 'Search users by name or email...', 'vigilante' ); ?>"
                                       autocomplete="off">
                                <div class="vigilante-2fa-search-results"></div>
                            </div>
                            <div class="vigilante-2fa-excluded-users">
                                <?php 
                                foreach ( $excluded as $user_id ) :
                                    $user = get_user_by( 'ID', $user_id );
                                    if ( ! $user ) continue;
                                ?>
                                <div class="vigilante-2fa-excluded-user" data-user-id="<?php echo esc_attr( $user_id ); ?>">
                                    <span class="user-display"><?php echo esc_html( $user->display_name . ' (' . $user->user_email . ')' ); ?></span>
                                    <button type="button" class="remove-user" aria-label="<?php esc_attr_e( 'Remove', 'vigilante' ); ?>">&times;</button>
                                    <input type="hidden" name="login_security[two_factor][excluded_users][]" value="<?php echo esc_attr( $user_id ); ?>">
                                </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        <p class="description"><?php esc_html_e( 'These users will not be required to use 2FA regardless of their role.', 'vigilante' ); ?></p>
                    </td>
                </tr>

                <!-- Remember device option -->
                <tr>
                    <th scope="row"><?php esc_html_e( 'Remember device', 'vigilante' ); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="login_security[two_factor][allow_remember_device]" value="1" <?php checked( ! empty( $two_factor['allow_remember_device'] ) ); ?>>
                            <?php esc_html_e( 'Allow users to skip 2FA verification on trusted devices', 'vigilante' ); ?>
                        </label>
                        <p class="description">
                            <?php
                            printf(
                                /* translators: %d: Number of days */
                                esc_html__( 'When enabled, users can check "Remember this device" on the verification screen to skip 2FA for %d days.', 'vigilante' ),
                                absint( $two_factor['remember_device_days'] ?? 30 )
                            );
                            ?>
                        </p>
                    </td>
                </tr>

                <!-- TOTP-specific: Grace period -->
                <tr class="vigilante-2fa-totp-only" <?php echo 'totp' !== $method ? 'style="display:none;"' : ''; ?>>
                    <th scope="row"><?php esc_html_e( 'Grace period', 'vigilante' ); ?></th>
                    <td>
                        <input type="number" 
                               name="login_security[two_factor][grace_period_days]" 
                               value="<?php echo esc_attr( $grace_days ); ?>" 
                               min="0" max="30" class="small-text">
                        <?php esc_html_e( 'days', 'vigilante' ); ?>
                        <p class="description"><?php esc_html_e( 'Days users have to set up their authenticator app. During this period they can log in without TOTP. Set to 0 for immediate enforcement.', 'vigilante' ); ?></p>
                    </td>
                </tr>

                <!-- Email-specific: Sender name -->
                <tr class="vigilante-2fa-email-only" <?php echo 'email' !== $method ? 'style="display:none;"' : ''; ?>>
                    <th scope="row"><?php esc_html_e( 'Email sender name', 'vigilante' ); ?></th>
                    <td>
                        <input type="text" 
                               name="login_security[two_factor][email_from_name]" 
                               value="<?php echo esc_attr( $two_factor['email_from_name'] ?? '' ); ?>" 
                               class="regular-text vigilante-2fa-email-from"
                               placeholder="<?php echo esc_attr( get_bloginfo( 'name' ) ); ?>">
                        <p class="description"><?php esc_html_e( 'Name shown in verification emails. Leave empty to use site name.', 'vigilante' ); ?></p>
                    </td>
                </tr>

                <!-- TOTP-specific: Reset users -->
                <tr class="vigilante-2fa-totp-only" <?php echo 'totp' !== $method ? 'style="display:none;"' : ''; ?>>
                    <th scope="row"><?php esc_html_e( 'Reset user TOTP', 'vigilante' ); ?></th>
                    <td>
                        <div class="vigilante-totp-reset-container">
                            <div class="vigilante-2fa-user-search">
                                <span class="search-icon"></span>
                                <input type="text" 
                                       id="vigilante_totp_reset_search"
                                       placeholder="<?php esc_attr_e( 'Search users with TOTP configured...', 'vigilante' ); ?>"
                                       autocomplete="off">
                                <div class="vigilante-totp-reset-results"></div>
                            </div>
                            <div class="vigilante-totp-reset-selected"></div>
                            <button type="button" id="vigilante_totp_reset_btn" class="button" style="display:none;">
                                <?php esc_html_e( 'Reset selected', 'vigilante' ); ?>
                            </button>
                            <span class="vigilante-totp-reset-status"></span>
                        </div>
                        <p class="description"><?php esc_html_e( 'Reset TOTP for users who lost access to their authenticator app. They will need to set up again.', 'vigilante' ); ?></p>
                    </td>
                </tr>
            </table>

            <h3><?php esc_html_e( 'User notification', 'vigilante' ); ?></h3>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e( 'Notify on enable', 'vigilante' ); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="login_security[two_factor][notify_on_enable]" value="1" <?php checked( $two_factor['notify_on_enable'] ?? true ); ?>>
                            <?php esc_html_e( 'Send notification email to affected users when 2FA is enabled', 'vigilante' ); ?>
                        </label>
                        
                        <div class="vigilante-2fa-notification-options">
                            <label>
                                <input type="radio" name="vigilante_2fa_notify_mode" value="all" checked>
                                <?php esc_html_e( 'Send to all affected users', 'vigilante' ); ?>
                            </label>
                            <label>
                                <input type="radio" name="vigilante_2fa_notify_mode" value="new">
                                <?php esc_html_e( 'Send only to users not previously notified', 'vigilante' ); ?>
                            </label>
                        </div>

                        <div class="vigilante-2fa-send-notification">
                            <button type="button" id="vigilante_2fa_send_notification" class="button">
                                <?php esc_html_e( 'Send notification now', 'vigilante' ); ?>
                            </button>
                            <span class="vigilante-2fa-notification-status"></span>
                        </div>
                    </td>
                </tr>
            </table>
        </div>
        <?php
    }

    /**
     * Render security headers tab
     */
    private function render_tab_headers() {
        $is_disabled = $this->render_module_disabled_notice( 'security_headers' );
        $options = $this->settings->get_section( 'security_headers' );
        ?>
        <form class="vigilante-settings-form <?php echo $is_disabled ? 'vigilante-form-disabled' : ''; ?>" data-section="security_headers" <?php echo $is_disabled ? 'inert' : ''; ?>>
            <div id="vigilante-section-headers-main" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Security Headers', 'vigilante' ); ?>
                    <span class="vigilante-method-badge htaccess"><?php esc_html_e( 'HTACCESS', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'HTTP headers sent with every response via .htaccess (mod_headers).', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'X-Frame-Options', 'vigilante' ); ?></th>
                        <td>
                            <select name="security_headers[x_frame_options]">
                                <option value="" <?php selected( empty( $options['x_frame_options'] ) ); ?>><?php esc_html_e( 'Disabled', 'vigilante' ); ?></option>
                                <option value="SAMEORIGIN" <?php selected( $options['x_frame_options'] ?? '', 'SAMEORIGIN' ); ?>>SAMEORIGIN</option>
                                <option value="DENY" <?php selected( $options['x_frame_options'] ?? '', 'DENY' ); ?>>DENY</option>
                            </select>
                            <p class="description"><?php esc_html_e( '&#9432; Prevents clickjacking attacks. Also sets CSP frame-ancestors automatically.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'X-Content-Type-Options', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="security_headers[x_content_type_options]" value="1" <?php checked( ! empty( $options['x_content_type_options'] ) ); ?>>
                                <?php esc_html_e( 'Add nosniff header to prevent MIME type sniffing', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Referrer-Policy', 'vigilante' ); ?></th>
                        <td>
                            <select name="security_headers[referrer_policy]">
                                <option value="" <?php selected( empty( $options['referrer_policy'] ) ); ?>><?php esc_html_e( 'Disabled', 'vigilante' ); ?></option>
                                <option value="no-referrer" <?php selected( $options['referrer_policy'] ?? '', 'no-referrer' ); ?>>no-referrer</option>
                                <option value="strict-origin-when-cross-origin" <?php selected( $options['referrer_policy'] ?? '', 'strict-origin-when-cross-origin' ); ?>>strict-origin-when-cross-origin</option>
                                <option value="same-origin" <?php selected( $options['referrer_policy'] ?? '', 'same-origin' ); ?>>same-origin</option>
                            </select>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e( 'HSTS (HTTP Strict Transport Security)', 'vigilante' ); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable HSTS', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="security_headers[hsts][enabled]" value="1" <?php checked( ! empty( $options['hsts']['enabled'] ) ); ?>>
                                <?php esc_html_e( 'Force HTTPS connections', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php esc_html_e( '&#9888; Warning: Only enable if your site fully supports HTTPS.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Max Age', 'vigilante' ); ?></th>
                        <td>
                            <select name="security_headers[hsts][max_age]">
                                <option value="86400" <?php selected( $options['hsts']['max_age'] ?? 31536000, 86400 ); ?>><?php esc_html_e( '1 day (testing)', 'vigilante' ); ?></option>
                                <option value="2592000" <?php selected( $options['hsts']['max_age'] ?? 31536000, 2592000 ); ?>><?php esc_html_e( '30 days', 'vigilante' ); ?></option>
                                <option value="31536000" <?php selected( $options['hsts']['max_age'] ?? 31536000, 31536000 ); ?>><?php esc_html_e( '1 year (recommended)', 'vigilante' ); ?></option>
                                <option value="63072000" <?php selected( $options['hsts']['max_age'] ?? 31536000, 63072000 ); ?>><?php esc_html_e( '2 years', 'vigilante' ); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Include Subdomains', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="security_headers[hsts][include_subdomains]" value="1" <?php checked( ! empty( $options['hsts']['include_subdomains'] ) ); ?>>
                                <?php esc_html_e( 'Apply HSTS to all subdomains', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e( 'Content Security Policy', 'vigilante' ); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable CSP', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="security_headers[csp][enabled]" value="1" <?php checked( ! empty( $options['csp']['enabled'] ) ); ?>>
                                <?php esc_html_e( 'Enable Content Security Policy', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Report Only Mode', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="security_headers[csp][report_only]" value="1" <?php checked( ! empty( $options['csp']['report_only'] ) ); ?>>
                                <?php esc_html_e( 'Report violations without blocking (for testing)', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e( 'Server Identity', 'vigilante' ); ?></h3>
                <p class="description"><?php esc_html_e( 'Hide identifying information that servers expose in responses.', 'vigilante' ); ?></p>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Server Signature', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="security_headers[hide_server_signature]" value="1" <?php checked( ! empty( $options['hide_server_signature'] ) ); ?>>
                                <?php esc_html_e( 'Hide server signature (ServerSignature Off)', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Remove Fingerprinting Headers', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="security_headers[remove_fingerprinting_headers]" value="1" <?php checked( ! empty( $options['remove_fingerprinting_headers'] ) ); ?>>
                                <?php esc_html_e( 'Remove X-Powered-By and Server headers', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <p class="submit vigilante-submit-buttons">
                <button type="submit" class="button button-primary vigilante-save-btn" data-original-text="<?php esc_attr_e( 'Save Settings', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Save Settings', 'vigilante' ); ?>
                </button>
                <button type="button" class="button vigilante-reset-section-btn" data-original-text="<?php esc_attr_e( 'Reset to Defaults', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Reset to Defaults', 'vigilante' ); ?>
                </button>
                <button type="button" class="button vigilante-test-headers">
                    <?php esc_html_e( 'Test Headers', 'vigilante' ); ?>
                </button>
            </p>
        </form>

        <div id="vigilante-headers-result"></div>
        <?php
    }

    /**
     * Render REST API tab
     */
    private function render_tab_rest_api() {
        $is_disabled = $this->render_module_disabled_notice( 'rest_api_security' );
        $options = $this->settings->get_section( 'rest_api_security' );
        ?>
        <form class="vigilante-settings-form <?php echo $is_disabled ? 'vigilante-form-disabled' : ''; ?>" data-section="rest_api_security" <?php echo $is_disabled ? 'inert' : ''; ?>>
            <div id="vigilante-section-rest-api-main" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'REST API Security', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Control access to WordPress REST API endpoints.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Access Mode', 'vigilante' ); ?></th>
                        <td>
                            <select name="rest_api_security[mode]">
                                <option value="open" <?php selected( $options['mode'] ?? 'selective', 'open' ); ?>><?php esc_html_e( 'Open - Allow all requests', 'vigilante' ); ?></option>
                                <option value="selective" <?php selected( $options['mode'] ?? 'selective', 'selective' ); ?>><?php esc_html_e( 'Selective - Protect sensitive endpoints', 'vigilante' ); ?></option>
                                <option value="authenticated_only" <?php selected( $options['mode'] ?? 'selective', 'authenticated_only' ); ?>><?php esc_html_e( 'Authenticated - Require login for all', 'vigilante' ); ?></option>
                            </select>
                            <p class="description"><?php esc_html_e( 'Selective mode is recommended.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr id="field-block-user-enumeration">
                        <th scope="row"><?php esc_html_e( 'Block User Enumeration', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="rest_api_security[block_user_enumeration]" value="1" <?php checked( ! empty( $options['block_user_enumeration'] ) ); ?>>
                                <?php esc_html_e( 'Protect /wp/v2/users endpoint for unauthenticated users', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Disable JSONP', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="rest_api_security[disable_jsonp]" value="1" <?php checked( ! empty( $options['disable_jsonp'] ) ); ?>>
                                <?php esc_html_e( 'Disable JSONP support in REST API', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <p class="submit vigilante-submit-buttons">
                <button type="submit" class="button button-primary vigilante-save-btn" data-original-text="<?php esc_attr_e( 'Save Settings', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Save Settings', 'vigilante' ); ?>
                </button>
                <button type="button" class="button vigilante-reset-section-btn" data-original-text="<?php esc_attr_e( 'Reset to Defaults', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Reset to Defaults', 'vigilante' ); ?>
                </button>
            </p>
        </form>
        <?php
    }

    /**
     * Render User Security tab
     */
    private function render_tab_users() {
        $is_disabled = $this->render_module_disabled_notice( 'user_security' );
        $options = $this->settings->get_section( 'user_security' );
        $monitoring = $options['admin_monitoring'] ?? array();
        $registration = $options['registration_approval'] ?? array();
        $session_limits = $options['session_limits'] ?? array();
        $password_exp = $options['password_expiration'] ?? array();
        $email_verify = $options['email_verification'] ?? array();
        ?>

        <!-- ============================================================
             SETTINGS SECTION - Single form for all configuration
             ============================================================ -->
        <form class="vigilante-settings-form <?php echo $is_disabled ? 'vigilante-form-disabled' : ''; ?>" data-section="user_security" <?php echo $is_disabled ? 'inert' : ''; ?>>
            
            <!-- Username & Password Protection -->
            <div id="vigilante-section-users-password" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Username & password protection', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Enforce secure username and password policies.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Block Insecure Usernames', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[block_insecure_usernames]" value="1" <?php checked( ! empty( $options['block_insecure_usernames'] ) ); ?>>
                                <?php esc_html_e( 'Prevent creation of users with common usernames (admin, administrator, etc.)', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enforce Strong Passwords', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[force_strong_passwords]" value="1" <?php checked( ! empty( $options['force_strong_passwords'] ) ); ?>>
                                <?php esc_html_e( 'Require passwords with uppercase, lowercase, numbers, and special characters', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Minimum Password Length', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="user_security[min_password_length]" value="<?php echo esc_attr( $options['min_password_length'] ?? 12 ); ?>" min="6" max="32" class="small-text">
                            <?php esc_html_e( 'characters', 'vigilante' ); ?>
                        </td>
                    </tr>
                    <tr id="field-block-author-scanning">
                        <th scope="row"><?php esc_html_e( 'Block Author Scanning', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[block_author_scanning]" value="1" <?php checked( ! empty( $options['block_author_scanning'] ) ); ?>>
                                <?php esc_html_e( 'Prevent username discovery via ?author=N URLs', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Display Name Protection', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[prevent_display_name_login_match]" value="1" <?php checked( ! empty( $options['prevent_display_name_login_match'] ) ); ?>>
                                <?php esc_html_e( 'Prevent users from saving a display name that matches their login username', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php esc_html_e( 'The display name is publicly visible and should not reveal the login username.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Admin Monitoring -->
            <div id="vigilante-section-users-admin-monitoring" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Admin monitoring', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Receive email alerts when administrator accounts are modified. All events are always logged to the Security Audit.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'New Administrator Alert', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[admin_monitoring][alert_new_admin]" value="1" <?php checked( ! empty( $monitoring['alert_new_admin'] ) ); ?>>
                                <?php esc_html_e( 'Send email alert when a new administrator account is created', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Admin Email Change Alert', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[admin_monitoring][alert_admin_email_change]" value="1" <?php checked( ! empty( $monitoring['alert_admin_email_change'] ) ); ?>>
                                <?php esc_html_e( 'Send email alert when an administrator email address is changed', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Permission Elevation Alert', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[admin_monitoring][alert_permission_elevation]" value="1" <?php checked( ! empty( $monitoring['alert_permission_elevation'] ) ); ?>>
                                <?php esc_html_e( 'Send email alert when a user is elevated to administrator role', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Admin Password Change Alert', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[admin_monitoring][alert_admin_password_change]" value="1" <?php checked( ! empty( $monitoring['alert_admin_password_change'] ) ); ?>>
                                <?php esc_html_e( 'Send email alert when an administrator password is changed', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <p class="description">
                    <?php
                    printf(
                        /* translators: %s: Link to notification settings */
                        esc_html__( '&#9432; Notifications are sent to the recipients configured in %s.', 'vigilante' ),
                        '<a href="' . esc_url( admin_url( 'admin.php?page=vigilante&tab=tools' ) ) . '">' . esc_html__( 'Settings & Tools', 'vigilante' ) . '</a>'
                    );
                    ?>
                </p>
            </div>

            <!-- Registration Approval -->
            <div id="vigilante-section-users-registration" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Registration approval', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Require manual approval for new user registrations.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable Registration Approval', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[registration_approval][enabled]" value="1" <?php checked( ! empty( $registration['enabled'] ) ); ?>>
                                <?php esc_html_e( 'New users must be approved by an administrator before they can log in', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Notify Admin', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[registration_approval][notify_admin]" value="1" <?php checked( ! empty( $registration['notify_admin'] ) ); ?>>
                                <?php esc_html_e( 'Send email notification when a new user registers', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php esc_html_e( 'Disable on high-traffic sites to avoid email overload.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Auto-reject After', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="user_security[registration_approval][auto_reject_days]" value="<?php echo esc_attr( $registration['auto_reject_days'] ?? 0 ); ?>" min="0" max="365" class="small-text">
                            <?php esc_html_e( 'days (0 = never)', 'vigilante' ); ?>
                            <p class="description"><?php esc_html_e( 'Automatically reject pending registrations after this many days.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Session Limits -->
            <div id="vigilante-section-users-sessions" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Session limits', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Limit the number of simultaneous sessions per user.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable Session Limits', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[session_limits][enabled]" value="1" <?php checked( ! empty( $session_limits['enabled'] ) ); ?>>
                                <?php esc_html_e( 'Limit the number of active sessions per user', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Maximum Sessions', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="user_security[session_limits][max_sessions]" value="<?php echo esc_attr( $session_limits['max_sessions'] ?? 3 ); ?>" min="1" max="10" class="small-text">
                            <?php esc_html_e( 'sessions per user', 'vigilante' ); ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'When Limit Exceeded', 'vigilante' ); ?></th>
                        <td>
                            <select name="user_security[session_limits][behavior]">
                                <option value="block_new" <?php selected( ( $session_limits['behavior'] ?? 'close_oldest' ), 'block_new' ); ?>><?php esc_html_e( 'Block new login', 'vigilante' ); ?></option>
                                <option value="close_oldest" <?php selected( ( $session_limits['behavior'] ?? 'close_oldest' ), 'close_oldest' ); ?>><?php esc_html_e( 'Close oldest session', 'vigilante' ); ?></option>
                            </select>
                            <p class="description"><?php esc_html_e( '"Close oldest" is recommended for security - ensures attackers cannot lock out legitimate users.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Exclude Administrators', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[session_limits][exclude_admins]" value="1" <?php checked( ! empty( $session_limits['exclude_admins'] ) ); ?>>
                                <?php esc_html_e( 'Do not apply session limits to administrators', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Password Expiration -->
            <div id="vigilante-section-users-password-exp" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Password expiration', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Force users to change their password periodically.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable Password Expiration', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[password_expiration][enabled]" value="1" <?php checked( ! empty( $password_exp['enabled'] ) ); ?>>
                                <?php esc_html_e( 'Force password change after a set number of days', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Expire After', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="user_security[password_expiration][expire_days]" value="<?php echo esc_attr( $password_exp['expire_days'] ?? 90 ); ?>" min="7" max="365" class="small-text">
                            <?php esc_html_e( 'days', 'vigilante' ); ?>
                            <p class="description"><?php esc_html_e( 'PCI-DSS recommends 90 days.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Warning Period', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="user_security[password_expiration][warning_days]" value="<?php echo esc_attr( $password_exp['warning_days'] ?? 14 ); ?>" min="1" max="30" class="small-text">
                            <?php esc_html_e( 'days before expiration', 'vigilante' ); ?>
                            <p class="description"><?php esc_html_e( 'Show warning notice this many days before password expires.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Password History', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="user_security[password_expiration][password_history]" value="<?php echo esc_attr( $password_exp['password_history'] ?? 3 ); ?>" min="0" max="24" class="small-text">
                            <?php esc_html_e( 'passwords to remember', 'vigilante' ); ?>
                            <p class="description"><?php esc_html_e( 'Prevent reusing recent passwords. Set to 0 to disable.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Email Reminder', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[password_expiration][send_reminder]" value="1" <?php checked( ! empty( $password_exp['send_reminder'] ) ); ?>>
                                <?php esc_html_e( 'Send email reminder when password is about to expire', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php esc_html_e( 'The reminder is sent once when the warning period starts, using the same number of days configured above.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Affected Roles', 'vigilante' ); ?></th>
                        <td>
                            <?php
                            $affected_roles = $password_exp['affected_roles'] ?? array( 'administrator', 'editor' );
                            $all_roles = wp_roles()->get_names();
                            foreach ( $all_roles as $role_slug => $role_name ) :
                            ?>
                            <label style="display: block; margin-bottom: 5px;">
                                <input type="checkbox" name="user_security[password_expiration][affected_roles][]" value="<?php echo esc_attr( $role_slug ); ?>" <?php checked( in_array( $role_slug, $affected_roles, true ) ); ?>>
                                <?php echo esc_html( translate_user_role( $role_name ) ); ?>
                            </label>
                            <?php endforeach; ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Exclude specific users', 'vigilante' ); ?></th>
                        <td>
                            <?php $pwexp_excluded = $password_exp['excluded_users'] ?? array(); ?>
                            <div class="vigilante-2fa-user-search-container">
                                <div class="vigilante-2fa-user-search">
                                    <span class="search-icon"></span>
                                    <input type="text"
                                           id="vigilante_pwexp_user_search"
                                           placeholder="<?php esc_attr_e( 'Search users by name or email...', 'vigilante' ); ?>"
                                           autocomplete="off">
                                    <div class="vigilante-pwexp-search-results"></div>
                                </div>
                                <div class="vigilante-pwexp-excluded-users">
                                    <?php
                                    foreach ( $pwexp_excluded as $pwexp_excluded_id ) :
                                        $excluded_user = get_user_by( 'ID', $pwexp_excluded_id );
                                        if ( ! $excluded_user ) {
                                            continue;
                                        }
                                    ?>
                                    <div class="vigilante-pwexp-excluded-user" data-user-id="<?php echo esc_attr( $pwexp_excluded_id ); ?>">
                                        <span class="user-display"><?php echo esc_html( $excluded_user->display_name . ' (' . $excluded_user->user_email . ')' ); ?></span>
                                        <button type="button" class="remove-user" aria-label="<?php esc_attr_e( 'Remove', 'vigilante' ); ?>">&times;</button>
                                        <input type="hidden" name="user_security[password_expiration][excluded_users][]" value="<?php echo esc_attr( $pwexp_excluded_id ); ?>">
                                    </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                            <p class="description"><?php esc_html_e( 'Listed users will be excluded from password expiration regardless of their role.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Email Verification -->
            <div id="vigilante-section-users-email-verify" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Email verification', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Require new users to verify their email address before logging in.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable Email Verification', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[email_verification][enabled]" value="1" <?php checked( ! empty( $email_verify['enabled'] ) ); ?>>
                                <?php esc_html_e( 'New users must verify their email before logging in', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Link Expiration', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="user_security[email_verification][token_expiry_hours]" value="<?php echo esc_attr( $email_verify['token_expiry_hours'] ?? 24 ); ?>" min="1" max="168" class="small-text">
                            <?php esc_html_e( 'hours', 'vigilante' ); ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Allow Resend', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="user_security[email_verification][allow_resend]" value="1" <?php checked( ! empty( $email_verify['allow_resend'] ) ); ?>>
                                <?php esc_html_e( 'Allow users to request a new verification email', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Auto-delete Unverified', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="user_security[email_verification][auto_delete_days]" value="<?php echo esc_attr( $email_verify['auto_delete_days'] ?? 7 ); ?>" min="0" max="365" class="small-text">
                            <?php esc_html_e( 'days (0 = never)', 'vigilante' ); ?>
                            <p class="description"><?php esc_html_e( 'Automatically delete users who never verify their email.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <p class="submit vigilante-submit-buttons">
                <button type="submit" class="button button-primary vigilante-save-btn" data-original-text="<?php esc_attr_e( 'Save Settings', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Save Settings', 'vigilante' ); ?>
                </button>
                <button type="button" class="button vigilante-reset-section-btn" data-original-text="<?php esc_attr_e( 'Reset to Defaults', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Reset to Defaults', 'vigilante' ); ?>
                </button>
            </p>
        </form>

        <!-- ============================================================
             TOOLS SECTION - Actions and utilities (no save button)
             ============================================================ -->
        <div class="vigilante-tools-section">
            <h2 class="vigilante-tools-header">
                <?php esc_html_e( 'User security tools', 'vigilante' ); ?>
            </h2>

            <!-- Force Password Reset -->
            <div class="vigilante-tool-box">
                <h3><?php esc_html_e( 'Force password reset', 'vigilante' ); ?></h3>
                <p class="description"><?php esc_html_e( 'Force users to reset their password. Useful after a security incident. Users will receive an email with a reset link.', 'vigilante' ); ?></p>

                <!-- Reset Specific Users -->
                <div class="vigilante-password-reset-box">
                    <h4><?php esc_html_e( 'Reset specific users', 'vigilante' ); ?></h4>
                    
                    <div class="vigilante-user-search-wrapper">
                        <input type="text" id="vigilante-password-reset-search" class="regular-text" placeholder="<?php esc_attr_e( 'Search by username, email, or display name...', 'vigilante' ); ?>">
                        <div id="vigilante-password-reset-results" class="vigilante-user-search-results" style="display: none;"></div>
                    </div>

                    <div id="vigilante-password-reset-selected" class="vigilante-selected-users" style="display: none;">
                        <strong><?php esc_html_e( 'Selected Users:', 'vigilante' ); ?></strong>
                        <ul class="vigilante-selected-users-list"></ul>
                    </div>

                    <p class="description" style="margin-top: 15px;">
                        <span class="dashicons dashicons-email-alt" style="color: #2271b1;"></span>
                        <?php esc_html_e( 'Selected users will receive an email with a password reset link.', 'vigilante' ); ?>
                    </p>

                    <p class="submit">
                        <button type="button" id="vigilante-reset-selected-users" class="button button-primary" disabled>
                            <?php esc_html_e( 'Force Reset for Selected Users', 'vigilante' ); ?>
                        </button>
                    </p>
                </div>

                <!-- Reset by Role -->
                <div class="vigilante-password-reset-box" style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">
                    <h4><?php esc_html_e( 'Reset by role', 'vigilante' ); ?></h4>
                    <p class="description"><?php esc_html_e( 'Select one or more roles to force a password reset for all users with those roles. Ideal for security incidents where you need to reset access quickly.', 'vigilante' ); ?></p>

                    <?php
                    $wp_roles      = wp_roles();
                    $user_counts   = count_users();
                    $avail_roles   = $user_counts['avail_roles'] ?? array();
                    $current_user  = wp_get_current_user();
                    $current_roles = $current_user->roles;
                    ?>

                    <fieldset class="vigilante-role-checkboxes" style="margin-top: 10px;">
                        <?php foreach ( $wp_roles->roles as $role_slug => $role_data ) :
                            $count = $avail_roles[ $role_slug ] ?? 0;
                            if ( 0 === $count ) {
                                continue;
                            }
                            $role_name = translate_user_role( $role_data['name'] );
                        ?>
                            <label style="display: block; margin-bottom: 6px;">
                                <input type="checkbox"
                                    class="vigilante-reset-role-checkbox"
                                    value="<?php echo esc_attr( $role_slug ); ?>"
                                    data-count="<?php echo absint( $count ); ?>">
                                <?php
                                printf(
                                    /* translators: 1: Role name, 2: Number of users */
                                    '%1$s <span class="description">(%2$d)</span>',
                                    esc_html( $role_name ),
                                    absint( $count )
                                );
                                ?>
                                <?php if ( in_array( $role_slug, $current_roles, true ) ) : ?>
                                    <em class="description"><?php esc_html_e( '(includes you)', 'vigilante' ); ?></em>
                                <?php endif; ?>
                            </label>
                        <?php endforeach; ?>
                    </fieldset>

                    <div id="vigilante-reset-role-summary" style="display: none; margin-top: 10px;">
                        <p>
                            <span class="dashicons dashicons-groups" style="color: #2271b1;"></span>
                            <strong id="vigilante-reset-role-count">0</strong>
                            <?php esc_html_e( 'user(s) will be affected.', 'vigilante' ); ?>
                        </p>
                    </div>

                    <div class="vigilante-password-reset-options" id="vigilante-reset-role-self-option" style="display: none; margin-top: 10px;">
                        <label>
                            <input type="checkbox" id="vigilante-reset-role-include-self" value="1">
                            <?php esc_html_e( 'Include myself (your current session will end)', 'vigilante' ); ?>
                        </label>
                    </div>

                    <p class="submit">
                        <button type="button" id="vigilante-reset-by-role" class="button button-primary" disabled>
                            <?php esc_html_e( 'Force Reset for Selected Roles', 'vigilante' ); ?>
                        </button>
                    </p>
                </div>

                <!-- Reset All Users -->
                <div class="vigilante-password-reset-box" style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">
                    <h4><?php esc_html_e( 'Reset all users', 'vigilante' ); ?></h4>

                    <?php
                    $total_users = count_users();
                    $total_count = $total_users['total_users'];
                    ?>
                    <p>
                        <?php
                        printf(
                            /* translators: %d: Number of users */
                            esc_html__( 'This will affect %d user(s).', 'vigilante' ),
                            absint( $total_count )
                        );
                        ?>
                    </p>

                    <p class="description" style="color: #d63638;">
                        <span class="dashicons dashicons-warning"></span>
                        <?php esc_html_e( 'Warning: All users will receive a password reset email. On sites with many users, this could overwhelm your mail server.', 'vigilante' ); ?>
                    </p>

                    <div class="vigilante-password-reset-options" style="margin-top: 10px;">
                        <label>
                            <input type="checkbox" id="vigilante-reset-all-include-self" value="1">
                            <?php esc_html_e( 'Include myself (your current session will end)', 'vigilante' ); ?>
                        </label>
                    </div>

                    <p class="submit">
                        <button type="button" id="vigilante-reset-all-users" class="button" style="color: #d63638; border-color: #d63638;">
                            <?php esc_html_e( 'Force Reset for ALL Users', 'vigilante' ); ?>
                        </button>
                    </p>
                </div>
            </div>

            <!-- Pending Registrations -->
            <?php
            $user_security = new Vigilante_User_Security( $this->settings, $this->activity_log );
            $pending_users = $user_security->get_pending_users();
            ?>
            <div class="vigilante-tool-box vigilante-pending-users-section">
                <h3>
                    <?php esc_html_e( 'Pending registrations', 'vigilante' ); ?>
                    <?php if ( count( $pending_users ) > 0 ) : ?>
                        <span class="vigilante-badge vigilante-badge-warning"><?php echo esc_html( count( $pending_users ) ); ?></span>
                    <?php endif; ?>
                </h3>

                <?php if ( empty( $registration['enabled'] ) ) : ?>
                    <p class="description">
                        <span class="dashicons dashicons-info" style="color: #72aee6;"></span>
                        <?php esc_html_e( 'Registration approval is disabled. Enable it in the settings above to require manual approval for new users.', 'vigilante' ); ?>
                    </p>
                <?php elseif ( empty( $pending_users ) ) : ?>
                    <div class="vigilante-no-lockouts">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <p><?php esc_html_e( 'No pending registrations.', 'vigilante' ); ?></p>
                    </div>
                <?php else : ?>
                    <table class="wp-list-table widefat fixed striped vigilante-pending-users-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'User', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Email', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Registered', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $pending_users as $pending_user ) : 
                                $pending_since = get_user_meta( $pending_user->ID, 'vigilante_pending_since', true );
                            ?>
                            <tr data-user-id="<?php echo esc_attr( $pending_user->ID ); ?>">
                                <td>
                                    <?php echo get_avatar( $pending_user->ID, 32 ); ?>
                                    <strong><?php echo esc_html( $pending_user->user_login ); ?></strong>
                                </td>
                                <td><?php echo esc_html( $pending_user->user_email ); ?></td>
                                <td>
                                    <?php 
                                    if ( $pending_since ) {
                                        /* translators: %s: Time ago */
                                        printf( esc_html__( '%s ago', 'vigilante' ), esc_html( human_time_diff( $pending_since ) ) );
                                    } else {
                                        echo esc_html( $pending_user->user_registered );
                                    }
                                    ?>
                                </td>
                                <td>
                                    <button type="button" class="button button-small vigilante-approve-user" data-user-id="<?php echo esc_attr( $pending_user->ID ); ?>">
                                        <?php esc_html_e( 'Approve', 'vigilante' ); ?>
                                    </button>
                                    <button type="button" class="button button-small vigilante-reject-user" data-user-id="<?php echo esc_attr( $pending_user->ID ); ?>" style="color: #d63638;">
                                        <?php esc_html_e( 'Reject', 'vigilante' ); ?>
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <!-- Active Sessions Management -->
            <div class="vigilante-tool-box vigilante-session-management-section">
                <h3><?php esc_html_e( 'Active sessions', 'vigilante' ); ?></h3>
                <p class="description"><?php esc_html_e( 'View and manage active login sessions. You can revoke sessions to force users to log in again.', 'vigilante' ); ?></p>

                <!-- Current user sessions -->
                <h4><?php esc_html_e( 'Your sessions', 'vigilante' ); ?></h4>
                <?php
                $current_user_id = get_current_user_id();
                $my_sessions = $user_security->get_user_sessions( $current_user_id );
                $has_corrupted = $user_security->has_corrupted_sessions( $current_user_id );
                $raw_count = $user_security->get_raw_session_count( $current_user_id );
                ?>
                
                <?php if ( $has_corrupted && $raw_count > 0 ) : ?>
                    <div class="notice notice-warning inline" style="margin: 10px 0;">
                        <p>
                            <span class="dashicons dashicons-warning" style="color: #dba617;"></span>
                            <?php esc_html_e( 'Some session data is corrupted and cannot be displayed. Use "Revoke All Other Sessions" to clean up, then log out and log in again to fix this.', 'vigilante' ); ?>
                        </p>
                    </div>
                <?php endif; ?>
                
                <?php if ( empty( $my_sessions ) ) : ?>
                    <p class="description"><?php esc_html_e( 'No active sessions found.', 'vigilante' ); ?></p>
                    <?php if ( $has_corrupted ) : ?>
                    <p style="margin-top: 10px;">
                        <button type="button" class="button vigilante-revoke-other-sessions" data-user-id="<?php echo esc_attr( $current_user_id ); ?>">
                            <?php esc_html_e( 'Clean Up Corrupted Sessions', 'vigilante' ); ?>
                        </button>
                    </p>
                    <?php endif; ?>
                <?php else : ?>
                    <div class="vigilante-paginated-section">
                    <div class="vigilante-fi-pagination-wrap"></div>
                    <table class="wp-list-table widefat fixed striped vigilante-sessions-table vigilante-fi-paginated">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'Browser', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'IP Address', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Login Time', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $my_sessions as $session ) : ?>
                            <tr data-token="<?php echo esc_attr( $session['token_hash'] ); ?>">
                                <td><?php echo esc_html( $session['browser'] ); ?></td>
                                <td><code><?php echo esc_html( $session['ip'] ); ?></code></td>
                                <td>
                                    <?php 
                                    if ( $session['login'] ) {
                                        /* translators: %s: Time ago */
                                        printf( esc_html__( '%s ago', 'vigilante' ), esc_html( human_time_diff( $session['login'] ) ) );
                                    } else {
                                        esc_html_e( 'Unknown', 'vigilante' );
                                    }
                                    ?>
                                </td>
                                <td>
                                    <?php if ( ! $session['is_current'] ) : ?>
                                        <button type="button" class="button button-small vigilante-revoke-session" data-user-id="<?php echo esc_attr( $current_user_id ); ?>" data-token="<?php echo esc_attr( $session['token_hash'] ); ?>">
                                            <?php esc_html_e( 'Revoke', 'vigilante' ); ?>
                                        </button>
                                    <?php else : ?>
                                        <span class="description"><?php esc_html_e( 'Current session', 'vigilante' ); ?></span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    
                    <?php if ( count( $my_sessions ) > 1 || $has_corrupted ) : ?>
                    <p style="margin-top: 10px;">
                        <button type="button" class="button vigilante-revoke-other-sessions" data-user-id="<?php echo esc_attr( $current_user_id ); ?>">
                            <?php esc_html_e( 'Revoke All Other Sessions', 'vigilante' ); ?>
                        </button>
                    </p>
                    <?php endif; ?>
                <?php endif; ?>

                <!-- Search user sessions (admin only) -->
                <h4 style="margin-top: 30px;"><?php esc_html_e( 'Manage user sessions', 'vigilante' ); ?></h4>
                <p class="description"><?php esc_html_e( 'Search for a user to view and manage their sessions.', 'vigilante' ); ?></p>
                
                <div class="vigilante-user-search-wrapper" style="margin-top: 10px;">
                    <input type="text" id="vigilante-session-user-search" class="regular-text" placeholder="<?php esc_attr_e( 'Search by username or email...', 'vigilante' ); ?>">
                    <div id="vigilante-session-search-results" class="vigilante-user-search-results" style="display: none;"></div>
                </div>
                
                <div id="vigilante-user-sessions-container" style="display: none; margin-top: 20px;">
                    <h4 id="vigilante-sessions-user-name"></h4>
                    <table class="wp-list-table widefat fixed striped vigilante-sessions-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'Browser', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'IP Address', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Login Time', 'vigilante' ); ?></th>
                                <th><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                            </tr>
                        </thead>
                        <tbody id="vigilante-user-sessions-list">
                        </tbody>
                    </table>
                    <p style="margin-top: 10px;">
                        <button type="button" class="button vigilante-revoke-all-user-sessions" style="color: #d63638;">
                            <?php esc_html_e( 'Revoke All Sessions', 'vigilante' ); ?>
                        </button>
                    </p>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render WordPress Hardening tab
     */
    private function render_tab_wp_hardening() {
        $is_disabled = $this->render_module_disabled_notice( 'wp_hardening' );
        $options = $this->settings->get_section( 'wp_hardening' );
        ?>
        <form class="vigilante-settings-form <?php echo $is_disabled ? 'vigilante-form-disabled' : ''; ?>" data-section="wp_hardening" <?php echo $is_disabled ? 'inert' : ''; ?>>
            <!-- Database Hardening (outside form save flow - uses its own AJAX action) -->
            <div id="vigilante-section-hardening-database" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Database Hardening', 'vigilante' ); ?>
                    <span class="vigilante-method-badge database"><?php esc_html_e( 'Database', 'vigilante' ); ?></span>
                    <span class="vigilante-method-badge config"><?php esc_html_e( 'WP-CONFIG', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Change the database table prefix to prevent SQL injection attacks that target default WordPress tables.', 'vigilante' ); ?></p>

                <?php
                $db_prefix = new Vigilante_Database_Prefix();
                $current_prefix = $db_prefix->get_current_prefix();
                $is_default = $db_prefix->is_default_prefix();
                ?>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Current prefix', 'vigilante' ); ?></th>
                        <td>
                            <code class="vigilante-db-current-prefix"><?php echo esc_html( $current_prefix ); ?></code>
                            <?php if ( $is_default ) : ?>
                                <span class="vigilante-inline-warning">
                                    <span class="dashicons dashicons-warning"></span>
                                    <?php esc_html_e( 'Default prefix detected. Changing it adds a layer of protection against automated SQL injection attacks.', 'vigilante' ); ?>
                                </span>
                            <?php else : ?>
                                <span class="vigilante-inline-ok">
                                    <span class="dashicons dashicons-yes-alt"></span>
                                    <?php esc_html_e( 'Custom prefix in use.', 'vigilante' ); ?>
                                </span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'New prefix', 'vigilante' ); ?></th>
                        <td>
                            <div class="vigilante-db-prefix-row">
                                <code class="vigilante-db-new-prefix" id="vigilante-new-prefix"><?php echo esc_html( $db_prefix->generate_prefix() ); ?></code>
                                <button type="button" class="button button-small vigilante-db-regenerate-prefix" title="<?php esc_attr_e( 'Generate new prefix', 'vigilante' ); ?>">
                                    <span class="dashicons dashicons-update"></span>
                                </button>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"></th>
                        <td>
                            <div class="vigilante-db-prefix-confirm">
                                <label>
                                    <input type="checkbox" id="vigilante-prefix-backup-confirm">
                                    <?php esc_html_e( 'I understand this operation is irreversible and I have a current database backup', 'vigilante' ); ?>
                                </label>
                                <p class="description">
                                    <?php
                                    printf(
                                        /* translators: %s: Link to tools tab */
                                        esc_html__( 'Need a backup? %s first.', 'vigilante' ),
                                        '<a href="' . esc_url( admin_url( 'admin.php?page=vigilante&tab=tools' ) ) . '">' . esc_html__( 'Download a database backup', 'vigilante' ) . '</a>'
                                    );
                                    ?>
                                </p>
                            </div>
                            <button type="button" class="button button-primary vigilante-db-change-prefix" disabled data-original-text="<?php esc_attr_e( 'Change Database Prefix', 'vigilante' ); ?>">
                                <?php esc_html_e( 'Change Database Prefix', 'vigilante' ); ?>
                            </button>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- wp-config Security -->
            <div id="vigilante-section-hardening-wpconfig" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'wp-config.php Security', 'vigilante' ); ?>
                    <span class="vigilante-method-badge config"><?php esc_html_e( 'WP-CONFIG', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Security constants added directly to wp-config.php file.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Disable File Editor', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[disallow_file_edit]" value="1" <?php checked( ! empty( $options['disallow_file_edit'] ) ); ?>>
                                <?php esc_html_e( 'Disable plugin and theme editor in admin (DISALLOW_FILE_EDIT)', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Disable File Modifications', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[disallow_file_mods]" value="1" <?php checked( ! empty( $options['disallow_file_mods'] ) ); ?>>
                                <?php esc_html_e( 'Disable all file modifications including updates (DISALLOW_FILE_MODS)', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php esc_html_e( '&#9888; Warning: This prevents automatic updates.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr id="field-force-ssl-admin">
                        <th scope="row"><?php esc_html_e( 'Force SSL Admin', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[force_ssl_admin]" value="1" <?php checked( ! empty( $options['force_ssl_admin'] ) ); ?>>
                                <?php esc_html_e( 'Force HTTPS for admin area (FORCE_SSL_ADMIN)', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php esc_html_e( '&#9888; Warning: Only enable if your site fully supports HTTPS.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr id="field-wp-debug">
                        <th scope="row"><?php esc_html_e( 'Hide PHP errors from visitors', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[wp_debug]" value="1" <?php checked( ! empty( $options['wp_debug'] ) ); ?>>
                                <?php esc_html_e( 'Prevents PHP errors and warnings from being displayed publicly. Also avoids exposing a debug.log file in wp-content/ that could leak paths and code. Uncheck only on development or staging sites.', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr id="field-disable-wp-cron">
                        <th scope="row"><?php esc_html_e( 'Disable WP Cron', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[disable_wp_cron]" value="1" <?php checked( ! empty( $options['disable_wp_cron'] ) ); ?>>
                                <?php esc_html_e( 'Disable WordPress\'s page-view cron trigger (DISABLE_WP_CRON)', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php
                                printf(
                                    /* translators: 1: opening <strong>, 2: closing </strong>, 3: opening <code>, 4: closing </code> */
                                    esc_html__( '%1$sWarning:%2$s Only enable if your host runs a real server-side cron job calling wp-cron.php. Otherwise scheduled tasks stop running. This constant only stops the page-view auto-spawn — to also block external HTTP abuse, enable %3$sProtect wp-cron.php%4$s in Firewall &rarr; File Protection.', 'vigilante' ),
                                    '<strong>',
                                    '</strong>',
                                    '<code>',
                                    '</code>'
                                ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML tags are hardcoded.
                            ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Comment Security -->
            <div id="vigilante-section-hardening-comments" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Comment Security', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                    <span class="vigilante-method-badge settings"><?php esc_html_e( 'Settings', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Comment protection using WordPress settings and PHP hooks.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Disable Pingbacks', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[disable_pingbacks]" value="1" <?php checked( ! empty( $options['disable_pingbacks'] ) ); ?>>
                                <?php esc_html_e( 'Disable pingbacks (commonly exploited for DDoS)', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Disable Trackbacks', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[disable_trackbacks]" value="1" <?php checked( ! empty( $options['disable_trackbacks'] ) ); ?>>
                                <?php esc_html_e( 'Disable trackbacks (rarely used legitimately)', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Require Moderation', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[require_comment_moderation]" value="1" <?php checked( ! empty( $options['require_comment_moderation'] ) ); ?>>
                                <?php esc_html_e( 'All comments must be manually approved', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Close Old Comments', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[close_old_comments]" value="1" <?php checked( ! empty( $options['close_old_comments'] ) ); ?>>
                                <?php esc_html_e( 'Automatically close comments on old posts after', 'vigilante' ); ?>
                            </label>
                            <input type="number" name="wp_hardening[close_comments_after_days]" value="<?php echo esc_attr( $options['close_comments_after_days'] ?? 30 ); ?>" min="1" max="365" class="small-text">
                            <?php esc_html_e( 'days', 'vigilante' ); ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Honeypot Protection', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[honeypot_comments]" value="1" <?php checked( ! empty( $options['honeypot_comments'] ) ); ?>>
                                <?php esc_html_e( 'Add hidden honeypot field to catch bots', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Head Cleaner -->
            <div id="vigilante-section-hardening-headers" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Header Cleanup', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Remove meta tags from HTML head.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Remove Generator', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[remove_wp_generator]" value="1" <?php checked( ! empty( $options['remove_wp_generator'] ) ); ?>>
                                <?php esc_html_e( 'Remove WordPress version from HTML head', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr id="field-remove-wp-version-assets">
                        <th scope="row"><?php esc_html_e( 'Remove version from assets', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[remove_wp_version_assets]" value="1" <?php checked( ! empty( $options['remove_wp_version_assets'] ) ); ?>>
                                <?php esc_html_e( 'Remove WordPress version from script/style URLs (?ver=)', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php esc_html_e( 'Hides the exact WordPress version that would otherwise leak in every enqueued asset URL. Versions added by plugins or themes are kept untouched.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Remove RSD Link', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[remove_rsd_link]" value="1" <?php checked( ! empty( $options['remove_rsd_link'] ) ); ?>>
                                <?php esc_html_e( 'Remove Really Simple Discovery link', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Remove WLW Manifest', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[remove_wlw_manifest]" value="1" <?php checked( ! empty( $options['remove_wlw_manifest'] ) ); ?>>
                                <?php esc_html_e( 'Remove Windows Live Writer manifest link', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Remove Shortlink', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[remove_shortlink]" value="1" <?php checked( ! empty( $options['remove_shortlink'] ) ); ?>>
                                <?php esc_html_e( 'Remove shortlink tag from header', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Remove REST API Link', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[remove_rest_api_link]" value="1" <?php checked( ! empty( $options['remove_rest_api_link'] ) ); ?>>
                                <?php esc_html_e( 'Remove REST API discovery link from header', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php esc_html_e( '&#9888; Notice: Some plugins may need this link.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Feed Manager -->
            <div id="vigilante-section-hardening-rss" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'RSS Feed Settings', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Control RSS/Atom feeds.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Disable Feeds', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[disable_feeds]" value="1" <?php checked( ! empty( $options['disable_feeds'] ) ); ?>>
                                <?php esc_html_e( 'Completely disable RSS/Atom feeds', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Disable If No Content', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[disable_if_no_content]" value="1" <?php checked( ! empty( $options['disable_if_no_content'] ) ); ?>>
                                <?php esc_html_e( 'Only disable feeds if site has no published posts', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Remove Feed Version', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="wp_hardening[remove_feed_version]" value="1" <?php checked( ! empty( $options['remove_feed_version'] ) ); ?>>
                                <?php esc_html_e( 'Remove WordPress version from feed generator tag', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <p class="submit vigilante-submit-buttons">
                <button type="submit" class="button button-primary vigilante-save-btn" data-original-text="<?php esc_attr_e( 'Save Settings', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Save Settings', 'vigilante' ); ?>
                </button>
                <button type="button" class="button vigilante-reset-section-btn" data-original-text="<?php esc_attr_e( 'Reset to Defaults', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Reset to Defaults', 'vigilante' ); ?>
                </button>
            </p>
        </form>
        <?php
    }

    /**
     * Render activity log tab
     */
    private function render_tab_activity_log() {
        $is_disabled = $this->render_module_disabled_notice( 'activity_log' );
        $options = $this->settings->get_section( 'activity_log' );
        ?>
        <form class="vigilante-settings-form <?php echo $is_disabled ? 'vigilante-form-disabled' : ''; ?>" data-section="activity_log" <?php echo $is_disabled ? 'inert' : ''; ?>>
            <div id="vigilante-section-audit-settings" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'Security Audit Settings', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                    <span class="vigilante-method-badge database"><?php esc_html_e( 'Database', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Security event logging and auditing.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Retention', 'vigilante' ); ?></th>
                        <td>
                            <input type="number" name="activity_log[retention_days]" value="<?php echo esc_attr( $options['retention_days'] ?? 30 ); ?>" min="7" max="365" class="small-text">
                            <?php esc_html_e( 'days', 'vigilante' ); ?>
                            &nbsp;&nbsp;
                            <input type="number" name="activity_log[max_entries]" value="<?php echo esc_attr( $options['max_entries'] ?? 10000 ); ?>" min="100" max="100000" step="100" class="small-text">
                            <?php esc_html_e( 'max entries', 'vigilante' ); ?>
                            <p class="description"><?php esc_html_e( 'Whichever limit is reached first takes effect. Changes apply immediately on save; daily maintenance also enforces these limits automatically.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Events to Log', 'vigilante' ); ?></th>
                        <td>
                            <fieldset style="display:grid; grid-template-columns:1fr 1fr; gap:6px 24px; max-width:600px;">
                                <label><input type="checkbox" name="activity_log[log_logins]" value="1" <?php checked( ! empty( $options['log_logins'] ) ); ?>> <?php esc_html_e( 'Successful logins', 'vigilante' ); ?></label>
                                <label><input type="checkbox" name="activity_log[log_failed_logins]" value="1" <?php checked( ! empty( $options['log_failed_logins'] ) ); ?>> <?php esc_html_e( 'Failed login attempts', 'vigilante' ); ?></label>
                                <label><input type="checkbox" name="activity_log[log_user_changes]" value="1" <?php checked( ! empty( $options['log_user_changes'] ) ); ?>> <?php esc_html_e( 'User changes', 'vigilante' ); ?></label>
                                <label><input type="checkbox" name="activity_log[log_post_changes]" value="1" <?php checked( ! empty( $options['log_post_changes'] ) ); ?>> <?php esc_html_e( 'Content changes', 'vigilante' ); ?></label>
                                <label><input type="checkbox" name="activity_log[log_plugin_changes]" value="1" <?php checked( ! empty( $options['log_plugin_changes'] ) ); ?>> <?php esc_html_e( 'Plugin changes', 'vigilante' ); ?></label>
                                <label><input type="checkbox" name="activity_log[log_theme_changes]" value="1" <?php checked( ! empty( $options['log_theme_changes'] ) ); ?>> <?php esc_html_e( 'Theme changes', 'vigilante' ); ?></label>
                                <label><input type="checkbox" name="activity_log[log_comments]" value="1" <?php checked( ! empty( $options['log_comments'] ) ); ?>> <?php esc_html_e( 'Comment changes', 'vigilante' ); ?></label>
                                <label><input type="checkbox" name="activity_log[log_media]" value="1" <?php checked( ! empty( $options['log_media'] ) ); ?>> <?php esc_html_e( 'Media uploads/deletions', 'vigilante' ); ?></label>
                                <label><input type="checkbox" name="activity_log[log_file_changes]" value="1" <?php checked( ! empty( $options['log_file_changes'] ) ); ?>> <?php esc_html_e( 'File integrity events', 'vigilante' ); ?></label>
                                <label><input type="checkbox" name="activity_log[log_option_changes]" value="1" <?php checked( ! empty( $options['log_option_changes'] ) ); ?>> <?php esc_html_e( 'WordPress option changes', 'vigilante' ); ?></label>
                            </fieldset>
                            <div class="notice notice-info inline" style="margin:10px 0 0;padding:8px 12px;">
                                <p style="margin:0;">
                                    <?php esc_html_e( 'Firewall blocks, security events, and Vigilant settings changes are always logged regardless of the above selections.', 'vigilante' ); ?>
                                </p>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Option Tracking', 'vigilante' ); ?></th>
                        <td>
                            <p class="description" style="margin-top:0;"><?php esc_html_e( 'When "WordPress option changes" is enabled, Vigilant tracks ~30 core WordPress settings (site URL, admin email, registration, active plugins, theme, comments, privacy, etc.). Use the field below to track additional options from other plugins.', 'vigilante' ); ?></p>
                            <br>
                            <label><?php esc_html_e( 'Additional options to track:', 'vigilante' ); ?></label><br>
                            <textarea name="activity_log[tracked_options]" rows="3" cols="50" class="regular-text code" placeholder="woocommerce_&#10;seopress_&#10;wpforms_"><?php echo esc_textarea( implode( "\n", $options['tracked_options'] ?? array() ) ); ?></textarea>
                            <p class="description"><?php esc_html_e( 'One option name per line. Use a trailing underscore to match all options with that prefix (e.g. "woocommerce_" tracks all WooCommerce settings).', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Exclusions', 'vigilante' ); ?></th>
                        <td>
                            <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; max-width:600px;">
                                <div>
                                    <label><?php esc_html_e( 'Excluded user IDs:', 'vigilante' ); ?></label><br>
                                    <textarea name="activity_log[excluded_users]" rows="3" cols="25"><?php echo esc_textarea( implode( "\n", $options['excluded_users'] ?? array() ) ); ?></textarea>
                                    <p class="description"><?php esc_html_e( 'One user ID per line. Actions by these users will not be logged.', 'vigilante' ); ?></p>
                                </div>
                                <div>
                                    <label><?php esc_html_e( 'Excluded IPs:', 'vigilante' ); ?></label><br>
                                    <textarea name="activity_log[excluded_ips]" rows="3" cols="25"><?php echo esc_textarea( implode( "\n", $options['excluded_ips'] ?? array() ) ); ?></textarea>
                                    <p class="description"><?php esc_html_e( 'One IP per line. Requests from these IPs will not be logged.', 'vigilante' ); ?></p>
                                </div>
                            </div>
                        </td>
                    </tr>
                </table>
            </div>

            <p class="submit vigilante-submit-buttons">
                <button type="submit" class="button button-primary vigilante-save-btn" data-original-text="<?php esc_attr_e( 'Save Settings', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Save Settings', 'vigilante' ); ?>
                </button>
                <button type="button" class="button vigilante-reset-section-btn" data-original-text="<?php esc_attr_e( 'Reset to Defaults', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Reset to Defaults', 'vigilante' ); ?>
                </button>
            </p>
        </form>

        <div id="vigilante-section-audit-recent" class="vigilante-settings-section">
            <h2><?php esc_html_e( 'Recent Activity', 'vigilante' ); ?></h2>

            <?php
            $logs = $this->activity_log->get_logs( array( 'per_page' => 20 ) );
            $total_logs = $this->activity_log->get_logs_count();

            // Label maps for translated display
            $type_labels = array(
                'login'    => __( 'Login', 'vigilante' ),
                'user'     => __( 'User', 'vigilante' ),
                'content'  => __( 'Content', 'vigilante' ),
                'plugin'   => __( 'Plugin', 'vigilante' ),
                'theme'    => __( 'Theme', 'vigilante' ),
                'settings' => __( 'Settings', 'vigilante' ),
                'comment'  => __( 'Comment', 'vigilante' ),
                'media'    => __( 'Media', 'vigilante' ),
                'firewall' => __( 'Firewall', 'vigilante' ),
                'file'     => __( 'File', 'vigilante' ),
                'security' => __( 'Security', 'vigilante' ),
                'system'   => __( 'System', 'vigilante' ),
            );
            $severity_labels = array(
                'info'     => __( 'Info', 'vigilante' ),
                'warning'  => __( 'Warning', 'vigilante' ),
                'critical' => __( 'Critical', 'vigilante' ),
            );

            $firewall_options = $this->settings->get_section( 'firewall' );
            $ip_whitelist = $firewall_options['ip_whitelist'] ?? array();
            $ip_blacklist = $firewall_options['ip_blacklist'] ?? array();
            $ua_whitelist = $firewall_options['ua_whitelist'] ?? array();
            $ua_blacklist = $firewall_options['ua_blacklist'] ?? array();
            ?>

            <div class="vigilante-log-filters">
                <input type="text" id="vigilante-log-search" size="1" placeholder="<?php esc_attr_e( 'Search logs (min. 3 characters)...', 'vigilante' ); ?>" class="vigilante-log-search-input">
                <select id="vigilante-log-type-filter">
                    <option value=""><?php esc_html_e( 'All Types', 'vigilante' ); ?></option>
                    <option value="login"><?php esc_html_e( 'Login', 'vigilante' ); ?></option>
                    <option value="user"><?php esc_html_e( 'User', 'vigilante' ); ?></option>
                    <option value="content"><?php esc_html_e( 'Content', 'vigilante' ); ?></option>
                    <option value="plugin"><?php esc_html_e( 'Plugin', 'vigilante' ); ?></option>
                    <option value="theme"><?php esc_html_e( 'Theme', 'vigilante' ); ?></option>
                    <option value="settings"><?php esc_html_e( 'Settings', 'vigilante' ); ?></option>
                    <option value="comment"><?php esc_html_e( 'Comment', 'vigilante' ); ?></option>
                    <option value="media"><?php esc_html_e( 'Media', 'vigilante' ); ?></option>
                    <option value="firewall"><?php esc_html_e( 'Firewall', 'vigilante' ); ?></option>
                    <option value="file"><?php esc_html_e( 'File', 'vigilante' ); ?></option>
                    <option value="security"><?php esc_html_e( 'Security', 'vigilante' ); ?></option>
                    <option value="system"><?php esc_html_e( 'System', 'vigilante' ); ?></option>
                </select>
                <select id="vigilante-log-severity-filter">
                    <option value=""><?php esc_html_e( 'All Severities', 'vigilante' ); ?></option>
                    <option value="info"><?php esc_html_e( 'Info', 'vigilante' ); ?></option>
                    <option value="warning"><?php esc_html_e( 'Warning', 'vigilante' ); ?></option>
                    <option value="critical"><?php esc_html_e( 'Critical', 'vigilante' ); ?></option>
                </select>
                <select id="vigilante-log-method-filter">
                    <option value=""><?php esc_html_e( 'All Methods', 'vigilante' ); ?></option>
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                    <option value="PATCH">PATCH</option>
                    <option value="OPTIONS">OPTIONS</option>
                    <option value="HEAD">HEAD</option>
                </select>
                <button type="button" id="vigilante-log-refresh" class="button"><?php esc_html_e( 'Refresh', 'vigilante' ); ?></button>
                <span class="vigilante-pagination" id="vigilante-log-pagination" data-total="<?php echo esc_attr( $total_logs ); ?>" data-per-page="20" data-page="1">
                    <?php if ( $total_logs > 20 ) : ?>
                    <button type="button" class="vigilante-page-first" title="<?php esc_attr_e( 'First page', 'vigilante' ); ?>" disabled>&laquo;</button>
                    <button type="button" class="vigilante-page-prev" title="<?php esc_attr_e( 'Previous page', 'vigilante' ); ?>" disabled>&lsaquo;</button>
                    <?php endif; ?>
                    <span class="vigilante-page-info">
                        <?php
                        $showing = min( 20, $total_logs );
                        printf(
                            /* translators: 1: first item, 2: last item, 3: total items */
                            esc_html__( '%1$d–%2$d of %3$d', 'vigilante' ),
                            $total_logs > 0 ? 1 : 0,
                            absint( $showing ),
                            absint( $total_logs )
                        );
                        ?>
                    </span>
                    <?php if ( $total_logs > 20 ) : ?>
                    <button type="button" class="vigilante-page-next" title="<?php esc_attr_e( 'Next page', 'vigilante' ); ?>">&rsaquo;</button>
                    <button type="button" class="vigilante-page-last" title="<?php esc_attr_e( 'Last page', 'vigilante' ); ?>">&raquo;</button>
                    <?php endif; ?>
                </span>
            </div>

            <div class="vigilante-log-table-wrap">
            <table id="vigilante-activity-log-table" class="wp-list-table widefat striped">
                <thead>
                    <tr>
                        <th class="column-date"><?php esc_html_e( 'Date', 'vigilante' ); ?></th>
                        <th class="column-type"><?php esc_html_e( 'Type', 'vigilante' ); ?></th>
                        <th class="column-method"><?php esc_html_e( 'Method', 'vigilante' ); ?></th>
                        <th class="column-severity"><?php esc_html_e( 'Severity', 'vigilante' ); ?></th>
                        <th class="column-message"><?php esc_html_e( 'Message', 'vigilante' ); ?></th>
                        <th class="column-user"><?php esc_html_e( 'User', 'vigilante' ); ?></th>
                        <th class="column-ip"><?php esc_html_e( 'IP', 'vigilante' ); ?></th>
                        <th class="column-details"><?php esc_html_e( 'Details', 'vigilante' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    if ( empty( $logs ) ) :
                        ?>
                        <tr><td colspan="8"><?php esc_html_e( 'No log entries found.', 'vigilante' ); ?></td></tr>
                    <?php else : ?>
                        <?php foreach ( $logs as $log ) :
                            $request_method = isset( $log->request_method ) ? $log->request_method : '';
                            // Prepare details as a simple object
                            $ip_val = (string) ( $log->ip_address ?? '' );
                            $ua_val = (string) ( $log->user_agent ?? '' );
                            $details = array(
                                'id'                 => (int) $log->id,
                                'type'               => (string) ( $log->event_type ?? '' ),
                                'action'             => (string) ( $log->event_action ?? '' ),
                                'message'            => (string) ( $log->event_message ?? '' ),
                                'user'               => (string) ( $log->user_login ?? '' ),
                                'ip'                 => $ip_val,
                                'user_agent'         => $ua_val,
                                'request_method'     => (string) $request_method,
                                'date'               => (string) ( $log->created_at ?? '' ),
                                'severity'           => (string) ( $log->severity ?? 'info' ),
                                'is_ip_whitelisted'  => ( '' !== $ip_val && in_array( $ip_val, $ip_whitelist, true ) ),
                                'is_ip_blacklisted'  => ( '' !== $ip_val && in_array( $ip_val, $ip_blacklist, true ) ),
                                'is_ua_whitelisted'  => ( '' !== $ua_val && in_array( $ua_val, $ua_whitelist, true ) ),
                                'is_ua_blacklisted'  => ( '' !== $ua_val && in_array( $ua_val, $ua_blacklist, true ) ),
                            );
                            $display_type = isset( $type_labels[ $log->event_type ] ) ? $type_labels[ $log->event_type ] : $log->event_type;
                            $display_severity = isset( $severity_labels[ $log->severity ] ) ? $severity_labels[ $log->severity ] : $log->severity;
                            ?>
                        <tr class="vigilante-severity-<?php echo esc_attr( $log->severity ); ?>">
                            <td><?php echo esc_html( $log->created_at ); ?></td>
                            <td><?php echo esc_html( $display_type ); ?></td>
                            <td><?php if ( ! empty( $request_method ) ) : ?><span class="vigilante-method-label vigilante-method-<?php echo esc_attr( strtolower( $request_method ) ); ?>"><?php echo esc_html( $request_method ); ?></span><?php else : ?>-<?php endif; ?></td>
                            <td><span class="vigilante-badge vigilante-badge-<?php echo esc_attr( $log->severity ); ?>"><?php echo esc_html( $display_severity ); ?></span></td>
                            <td><?php echo esc_html( $log->event_message ); ?></td>
                            <td><?php echo esc_html( $log->user_login ?? '-' ); ?></td>
                            <td><code><?php echo esc_html( $log->ip_address ); ?></code></td>
                            <td>
                                <button type="button" class="button button-small vigilante-view-log-details" 
                                    data-details='<?php echo esc_attr( wp_json_encode( $details, JSON_HEX_APOS | JSON_HEX_QUOT ) ); ?>'>
                                    <?php esc_html_e( 'View', 'vigilante' ); ?>
                                </button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
            </div>

            <!-- Log Details Modal -->
            <div id="vigilante-log-details-modal" class="vigilante-modal" style="display: none;">
                <div class="vigilante-modal-content">
                    <span class="vigilante-modal-close">&times;</span>
                    <h3><?php esc_html_e( 'Log Entry Details', 'vigilante' ); ?></h3>
                    <div id="vigilante-log-details-content"></div>
                </div>
            </div>

            <p>
                <button type="button" class="button vigilante-export-logs"><?php esc_html_e( 'Export Audit Log', 'vigilante' ); ?></button>
                <button type="button" class="button vigilante-clear-logs" style="color: #a00;"><?php esc_html_e( 'Clear All Logs', 'vigilante' ); ?></button>
            </p>
        </div>
        <?php
    }

    /**
     * Render File Integrity tab
     */
    private function render_tab_file_integrity() {
        $is_disabled = $this->render_module_disabled_notice( 'file_integrity' );
        $options = $this->settings->get_section( 'file_integrity' );
        $last_scan = get_option( 'vigilante_last_integrity_scan' );
        $last_results = get_option( 'vigilante_last_integrity_results' );
        $ignored_files = get_option( 'vigilante_ignored_files', array() );

        // Backward compat: convert old notify_on_changes to notify_level
        $notify_level = $options['notify_level'] ?? '';
        if ( empty( $notify_level ) ) {
            $notify_level = ! empty( $options['notify_on_changes'] ) ? 'all' : 'disabled';
        }

        // Closed + Removed plugins data. Surfaced inside Last Scan Results so the
        // user sees file findings and plugin closures together (same tier of risk,
        // same UI), and as the trigger to keep Last Scan Results open even when no
        // file scan has run yet (the daily cron may have populated this section).
        //
        // Gating by last_check_time > 0 is how "Clear Previous Results" visually
        // resets this block: the option vigilante_plugin_status_last_check is
        // deleted on Clear, but the state map and the ignored list survive so the
        // next scan reconstructs without degrading a 'removed' slug. While
        // last_check is 0, we treat the plugin_status data as if it didn't exist.
        if ( ! class_exists( 'Vigilante_Plugin_Status' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-plugin-status.php';
        }
        $closed_checker    = new Vigilante_Plugin_Status( $this->settings, $this->activity_log );
        $closed_last_check = $closed_checker->get_last_check_time();
        if ( $closed_last_check > 0 ) {
            $closed_plugins         = $closed_checker->get_closed_plugins();
            $ignored_closed_plugins = $closed_checker->get_ignored_closed_plugins();
        } else {
            $closed_plugins         = array();
            $ignored_closed_plugins = array();
        }
        $has_closed      = ! empty( $closed_plugins );
        $datetime_format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
        ?>
        <form class="vigilante-settings-form <?php echo $is_disabled ? 'vigilante-form-disabled' : ''; ?>" data-section="file_integrity" <?php echo $is_disabled ? 'inert' : ''; ?>>
            <div id="vigilante-section-fi-monitoring" class="vigilante-settings-section">
                <h2>
                    <?php esc_html_e( 'File Integrity Monitoring', 'vigilante' ); ?>
                    <span class="vigilante-method-badge php"><?php esc_html_e( 'PHP', 'vigilante' ); ?></span>
                </h2>
                <p><?php esc_html_e( 'Detects file modifications using WordPress.org checksums.', 'vigilante' ); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Automatic Scans', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="file_integrity[auto_scan]" value="1" <?php checked( ! empty( $options['auto_scan'] ) ); ?>>
                                <?php esc_html_e( 'Enable scheduled file integrity scans', 'vigilante' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Scan Frequency', 'vigilante' ); ?></th>
                        <td>
                            <select name="file_integrity[scan_frequency]">
                                <option value="daily" <?php selected( $options['scan_frequency'] ?? 'daily', 'daily' ); ?>><?php esc_html_e( 'Daily', 'vigilante' ); ?></option>
                                <option value="weekly" <?php selected( $options['scan_frequency'] ?? 'daily', 'weekly' ); ?>><?php esc_html_e( 'Weekly', 'vigilante' ); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Email Notifications', 'vigilante' ); ?></th>
                        <td>
                            <select name="file_integrity[notify_level]">
                                <option value="all" <?php selected( $notify_level, 'all' ); ?>><?php esc_html_e( 'All issues (modified + suspicious)', 'vigilante' ); ?></option>
                                <option value="suspicious_only" <?php selected( $notify_level, 'suspicious_only' ); ?>><?php esc_html_e( 'Suspicious files only', 'vigilante' ); ?></option>
                                <option value="disabled" <?php selected( $notify_level, 'disabled' ); ?>><?php esc_html_e( 'Disabled', 'vigilante' ); ?></option>
                            </select>
                            <p class="description"><?php esc_html_e( '"Suspicious files only" reduces noise by skipping modified file notifications. Recommended for most sites.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Instant Alert', 'vigilante' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="file_integrity[instant_alert]" value="1" <?php checked( ! empty( $options['instant_alert'] ) ); ?>>
                                <?php esc_html_e( 'Send immediate alert when modified, suspicious or additional files are detected, or when a closed plugin is found', 'vigilante' ); ?>
                            </label>
                            <p class="description"><?php esc_html_e( 'Fires even if the Email Notifications setting above is set to Disabled.', 'vigilante' ); ?></p>
                            <p class="description">
                                <?php
                                printf(
                                    /* translators: %s: Link to notification settings */
                                    esc_html__( '&#9432; Notifications are sent to the recipients configured in %s.', 'vigilante' ),
                                    '<a href="' . esc_url( admin_url( 'admin.php?page=vigilante&tab=tools' ) ) . '">' . esc_html__( 'Settings & Tools', 'vigilante' ) . '</a>'
                                );
                                ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Scan Scope', 'vigilante' ); ?></th>
                        <td>
                            <fieldset>
                                <label>
                                    <input type="checkbox" name="file_integrity[scan_core]" value="1" <?php checked( $options['scan_core'] ?? true ); ?>>
                                    <?php esc_html_e( 'Core files (compare against WordPress.org checksums)', 'vigilante' ); ?>
                                </label>
                                <br>
                                <label>
                                    <input type="checkbox" name="file_integrity[scan_plugins]" value="1" <?php checked( $options['scan_plugins'] ?? true ); ?>>
                                    <?php esc_html_e( 'Plugins (WordPress.org repository plugins)', 'vigilante' ); ?>
                                </label>
                                <br>
                                <label>
                                    <input type="checkbox" name="file_integrity[scan_themes]" value="1" <?php checked( $options['scan_themes'] ?? true ); ?>>
                                    <?php esc_html_e( 'Themes (WordPress.org repository themes)', 'vigilante' ); ?>
                                </label>
                                <br>
                                <label>
                                    <input type="checkbox" name="file_integrity[scan_uploads]" value="1" <?php checked( $options['scan_uploads'] ?? true ); ?>>
                                    <?php esc_html_e( 'Uploads directory (detect PHP files, double extensions, .htaccess)', 'vigilante' ); ?>
                                </label>
                                <br>
                                <label>
                                    <input type="checkbox" name="file_integrity[scan_critical_config]" value="1" <?php checked( $options['scan_critical_config'] ?? true ); ?>>
                                    <?php esc_html_e( 'Critical config files (wp-config.php, .htaccess baseline monitoring)', 'vigilante' ); ?>
                                </label>
                                <br>
                                <label>
                                    <input type="checkbox" name="file_integrity[check_closed_plugins]" value="1" <?php checked( $options['check_closed_plugins'] ?? true ); ?>>
                                    <?php esc_html_e( 'Closed plugins (daily check against the WordPress.org repository)', 'vigilante' ); ?>
                                </label>
                            </fieldset>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Excluded Paths', 'vigilante' ); ?></th>
                        <td>
                            <textarea name="file_integrity[excluded_paths]" rows="4" class="large-text code" placeholder="wp-content/cache&#10;wp-content/languages"><?php echo esc_textarea( implode( "\n", $options['excluded_paths'] ?? array() ) ); ?></textarea>
                            <p class="description"><?php esc_html_e( 'One path per line (relative to WordPress root). Files within these paths will be skipped during scans.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Excluded Extensions', 'vigilante' ); ?></th>
                        <td>
                            <textarea name="file_integrity[excluded_extensions]" rows="3" class="large-text code" placeholder=".log&#10;.po&#10;.mo&#10;.pot"><?php echo esc_textarea( implode( "\n", $options['excluded_extensions'] ?? array() ) ); ?></textarea>
                            <p class="description"><?php esc_html_e( 'One extension per line (e.g. .log, .po, .mo). Files with these extensions will be skipped. Useful to avoid false positives from translation or log files.', 'vigilante' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <p class="submit vigilante-submit-buttons">
                <button type="submit" class="button button-primary vigilante-save-btn" data-original-text="<?php esc_attr_e( 'Save Settings', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Save Settings', 'vigilante' ); ?>
                </button>
                <button type="button" class="button vigilante-reset-section-btn" data-original-text="<?php esc_attr_e( 'Reset to Defaults', 'vigilante' ); ?>">
                    <?php esc_html_e( 'Reset to Defaults', 'vigilante' ); ?>
                </button>
                <span class="vigilante-buttons-separator"></span>
                <button type="button" class="button button-primary vigilante-run-scan">
                    <?php esc_html_e( 'Run Scan Now', 'vigilante' ); ?>
                </button>
                <button type="button" class="button vigilante-clear-scan-btn vigilante-clear-scan">
                    <?php esc_html_e( 'Clear Previous Results', 'vigilante' ); ?>
                </button>
            </p>
        </form>

        <div id="vigilante-scan-results" class="vigilante-settings-section" style="display:none;"></div>

        <?php if ( $last_scan || $has_closed || $closed_last_check > 0 ) : ?>
        <div id="vigilante-section-fi-last-scan" class="vigilante-settings-section">
            <h2><?php esc_html_e( 'Last Scan Results', 'vigilante' ); ?></h2>
            <?php if ( $last_scan ) : ?>
            <p>
                <?php
                // Build the "X files scanned" hint inline with the date so it doesn't
                // need its own stat box (keeps the row compact when closed plugins are
                // present).
                $scanned_total = 0;
                if ( $last_results ) {
                    $scanned_total = (int) ( $last_results['ok'] ?? 0 )
                        + count( $last_results['modified'] ?? array() )
                        + count( $last_results['suspicious'] ?? array() )
                        + count( $last_results['extra'] ?? array() )
                        + count( $ignored_files );
                }
                if ( $scanned_total > 0 ) {
                    printf(
                        /* translators: 1: date and time of last scan, 2: formatted file count */
                        esc_html__( 'Last scan: %1$s (%2$s files scanned)', 'vigilante' ),
                        esc_html( wp_date( $datetime_format, $last_scan ) ),
                        esc_html( number_format_i18n( $scanned_total ) )
                    );
                } else {
                    printf(
                        /* translators: %s: date and time of last scan */
                        esc_html__( 'Last scan: %s', 'vigilante' ),
                        esc_html( wp_date( $datetime_format, $last_scan ) )
                    );
                }
                if ( $closed_last_check > 0 && $closed_last_check !== (int) $last_scan ) {
                    echo ' &middot; ';
                    printf(
                        /* translators: %s: date and time of last closed plugins check */
                        esc_html__( 'Closed plugins last checked: %s', 'vigilante' ),
                        esc_html( wp_date( $datetime_format, $closed_last_check ) )
                    );
                }
                ?>
            </p>
            <?php elseif ( $closed_last_check > 0 ) : ?>
            <p>
                <?php
                printf(
                    /* translators: %s: date and time of last closed plugins check */
                    esc_html__( 'Closed plugins last checked: %s &middot; the daily cron is running, no full integrity scan yet.', 'vigilante' ),
                    esc_html( wp_date( $datetime_format, $closed_last_check ) )
                );
                ?>
            </p>
            <?php endif; ?>
            <div id="vigilante-last-scan-results">
                <?php if ( $last_results || $has_closed ) : ?>
                    <div class="vigilante-scan-summary">
                        <?php if ( $last_results ) : ?>
                        <div class="vigilante-scan-stat vigilante-stat-ok">
                            <span class="vigilante-stat-number"><?php echo esc_html( $last_results['ok'] ?? 0 ); ?></span>
                            <span class="vigilante-stat-label"><?php esc_html_e( 'OK', 'vigilante' ); ?></span>
                        </div>
                        <div class="vigilante-scan-stat vigilante-stat-modified">
                            <span class="vigilante-stat-number"><?php echo esc_html( count( $last_results['modified'] ?? array() ) ); ?></span>
                            <span class="vigilante-stat-label"><?php esc_html_e( 'Modified', 'vigilante' ); ?></span>
                        </div>
                        <div class="vigilante-scan-stat vigilante-stat-suspicious">
                            <span class="vigilante-stat-number"><?php echo esc_html( count( $last_results['suspicious'] ?? array() ) ); ?></span>
                            <span class="vigilante-stat-label"><?php esc_html_e( 'Suspicious', 'vigilante' ); ?></span>
                        </div>
                        <div class="vigilante-scan-stat vigilante-stat-extra">
                            <span class="vigilante-stat-number"><?php echo esc_html( count( $last_results['extra'] ?? array() ) ); ?></span>
                            <span class="vigilante-stat-label"><?php esc_html_e( 'Extra', 'vigilante' ); ?></span>
                        </div>
                        <?php endif; ?>
                        <?php if ( $has_closed ) : ?>
                        <div class="vigilante-scan-stat vigilante-stat-suspicious">
                            <span class="vigilante-stat-number" style="color: #d63638;"><?php echo (int) count( $closed_plugins ); ?></span>
                            <span class="vigilante-stat-label"><?php esc_html_e( 'Closed/Removed', 'vigilante' ); ?></span>
                        </div>
                        <?php endif; ?>
                        <?php if ( ! empty( $ignored_files ) ) : ?>
                        <div class="vigilante-scan-stat vigilante-stat-ignored">
                            <span class="vigilante-stat-number"><?php echo esc_html( count( $ignored_files ) ); ?></span>
                            <span class="vigilante-stat-label"><?php esc_html_e( 'Ignored', 'vigilante' ); ?></span>
                        </div>
                        <?php endif; ?>
                    </div>

                    <?php if ( ! empty( $last_results['suspicious'] ) ) : ?>
                    <div class="vigilante-file-list vigilante-suspicious-files vigilante-paginated-section" data-bulk-mode="ignore">
                        <h3 style="color: #d63638;"><?php esc_html_e( 'Suspicious Files', 'vigilante' ); ?></h3>
                        <p class="description" style="color: #d63638;"><?php esc_html_e( '&#9888; Warning: These files may contain malicious code or are in unexpected locations. Review immediately!', 'vigilante' ); ?></p>
                        <div class="vigilante-fi-bulk-bar">
                            <button type="button" class="button vigilante-bulk-ignore" disabled><?php esc_html_e( 'Ignore selected', 'vigilante' ); ?></button>
                            <span class="vigilante-fi-bulk-count" aria-live="polite"></span>
                        </div>
                        <div class="vigilante-fi-pagination-wrap"></div>
                        <table class="wp-list-table widefat fixed striped vigilante-fi-paginated">
                            <thead>
                                <tr>
                                    <td class="manage-column column-cb check-column"><input type="checkbox" class="vigilante-fi-cb-all" aria-label="<?php esc_attr_e( 'Select all', 'vigilante' ); ?>"></td>
                                    <th><?php esc_html_e( 'File', 'vigilante' ); ?></th>
                                    <th style="width: 250px;"><?php esc_html_e( 'Reason', 'vigilante' ); ?></th>
                                    <th style="width: 120px;"><?php esc_html_e( 'Type', 'vigilante' ); ?></th>
                                    <th style="width: 80px;"><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                foreach ( $last_results['suspicious'] as $item ) {
                                    $file_path = '';
                                    $file_reason = __( 'Unknown', 'vigilante' );
                                    $file_type = 'unknown';

                                    if ( is_array( $item ) ) {
                                        if ( isset( $item['file'] ) ) {
                                            $file_path = $item['file'];
                                        }
                                        if ( isset( $item['reason'] ) ) {
                                            $file_reason = $item['reason'];
                                        }
                                        if ( isset( $item['type'] ) ) {
                                            $file_type = $item['type'];
                                        }
                                    } else {
                                        $file_path = (string) $item;
                                    }
                                    ?>
                                    <tr>
                                        <th scope="row" class="check-column"><input type="checkbox" class="vigilante-fi-cb" value="<?php echo esc_attr( $file_path ); ?>"></th>
                                        <td><code style="color: #d63638;"><?php echo esc_html( $file_path ); ?></code></td>
                                        <td><?php echo esc_html( $file_reason ); ?></td>
                                        <td><?php echo esc_html( $file_type ); ?></td>
                                        <td><button type="button" class="button button-small vigilante-ignore-file" data-file="<?php echo esc_attr( $file_path ); ?>"><?php esc_html_e( 'Ignore', 'vigilante' ); ?></button></td>
                                    </tr>
                                    <?php
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                    <?php endif; ?>

                    <?php if ( ! empty( $last_results['extra'] ) ) : ?>
                    <div class="vigilante-file-list vigilante-extra-files vigilante-paginated-section" data-bulk-mode="ignore">
                        <h3 style="color: #b32d2e;"><?php esc_html_e( 'Extra Files', 'vigilante' ); ?></h3>
                        <p class="description"><?php esc_html_e( 'PHP files found in plugins or themes that are not part of the original distribution from WordPress.org. May be legitimate customizations or injected backdoors.', 'vigilante' ); ?></p>
                        <div class="vigilante-fi-bulk-bar">
                            <button type="button" class="button vigilante-bulk-ignore" disabled><?php esc_html_e( 'Ignore selected', 'vigilante' ); ?></button>
                            <span class="vigilante-fi-bulk-count" aria-live="polite"></span>
                        </div>
                        <div class="vigilante-fi-pagination-wrap"></div>
                        <table class="wp-list-table widefat fixed striped vigilante-fi-paginated">
                            <thead>
                                <tr>
                                    <td class="manage-column column-cb check-column"><input type="checkbox" class="vigilante-fi-cb-all" aria-label="<?php esc_attr_e( 'Select all', 'vigilante' ); ?>"></td>
                                    <th><?php esc_html_e( 'File', 'vigilante' ); ?></th>
                                    <th style="width: 250px;"><?php esc_html_e( 'Reason', 'vigilante' ); ?></th>
                                    <th style="width: 120px;"><?php esc_html_e( 'Type', 'vigilante' ); ?></th>
                                    <th style="width: 80px;"><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                foreach ( $last_results['extra'] as $item ) {
                                    $file_path = is_array( $item ) ? ( $item['file'] ?? '' ) : (string) $item;
                                    $file_reason = is_array( $item ) ? ( $item['reason'] ?? __( 'Unknown', 'vigilante' ) ) : __( 'Unknown', 'vigilante' );
                                    $file_type = is_array( $item ) ? ( $item['type'] ?? 'unknown' ) : 'unknown';
                                    ?>
                                    <tr>
                                        <th scope="row" class="check-column"><input type="checkbox" class="vigilante-fi-cb" value="<?php echo esc_attr( $file_path ); ?>"></th>
                                        <td><code style="color: #b32d2e;"><?php echo esc_html( $file_path ); ?></code></td>
                                        <td><?php echo esc_html( $file_reason ); ?></td>
                                        <td><?php echo esc_html( $file_type ); ?></td>
                                        <td><button type="button" class="button button-small vigilante-ignore-file" data-file="<?php echo esc_attr( $file_path ); ?>"><?php esc_html_e( 'Ignore', 'vigilante' ); ?></button></td>
                                    </tr>
                                    <?php
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                    <?php endif; ?>

                    <?php
                    // Split critical config files from regular modified files.
                    // Computed unconditionally so the three sub-sections that consume
                    // these arrays (Critical Config, Closed + Removed, Modified Files)
                    // can render independently and in the order the team picked.
                    $critical_modified = array();
                    $regular_modified  = array();
                    if ( $last_results && ! empty( $last_results['modified'] ) ) {
                        foreach ( $last_results['modified'] as $item ) {
                            if ( is_array( $item ) && isset( $item['type'] ) && 'critical_config' === $item['type'] ) {
                                $critical_modified[] = $item;
                            } else {
                                $regular_modified[] = $item;
                            }
                        }
                    }
                    ?>

                    <?php if ( ! empty( $critical_modified ) ) : ?>
                    <div class="vigilante-file-list vigilante-critical-config-files">
                        <h3 style="color: #e36210;"><?php esc_html_e( 'Critical config files modified', 'vigilante' ); ?></h3>
                        <p class="description">
                            <?php esc_html_e( 'These files are common targets for code injection. Review the changes and approve if they are legitimate. Vigilant\'s own blocks are excluded from this check.', 'vigilante' ); ?>
                        </p>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e( 'File', 'vigilante' ); ?></th>
                                    <th style="width: 200px;"><?php esc_html_e( 'Changes', 'vigilante' ); ?></th>
                                    <th style="width: 220px;"><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ( $critical_modified as $crit_item ) :
                                    $crit_file = $crit_item['file'] ?? '';
                                    $crit_baseline_size = $crit_item['baseline_size'] ?? 0;
                                    $crit_current_size = $crit_item['current_size'] ?? 0;
                                    $crit_diff = $crit_item['diff'] ?? array();
                                    $crit_id = sanitize_html_class( $crit_file );
                                    $added_count = is_array( $crit_diff ) ? count( $crit_diff['added'] ?? array() ) : 0;
                                    $removed_count = is_array( $crit_diff ) ? count( $crit_diff['removed'] ?? array() ) : 0;
                                    $diff_unavailable = is_array( $crit_diff ) && ! empty( $crit_diff['unavailable'] );
                                ?>
                                <tr>
                                    <td><code style="color: #e36210;"><?php echo esc_html( $crit_file ); ?></code></td>
                                    <td>
                                        <?php if ( ! $diff_unavailable ) : ?>
                                            <span style="color: #007017;">+<?php echo (int) $added_count; ?></span>
                                            <span style="color: #b32d2e;">-<?php echo (int) $removed_count; ?></span>
                                            <?php esc_html_e( 'lines', 'vigilante' ); ?><br>
                                        <?php endif; ?>
                                        <small style="color: #50575e;">
                                            <?php
                                            printf(
                                                /* translators: 1: baseline size, 2: current size */
                                                esc_html__( '%1$s &rarr; %2$s bytes', 'vigilante' ),
                                                esc_html( number_format_i18n( $crit_baseline_size ) ),
                                                esc_html( number_format_i18n( $crit_current_size ) )
                                            );
                                            ?>
                                        </small>
                                    </td>
                                    <td>
                                        <button type="button" class="button button-small vigilante-toggle-critical-content" data-target="vigilante-critical-content-<?php echo esc_attr( $crit_id ); ?>" data-label-show="<?php esc_attr_e( 'Review changes', 'vigilante' ); ?>" data-label-hide="<?php esc_attr_e( 'Hide changes', 'vigilante' ); ?>">
                                            <?php esc_html_e( 'Review changes', 'vigilante' ); ?>
                                        </button>
                                        <button type="button" class="button button-small button-primary vigilante-approve-critical-file" data-file="<?php echo esc_attr( $crit_file ); ?>">
                                            <?php esc_html_e( 'Approve', 'vigilante' ); ?>
                                        </button>
                                    </td>
                                </tr>
                                <tr id="vigilante-critical-content-<?php echo esc_attr( $crit_id ); ?>" class="vigilante-critical-content-row" style="display:none;">
                                    <td colspan="3" style="padding: 0;">
                                        <div class="vigilante-critical-content" style="max-height: 400px; overflow: auto; background: #fff; padding: 10px; font-size: 12px; line-height: 1.5; font-family: Consolas, Monaco, monospace; border-top: 1px solid #c3c4c7;">
                                            <?php if ( $diff_unavailable ) : ?>
                                                <p style="color: #50575e; font-style: italic; margin: 0;">
                                                    <?php esc_html_e( 'Diff not available for this file (baseline was created before diff tracking was added). Approve to enable diff on future changes.', 'vigilante' ); ?>
                                                </p>
                                            <?php elseif ( empty( $crit_diff['added'] ) && empty( $crit_diff['removed'] ) ) : ?>
                                                <p style="color: #50575e; font-style: italic; margin: 0;">
                                                    <?php esc_html_e( 'No line-level changes detected (may be whitespace or reordering).', 'vigilante' ); ?>
                                                </p>
                                            <?php else : ?>
                                                <?php if ( ! empty( $crit_diff['removed'] ) ) : ?>
                                                    <?php foreach ( $crit_diff['removed'] as $rline ) : ?>
<div style="background: #fbeaea; color: #b32d2e; padding: 1px 4px; white-space: pre-wrap; word-wrap: break-word;"><span style="display: inline-block; width: 50px; color: #999; user-select: none;"><?php echo (int) $rline['line']; ?></span>- <?php echo esc_html( $rline['content'] ); ?></div>
                                                    <?php endforeach; ?>
                                                <?php endif; ?>
                                                <?php if ( ! empty( $crit_diff['added'] ) ) : ?>
                                                    <?php foreach ( $crit_diff['added'] as $aline ) : ?>
<div style="background: #e6f4e9; color: #007017; padding: 1px 4px; white-space: pre-wrap; word-wrap: break-word;"><span style="display: inline-block; width: 50px; color: #999; user-select: none;"><?php echo (int) $aline['line']; ?></span>+ <?php echo esc_html( $aline['content'] ); ?></div>
                                                    <?php endforeach; ?>
                                                <?php endif; ?>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php endif; ?>

                    <?php if ( $has_closed ) : ?>
                    <div class="vigilante-file-list vigilante-closed-plugins">
                        <h3 style="color: #d63638;"><?php esc_html_e( 'Closed + Removed Plugins', 'vigilante' ); ?></h3>
                        <p class="description" style="color: #d63638;">
                            <?php esc_html_e( '&#9888; Warning: These plugins have been closed in the WordPress.org repository. Closures usually indicate malware, security issues, guideline violations, or supply chain attacks. Uninstall and replace as soon as possible.', 'vigilante' ); ?>
                        </p>
                        <table class="wp-list-table widefat striped">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e( 'Plugin', 'vigilante' ); ?></th>
                                    <th style="width: 70px;"><?php esc_html_e( 'Version', 'vigilante' ); ?></th>
                                    <th style="width: 90px;"><?php esc_html_e( 'State', 'vigilante' ); ?></th>
                                    <th style="width: 110px;"><?php esc_html_e( 'Closed date', 'vigilante' ); ?></th>
                                    <th><?php esc_html_e( 'Reason', 'vigilante' ); ?></th>
                                    <th style="width: 130px;"><?php esc_html_e( 'Detected', 'vigilante' ); ?></th>
                                    <th style="width: 90px;"><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ( $closed_plugins as $cp_slug => $cp_entry ) :
                                    $cp_state       = $cp_entry['state'] ?? '';
                                    $cp_state_label = 'closed' === $cp_state ? __( 'Closed', 'vigilante' ) : __( 'Removed', 'vigilante' );
                                    $cp_state_color = 'closed' === $cp_state ? '#d63638' : '#b32d2e';
                                    $cp_reason      = '';
                                    if ( ! empty( $cp_entry['closed_reason_text'] ) ) {
                                        $cp_reason = $cp_entry['closed_reason_text'];
                                    } elseif ( 'removed' === $cp_state ) {
                                        $cp_reason = __( 'Removed from repository (metadata hidden, typical of Security Issue closures)', 'vigilante' );
                                    }
                                    $cp_detected = isset( $cp_entry['first_detected'] ) ? (int) $cp_entry['first_detected'] : 0;
                                    ?>
                                    <tr>
                                        <td>
                                            <strong><?php echo esc_html( $cp_entry['name'] ?? $cp_slug ); ?></strong><br>
                                            <a href="<?php echo esc_url( 'https://wordpress.org/plugins/' . $cp_slug . '/' ); ?>" target="_blank" rel="noopener noreferrer"><code style="color: #50575e;"><?php echo esc_html( $cp_slug ); ?></code></a>
                                        </td>
                                        <td><?php echo esc_html( $cp_entry['version'] ?? '' ); ?></td>
                                        <td><span style="color: <?php echo esc_attr( $cp_state_color ); ?>; font-weight: 600;"><?php echo esc_html( $cp_state_label ); ?></span></td>
                                        <td><?php echo esc_html( $cp_entry['closed_date'] ?? '' ); ?></td>
                                        <td><?php echo esc_html( $cp_reason ); ?></td>
                                        <td>
                                            <?php echo $cp_detected > 0 ? esc_html( wp_date( $datetime_format, $cp_detected ) ) : '&mdash;'; ?>
                                        </td>
                                        <td>
                                            <button type="button" class="button button-small vigilante-ignore-closed-plugin" data-slug="<?php echo esc_attr( $cp_slug ); ?>">
                                                <?php esc_html_e( 'Ignore', 'vigilante' ); ?>
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php endif; ?>

                    <?php if ( ! empty( $regular_modified ) ) : ?>
                    <div class="vigilante-file-list vigilante-paginated-section" data-bulk-mode="ignore">
                        <h3><?php esc_html_e( 'Modified Files', 'vigilante' ); ?></h3>
                        <p class="description"><?php esc_html_e( 'These files (apparently) differ from the original WordPress or plugin versions.', 'vigilante' ); ?></p>
                        <div class="vigilante-fi-bulk-bar">
                            <button type="button" class="button vigilante-bulk-ignore" disabled><?php esc_html_e( 'Ignore selected', 'vigilante' ); ?></button>
                            <span class="vigilante-fi-bulk-count" aria-live="polite"></span>
                        </div>
                        <div class="vigilante-fi-pagination-wrap"></div>
                        <table class="wp-list-table widefat fixed striped vigilante-fi-paginated">
                            <thead>
                                <tr>
                                    <td class="manage-column column-cb check-column"><input type="checkbox" class="vigilante-fi-cb-all" aria-label="<?php esc_attr_e( 'Select all', 'vigilante' ); ?>"></td>
                                    <th><?php esc_html_e( 'File', 'vigilante' ); ?></th>
                                    <th style="width: 100px;"><?php esc_html_e( 'Type', 'vigilante' ); ?></th>
                                    <th style="width: 80px;"><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                foreach ( $regular_modified as $item ) {
                                    $file_path = '';
                                    $file_type = 'unknown';

                                    if ( is_array( $item ) ) {
                                        if ( isset( $item['file'] ) ) {
                                            $file_path = $item['file'];
                                        }
                                        if ( isset( $item['type'] ) ) {
                                            $file_type = $item['type'];
                                        }
                                    } else {
                                        $file_path = (string) $item;
                                    }
                                    ?>
                                    <tr>
                                        <th scope="row" class="check-column"><input type="checkbox" class="vigilante-fi-cb" value="<?php echo esc_attr( $file_path ); ?>"></th>
                                        <td><code><?php echo esc_html( $file_path ); ?></code></td>
                                        <td><?php echo esc_html( $file_type ); ?></td>
                                        <td><button type="button" class="button button-small vigilante-ignore-file" data-file="<?php echo esc_attr( $file_path ); ?>"><?php esc_html_e( 'Ignore', 'vigilante' ); ?></button></td>
                                    </tr>
                                    <?php
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                    <?php endif; ?>

                    <?php if ( $last_results && empty( $last_results['modified'] ) && empty( $last_results['suspicious'] ) && empty( $last_results['extra'] ) && ! $has_closed ) : ?>
                    <p class="vigilante-all-clear" style="color: #00a32a; font-weight: bold;">
                        <?php esc_html_e( 'Good Job! All files passed integrity check. No issues found.', 'vigilante' ); ?>
                    </p>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>

        <?php if ( ! empty( $ignored_closed_plugins ) ) : ?>
        <div id="vigilante-section-fi-ignored-closed" class="vigilante-settings-section">
            <h2><?php esc_html_e( 'Ignored Closed + Removed Plugins', 'vigilante' ); ?></h2>
            <p class="description"><?php esc_html_e( 'These plugins remain closed/removed in WordPress.org but you have chosen to hide them from the main list and from email alerts. They are still installed on the site and still running their code &mdash; the silencing is purely cosmetic.', 'vigilante' ); ?></p>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e( 'Plugin', 'vigilante' ); ?></th>
                        <th style="width: 110px;"><?php esc_html_e( 'State', 'vigilante' ); ?></th>
                        <th style="width: 120px;"><?php esc_html_e( 'Closed date', 'vigilante' ); ?></th>
                        <th style="width: 130px;"><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $ignored_closed_plugins as $icp_slug => $icp_entry ) :
                        $icp_state       = $icp_entry['state'] ?? '';
                        $icp_state_label = 'closed' === $icp_state ? __( 'Closed', 'vigilante' ) : __( 'Removed', 'vigilante' );
                        ?>
                        <tr>
                            <td>
                                <strong><?php echo esc_html( $icp_entry['name'] ?? $icp_slug ); ?></strong><br>
                                <a href="<?php echo esc_url( 'https://wordpress.org/plugins/' . $icp_slug . '/' ); ?>" target="_blank" rel="noopener noreferrer"><code style="color: #50575e;"><?php echo esc_html( $icp_slug ); ?></code></a>
                            </td>
                            <td><?php echo esc_html( $icp_state_label ); ?></td>
                            <td><?php echo esc_html( $icp_entry['closed_date'] ?? '' ); ?></td>
                            <td>
                                <button type="button" class="button button-small vigilante-unignore-closed-plugin" data-slug="<?php echo esc_attr( $icp_slug ); ?>">
                                    <?php esc_html_e( 'Stop ignoring', 'vigilante' ); ?>
                                </button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <p style="margin-top: 10px;">
                <button type="button" class="button vigilante-clear-ignored-closed-plugins"><?php esc_html_e( 'Clear All Ignored Closed + Removed Plugins', 'vigilante' ); ?></button>
            </p>
        </div>
        <?php endif; ?>

        <?php if ( ! empty( $ignored_files ) ) : ?>
        <div id="vigilante-section-fi-ignored" class="vigilante-settings-section">
            <h2><?php esc_html_e( 'Ignored Files', 'vigilante' ); ?></h2>
            <p class="description"><?php esc_html_e( 'These files are excluded from scan results and email notifications. They will still be scanned but any findings will be hidden.', 'vigilante' ); ?></p>
            <div class="vigilante-paginated-section" data-bulk-mode="unignore">
                <div class="vigilante-fi-bulk-bar">
                    <button type="button" class="button vigilante-bulk-unignore" disabled><?php esc_html_e( 'Stop ignoring selected', 'vigilante' ); ?></button>
                    <span class="vigilante-fi-bulk-count" aria-live="polite"></span>
                </div>
                <div class="vigilante-fi-pagination-wrap"></div>
                <table class="wp-list-table widefat fixed striped vigilante-fi-paginated">
                <thead>
                    <tr>
                        <td class="manage-column column-cb check-column"><input type="checkbox" class="vigilante-fi-cb-all" aria-label="<?php esc_attr_e( 'Select all', 'vigilante' ); ?>"></td>
                        <th><?php esc_html_e( 'File', 'vigilante' ); ?></th>
                        <th style="width: 120px;"><?php esc_html_e( 'Actions', 'vigilante' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $ignored_files as $file ) : ?>
                    <tr>
                        <th scope="row" class="check-column"><input type="checkbox" class="vigilante-fi-cb" value="<?php echo esc_attr( $file ); ?>"></th>
                        <td><code><?php echo esc_html( $file ); ?></code></td>
                        <td><button type="button" class="button button-small vigilante-unignore-file" data-file="<?php echo esc_attr( $file ); ?>"><?php esc_html_e( 'Stop ignoring', 'vigilante' ); ?></button></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <p style="margin-top: 10px;">
                <button type="button" class="button vigilante-clear-ignored"><?php esc_html_e( 'Clear All Ignored Files', 'vigilante' ); ?></button>
            </p>
        </div>
        <?php endif; ?>
        <?php
    }

    /**
     * Render sidebar with promotional widgets
     */
    private function render_sidebar() {
        $promo_banner = new Vigilante_Promo_Banner( 'vigilante', 'vigilante' );
        $promo_banner->render();
    }

    /**
     * AJAX: Create backup
     */
    public function ajax_create_backup() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $backup_manager = new Vigilante_Backup_Manager();
        $result = $backup_manager->create_backups();

        if ( $result ) {
            wp_send_json_success( __( 'Backup created successfully.', 'vigilante' ) );
        } else {
            wp_send_json_error( __( 'Failed to create backup.', 'vigilante' ) );
        }
    }

    /**
     * AJAX: Save settings
     */
    public function ajax_save_settings() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $section = isset( $_POST['section'] ) ? sanitize_key( $_POST['section'] ) : '';
        
        // Handle $_POST['data'] based on type
        if ( isset( $_POST['data'] ) && is_array( $_POST['data'] ) ) {
            $data = map_deep( wp_unslash( $_POST['data'] ), 'sanitize_text_field' );
        } elseif ( isset( $_POST['data'] ) ) {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
            $raw_data = wp_unslash( $_POST['data'] );
            parse_str( $raw_data, $data );
            $data = map_deep( $data, 'sanitize_textarea_field' );
        } else {
            $data = array();
        }

        if ( empty( $section ) ) {
            wp_send_json_error( __( 'Invalid section.', 'vigilante' ) );
        }

        // Check if 2FA is being enabled or method changed (for notification sending)
        $send_2fa_notification = false;
        $send_login_url_notification = false;
        
        if ( 'login_security' === $section ) {
            // Read old state from DB
            $db_options = get_option( Vigilante_Settings::OPTION_NAME, array() );
            $old_2fa_enabled = ! empty( $db_options['login_security']['two_factor']['enabled'] );
            $old_method = $db_options['login_security']['two_factor']['method'] ?? 'email';
            
            // Check new state from submitted data
            $new_2fa_enabled = false;
            $notify_on_enable = false;
            $new_method = isset( $data['login_security']['two_factor']['method'] ) 
                ? sanitize_key( $data['login_security']['two_factor']['method'] ) 
                : 'email';
            
            if ( isset( $data['login_security']['two_factor']['enabled'] ) ) {
                $new_2fa_enabled = filter_var( $data['login_security']['two_factor']['enabled'], FILTER_VALIDATE_BOOLEAN );
            }
            if ( isset( $data['login_security']['two_factor']['notify_on_enable'] ) ) {
                $notify_on_enable = filter_var( $data['login_security']['two_factor']['notify_on_enable'], FILTER_VALIDATE_BOOLEAN );
            }
            
            // Send notification if:
            // 1. 2FA is being enabled (was off, now on) OR
            // 2. Method changed while 2FA is enabled
            if ( $notify_on_enable && $new_2fa_enabled ) {
                if ( ! $old_2fa_enabled || ( $old_2fa_enabled && $old_method !== $new_method ) ) {
                    $send_2fa_notification = true;
                }
            }

            // Check if login URL changed and notification is enabled
            $old_login_url = $db_options['login_security']['custom_login_url'] ?? '';
            $new_login_url = isset( $data['login_security']['custom_login_url'] )
                ? sanitize_title( $data['login_security']['custom_login_url'] )
                : '';
            $notify_on_url_change = isset( $data['login_security']['notify_on_login_url_change'] )
                ? filter_var( $data['login_security']['notify_on_login_url_change'], FILTER_VALIDATE_BOOLEAN )
                : false;

            if ( $notify_on_url_change && ! empty( $new_login_url ) && $new_login_url !== $old_login_url ) {
                $send_login_url_notification = true;
            }
        }
        
        // Get defaults
        $defaults = $this->settings->get_default_options();

        // Read ONLY saved options from database (not merged with defaults)
        $saved_options = get_option( Vigilante_Settings::OPTION_NAME, array() );

        // Handle modules
        if ( 'modules' === $section && isset( $data['modules'] ) ) {
            if ( ! isset( $saved_options['modules'] ) ) {
                $saved_options['modules'] = array();
            }
            foreach ( $data['modules'] as $module => $enabled ) {
                $module = sanitize_key( $module );
                $saved_options['modules'][ $module ] = in_array( $enabled, array( '1', 1, 'true', true ), true );
            }
            // Clear active preset when modules change
            update_option( 'vigilante_active_preset', '' );
        } else {
            // Process primary section
            if ( isset( $data[ $section ] ) && is_array( $data[ $section ] ) ) {
                $section_defaults = isset( $defaults[ $section ] ) ? $defaults[ $section ] : array();
                $current_section = isset( $saved_options[ $section ] ) ? $saved_options[ $section ] : array();
                
                // Process the submitted data
                $processed = $this->process_section_data( $data[ $section ], $section_defaults, $current_section );
                
                // Save the processed section
                $saved_options[ $section ] = $processed;
                
                // Clear active preset when any section settings change
                update_option( 'vigilante_active_preset', '' );
            }
        }

        // Clear cache before saving
        wp_cache_delete( Vigilante_Settings::OPTION_NAME, 'options' );
        
        // Save to database
        update_option( Vigilante_Settings::OPTION_NAME, $saved_options );
        
        // Clear the settings cache
        $this->settings->clear_cache();

        // Apply changes based on section
        $this->apply_section_changes( $section, $saved_options );

        // Send 2FA notifications after settings are saved
        $notification_result = null;
        if ( $send_2fa_notification ) {
            $notification_result = $this->send_2fa_enable_notifications();
        }

        // Send login URL notifications after settings are saved
        $login_url_result = null;
        if ( $send_login_url_notification ) {
            $login_url_result = $this->send_login_url_notifications();
        }

        // Build success message
        $message = __( 'Settings saved successfully.', 'vigilante' );
        
        if ( $notification_result && $notification_result['sent'] > 0 ) {
            $message .= ' ' . sprintf(
                /* translators: %d: Number of emails sent */
                _n(
                    '2FA notification sent to %d user.',
                    '2FA notifications sent to %d users.',
                    $notification_result['sent'],
                    'vigilante'
                ),
                $notification_result['sent']
            );
        }

        if ( $login_url_result && $login_url_result['sent'] > 0 ) {
            $message .= ' ' . sprintf(
                /* translators: %d: Number of emails sent */
                _n(
                    'Login URL notification sent to %d user.',
                    'Login URL notifications sent to %d users.',
                    $login_url_result['sent'],
                    'vigilante'
                ),
                $login_url_result['sent']
            );
        }

        wp_send_json_success( $message );
    }
    
    /**
     * Send 2FA enable notifications to users
     *
     * @return array Result with 'sent' and 'failed' counts.
     */
    private function send_2fa_enable_notifications() {
        $result = array(
            'sent'   => 0,
            'failed' => 0,
        );
        
        // Get settings for roles and method
        $login_security = $this->settings->get_section( 'login_security' );
        $two_factor = isset( $login_security['two_factor'] ) ? $login_security['two_factor'] : array();
        $roles  = isset( $two_factor['enforced_roles'] ) ? $two_factor['enforced_roles'] : array( 'administrator' );
        $method = isset( $two_factor['method'] ) ? $two_factor['method'] : 'email';
        
        if ( empty( $roles ) ) {
            $roles = array( 'administrator' );
        }
        
        $excluded = isset( $two_factor['excluded_users'] ) ? array_map( 'absint', $two_factor['excluded_users'] ) : array();
        
        // Get users with these roles
        $args = array(
            'role__in' => $roles,
        );
        if ( ! empty( $excluded ) ) {
            // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- Small excluded users list from settings.
            $args['exclude'] = $excluded;
        }
        $users = get_users( $args );
        
        if ( empty( $users ) ) {
            return $result;
        }
        
        $site_name = get_bloginfo( 'name' );
        $from_name = ! empty( $two_factor['email_from_name'] ) ? $two_factor['email_from_name'] : $site_name;
        
        if ( 'totp' === $method ) {
            // Use TOTP class for styled HTML emails
            if ( ! class_exists( 'Vigilante_Two_Factor_TOTP' ) ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-two-factor-totp.php';
            }
            $totp = new Vigilante_Two_Factor_TOTP( $this->settings, $this->database, $this->activity_log );
            
            foreach ( $users as $user ) {
                // Skip users who already have TOTP configured
                $totp_data = $this->database->get_totp_data( $user->ID );
                if ( $totp_data && ! empty( $totp_data['is_configured'] ) ) {
                    continue;
                }
                
                $sent = $totp->send_activation_email( $user, $site_name, $from_name );
                
                if ( $sent ) {
                    $this->database->mark_2fa_notified( $user->ID );
                    $result['sent']++;
                } else {
                    $result['failed']++;
                }
            }
        } else {
            // Email method - use existing email 2FA class
            if ( ! class_exists( 'Vigilante_Two_Factor_Email' ) ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-two-factor-email.php';
            }
            $email_2fa = new Vigilante_Two_Factor_Email( $this->settings, $this->database, $this->activity_log );
            return $email_2fa->send_activation_notifications( false );
        }
        
        return $result;
    }

    /**
     * Send login URL change notifications to users with admin access
     *
     * @return array Result with 'sent' and 'failed' counts.
     */
    private function send_login_url_notifications() {
        $login_options = $this->settings->get_section( 'login_security' );
        $custom_url    = ! empty( $login_options['custom_login_url'] ) ? sanitize_title( $login_options['custom_login_url'] ) : '';

        if ( empty( $custom_url ) ) {
            return array( 'sent' => 0, 'failed' => 0 );
        }

        $login_url = home_url( $custom_url . '/' );
        $site_name = get_bloginfo( 'name' );

        $admin_roles = array( 'administrator', 'editor', 'author', 'contributor' );
        $users = get_users( array( 'role__in' => $admin_roles ) );

        if ( empty( $users ) ) {
            return array( 'sent' => 0, 'failed' => 0 );
        }

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Your login URL has changed', 'vigilante' ),
            $site_name
        );

        $body  = Vigilante_Email_Template::p( __( 'The login URL for the admin area has been changed. Please save the new URL below and use it from now on.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::url_box( $login_url, __( 'Your new login URL:', 'vigilante' ) );
        $body .= Vigilante_Email_Template::alert_box( __( 'The old login address (wp-login.php) will no longer work.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::button( $login_url, __( 'Go to login', 'vigilante' ) );

        $sent   = 0;
        $failed = 0;

        foreach ( $users as $user ) {
            $result = Vigilante_Email_Template::send(
                $user->user_email,
                $subject,
                __( 'Login URL changed', 'vigilante' ),
                $body
            );
            if ( $result ) {
                $sent++;
            } else {
                $failed++;
            }
        }

        if ( $this->activity_log ) {
            $this->activity_log->log(
                'login',
                'login_url_notified',
                sprintf(
                    /* translators: 1: Sent count, 2: Failed count */
                    __( 'Login URL notification sent on save: %1$d sent, %2$d failed', 'vigilante' ),
                    $sent,
                    $failed
                )
            );
        }

        return array( 'sent' => $sent, 'failed' => $failed );
    }

    /**
     * Process section data maintaining proper types from defaults
     *
     * @param array  $submitted_data Data submitted from form.
     * @param array  $defaults       Default values for this section.
     * @param array  $current        Current saved values.
     * @param string $section_name   Section name for special handling.
     * @return array Processed data.
     */
    private function process_section_data( $submitted_data, $defaults, $current, $section_name = '' ) {
        // Start with defaults, then merge current saved values
        $result = array_replace_recursive( $defaults, $current );
        
        // Process each submitted value
        foreach ( $submitted_data as $key => $value ) {
            $key = sanitize_key( $key );
            
            if ( is_array( $value ) ) {
                // Nested array (like rate_limiting)
                $nested_defaults = isset( $defaults[ $key ] ) && is_array( $defaults[ $key ] ) ? $defaults[ $key ] : array();
                $nested_current = isset( $result[ $key ] ) && is_array( $result[ $key ] ) ? $result[ $key ] : array();
                $result[ $key ] = $this->process_section_data( $value, $nested_defaults, $nested_current, $key );
            } else {
                // Determine type from default value
                $default_value = isset( $defaults[ $key ] ) ? $defaults[ $key ] : null;
                
                if ( null === $default_value ) {
                    // No default, check current value type or use as string
                    $current_value = isset( $current[ $key ] ) ? $current[ $key ] : null;
                    if ( is_bool( $current_value ) ) {
                        $result[ $key ] = in_array( $value, array( '1', 1, 'true', true ), true );
                    } elseif ( is_int( $current_value ) ) {
                        $result[ $key ] = intval( $value );
                    } elseif ( is_array( $current_value ) ) {
                        $result[ $key ] = is_string( $value ) ? array_filter( array_map( 'trim', explode( "\n", $value ) ) ) : (array) $value;
                    } else {
                        $result[ $key ] = sanitize_text_field( $value );
                    }
                } elseif ( is_bool( $default_value ) ) {
                    // Boolean: '1', 1, 'true' become true; '0', 0, '', 'false' become false
                    $result[ $key ] = in_array( $value, array( '1', 1, 'true', true ), true );
                } elseif ( is_int( $default_value ) ) {
                    // Integer - with special handling for time fields shown in minutes
                    $int_value = intval( $value );
                    
                    // Convert minutes to seconds for login_security duration fields
                    // These are displayed as minutes in the form but stored as seconds
                    if ( in_array( $key, array( 'lockout_duration', 'max_lockout_duration' ), true ) ) {
                        $int_value = $int_value * 60;
                    }
                    
                    $result[ $key ] = $int_value;
                } elseif ( is_array( $default_value ) ) {
                    // Array from textarea (e.g., IP lists)
                    if ( is_string( $value ) ) {
                        $result[ $key ] = array_filter( array_map( 'trim', explode( "\n", $value ) ) );
                    } else {
                        $result[ $key ] = (array) $value;
                    }
                } else {
                    // String - preserve newlines for textarea fields
                    if ( is_string( $value ) && ( strpos( $value, "\n" ) !== false || strpos( $value, "\r" ) !== false ) ) {
                        $result[ $key ] = sanitize_textarea_field( $value );
                    } else {
                        $result[ $key ] = sanitize_text_field( $value );
                    }
                }
            }
        }
        
        // Handle unchecked checkboxes: HTML forms don't submit unchecked boxes
        // If a boolean field exists in defaults but NOT in submitted_data, set it to false
        //
        // EXCEPTION: the top-level 'enabled' flag of every section is the
        // module's master switch and is controlled by the Dashboard module
        // toggle, NOT by a checkbox inside the section's form. Treating it
        // like a regular checkbox here would silently switch the module off
        // every time the user saves the tab — see the REST API enabled=false
        // regression. We only skip it at the top level (when section_name is
        // empty); nested 'enabled' fields like security_headers.csp.enabled
        // are real checkboxes and must keep the auto-unset behaviour.
        $preserve_top_level = array( 'enabled' );

        foreach ( $defaults as $key => $default_value ) {
            if ( '' === $section_name && in_array( $key, $preserve_top_level, true ) ) {
                continue;
            }
            if ( is_bool( $default_value ) && ! array_key_exists( $key, $submitted_data ) ) {
                $result[ $key ] = false;
            } elseif ( is_array( $default_value ) && ! isset( $submitted_data[ $key ] ) ) {
                // Check if this is a flat value list (like excluded_users, enforced_roles, ip_whitelist)
                // vs a nested settings group (like rate_limiting, two_factor)
                // Flat lists: default is empty array OR all values are scalar
                $is_value_list = empty( $default_value );
                if ( ! $is_value_list ) {
                    $is_value_list = true;
                    foreach ( $default_value as $dv ) {
                        if ( ! is_scalar( $dv ) ) {
                            $is_value_list = false;
                            break;
                        }
                    }
                }

                if ( $is_value_list ) {
                    // All items removed - reset to empty array
                    $result[ $key ] = array();
                } else {
                    // Nested settings group - handle boolean children
                    foreach ( $default_value as $nested_key => $nested_default ) {
                        if ( is_bool( $nested_default ) && isset( $result[ $key ] ) && is_array( $result[ $key ] ) ) {
                            $nested_submitted = isset( $submitted_data[ $key ] ) && is_array( $submitted_data[ $key ] ) 
                                ? $submitted_data[ $key ] 
                                : array();
                            if ( ! array_key_exists( $nested_key, $nested_submitted ) ) {
                                $result[ $key ][ $nested_key ] = false;
                            }
                        }
                    }
                }
            }
        }
        
        return $result;
    }

    /**
     * AJAX: Export settings
     */
    public function ajax_export_settings() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $options = $this->settings->get_all_options();
        $filename = 'vigilante-settings-' . gmdate( 'Y-m-d-His' ) . '.json';

        wp_send_json_success( array(
            'content'  => wp_json_encode( $options, JSON_PRETTY_PRINT ),
            'filename' => $filename,
        ) );
    }

    /**
     * AJAX: Import settings
     */
    public function ajax_import_settings() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        // Accept both 'settings' (from JS) and 'content' (legacy).
        // Do NOT run sanitize_text_field() on the raw payload: it calls
        // wp_strip_all_tags() internally, which removes any "<...>" substring
        // and turns a valid export JSON into garbage if any stored value
        // contains < or > (htaccess snippets, email templates, etc.). The
        // real sanitization happens after json_decode(), via map_deep() on
        // the parsed array.
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash
        $content = isset( $_POST['settings'] ) ? wp_unslash( $_POST['settings'] ) : '';
        if ( empty( $content ) ) {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash
            $content = isset( $_POST['content'] ) ? wp_unslash( $_POST['content'] ) : '';
        }

        if ( empty( $content ) || ! is_string( $content ) ) {
            wp_send_json_error( __( 'No content provided.', 'vigilante' ) );
        }

        $imported = json_decode( $content, true );

        if ( json_last_error() !== JSON_ERROR_NONE || ! is_array( $imported ) ) {
            wp_send_json_error( __( 'Invalid JSON format.', 'vigilante' ) );
        }

        // Sanitize imported data recursively
        $imported = map_deep( $imported, 'sanitize_text_field' );

        // Validate structure
        $defaults = $this->settings->get_default_options();
        $merged = array_replace_recursive( $defaults, $imported );

        // Save
        update_option( Vigilante_Settings::OPTION_NAME, $merged );
        $this->settings->clear_cache();

        // Re-evaluate the active preset marker. The imported config may match
        // a known preset exactly, partially, or not at all — without this step
        // the dashboard would keep showing whatever preset was active before
        // the import even if the new config no longer matches it.
        $matched_preset = $this->detect_matching_preset( $merged );
        if ( null === $matched_preset ) {
            delete_option( 'vigilante_active_preset' );
        } else {
            update_option( 'vigilante_active_preset', $matched_preset );
        }

        // Apply file changes after import
        $this->apply_all_file_changes( $merged );

        // Refresh the Security Analyzer score so the dashboard widget reflects
        // the imported config rather than the pre-import scan. Reuse the
        // post-Under-Attack scan hook (same job: full scan, async).
        if ( ! wp_next_scheduled( 'vigilante_under_attack_post_scan' ) ) {
            wp_schedule_single_event( time() + 5, 'vigilante_under_attack_post_scan' );
        }

        wp_send_json_success( __( 'Settings imported successfully.', 'vigilante' ) );
    }

    /**
     * Detect whether a vigilante_options array matches a known preset.
     *
     * A preset matches when every field the preset explicitly declares is
     * present in the config with the same (normalised) value. Fields outside
     * the preset are ignored — they may have been modified by the user before
     * applying the preset and do not invalidate the match. This mirrors how
     * apply_preset() now layers presets on top of the user's existing config.
     *
     * @param array $options The current/imported vigilante_options.
     * @return string|null   Preset id ('standard', 'maximum') or null if custom.
     */
    private function detect_matching_preset( $options ) {
        if ( ! is_array( $options ) ) {
            return null;
        }

        $presets = $this->settings->get_presets();

        foreach ( $presets as $preset_id => $preset_data ) {
            unset( $preset_data['name'], $preset_data['description'] );
            if ( $this->preset_subset_matches( $preset_data, $options ) ) {
                return $preset_id;
            }
        }

        return null;
    }

    /**
     * Check whether every leaf value inside $preset_subset exists with the
     * same (normalised) value at the same path inside $config.
     *
     * @param mixed $preset_subset Branch of the preset definition.
     * @param mixed $config        Same branch in the live/imported config.
     * @return bool
     */
    private function preset_subset_matches( $preset_subset, $config ) {
        if ( is_array( $preset_subset ) ) {
            if ( ! is_array( $config ) ) {
                return false;
            }
            foreach ( $preset_subset as $key => $value ) {
                if ( ! array_key_exists( $key, $config ) ) {
                    return false;
                }
                if ( ! $this->preset_subset_matches( $value, $config[ $key ] ) ) {
                    return false;
                }
            }
            return true;
        }

        return $this->normalise_scalar_for_compare( $preset_subset ) === $this->normalise_scalar_for_compare( $config );
    }

    /**
     * Normalise a scalar value so that the variants WordPress and the form
     * layer routinely produce ('1' / 1 / true → "1"; '' / '0' / 0 / false /
     * null → "") compare equal. Other values become strings unchanged.
     *
     * @param mixed $value
     * @return string
     */
    private function normalise_scalar_for_compare( $value ) {
        if ( is_bool( $value ) ) {
            return $value ? '1' : '';
        }
        if ( null === $value ) {
            return '';
        }
        if ( is_int( $value ) || is_float( $value ) ) {
            return (string) $value;
        }
        if ( is_string( $value ) ) {
            if ( 'true' === $value ) {
                return '1';
            }
            if ( 'false' === $value ) {
                return '';
            }
            return $value;
        }
        // Arrays and objects shouldn't reach here (handled by recursion above),
        // but if they do, fall back to a stable comparable representation.
        return wp_json_encode( $value );
    }

    /**
     * AJAX: Apply preset
     */
    public function ajax_apply_preset() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $preset = isset( $_POST['preset'] ) ? sanitize_key( $_POST['preset'] ) : '';
        
        // Handle reset to defaults
        if ( 'reset' === $preset ) {
            $defaults = $this->settings->get_default_options();
            update_option( Vigilante_Settings::OPTION_NAME, $defaults );
            $this->settings->clear_cache();
            
            // Clear active preset
            update_option( 'vigilante_active_preset', '' );
            
            // Apply file changes after reset
            $this->apply_all_file_changes( $defaults );
            
            wp_send_json_success( __( 'Settings reset to defaults.', 'vigilante' ) );
            return;
        }
        
        $presets = $this->settings->get_presets();

        if ( ! isset( $presets[ $preset ] ) ) {
            wp_send_json_error( __( 'Invalid preset.', 'vigilante' ) );
        }

        $preset_options = $presets[ $preset ];
        unset( $preset_options['name'], $preset_options['description'] );

        // Layer the preset on top of the user's CURRENT configuration, not on
        // top of defaults. This way applying a preset only changes the fields
        // the preset explicitly mentions; everything else stays as the user
        // had it. For example, applying Maximum will not flip HSTS off if the
        // user had it on — Maximum doesn't touch HSTS, so it's left alone.
        // Use "Reset to Defaults" if a clean slate is needed.
        $current = get_option( Vigilante_Settings::OPTION_NAME, array() );
        if ( ! is_array( $current ) ) {
            $current = array();
        }
        // Make sure all known keys exist before merging — array_replace_recursive
        // does not invent keys that are missing on both sides.
        $current = array_replace_recursive( $this->settings->get_default_options(), $current );

        $merged = array_replace_recursive( $current, $preset_options );

        update_option( Vigilante_Settings::OPTION_NAME, $merged );
        $this->settings->clear_cache();

        // Save active preset
        update_option( 'vigilante_active_preset', $preset );

        // Apply file changes after preset
        $this->apply_all_file_changes( $merged );

        wp_send_json_success( __( 'Preset applied successfully.', 'vigilante' ) );
    }

    /**
     * AJAX: Reset a specific section to defaults
     */
    public function ajax_reset_section() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $section = isset( $_POST['section'] ) ? sanitize_key( $_POST['section'] ) : '';
        
        if ( empty( $section ) ) {
            wp_send_json_error( __( 'No section specified.', 'vigilante' ) );
        }

        // Get current options and defaults
        $current_options = $this->settings->get_all_options();
        $defaults = $this->settings->get_default_options();

        // Check if section exists in defaults
        if ( ! isset( $defaults[ $section ] ) ) {
            wp_send_json_error( __( 'Invalid section.', 'vigilante' ) );
        }

        // Reset only this section to defaults
        $current_options[ $section ] = $defaults[ $section ];

        // Save
        update_option( Vigilante_Settings::OPTION_NAME, $current_options );
        $this->settings->clear_cache();

        // Apply file changes if needed
        $this->apply_section_changes( $section, $current_options );

        wp_send_json_success( array(
            'message' => __( 'Section reset to defaults.', 'vigilante' ),
            'section' => $section,
            'reload'  => true,
        ) );
    }

    /**
     * AJAX: Clear lockouts
     */
    public function ajax_clear_lockouts() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
        
        if ( ! empty( $ip ) ) {
            $this->database->clear_lockout( $ip );
        } else {
            $this->database->clear_all_lockouts();
        }

        wp_send_json_success( __( 'Lockouts cleared.', 'vigilante' ) );
    }

    /**
     * AJAX: Clear logs
     */
    public function ajax_clear_logs() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        if ( $this->activity_log ) {
            $result = $this->activity_log->clear_all_logs();
            if ( $result ) {
                wp_send_json_success( __( 'Logs cleared.', 'vigilante' ) );
            } else {
                wp_send_json_error( __( 'Failed to clear logs.', 'vigilante' ) );
            }
        } else {
            wp_send_json_error( __( 'Activity log not available.', 'vigilante' ) );
        }
    }

    /**
     * AJAX: Run file integrity scan.
     *
     * Triggers the file integrity scan, which now also runs the closed plugins
     * check at the end when the `check_closed_plugins` toggle is on. Activity
     * log is passed through so Security Audit entries (both file-level and
     * plugin-status) are recorded from this entry point.
     */
    public function ajax_run_scan() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        // Clear previous results before running new scan
        delete_option( 'vigilante_last_integrity_results' );
        delete_option( 'vigilante_last_integrity_scan' );

        $file_integrity = new Vigilante_File_Integrity( $this->settings, $this->database, $this->activity_log );
        $results = $file_integrity->run_scan();

        // Save new results
        update_option( 'vigilante_last_integrity_scan', time() );
        update_option( 'vigilante_last_integrity_results', $results );

        wp_send_json_success( array(
            'message'      => __( 'Scan completed.', 'vigilante' ),
            'results'      => $results,
            'ignored_count' => count( get_option( 'vigilante_ignored_files', array() ) ),
        ) );
    }

    /**
     * AJAX: Clear scan results.
     *
     * Wipes visually everything inside "Last Scan Results": file scan findings
     * (Suspicious / Modified / Extra / Critical Config), file hashes and the
     * Closed + Removed Plugins block.
     *
     * Implementation detail to keep persistence intact:
     *   - We delete the file scan options + hashes outright.
     *   - For plugin status we ONLY delete the last_check timestamp — the state
     *     map and the ignore list are preserved in DB. The render gates the
     *     plugin_status subsections on last_check > 0, so they hide after
     *     Clear (visual reset) and reappear on the next Run Scan Now with the
     *     state intact. This avoids degrading a 'removed' slug (404 without
     *     metadata) back to 'not_in_repo' on the next scan, which would
     *     silently lose the alert.
     *
     * The Ignored Files list and the Ignored Closed + Removed Plugins list
     * are preserved on purpose; each has its own explicit "Clear All …"
     * button.
     */
    public function ajax_clear_scan() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        delete_option( 'vigilante_last_integrity_results' );
        delete_option( 'vigilante_last_integrity_scan' );

        if ( $this->database ) {
            $this->database->clear_file_hashes();
        }

        // Visual reset of plugin_status block without touching the state map
        // or the ignored list. See PHPDoc above for the rationale.
        delete_option( 'vigilante_plugin_status_last_check' );

        wp_send_json_success( __( 'Scan results cleared.', 'vigilante' ) );
    }

    /**
     * AJAX: Ignore a file from scan results
     */
    public function ajax_ignore_file() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $file = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';

        if ( empty( $file ) ) {
            wp_send_json_error( __( 'No file specified.', 'vigilante' ) );
        }

        $file_integrity = new Vigilante_File_Integrity( $this->settings, $this->database );
        $file_integrity->ignore_file( $file );

        // Also remove the file from stored scan results so UI updates
        $results = get_option( 'vigilante_last_integrity_results' );
        if ( $results ) {
            foreach ( array( 'modified', 'suspicious', 'extra' ) as $category ) {
                if ( ! empty( $results[ $category ] ) ) {
                    $results[ $category ] = array_values(
                        array_filter(
                            $results[ $category ],
                            function ( $item ) use ( $file ) {
                                return ( is_array( $item ) ? ( $item['file'] ?? '' ) : (string) $item ) !== $file;
                            }
                        )
                    );
                }
            }
            update_option( 'vigilante_last_integrity_results', $results );
        }

        wp_send_json_success( __( 'File added to ignored list.', 'vigilante' ) );
    }

    /**
     * AJAX: Stop ignoring a file
     */
    public function ajax_unignore_file() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $file = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';

        if ( empty( $file ) ) {
            wp_send_json_error( __( 'No file specified.', 'vigilante' ) );
        }

        $file_integrity = new Vigilante_File_Integrity( $this->settings, $this->database );
        $file_integrity->unignore_file( $file );

        wp_send_json_success( __( 'File removed from ignored list.', 'vigilante' ) );
    }

    /**
     * AJAX: Bulk ignore multiple files at once
     *
     * Processes a single batch into ignored list and prunes them from the
     * stored scan results so the UI updates without a re-scan.
     */
    public function ajax_bulk_ignore_files() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized below per-item.
        $raw_files = isset( $_POST['files'] ) ? wp_unslash( $_POST['files'] ) : array();
        if ( ! is_array( $raw_files ) ) {
            wp_send_json_error( __( 'Invalid request.', 'vigilante' ) );
        }

        $files = array();
        foreach ( $raw_files as $f ) {
            $clean = sanitize_text_field( $f );
            if ( '' !== $clean ) {
                $files[] = $clean;
            }
        }

        if ( empty( $files ) ) {
            wp_send_json_error( __( 'No files selected.', 'vigilante' ) );
        }

        $file_integrity = new Vigilante_File_Integrity( $this->settings, $this->database );
        $count = 0;
        foreach ( $files as $file ) {
            $file_integrity->ignore_file( $file );
            $count++;
        }

        // Also prune the stored scan results so the UI matches the new ignore list.
        $results = get_option( 'vigilante_last_integrity_results' );
        if ( $results ) {
            $files_set = array_flip( $files );
            foreach ( array( 'modified', 'suspicious', 'extra' ) as $category ) {
                if ( ! empty( $results[ $category ] ) ) {
                    $results[ $category ] = array_values(
                        array_filter(
                            $results[ $category ],
                            function ( $item ) use ( $files_set ) {
                                $path = is_array( $item ) ? ( $item['file'] ?? '' ) : (string) $item;
                                return ! isset( $files_set[ $path ] );
                            }
                        )
                    );
                }
            }
            update_option( 'vigilante_last_integrity_results', $results );
        }

        wp_send_json_success(
            array(
                'count'   => $count,
                'message' => sprintf(
                    /* translators: %d: number of files added to the ignored list */
                    _n( '%d file added to ignored list.', '%d files added to ignored list.', $count, 'vigilante' ),
                    $count
                ),
            )
        );
    }

    /**
     * AJAX: Bulk un-ignore multiple files at once
     */
    public function ajax_bulk_unignore_files() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized below per-item.
        $raw_files = isset( $_POST['files'] ) ? wp_unslash( $_POST['files'] ) : array();
        if ( ! is_array( $raw_files ) ) {
            wp_send_json_error( __( 'Invalid request.', 'vigilante' ) );
        }

        $files = array();
        foreach ( $raw_files as $f ) {
            $clean = sanitize_text_field( $f );
            if ( '' !== $clean ) {
                $files[] = $clean;
            }
        }

        if ( empty( $files ) ) {
            wp_send_json_error( __( 'No files selected.', 'vigilante' ) );
        }

        $file_integrity = new Vigilante_File_Integrity( $this->settings, $this->database );
        $count = 0;
        foreach ( $files as $file ) {
            $file_integrity->unignore_file( $file );
            $count++;
        }

        wp_send_json_success(
            array(
                'count'   => $count,
                'message' => sprintf(
                    /* translators: %d: number of files removed from the ignored list */
                    _n( '%d file removed from ignored list.', '%d files removed from ignored list.', $count, 'vigilante' ),
                    $count
                ),
            )
        );
    }

    /**
     * AJAX: Clear all ignored files
     */
    public function ajax_clear_ignored() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $file_integrity = new Vigilante_File_Integrity( $this->settings, $this->database );
        $file_integrity->clear_ignored_files();

        wp_send_json_success( __( 'Ignored files list cleared.', 'vigilante' ) );
    }

    /**
     * AJAX: Ignore a closed/removed plugin slug so it stops appearing in the
     * main list and email digests. The plugin keeps running on the site;
     * silencing is purely cosmetic and reversible.
     */
    public function ajax_ignore_closed_plugin() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $slug = isset( $_POST['slug'] ) ? sanitize_key( wp_unslash( $_POST['slug'] ) ) : '';
        if ( '' === $slug ) {
            wp_send_json_error( __( 'No slug specified.', 'vigilante' ) );
        }

        if ( ! class_exists( 'Vigilante_Plugin_Status' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-plugin-status.php';
        }
        $checker = new Vigilante_Plugin_Status( $this->settings, $this->activity_log );
        $checker->ignore_slug( $slug );

        wp_send_json_success( __( 'Plugin added to the ignored list.', 'vigilante' ) );
    }

    /**
     * AJAX: Stop ignoring a previously-ignored closed/removed plugin slug.
     */
    public function ajax_unignore_closed_plugin() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $slug = isset( $_POST['slug'] ) ? sanitize_key( wp_unslash( $_POST['slug'] ) ) : '';
        if ( '' === $slug ) {
            wp_send_json_error( __( 'No slug specified.', 'vigilante' ) );
        }

        if ( ! class_exists( 'Vigilante_Plugin_Status' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-plugin-status.php';
        }
        $checker = new Vigilante_Plugin_Status( $this->settings, $this->activity_log );
        $checker->unignore_slug( $slug );

        wp_send_json_success( __( 'Plugin removed from the ignored list.', 'vigilante' ) );
    }

    /**
     * AJAX: Clear the entire ignored-closed-plugins list.
     */
    public function ajax_clear_ignored_closed_plugins() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        if ( ! class_exists( 'Vigilante_Plugin_Status' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-plugin-status.php';
        }
        $checker = new Vigilante_Plugin_Status( $this->settings, $this->activity_log );
        $checker->clear_ignored();

        wp_send_json_success( __( 'Ignored closed plugins list cleared.', 'vigilante' ) );
    }

    /**
     * AJAX: Test security headers
     */
    public function ajax_test_headers() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        // Get security grade from settings (not from actual HTTP request)
        $security_headers = new Vigilante_Security_Headers( $this->settings );
        $results = $security_headers->get_security_grade();

        wp_send_json_success( $results );
    }

    /**
     * Sanitize section data (kept for compatibility)
     *
     * @param string $section Section name.
     * @param array  $data    Section data.
     * @return array
     */
    private function sanitize_section_data( $section, $data ) {
        $sanitized = array();

        foreach ( $data as $key => $value ) {
            $key = sanitize_key( $key );
            
            if ( is_array( $value ) ) {
                $sanitized[ $key ] = $this->sanitize_section_data( $key, $value );
            } elseif ( is_numeric( $value ) ) {
                $sanitized[ $key ] = intval( $value );
            } else {
                $sanitized[ $key ] = sanitize_text_field( $value );
            }
        }

        return $sanitized;
    }

    /**
     * Apply changes after saving settings
     *
     * @param string $section     Section that was updated.
     * @param array  $all_options All options.
     */
    private function apply_section_changes( $section, $all_options ) {
        // Create fresh settings instance to ensure we have the latest data
        $fresh_settings = new Vigilante_Settings();

        // Regenerate htaccess for firewall section
        if ( 'firewall' === $section || 'modules' === $section ) {
            $htaccess = new Vigilante_Htaccess_Protection( $fresh_settings );
            $firewall_enabled = ! empty( $all_options['modules']['firewall'] );
            
            if ( $firewall_enabled ) {
                $htaccess->apply_rules();
            } else {
                $htaccess->remove_rules();
            }
        }

        // Regenerate htaccess for security_headers section
        if ( 'security_headers' === $section || 'modules' === $section ) {
            $security_headers = new Vigilante_Security_Headers( $fresh_settings );
            $headers_enabled = ! empty( $all_options['modules']['security_headers'] );
            
            if ( $headers_enabled ) {
                $security_headers->apply_rules();
            } else {
                $security_headers->remove_rules();
            }
        }

        // Regenerate wp-config for wp_hardening section
        if ( 'wp_hardening' === $section || 'modules' === $section ) {
            $wpconfig = new Vigilante_Wpconfig_Security( $fresh_settings );
            $hardening_enabled = ! empty( $all_options['modules']['wp_hardening'] );
            
            if ( $hardening_enabled ) {
                $wpconfig->apply_security_constants();
            } else {
                $wpconfig->remove_constants();
            }

            // Apply WordPress options for comments/pingbacks
            $hardening_options = $all_options['wp_hardening'] ?? array();

            if ( $hardening_enabled ) {
                // Pingbacks
                if ( ! empty( $hardening_options['disable_pingbacks'] ) ) {
                    update_option( 'default_pingback_flag', 0 );
                } else {
                    // Restore default: pingbacks enabled
                    update_option( 'default_pingback_flag', 1 );
                }

                // Trackbacks and ping status
                // Only close if either pingbacks OR trackbacks are disabled
                if ( ! empty( $hardening_options['disable_pingbacks'] ) || ! empty( $hardening_options['disable_trackbacks'] ) ) {
                    update_option( 'default_ping_status', 'closed' );
                } else {
                    // Restore default: pings open
                    update_option( 'default_ping_status', 'open' );
                }

                // Comment moderation
                if ( ! empty( $hardening_options['require_comment_moderation'] ) ) {
                    update_option( 'comment_moderation', 1 );
                } else {
                    // Restore default: no moderation required
                    update_option( 'comment_moderation', 0 );
                }
            }
        }

        // Trim activity log entries immediately when limits change
        if ( 'activity_log' === $section && $this->activity_log ) {
            $this->activity_log->cleanup_old_logs();
        }

        // Flush rewrite rules if login URL changed
        if ( 'login_security' === $section ) {
            $login_options = $all_options['login_security'] ?? array();
            if ( ! empty( $login_options['custom_login_url'] ) ) {
                delete_option( 'vigilante_login_rules_version' );
            }
        }

        // Log the settings change with readable section name
        if ( $this->activity_log ) {
            $section_names = array(
                'firewall'         => __( 'Firewall', 'vigilante' ),
                'login_security'   => __( 'Login Security', 'vigilante' ),
                'security_headers' => __( 'Security Headers', 'vigilante' ),
                'rest_api_security'=> __( 'REST API Security', 'vigilante' ),
                'user_security'    => __( 'User Security', 'vigilante' ),
                'wp_hardening'     => __( 'WP Hardening', 'vigilante' ),
                'activity_log'     => __( 'Security Audit', 'vigilante' ),
                'file_integrity'   => __( 'File Integrity', 'vigilante' ),
                'email'            => __( 'Notification Settings', 'vigilante' ),
                'backup'           => __( 'Backup', 'vigilante' ),
                'advanced'         => __( 'Advanced', 'vigilante' ),
                'modules'          => __( 'Modules', 'vigilante' ),
            );
            $display_name = isset( $section_names[ $section ] ) ? $section_names[ $section ] : $section;

            $this->activity_log->log(
                'settings',
                'settings_updated',
                sprintf(
                    /* translators: %s: Section name */
                    __( 'Settings updated: %s', 'vigilante' ),
                    $display_name
                ),
                array( 'section' => $section ),
                'info'
            );
        }
    }

    /**
     * Apply all file changes (htaccess, wp-config) based on current options
     *
     * Used after preset, import, or reset operations
     *
     * @param array $all_options All plugin options.
     */
    private function apply_all_file_changes( $all_options ) {
        // Refresh settings cache first
        $this->settings->clear_cache();

        // Create fresh settings instance
        $fresh_settings = new Vigilante_Settings();

        // Apply firewall htaccess changes
        $htaccess = new Vigilante_Htaccess_Protection( $fresh_settings );
        $firewall_enabled = ! empty( $all_options['modules']['firewall'] );
        
        if ( $firewall_enabled ) {
            $htaccess->apply_rules();
        } else {
            $htaccess->remove_rules();
        }

        // Apply security headers htaccess changes
        $security_headers = new Vigilante_Security_Headers( $fresh_settings );
        $headers_enabled = ! empty( $all_options['modules']['security_headers'] );
        
        if ( $headers_enabled ) {
            $security_headers->apply_rules();
        } else {
            $security_headers->remove_rules();
        }

        // Apply wp-config changes
        $wpconfig = new Vigilante_Wpconfig_Security( $fresh_settings );
        $hardening_enabled = ! empty( $all_options['modules']['wp_hardening'] );
        
        if ( $hardening_enabled ) {
            $wpconfig->apply_security_constants();
        } else {
            $wpconfig->remove_constants();
        }

        // Apply WordPress options for comments/pingbacks
        $hardening_options = $all_options['wp_hardening'] ?? array();

        if ( $hardening_enabled ) {
            // Pingbacks
            if ( ! empty( $hardening_options['disable_pingbacks'] ) ) {
                update_option( 'default_pingback_flag', 0 );
            } else {
                // Restore default: pingbacks enabled
                update_option( 'default_pingback_flag', 1 );
            }

            // Trackbacks and ping status
            // Only close if either pingbacks OR trackbacks are disabled
            if ( ! empty( $hardening_options['disable_pingbacks'] ) || ! empty( $hardening_options['disable_trackbacks'] ) ) {
                update_option( 'default_ping_status', 'closed' );
            } else {
                // Restore default: pings open
                update_option( 'default_ping_status', 'open' );
            }

            // Comment moderation
            if ( ! empty( $hardening_options['require_comment_moderation'] ) ) {
                update_option( 'comment_moderation', 1 );
            } else {
                // Restore default: no moderation required
                update_option( 'comment_moderation', 0 );
            }
        }

        // Log the change
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'settings',
                'bulk_settings_applied',
                __( 'Bulk settings applied (preset/import/reset)', 'vigilante' ),
                array(),
                'info'
            );
        }
    }
}