<?php
/**
 * Deactivator Class
 *
 * Handles plugin deactivation tasks
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Deactivator
 *
 * Fired during plugin deactivation
 */
class Vigilante_Deactivator {

    /**
     * Run deactivation tasks
     */
    public static function deactivate() {
        // ALWAYS remove htaccess rules using the centralized manager
        self::remove_htaccess_rules();

        // ALWAYS remove wp-config security constants and restore originals
        self::remove_wpconfig_security();

        // Clear scheduled events
        self::clear_scheduled_events();

        // Send deactivation email
        self::send_deactivation_email();

        // Clear transients
        delete_transient( 'vigilante_activated' );
        delete_transient( 'vigilante_restore_on_deactivate' );
        delete_transient( 'vigilante_backup_error' );

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Remove htaccess rules using the centralized manager
     */
    private static function remove_htaccess_rules() {
        // Use the centralized manager
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        
        $manager = Vigilante_Htaccess_Manager::get_instance();

        // Remove our blocks
        $manager->remove_block( '# BEGIN Vigilante Protection', '# END Vigilante Protection' );
        $manager->remove_block( '# BEGIN Vigilante Security Headers', '# END Vigilante Security Headers' );
    }

    /**
     * Remove wp-config security constants and restore original values
     */
    private static function remove_wpconfig_security() {
        $wpconfig_path = ABSPATH . 'wp-config.php';

        if ( ! file_exists( $wpconfig_path ) ) {
            return;
        }

        // Initialize WP_Filesystem
        global $wp_filesystem;
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        if ( ! $wp_filesystem || ! $wp_filesystem->is_writable( $wpconfig_path ) ) {
            return;
        }

        $content = $wp_filesystem->get_contents( $wpconfig_path );

        if ( false === $content || empty( $content ) ) {
            return;
        }

        $modified = false;

        // Step 1: Remove our Vigilante block
        if ( strpos( $content, '/* BEGIN Vigilante Security Constants */' ) !== false ) {
            $lines = explode( "\n", $content );
            $new_lines = array();
            $inside_block = false;

            foreach ( $lines as $line ) {
                if ( strpos( $line, '/* BEGIN Vigilante Security Constants */' ) !== false ) {
                    $inside_block = true;
                    continue;
                }

                if ( strpos( $line, '/* END Vigilante Security Constants */' ) !== false ) {
                    $inside_block = false;
                    continue;
                }

                if ( ! $inside_block ) {
                    $new_lines[] = $line;
                }
            }

            $content = implode( "\n", $new_lines );
            $modified = true;
        }

        // Step 2: Uncomment original constants (restore [VIGILANTE_ORIGINAL] lines)
        $original_marker = '// [VIGILANTE_ORIGINAL] ';
        if ( strpos( $content, $original_marker ) !== false ) {
            $pattern = '/^(\s*)' . preg_quote( $original_marker, '/' ) . '(.+)$/m';
            $content = preg_replace( $pattern, '$1$2', $content );
            $modified = true;
        }

        if ( ! $modified ) {
            return;
        }

        // Clean up multiple empty lines
        $content = preg_replace( '/\n{3,}/', "\n\n", $content );

        // Safety check: must still have basic wp-config content
        if ( strpos( $content, 'DB_NAME' ) === false ) {
            return; // Don't write if it would corrupt wp-config
        }

        $wp_filesystem->put_contents( $wpconfig_path, $content, FS_CHMOD_FILE );
    }

    /**
     * Clear all scheduled cron events
     */
    private static function clear_scheduled_events() {
        $events = array(
            'vigilante_daily_maintenance',
            'vigilante_hourly_checks',
            'vigilante_file_integrity_scan',
            'vigilante_password_expiry_reminder',
            'vigilante_analyzer_weekly_scan',
            'vigilante_plugin_status_check',
        );

        foreach ( $events as $event ) {
            $timestamp = wp_next_scheduled( $event );
            if ( $timestamp ) {
                wp_unschedule_event( $timestamp, $event );
            }
        }

        // Clear all events with our prefix
        wp_unschedule_hook( 'vigilante_daily_maintenance' );
        wp_unschedule_hook( 'vigilante_hourly_checks' );
        wp_unschedule_hook( 'vigilante_file_integrity_scan' );
        wp_unschedule_hook( 'vigilante_password_expiry_reminder' );
        wp_unschedule_hook( 'vigilante_analyzer_weekly_scan' );
        wp_unschedule_hook( 'vigilante_plugin_status_check' );
    }

    /**
     * Send deactivation notification email
     */
    private static function send_deactivation_email() {
        $settings = new Vigilante_Settings();
        $email_settings = $settings->get_section( 'email' );

        if ( empty( $email_settings['send_deactivation_email'] ) ) {
            return;
        }

        if ( ! class_exists( 'Vigilante_Email_Template' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-email-template.php';
        }

        $to = Vigilante_Email_Template::get_admin_recipients();

        $site_name = get_bloginfo( 'name' );
        $site_url = get_site_url();

        // Get current user info
        $current_user = wp_get_current_user();
        $user_info = $current_user->ID > 0 
            ? $current_user->user_login . ' (' . $current_user->user_email . ')' 
            : __( 'Unknown', 'vigilante' );

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Vigilant Deactivated', 'vigilante' ),
            $site_name
        );

        $body  = Vigilante_Email_Template::warning_box( __( 'Security protection has been disabled. Please ensure you have alternative security measures in place.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::data_table( array(
            __( 'Site', 'vigilante' )            => $site_name,
            __( 'URL', 'vigilante' )             => $site_url,
            __( 'Date', 'vigilante' )            => wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ),
            __( 'Deactivated by', 'vigilante' )  => $user_info,
        ) );

        Vigilante_Email_Template::send( $to, $subject, __( 'Plugin deactivated', 'vigilante' ), $body );
    }

    /**
     * Full uninstall - removes all data
     * Called from uninstall.php
     */
    public static function uninstall() {
        // Drop database tables
        $database = new Vigilante_Database();
        $database->drop_tables();

        // Remove all options
        delete_option( 'vigilante_options' );
        delete_option( 'vigilante_db_version' );
        delete_option( 'vigilante_activated_time' );
        delete_option( 'vigilante_dismissed_notices' );
        delete_option( 'vigilante_backup_timestamp' );
        delete_option( 'vigilante_last_integrity_results' );
        delete_option( 'vigilante_last_integrity_scan' );
        delete_option( 'vigilante_critical_files_baseline' );
        delete_option( 'vigilante_analyzer_last_scan' );
        delete_option( 'vigilante_analyzer_history' );
        delete_option( 'vigilante_analyzer_fix_log' );

        // Remove transients
        delete_transient( 'vigilante_activated' );
        delete_transient( 'vigilante_restore_on_deactivate' );
        delete_transient( 'vigilante_backup_error' );
        delete_transient( 'vigilante_file_integrity_last_scan' );

        // Remove backup directory
        self::remove_backup_directory();

        // Clear scheduled events
        self::clear_scheduled_events();

        // Remove htaccess rules
        self::remove_htaccess_rules();

        // Remove wp-config security constants and restore originals
        self::remove_wpconfig_security();
    }

    /**
     * Remove backup directory and its contents
     */
    private static function remove_backup_directory() {
        $backup_dirs = array(
            WP_CONTENT_DIR . '/vigilante-backups',
        );

        if ( defined( 'VIGILANTE_BACKUP_DIR' ) ) {
            $backup_dirs[] = VIGILANTE_BACKUP_DIR;
        }

        // Initialize WP_Filesystem
        global $wp_filesystem;
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        if ( ! $wp_filesystem ) {
            return;
        }

        foreach ( $backup_dirs as $backup_dir ) {
            if ( ! $wp_filesystem->is_dir( $backup_dir ) ) {
                continue;
            }

            // Remove directory and contents recursively
            $wp_filesystem->delete( $backup_dir, true );
        }
    }
}