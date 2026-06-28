<?php
/**
 * Uninstall Vigilante AyudaWP
 *
 * This file runs when the plugin is deleted via WordPress admin.
 * It removes all plugin data including database tables and options.
 *
 * @package Vigilante
 */

// Exit if not called by WordPress
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// Load required files
require_once plugin_dir_path( __FILE__ ) . 'includes/class-settings.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-database.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-backup-manager.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-deactivator.php';

// Define constants if not already defined
if ( ! defined( 'VIGILANTE_BACKUP_DIR' ) ) {
    define( 'VIGILANTE_BACKUP_DIR', WP_CONTENT_DIR . '/vigilante-backups/' );
}

/**
 * Uninstall function
 */
function vigilante_uninstall() {
    global $wpdb;

    // Drop custom tables
    $tables = array(
        $wpdb->prefix . 'vigilante_activity_log',
        $wpdb->prefix . 'vigilante_login_attempts',
        $wpdb->prefix . 'vigilante_file_integrity',
        $wpdb->prefix . 'vigilante_2fa_codes',
        $wpdb->prefix . 'vigilante_2fa_trusted_devices',
        $wpdb->prefix . 'vigilante_2fa_notifications',
        $wpdb->prefix . 'vigilante_2fa_totp',
    );

    foreach ( $tables as $table ) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $wpdb->query( "DROP TABLE IF EXISTS {$table}" );
    }

    // Delete options
    $options_to_delete = array(
        'vigilante_options',
        'vigilante_db_version',
        'vigilante_backup_timestamp',
        'vigilante_last_integrity_scan',
        'vigilante_last_integrity_results',
        'vigilante_ignored_files',
        'vigilante_dismissed_notices',
        'vigilante_under_attack_mode',
        'vigilante_active_preset',
        'vigilante_firewall_blocks',
        'vigilante_critical_files_baseline',
        'vigilante_activated_time',
        'vigilante_analyzer_last_scan',
        'vigilante_analyzer_history',
        'vigilante_legacy_backups_cleaned',
        'vigilante_css_exclusion_migrated',
        'vigilante_checksum_cache_flushed_290',
    );

    foreach ( $options_to_delete as $option ) {
        delete_option( $option );
    }

    // Delete all transients
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query(
        "DELETE FROM {$wpdb->options} 
        WHERE option_name LIKE '_transient_vigilante_%' 
        OR option_name LIKE '_transient_timeout_vigilante_%'"
    );

    // Remove backup directory
    $backup_dir = WP_CONTENT_DIR . '/vigilante-backups/';
    if ( is_dir( $backup_dir ) ) {
        vigilante_recursive_rmdir( $backup_dir );
    }

    // Clear scheduled hooks
    $hooks_to_clear = array(
        'vigilante_daily_maintenance',
        'vigilante_hourly_check',
        'vigilante_hourly_checks',
        'vigilante_file_integrity_scan',
        'vigilante_cleanup_logs',
        'vigilante_password_expiry_reminder',
        'vigilante_analyzer_weekly_scan',
        'vigilante_under_attack_post_scan',
    );

    foreach ( $hooks_to_clear as $hook ) {
        wp_clear_scheduled_hook( $hook );
    }

    // Post-update verification events are scheduled with per-update arguments,
    // so clear every instance regardless of args.
    wp_unschedule_hook( 'vigilante_fi_postupdate_verify' );

    // Delete all user meta with vigilante_ prefix
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query(
        "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'vigilante\_%'"
    );
}

/**
 * Recursively remove directory
 *
 * @param string $dir Directory path.
 * @return bool
 */
function vigilante_recursive_rmdir( $dir ) {
    if ( ! is_dir( $dir ) ) {
        return false;
    }

    // Initialize WP_Filesystem
    global $wp_filesystem;
    if ( ! function_exists( 'WP_Filesystem' ) ) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
    }
    WP_Filesystem();

    if ( ! $wp_filesystem ) {
        return false;
    }

    // Use WP_Filesystem delete with recursive flag
    return $wp_filesystem->delete( $dir, true );
}

// Run uninstall
vigilante_uninstall();