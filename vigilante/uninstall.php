<?php
/**
 * Uninstall Vigilante AyudaWP
 *
 * This file runs when the plugin is deleted via WordPress admin.
 * It removes all plugin data including database tables and options.
 *
 * On a network it visits every site: tables, options, transients and cron
 * events are per site, so cleaning only the site that runs the uninstall
 * left everything else behind until 2.11.0 (S13 of the 28 Aug 2026 audit).
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

    /*
     * Per-site data. switch_to_blog() repoints $wpdb->prefix, $wpdb->options
     * and the cron option, so the same routine serves every site of a network.
     * 'number' => 0 lifts the default cap of 100 sites: an uninstall that
     * cleaned the first hundred sites and left the rest would be the same bug
     * with a bigger threshold.
     */
    if ( is_multisite() ) {
        $site_ids = get_sites(
            array(
                'fields' => 'ids',
                'number' => 0,
            )
        );

        foreach ( $site_ids as $site_id ) {
            switch_to_blog( $site_id );
            vigilante_uninstall_site();
            restore_current_blog();
        }
    } else {
        vigilante_uninstall_site();
    }

    // Remove backup directory. WP_CONTENT_DIR is shared by the whole network,
    // so this happens once.
    $backup_dir = WP_CONTENT_DIR . '/vigilante-backups/';
    if ( is_dir( $backup_dir ) ) {
        vigilante_recursive_rmdir( $backup_dir );
    }

    // Delete all user meta with vigilante_ prefix. The usermeta table is global
    // on a network, so this also happens once.
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin's own user meta (prefix vigilante_) swept by pattern at uninstall; no cache to invalidate once the plugin is gone.
    $wpdb->query(
        "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'vigilante\_%'"
    );

    /*
     * The plugin is still loaded in the request that runs this file, so
     * whatever it does later, on shutdown or on a late hook, writes its data
     * back after the cleanup above has finished. Measured on 22 aug 2026: an
     * uninstall left 112 rows of plugin status transients and its last check
     * timestamp behind, all of them written after this file had run. So the
     * sweep is repeated at the very end of the request. The loaded plugin is
     * the current site's instance and writes to the current site, which is
     * why the sweep does not visit the network again.
     */
    add_action( 'shutdown', 'vigilante_uninstall_final_sweep', PHP_INT_MAX );
}

/**
 * Remove the data of the current site (tables, options, transients, cron)
 *
 * Runs once on a single site and once per site on a network, after
 * switch_to_blog().
 *
 * @since 2.11.0 Extracted from vigilante_uninstall() so a network can loop it.
 */
function vigilante_uninstall_site() {
    global $wpdb;

    /*
     * The scheduled events go first. WordPress can spawn wp-cron in the middle
     * of an uninstall, and that loopback request runs in its own process with
     * the plugin still on disk: clearing the events before anything else means
     * it finds nothing to run.
     */
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
        'vigilante_plugin_status_check',
    );

    foreach ( $hooks_to_clear as $hook ) {
        wp_clear_scheduled_hook( $hook );
    }

    // Post-update verification events are scheduled with per-update arguments,
    // so clear every instance regardless of args.
    wp_unschedule_hook( 'vigilante_fi_postupdate_verify' );

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
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Dropping the plugin's own tables at uninstall; the name comes from $wpdb->prefix and a literal, never from input.
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
        'vigilante_server_software',
        'vigilante_server_files_version',
        'vigilante_server_files_pending',
        'vigilante_server_files_retry_after',
        // Safety copies taken before writing to the site's configuration files.
        // The wp-config.php one holds the database credentials and the
        // authentication salts, so leaving it behind would keep them readable in
        // the options table long after the plugin is gone.
        'vigilante_htaccess_backup',
        'vigilante_wpconfig_backup',
        'vigilante_plugin_status_state',
        'vigilante_plugin_status_last_check',
        'vigilante_ignored_closed_plugins',
    );

    foreach ( $options_to_delete as $option ) {
        delete_option( $option );
    }

    // Per-backup records are named after their timestamp
    // (vigilante_backup_info_<Y-m-d_H-i-s>), so a fixed list cannot reach them.
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin's own options swept by pattern at uninstall; the options API has no LIKE.
    $wpdb->query(
        "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'vigilante_backup_info_%'"
    );

    // Delete all transients
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin's own transients swept by pattern at uninstall; the transients API has no LIKE.
    $wpdb->query(
        "DELETE FROM {$wpdb->options}
        WHERE option_name LIKE '_transient_vigilante_%'
        OR option_name LIKE '_transient_timeout_vigilante_%'"
    );
}

/**
 * Second pass at the end of the request, for anything written after the first one
 *
 * Deliberately not a blunt "vigilante%" wildcard: other plugins live under that
 * name too, the network sync companion among them, and deleting their options
 * from here would be a fine way to break somebody else's site.
 *
 * @since 2.9.9
 */
function vigilante_uninstall_final_sweep() {
    global $wpdb;

    // The scheduled events go too: they are rescheduled by the plugin that is
    // still loaded in this request, which is how vigilante_plugin_status_check
    // survived an uninstall until 2.9.9.
    $hooks = array(
        'vigilante_daily_maintenance',
        'vigilante_hourly_check',
        'vigilante_hourly_checks',
        'vigilante_file_integrity_scan',
        'vigilante_cleanup_logs',
        'vigilante_password_expiry_reminder',
        'vigilante_analyzer_weekly_scan',
        'vigilante_under_attack_post_scan',
        'vigilante_plugin_status_check',
        'vigilante_fi_postupdate_verify',
    );

    foreach ( $hooks as $hook ) {
        wp_unschedule_hook( $hook );
    }

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Same sweep as vigilante_uninstall_site(), repeated at shutdown for rows the still-loaded plugin wrote back after the first pass.
    $wpdb->query(
        "DELETE FROM {$wpdb->options}
        WHERE option_name LIKE '_transient_vigilante\_%'
        OR option_name LIKE '_transient_timeout_vigilante\_%'
        OR option_name LIKE 'vigilante_plugin_status\_%'
        OR option_name LIKE 'vigilante_backup_info\_%'
        OR option_name IN (
            'vigilante_options',
            'vigilante_db_version',
            'vigilante_ignored_closed_plugins',
            'vigilante_ignored_files',
            'vigilante_dismissed_notices',
            'vigilante_under_attack_mode',
            'vigilante_active_preset',
            'vigilante_server_software',
            'vigilante_server_files_version',
            'vigilante_server_files_pending',
            'vigilante_server_files_retry_after'
        )"
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
