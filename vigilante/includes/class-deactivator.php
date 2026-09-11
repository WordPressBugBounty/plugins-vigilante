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
     *
     * @param bool $network_wide Whether core is deactivating the plugin for the
     *                           whole network, as it passes it to the hook.
     */
    public static function deactivate( $network_wide = false ) {
        /*
         * wp-config.php and the root .htaccess belong to the main site of a
         * network, and the gate that protects them asks whether the request is
         * on the main site. A network-wide deactivation can arrive from any site,
         * though: the REST plugins endpoint answers on every site's URL, and
         * WP-CLI takes --network together with the --url of a subsite. Asked
         * there, the gate said no and the blocks stayed behind, with no plugin
         * left to remove them. So the question is asked on the main site. Only
         * the site changes: the capability is still checked against whoever is
         * deactivating, so a subsite administrator gains nothing from it.
         */
        $switched = false;
        if ( $network_wide && is_multisite() && ! is_main_site() ) {
            switch_to_blog( get_main_site_id() );
            $switched = true;
        }

        try {
            /*
             * Activating network-wide does not clear a site's own activation, so
             * a Vigilant that was active on the main site before it was activated
             * for the network is still running there after a network
             * deactivation. Its blocks are still in use, and removing them would
             * leave that copy running without the protections it wrote.
             */
            if ( ! self::still_active_here( $network_wide ) ) {
                // ALWAYS remove htaccess rules using the centralized manager
                self::remove_htaccess_rules();

                // ALWAYS remove wp-config security constants and restore originals
                self::remove_wpconfig_security();
            }
        } finally {
            if ( $switched ) {
                restore_current_blog();
            }
        }

        /*
         * The same question for the site the request is on: a copy that keeps
         * running here keeps its schedule, and since it has not been deactivated
         * it is not the one to announce that protection is off. The transients
         * below are cleared either way; for a copy that keeps running that only
         * resets the alert engine's counters and cooldowns, so an alert can come
         * back sooner than it would have.
         */
        if ( ! self::still_active_here( $network_wide ) ) {
            // Clear scheduled events
            self::clear_scheduled_events();

            // Send deactivation email
            self::send_deactivation_email();
        }

        // Clear transients
        delete_transient( 'vigilante_activated' );
        delete_transient( 'vigilante_restore_on_deactivate' );
        delete_transient( 'vigilante_backup_error' );

        // Audit Alerts: clear every engine transient (per-category counters and
        // cooldowns, plus the immediate anti-duplicate keys). Names are dynamic
        // (one per category, md5 per event), so a prefix sweep is the only way.
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One-off cleanup on deactivate; dynamic transient names cannot be enumerated individually.
        $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_vigilante\\_aa\\_%' OR option_name LIKE '\\_transient\\_timeout\\_vigilante\\_aa\\_%'" );

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
        /*
         * One removal for the whole plugin. This used to be a copy of
         * Vigilante_Wpconfig_Security::remove_constants(), and the copy had
         * drifted from it in three ways. Until 2.11.5 it did not ask the network
         * gate, so the administrator of a subsite who deactivated a per-site
         * Vigilant stripped the constants for every site of the network (reported
         * by the wordpress.org automated security review). It cut the block line
         * by line, so a block that had lost its END marker took everything after
         * it, the require of wp-settings.php included. And it wrote through
         * WP_Filesystem with FS_CHMOD_FILE, which is "permissions of index.php |
         * 0644", so a wp-config.php kept at 0600 or 0640 was left at 0644; a
         * direct write keeps the permissions the file already has.
         */
        $wpconfig_path = ABSPATH . 'wp-config.php';

        // remove_constants() writes the file directly, so there is nothing to do
        // when PHP cannot.
        if ( ! file_exists( $wpconfig_path ) || ! wp_is_writable( $wpconfig_path ) ) {
            return;
        }

        require_once VIGILANTE_INCLUDES_DIR . 'class-wpconfig-security.php';

        // remove_constants() asks the network gate and leaves alone a block that
        // has lost one of its markers.
        $wpconfig = new Vigilante_Wpconfig_Security( new Vigilante_Settings() );
        $wpconfig->remove_constants();
    }

    /**
     * Whether a per-site Vigilant keeps running on the current site
     *
     * Only a network-wide deactivation can leave one behind, and only then is
     * the site's own list final when the hook runs: core saves the lists after
     * the hook, so for a per-site deactivation the list still names the plugin.
     * Code that calls deactivate_plugins() without saying whether it is
     * network-wide on a plugin active both ways drops the site's entry too,
     * after the hook, and then this answers yes for a copy that is going away;
     * core itself never makes that call.
     *
     * @since 2.11.6
     *
     * @param bool $network_wide Whether the deactivation is network-wide.
     * @return bool
     */
    private static function still_active_here( $network_wide ) {
        return $network_wide && is_multisite()
            && in_array( VIGILANTE_PLUGIN_BASENAME, (array) get_option( 'active_plugins', array() ), true );
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
        // Post-update verification single events (scheduled with per-update args).
        wp_unschedule_hook( 'vigilante_fi_postupdate_verify' );
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
}