<?php
/**
 * Backup Manager Class
 *
 * Builds the downloadable archive of the configuration files, and cleans up
 * the copies of those files that earlier versions kept: on disk under the web
 * root until 2.7.0, and in the options table until 2.11.6.
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Backup_Manager
 *
 * Configuration file archive and cleanup of stored copies.
 */
class Vigilante_Backup_Manager {

    /**
     * Option recording that the stored copies are gone
     *
     * 1 once this site is clean, 2 once the walk over the network has finished
     * as well, so the site stops asking the network. Autoloaded, because it is
     * read on every request.
     *
     * @since 2.11.6
     */
    const COPIES_PURGED_OPTION = 'vigilante_config_copies_purged';

    /**
     * Network option holding the last site the walk cleaned, or 'done'
     *
     * @since 2.11.6
     */
    const COPIES_SWEEP_OPTION = 'vigilante_config_copies_sweep';

    /**
     * Sites the walk cleans per request
     *
     * @since 2.11.6
     */
    const COPIES_SWEEP_BATCH = 50;

    /**
     * Lock that keeps two requests from walking the network at once
     *
     * @since 2.11.8
     */
    const COPIES_SWEEP_LOCK = 'vigilante_config_copies_sweep_lock';

    /**
     * Legacy on-disk backup directory (kept only to clean it up on upgrade).
     *
     * @var string
     */
    private $backup_dir;

    /**
     * Configuration files the archive carries
     *
     * @var array
     */
    private $backup_files = array();

    /**
     * Constructor
     */
    public function __construct() {
        $this->backup_dir = VIGILANTE_BACKUP_DIR;
        $this->setup_backup_files();
    }

    /**
     * Setup list of files to backup
     */
    private function setup_backup_files() {
        $this->backup_files = array(
            'htaccess' => array(
                'source' => ABSPATH . '.htaccess',
                'name'   => 'htaccess',
            ),
            'wpconfig' => array(
                'source' => ABSPATH . 'wp-config.php',
                'name'   => 'wpconfig',
            ),
            'robots' => array(
                'source' => ABSPATH . 'robots.txt',
                'name'   => 'robots',
            ),
        );
    }

    /**
     * Delete the copies of the configuration files kept in this site's options
     *
     * Until 2.11.6 activating Vigilant copied wp-config.php, .htaccess and
     * robots.txt into vigilante_backup_info_<date>, up to five of them, and
     * writing the constants block kept one more copy of wp-config.php in
     * vigilante_wpconfig_backup. Nothing read them back: the method that
     * restored the files had no caller. wp-config.php carries the database
     * password and the authentication keys and salts, so every copy put them in
     * the options table, within reach of anyone who can read the database or a
     * dump of it. 2.7.0 moved the copies there from files under the web root,
     * which changed where they lived and not whether they should exist.
     *
     * @since 2.11.6
     */
    public static function purge_stored_copies() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off cleanup of our own dated option names, which the options API cannot list.
        $names = $wpdb->get_col( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE 'vigilante\\_backup\\_info\\_%'" );

        foreach ( (array) $names as $name ) {
            delete_option( $name );
        }

        delete_option( 'vigilante_backup_timestamp' );
        delete_option( 'vigilante_wpconfig_backup' );
    }

    /**
     * Run purge_stored_copies() once on this site, and once over the network
     *
     * The walk exists for the sites where Vigilant no longer runs: a copy made
     * by a per-site activation stays in that site's options after the plugin is
     * deactivated there, and nothing on that site would ever clean it. It
     * advances one batch of sites per request, from whichever site runs
     * Vigilant, remembers the last site it cleaned, and only visits this
     * network.
     *
     * @since 2.11.6
     */
    public static function maybe_purge_stored_copies() {
        $state = (int) get_option( self::COPIES_PURGED_OPTION, 0 );

        if ( $state >= 2 ) {
            return;
        }

        if ( $state < 1 ) {
            self::purge_stored_copies();
            update_option( self::COPIES_PURGED_OPTION, 1, true );
        }

        if ( ! is_multisite() ) {
            update_option( self::COPIES_PURGED_OPTION, 2, true );
            return;
        }

        if ( 'done' !== get_site_option( self::COPIES_SWEEP_OPTION, 0 ) ) {
            /*
             * One request walks at a time. Right after an update every request
             * gets here, and until 2.11.8 each of them repeated the same batch of
             * sites. The lock lives in the options table of the main site, which
             * every site of the network reaches the same way.
             */
            switch_to_blog( get_main_site_id() );
            $locked = Vigilante_Settings::acquire_option_lock( self::COPIES_SWEEP_LOCK, MINUTE_IN_SECONDS );
            restore_current_blog();

            if ( ! $locked ) {
                return;
            }

            try {
                self::sweep_next_batch();
            } finally {
                switch_to_blog( get_main_site_id() );
                Vigilante_Settings::release_option_lock( self::COPIES_SWEEP_LOCK );
                restore_current_blog();
            }
        }

        if ( 'done' === get_site_option( self::COPIES_SWEEP_OPTION, 0 ) ) {
            update_option( self::COPIES_PURGED_OPTION, 2, true );
        }
    }

    /**
     * Clean the next batch of sites of the network, with the walk lock held
     *
     * @since 2.11.8
     */
    private static function sweep_next_batch() {
        global $wpdb;

        // Read again inside the lock: the request that held it before may have
        // moved the walk on.
        // The core caches network options under "$network_id:$option", and absent
        // ones in "$network_id:notoptions" (wp-includes/option.php:2091 and :2065).
        wp_cache_delete( get_current_network_id() . ':' . self::COPIES_SWEEP_OPTION, 'site-options' );
        wp_cache_delete( get_current_network_id() . ':notoptions', 'site-options' );
        $sweep = get_site_option( self::COPIES_SWEEP_OPTION, 0 );

        if ( 'done' === $sweep ) {
            return;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- the walk needs the sites after the last one it cleaned, in id order, and get_sites() cannot ask for ids greater than a value.
        $site_ids = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT blog_id FROM {$wpdb->blogs} WHERE site_id = %d AND blog_id > %d ORDER BY blog_id ASC LIMIT %d",
                get_current_network_id(),
                (int) $sweep,
                self::COPIES_SWEEP_BATCH
            )
        );

        foreach ( $site_ids as $site_id ) {
            switch_to_blog( (int) $site_id );
            self::purge_stored_copies();
            restore_current_blog();
        }

        update_site_option( self::COPIES_SWEEP_OPTION, count( $site_ids ) < self::COPIES_SWEEP_BATCH ? 'done' : (int) end( $site_ids ) );
    }

    /**
     * Get the legacy on-disk backup directory path.
     *
     * Backups no longer live there; this is used to clean up files left by
     * older versions.
     *
     * @return string
     */
    public function get_backup_dir() {
        return $this->backup_dir;
    }

    /**
     * Build a ZIP with the current config files and stream it to the browser.
     *
     * Used by the "Create Backup" tool: instead of leaving files under the web
     * root, it hands the admin a downloadable archive of wp-config.php and
     * .htaccess (and robots.txt if present). The temp ZIP is removed right after.
     *
     * @return void|WP_Error WP_Error on failure; on success it streams and exits.
     */
    public function stream_files_zip() {
        // Second line of defence: the archive contains network-shared files, so
        // no future caller can hand them to a subsite administrator by mistake.
        if ( ! Vigilante_Settings::can_write_shared_files() ) {
            return new WP_Error( 'shared_files_denied', Vigilante_Settings::get_shared_files_notice() );
        }

        if ( ! class_exists( 'ZipArchive' ) ) {
            return new WP_Error( 'zip_unavailable', __( 'ZipArchive extension is not available on this server.', 'vigilante' ) );
        }

        $upload_dir = wp_upload_dir();
        $temp_dir   = trailingslashit( $upload_dir['basedir'] ) . 'vigilante-temp/';
        if ( ! wp_mkdir_p( $temp_dir ) ) {
            return new WP_Error( 'dir_error', __( 'Cannot create temporary directory.', 'vigilante' ) );
        }
        if ( ! file_exists( $temp_dir . '.htaccess' ) ) {
            file_put_contents( $temp_dir . '.htaccess', "Deny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- protective deny rule, not user input.
        }
        if ( ! file_exists( $temp_dir . 'index.php' ) ) {
            file_put_contents( $temp_dir . 'index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- silence-is-golden index, not user input.
        }

        $token    = wp_generate_password( 20, false );
        $zip_name = 'vigilant-config-backup-' . gmdate( 'Y-m-d-His' ) . '-' . $token . '.zip';
        $zip_path = $temp_dir . $zip_name;

        $zip = new ZipArchive();
        if ( true !== $zip->open( $zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
            return new WP_Error( 'zip_create_error', __( 'Failed to create ZIP file.', 'vigilante' ) );
        }

        $added = 0;
        foreach ( $this->backup_files as $file ) {
            if ( file_exists( $file['source'] ) ) {
                $zip->addFile( $file['source'], basename( $file['source'] ) );
                $added++;
            }
        }
        $zip->close();

        if ( 0 === $added || ! file_exists( $zip_path ) ) {
            return new WP_Error( 'zip_empty', __( 'No configuration files were found to back up.', 'vigilante' ) );
        }

        while ( ob_get_level() ) {
            ob_end_clean();
        }
        nocache_headers();
        header( 'Content-Type: application/zip' );
        header( 'Content-Disposition: attachment; filename="' . $zip_name . '"' );
        header( 'Content-Length: ' . filesize( $zip_path ) );
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- streaming a freshly built archive to the browser.
        readfile( $zip_path );
        wp_delete_file( $zip_path );
        exit;
    }

    /**
     * Remove backup files written under the web root by versions before 2.7.0.
     *
     * Config backups now live in the database, so the legacy on-disk directory
     * and any leftover database dumps are deleted. Best-effort.
     *
     * @return void
     */
    public static function cleanup_legacy_files() {
        global $wp_filesystem;
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();
        if ( ! $wp_filesystem ) {
            return;
        }

        $dir = defined( 'VIGILANTE_BACKUP_DIR' ) ? VIGILANTE_BACKUP_DIR : WP_CONTENT_DIR . '/vigilante-backups/';
        if ( $wp_filesystem->is_dir( $dir ) ) {
            $wp_filesystem->rmdir( $dir, true );
        }

        $upload_dir = wp_upload_dir();
        if ( ! empty( $upload_dir['basedir'] ) ) {
            $temp = trailingslashit( $upload_dir['basedir'] ) . 'vigilante-temp/';
            if ( $wp_filesystem->is_dir( $temp ) ) {
                $wp_filesystem->rmdir( $temp, true );
            }
        }
    }
}
