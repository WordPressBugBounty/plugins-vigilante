<?php
/**
 * Backup Manager Class
 *
 * Handles backup and restoration of critical files. Backups are stored in
 * private database options (autoload off), never as files under the web root,
 * so a copy of wp-config.php or .htaccess can never be served over HTTP.
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
 * Manages file backups for security modifications.
 */
class Vigilante_Backup_Manager {

    /**
     * Legacy on-disk backup directory (kept only to clean it up on upgrade).
     *
     * @var string
     */
    private $backup_dir;

    /**
     * Maximum number of backups to keep
     *
     * @var int
     */
    private $max_backups = 5;

    /**
     * Files to backup
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
     * Create backups of all important files
     *
     * The content is stored in the database, never copied to a file under the
     * web root.
     *
     * @return true|WP_Error True on success, WP_Error on failure.
     */
    public function create_backups() {
        $timestamp   = gmdate( 'Y-m-d_H-i-s' );
        $backup_info = array();
        $errors      = array();

        foreach ( $this->backup_files as $key => $file ) {
            if ( file_exists( $file['source'] ) ) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_get_contents -- reading a known local config file to store it in the DB, not a filesystem op on user input.
                $content = file_get_contents( $file['source'] );

                if ( false !== $content ) {
                    $backup_info[ $key ] = array(
                        'content' => $content,
                        'hash'    => md5( $content ),
                        'size'    => strlen( $content ),
                        'exists'  => true,
                        'time'    => time(),
                    );
                } else {
                    $errors[] = sprintf(
                        /* translators: %s: File name */
                        __( 'Failed to backup %s', 'vigilante' ),
                        basename( $file['source'] )
                    );
                }
            } else {
                // Mark as non-existent (important for restoration).
                $backup_info[ $key ] = array(
                    'content' => '',
                    'exists'  => false,
                    'time'    => time(),
                );
            }
        }

        if ( ! empty( $errors ) ) {
            return new WP_Error( 'backup_partial', implode( ', ', $errors ) );
        }

        // Store metadata + content in non-autoloaded options (may be large and
        // is only needed on demand).
        $backup_info['timestamp'] = $timestamp;
        update_option( 'vigilante_backup_timestamp', $timestamp, false );
        update_option( 'vigilante_backup_info_' . $timestamp, $backup_info, false );

        $this->cleanup_old_backups();

        return true;
    }

    /**
     * Restore files from backup
     *
     * @param string $timestamp Optional specific timestamp to restore.
     * @return true|WP_Error
     */
    public function restore_backups( $timestamp = '' ) {
        if ( empty( $timestamp ) ) {
            $timestamp = get_option( 'vigilante_backup_timestamp' );
        }

        if ( empty( $timestamp ) ) {
            return new WP_Error(
                'no_backup',
                __( 'No backup found to restore.', 'vigilante' )
            );
        }

        $backup_info = get_option( 'vigilante_backup_info_' . $timestamp );

        if ( empty( $backup_info ) ) {
            return new WP_Error(
                'backup_info_missing',
                __( 'Backup information not found.', 'vigilante' )
            );
        }

        $errors = array();

        foreach ( $this->backup_files as $key => $file ) {
            if ( ! isset( $backup_info[ $key ] ) ) {
                continue;
            }

            $info = $backup_info[ $key ];

            // If the file did not exist originally, delete it.
            if ( isset( $info['exists'] ) && false === $info['exists'] ) {
                if ( file_exists( $file['source'] ) ) {
                    wp_delete_file( $file['source'] );
                }
                continue;
            }

            if ( ! isset( $info['content'] ) || '' === $info['content'] ) {
                continue;
            }

            // Verify integrity against the stored hash.
            if ( isset( $info['hash'] ) && md5( $info['content'] ) !== $info['hash'] ) {
                $errors[] = sprintf(
                    /* translators: %s: File name */
                    __( 'Backup integrity check failed for %s', 'vigilante' ),
                    $file['name']
                );
                continue;
            }

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- restoring a known local config file from the DB backup.
            if ( false === file_put_contents( $file['source'], $info['content'] ) ) {
                $errors[] = sprintf(
                    /* translators: %s: File name */
                    __( 'Failed to restore %s', 'vigilante' ),
                    basename( $file['source'] )
                );
            }
        }

        if ( ! empty( $errors ) ) {
            return new WP_Error( 'restore_partial', implode( ', ', $errors ) );
        }

        return true;
    }

    /**
     * Cleanup old backups keeping only the most recent
     */
    private function cleanup_old_backups() {
        $settings        = new Vigilante_Settings();
        $backup_settings = $settings->get_section( 'backup' );
        $this->max_backups = isset( $backup_settings['max_backups'] ) ? absint( $backup_settings['max_backups'] ) : 5;

        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off maintenance scan of our own option names.
        $backup_options = $wpdb->get_col(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE 'vigilante_backup_info_%' ORDER BY option_name DESC"
        );

        if ( count( $backup_options ) > $this->max_backups ) {
            $to_delete = array_slice( $backup_options, $this->max_backups );

            foreach ( $to_delete as $option_name ) {
                $timestamp = str_replace( 'vigilante_backup_info_', '', $option_name );
                $this->delete_backup( $timestamp );
            }
        }
    }

    /**
     * Delete a specific backup
     *
     * @param string $timestamp Backup timestamp.
     * @return bool
     */
    public function delete_backup( $timestamp ) {
        delete_option( 'vigilante_backup_info_' . $timestamp );

        $current_timestamp = get_option( 'vigilante_backup_timestamp' );
        if ( $current_timestamp === $timestamp ) {
            delete_option( 'vigilante_backup_timestamp' );
        }

        return true;
    }

    /**
     * Get list of available backups
     *
     * @return array
     */
    public function get_available_backups() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- listing our own option names.
        $backup_options = $wpdb->get_col(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE 'vigilante_backup_info_%' ORDER BY option_name DESC"
        );

        $backups = array();

        foreach ( $backup_options as $option_name ) {
            $timestamp = str_replace( 'vigilante_backup_info_', '', $option_name );
            $info      = get_option( $option_name );

            if ( ! empty( $info ) ) {
                $backups[] = array(
                    'timestamp' => $timestamp,
                    'date'      => date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( str_replace( '_', ' ', $timestamp ) ) ),
                    'files'     => count(
                        array_filter(
                            $info,
                            function ( $item ) {
                                return is_array( $item ) && ! empty( $item['exists'] );
                            }
                        )
                    ),
                );
            }
        }

        return $backups;
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
     * Check if backups exist
     *
     * @return bool
     */
    public function has_backups() {
        $timestamp = get_option( 'vigilante_backup_timestamp' );
        return ! empty( $timestamp );
    }

    /**
     * Get last backup timestamp
     *
     * @return string|false
     */
    public function get_last_backup_timestamp() {
        return get_option( 'vigilante_backup_timestamp' );
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
     * Verify backup integrity
     *
     * @param string $timestamp Backup timestamp.
     * @return array Verification results.
     */
    public function verify_backup( $timestamp ) {
        $backup_info = get_option( 'vigilante_backup_info_' . $timestamp );

        if ( empty( $backup_info ) ) {
            return array(
                'valid'  => false,
                'errors' => array( __( 'Backup information not found.', 'vigilante' ) ),
            );
        }

        $results = array(
            'valid'  => true,
            'errors' => array(),
            'files'  => array(),
        );

        foreach ( $this->backup_files as $key => $file ) {
            if ( ! isset( $backup_info[ $key ] ) ) {
                continue;
            }

            $info = $backup_info[ $key ];

            // Skip non-existent files.
            if ( isset( $info['exists'] ) && false === $info['exists'] ) {
                $results['files'][ $key ] = array(
                    'status' => 'skipped',
                    'reason' => __( 'File did not exist', 'vigilante' ),
                );
                continue;
            }

            if ( ! isset( $info['content'] ) ) {
                $results['valid']         = false;
                $results['errors'][]      = sprintf(
                    /* translators: %s: File name */
                    __( 'Backup content missing: %s', 'vigilante' ),
                    $file['name']
                );
                $results['files'][ $key ] = array( 'status' => 'missing' );
                continue;
            }

            // Verify hash.
            if ( isset( $info['hash'] ) && md5( $info['content'] ) !== $info['hash'] ) {
                $results['valid']         = false;
                $results['errors'][]      = sprintf(
                    /* translators: %s: File name */
                    __( 'Backup corrupted: %s', 'vigilante' ),
                    $file['name']
                );
                $results['files'][ $key ] = array( 'status' => 'corrupted' );
                continue;
            }

            $results['files'][ $key ] = array(
                'status' => 'valid',
                'size'   => isset( $info['size'] ) ? (int) $info['size'] : strlen( $info['content'] ),
            );
        }

        return $results;
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
