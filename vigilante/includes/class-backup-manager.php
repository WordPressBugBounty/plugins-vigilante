<?php
/**
 * Backup Manager Class
 *
 * Handles backup and restoration of files and settings
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
 * Manages file backups for security modifications
 */
class Vigilante_Backup_Manager {

    /**
     * Backup directory path
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
                'ext'    => '.txt',
            ),
            'wpconfig' => array(
                'source' => ABSPATH . 'wp-config.php',
                'name'   => 'wpconfig',
                'ext'    => '.php.txt',
            ),
            'robots' => array(
                'source' => ABSPATH . 'robots.txt',
                'name'   => 'robots',
                'ext'    => '.txt',
            ),
        );
    }

    /**
     * Create backups of all important files
     *
     * @return true|WP_Error True on success, WP_Error on failure.
     */
    public function create_backups() {
        // Create backup directory if it doesn't exist
        if ( ! $this->ensure_backup_directory() ) {
            return new WP_Error(
                'backup_dir_failed',
                __( 'Could not create backup directory. Check permissions.', 'vigilante' )
            );
        }

        $timestamp = gmdate( 'Y-m-d_H-i-s' );
        $backup_info = array();
        $errors = array();

        foreach ( $this->backup_files as $key => $file ) {
            if ( file_exists( $file['source'] ) ) {
                $backup_path = $this->backup_dir . $file['name'] . '_' . $timestamp . $file['ext'];
                
                if ( copy( $file['source'], $backup_path ) ) {
                    $backup_info[ $key ] = array(
                        'path' => $backup_path,
                        'hash' => md5_file( $backup_path ),
                        'size' => filesize( $file['source'] ),
                        'time' => time(),
                    );
                } else {
                    $errors[] = sprintf(
                        /* translators: %s: File name */
                        __( 'Failed to backup %s', 'vigilante' ),
                        basename( $file['source'] )
                    );
                }
            } else {
                // Mark as non-existent (important for restoration)
                $backup_info[ $key ] = array(
                    'path'   => '',
                    'exists' => false,
                    'time'   => time(),
                );
            }
        }

        if ( ! empty( $errors ) ) {
            return new WP_Error( 'backup_partial', implode( ', ', $errors ) );
        }

        // Save backup metadata
        $backup_info['timestamp'] = $timestamp;
        update_option( 'vigilante_backup_timestamp', $timestamp );
        update_option( 'vigilante_backup_info_' . $timestamp, $backup_info );

        // Cleanup old backups
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

            // If file didn't exist originally, delete it
            if ( isset( $info['exists'] ) && false === $info['exists'] ) {
                if ( file_exists( $file['source'] ) ) {
                    wp_delete_file( $file['source'] );
                }
                continue;
            }

            // Restore from backup
            if ( ! empty( $info['path'] ) && file_exists( $info['path'] ) ) {
                // Verify hash
                if ( isset( $info['hash'] ) && md5_file( $info['path'] ) !== $info['hash'] ) {
                    $errors[] = sprintf(
                        /* translators: %s: File name */
                        __( 'Backup integrity check failed for %s', 'vigilante' ),
                        $file['name']
                    );
                    continue;
                }

                if ( ! copy( $info['path'], $file['source'] ) ) {
                    $errors[] = sprintf(
                        /* translators: %s: File name */
                        __( 'Failed to restore %s', 'vigilante' ),
                        basename( $file['source'] )
                    );
                }
            }
        }

        if ( ! empty( $errors ) ) {
            return new WP_Error( 'restore_partial', implode( ', ', $errors ) );
        }

        return true;
    }

    /**
     * Ensure backup directory exists and is secure
     *
     * @return bool
     */
    private function ensure_backup_directory() {
        if ( ! file_exists( $this->backup_dir ) ) {
            if ( ! wp_mkdir_p( $this->backup_dir ) ) {
                return false;
            }
        }

        // Add security files
        $this->add_security_files();

        // Initialize WP_Filesystem
        global $wp_filesystem;
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        if ( ! $wp_filesystem ) {
            return false;
        }

        return $wp_filesystem->is_dir( $this->backup_dir ) && $wp_filesystem->is_writable( $this->backup_dir );
    }

    /**
     * Add security files to backup directory
     */
    private function add_security_files() {
        // index.php to prevent directory listing
        $index_path = $this->backup_dir . 'index.php';
        if ( ! file_exists( $index_path ) ) {
            file_put_contents( $index_path, "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        }

        // .htaccess to deny access
        $htaccess_path = $this->backup_dir . '.htaccess';
        if ( ! file_exists( $htaccess_path ) ) {
            $htaccess_content = "# Deny all access\n";
            $htaccess_content .= "<IfModule mod_authz_core.c>\n";
            $htaccess_content .= "    Require all denied\n";
            $htaccess_content .= "</IfModule>\n";
            $htaccess_content .= "<IfModule !mod_authz_core.c>\n";
            $htaccess_content .= "    Order deny,allow\n";
            $htaccess_content .= "    Deny from all\n";
            $htaccess_content .= "</IfModule>\n";
            file_put_contents( $htaccess_path, $htaccess_content ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        }
    }

    /**
     * Cleanup old backups keeping only the most recent
     */
    private function cleanup_old_backups() {
        $settings = new Vigilante_Settings();
        $backup_settings = $settings->get_section( 'backup' );
        $this->max_backups = isset( $backup_settings['max_backups'] ) ? absint( $backup_settings['max_backups'] ) : 5;

        // Get all backup timestamps
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $backup_options = $wpdb->get_col(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE 'vigilante_backup_info_%' ORDER BY option_name DESC"
        );

        // Keep only max_backups
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
        $backup_info = get_option( 'vigilante_backup_info_' . $timestamp );

        if ( ! empty( $backup_info ) && is_array( $backup_info ) ) {
            foreach ( $backup_info as $key => $info ) {
                if ( is_array( $info ) && ! empty( $info['path'] ) && file_exists( $info['path'] ) ) {
                    wp_delete_file( $info['path'] );
                }
            }
        }

        delete_option( 'vigilante_backup_info_' . $timestamp );

        // Update current timestamp if needed
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

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $backup_options = $wpdb->get_col(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE 'vigilante_backup_info_%' ORDER BY option_name DESC"
        );

        $backups = array();

        foreach ( $backup_options as $option_name ) {
            $timestamp = str_replace( 'vigilante_backup_info_', '', $option_name );
            $info = get_option( $option_name );

            if ( ! empty( $info ) ) {
                $backups[] = array(
                    'timestamp'  => $timestamp,
                    'date'       => date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( str_replace( '_', ' ', $timestamp ) ) ),
                    'files'      => count( array_filter( $info, function( $item ) {
                        return is_array( $item ) && ! empty( $item['path'] );
                    })),
                );
            }
        }

        return $backups;
    }

    /**
     * Get backup directory path
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

            // Skip non-existent files
            if ( isset( $info['exists'] ) && false === $info['exists'] ) {
                $results['files'][ $key ] = array(
                    'status' => 'skipped',
                    'reason' => __( 'File did not exist', 'vigilante' ),
                );
                continue;
            }

            if ( empty( $info['path'] ) || ! file_exists( $info['path'] ) ) {
                $results['valid'] = false;
                $results['errors'][] = sprintf(
                    /* translators: %s: File name */
                    __( 'Backup file missing: %s', 'vigilante' ),
                    $file['name']
                );
                $results['files'][ $key ] = array(
                    'status' => 'missing',
                );
                continue;
            }

            // Verify hash
            if ( isset( $info['hash'] ) ) {
                $current_hash = md5_file( $info['path'] );
                if ( $current_hash !== $info['hash'] ) {
                    $results['valid'] = false;
                    $results['errors'][] = sprintf(
                        /* translators: %s: File name */
                        __( 'Backup corrupted: %s', 'vigilante' ),
                        $file['name']
                    );
                    $results['files'][ $key ] = array(
                        'status' => 'corrupted',
                    );
                    continue;
                }
            }

            $results['files'][ $key ] = array(
                'status' => 'valid',
                'size'   => filesize( $info['path'] ),
            );
        }

        return $results;
    }
}