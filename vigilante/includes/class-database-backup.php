<?php
/**
 * Database Backup Class
 *
 * Handles database backup with table selection and ZIP download
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

/**
 * Class Vigilante_Database_Backup
 *
 * Creates downloadable database backups
 */
class Vigilante_Database_Backup {

    /**
     * WordPress database instance
     *
     * @var wpdb
     */
    private $wpdb;

    /**
     * Default WordPress core tables (without prefix)
     *
     * @var array
     */
    private $core_tables = array(
        'commentmeta',
        'comments',
        'links',
        'options',
        'postmeta',
        'posts',
        'term_relationships',
        'term_taxonomy',
        'termmeta',
        'terms',
        'usermeta',
        'users',
    );

    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;
    }

    /**
     * Get all database tables grouped by type
     *
     * Returns tables organized as 'core' (WP default) and 'other' (plugins, etc.)
     *
     * @return array {
     *     @type array $core  WordPress core tables.
     *     @type array $other Plugin and custom tables.
     * }
     */
    public function get_tables() {
        $prefix = $this->wpdb->prefix;
        $tables = array(
            'core'  => array(),
            'other' => array(),
        );

        // Get all tables that match the current prefix
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $all_tables = $this->wpdb->get_results(
            $this->wpdb->prepare(
                'SHOW TABLE STATUS LIKE %s',
                $this->wpdb->esc_like( $prefix ) . '%'
            )
        );

        if ( ! $all_tables ) {
            return $tables;
        }

        foreach ( $all_tables as $table ) {
            $name_without_prefix = substr( $table->Name, strlen( $prefix ) );
            $table_info = array(
                'name'  => $table->Name,
                'short' => $name_without_prefix,
                'rows'  => (int) $table->Rows,
                'size'  => $this->format_size( $table->Data_length + $table->Index_length ),
                'bytes' => (int) ( $table->Data_length + $table->Index_length ),
            );

            if ( in_array( $name_without_prefix, $this->core_tables, true ) ) {
                $tables['core'][] = $table_info;
            } else {
                $tables['other'][] = $table_info;
            }
        }

        // Sort by name
        usort( $tables['core'], array( $this, 'sort_by_name' ) );
        usort( $tables['other'], array( $this, 'sort_by_name' ) );

        return $tables;
    }

    /**
     * Generate SQL dump for selected tables
     *
     * @param array $table_names List of full table names to export.
     * @return string|WP_Error SQL content or error.
     */
    public function generate_sql_dump( $table_names ) {
        if ( empty( $table_names ) ) {
            return new WP_Error( 'no_tables', __( 'No tables selected for backup.', 'vigilante' ) );
        }

        // Validate all table names belong to this site
        $valid_tables = $this->get_valid_table_names();
        foreach ( $table_names as $table ) {
            if ( ! in_array( $table, $valid_tables, true ) ) {
                return new WP_Error(
                    'invalid_table',
                    sprintf(
                        /* translators: %s: Table name */
                        __( 'Invalid table name: %s', 'vigilante' ),
                        $table
                    )
                );
            }
        }

        $sql = '';

        // File header
        $sql .= "-- ==========================================================\n";
        $sql .= "-- Vigilante Database Backup\n";
        $sql .= '-- Generated: ' . gmdate( 'Y-m-d H:i:s' ) . " UTC\n";
        $sql .= '-- WordPress: ' . get_bloginfo( 'version' ) . "\n";
        $sql .= '-- Site: ' . esc_url( home_url() ) . "\n";
        $sql .= '-- Tables: ' . count( $table_names ) . "\n";
        $sql .= "-- ==========================================================\n\n";

        $sql .= "SET SQL_MODE = \"NO_AUTO_VALUE_ON_ZERO\";\n";
        $sql .= "SET time_zone = \"+00:00\";\n";
        $sql .= "SET NAMES utf8mb4;\n\n";

        foreach ( $table_names as $table_name ) {
            $table_sql = $this->dump_table( $table_name );
            if ( is_wp_error( $table_sql ) ) {
                return $table_sql;
            }
            $sql .= $table_sql;
        }

        $sql .= "-- End of Vigilante backup\n";

        return $sql;
    }

    /**
     * Create ZIP file with SQL dump
     *
     * @param string $sql_content SQL dump content.
     * @return string|WP_Error Path to temporary ZIP file or error.
     */
    public function create_zip( $sql_content ) {
        if ( ! class_exists( 'ZipArchive' ) ) {
            return new WP_Error(
                'zip_unavailable',
                __( 'ZipArchive extension is not available on this server.', 'vigilante' )
            );
        }

        $upload_dir = wp_upload_dir();
        $temp_dir   = trailingslashit( $upload_dir['basedir'] ) . 'vigilante-temp/';

        // Create temp directory
        if ( ! wp_mkdir_p( $temp_dir ) ) {
            return new WP_Error( 'dir_error', __( 'Cannot create temporary directory.', 'vigilante' ) );
        }

        // Protect temp directory: deny rule (Apache/LiteSpeed) plus an index so
        // it cannot be listed. The unguessable filename below is the real guard
        // on servers that ignore .htaccess.
        $htaccess_path = $temp_dir . '.htaccess';
        if ( ! file_exists( $htaccess_path ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- writing a protective deny rule, not user input.
            file_put_contents( $htaccess_path, "Deny from all\n" );
        }
        $index_path = $temp_dir . 'index.php';
        if ( ! file_exists( $index_path ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- writing a silence-is-golden index, not user input.
            file_put_contents( $index_path, "<?php\n// Silence is golden.\n" );
        }

        // Random suffix so the archive cannot be fetched by guessing the
        // timestamp if it is ever left behind on a server that serves uploads.
        $token        = wp_generate_password( 20, false );
        $sql_filename = 'vigilante-db-backup-' . gmdate( 'Y-m-d-His' ) . '.sql';
        $zip_filename = 'vigilante-db-backup-' . gmdate( 'Y-m-d-His' ) . '-' . $token . '.zip';
        $zip_path     = $temp_dir . $zip_filename;

        $zip = new ZipArchive();
        $result = $zip->open( $zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE );

        if ( true !== $result ) {
            return new WP_Error( 'zip_create_error', __( 'Failed to create ZIP file.', 'vigilante' ) );
        }

        $zip->addFromString( $sql_filename, $sql_content );
        $zip->close();

        if ( ! file_exists( $zip_path ) ) {
            return new WP_Error( 'zip_missing', __( 'ZIP file was not created.', 'vigilante' ) );
        }

        return $zip_path;
    }

    /**
     * Stream ZIP file to browser and clean up
     *
     * @param string $zip_path Path to ZIP file.
     * @return void|WP_Error
     */
    public function stream_download( $zip_path ) {
        if ( ! file_exists( $zip_path ) ) {
            return new WP_Error( 'file_not_found', __( 'Backup file not found.', 'vigilante' ) );
        }

        $filename = basename( $zip_path );

        // Clear output buffers
        while ( ob_get_level() ) {
            ob_end_clean();
        }

        // Send headers
        nocache_headers();
        header( 'Content-Type: application/zip' );
        header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
        header( 'Content-Length: ' . filesize( $zip_path ) );
        header( 'Content-Transfer-Encoding: binary' );

        // Stream file
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
        readfile( $zip_path );

        // Clean up
        $this->cleanup_temp_files();

        exit;
    }

    /**
     * Remove temporary backup files
     */
    public function cleanup_temp_files() {
        $upload_dir = wp_upload_dir();
        $temp_dir   = trailingslashit( $upload_dir['basedir'] ) . 'vigilante-temp/';

        if ( ! is_dir( $temp_dir ) ) {
            return;
        }

        $files = glob( $temp_dir . '*' );
        if ( $files ) {
            foreach ( $files as $file ) {
                if ( is_file( $file ) ) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
                    unlink( $file );
                }
            }
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
        rmdir( $temp_dir );
    }

    /**
     * Dump a single table to SQL
     *
     * @param string $table_name Full table name.
     * @return string|WP_Error SQL for the table.
     */
    private function dump_table( $table_name ) {
        $sql = '';
        $sql .= "-- ----------------------------------------------------------\n";
        $sql .= '-- Table: ' . $table_name . "\n";
        $sql .= "-- ----------------------------------------------------------\n\n";

        // Get CREATE TABLE statement (%i identifier placeholder, WP 6.2+)
        $create = $this->wpdb->get_row(
            $this->wpdb->prepare( 'SHOW CREATE TABLE %i', $table_name ),
            ARRAY_N
        );
        if ( ! $create ) {
            return new WP_Error(
                'table_error',
                sprintf(
                    /* translators: %s: Table name */
                    __( 'Cannot read table structure: %s', 'vigilante' ),
                    $table_name
                )
            );
        }

        $sql .= "DROP TABLE IF EXISTS `{$table_name}`;\n";
        $sql .= $create[1] . ";\n\n";

        // Get row count first
        $row_count = (int) $this->wpdb->get_var(
            $this->wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table_name )
        );

        if ( $row_count > 0 ) {
            // Export in batches to avoid memory issues
            $batch_size = 500;
            $offset     = 0;

            // Get column names for INSERT statement
            $columns = $this->wpdb->get_results(
                $this->wpdb->prepare( 'SHOW COLUMNS FROM %i', $table_name ),
                ARRAY_A
            );
            $col_names = array_map(
                function ( $col ) {
                    return '`' . $col['Field'] . '`';
                },
                $columns
            );

            $sql .= 'LOCK TABLES `' . $table_name . "` WRITE;\n";

            while ( $offset < $row_count ) {
                $rows = $this->wpdb->get_results(
                    $this->wpdb->prepare(
                        'SELECT * FROM %i LIMIT %d OFFSET %d',
                        $table_name,
                        $batch_size,
                        $offset
                    ),
                    ARRAY_N
                );

                if ( ! empty( $rows ) ) {
                    $sql .= 'INSERT INTO `' . $table_name . '` (' . implode( ', ', $col_names ) . ") VALUES\n";

                    $values = array();
                    foreach ( $rows as $row ) {
                        $escaped = array_map(
                            function ( $value ) {
                                if ( null === $value ) {
                                    return 'NULL';
                                }
                                return "'" . esc_sql( $value ) . "'";
                            },
                            $row
                        );
                        $values[] = '(' . implode( ', ', $escaped ) . ')';
                    }

                    $sql .= implode( ",\n", $values ) . ";\n";
                }

                $offset += $batch_size;
            }

            $sql .= "UNLOCK TABLES;\n";
        }

        $sql .= "\n";

        return $sql;
    }

    /**
     * Get list of valid table names for this site
     *
     * @return array Full table names.
     */
    private function get_valid_table_names() {
        $prefix = $this->wpdb->prefix;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $results = $this->wpdb->get_col(
            $this->wpdb->prepare(
                'SHOW TABLES LIKE %s',
                $this->wpdb->esc_like( $prefix ) . '%'
            )
        );

        return $results ? $results : array();
    }

    /**
     * Format byte size to human readable
     *
     * @param int $bytes Size in bytes.
     * @return string Formatted size.
     */
    private function format_size( $bytes ) {
        $units = array( 'B', 'KB', 'MB', 'GB' );
        $bytes = max( $bytes, 0 );
        $pow   = floor( ( $bytes ? log( $bytes ) : 0 ) / log( 1024 ) );
        $pow   = min( $pow, count( $units ) - 1 );
        $bytes /= pow( 1024, $pow );

        return round( $bytes, 2 ) . ' ' . $units[ $pow ];
    }

    /**
     * Sort callback by table name
     *
     * @param array $a First table.
     * @param array $b Second table.
     * @return int
     */
    private function sort_by_name( $a, $b ) {
        return strcmp( $a['name'], $b['name'] );
    }
}