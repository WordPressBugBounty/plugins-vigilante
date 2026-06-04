<?php
/**
 * Database Prefix Changer Class
 *
 * Safely changes the WordPress database table prefix
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, PluginCheck.Security.DirectDB.UnescapedDBParameter

/**
 * Class Vigilante_Database_Prefix
 *
 * Changes the WordPress database prefix safely
 */
class Vigilante_Database_Prefix {

    /**
     * WordPress database instance
     *
     * @var wpdb
     */
    private $wpdb;

    /**
     * Current prefix
     *
     * @var string
     */
    private $old_prefix;

    /**
     * New prefix to apply
     *
     * @var string
     */
    private $new_prefix;

    /**
     * Path to wp-config.php
     *
     * @var string
     */
    private $wpconfig_path;

    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        $this->wpdb       = $wpdb;
        $this->old_prefix  = $wpdb->prefix;
        $this->wpconfig_path = $this->find_wpconfig_path();
    }

    /**
     * Get the current database prefix
     *
     * @return string
     */
    public function get_current_prefix() {
        return $this->old_prefix;
    }

    /**
     * Check if current prefix is the insecure default
     *
     * @return bool
     */
    public function is_default_prefix() {
        return 'wp_' === $this->old_prefix;
    }

    /**
     * Generate a random secure prefix
     *
     * Format: 2-3 lowercase letters + 2-3 digits + underscore (e.g., vg72_ or kx391_)
     *
     * @return string
     */
    public function generate_prefix() {
        $letters = 'abcdefghijklmnopqrstuvwxyz';
        $prefix  = '';

        // 2-3 random letters
        $letter_count = wp_rand( 2, 3 );
        for ( $i = 0; $i < $letter_count; $i++ ) {
            $prefix .= $letters[ wp_rand( 0, strlen( $letters ) - 1 ) ];
        }

        // 2-3 random digits
        $digit_count = wp_rand( 2, 3 );
        for ( $i = 0; $i < $digit_count; $i++ ) {
            $prefix .= wp_rand( 0, 9 );
        }

        $prefix .= '_';

        // Verify no tables exist with this prefix
        if ( $this->prefix_tables_exist( $prefix ) ) {
            return $this->generate_prefix(); // Regenerate if collision
        }

        return $prefix;
    }

    /**
     * Validate a prefix string
     *
     * @param string $prefix Prefix to validate.
     * @return true|WP_Error
     */
    public function validate_prefix( $prefix ) {
        // Must end with underscore
        if ( substr( $prefix, -1 ) !== '_' ) {
            return new WP_Error( 'no_underscore', __( 'Prefix must end with an underscore.', 'vigilante' ) );
        }

        // Length check (including underscore): 3-16 characters
        $len = strlen( $prefix );
        if ( $len < 3 || $len > 16 ) {
            return new WP_Error( 'invalid_length', __( 'Prefix must be between 3 and 16 characters (including underscore).', 'vigilante' ) );
        }

        // Only lowercase letters, digits, and underscore
        if ( ! preg_match( '/^[a-z0-9_]+$/', $prefix ) ) {
            return new WP_Error( 'invalid_chars', __( 'Prefix must contain only lowercase letters, digits, and underscores.', 'vigilante' ) );
        }

        // Must start with a letter
        if ( ! preg_match( '/^[a-z]/', $prefix ) ) {
            return new WP_Error( 'must_start_letter', __( 'Prefix must start with a letter.', 'vigilante' ) );
        }

        // Cannot be the same as current
        if ( $prefix === $this->old_prefix ) {
            return new WP_Error( 'same_prefix', __( 'New prefix is the same as the current one.', 'vigilante' ) );
        }

        // Check for existing tables with this prefix
        if ( $this->prefix_tables_exist( $prefix ) ) {
            return new WP_Error( 'prefix_exists', __( 'Tables with this prefix already exist in the database.', 'vigilante' ) );
        }

        return true;
    }

    /**
     * Execute the full prefix change operation
     *
     * @param string $new_prefix New prefix to apply.
     * @return true|WP_Error
     */
    public function change_prefix( $new_prefix ) {
        $this->new_prefix = $new_prefix;

        // Step 1: Validate
        $valid = $this->validate_prefix( $new_prefix );
        if ( is_wp_error( $valid ) ) {
            return $valid;
        }

        // Step 2: Check wp-config.php is writable
        if ( ! $this->wpconfig_path ) {
            return new WP_Error( 'wpconfig_not_found', __( 'Cannot locate wp-config.php file.', 'vigilante' ) );
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
        if ( ! is_writable( $this->wpconfig_path ) ) {
            return new WP_Error( 'wpconfig_not_writable', __( 'wp-config.php is not writable. Check file permissions.', 'vigilante' ) );
        }

        // Step 3: Get all tables with current prefix
        $tables = $this->get_prefixed_tables();
        if ( empty( $tables ) ) {
            return new WP_Error( 'no_tables', __( 'No tables found with the current prefix.', 'vigilante' ) );
        }

        // Step 4: Rename all tables
        $rename_result = $this->rename_tables( $tables );
        if ( is_wp_error( $rename_result ) ) {
            return $rename_result;
        }

        // Step 5: Update wp-config.php
        $config_result = $this->update_wpconfig();
        if ( is_wp_error( $config_result ) ) {
            // Rollback table renames
            $this->rollback_tables( $tables );
            return $config_result;
        }

        // Step 6: Update options table references (user_roles, etc.)
        $this->update_options_prefix();

        // Step 7: Update usermeta prefix keys
        $this->update_usermeta_prefix();

        return true;
    }

    /**
     * Get all tables with the current prefix
     *
     * @return array Table names.
     */
    private function get_prefixed_tables() {
        return $this->wpdb->get_col(
            $this->wpdb->prepare(
                'SHOW TABLES LIKE %s',
                $this->wpdb->esc_like( $this->old_prefix ) . '%'
            )
        );
    }

    /**
     * Check if tables exist with a given prefix
     *
     * @param string $prefix Prefix to check.
     * @return bool
     */
    private function prefix_tables_exist( $prefix ) {
        $result = $this->wpdb->get_var(
            $this->wpdb->prepare(
                'SHOW TABLES LIKE %s',
                $this->wpdb->esc_like( $prefix ) . '%'
            )
        );

        return ! empty( $result );
    }

    /**
     * Rename all tables from old prefix to new prefix
     *
     * @param array $tables List of table names.
     * @return true|WP_Error
     */
    private function rename_tables( $tables ) {
        $renamed = array();

        foreach ( $tables as $old_name ) {
            $new_name = $this->new_prefix . substr( $old_name, strlen( $this->old_prefix ) );

            // Use RENAME TABLE (atomic operation, works within same database)
            $result = $this->wpdb->query(
                $this->wpdb->prepare(
                    'RENAME TABLE %i TO %i',
                    $old_name,
                    $new_name
                )
            );

            if ( false === $result ) {
                // Rollback already renamed tables
                foreach ( $renamed as $rollback_new => $rollback_old ) {
                    $this->wpdb->query(
                        $this->wpdb->prepare(
                            'RENAME TABLE %i TO %i',
                            $rollback_new,
                            $rollback_old
                        )
                    );
                }

                return new WP_Error(
                    'rename_failed',
                    sprintf(
                        /* translators: %s: Table name */
                        __( 'Failed to rename table: %s. All changes have been rolled back.', 'vigilante' ),
                        $old_name
                    )
                );
            }

            $renamed[ $new_name ] = $old_name;
        }

        return true;
    }

    /**
     * Rollback table renames
     *
     * @param array $original_tables Original table names.
     */
    private function rollback_tables( $original_tables ) {
        foreach ( $original_tables as $old_name ) {
            $new_name = $this->new_prefix . substr( $old_name, strlen( $this->old_prefix ) );

            // Check if new name exists (it was renamed)
            $exists = $this->wpdb->get_var(
                $this->wpdb->prepare( 'SHOW TABLES LIKE %s', $new_name )
            );

            if ( $exists ) {
                $this->wpdb->query(
                    $this->wpdb->prepare(
                        'RENAME TABLE %i TO %i',
                        $new_name,
                        $old_name
                    )
                );
            }
        }
    }

    /**
     * Update $table_prefix in wp-config.php
     *
     * @return true|WP_Error
     */
    private function update_wpconfig() {
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        $content = file_get_contents( $this->wpconfig_path );

        if ( false === $content ) {
            return new WP_Error( 'read_error', __( 'Cannot read wp-config.php.', 'vigilante' ) );
        }

        // Back up the original file
        $backup_path = $this->wpconfig_path . '.vigilante-backup-' . gmdate( 'YmdHis' );
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        if ( ! file_put_contents( $backup_path, $content ) ) {
            return new WP_Error( 'backup_error', __( 'Cannot create wp-config.php backup.', 'vigilante' ) );
        }

        // Match the $table_prefix line (handles single and double quotes, with/without spaces)
        $pattern = '/(\$table_prefix\s*=\s*)([\'"]).+?\\2(\s*;)/';
        $replacement = '${1}\'' . $this->new_prefix . '\'${3}';

        $new_content = preg_replace( $pattern, $replacement, $content, 1, $count );

        if ( 0 === $count || null === $new_content ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
            unlink( $backup_path );
            return new WP_Error( 'replace_error', __( 'Cannot find $table_prefix in wp-config.php.', 'vigilante' ) );
        }

        // Write updated content
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        $result = file_put_contents( $this->wpconfig_path, $new_content );

        if ( false === $result ) {
            // Restore backup
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            file_put_contents( $this->wpconfig_path, $content );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
            unlink( $backup_path );
            return new WP_Error( 'write_error', __( 'Cannot write to wp-config.php.', 'vigilante' ) );
        }

        // Clean up backup after successful write
        // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
        unlink( $backup_path );

        return true;
    }

    /**
     * Update option names that contain the old prefix
     *
     * WordPress stores some options with the prefix in their name:
     * - {prefix}user_roles
     */
    private function update_options_prefix() {
        $options_table = $this->new_prefix . 'options';

        // Find and update options that start with old prefix
        $old_like = $this->wpdb->esc_like( $this->old_prefix ) . '%';

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $options = $this->wpdb->get_results(
            $this->wpdb->prepare(
                "SELECT option_id, option_name FROM `{$options_table}` WHERE option_name LIKE %s",
                $old_like
            )
        );

        if ( $options ) {
            foreach ( $options as $option ) {
                $new_option_name = $this->new_prefix . substr( $option->option_name, strlen( $this->old_prefix ) );

                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $this->wpdb->update(
                    $options_table,
                    array( 'option_name' => $new_option_name ),
                    array( 'option_id' => $option->option_id ),
                    array( '%s' ),
                    array( '%d' )
                );
            }
        }
    }

    /**
     * Update usermeta keys that contain the old prefix
     *
     * WordPress stores some usermeta with the prefix in the key:
     * - {prefix}capabilities
     * - {prefix}user_level
     * - {prefix}dashboard_quick_press_last_post_id
     * - {prefix}user-settings
     * - {prefix}user-settings-time
     */
    private function update_usermeta_prefix() {
        $usermeta_table = $this->new_prefix . 'usermeta';

        $old_like = $this->wpdb->esc_like( $this->old_prefix ) . '%';

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $metas = $this->wpdb->get_results(
            $this->wpdb->prepare(
                "SELECT umeta_id, meta_key FROM `{$usermeta_table}` WHERE meta_key LIKE %s",
                $old_like
            )
        );

        if ( $metas ) {
            foreach ( $metas as $meta ) {
                $new_meta_key = $this->new_prefix . substr( $meta->meta_key, strlen( $this->old_prefix ) );

                // Prefix migration has to rewrite meta_key values by definition — the slow-query
                // rule does not apply here. Disable around the whole statement so the sniff
                // catches both the call and the 'meta_key' array literal inside it.
                // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.SlowDBQuery.slow_db_query_meta_key
                $this->wpdb->update(
                    $usermeta_table,
                    array( 'meta_key' => $new_meta_key ),
                    array( 'umeta_id' => $meta->umeta_id ),
                    array( '%s' ),
                    array( '%d' )
                );
                // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.SlowDBQuery.slow_db_query_meta_key
            }
        }
    }

    /**
     * Find wp-config.php path
     *
     * Checks standard location and one level up (common setup)
     *
     * @return string|false Path or false if not found.
     */
    private function find_wpconfig_path() {
        // Standard location
        $path = ABSPATH . 'wp-config.php';
        if ( file_exists( $path ) ) {
            return $path;
        }

        // One directory up
        $path = dirname( ABSPATH ) . '/wp-config.php';
        if ( file_exists( $path ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
            return $path;
        }

        return false;
    }
}