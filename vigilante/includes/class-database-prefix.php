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
        $this->wpdb        = $wpdb;
        // Always the network-wide base prefix. On a single site it is identical to
        // $wpdb->prefix; on multisite $wpdb->prefix is the prefix of the *current*
        // blog (wp_3_), and using it would rename only that subsite's tables while
        // rewriting the $table_prefix shared by the whole network.
        $this->old_prefix  = $wpdb->base_prefix;
        $this->wpconfig_path = $this->find_wpconfig_path();
    }

    /**
     * Whether the prefix may be changed from the current context
     *
     * The prefix lives in wp-config.php, which a multisite network shares across
     * every site, so changing it is a network-wide operation: only a network
     * administrator working from the main site may run it.
     *
     * @return true|WP_Error
     */
    public function can_change_prefix() {
        if ( ! is_multisite() ) {
            return true;
        }

        if ( ! is_main_site() ) {
            return new WP_Error(
                'multisite_not_main_site',
                __( 'The database prefix is shared by the whole network. Change it from the main site of the network.', 'vigilante' )
            );
        }

        if ( ! Vigilante_Settings::can_write_shared_files() ) {
            return new WP_Error(
                'multisite_not_network_admin',
                __( 'Only a network administrator can change the database prefix of a multisite network.', 'vigilante' )
            );
        }

        return true;
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

        // Step 1: Check the context is allowed to change a network-wide setting
        $allowed = $this->can_change_prefix();
        if ( is_wp_error( $allowed ) ) {
            return $allowed;
        }

        // Step 2: Validate
        $valid = $this->validate_prefix( $new_prefix );
        if ( is_wp_error( $valid ) ) {
            return $valid;
        }

        // Step 3: Check wp-config.php is writable
        if ( ! $this->wpconfig_path ) {
            return new WP_Error( 'wpconfig_not_found', __( 'Cannot locate wp-config.php file.', 'vigilante' ) );
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
        if ( ! is_writable( $this->wpconfig_path ) ) {
            return new WP_Error( 'wpconfig_not_writable', __( 'wp-config.php is not writable. Check file permissions.', 'vigilante' ) );
        }

        // Step 4: Map every site of the install to its old and new prefix.
        // Has to happen before the rename: once the blogs table moves, neither
        // get_sites() nor $wpdb->blogs can resolve the list any more.
        $sites = $this->get_site_prefix_map();
        if ( is_wp_error( $sites ) ) {
            return $sites;
        }

        // Step 5: Get all tables with current prefix
        $tables = $this->get_prefixed_tables();
        if ( empty( $tables ) ) {
            return new WP_Error( 'no_tables', __( 'No tables found with the current prefix.', 'vigilante' ) );
        }

        // Step 6: Rename all tables
        $rename_result = $this->rename_tables( $tables );
        if ( is_wp_error( $rename_result ) ) {
            return $rename_result;
        }

        // Step 7: Point wpdb at the new table names, so the remainder of this
        // request (option rewrites, activity log entry) still has a database.
        $this->wpdb->set_prefix( $this->new_prefix );

        // Step 8: Update wp-config.php
        $config_result = $this->update_wpconfig();
        if ( is_wp_error( $config_result ) ) {
            // Rollback table renames
            $this->rollback_tables( $tables );
            $this->wpdb->set_prefix( $this->old_prefix );
            return $config_result;
        }

        // Step 9: Update the option names WordPress derives from the prefix,
        // in the options table of every site of the install
        $this->update_options_prefix( $sites );

        // Step 10: Update usermeta prefix keys
        $this->update_usermeta_prefix( $sites );

        // Step 11: Drop cached copies of everything that was renamed
        $this->flush_caches();

        return true;
    }

    /**
     * Build the old/new prefix map for every site of the install
     *
     * A single site returns one entry with no blog segment. A network returns one
     * entry per row of the blogs table: blog 1 uses the bare base prefix and every
     * other blog the {base}{id}_ form, matching wpdb::get_blog_prefix().
     *
     * Must run before the tables are renamed.
     *
     * @return array|WP_Error
     */
    private function get_site_prefix_map() {
        if ( ! is_multisite() ) {
            return array(
                array(
                    'blog_id'    => 1,
                    'is_main'    => true,
                    'old_prefix' => $this->old_prefix,
                    'new_prefix' => $this->new_prefix,
                ),
            );
        }

        $blogs_table = $this->old_prefix . 'blogs';

        if ( ! $this->table_exists( $blogs_table ) ) {
            return new WP_Error( 'no_blogs_table', __( 'Cannot find the network sites table.', 'vigilante' ) );
        }

        $blog_ids = $this->wpdb->get_col( "SELECT blog_id FROM `{$blogs_table}` ORDER BY blog_id ASC" );

        if ( empty( $blog_ids ) ) {
            return new WP_Error( 'no_sites', __( 'Cannot read the list of sites of the network.', 'vigilante' ) );
        }

        $map = array();

        foreach ( $blog_ids as $blog_id ) {
            $blog_id = (int) $blog_id;
            // wpdb::get_blog_prefix() treats blog 1 (and 0) as the base prefix.
            $segment = ( $blog_id > 1 ) ? $blog_id . '_' : '';

            $map[] = array(
                'blog_id'    => $blog_id,
                'is_main'    => ( '' === $segment ),
                'old_prefix' => $this->old_prefix . $segment,
                'new_prefix' => $this->new_prefix . $segment,
            );
        }

        return $map;
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
            $exists = $this->table_exists( $new_name );

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

        $this->invalidate_wpconfig_opcode_cache();

        return true;
    }

    /**
     * Drop the compiled copy of wp-config.php from the opcode cache
     *
     * wp-config.php is PHP, so OPcache keeps serving the compiled old
     * $table_prefix for up to opcache.revalidate_freq seconds after the file is
     * rewritten. Any request landing in that window boots WordPress against
     * tables that no longer exist: it cannot read siteurl, decides the site is
     * not installed and redirects to install.php, and the missing users table
     * makes the auth cookie fail validation, which core answers by clearing it.
     * The visitor is thrown out of the session and offered the installer, and it
     * fixes itself a couple of seconds later, which makes it look like a ghost.
     *
     * With PHP-FPM the opcode cache is shared by the whole pool, so invalidating
     * it here covers every worker.
     */
    private function invalidate_wpconfig_opcode_cache() {
        if ( ! $this->wpconfig_path ) {
            return;
        }

        clearstatcache( true, $this->wpconfig_path );

        if ( ! function_exists( 'opcache_invalidate' ) ) {
            return;
        }

        if ( ! filter_var( ini_get( 'opcache.enable' ), FILTER_VALIDATE_BOOLEAN ) ) {
            return;
        }

        // Silenced on purpose: with opcache.restrict_api set to a path this file
        // is not under, the call is refused with a warning and there is nothing
        // to do about it. Losing the invalidation is survivable, a warning in
        // the log of every site that hardens the API is not.
        // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        @opcache_invalidate( $this->wpconfig_path, true );
    }

    /**
     * Rename the option names WordPress derives from the table prefix
     *
     * WordPress builds exactly one option name out of the prefix:
     * {$blog_prefix}user_roles (see WP_Roles::for_site()). Every other option
     * that merely starts with the same letters is a literal name owned by core
     * (wp_page_for_privacy_policy, wp_notes_notify, wp_attachment_pages_enabled,
     * wp_force_deactivated_plugins) or by a plugin (wp_rocket_settings,
     * wp_installer_settings) and renaming it silently destroys that setting.
     *
     * On multisite each site keeps its roles in its own options table, so every
     * site of the network is visited, not just the main one. A subsite whose
     * {prefix}{id}_user_roles is left behind ends up with zero roles: an empty
     * role dropdown and fatals in plugins that assume a role exists.
     *
     * @param array $sites Prefix map from get_site_prefix_map().
     */
    private function update_options_prefix( $sites ) {
        /**
         * Filters the option name suffixes that are derived from the table prefix.
         *
         * Only add suffixes for options a plugin stores as
         * $wpdb->get_blog_prefix() . 'suffix'. Anything whose name merely starts
         * with the prefix letters must NOT be listed here.
         *
         * @since 2.9.8
         *
         * @param string[] $suffixes Suffixes appended to the blog prefix.
         */
        $suffixes = apply_filters( 'vigilante_prefixed_option_suffixes', array( 'user_roles' ) );

        foreach ( $sites as $site ) {
            $table = $site['new_prefix'] . 'options';

            if ( ! $this->table_exists( $table ) ) {
                continue;
            }

            // In a subsite's own options table anything named {base}{id}_* is
            // prefix-derived by construction: no plugin calls an option "wp_3_...".
            if ( empty( $site['is_main'] ) ) {
                $this->bulk_rename_options( $table, $site['old_prefix'], $site['new_prefix'] );
            }

            foreach ( $suffixes as $suffix ) {
                $this->rename_option( $table, $site['old_prefix'] . $suffix, $site['new_prefix'] . $suffix );
            }
        }

        $this->repair_subsite_user_roles( $sites );
    }

    /**
     * Last-resort repair for subsites whose roles option has an unexpected name
     *
     * A subsite that was cloned from another install, or migrated by a tool that
     * did not rewrite the option, can hold its roles under the bare base prefix
     * ({base}user_roles) inside its own options table. WordPress looks for
     * {base}{id}_user_roles, finds nothing and the site is left with no roles at
     * all. Runs only when the correct name is missing, so it never overwrites
     * roles that are already in place.
     *
     * @param array $sites Prefix map from get_site_prefix_map().
     */
    private function repair_subsite_user_roles( $sites ) {
        foreach ( $sites as $site ) {
            if ( ! empty( $site['is_main'] ) ) {
                continue;
            }

            $table = $site['new_prefix'] . 'options';

            if ( ! $this->table_exists( $table ) ) {
                continue;
            }

            $correct = $site['new_prefix'] . 'user_roles';

            if ( $this->option_exists( $table, $correct ) ) {
                continue;
            }

            $candidates = array(
                $this->old_prefix . 'user_roles',
                $this->new_prefix . 'user_roles',
            );

            foreach ( $candidates as $candidate ) {
                if ( $this->rename_option( $table, $candidate, $correct ) ) {
                    break;
                }
            }
        }
    }

    /**
     * Update usermeta keys that contain the old prefix
     *
     * WordPress stores per-site user meta with the blog prefix in the key
     * ({prefix}capabilities, {prefix}user_level, and everything written through
     * update_user_option()). Keys that merely start with the same letters
     * (wp_sensei_*, wp_language_pairs) belong to a plugin and are left alone.
     *
     * For a subsite the {base}{id}_ form cannot collide with a literal key, so
     * everything carrying it is renamed. For the main site, where the prefix is
     * bare, only the known core keys are touched.
     *
     * @param array $sites Prefix map from get_site_prefix_map().
     */
    private function update_usermeta_prefix( $sites ) {
        $usermeta_table = $this->new_prefix . 'usermeta';

        if ( ! $this->table_exists( $usermeta_table ) ) {
            return;
        }

        /**
         * Filters the usermeta key suffixes that are derived from the table prefix.
         *
         * These are the keys core stores as $wpdb->get_blog_prefix() . 'suffix'.
         * Add a suffix here for a plugin that stores per-site user meta through
         * update_user_option() and needs it carried over on the main site.
         *
         * @since 2.9.8
         *
         * @param string[] $suffixes Suffixes appended to the blog prefix.
         */
        $suffixes = apply_filters(
            'vigilante_prefixed_usermeta_suffixes',
            array(
                'capabilities',
                'user_level',
                'user-settings',
                'user-settings-time',
                'dashboard_quick_press_last_post_id',
                'media_library_mode',
                'persisted_preferences',
            )
        );

        foreach ( $sites as $site ) {
            if ( empty( $site['is_main'] ) ) {
                $this->bulk_rename_usermeta( $usermeta_table, $site['old_prefix'], $site['new_prefix'] );
                continue;
            }

            foreach ( $suffixes as $suffix ) {
                $this->rename_usermeta( $usermeta_table, $site['old_prefix'] . $suffix, $site['new_prefix'] . $suffix );
            }
        }
    }

    /**
     * Rename every option in a table whose name starts with a given prefix
     *
     * Only ever called with a subsite prefix ({base}{id}_), where the prefix
     * cannot appear at the start of a literal option name.
     *
     * @param string $table      Options table name.
     * @param string $old_prefix Prefix to strip.
     * @param string $new_prefix Prefix to write.
     */
    private function bulk_rename_options( $table, $old_prefix, $new_prefix ) {
        $this->wpdb->query(
            $this->wpdb->prepare(
                "UPDATE `{$table}` SET option_name = CONCAT( %s, SUBSTRING( option_name, %d ) ) WHERE option_name LIKE %s",
                $new_prefix,
                strlen( $old_prefix ) + 1,
                $this->wpdb->esc_like( $old_prefix ) . '%'
            )
        );
    }

    /**
     * Rename every usermeta key that starts with a given prefix
     *
     * Only ever called with a subsite prefix ({base}{id}_), where the prefix
     * cannot appear at the start of a literal meta key.
     *
     * @param string $table      Usermeta table name.
     * @param string $old_prefix Prefix to strip.
     * @param string $new_prefix Prefix to write.
     */
    private function bulk_rename_usermeta( $table, $old_prefix, $new_prefix ) {
        // Prefix migration has to rewrite meta_key values by definition, so the
        // slow-query rule does not apply here.
        // phpcs:disable WordPress.DB.SlowDBQuery.slow_db_query_meta_key
        $this->wpdb->query(
            $this->wpdb->prepare(
                "UPDATE `{$table}` SET meta_key = CONCAT( %s, SUBSTRING( meta_key, %d ) ) WHERE meta_key LIKE %s",
                $new_prefix,
                strlen( $old_prefix ) + 1,
                $this->wpdb->esc_like( $old_prefix ) . '%'
            )
        );
        // phpcs:enable WordPress.DB.SlowDBQuery.slow_db_query_meta_key
    }

    /**
     * Rename a single option, without ever overwriting an existing one
     *
     * @param string $table    Options table name.
     * @param string $old_name Current option name.
     * @param string $new_name Wanted option name.
     * @return bool Whether the option was renamed.
     */
    private function rename_option( $table, $old_name, $new_name ) {
        if ( $old_name === $new_name || $this->option_exists( $table, $new_name ) ) {
            return false;
        }

        $option_id = $this->wpdb->get_var(
            $this->wpdb->prepare( "SELECT option_id FROM `{$table}` WHERE option_name = %s LIMIT 1", $old_name )
        );

        if ( ! $option_id ) {
            return false;
        }

        return (bool) $this->wpdb->update(
            $table,
            array( 'option_name' => $new_name ),
            array( 'option_id' => (int) $option_id ),
            array( '%s' ),
            array( '%d' )
        );
    }

    /**
     * Rename every row of a usermeta key
     *
     * @param string $table    Usermeta table name.
     * @param string $old_key  Current meta key.
     * @param string $new_key  Wanted meta key.
     */
    private function rename_usermeta( $table, $old_key, $new_key ) {
        if ( $old_key === $new_key ) {
            return;
        }

        // Prefix migration has to rewrite meta_key values by definition, so the
        // slow-query rule does not apply here.
        // phpcs:disable WordPress.DB.SlowDBQuery.slow_db_query_meta_key
        $this->wpdb->query(
            $this->wpdb->prepare(
                "UPDATE `{$table}` SET meta_key = %s WHERE meta_key = %s",
                $new_key,
                $old_key
            )
        );
        // phpcs:enable WordPress.DB.SlowDBQuery.slow_db_query_meta_key
    }

    /**
     * Whether an option name exists in a given options table
     *
     * @param string $table       Options table name.
     * @param string $option_name Option name.
     * @return bool
     */
    private function option_exists( $table, $option_name ) {
        $found = $this->wpdb->get_var(
            $this->wpdb->prepare( "SELECT option_id FROM `{$table}` WHERE option_name = %s LIMIT 1", $option_name )
        );

        return ! empty( $found );
    }

    /**
     * Whether a table exists
     *
     * @param string $table Table name.
     * @return bool
     */
    private function table_exists( $table ) {
        $found = $this->wpdb->get_var(
            $this->wpdb->prepare( 'SHOW TABLES LIKE %s', $this->wpdb->esc_like( $table ) )
        );

        return ! empty( $found );
    }

    /**
     * Drop cached copies of everything the rename touched
     *
     * Options are served from the object cache, and the rows were renamed behind
     * WordPress's back, so the cached alloptions/notoptions arrays still describe
     * the old names. With a persistent object cache (Memcached, Redis) that stale
     * copy outlives the request and the site keeps behaving as if nothing changed.
     */
    private function flush_caches() {
        wp_cache_flush();

        if ( function_exists( 'wp_cache_flush_runtime' ) ) {
            wp_cache_flush_runtime();
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