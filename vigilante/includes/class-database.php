<?php
/**
 * Database Class
 *
 * Handles database operations for activity log and login attempts
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- All queries use $wpdb->prepare() with validated parameters

/**
 * Class Vigilante_Database
 *
 * Manages custom database tables
 */
class Vigilante_Database {

    /**
     * Database version for migrations
     */
    const DB_VERSION = '1.4.0';

    /**
     * Option name for storing DB version
     */
    const DB_VERSION_OPTION = 'vigilante_db_version';

    /**
     * Activity log table name (without prefix)
     *
     * @var string
     */
    private $activity_log_table = 'vigilante_activity_log';

    /**
     * Login attempts table name (without prefix)
     *
     * @var string
     */
    private $login_attempts_table = 'vigilante_login_attempts';

    /**
     * File integrity table name (without prefix)
     *
     * @var string
     */
    private $file_integrity_table = 'vigilante_file_integrity';

    /**
     * 2FA codes table name (without prefix)
     *
     * @var string
     */
    private $two_factor_codes_table = 'vigilante_2fa_codes';

    /**
     * 2FA trusted devices table name (without prefix)
     *
     * @var string
     */
    private $two_factor_devices_table = 'vigilante_2fa_trusted_devices';

    /**
     * 2FA notifications table name (without prefix)
     *
     * @var string
     */
    private $two_factor_notifications_table = 'vigilante_2fa_notifications';

    /**
     * 2FA TOTP secrets table name (without prefix)
     *
     * @var string
     */
    private $two_factor_totp_table = 'vigilante_2fa_totp';

    /**
     * WordPress database instance
     *
     * @var wpdb
     */
    private $wpdb;

    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;
    }

    /**
     * Get full table name with prefix
     *
     * @param string $table Table name without prefix.
     * @return string Full table name.
     */
    public function get_table_name( $table ) {
        return $this->wpdb->prefix . $table;
    }

    /**
     * Get escaped table name for use in SQL queries
     *
     * @param string $table Full table name.
     * @return string Escaped table name with backticks.
     */
    private function esc_table( $table ) {
        return '`' . esc_sql( $table ) . '`';
    }

    /**
     * Get activity log table name
     *
     * @return string
     */
    public function get_activity_log_table() {
        return $this->get_table_name( $this->activity_log_table );
    }

    /**
     * Get login attempts table name
     *
     * @return string
     */
    public function get_login_attempts_table() {
        return $this->get_table_name( $this->login_attempts_table );
    }

    /**
     * Get file integrity table name
     *
     * @return string
     */
    public function get_file_integrity_table() {
        return $this->get_table_name( $this->file_integrity_table );
    }

    /**
     * Get 2FA codes table name
     *
     * @return string
     */
    public function get_2fa_codes_table() {
        return $this->get_table_name( $this->two_factor_codes_table );
    }

    /**
     * Get 2FA trusted devices table name
     *
     * @return string
     */
    public function get_2fa_devices_table() {
        return $this->get_table_name( $this->two_factor_devices_table );
    }

    /**
     * Get 2FA notifications table name
     *
     * @return string
     */
    public function get_2fa_notifications_table() {
        return $this->get_table_name( $this->two_factor_notifications_table );
    }

    /**
     * Get TOTP secrets table name with prefix
     *
     * @return string
     */
    public function get_totp_table() {
        return $this->get_table_name( $this->two_factor_totp_table );
    }

    /**
     * Create all required database tables
     *
     * @return bool True on success.
     */
    public function create_tables() {
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $charset_collate = $this->wpdb->get_charset_collate();
        $result = true;

        // Activity Log table
        $activity_log_sql = "CREATE TABLE {$this->get_activity_log_table()} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            event_type varchar(50) NOT NULL,
            event_action varchar(100) NOT NULL,
            event_message text NOT NULL,
            user_id bigint(20) unsigned DEFAULT 0,
            user_login varchar(60) DEFAULT '',
            ip_address varchar(45) DEFAULT '',
            user_agent text,
            request_method varchar(10) DEFAULT '',
            object_type varchar(50) DEFAULT '',
            object_id bigint(20) unsigned DEFAULT 0,
            object_name varchar(255) DEFAULT '',
            severity varchar(20) DEFAULT 'info',
            extra_data longtext,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY event_action (event_action),
            KEY user_id (user_id),
            KEY ip_address (ip_address),
            KEY severity (severity),
            KEY request_method (request_method),
            KEY created_at (created_at)
        ) $charset_collate;";

        dbDelta( $activity_log_sql );

        // Login Attempts table
        $login_attempts_sql = "CREATE TABLE {$this->get_login_attempts_table()} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            username varchar(60) NOT NULL,
            attempt_type varchar(20) NOT NULL DEFAULT 'login',
            status varchar(20) NOT NULL DEFAULT 'failed',
            user_agent text,
            lockout_until datetime DEFAULT NULL,
            attempt_count int(11) unsigned DEFAULT 1,
            last_attempt datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY username (username),
            KEY status (status),
            KEY lockout_until (lockout_until),
            KEY last_attempt (last_attempt),
            UNIQUE KEY ip_username (ip_address, username)
        ) $charset_collate;";

        dbDelta( $login_attempts_sql );

        // File Integrity table
        $file_integrity_sql = "CREATE TABLE {$this->get_file_integrity_table()} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            file_path varchar(500) NOT NULL,
            file_hash varchar(64) NOT NULL,
            file_size bigint(20) unsigned NOT NULL DEFAULT 0,
            file_type varchar(50) NOT NULL DEFAULT 'core',
            status varchar(20) NOT NULL DEFAULT 'ok',
            last_checked datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_modified datetime DEFAULT NULL,
            extra_data text,
            PRIMARY KEY (id),
            KEY file_type (file_type),
            KEY status (status),
            KEY last_checked (last_checked),
            UNIQUE KEY file_path (file_path(255))
        ) $charset_collate;";

        dbDelta( $file_integrity_sql );

        // 2FA Codes table
        $two_factor_codes_sql = "CREATE TABLE {$this->get_2fa_codes_table()} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned NOT NULL,
            code varchar(6) NOT NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at datetime NOT NULL,
            attempts int(11) unsigned DEFAULT 0,
            used tinyint(1) DEFAULT 0,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY expires_at (expires_at)
        ) $charset_collate;";

        dbDelta( $two_factor_codes_sql );

        // 2FA Trusted Devices table
        $two_factor_devices_sql = "CREATE TABLE {$this->get_2fa_devices_table()} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned NOT NULL,
            device_hash varchar(64) NOT NULL,
            user_agent text,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at datetime NOT NULL,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY device_hash (device_hash),
            KEY expires_at (expires_at)
        ) $charset_collate;";

        dbDelta( $two_factor_devices_sql );

        // 2FA Notifications table (tracks which users have been notified)
        $two_factor_notifications_sql = "CREATE TABLE {$this->get_2fa_notifications_table()} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned NOT NULL,
            sent_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY user_id (user_id)
        ) $charset_collate;";

        dbDelta( $two_factor_notifications_sql );

        // 2FA TOTP secrets table
        $two_factor_totp_sql = "CREATE TABLE {$this->get_totp_table()} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned NOT NULL,
            secret text NOT NULL,
            backup_codes text,
            is_configured tinyint(1) DEFAULT 0,
            configured_at datetime DEFAULT NULL,
            last_used_at datetime DEFAULT NULL,
            grace_period_expires datetime DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY user_id (user_id)
        ) $charset_collate;";

        dbDelta( $two_factor_totp_sql );

        // Store database version
        update_option( self::DB_VERSION_OPTION, self::DB_VERSION );

        return $result;
    }

    /**
     * Check if tables need to be updated
     *
     * @return bool True if update needed.
     */
    public function needs_update() {
        $current_version = get_option( self::DB_VERSION_OPTION, '0' );
        return version_compare( $current_version, self::DB_VERSION, '<' );
    }

    /**
     * Run database migrations
     *
     * Handles schema changes between versions.
     */
    public function run_migrations() {
        $current_version = get_option( self::DB_VERSION_OPTION, '0' );

        // v1.3.0: Add request_method column to activity log
        if ( version_compare( $current_version, '1.3.0', '<' ) ) {
            $table = $this->get_activity_log_table();

            // Check if column already exists
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $column_exists = $this->wpdb->get_results(
                $this->wpdb->prepare(
                    'SHOW COLUMNS FROM %i LIKE %s',
                    $table,
                    'request_method'
                )
            );

            if ( empty( $column_exists ) ) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
                $this->wpdb->query(
                    $this->wpdb->prepare(
                        'ALTER TABLE %i ADD COLUMN request_method varchar(10) DEFAULT %s AFTER user_agent',
                        $table,
                        ''
                    )
                );

                // Add index
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
                $this->wpdb->query(
                    $this->wpdb->prepare(
                        'ALTER TABLE %i ADD KEY request_method (request_method)',
                        $table
                    )
                );
            }
        }

        // Update stored version
        update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
    }

    /**
     * Drop all plugin tables
     *
     * @return bool
     */
    public function drop_tables() {
        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange
        $tables = array(
            $this->get_activity_log_table(),
            $this->get_login_attempts_table(),
            $this->get_file_integrity_table(),
            $this->get_2fa_codes_table(),
            $this->get_2fa_devices_table(),
            $this->get_2fa_notifications_table(),
            $this->get_totp_table(),
        );

        foreach ( $tables as $table ) {
            $this->wpdb->query( $this->wpdb->prepare( 'DROP TABLE IF EXISTS %i', $table ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, PluginCheck.Security.DirectDB.UnescapedDBParameter
        }

        delete_option( self::DB_VERSION_OPTION );

        return true;
        // phpcs:enable
    }

    // =========================================================================
    // ACTIVITY LOG METHODS
    // =========================================================================

    /**
     * Check if activity log table exists
     *
     * @return bool
     */
    private function activity_log_table_exists() {
        $table = $this->get_activity_log_table();
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $result = $this->wpdb->get_var( $this->wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
        return $result === $table;
    }

    /**
     * Insert activity log entry
     *
     * @param array $data Log data.
     * @return int|false Insert ID or false on failure.
     */
    public function insert_activity_log( $data ) {
        // Verify table exists before inserting (prevents errors in Plugin Check environment)
        if ( ! $this->activity_log_table_exists() ) {
            return false;
        }

        $defaults = array(
            'event_type'     => 'general',
            'event_action'   => '',
            'event_message'  => '',
            'user_id'        => get_current_user_id(),
            'user_login'     => '',
            'ip_address'     => $this->get_client_ip(),
            'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
            'request_method' => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
            'object_type'    => '',
            'object_id'      => 0,
            'object_name'    => '',
            'severity'       => 'info',
            'extra_data'     => '',
            'created_at'     => current_time( 'mysql' ),
        );

        $data = wp_parse_args( $data, $defaults );

        // Get username if not provided
        if ( empty( $data['user_login'] ) && $data['user_id'] > 0 ) {
            $user = get_userdata( $data['user_id'] );
            if ( $user ) {
                $data['user_login'] = $user->user_login;
            }
        }

        // Serialize extra data if array
        if ( is_array( $data['extra_data'] ) ) {
            $data['extra_data'] = wp_json_encode( $data['extra_data'] );
        }

        // Sanitize data
        $data = array(
            'event_type'     => sanitize_key( $data['event_type'] ),
            'event_action'   => sanitize_text_field( $data['event_action'] ),
            'event_message'  => sanitize_textarea_field( $data['event_message'] ),
            'user_id'        => absint( $data['user_id'] ),
            'user_login'     => sanitize_user( $data['user_login'] ),
            'ip_address'     => sanitize_text_field( $data['ip_address'] ),
            'user_agent'     => sanitize_textarea_field( substr( $data['user_agent'], 0, 500 ) ),
            'request_method' => sanitize_text_field( strtoupper( substr( $data['request_method'], 0, 10 ) ) ),
            'object_type'    => sanitize_key( $data['object_type'] ),
            'object_id'      => absint( $data['object_id'] ),
            'object_name'    => sanitize_text_field( $data['object_name'] ),
            'severity'       => sanitize_key( $data['severity'] ),
            'extra_data'     => $data['extra_data'],
            'created_at'     => $data['created_at'],
        );

        $result = $this->wpdb->insert(
            $this->get_activity_log_table(),
            $data,
            array( '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s' )
        );

        return $result ? $this->wpdb->insert_id : false;
    }

    /**
     * Get activity log entries
     *
     * @param array $args Query arguments.
     * @return array
     */
    public function get_activity_logs( $args = array() ) {
        $defaults = array(
            'per_page'       => 50,
            'page'           => 1,
            'event_type'     => '',
            'severity'       => '',
            'request_method' => '',
            'search'         => '',
            'date_from'      => '',
            'date_to'        => '',
        );

        $args = wp_parse_args( $args, $defaults );
        $table = $this->get_activity_log_table();

        // Sanitize inputs
        $event_type     = sanitize_key( $args['event_type'] );
        $severity       = sanitize_key( $args['severity'] );
        $request_method = sanitize_text_field( $args['request_method'] );
        $search         = sanitize_text_field( $args['search'] );
        
        // Use default dates for empty values (MySQL requires valid DATETIME)
        $date_from = ! empty( $args['date_from'] ) ? sanitize_text_field( $args['date_from'] ) : '1970-01-01 00:00:00';
        $date_to   = ! empty( $args['date_to'] ) ? sanitize_text_field( $args['date_to'] ) : '9999-12-31 23:59:59';

        // Calculate pagination
        $per_page = absint( $args['per_page'] );
        $offset   = ( absint( $args['page'] ) - 1 ) * $per_page;

        if ( ! empty( $search ) ) {
            $like = '%' . $this->wpdb->esc_like( $search ) . '%';
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $results = $this->wpdb->get_results( $this->wpdb->prepare( "SELECT * FROM %i WHERE (event_type = %s OR %s = '') AND (severity = %s OR %s = '') AND (request_method = %s OR %s = '') AND created_at >= %s AND created_at <= %s AND (event_message LIKE %s OR user_login LIKE %s OR ip_address LIKE %s OR user_agent LIKE %s OR object_name LIKE %s OR extra_data LIKE %s) ORDER BY created_at DESC LIMIT %d OFFSET %d", $table, $event_type, $event_type, $severity, $severity, $request_method, $request_method, $date_from, $date_to, $like, $like, $like, $like, $like, $like, $per_page, $offset ) );
        } else {
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $results = $this->wpdb->get_results( $this->wpdb->prepare( "SELECT * FROM %i WHERE (event_type = %s OR %s = '') AND (severity = %s OR %s = '') AND (request_method = %s OR %s = '') AND created_at >= %s AND created_at <= %s ORDER BY created_at DESC LIMIT %d OFFSET %d", $table, $event_type, $event_type, $severity, $severity, $request_method, $request_method, $date_from, $date_to, $per_page, $offset ) );
        }

        return $results ? $results : array();
    }

    /**
     * Get total count of activity logs
     *
     * @param array $args Query arguments (same as get_activity_logs).
     * @return int
     */
    public function get_activity_logs_count( $args = array() ) {
        $table = $this->get_activity_log_table();

        // Sanitize inputs
        $event_type     = isset( $args['event_type'] ) ? sanitize_key( $args['event_type'] ) : '';
        $severity       = isset( $args['severity'] ) ? sanitize_key( $args['severity'] ) : '';
        $request_method = isset( $args['request_method'] ) ? sanitize_text_field( $args['request_method'] ) : '';
        $search         = isset( $args['search'] ) ? sanitize_text_field( $args['search'] ) : '';
        
        // Use default dates for empty values (MySQL requires valid DATETIME)
        $date_from = ! empty( $args['date_from'] ) ? sanitize_text_field( $args['date_from'] ) : '1970-01-01 00:00:00';
        $date_to   = ! empty( $args['date_to'] ) ? sanitize_text_field( $args['date_to'] ) : '9999-12-31 23:59:59';

        if ( ! empty( $search ) ) {
            $like = '%' . $this->wpdb->esc_like( $search ) . '%';
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $count = $this->wpdb->get_var( $this->wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE (event_type = %s OR %s = '') AND (severity = %s OR %s = '') AND (request_method = %s OR %s = '') AND created_at >= %s AND created_at <= %s AND (event_message LIKE %s OR user_login LIKE %s OR ip_address LIKE %s OR user_agent LIKE %s OR object_name LIKE %s OR extra_data LIKE %s)", $table, $event_type, $event_type, $severity, $severity, $request_method, $request_method, $date_from, $date_to, $like, $like, $like, $like, $like, $like ) );
        } else {
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $count = $this->wpdb->get_var( $this->wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE (event_type = %s OR %s = '') AND (severity = %s OR %s = '') AND (request_method = %s OR %s = '') AND created_at >= %s AND created_at <= %s", $table, $event_type, $event_type, $severity, $severity, $request_method, $request_method, $date_from, $date_to ) );
        }

        return absint( $count );
    }

    /**
     * Delete old activity logs
     *
     * @param int $days Days to keep.
     * @return int Number of deleted rows.
     */
    public function cleanup_old_activity_logs( $days = 30 ) {
        $table = $this->get_activity_log_table();
        $date = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $deleted = $this->wpdb->query( $this->wpdb->prepare( 'DELETE FROM %i WHERE created_at < %s', $table, $date ) );

        return $deleted ? $deleted : 0;
    }

    /**
     * Truncate activity log table
     *
     * @return bool
     */
    public function truncate_activity_log() {
        $table = $this->get_activity_log_table();
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return false !== $this->wpdb->query( $this->wpdb->prepare( 'TRUNCATE TABLE %i', $table ) );
    }

    // =========================================================================
    // LOGIN ATTEMPTS METHODS
    // =========================================================================

    /**
     * Check if login attempts table exists
     *
     * @return bool
     */
    private function login_attempts_table_exists() {
        $table = $this->get_login_attempts_table();
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $result = $this->wpdb->get_var( $this->wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
        return $result === $table;
    }

    /**
     * Record a login attempt
     *
     * @param string $ip_address IP address.
     * @param string $username   Username attempted.
     * @param string $status     Status: 'failed', 'success', 'lockout'.
     * @return int|false
     */
    public function record_login_attempt( $ip_address, $username, $status = 'failed' ) {
        // Verify table exists before inserting
        if ( ! $this->login_attempts_table_exists() ) {
            return false;
        }

        $table = $this->get_login_attempts_table();
        $ip_address = sanitize_text_field( $ip_address );
        $username = sanitize_user( $username );
        $status = sanitize_key( $status );
        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
        $now = current_time( 'mysql' );

        // Check if record exists for this IP + username
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $existing = $this->wpdb->get_row( $this->wpdb->prepare( 'SELECT * FROM %i WHERE ip_address = %s AND username = %s', $table, $ip_address, $username ), ARRAY_A );

        if ( $existing ) {
            // Update existing record
            $data = array(
                'status'        => $status,
                'attempt_count' => $existing['attempt_count'] + 1,
                'last_attempt'  => $now,
                'user_agent'    => $user_agent,
            );

            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $this->wpdb->update(
                $table,
                $data,
                array(
                    'ip_address' => $ip_address,
                    'username'   => $username,
                ),
                array( '%s', '%d', '%s', '%s' ),
                array( '%s', '%s' )
            );

            return $existing['id'];
        } else {
            // Insert new record
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $this->wpdb->insert(
                $table,
                array(
                    'ip_address'    => $ip_address,
                    'username'      => $username,
                    'status'        => $status,
                    'user_agent'    => $user_agent,
                    'attempt_count' => 1,
                    'last_attempt'  => $now,
                    'created_at'    => $now,
                ),
                array( '%s', '%s', '%s', '%s', '%d', '%s', '%s' )
            );

            return $this->wpdb->insert_id;
        }
    }

    /**
     * Get login attempts for an IP
     *
     * @param string $ip_address IP address.
     * @param int    $minutes    Minutes to look back.
     * @return array
     */
    public function get_login_attempts( $ip_address, $minutes = 30 ) {
        $table = $this->get_login_attempts_table();
        $since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$minutes} minutes" ) );

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $results = $this->wpdb->get_results( $this->wpdb->prepare( 'SELECT * FROM %i WHERE ip_address = %s AND last_attempt >= %s ORDER BY last_attempt DESC', $table, $ip_address, $since ), ARRAY_A );

        return $results ? $results : array();
    }

    /**
     * Get failed attempt count for an IP
     *
     * @param string $ip_address IP address.
     * @param int    $minutes    Minutes to look back.
     * @return int
     */
    public function get_failed_attempt_count( $ip_address, $minutes = 30 ) {
        $table = $this->get_login_attempts_table();
        $since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$minutes} minutes" ) );

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $count = $this->wpdb->get_var( $this->wpdb->prepare( "SELECT SUM(attempt_count) FROM %i WHERE ip_address = %s AND status = 'failed' AND last_attempt >= %s", $table, $ip_address, $since ) );

        return absint( $count );
    }

    /**
     * Set lockout for an IP
     *
     * @param string $ip_address IP address.
     * @param int    $seconds    Lockout duration in seconds.
     * @return bool
     */
    public function set_lockout( $ip_address, $seconds ) {
        $table = $this->get_login_attempts_table();
        $lockout_until = gmdate( 'Y-m-d H:i:s', time() + $seconds );

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        return false !== $this->wpdb->query( $this->wpdb->prepare( "UPDATE %i SET lockout_until = %s, status = 'lockout' WHERE ip_address = %s", $table, $lockout_until, $ip_address ) );
    }

    /**
     * Check if an IP is locked out
     *
     * @param string $ip_address IP address.
     * @return array|false Lockout data or false if not locked.
     */
    public function is_locked_out( $ip_address ) {
        $table = $this->get_login_attempts_table();
        $now = current_time( 'mysql' );

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $lockout = $this->wpdb->get_row( $this->wpdb->prepare( "SELECT * FROM %i WHERE ip_address = %s AND lockout_until > %s AND status = 'lockout' ORDER BY lockout_until DESC LIMIT 1", $table, $ip_address, $now ), ARRAY_A );

        return $lockout ? $lockout : false;
    }

    /**
     * Clear lockout for an IP
     *
     * @param string $ip_address IP address.
     * @return bool
     */
    public function clear_lockout( $ip_address ) {
        $table = $this->get_login_attempts_table();

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        return false !== $this->wpdb->query( $this->wpdb->prepare( "UPDATE %i SET lockout_until = NULL, status = 'cleared', attempt_count = 0 WHERE ip_address = %s", $table, $ip_address ) );
    }

    /**
     * Get all active lockouts
     *
     * @return array List of locked IPs with their data.
     */
    public function get_active_lockouts() {
        $table = $this->get_login_attempts_table();
        $now = current_time( 'mysql' );

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $lockouts = $this->wpdb->get_results( $this->wpdb->prepare( "SELECT ip_address, username, attempt_count as attempts, lockout_until as locked_until, last_attempt FROM %i WHERE lockout_until > %s AND status = 'lockout' ORDER BY lockout_until DESC", $table, $now ) );

        return $lockouts ? $lockouts : array();
    }

    /**
     * Clear all lockouts
     *
     * @return bool
     */
    public function clear_all_lockouts() {
        $table = $this->get_login_attempts_table();

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        return false !== $this->wpdb->query( $this->wpdb->prepare( "UPDATE %i SET lockout_until = NULL, status = 'cleared', attempt_count = 0 WHERE status = 'lockout'", $table ) );
    }

    /**
     * Reset login attempts for an IP
     *
     * @param string $ip_address IP address.
     * @return bool
     */
    public function reset_login_attempts( $ip_address ) {
        $table = $this->get_login_attempts_table();

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return false !== $this->wpdb->delete(
            $table,
            array( 'ip_address' => $ip_address ),
            array( '%s' )
        );
    }

    /**
     * Clean up old login attempts
     *
     * @param int $hours Hours to keep.
     * @return int Number of deleted rows.
     */
    public function cleanup_old_login_attempts( $hours = 24 ) {
        $table = $this->get_login_attempts_table();
        $date = gmdate( 'Y-m-d H:i:s', strtotime( "-{$hours} hours" ) );

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $deleted = $this->wpdb->query( $this->wpdb->prepare( 'DELETE FROM %i WHERE last_attempt < %s AND (lockout_until IS NULL OR lockout_until < %s)', $table, $date, current_time( 'mysql' ) ) );

        return $deleted ? $deleted : 0;
    }

    /**
     * Get all currently locked out IPs
     *
     * @return array
     */
    public function get_locked_out_ips() {
        $table = $this->get_login_attempts_table();
        $now = current_time( 'mysql' );

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $results = $this->wpdb->get_results( $this->wpdb->prepare( "SELECT DISTINCT ip_address, lockout_until, attempt_count, last_attempt FROM %i WHERE lockout_until > %s AND status = 'lockout' ORDER BY lockout_until DESC", $table, $now ), ARRAY_A );

        return $results ? $results : array();
    }

    // =========================================================================
    // FILE INTEGRITY METHODS
    // =========================================================================

    /**
     * Check if file integrity table exists
     *
     * @return bool
     */
    private function file_integrity_table_exists() {
        $table = $this->get_file_integrity_table();
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $result = $this->wpdb->get_var( $this->wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
        return $result === $table;
    }

    /**
     * Store file hash
     *
     * @param string $file_path File path.
     * @param string $hash      File hash.
     * @param int    $size      File size.
     * @param string $type      File type: 'core', 'plugin', 'theme'.
     * @return int|false
     */
    public function store_file_hash( $file_path, $hash, $size = 0, $type = 'core' ) {
        // Verify table exists before inserting
        if ( ! $this->file_integrity_table_exists() ) {
            return false;
        }

        $table = $this->get_file_integrity_table();
        $now = current_time( 'mysql' );

        // Check if exists
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $existing = $this->wpdb->get_var( $this->wpdb->prepare( 'SELECT id FROM %i WHERE file_path = %s', $table, $file_path ) );

        if ( $existing ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $this->wpdb->update(
                $table,
                array(
                    'file_hash'    => $hash,
                    'file_size'    => $size,
                    'file_type'    => $type,
                    'status'       => 'ok',
                    'last_checked' => $now,
                ),
                array( 'id' => $existing ),
                array( '%s', '%d', '%s', '%s', '%s' ),
                array( '%d' )
            );
            return $existing;
        }

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $this->wpdb->insert(
            $table,
            array(
                'file_path'    => $file_path,
                'file_hash'    => $hash,
                'file_size'    => $size,
                'file_type'    => $type,
                'status'       => 'ok',
                'last_checked' => $now,
            ),
            array( '%s', '%s', '%d', '%s', '%s', '%s' )
        );

        return $this->wpdb->insert_id;
    }

    /**
     * Get stored file hash
     *
     * @param string $file_path File path.
     * @return array|null
     */
    public function get_file_hash( $file_path ) {
        $table = $this->get_file_integrity_table();

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $result = $this->wpdb->get_row( $this->wpdb->prepare( 'SELECT * FROM %i WHERE file_path = %s', $table, $file_path ), ARRAY_A );

        return $result;
    }

    /**
     * Update file status
     *
     * @param string $file_path File path.
     * @param string $status    Status: 'ok', 'modified', 'deleted', 'new'.
     * @param string $new_hash  New hash if modified.
     * @return bool
     */
    public function update_file_status( $file_path, $status, $new_hash = '' ) {
        $table = $this->get_file_integrity_table();

        $data = array(
            'status'       => $status,
            'last_checked' => current_time( 'mysql' ),
        );

        if ( ! empty( $new_hash ) ) {
            $data['file_hash'] = $new_hash;
        }

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return false !== $this->wpdb->update(
            $table,
            $data,
            array( 'file_path' => $file_path ),
            array_fill( 0, count( $data ), '%s' ),
            array( '%s' )
        );
    }

    /**
     * Get files by status
     *
     * @param string $status File status.
     * @param string $type   File type (optional).
     * @return array
     */
    public function get_files_by_status( $status, $type = '' ) {
        $table  = $this->get_file_integrity_table();
        $status = sanitize_key( $status );
        $type   = sanitize_key( $type );

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $results = $this->wpdb->get_results( $this->wpdb->prepare( "SELECT * FROM %i WHERE status = %s AND (file_type = %s OR %s = '') ORDER BY file_path ASC", $table, $status, $type, $type ), ARRAY_A );

        return $results ? $results : array();
    }

    /**
     * Clear all file hashes
     *
     * @param string $type Optional file type to clear.
     * @return bool
     */
    public function clear_file_hashes( $type = '' ) {
        $table = $this->get_file_integrity_table();

        if ( ! empty( $type ) ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            return false !== $this->wpdb->delete(
                $table,
                array( 'file_type' => $type ),
                array( '%s' )
            );
        }

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return false !== $this->wpdb->query( $this->wpdb->prepare( 'TRUNCATE TABLE %i', $table ) );
    }

    // =========================================================================
    // UTILITY METHODS
    // =========================================================================

    /**
     * Get client IP address
     *
     * Delegates to the shared resolver, which only trusts REMOTE_ADDR unless a
     * proxy header has been explicitly declared in settings.
     *
     * @return string
     */
    public function get_client_ip() {
        return Vigilante_IP_Utils::get_client_ip();
    }

    /**
     * Get database statistics
     *
     * @return array
     */
    public function get_stats() {
        $stats = array(
            'activity_log_count'   => $this->get_activity_logs_count(),
            'locked_out_ips_count' => count( $this->get_locked_out_ips() ),
            'file_integrity_count' => 0,
            'modified_files_count' => 0,
        );

        $table = $this->get_file_integrity_table();
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $stats['file_integrity_count'] = absint( $this->wpdb->get_var( $this->wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table ) ) );
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $stats['modified_files_count'] = absint( $this->wpdb->get_var( $this->wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status != 'ok'", $table ) ) );

        return $stats;
    }

    // =========================================================================
    // TWO-FACTOR AUTHENTICATION METHODS
    // =========================================================================

    /**
     * Store 2FA verification code
     *
     * @param int    $user_id    User ID.
     * @param string $code       Verification code.
     * @param string $expires_at Expiration datetime.
     * @return int|false Insert ID or false on failure.
     */
    public function store_2fa_code( $user_id, $code, $expires_at ) {
        $table = $this->get_2fa_codes_table();

        // Delete any existing codes for this user
        $this->delete_2fa_code( $user_id );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $result = $this->wpdb->insert(
            $table,
            array(
                'user_id'    => $user_id,
                'code'       => $code,
                'expires_at' => $expires_at,
                'attempts'   => 0,
                'used'       => 0,
            ),
            array( '%d', '%s', '%s', '%d', '%d' )
        );

        return $result ? $this->wpdb->insert_id : false;
    }

    /**
     * Get 2FA code for user
     *
     * @param int $user_id User ID.
     * @return array|null Code data or null if not found.
     */
    public function get_2fa_code( $user_id ) {
        $table = $this->get_2fa_codes_table();

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return $this->wpdb->get_row(
            $this->wpdb->prepare(
                'SELECT * FROM %i WHERE user_id = %d AND used = 0 ORDER BY created_at DESC LIMIT 1',
                $table,
                $user_id
            ),
            ARRAY_A
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared
    }

    /**
     * Increment 2FA code attempts
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function increment_2fa_attempts( $user_id ) {
        $table = $this->get_2fa_codes_table();

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return false !== $this->wpdb->query(
            $this->wpdb->prepare(
                'UPDATE %i SET attempts = attempts + 1 WHERE user_id = %d AND used = 0',
                $table,
                $user_id
            )
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared
    }

    /**
     * Mark 2FA code as used
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function mark_2fa_code_used( $user_id ) {
        $table = $this->get_2fa_codes_table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return false !== $this->wpdb->update(
            $table,
            array( 'used' => 1 ),
            array( 'user_id' => $user_id ),
            array( '%d' ),
            array( '%d' )
        );
    }

    /**
     * Delete 2FA code for user
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function delete_2fa_code( $user_id ) {
        $table = $this->get_2fa_codes_table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return false !== $this->wpdb->delete(
            $table,
            array( 'user_id' => $user_id ),
            array( '%d' )
        );
    }

    /**
     * Cleanup expired 2FA codes
     *
     * @return int Number of deleted rows.
     */
    public function cleanup_expired_2fa_codes() {
        $table = $this->get_2fa_codes_table();
        $now   = current_time( 'mysql', true );

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $this->wpdb->query(
            $this->wpdb->prepare(
                'DELETE FROM %i WHERE expires_at < %s OR used = 1',
                $table,
                $now
            )
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared

        return $this->wpdb->rows_affected;
    }

    /**
     * Trust a device for 2FA
     *
     * @param int    $user_id     User ID.
     * @param string $device_hash Device hash.
     * @param string $user_agent  User agent.
     * @param string $expires_at  Expiration datetime.
     * @return int|false Insert ID or false on failure.
     */
    public function trust_device( $user_id, $device_hash, $user_agent, $expires_at ) {
        $table = $this->get_2fa_devices_table();

        // Delete existing entry for this device
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $this->wpdb->delete(
            $table,
            array(
                'user_id'     => $user_id,
                'device_hash' => $device_hash,
            ),
            array( '%d', '%s' )
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $result = $this->wpdb->insert(
            $table,
            array(
                'user_id'     => $user_id,
                'device_hash' => $device_hash,
                'user_agent'  => $user_agent,
                'expires_at'  => $expires_at,
            ),
            array( '%d', '%s', '%s', '%s' )
        );

        return $result ? $this->wpdb->insert_id : false;
    }

    /**
     * Check if device is trusted
     *
     * @param int    $user_id     User ID.
     * @param string $device_hash Device hash.
     * @return bool
     */
    public function is_device_trusted( $user_id, $device_hash ) {
        $table = $this->get_2fa_devices_table();
        $now   = current_time( 'mysql', true );

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $result = $this->wpdb->get_var(
            $this->wpdb->prepare(
                'SELECT id FROM %i WHERE user_id = %d AND device_hash = %s AND expires_at > %s LIMIT 1',
                $table,
                $user_id,
                $device_hash,
                $now
            )
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared

        return ! empty( $result );
    }

    /**
     * Get trusted devices for user
     *
     * @param int $user_id User ID.
     * @return array
     */
    public function get_trusted_devices( $user_id ) {
        $table = $this->get_2fa_devices_table();
        $now   = current_time( 'mysql', true );

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $results = $this->wpdb->get_results(
            $this->wpdb->prepare(
                'SELECT * FROM %i WHERE user_id = %d AND expires_at > %s ORDER BY created_at DESC',
                $table,
                $user_id,
                $now
            ),
            ARRAY_A
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared

        return $results ? $results : array();
    }

    /**
     * Revoke all trusted devices for user
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function revoke_trusted_devices( $user_id ) {
        $table = $this->get_2fa_devices_table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return false !== $this->wpdb->delete(
            $table,
            array( 'user_id' => $user_id ),
            array( '%d' )
        );
    }

    /**
     * Cleanup expired trusted devices
     *
     * @return int Number of deleted rows.
     */
    public function cleanup_expired_trusted_devices() {
        $table = $this->get_2fa_devices_table();
        $now   = current_time( 'mysql', true );

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $this->wpdb->query(
            $this->wpdb->prepare(
                'DELETE FROM %i WHERE expires_at < %s',
                $table,
                $now
            )
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared

        return $this->wpdb->rows_affected;
    }

    /**
     * Mark user as notified about 2FA
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function mark_2fa_notified( $user_id ) {
        $table = $this->get_2fa_notifications_table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $result = $this->wpdb->replace(
            $table,
            array(
                'user_id' => $user_id,
                'sent_at' => current_time( 'mysql', true ),
            ),
            array( '%d', '%s' )
        );

        return false !== $result;
    }

    /**
     * Check if user was notified about 2FA
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function user_was_2fa_notified( $user_id ) {
        $table = $this->get_2fa_notifications_table();

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $result = $this->wpdb->get_var(
            $this->wpdb->prepare(
                'SELECT id FROM %i WHERE user_id = %d LIMIT 1',
                $table,
                $user_id
            )
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared

        return ! empty( $result );
    }

    /**
     * Clear 2FA notification records
     *
     * @return bool
     */
    public function clear_2fa_notifications() {
        $table = $this->get_2fa_notifications_table();

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return false !== $this->wpdb->query(
            $this->wpdb->prepare( 'TRUNCATE TABLE %i', $table )
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared
    }

    // =========================================================================
    // TOTP METHODS
    // =========================================================================

    /**
     * Get TOTP data for a user
     *
     * @param int $user_id User ID.
     * @return array|null
     */
    public function get_totp_data( $user_id ) {
        $table = $this->get_totp_table();

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return $this->wpdb->get_row(
            $this->wpdb->prepare(
                'SELECT * FROM %i WHERE user_id = %d LIMIT 1',
                $table,
                $user_id
            ),
            ARRAY_A
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared
    }

    /**
     * Create TOTP placeholder row (grace period tracking)
     *
     * @param int    $user_id        User ID.
     * @param string $grace_expires  Grace period expiry datetime.
     * @return bool
     */
    public function create_totp_placeholder( $user_id, $grace_expires ) {
        $table = $this->get_totp_table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        return false !== $this->wpdb->replace(
            $table,
            array(
                'user_id'              => $user_id,
                'secret'               => '',
                'is_configured'        => 0,
                'grace_period_expires' => $grace_expires,
            ),
            array( '%d', '%s', '%d', '%s' )
        );
    }

    /**
     * Save TOTP data after successful setup
     *
     * @param int    $user_id   User ID.
     * @param string $encrypted Encrypted secret.
     * @return bool
     */
    public function save_totp_data( $user_id, $encrypted ) {
        $table = $this->get_totp_table();
        $now   = current_time( 'mysql', true );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        return false !== $this->wpdb->replace(
            $table,
            array(
                'user_id'              => $user_id,
                'secret'               => $encrypted,
                'is_configured'        => 1,
                'configured_at'        => $now,
                'grace_period_expires' => null,
            ),
            array( '%d', '%s', '%d', '%s', '%s' )
        );
    }

    /**
     * Store backup codes for a user
     *
     * @param int    $user_id      User ID.
     * @param string $hashed_codes JSON-encoded hashed codes.
     * @return bool
     */
    public function store_totp_backup_codes( $user_id, $hashed_codes ) {
        $table = $this->get_totp_table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return false !== $this->wpdb->update(
            $table,
            array( 'backup_codes' => $hashed_codes ),
            array( 'user_id' => $user_id ),
            array( '%s' ),
            array( '%d' )
        );
    }

    /**
     * Update TOTP last used timestamp
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function update_totp_last_used( $user_id ) {
        $table = $this->get_totp_table();
        $now   = current_time( 'mysql', true );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return false !== $this->wpdb->update(
            $table,
            array( 'last_used_at' => $now ),
            array( 'user_id' => $user_id ),
            array( '%s' ),
            array( '%d' )
        );
    }

    /**
     * Reset TOTP data for a user (admin reset)
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function reset_totp_data( $user_id ) {
        $table = $this->get_totp_table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return false !== $this->wpdb->delete(
            $table,
            array( 'user_id' => $user_id ),
            array( '%d' )
        );
    }

    /**
     * Get all users with TOTP configured
     *
     * @return array
     */
    public function get_totp_configured_users() {
        $table = $this->get_totp_table();

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $results = $this->wpdb->get_results(
            $this->wpdb->prepare(
                'SELECT user_id, configured_at, last_used_at FROM %i WHERE is_configured = 1 ORDER BY configured_at DESC',
                $table
            ),
            ARRAY_A
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared

        return $results ? $results : array();
    }

    /**
     * Search users with TOTP configured by name or email
     *
     * @param string $query   Search query.
     * @param int    $limit   Max results.
     * @return array
     */
    public function search_totp_users( $query, $limit = 10 ) {
        $table = $this->get_totp_table();

        // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- %i placeholder requires WP 6.2+.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $results = $this->wpdb->get_results(
            $this->wpdb->prepare(
                "SELECT t.user_id, t.configured_at, t.last_used_at, u.display_name, u.user_email
                FROM %i AS t
                INNER JOIN %i AS u ON t.user_id = u.ID
                WHERE t.is_configured = 1
                AND (u.display_name LIKE %s OR u.user_email LIKE %s OR u.user_login LIKE %s)
                ORDER BY u.display_name ASC
                LIMIT %d",
                $table,
                $this->wpdb->users,
                '%' . $this->wpdb->esc_like( $query ) . '%',
                '%' . $this->wpdb->esc_like( $query ) . '%',
                '%' . $this->wpdb->esc_like( $query ) . '%',
                $limit
            ),
            ARRAY_A
        );
        // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared

        return $results ? $results : array();
    }
}