<?php
/**
 * Admin AJAX Trait
 *
 * AJAX handlers and helper methods for Vigilante_Admin class
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Trait for AJAX handlers
 * To be used in Vigilante_Admin class
 */
trait Vigilante_Admin_Ajax {

    /**
     * AJAX: Apply preset
     */
    // ajax_apply_preset() is defined in class-admin.php directly (not in this trait)

    /**
     * AJAX: Clear lockouts
     */
    public function ajax_clear_lockouts() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';

        if ( ! empty( $ip ) ) {
            // Clear specific IP
            $result = $this->database->clear_lockout( $ip );
        } else {
            // Clear all
            $result = $this->database->clear_all_lockouts();
        }

        if ( $result ) {
            wp_send_json_success( __( 'Lockouts cleared.', 'vigilante' ) );
        } else {
            wp_send_json_error( __( 'Failed to clear lockouts.', 'vigilante' ) );
        }
    }

    /**
     * AJAX: Clear logs
     */
    public function ajax_clear_logs() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $result = $this->activity_log->clear_all_logs();

        if ( $result ) {
            wp_send_json_success( __( 'Logs cleared.', 'vigilante' ) );
        } else {
            wp_send_json_error( __( 'Failed to clear logs.', 'vigilante' ) );
        }
    }

    /**
     * AJAX: Run file integrity scan
     */
    public function ajax_run_scan() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        try {
            if ( ! class_exists( 'Vigilante_File_Integrity' ) ) {
                require_once VIGILANTE_PLUGIN_DIR . 'includes/class-file-integrity.php';
            }

            if ( ! $this->settings ) {
                wp_send_json_error( 'Settings not initialized' );
            }

            $activity_log = isset( $this->activity_log ) ? $this->activity_log : null;
            $database = isset( $this->database ) ? $this->database : null;

            $file_integrity = new Vigilante_File_Integrity( $this->settings, $database, $activity_log );
            $results = $file_integrity->run_scan();

            // Save results for display
            update_option( 'vigilante_last_integrity_scan', time() );
            update_option( 'vigilante_last_integrity_results', $results );

            wp_send_json_success( array(
                'message' => __( 'Scan completed.', 'vigilante' ),
                'results' => $results,
            ) );
        } catch ( Exception $e ) {
            wp_send_json_error( 'Exception: ' . $e->getMessage() );
        } catch ( Error $e ) {
            wp_send_json_error( 'PHP Error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine() );
        }
    }

    /**
     * AJAX: Approve a critical config file modification
     *
     * Updates the baseline hash for a single critical file (wp-config.php
     * or .htaccess), accepting the current content as legitimate.
     */
    public function ajax_approve_critical_file() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        // The request carries an opaque key instead of the file name: hosting
        // WAFs (e.g. ModSecurity with OWASP CRS rule 930130) reject any POST
        // whose arguments contain the literal "wp-config.php", which made
        // this Approve button fail with a generic AJAX error behind such
        // firewalls. The server-side map below is the real security gate.
        $file_keys = array(
            'cfg' => 'wp-config.php',
            'hta' => '.htaccess',
        );
        $file_key = isset( $_POST['file_key'] ) ? sanitize_key( $_POST['file_key'] ) : '';
        $file     = isset( $file_keys[ $file_key ] ) ? $file_keys[ $file_key ] : '';
        $allowed  = array( 'wp-config.php', '.htaccess' );
        if ( ! in_array( $file, $allowed, true ) ) {
            wp_send_json_error( __( 'Invalid file.', 'vigilante' ) );
        }

        if ( ! class_exists( 'Vigilante_File_Integrity' ) ) {
            require_once VIGILANTE_PLUGIN_DIR . 'includes/class-file-integrity.php';
        }

        $activity_log = isset( $this->activity_log ) ? $this->activity_log : null;
        $database     = isset( $this->database ) ? $this->database : null;

        $fi     = new Vigilante_File_Integrity( $this->settings, $database, $activity_log );
        $result = $fi->update_critical_file_baseline( $file );

        if ( $result ) {
            // Log the approval in the activity log
            if ( $activity_log ) {
                $activity_log->log(
                    'file',
                    'critical_file_approved',
                    sprintf(
                        /* translators: %s: file name */
                        __( 'Critical config file modification approved: %s', 'vigilante' ),
                        $file
                    ),
                    array( 'file' => $file ),
                    'info'
                );
            }

            // Update stored scan results to remove the approved file
            $last_results = get_option( 'vigilante_last_integrity_results', array() );
            if ( ! empty( $last_results['modified'] ) ) {
                $last_results['modified'] = array_values(
                    array_filter(
                        $last_results['modified'],
                        function ( $item ) use ( $file ) {
                            return ! ( is_array( $item ) && isset( $item['file'] ) && $item['file'] === $file );
                        }
                    )
                );
                update_option( 'vigilante_last_integrity_results', $last_results );
            }

            wp_send_json_success( array(
                'message' => __( 'Change approved. Next scan will use the current state as baseline.', 'vigilante' ),
                'file'    => $file,
            ) );
        } else {
            wp_send_json_error( __( 'Failed to update baseline.', 'vigilante' ) );
        }
    }

    /**
     * AJAX: Get activity logs
     */
    public function ajax_get_logs() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $per_page = isset( $_POST['per_page'] ) ? absint( $_POST['per_page'] ) : 50;
        // Limit max to prevent memory issues
        $per_page = min( $per_page, 10000 );

        $args = array(
            'per_page' => $per_page,
            'page'     => isset( $_POST['page'] ) ? absint( $_POST['page'] ) : 1,
        );

        if ( ! empty( $_POST['type'] ) ) {
            $args['event_type'] = sanitize_key( $_POST['type'] );
        }

        if ( ! empty( $_POST['severity'] ) ) {
            $args['severity'] = sanitize_key( $_POST['severity'] );
        }

        if ( ! empty( $_POST['request_method'] ) ) {
            $args['request_method'] = sanitize_text_field( wp_unslash( $_POST['request_method'] ) );
        }

        if ( ! empty( $_POST['search'] ) ) {
            $args['search'] = sanitize_text_field( wp_unslash( $_POST['search'] ) );
        }

        if ( ! $this->activity_log ) {
            wp_send_json_error( 'Activity log not initialized' );
        }

        $logs = $this->activity_log->get_logs( $args );
        $total = $this->activity_log->get_logs_count( $args );

        // Attach firewall list flags so the popup can show "In whitelist"/"In blacklist"
        // states when users paginate or filter without reloading the page.
        $firewall_options = $this->settings->get_section( 'firewall' );
        $ip_whitelist     = $firewall_options['ip_whitelist'] ?? array();
        $ip_blacklist     = $firewall_options['ip_blacklist'] ?? array();
        $ua_whitelist     = $firewall_options['ua_whitelist'] ?? array();
        $ua_blacklist     = $firewall_options['ua_blacklist'] ?? array();

        foreach ( $logs as $log ) {
            $ip_val = (string) ( $log->ip_address ?? '' );
            $ua_val = (string) ( $log->user_agent ?? '' );
            $log->is_ip_whitelisted = ( '' !== $ip_val && in_array( $ip_val, $ip_whitelist, true ) );
            $log->is_ip_blacklisted = ( '' !== $ip_val && in_array( $ip_val, $ip_blacklist, true ) );
            $log->is_ua_whitelisted = ( '' !== $ua_val && in_array( $ua_val, $ua_whitelist, true ) );
            $log->is_ua_blacklisted = ( '' !== $ua_val && in_array( $ua_val, $ua_blacklist, true ) );
            $log->request_uri       = Vigilante_Activity_Log::extract_request_uri( $log->extra_data ?? '' );
        }

        wp_send_json_success( array(
            'logs'  => $logs,
            'total' => $total,
        ) );
    }

    /**
     * AJAX: Add IP or User-Agent to firewall whitelist/blacklist
     */
    public function ajax_add_to_firewall_list() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $value     = isset( $_POST['value'] ) ? sanitize_text_field( wp_unslash( $_POST['value'] ) ) : '';
        $list_type = isset( $_POST['list_type'] ) ? sanitize_key( $_POST['list_type'] ) : '';
        $item_type = isset( $_POST['item_type'] ) ? sanitize_key( $_POST['item_type'] ) : '';

        if ( empty( $value ) || empty( $list_type ) || empty( $item_type ) ) {
            wp_send_json_error( __( 'Missing parameters.', 'vigilante' ) );
        }

        // Validate list_type and item_type
        $valid_lists = array( 'whitelist', 'blacklist' );
        $valid_items = array( 'ip', 'ua' );

        if ( ! in_array( $list_type, $valid_lists, true ) || ! in_array( $item_type, $valid_items, true ) ) {
            wp_send_json_error( __( 'Invalid parameters.', 'vigilante' ) );
        }

        // Validate IP if item_type is ip
        if ( 'ip' === $item_type && ! filter_var( $value, FILTER_VALIDATE_IP ) ) {
            wp_send_json_error( __( 'Invalid IP address.', 'vigilante' ) );
        }

        $option_key = $item_type . '_' . $list_type; // ip_whitelist, ip_blacklist, ua_whitelist, ua_blacklist
        $options    = $this->settings->get_section( 'firewall' );
        $list       = isset( $options[ $option_key ] ) ? (array) $options[ $option_key ] : array();

        // Check if already in list
        if ( in_array( $value, $list, true ) ) {
            wp_send_json_error(
                sprintf(
                    /* translators: %s: the value being added */
                    __( '%s is already in this list.', 'vigilante' ),
                    $value
                )
            );
        }

        // Add to list
        $list[] = $value;

        // Check opposite list and remove if present
        $opposite_type = ( 'whitelist' === $list_type ) ? 'blacklist' : 'whitelist';
        $opposite_key  = $item_type . '_' . $opposite_type;
        $removed_from_opposite = false;

        // Save
        $all_options = get_option( Vigilante_Settings::OPTION_NAME, array() );
        if ( ! isset( $all_options['firewall'] ) ) {
            $all_options['firewall'] = array();
        }
        $all_options['firewall'][ $option_key ] = $list;

        // Remove from opposite list if found
        if ( ! empty( $all_options['firewall'][ $opposite_key ] ) && is_array( $all_options['firewall'][ $opposite_key ] ) ) {
            $opposite_list = $all_options['firewall'][ $opposite_key ];
            $filtered = array_values( array_filter( $opposite_list, function( $item ) use ( $value ) {
                return $item !== $value;
            } ) );

            if ( count( $filtered ) < count( $opposite_list ) ) {
                $all_options['firewall'][ $opposite_key ] = $filtered;
                $removed_from_opposite = true;
            }
        }

        wp_cache_delete( Vigilante_Settings::OPTION_NAME, 'options' );
        update_option( Vigilante_Settings::OPTION_NAME, $all_options );
        $this->settings->clear_cache();

        // Whitelist entries feed the .htaccess exception conditions (Server
        // Protection), so the block must be rewritten with the updated list.
        // Saving from the Firewall tab does this via apply_section_changes();
        // this handler writes the option directly, so it regenerates here.
        if ( 'whitelist' === $list_type ) {
            $fresh_settings = new Vigilante_Settings();
            $sh             = $fresh_settings->get_section( 'security_headers' );

            $needs_htaccess_block = ! empty( $all_options['modules']['firewall'] )
                || ! empty( $sh['hide_server_signature'] )
                || ! empty( $sh['remove_fingerprinting_headers'] );

            if ( $needs_htaccess_block ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-protection.php';
                $htaccess = new Vigilante_Htaccess_Protection( $fresh_settings );
                $htaccess->apply_rules();
            }
        }

        $list_label = ( 'whitelist' === $list_type )
            ? __( 'whitelist', 'vigilante' )
            : __( 'blacklist', 'vigilante' );

        $message = sprintf(
            /* translators: 1: the value added, 2: list name */
            __( '%1$s added to %2$s.', 'vigilante' ),
            $value,
            $list_label
        );

        if ( $removed_from_opposite ) {
            $opposite_label = ( 'whitelist' === $opposite_type )
                ? __( 'whitelist', 'vigilante' )
                : __( 'blacklist', 'vigilante' );

            $message .= ' ' . sprintf(
                /* translators: %s: opposite list name */
                __( 'Automatically removed from %s.', 'vigilante' ),
                $opposite_label
            );
        }

        wp_send_json_success( $message );
    }

    /**
     * AJAX: Test security headers
     */
    public function ajax_test_headers() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $security_headers = new Vigilante_Security_Headers( $this->settings );
        $results = $security_headers->test_headers();

        wp_send_json_success( $results );
    }

    /**
     * Sanitize activity log data
     *
     * @param array $data Data to sanitize.
     * @return array
     */
    /**
     * Sanitize IP list
     *
     * @param string|array $ips IPs as string (newline separated) or array.
     * @return array
     */
    private function sanitize_ip_list( $ips ) {
        if ( is_string( $ips ) ) {
            $ips = array_filter( array_map( 'trim', explode( "\n", $ips ) ) );
        }

        $sanitized = array();

        foreach ( (array) $ips as $ip ) {
            $ip = trim( $ip );
            // Validate IP or CIDR
            if ( filter_var( $ip, FILTER_VALIDATE_IP ) || preg_match( '/^[\d\.]+\/\d{1,2}$/', $ip ) ) {
                $sanitized[] = $ip;
            }
        }

        return $sanitized;
    }

    /**
     * Sanitize User-Agent list
     *
     * @param string|array $uas User-Agent strings (newline-separated or array).
     * @return array
     */
    private function sanitize_ua_list( $uas ) {
        if ( is_string( $uas ) ) {
            $uas = array_filter( array_map( 'trim', explode( "\n", $uas ) ) );
        }

        $sanitized = array();

        foreach ( (array) $uas as $ua ) {
            $ua = sanitize_text_field( trim( $ua ) );
            if ( ! empty( $ua ) ) {
                $sanitized[] = $ua;
            }
        }

        return array_unique( $sanitized );
    }

    /**
     * AJAX: Search users for 2FA exclusion
     */
    public function ajax_search_users_2fa() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $query   = isset( $_POST['query'] ) ? sanitize_text_field( wp_unslash( $_POST['query'] ) ) : '';
        $exclude = isset( $_POST['exclude'] ) ? array_map( 'absint', (array) $_POST['exclude'] ) : array();

        if ( strlen( $query ) < 2 ) {
            wp_send_json_error( __( 'Query too short.', 'vigilante' ) );
        }

        // Search users by login, email, or display name
        $users = get_users( array(
            'search'         => '*' . $query . '*',
            'search_columns' => array( 'user_login', 'user_email', 'display_name' ),
            'exclude'        => $exclude,
            'number'         => 10,
            'orderby'        => 'display_name',
            'order'          => 'ASC',
        ) );

        $results = array();

        foreach ( $users as $user ) {
            $results[] = array(
                'ID'           => $user->ID,
                'user_login'   => $user->user_login,
                'user_email'   => $user->user_email,
                'display_name' => $user->display_name,
                'avatar'       => get_avatar_url( $user->ID, array( 'size' => 32 ) ),
            );
        }

        wp_send_json_success( $results );
    }

    /**
     * AJAX: Send 2FA activation notification
     */
    public function ajax_send_2fa_notification() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $mode = isset( $_POST['mode'] ) ? sanitize_key( $_POST['mode'] ) : 'all';
        $only_new = 'new' === $mode;

        // Read settings to determine active 2FA method
        $login_security = $this->settings->get_section( 'login_security' );
        $two_factor     = isset( $login_security['two_factor'] ) ? $login_security['two_factor'] : array();
        $method         = isset( $two_factor['method'] ) ? $two_factor['method'] : 'email';

        if ( 'totp' === $method ) {
            // TOTP method: use TOTP class for styled activation emails
            if ( ! class_exists( 'Vigilante_Two_Factor_TOTP' ) ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-two-factor-totp.php';
            }

            $totp      = new Vigilante_Two_Factor_TOTP( $this->settings, $this->database, $this->activity_log );
            $roles     = isset( $two_factor['enforced_roles'] ) ? $two_factor['enforced_roles'] : array( 'administrator' );
            $excluded  = isset( $two_factor['excluded_users'] ) ? array_map( 'absint', $two_factor['excluded_users'] ) : array();
            $site_name = get_bloginfo( 'name' );
            $from_name = ! empty( $two_factor['email_from_name'] ) ? $two_factor['email_from_name'] : $site_name;

            if ( empty( $roles ) ) {
                $roles = array( 'administrator' );
            }

            $args = array( 'role__in' => $roles );
            if ( ! empty( $excluded ) ) {
                // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- Small excluded users list from settings.
                $args['exclude'] = $excluded;
            }
            $users = get_users( $args );

            $sent    = 0;
            $skipped = 0;
            $failed  = 0;

            foreach ( $users as $user ) {
                // Skip users who already have TOTP configured (unless sending to all)
                if ( $only_new ) {
                    $totp_data = $this->database->get_totp_data( $user->ID );
                    if ( $totp_data && ! empty( $totp_data['is_configured'] ) ) {
                        $skipped++;
                        continue;
                    }
                    if ( $this->database->user_was_2fa_notified( $user->ID ) ) {
                        $skipped++;
                        continue;
                    }
                }

                $email_sent = $totp->send_activation_email( $user, $site_name, $from_name );

                if ( $email_sent ) {
                    $this->database->mark_2fa_notified( $user->ID );
                    $sent++;
                } else {
                    $failed++;
                }
            }

            wp_send_json_success( array(
                'sent'    => $sent,
                'skipped' => $skipped,
                'failed'  => $failed,
            ) );
        } else {
            // Email method: use email 2FA class
            if ( ! class_exists( 'Vigilante_Two_Factor_Email' ) ) {
                require_once VIGILANTE_PLUGIN_DIR . 'includes/class-two-factor-email.php';
            }

            $two_factor_email = new Vigilante_Two_Factor_Email( $this->settings, $this->database, $this->activity_log );
            $result = $two_factor_email->send_activation_notifications( $only_new );

            wp_send_json_success( $result );
        }
    }

    /**
     * AJAX: Search users with TOTP configured (for admin reset)
     */
    public function ajax_search_totp_users() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $query = isset( $_POST['query'] ) ? sanitize_text_field( wp_unslash( $_POST['query'] ) ) : '';

        if ( strlen( $query ) < 2 ) {
            wp_send_json_error( __( 'Query too short.', 'vigilante' ) );
        }

        $results = $this->database->search_totp_users( $query, 10 );

        $users = array();
        foreach ( $results as $row ) {
            $avatar = get_avatar_url( $row['user_id'], array( 'size' => 32 ) );
            $users[] = array(
                'ID'            => absint( $row['user_id'] ),
                'display_name'  => $row['display_name'],
                'user_email'    => $row['user_email'],
                'configured_at' => $row['configured_at'],
                'last_used_at'  => $row['last_used_at'],
                'avatar'        => $avatar,
            );
        }

        wp_send_json_success( $users );
    }

    /**
     * AJAX: Reset TOTP for selected users (admin action)
     */
    public function ajax_reset_totp_users() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized with array_map
        $user_ids = isset( $_POST['user_ids'] ) ? array_map( 'absint', (array) wp_unslash( $_POST['user_ids'] ) ) : array();

        if ( empty( $user_ids ) ) {
            wp_send_json_error( __( 'No users selected.', 'vigilante' ) );
        }

        if ( ! class_exists( 'Vigilante_Two_Factor_TOTP' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-two-factor-totp.php';
        }

        $totp    = new Vigilante_Two_Factor_TOTP( $this->settings, $this->database, $this->activity_log );
        $count   = 0;
        $skipped = 0;

        foreach ( $user_ids as $uid ) {
            if ( $uid < 1 ) {
                continue;
            }

            // Same gate as the rest of the TOTP handlers: resetting somebody's
            // second factor is editing their account, so ask for edit_user
            // rather than for manage_options, which on a network is per site.
            if ( ! current_user_can( 'edit_user', $uid ) ) {
                $skipped++;
                continue;
            }

            $totp->reset_user_totp( $uid );
            $count++;
        }

        $message = sprintf(
            /* translators: %d: Number of users reset */
            _n( 'TOTP reset for %d user.', 'TOTP reset for %d users.', $count, 'vigilante' ),
            $count
        );

        if ( $skipped > 0 ) {
            $message .= ' ' . sprintf(
                /* translators: %d: Number of users skipped because the current user cannot edit them */
                __( '%d skipped: you cannot edit those users.', 'vigilante' ),
                $skipped
            );
        }

        wp_send_json_success( array(
            'message' => $message,
            'count'   => $count,
        ) );
    }

    /**
     * AJAX: Get TOTP setup data (secret + QR) for user profile
     */
    public function ajax_totp_get_setup() {
        check_ajax_referer( 'vigilante_totp_profile', 'nonce' );

        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;

        // Fallback to current user if user_id is 0
        if ( 0 === $user_id ) {
            $user_id = get_current_user_id();
        }

        if ( 0 === $user_id ) {
            wp_send_json_error( __( 'Invalid user.', 'vigilante' ) );
        }

        // Permission check: own profile, or a user this one may actually edit.
        // manage_options is held by every subsite administrator on a network.
        if ( get_current_user_id() !== $user_id && ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        if ( ! class_exists( 'Vigilante_Two_Factor_TOTP' ) ) {
            wp_send_json_error( __( 'TOTP module not available.', 'vigilante' ) );
        }

        $totp = new Vigilante_Two_Factor_TOTP( $this->settings, $this->database, $this->activity_log );
        $data = $totp->get_setup_data( $user_id );

        if ( empty( $data ) ) {
            wp_send_json_error( __( 'Could not generate setup data. User not found.', 'vigilante' ) );
        }

        wp_send_json_success( $data );
    }

    /**
     * AJAX: Send login URL notification to users with admin access
     */
    public function ajax_notify_login_url() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $login_options = $this->settings->get_section( 'login_security' );
        $custom_url    = ! empty( $login_options['custom_login_url'] ) ? sanitize_title( $login_options['custom_login_url'] ) : '';

        if ( empty( $custom_url ) ) {
            wp_send_json_error( __( 'No custom login URL configured.', 'vigilante' ) );
        }

        $login_url = home_url( $custom_url . '/' );
        $site_name = get_bloginfo( 'name' );

        // Roles that can access wp-admin
        $admin_roles = array( 'administrator', 'editor', 'author', 'contributor' );

        $users = get_users( array(
            'role__in' => $admin_roles,
        ) );

        if ( empty( $users ) ) {
            wp_send_json_error( __( 'No users found.', 'vigilante' ) );
        }

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Your login URL has changed', 'vigilante' ),
            $site_name
        );

        // Build email body using template
        $body  = Vigilante_Email_Template::p( __( 'The login URL for the admin area has been changed. Please save the new URL below and use it from now on.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::url_box( $login_url, __( 'Your new login URL:', 'vigilante' ) );
        $body .= Vigilante_Email_Template::alert_box( __( 'The old login address (wp-login.php) will no longer work.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::button( $login_url, __( 'Go to login', 'vigilante' ) );

        $sent   = 0;
        $failed = 0;

        foreach ( $users as $user ) {
            $result = Vigilante_Email_Template::send(
                $user->user_email,
                $subject,
                __( 'Login URL changed', 'vigilante' ),
                $body
            );
            if ( $result ) {
                $sent++;
            } else {
                $failed++;
            }
        }

        if ( $this->activity_log ) {
            $this->activity_log->log(
                'login',
                'login_url_notified',
                sprintf(
                    /* translators: 1: Sent count, 2: Failed count */
                    __( 'Login URL notification sent: %1$d sent, %2$d failed', 'vigilante' ),
                    $sent,
                    $failed
                )
            );
        }

        wp_send_json_success( array(
            'sent'   => $sent,
            'failed' => $failed,
        ) );
    }

    /**
     * Sanitize 2FA data within login security
     *
     * @param array $two_factor 2FA data to sanitize.
     * @return array
     */
    private function sanitize_two_factor_data( $two_factor ) {
        $valid_methods = array( 'email', 'totp' );
        $method = isset( $two_factor['method'] ) ? sanitize_key( $two_factor['method'] ) : 'email';

        return array(
            'enabled'              => ! empty( $two_factor['enabled'] ),
            'method'               => in_array( $method, $valid_methods, true ) ? $method : 'email',
            'enforced_roles'       => isset( $two_factor['enforced_roles'] ) 
                ? array_map( 'sanitize_key', (array) $two_factor['enforced_roles'] ) 
                : array( 'administrator', 'editor' ),
            'excluded_users'       => isset( $two_factor['excluded_users'] ) 
                ? array_map( 'absint', (array) $two_factor['excluded_users'] ) 
                : array(),
            'remember_device_days' => isset( $two_factor['remember_device_days'] ) 
                ? absint( $two_factor['remember_device_days'] ) 
                : 30,
            'code_expiry_minutes'  => isset( $two_factor['code_expiry_minutes'] ) 
                ? absint( $two_factor['code_expiry_minutes'] ) 
                : 10,
            'max_attempts'         => isset( $two_factor['max_attempts'] ) 
                ? absint( $two_factor['max_attempts'] ) 
                : 3,
            'email_from_name'      => isset( $two_factor['email_from_name'] ) 
                ? sanitize_text_field( $two_factor['email_from_name'] ) 
                : '',
            'notify_on_enable'     => ! empty( $two_factor['notify_on_enable'] ),
            'grace_period_days'    => isset( $two_factor['grace_period_days'] )
                ? min( 30, absint( $two_factor['grace_period_days'] ) )
                : 3,
        );
    }

    /**
     * AJAX: Search users for password reset
     */
    public function ajax_search_users_password_reset() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $query = isset( $_POST['query'] ) ? sanitize_text_field( wp_unslash( $_POST['query'] ) ) : '';

        if ( strlen( $query ) < 2 ) {
            wp_send_json_error( __( 'Query too short.', 'vigilante' ) );
        }

        // Search users by login, email, or display name
        $users = get_users( array(
            'search'         => '*' . $query . '*',
            'search_columns' => array( 'user_login', 'user_email', 'display_name' ),
            'number'         => 10,
            'orderby'        => 'display_name',
            'order'          => 'ASC',
        ) );

        $results = array();

        foreach ( $users as $user ) {
            $results[] = array(
                'ID'           => $user->ID,
                'user_login'   => $user->user_login,
                'user_email'   => $user->user_email,
                'display_name' => $user->display_name,
                'avatar'       => get_avatar_url( $user->ID, array( 'size' => 32 ) ),
                'roles'        => implode( ', ', $user->roles ),
            );
        }

        wp_send_json_success( $results );
    }

    /**
     * AJAX: Force password reset for specific users
     * Uses native WordPress password reset flow
     */
    public function ajax_force_password_reset() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $user_ids = isset( $_POST['user_ids'] ) ? array_map( 'absint', (array) $_POST['user_ids'] ) : array();
        $current_user_id = get_current_user_id();

        if ( empty( $user_ids ) ) {
            wp_send_json_error( __( 'No users selected.', 'vigilante' ) );
        }

        // Check if current user is resetting themselves
        $resetting_self = in_array( $current_user_id, $user_ids, true );

        // Create user security instance to use native reset
        $user_security = new Vigilante_User_Security( $this->settings, $this->activity_log );

        // Perform bulk reset
        $results = $user_security->force_password_reset_bulk( $user_ids, $current_user_id );

        $message = sprintf(
            /* translators: %d: Number of users */
            __( 'Password reset forced for %d user(s). Reset emails sent.', 'vigilante' ),
            $results['success']
        );

        if ( $results['failed'] > 0 ) {
            $message .= ' ' . sprintf(
                /* translators: %d: Number of failures */
                __( '%d failed.', 'vigilante' ),
                $results['failed']
            );
        }

        if ( ! empty( $results['skipped'] ) ) {
            $message .= ' ' . sprintf(
                /* translators: %d: Number of users skipped because the current user cannot edit them */
                __( '%d skipped: you cannot edit those users.', 'vigilante' ),
                $results['skipped']
            );
        }

        wp_send_json_success( array(
            'message'        => $message,
            'results'        => $results,
            'resetting_self' => $resetting_self,
        ) );
    }

    /**
     * AJAX: Force password reset for all users
     * Uses native WordPress password reset flow
     */
    public function ajax_force_password_reset_all() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $include_self    = ! empty( $_POST['include_self'] );
        $current_user_id = get_current_user_id();

        // Create user security instance to use native reset
        $user_security = new Vigilante_User_Security( $this->settings, $this->activity_log );

        // Perform reset for all users
        $results = $user_security->force_password_reset_all( $current_user_id, ! $include_self );

        // Log the bulk action
        if ( $this->activity_log ) {
            $reset_by_user = get_userdata( $current_user_id );
            $this->activity_log->log(
                'user',
                'force_password_reset_all',
                sprintf(
                    /* translators: 1: Number of users, 2: Admin username */
                    __( 'Password reset forced for %1$d users by %2$s', 'vigilante' ),
                    $results['success'],
                    $reset_by_user ? $reset_by_user->user_login : __( 'System', 'vigilante' )
                ),
                array(
                    'count'        => $results['success'],
                    'reset_by'     => $current_user_id,
                    'include_self' => $include_self,
                ),
                'warning'
            );
        }

        $message = sprintf(
            /* translators: %d: Number of users */
            __( 'Password reset forced for %d user(s). Reset emails sent.', 'vigilante' ),
            $results['success']
        );

        if ( $results['failed'] > 0 ) {
            $message .= ' ' . sprintf(
                /* translators: %d: Number of failures */
                __( '%d failed.', 'vigilante' ),
                $results['failed']
            );
        }

        if ( ! empty( $results['skipped'] ) ) {
            $message .= ' ' . sprintf(
                /* translators: %d: Number of users skipped because the current user cannot edit them */
                __( '%d skipped: you cannot edit those users.', 'vigilante' ),
                $results['skipped']
            );
        }

        wp_send_json_success( array(
            'message'        => $message,
            'results'        => $results,
            'resetting_self' => $include_self,
        ) );
    }

    /**
     * AJAX: Force password reset by role
     * Resets passwords for all users with the selected roles
     */
    public function ajax_force_password_reset_by_role() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $roles = isset( $_POST['roles'] ) ? array_map( 'sanitize_key', (array) $_POST['roles'] ) : array();

        if ( empty( $roles ) ) {
            wp_send_json_error( __( 'No roles selected.', 'vigilante' ) );
        }

        // Validate that submitted roles actually exist.
        $wp_roles = wp_roles();
        foreach ( $roles as $role ) {
            if ( ! isset( $wp_roles->roles[ $role ] ) ) {
                wp_send_json_error(
                    sprintf(
                        /* translators: %s: Role slug */
                        __( 'Invalid role: %s', 'vigilante' ),
                        $role
                    )
                );
            }
        }

        $include_self    = ! empty( $_POST['include_self'] );
        $current_user_id = get_current_user_id();

        $user_security = new Vigilante_User_Security( $this->settings, $this->activity_log );

        $results = $user_security->force_password_reset_by_roles(
            $roles,
            $current_user_id,
            ! $include_self
        );

        // Log the action.
        if ( $this->activity_log ) {
            $reset_by_user = get_userdata( $current_user_id );
            $role_names    = array();

            foreach ( $roles as $role ) {
                $role_names[] = isset( $wp_roles->roles[ $role ] )
                    ? translate_user_role( $wp_roles->roles[ $role ]['name'] )
                    : $role;
            }

            $this->activity_log->log(
                'user',
                'force_password_reset_by_role',
                sprintf(
                    /* translators: 1: Number of users, 2: Role names, 3: Admin username */
                    __( 'Password reset forced for %1$d users (roles: %2$s) by %3$s', 'vigilante' ),
                    $results['success'],
                    implode( ', ', $role_names ),
                    $reset_by_user ? $reset_by_user->user_login : __( 'System', 'vigilante' )
                ),
                array(
                    'count'        => $results['success'],
                    'roles'        => $roles,
                    'reset_by'     => $current_user_id,
                    'include_self' => $include_self,
                ),
                'warning'
            );
        }

        $message = sprintf(
            /* translators: %d: Number of users */
            __( 'Password reset forced for %d user(s). Reset emails sent.', 'vigilante' ),
            $results['success']
        );

        if ( $results['failed'] > 0 ) {
            $message .= ' ' . sprintf(
                /* translators: %d: Number of failures */
                __( '%d failed.', 'vigilante' ),
                $results['failed']
            );
        }

        if ( ! empty( $results['skipped'] ) ) {
            $message .= ' ' . sprintf(
                /* translators: %d: Number of users skipped because the current user cannot edit them */
                __( '%d skipped: you cannot edit those users.', 'vigilante' ),
                $results['skipped']
            );
        }

        // Check if current user was included via role membership.
        $resetting_self = false;
        if ( $include_self ) {
            $current_user   = wp_get_current_user();
            $resetting_self = ! empty( array_intersect( $roles, $current_user->roles ) );
        }

        wp_send_json_success( array(
            'message'        => $message,
            'results'        => $results,
            'resetting_self' => $resetting_self,
        ) );
    }

    /**
     * AJAX: Approve pending user
     */
    public function ajax_approve_user() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;

        if ( ! $user_id ) {
            wp_send_json_error( __( 'Invalid user ID.', 'vigilante' ) );
        }

        $user_security = new Vigilante_User_Security( $this->settings, $this->activity_log );
        $result = $user_security->approve_user( $user_id, get_current_user_id() );

        if ( $result ) {
            $user = get_userdata( $user_id );
            wp_send_json_success( array(
                'message' => sprintf(
                    /* translators: %s: Username */
                    __( 'User "%s" has been approved.', 'vigilante' ),
                    $user ? $user->user_login : $user_id
                ),
            ) );
        } else {
            wp_send_json_error( __( 'Failed to approve user.', 'vigilante' ) );
        }
    }

    /**
     * AJAX: Reject pending user
     */
    public function ajax_reject_user() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        $reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';

        if ( ! $user_id ) {
            wp_send_json_error( __( 'Invalid user ID.', 'vigilante' ) );
        }

        $user = get_userdata( $user_id );
        $username = $user ? $user->user_login : $user_id;

        $user_security = new Vigilante_User_Security( $this->settings, $this->activity_log );
        $result = $user_security->reject_user( $user_id, get_current_user_id(), $reason );

        if ( $result ) {
            wp_send_json_success( array(
                'message' => sprintf(
                    /* translators: %s: Username */
                    __( 'User "%s" has been rejected and deleted.', 'vigilante' ),
                    $username
                ),
            ) );
        } else {
            wp_send_json_error( __( 'Failed to reject user.', 'vigilante' ) );
        }
    }

    /**
     * AJAX: Get user sessions
     */
    public function ajax_get_user_sessions() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;

        if ( ! $user_id ) {
            wp_send_json_error( __( 'Invalid user ID.', 'vigilante' ) );
        }

        $user = get_userdata( $user_id );
        if ( ! $user ) {
            wp_send_json_error( __( 'User not found.', 'vigilante' ) );
        }

        // Sessions carry IP, User-Agent and login time. manage_options alone is
        // not enough on a network, where it is held per subsite.
        if ( ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $user_security = new Vigilante_User_Security( $this->settings, $this->activity_log );
        $sessions = $user_security->get_user_sessions( $user_id );

        wp_send_json_success( array(
            'user'     => array(
                'ID'           => $user->ID,
                'user_login'   => $user->user_login,
                'display_name' => $user->display_name,
            ),
            'sessions' => $sessions,
        ) );
    }

    /**
     * AJAX: Revoke specific session
     */
    public function ajax_revoke_session() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        $token_hash = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';

        if ( ! $user_id || ! $token_hash ) {
            wp_send_json_error( __( 'Invalid parameters.', 'vigilante' ) );
        }

        if ( ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $user_security = new Vigilante_User_Security( $this->settings, $this->activity_log );
        $result = $user_security->revoke_session( $user_id, $token_hash );

        if ( $result ) {
            wp_send_json_success( array(
                'message' => __( 'Session revoked successfully.', 'vigilante' ),
            ) );
        } else {
            wp_send_json_error( __( 'Failed to revoke session.', 'vigilante' ) );
        }
    }

    /**
     * AJAX: Revoke all sessions for a user
     */
    public function ajax_revoke_all_sessions() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        $include_current = ! empty( $_POST['include_current'] );

        if ( ! $user_id ) {
            wp_send_json_error( __( 'Invalid user ID.', 'vigilante' ) );
        }

        if ( ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $user_security = new Vigilante_User_Security( $this->settings, $this->activity_log );
        $count = $user_security->revoke_all_sessions( $user_id, $include_current );

        wp_send_json_success( array(
            'message' => sprintf(
                /* translators: %d: Number of sessions */
                __( '%d session(s) revoked.', 'vigilante' ),
                $count
            ),
            'count' => $count,
        ) );
    }

    /**
     * AJAX: Activate Under Attack mode
     */
    public function ajax_activate_under_attack() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $under_attack = new Vigilante_Under_Attack( $this->settings, $this->activity_log );

        if ( $under_attack->is_active() ) {
            wp_send_json_error( __( 'Under Attack mode is already active.', 'vigilante' ) );
        }

        $result = $under_attack->activate();

        if ( $result ) {
            wp_send_json_success( array(
                'message'   => __( 'Under Attack mode activated.', 'vigilante' ),
                'remaining' => $under_attack->get_remaining_time(),
                'expires'   => $under_attack->get_status()['activated_at'] + $under_attack->get_status()['duration'],
            ) );
        } else {
            wp_send_json_error( __( 'Failed to activate Under Attack mode.', 'vigilante' ) );
        }
    }

    /**
     * AJAX: Deactivate Under Attack mode
     */
    public function ajax_deactivate_under_attack() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $under_attack = new Vigilante_Under_Attack( $this->settings, $this->activity_log );

        if ( ! $under_attack->is_active() ) {
            wp_send_json_error( __( 'Under Attack mode is not active.', 'vigilante' ) );
        }

        $result = $under_attack->deactivate( 'manual' );

        if ( $result ) {
            wp_send_json_success( __( 'Under Attack mode deactivated.', 'vigilante' ) );
        } else {
            wp_send_json_error( __( 'Failed to deactivate Under Attack mode.', 'vigilante' ) );
        }
    }

    /**
     * AJAX: Get Under Attack mode status
     */
    public function ajax_under_attack_status() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $under_attack = new Vigilante_Under_Attack( $this->settings, $this->activity_log );

        wp_send_json_success( array(
            'active'    => $under_attack->is_active(),
            'remaining' => $under_attack->get_remaining_time(),
        ) );
    }

    // =========================================================================
    // DATABASE BACKUP AJAX HANDLERS
    // =========================================================================

    /**
     * AJAX: Get database tables list
     */
    public function ajax_get_db_tables() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        // The dump is taken with $wpdb->prefix, which on the main site of a
        // network matches every subsite table plus the global user tables, and
        // the options it carries include the stored copy of wp-config.php. Same
        // gate the rest of the network-shared operations use.
        if ( ! Vigilante_Settings::can_write_shared_files() ) {
            wp_send_json_error( Vigilante_Settings::get_shared_files_notice() );
        }

        $backup = new Vigilante_Database_Backup();
        $tables = $backup->get_tables();

        wp_send_json_success( $tables );
    }

    /**
     * AJAX: Download database backup
     *
     * Streams a ZIP file directly to the browser
     */
    public function ajax_download_db_backup() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Permission denied.', 'vigilante' ), 403 );
        }

        // The dump is taken with $wpdb->prefix, which on the main site of a
        // network matches every subsite table plus the global user tables, and
        // the options it carries include the stored copy of wp-config.php. Same
        // gate the rest of the network-shared operations use.
        if ( ! Vigilante_Settings::can_write_shared_files() ) {
            wp_die( esc_html( Vigilante_Settings::get_shared_files_notice() ), 403 );
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $tables_raw = isset( $_POST['tables'] ) ? wp_unslash( $_POST['tables'] ) : '';

        if ( empty( $tables_raw ) ) {
            wp_die( esc_html__( 'No tables selected.', 'vigilante' ), 400 );
        }

        // Sanitize table names
        $tables = array_map( 'sanitize_key', explode( ',', $tables_raw ) );
        $tables = array_filter( $tables );

        if ( empty( $tables ) ) {
            wp_die( esc_html__( 'No valid tables selected.', 'vigilante' ), 400 );
        }

        $backup = new Vigilante_Database_Backup();

        // Generate SQL dump
        $sql = $backup->generate_sql_dump( $tables );
        if ( is_wp_error( $sql ) ) {
            wp_die( esc_html( $sql->get_error_message() ), 500 );
        }

        // Create ZIP
        $zip_path = $backup->create_zip( $sql );
        if ( is_wp_error( $zip_path ) ) {
            wp_die( esc_html( $zip_path->get_error_message() ), 500 );
        }

        // Log the backup
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'system',
                'database_backup',
                sprintf(
                    /* translators: %d: Number of tables */
                    __( 'Database backup created (%d tables)', 'vigilante' ),
                    count( $tables )
                ),
                array( 'tables' => $tables ),
                'info'
            );
        }

        // Stream download
        $backup->stream_download( $zip_path );
    }

    // =========================================================================
    // DATABASE PREFIX AJAX HANDLERS
    // =========================================================================

    /**
     * AJAX: Generate a new random prefix
     */
    public function ajax_generate_prefix() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $db_prefix = new Vigilante_Database_Prefix();
        $prefix = $db_prefix->generate_prefix();

        wp_send_json_success( array( 'prefix' => $prefix ) );
    }

    /**
     * AJAX: Change the database prefix
     */
    public function ajax_change_prefix() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $new_prefix = isset( $_POST['prefix'] ) ? sanitize_key( $_POST['prefix'] ) : '';

        // Restore the underscore that sanitize_key might not strip but ensure it ends with one
        if ( ! empty( $new_prefix ) && substr( $new_prefix, -1 ) !== '_' ) {
            $new_prefix .= '_';
        }

        if ( empty( $new_prefix ) ) {
            wp_send_json_error( __( 'Invalid prefix provided.', 'vigilante' ) );
        }

        $db_prefix = new Vigilante_Database_Prefix();

        // On a network the prefix is shared by every site: main site + network admin only
        $allowed = $db_prefix->can_change_prefix();
        if ( is_wp_error( $allowed ) ) {
            wp_send_json_error( $allowed->get_error_message() );
        }

        // Validate first
        $valid = $db_prefix->validate_prefix( $new_prefix );
        if ( is_wp_error( $valid ) ) {
            wp_send_json_error( $valid->get_error_message() );
        }

        // Log before changing (since after change, the log table will have new prefix)
        $old_prefix = $db_prefix->get_current_prefix();

        // Execute the change
        $result = $db_prefix->change_prefix( $new_prefix );

        if ( is_wp_error( $result ) ) {
            wp_send_json_error( $result->get_error_message() );
        }

        // Log success (table has already been renamed, but the activity log object may still work for this request)
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'system',
                'prefix_changed',
                sprintf(
                    /* translators: 1: Old prefix, 2: New prefix */
                    __( 'Database prefix changed from %1$s to %2$s', 'vigilante' ),
                    $old_prefix,
                    $new_prefix
                ),
                array(
                    'old_prefix' => $old_prefix,
                    'new_prefix' => $new_prefix,
                ),
                'warning'
            );
        }

        wp_send_json_success( array(
            'message'    => __( 'Database prefix changed successfully.', 'vigilante' ),
            'old_prefix' => $old_prefix,
            'new_prefix' => $new_prefix,
        ) );
    }

    /**
     * AJAX: Unblock an IP from firewall rate limiting
     */
    public function ajax_unblock_firewall_ip() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';

        if ( empty( $ip ) ) {
            wp_send_json_error( __( 'No IP address provided.', 'vigilante' ) );
        }

        $result = Vigilante_Firewall::unblock_ip( $ip );

        if ( $result ) {
            // Log the manual unblock
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'firewall',
                    'unblocked',
                    sprintf(
                        /* translators: %s: IP address */
                        __( 'IP %s manually unblocked from rate limiting', 'vigilante' ),
                        $ip
                    ),
                    array( 'ip' => $ip ),
                    'info'
                );
            }
            wp_send_json_success( sprintf(
                /* translators: %s: IP address */
                __( 'IP %s has been unblocked.', 'vigilante' ),
                $ip
            ) );
        } else {
            wp_send_json_error( __( 'IP not found in active blocks.', 'vigilante' ) );
        }
    }

}