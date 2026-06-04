<?php
/**
 * User Security Class
 *
 * Handles user security validations and protections
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_User_Security
 *
 * Manages user security features
 */
class Vigilante_User_Security {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Activity log instance
     *
     * @var Vigilante_Activity_Log
     */
    private $activity_log;

    /**
     * User security options
     *
     * @var array
     */
    private $options;

    /**
     * Constructor
     *
     * @param Vigilante_Settings     $settings     Settings instance.
     * @param Vigilante_Activity_Log $activity_log Activity log instance.
     */
    public function __construct( $settings, $activity_log ) {
        $this->settings     = $settings;
        $this->activity_log = $activity_log;
        $this->options      = $settings->get_section( 'user_security' );

        $this->init_hooks();
    }

    /**
     * Initialize hooks
     */
    private function init_hooks() {
        // Block insecure usernames
        if ( ! empty( $this->options['block_insecure_usernames'] ) ) {
            add_action( 'user_profile_update_errors', array( $this, 'validate_username' ), 10, 3 );
            add_filter( 'pre_user_login', array( $this, 'check_username_on_create' ) );
            add_action( 'register_post', array( $this, 'validate_registration_username' ), 10, 3 );
        }

        // Warn about existing insecure users (always active, independent of settings)
        add_action( 'admin_notices', array( $this, 'show_insecure_user_warning' ) );

        // Block author scanning — must run BEFORE WordPress core's redirect_canonical()
        // (also on template_redirect, default priority 10), which would otherwise redirect
        // /?author=N to /author/USERNAME/ and leak the login. Priority 1 puts our redirect
        // first so the username never reaches the response.
        if ( ! empty( $this->options['block_author_scanning'] ) ) {
            add_action( 'template_redirect', array( $this, 'block_author_scan' ), 1 );
        }

        // Block user enumeration via REST API
        if ( ! empty( $this->options['disable_user_rest_enum'] ) ) {
            add_filter( 'rest_endpoints', array( $this, 'disable_user_endpoints' ) );
        }

        // Force strong passwords
        if ( ! empty( $this->options['force_strong_passwords'] ) ) {
            add_action( 'user_profile_update_errors', array( $this, 'validate_password_strength' ), 10, 3 );
            add_filter( 'registration_errors', array( $this, 'validate_registration_password' ), 10, 3 );
        }

        // Prevent display name matching login username
        // Also enforced during Under Attack mode regardless of setting
        $under_attack = get_option( 'vigilante_under_attack_mode', array() );
        if ( ! empty( $this->options['prevent_display_name_login_match'] ) || ! empty( $under_attack['active'] ) ) {
            add_action( 'user_profile_update_errors', array( $this, 'validate_display_name' ), 10, 3 );
        }

        // Log user changes and admin monitoring
        add_action( 'profile_update', array( $this, 'log_profile_update' ), 10, 2 );
        add_action( 'user_register', array( $this, 'log_user_register' ) );
        add_action( 'delete_user', array( $this, 'log_user_delete' ) );
        add_action( 'set_user_role', array( $this, 'log_role_change' ), 10, 3 );

        // Registration approval
        $registration_approval = $this->options['registration_approval'] ?? array();
        if ( ! empty( $registration_approval['enabled'] ) ) {
            add_action( 'user_register', array( $this, 'set_user_pending_approval' ), 5 );
            add_filter( 'wp_authenticate_user', array( $this, 'block_pending_user_login' ), 15, 2 );
            add_action( 'admin_notices', array( $this, 'show_pending_users_notice' ) );
        }

        // Session limits
        $session_limits = $this->options['session_limits'] ?? array();
        if ( ! empty( $session_limits['enabled'] ) ) {
            // For block_new: check BEFORE login completes
            if ( 'block_new' === ( $session_limits['behavior'] ?? 'block_new' ) ) {
                add_filter( 'wp_authenticate_user', array( $this, 'check_session_limit_before_login' ), 20, 2 );
            }
            // For close_oldest: handle AFTER login
            add_action( 'wp_login', array( $this, 'enforce_session_limit' ), 10, 2 );
        }

        // Admin password change monitoring (independent of password expiration)
        $admin_monitoring = $this->options['admin_monitoring'] ?? array();
        if ( ! empty( $admin_monitoring['alert_admin_password_change'] ) ) {
            add_action( 'profile_update', array( $this, 'check_admin_password_change' ), 10, 2 );
        }

        // Password expiration
        $password_expiration = $this->options['password_expiration'] ?? array();
        if ( ! empty( $password_expiration['enabled'] ) ) {
            add_action( 'wp_login', array( $this, 'check_password_expiration' ), 10, 2 );
            add_action( 'admin_notices', array( $this, 'show_password_expiration_notice' ) );
            add_action( 'admin_init', array( $this, 'force_password_change_redirect' ) );
            add_action( 'profile_update', array( $this, 'update_password_change_date' ), 10, 2 );
            add_action( 'user_register', array( $this, 'set_initial_password_date' ) );
            add_action( 'user_profile_update_errors', array( $this, 'check_password_history' ), 10, 3 );

            // Email reminder cron
            if ( ! empty( $password_expiration['send_reminder'] ) ) {
                add_action( 'vigilante_password_expiry_reminder', array( $this, 'send_password_expiry_reminders' ) );
                if ( ! wp_next_scheduled( 'vigilante_password_expiry_reminder' ) ) {
                    wp_schedule_event( time(), 'daily', 'vigilante_password_expiry_reminder' );
                }
            }
        }

        // Email verification
        $email_verification = $this->options['email_verification'] ?? array();
        if ( ! empty( $email_verification['enabled'] ) ) {
            add_action( 'user_register', array( $this, 'send_verification_email' ), 15 );
            add_filter( 'wp_authenticate_user', array( $this, 'block_unverified_user_login' ), 10, 2 );
            add_action( 'init', array( $this, 'handle_email_verification' ) );
            add_action( 'login_message', array( $this, 'show_verification_message' ) );
        }

        // Registration flow control - suppress WP email and show custom messages
        if ( ! empty( $registration_approval['enabled'] ) || ! empty( $email_verification['enabled'] ) ) {
            add_filter( 'wp_new_user_notification_email', array( $this, 'suppress_new_user_email' ), 10, 3 );
            add_filter( 'registration_redirect', array( $this, 'custom_registration_redirect' ) );
            add_action( 'login_message', array( $this, 'show_registration_pending_message' ) );
        }

        // Force password reset login message (always active, independent of settings)
        add_filter( 'authenticate', array( $this, 'check_force_reset_on_login' ), 30, 3 );
        add_action( 'after_password_reset', array( $this, 'clear_force_reset_meta' ), 10, 1 );
    }

    /**
     * Validate username on profile update
     *
     * @param WP_Error $errors Error object.
     * @param bool     $update Whether this is an update.
     * @param WP_User  $user   User object.
     */
    public function validate_username( $errors, $update, $user ) {
        if ( $update ) {
            return; // Can't change username on update
        }

        $username = isset( $user->user_login ) ? $user->user_login : '';
        
        if ( $this->is_insecure_username( $username ) ) {
            $errors->add(
                'insecure_username',
                sprintf(
                    /* translators: %s: Username */
                    __( '<strong>Error</strong>: The username "%s" is not allowed for security reasons. Please choose a different username.', 'vigilante' ),
                    esc_html( $username )
                )
            );
        }
    }

    /**
     * Check username before creation
     *
     * @param string $username Username.
     * @return string
     */
    public function check_username_on_create( $username ) {
        if ( $this->is_insecure_username( $username ) ) {
            // Log the attempt
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'user',
                    'insecure_username_blocked',
                    sprintf(
                        /* translators: %s: Username */
                        __( 'Attempted to create user with insecure username: %s', 'vigilante' ),
                        $username
                    ),
                    array( 'username' => $username ),
                    'warning'
                );
            }
        }
        return $username;
    }

    /**
     * Validate username during registration
     *
     * @param string   $sanitized_user_login Username.
     * @param string   $user_email           Email.
     * @param WP_Error $errors               Error object.
     */
    public function validate_registration_username( $sanitized_user_login, $user_email, $errors ) {
        if ( $this->is_insecure_username( $sanitized_user_login ) ) {
            $errors->add(
                'insecure_username',
                __( '<strong>Error</strong>: This username is not allowed for security reasons. Please choose a different username.', 'vigilante' )
            );
        }
    }

    /**
     * Check if username is insecure
     *
     * @param string $username Username to check.
     * @return bool
     */
    private function is_insecure_username( $username ) {
        $username = strtolower( trim( $username ) );
        $insecure_usernames = $this->options['insecure_usernames'] ?? array();

        return in_array( $username, array_map( 'strtolower', $insecure_usernames ), true );
    }

    /**
     * Show warning if insecure admin users exist
     */
    public function show_insecure_user_warning() {
        // Only show to administrators
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // Check for dismissed notices
        $dismissed = get_option( 'vigilante_dismissed_notices', array() );
        if ( isset( $dismissed['insecure_users'] ) && $dismissed['insecure_users'] > ( time() - WEEK_IN_SECONDS ) ) {
            return;
        }

        $priority_usernames = array( 'admin', 'administrator', 'root', 'test', 'user', 'guest', 'info', 'sysadmin', 'webmaster' );
        $found_users = array();

        foreach ( $priority_usernames as $username ) {
            $user = get_user_by( 'login', $username );
            if ( $user ) {
                $found_users[] = $username;
            }
        }

        if ( ! empty( $found_users ) ) {
            ?>
            <div class="notice notice-error is-dismissible" data-notice-id="insecure_users">
                            <p>
                    <strong><?php esc_html_e( 'Security Alert!', 'vigilante' ); ?></strong>
                </p>
                <p>
                    <?php
                    $escaped_users = array_map( 'esc_html', $found_users );
                    $usernames_html = '<code>' . implode( '</code>, <code>', $escaped_users ) . '</code>';
                    printf(
                        /* translators: %s: Comma-separated list of usernames in <code> tags */
                        esc_html__( 'The following accounts use insecure usernames that are commonly targeted in brute force attacks: %s', 'vigilante' ),
                        wp_kses( $usernames_html, array( 'code' => array() ) )
                    );
                    ?>
                </p>
                <p>
                    <?php esc_html_e( 'For security, create new accounts with unique usernames and delete these.', 'vigilante' ); ?>
                </p>
            </div>                      
            <?php
        }
    }

    /**
     * Block author scanning via URL
     */
    public function block_author_scan() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
            // Log the attempt
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'user',
                    'author_scan_blocked',
                    __( 'Author enumeration attempt blocked', 'vigilante' ),
                    array(
                        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                        'author_id' => absint( $_GET['author'] ),
                    ),
                    'warning'
                );
            }

            // Redirect to homepage
            wp_safe_redirect( home_url(), 301 );
            exit;
        }
    }

    /**
     * Disable user endpoints in REST API
     *
     * @param array $endpoints REST API endpoints.
     * @return array Modified endpoints.
     */
    public function disable_user_endpoints( $endpoints ) {
        // Only for non-logged in users
        if ( is_user_logged_in() ) {
            return $endpoints;
        }

        $endpoints_to_remove = array(
            '/wp/v2/users',
            '/wp/v2/users/(?P<id>[\d]+)',
        );

        foreach ( $endpoints_to_remove as $endpoint ) {
            if ( isset( $endpoints[ $endpoint ] ) ) {
                unset( $endpoints[ $endpoint ] );
            }
        }

        return $endpoints;
    }

    // =========================================================================
    // Display Name Protection - Prevent display name matching login
    // =========================================================================

    /**
     * Prevent users from saving a display name that matches their login username
     *
     * The display name is publicly visible (author archives, comments, REST API).
     * If it matches the login username, the login is exposed to attackers.
     *
     * @param WP_Error $errors Error object.
     * @param bool     $update Whether this is an update.
     * @param WP_User  $user   User object.
     */
    public function validate_display_name( $errors, $update, $user ) {
        if ( ! $update || ! isset( $user->ID ) ) {
            return;
        }

        // Get the display name being saved
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $display_name = isset( $_POST['display_name'] ) ? sanitize_text_field( wp_unslash( $_POST['display_name'] ) ) : '';

        if ( empty( $display_name ) ) {
            return;
        }

        // Get the actual login username
        $user_data = get_userdata( $user->ID );
        if ( ! $user_data ) {
            return;
        }

        if ( strcasecmp( $display_name, $user_data->user_login ) === 0 ) {
            $errors->add(
                'display_name_login_match',
                __( '<strong>Error</strong>: Your display name cannot be the same as your login username. The display name is publicly visible and would expose your login credentials.', 'vigilante' )
            );
        }
    }

    /**
     * Validate password strength
     *
     * @param WP_Error $errors Error object.
     * @param bool     $update Whether this is an update.
     * @param WP_User  $user   User object.
     */
    public function validate_password_strength( $errors, $update, $user ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( empty( $_POST['pass1'] ) ) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $password = sanitize_text_field( wp_unslash( $_POST['pass1'] ) );
        $strength_errors = $this->check_password_strength( $password );

        foreach ( $strength_errors as $error ) {
            $errors->add( 'weak_password', $error );
        }
    }

    /**
     * Validate password on registration
     *
     * @param WP_Error $errors               Error object.
     * @param string   $sanitized_user_login Username.
     * @param string   $user_email           Email.
     * @return WP_Error
     */
    public function validate_registration_password( $errors, $sanitized_user_login, $user_email ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( empty( $_POST['user_pass'] ) ) {
            return $errors;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $password = sanitize_text_field( wp_unslash( $_POST['user_pass'] ) );
        $strength_errors = $this->check_password_strength( $password );

        foreach ( $strength_errors as $error ) {
            $errors->add( 'weak_password', $error );
        }

        return $errors;
    }

    /**
     * Check password strength
     *
     * @param string $password Password to check.
     * @return array Array of error messages (empty if password is strong).
     */
    public function check_password_strength( $password ) {
        $errors = array();
        $min_length = $this->options['min_password_length'] ?? 12;

        // Check length
        if ( strlen( $password ) < $min_length ) {
            $errors[] = sprintf(
                /* translators: %d: Minimum password length */
                __( 'Password must be at least %d characters long.', 'vigilante' ),
                $min_length
            );
        }

        // Check for uppercase
        if ( ! preg_match( '/[A-Z]/', $password ) ) {
            $errors[] = __( 'Password must contain at least one uppercase letter.', 'vigilante' );
        }

        // Check for lowercase
        if ( ! preg_match( '/[a-z]/', $password ) ) {
            $errors[] = __( 'Password must contain at least one lowercase letter.', 'vigilante' );
        }

        // Check for numbers
        if ( ! preg_match( '/[0-9]/', $password ) ) {
            $errors[] = __( 'Password must contain at least one number.', 'vigilante' );
        }

        // Check for special characters
        if ( ! preg_match( '/[^a-zA-Z0-9]/', $password ) ) {
            $errors[] = __( 'Password must contain at least one special character.', 'vigilante' );
        }

        // Check for common passwords
        $common_passwords = array(
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321',
        );

        if ( in_array( strtolower( $password ), $common_passwords, true ) ) {
            $errors[] = __( 'This password is too common. Please choose a more unique password.', 'vigilante' );
        }

        return $errors;
    }

    /**
     * Log profile update and check for admin email changes
     *
     * @param int     $user_id       User ID.
     * @param WP_User $old_user_data Old user data.
     */
    public function log_profile_update( $user_id, $old_user_data ) {
        $user = get_userdata( $user_id );
        $changes = array();
        $is_admin = user_can( $user, 'administrator' );
        $email_changed = $user->user_email !== $old_user_data->user_email;

        if ( $email_changed ) {
            $changes['email'] = array(
                'old' => $old_user_data->user_email,
                'new' => $user->user_email,
            );
        }

        if ( $user->display_name !== $old_user_data->display_name ) {
            $changes['display_name'] = array(
                'old' => $old_user_data->display_name,
                'new' => $user->display_name,
            );

            // Invalidate cached display name check for dashboard recommendation
            delete_transient( 'vigilante_exposed_display_names' );
        }

        // Determine severity - admin email change is always warning
        $severity = ( $is_admin && $email_changed ) ? 'warning' : 'info';

        // Log the change
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'user',
                'profile_updated',
                sprintf(
                    /* translators: %s: Username */
                    __( 'User profile updated: %s', 'vigilante' ),
                    $user->user_login
                ),
                array(
                    'user_id' => $user_id,
                    'changes' => $changes,
                ),
                $severity
            );
        }

        // Send alert for admin email change if enabled
        if ( $is_admin && $email_changed ) {
            $monitoring = $this->options['admin_monitoring'] ?? array();
            if ( ! empty( $monitoring['alert_admin_email_change'] ) ) {
                $this->send_admin_monitoring_alert(
                    'admin_email_change',
                    sprintf(
                        /* translators: 1: Username, 2: Old email, 3: New email */
                        __( 'Administrator email changed for user "%1$s": %2$s → %3$s', 'vigilante' ),
                        $user->user_login,
                        $old_user_data->user_email,
                        $user->user_email
                    ),
                    array(
                        'user_id'   => $user_id,
                        'username'  => $user->user_login,
                        'old_email' => $old_user_data->user_email,
                        'new_email' => $user->user_email,
                    )
                );
            }
        }
    }

    /**
     * Log user registration and check for new admin
     *
     * @param int $user_id User ID.
     */
    public function log_user_register( $user_id ) {
        $user = get_userdata( $user_id );
        $is_admin = user_can( $user, 'administrator' );
        $severity = $is_admin ? 'warning' : 'info';

        // Log the registration
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'user',
                'registered',
                sprintf(
                    /* translators: %s: Username */
                    __( 'New user registered: %s', 'vigilante' ),
                    $user->user_login
                ),
                array(
                    'user_id' => $user_id,
                    'email'   => $user->user_email,
                    'role'    => implode( ', ', $user->roles ),
                ),
                $severity
            );
        }

        // Send alert for new admin if enabled
        if ( $is_admin ) {
            $monitoring = $this->options['admin_monitoring'] ?? array();
            if ( ! empty( $monitoring['alert_new_admin'] ) ) {
                $this->send_admin_monitoring_alert(
                    'new_admin',
                    sprintf(
                        /* translators: 1: Username, 2: Email */
                        __( 'New administrator account created: "%1$s" (%2$s)', 'vigilante' ),
                        $user->user_login,
                        $user->user_email
                    ),
                    array(
                        'user_id'  => $user_id,
                        'username' => $user->user_login,
                        'email'    => $user->user_email,
                    )
                );
            }
        }
    }

    /**
     * Log user deletion
     *
     * @param int $user_id User ID.
     */
    public function log_user_delete( $user_id ) {
        if ( ! $this->activity_log ) {
            return;
        }

        $user = get_userdata( $user_id );

        if ( $user ) {
            $this->activity_log->log(
                'user',
                'deleted',
                sprintf(
                    /* translators: %s: Username */
                    __( 'User deleted: %s', 'vigilante' ),
                    $user->user_login
                ),
                array(
                    'user_id' => $user_id,
                    'email'   => $user->user_email,
                    'role'    => implode( ', ', $user->roles ),
                ),
                'warning'
            );
        }
    }

    /**
     * Log role change and check for permission elevation
     *
     * @param int    $user_id   User ID.
     * @param string $new_role  New role.
     * @param array  $old_roles Old roles.
     */
    public function log_role_change( $user_id, $new_role, $old_roles ) {
        // Skip if this is initial role assignment during user creation
        // (already logged by log_user_register, old_roles is empty for new users)
        if ( empty( $old_roles ) ) {
            return;
        }

        $user = get_userdata( $user_id );
        $was_admin = in_array( 'administrator', $old_roles, true );
        $is_now_admin = 'administrator' === $new_role;
        $elevated_to_admin = ! $was_admin && $is_now_admin;

        // Log the change (always warning for role changes)
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'user',
                'role_changed',
                sprintf(
                    /* translators: 1: Username, 2: Old role, 3: New role */
                    __( 'User role changed for %1$s: %2$s → %3$s', 'vigilante' ),
                    $user->user_login,
                    implode( ', ', $old_roles ),
                    $new_role
                ),
                array(
                    'user_id'   => $user_id,
                    'old_roles' => $old_roles,
                    'new_role'  => $new_role,
                ),
                'warning'
            );
        }

        // Send alert for permission elevation if enabled
        if ( $elevated_to_admin ) {
            $monitoring = $this->options['admin_monitoring'] ?? array();
            if ( ! empty( $monitoring['alert_permission_elevation'] ) ) {
                $this->send_admin_monitoring_alert(
                    'permission_elevation',
                    sprintf(
                        /* translators: 1: Username, 2: Old role */
                        __( 'User "%1$s" elevated to administrator (was: %2$s)', 'vigilante' ),
                        $user->user_login,
                        implode( ', ', $old_roles )
                    ),
                    array(
                        'user_id'   => $user_id,
                        'username'  => $user->user_login,
                        'email'     => $user->user_email,
                        'old_roles' => $old_roles,
                        'new_role'  => $new_role,
                    )
                );
            }
        }
    }

    /**
     * Send admin monitoring alert email
     *
     * @param string $alert_type Alert type identifier.
     * @param string $message    Alert message.
     * @param array  $data       Additional data.
     */
    private function send_admin_monitoring_alert( $alert_type, $message, $data = array() ) {
        // Use centralized notification recipients
        $recipients = Vigilante_Email_Template::get_admin_recipients();

        if ( empty( $recipients ) ) {
            return;
        }

        $site_name = get_bloginfo( 'name' );
        $site_url = home_url();

        // Build subject based on alert type
        $subjects = array(
            'new_admin'              => __( '[Security Alert] New administrator created', 'vigilante' ),
            'admin_email_change'     => __( '[Security Alert] Administrator email changed', 'vigilante' ),
            'permission_elevation'   => __( '[Security Alert] User elevated to administrator', 'vigilante' ),
            'admin_password_change'  => __( '[Security Alert] Administrator password changed', 'vigilante' ),
        );

        $subject = isset( $subjects[ $alert_type ] ) 
            ? $subjects[ $alert_type ] . ' - ' . $site_name 
            : __( '[Security Alert]', 'vigilante' ) . ' - ' . $site_name;

        // Build email body
        $body = Vigilante_Email_Template::alert_box( $message );

        $table_data = array(
            __( 'Site', 'vigilante' ) => $site_url,
            __( 'Time', 'vigilante' ) => wp_date( 'Y-m-d H:i:s' ),
        );
        if ( ! empty( $data['username'] ) ) {
            $table_data[ __( 'Username', 'vigilante' ) ] = $data['username'];
        }
        if ( ! empty( $data['email'] ) ) {
            $table_data[ __( 'Email', 'vigilante' ) ] = $data['email'];
        }
        $current_user = wp_get_current_user();
        if ( $current_user && $current_user->ID ) {
            $table_data[ __( 'Changed by', 'vigilante' ) ] = $current_user->user_login;
        }
        $body .= Vigilante_Email_Template::data_table( $table_data );
        $body .= Vigilante_Email_Template::warning_box( __( 'If you did not make this change, please review your site security immediately.', 'vigilante' ) );

        Vigilante_Email_Template::send( $recipients, $subject, __( 'Security alert', 'vigilante' ), $body, true );
    }

    /**
     * Get list of insecure usernames
     *
     * @return array
     */
    public function get_insecure_usernames() {
        return $this->options['insecure_usernames'] ?? array();
    }

    /**
     * Check for existing insecure admin users
     *
     * @return array Array of insecure admin users.
     */
    public function get_insecure_admin_users() {
        $insecure_users = array();
        $insecure_usernames = $this->get_insecure_usernames();

        foreach ( $insecure_usernames as $username ) {
            $user = get_user_by( 'login', $username );
            if ( $user ) {
                $insecure_users[] = array(
                    'id'       => $user->ID,
                    'username' => $user->user_login,
                    'email'    => $user->user_email,
                );
            }
        }

        return $insecure_users;
    }

    // =========================================================================
    // Force Password Reset - Uses native WordPress password reset flow
    // =========================================================================

    /**
     * Force password reset for a single user using native WordPress flow
     *
     * Flags the user with vigilante_force_reset_pending so any login attempt
     * is blocked by check_force_reset_on_login(), destroys all active sessions
     * to kick the user out if currently logged in, and emails them the standard
     * WordPress password reset link.
     *
     * @param int $user_id          User ID.
     * @param int $reset_by_user_id User ID who initiated the reset.
     * @return array Result with status and message.
     */
    public function force_password_reset( $user_id, $reset_by_user_id = 0 ) {
        $user = get_userdata( $user_id );
        if ( ! $user ) {
            return array(
                'success' => false,
                'message' => __( 'User not found.', 'vigilante' ),
            );
        }

        // Flag user FIRST so the authenticate hook blocks any login attempt
        // even if the reset key generation or email sending fails midway.
        update_user_meta( $user_id, 'vigilante_force_reset_pending', time() );

        // Destroy all active sessions so a user that's already logged in is
        // kicked out and forced through the reset flow on next request.
        $sessions = WP_Session_Tokens::get_instance( $user_id );
        $sessions->destroy_all();

        // Generate password reset key using WordPress native function.
        // IMPORTANT: don't call wp_set_password() afterwards — it would clear
        // user_activation_key in the same UPDATE and immediately invalidate
        // the key we just stored, breaking the reset link in the email.
        $reset_key = get_password_reset_key( $user );

        if ( is_wp_error( $reset_key ) ) {
            return array(
                'success' => false,
                'message' => $reset_key->get_error_message(),
            );
        }

        // Send the native WordPress password reset email
        $email_sent = $this->send_native_reset_email( $user, $reset_key );

        // Log the action
        if ( $this->activity_log ) {
            $reset_by_user = $reset_by_user_id ? get_userdata( $reset_by_user_id ) : null;
            $this->activity_log->log(
                'user',
                'force_password_reset',
                sprintf(
                    /* translators: 1: Target username, 2: Admin username */
                    __( 'Password reset forced for user "%1$s" by %2$s', 'vigilante' ),
                    $user->user_login,
                    $reset_by_user ? $reset_by_user->user_login : __( 'System', 'vigilante' )
                ),
                array(
                    'user_id'    => $user_id,
                    'username'   => $user->user_login,
                    'email'      => $user->user_email,
                    'reset_by'   => $reset_by_user_id,
                    'email_sent' => $email_sent,
                ),
                'warning'
            );
        }

        return array(
            'success'    => true,
            'email_sent' => $email_sent,
            'message'    => $email_sent
                ? __( 'Password reset email sent.', 'vigilante' )
                : __( 'Account flagged for reset but email could not be sent.', 'vigilante' ),
        );
    }

    /**
     * Send native WordPress password reset email
     *
     * @param WP_User $user      User object.
     * @param string  $reset_key Password reset key.
     * @return bool Whether email was sent successfully.
     */
    private function send_native_reset_email( $user, $reset_key ) {
        $site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
        $reset_url = network_site_url( "wp-login.php?action=rp&key=$reset_key&login=" . rawurlencode( $user->user_login ), 'login' );

        /* translators: %s: User login */
        $title = sprintf( __( '[%s] Password Reset', 'vigilante' ), $site_name );

        $body  = Vigilante_Email_Template::p(
            sprintf(
                /* translators: %s: Username */
                __( 'A site administrator has required a password reset for the account: %s', 'vigilante' ),
                $user->user_login
            )
        );
        $body .= Vigilante_Email_Template::info_box( __( 'For security reasons, you need to set a new password.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::button( $reset_url, __( 'Reset your password', 'vigilante' ) );

        /** This filter is documented in class-user-security.php */
        $title = apply_filters( 'vigilante_password_reset_title', $title, $user->user_login, $user );

        return Vigilante_Email_Template::send( $user->user_email, $title, __( 'Password reset required', 'vigilante' ), $body );
    }

    /**
     * Force password reset for multiple users
     *
     * @param array $user_ids         Array of user IDs.
     * @param int   $reset_by_user_id User ID who initiated the reset.
     * @return array Results with counts.
     */
    public function force_password_reset_bulk( $user_ids, $reset_by_user_id = 0 ) {
        $results = array(
            'success'     => 0,
            'failed'      => 0,
            'emails_sent' => 0,
            'total'       => count( $user_ids ),
        );

        foreach ( $user_ids as $user_id ) {
            $result = $this->force_password_reset( $user_id, $reset_by_user_id );
            
            if ( $result['success'] ) {
                $results['success']++;
                if ( ! empty( $result['email_sent'] ) ) {
                    $results['emails_sent']++;
                }
            } else {
                $results['failed']++;
            }
        }

        return $results;
    }

    /**
     * Force password reset for all users
     *
     * @param int  $reset_by_user_id User ID who initiated the reset.
     * @param bool $exclude_current  Whether to exclude current user.
     * @return array Results with counts.
     */
    public function force_password_reset_all( $reset_by_user_id = 0, $exclude_current = true ) {
        $args = array(
            'fields' => 'ID',
        );

        // phpcs:disable WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- Excluding single user is acceptable here.
        if ( $exclude_current && $reset_by_user_id ) {
            $args['exclude'] = array( $reset_by_user_id );
        }
        // phpcs:enable WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude

        $user_ids = get_users( $args );

        return $this->force_password_reset_bulk( $user_ids, $reset_by_user_id );
    }

    /**
     * Force password reset for users with specific roles
     *
     * @param array $roles            Array of role slugs.
     * @param int   $reset_by_user_id User ID who initiated the reset.
     * @param bool  $exclude_current  Whether to exclude current user.
     * @return array Results with counts and affected roles.
     */
    public function force_password_reset_by_roles( $roles, $reset_by_user_id = 0, $exclude_current = true ) {
        if ( empty( $roles ) ) {
            return array(
                'success'     => 0,
                'failed'      => 0,
                'emails_sent' => 0,
                'total'       => 0,
                'roles'       => array(),
            );
        }

        $user_ids = array();

        foreach ( $roles as $role ) {
            $role_users = get_users( array(
                'role'   => $role,
                'fields' => 'ID',
            ) );
            $user_ids = array_merge( $user_ids, $role_users );
        }

        // Remove duplicates (users with multiple roles).
        $user_ids = array_unique( array_map( 'absint', $user_ids ) );

        // phpcs:disable WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- Excluding single user is acceptable here.
        if ( $exclude_current && $reset_by_user_id ) {
            $user_ids = array_diff( $user_ids, array( $reset_by_user_id ) );
        }
        // phpcs:enable WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude

        $results          = $this->force_password_reset_bulk( array_values( $user_ids ), $reset_by_user_id );
        $results['roles'] = $roles;

        return $results;
    }

    /**
     * Show informative message when a user with a forced reset tries to log in
     *
     * Hooked to 'authenticate' at priority 30 (after default password check at 20).
     * Blocks login while a forced reset is pending REGARDLESS of whether the
     * user typed the right password — the admin invalidated the account, not
     * just the password, so even valid credentials must not let them in until
     * they've gone through the reset link in their email.
     *
     * @param WP_User|WP_Error|null $user     User object, error, or null.
     * @param string                $username Username or email.
     * @param string                $password Password.
     * @return WP_User|WP_Error|null
     */
    public function check_force_reset_on_login( $user, $username, $password ) {
        // Resolve the target user. The flag must be evaluated whether the
        // credentials matched (WP_User) or not (WP_Error).
        if ( $user instanceof WP_User ) {
            $login_user = $user;
        } else {
            $login_user = get_user_by( 'login', $username );
            if ( ! $login_user ) {
                $login_user = get_user_by( 'email', $username );
            }
        }

        if ( ! $login_user ) {
            return $user;
        }

        // Check if this user has a pending forced reset.
        $force_reset = get_user_meta( $login_user->ID, 'vigilante_force_reset_pending', true );
        if ( ! $force_reset ) {
            return $user;
        }

        // If credentials were wrong with an error other than incorrect_password
        // (e.g. a Vigilant lockout, pending approval), don't shadow it.
        if ( is_wp_error( $user ) && ! in_array( 'incorrect_password', $user->get_error_codes(), true ) ) {
            return $user;
        }

        // Skip brute force counter for this controlled rejection.
        add_filter( 'vigilante_skip_failed_login_count', '__return_true' );

        // Surface the controlled rejection in the activity log so the admin
        // can tell apart "user fails login because they typed wrong password"
        // from "user fails login because we are forcing a reset".
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'login',
                'force_reset_login_blocked',
                sprintf(
                    /* translators: %s: Username */
                    __( 'Login blocked for "%s" — pending forced password reset', 'vigilante' ),
                    $login_user->user_login
                ),
                array(
                    'user_id'  => $login_user->ID,
                    'username' => $login_user->user_login,
                ),
                'warning'
            );
        }

        return new WP_Error(
            'vigilante_force_reset',
            __( '<strong>Password reset required:</strong> Your password has been reset by the site administrator for security reasons. Please check your email for a link to set a new password.', 'vigilante' )
        );
    }

    /**
     * Clear force reset meta after user successfully resets their password
     *
     * Hooked to 'after_password_reset'. Also resets password expiration
     * tracking — reset_password() doesn't fire profile_update, so without
     * this the freshly-reset password may immediately be flagged as expired
     * again on next login, creating a redirect loop into profile.php.
     *
     * @param WP_User $user User object.
     */
    public function clear_force_reset_meta( $user ) {
        if ( ! $user || empty( $user->ID ) ) {
            return;
        }

        delete_user_meta( $user->ID, 'vigilante_force_reset_pending' );
        update_user_meta( $user->ID, 'vigilante_password_changed', time() );
        delete_user_meta( $user->ID, 'vigilante_must_change_password' );
        delete_user_meta( $user->ID, 'vigilante_password_reminder_sent' );
    }

    // =========================================================================
    // Registration Approval - Manual approval for new user registrations
    // =========================================================================

    /**
     * Set new user as pending approval
     *
     * @param int $user_id User ID.
     */
    public function set_user_pending_approval( $user_id ) {
        $user = get_userdata( $user_id );
        if ( ! $user ) {
            return;
        }

        $settings = $this->options['registration_approval'] ?? array();
        $affected_roles = $settings['affected_roles'] ?? array( 'subscriber' );

        // Check if user role requires approval
        $user_roles = $user->roles;
        $needs_approval = array_intersect( $user_roles, $affected_roles );

        if ( empty( $needs_approval ) ) {
            return;
        }

        // Set pending status
        update_user_meta( $user_id, 'vigilante_pending_approval', true );
        update_user_meta( $user_id, 'vigilante_pending_since', time() );

        // Log
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'user',
                'pending_approval',
                sprintf(
                    /* translators: %s: Username */
                    __( 'New user "%s" awaiting approval', 'vigilante' ),
                    $user->user_login
                ),
                array( 'user_id' => $user_id, 'email' => $user->user_email ),
                'info'
            );
        }

        // Notify admin
        if ( ! empty( $settings['notify_admin'] ) ) {
            $this->notify_admin_pending_user( $user );
        }
    }

    /**
     * Block pending users from logging in
     *
     * @param WP_User $user     User object.
     * @param string  $password Password.
     * @return WP_User|WP_Error
     */
    public function block_pending_user_login( $user, $password ) {
        if ( is_wp_error( $user ) ) {
            return $user;
        }

        $is_pending = get_user_meta( $user->ID, 'vigilante_pending_approval', true );

        if ( $is_pending ) {
            // Mark this as a controlled rejection (not a brute force attempt)
            add_filter( 'vigilante_skip_failed_login_count', '__return_true' );
            
            return new WP_Error(
                'pending_approval',
                __( '<strong>Account pending:</strong> Your account is awaiting administrator approval. You will receive an email once approved.', 'vigilante' )
            );
        }

        return $user;
    }

    /**
     * Show admin notice about pending users
     */
    public function show_pending_users_notice() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $pending_users = $this->get_pending_users();
        $count = count( $pending_users );

        if ( $count === 0 ) {
            return;
        }

        $screen = get_current_screen();
        if ( $screen && 'toplevel_page_vigilante' === $screen->id ) {
            return; // Don't show on Vigilante page, shown in UI
        }
        ?>
        <div class="notice notice-warning">
            <p>
                <?php
                printf(
                    /* translators: 1: Number of users, 2: Link to Vigilante */
                    esc_html( _n(
                        '%1$d user is awaiting approval. %2$s',
                        '%1$d users are awaiting approval. %2$s',
                        $count,
                        'vigilante'
                    ) ),
                    absint( $count ),
                    '<a href="' . esc_url( admin_url( 'admin.php?page=vigilante&tab=users' ) ) . '">' . esc_html__( 'Review in Vigilant', 'vigilante' ) . '</a>'
                );
                ?>
            </p>
        </div>
        <?php
    }

    /**
     * Get pending users
     *
     * @return array Array of pending user objects.
     */
    public function get_pending_users() {
        // phpcs:disable WordPress.DB.SlowDBQuery.slow_db_query_meta_key, WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- Limited results in admin context.
        $args = array(
            'meta_key'   => 'vigilante_pending_approval',
            'meta_value' => '1',
            'orderby'    => 'registered',
            'order'      => 'DESC',
        );
        // phpcs:enable WordPress.DB.SlowDBQuery.slow_db_query_meta_key, WordPress.DB.SlowDBQuery.slow_db_query_meta_value

        return get_users( $args );
    }

    /**
     * Approve a pending user
     *
     * @param int $user_id User ID.
     * @param int $approved_by Admin user ID who approved.
     * @return bool
     */
    public function approve_user( $user_id, $approved_by = 0 ) {
        $user = get_userdata( $user_id );
        if ( ! $user ) {
            return false;
        }

        delete_user_meta( $user_id, 'vigilante_pending_approval' );
        delete_user_meta( $user_id, 'vigilante_pending_since' );
        update_user_meta( $user_id, 'vigilante_approved_by', $approved_by );
        update_user_meta( $user_id, 'vigilante_approved_date', time() );

        // Log
        if ( $this->activity_log ) {
            $admin = $approved_by ? get_userdata( $approved_by ) : null;
            $this->activity_log->log(
                'user',
                'user_approved',
                sprintf(
                    /* translators: 1: Username, 2: Admin username */
                    __( 'User "%1$s" approved by %2$s', 'vigilante' ),
                    $user->user_login,
                    $admin ? $admin->user_login : __( 'System', 'vigilante' )
                ),
                array( 'user_id' => $user_id, 'approved_by' => $approved_by ),
                'info'
            );
        }

        // Send approval email
        $this->send_approval_email( $user );

        return true;
    }

    /**
     * Reject a pending user
     *
     * @param int    $user_id     User ID.
     * @param int    $rejected_by Admin user ID who rejected.
     * @param string $reason      Optional rejection reason.
     * @return bool
     */
    public function reject_user( $user_id, $rejected_by = 0, $reason = '' ) {
        $user = get_userdata( $user_id );
        if ( ! $user ) {
            return false;
        }

        // Log before deletion
        if ( $this->activity_log ) {
            $admin = $rejected_by ? get_userdata( $rejected_by ) : null;
            $this->activity_log->log(
                'user',
                'user_rejected',
                sprintf(
                    /* translators: 1: Username, 2: Admin username */
                    __( 'User "%1$s" rejected by %2$s', 'vigilante' ),
                    $user->user_login,
                    $admin ? $admin->user_login : __( 'System', 'vigilante' )
                ),
                array(
                    'user_id'     => $user_id,
                    'rejected_by' => $rejected_by,
                    'reason'      => $reason,
                    'email'       => $user->user_email,
                ),
                'warning'
            );
        }

        // Send rejection email before deleting
        $this->send_rejection_email( $user, $reason );

        // Delete user
        require_once ABSPATH . 'wp-admin/includes/user.php';
        return wp_delete_user( $user_id );
    }

    /**
     * Notify admin about pending user
     *
     * @param WP_User $user User object.
     */
    private function notify_admin_pending_user( $user ) {
        $recipients = Vigilante_Email_Template::get_admin_recipients();
        $site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] New user registration pending approval', 'vigilante' ),
            $site_name
        );

        $approve_url = admin_url( 'admin.php?page=vigilante&tab=users' );

        $body  = Vigilante_Email_Template::p( __( 'A new user has registered and is awaiting your approval.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::data_table( array(
            __( 'Username', 'vigilante' ) => $user->user_login,
            __( 'Email', 'vigilante' )    => $user->user_email,
        ) );
        $body .= Vigilante_Email_Template::button( $approve_url, __( 'Review registration', 'vigilante' ) );

        Vigilante_Email_Template::send( $recipients, $subject, __( 'New registration pending', 'vigilante' ), $body );
    }

    /**
     * Send approval email to user
     *
     * @param WP_User $user User object.
     */
    private function send_approval_email( $user ) {
        $site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

        // Generate password reset key so user can set their password
        $key = get_password_reset_key( $user );
        if ( is_wp_error( $key ) ) {
            // Fallback to simple login URL if key generation fails
            $action_url = wp_login_url();
            $action_text = __( 'You can now log in:', 'vigilante' );
        } else {
            $action_url = network_site_url( "wp-login.php?action=rp&key=$key&login=" . rawurlencode( $user->user_login ), 'login' );
            $action_text = __( 'Please set your password by clicking the link below:', 'vigilante' );
        }

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Your account has been approved', 'vigilante' ),
            $site_name
        );

        $body  = Vigilante_Email_Template::success_box(
            sprintf(
                /* translators: 1: Username, 2: Site name */
                __( 'Hello %1$s, great news! Your account on %2$s has been approved.', 'vigilante' ),
                $user->display_name,
                $site_name
            )
        );
        $body .= Vigilante_Email_Template::p( $action_text );
        $body .= Vigilante_Email_Template::button( $action_url, __( 'Set up your account', 'vigilante' ) );

        /**
         * Filters the approval email message
         *
         * @param string  $body Email HTML body.
         * @param WP_User $user User object.
         */
        $body = apply_filters( 'vigilante_approval_email_message', $body, $user );

        Vigilante_Email_Template::send( $user->user_email, $subject, __( 'Account approved', 'vigilante' ), $body );
    }

    /**
     * Send rejection email to user
     *
     * @param WP_User $user   User object.
     * @param string  $reason Rejection reason.
     */
    private function send_rejection_email( $user, $reason = '' ) {
        $site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Your registration was not approved', 'vigilante' ),
            $site_name
        );

        $body = Vigilante_Email_Template::p(
            sprintf(
                /* translators: 1: Username, 2: Site name */
                __( 'Hello %1$s, your registration on %2$s was not approved.', 'vigilante' ),
                $user->display_name,
                $site_name
            )
        );

        if ( ! empty( $reason ) ) {
            $body .= Vigilante_Email_Template::info_box(
                sprintf(
                    /* translators: %s: Reason */
                    __( 'Reason: %s', 'vigilante' ),
                    $reason
                )
            );
        }

        /**
         * Filters the rejection email message
         *
         * @param string  $body   Email HTML body.
         * @param WP_User $user   User object.
         * @param string  $reason Rejection reason.
         */
        $body = apply_filters( 'vigilante_rejection_email_message', $body, $user, $reason );

        Vigilante_Email_Template::send( $user->user_email, $subject, __( 'Registration not approved', 'vigilante' ), $body );
    }

    // =========================================================================
    // Session Management - View and revoke user sessions
    // =========================================================================

    /**
     * Check if user has sessions with corrupted format (numeric keys instead of hash keys)
     *
     * @param int $user_id User ID.
     * @return bool True if corrupted sessions found.
     */
    public function has_corrupted_sessions( $user_id ) {
        $all_sessions = get_user_meta( $user_id, 'session_tokens', true );
        
        if ( ! is_array( $all_sessions ) || empty( $all_sessions ) ) {
            return false;
        }

        foreach ( $all_sessions as $key => $session ) {
            // If any key is numeric or not a valid hash, sessions are corrupted
            if ( is_int( $key ) || ! is_string( $key ) || strlen( $key ) < 32 ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get raw session count (including corrupted ones)
     *
     * @param int $user_id User ID.
     * @return int Number of sessions in database.
     */
    public function get_raw_session_count( $user_id ) {
        $all_sessions = get_user_meta( $user_id, 'session_tokens', true );
        return is_array( $all_sessions ) ? count( $all_sessions ) : 0;
    }

    /**
     * Get user sessions with details
     *
     * @param int $user_id User ID.
     * @return array Array of sessions with details.
     */
    public function get_user_sessions( $user_id ) {
        // Get sessions directly from user meta to preserve keys
        $all_sessions = get_user_meta( $user_id, 'session_tokens', true );
        
        if ( ! is_array( $all_sessions ) || empty( $all_sessions ) ) {
            return array();
        }

        $formatted = array();
        foreach ( $all_sessions as $token_hash => $session ) {
            // Skip if token_hash is not a valid hash (should be 64 char hex string)
            if ( ! is_string( $token_hash ) || strlen( $token_hash ) < 32 ) {
                continue;
            }
            
            $formatted[] = array(
                'token_hash'  => $token_hash,
                'ip'          => $session['ip'] ?? __( 'Unknown', 'vigilante' ),
                'ua'          => $session['ua'] ?? __( 'Unknown', 'vigilante' ),
                'login'       => $session['login'] ?? 0,
                'expiration'  => $session['expiration'] ?? 0,
                'browser'     => $this->parse_user_agent( $session['ua'] ?? '' ),
                'is_current'  => $this->is_current_session( $token_hash ),
            );
        }

        return $formatted;
    }

    /**
     * Parse user agent string to get browser info
     *
     * @param string $ua User agent string.
     * @return string Browser name and version.
     */
    private function parse_user_agent( $ua ) {
        if ( empty( $ua ) ) {
            return __( 'Unknown browser', 'vigilante' );
        }

        $browser = __( 'Unknown browser', 'vigilante' );

        if ( strpos( $ua, 'Firefox' ) !== false ) {
            preg_match( '/Firefox\/([0-9.]+)/', $ua, $matches );
            $browser = 'Firefox ' . ( $matches[1] ?? '' );
        } elseif ( strpos( $ua, 'Edg/' ) !== false ) {
            preg_match( '/Edg\/([0-9.]+)/', $ua, $matches );
            $browser = 'Edge ' . ( $matches[1] ?? '' );
        } elseif ( strpos( $ua, 'Chrome' ) !== false ) {
            preg_match( '/Chrome\/([0-9.]+)/', $ua, $matches );
            $browser = 'Chrome ' . ( $matches[1] ?? '' );
        } elseif ( strpos( $ua, 'Safari' ) !== false ) {
            preg_match( '/Version\/([0-9.]+)/', $ua, $matches );
            $browser = 'Safari ' . ( $matches[1] ?? '' );
        } elseif ( strpos( $ua, 'MSIE' ) !== false || strpos( $ua, 'Trident' ) !== false ) {
            $browser = 'Internet Explorer';
        }

        // Add OS info
        $os = '';
        if ( strpos( $ua, 'Windows' ) !== false ) {
            $os = 'Windows';
        } elseif ( strpos( $ua, 'Mac OS' ) !== false ) {
            $os = 'macOS';
        } elseif ( strpos( $ua, 'Linux' ) !== false ) {
            $os = 'Linux';
        } elseif ( strpos( $ua, 'iPhone' ) !== false || strpos( $ua, 'iPad' ) !== false ) {
            $os = 'iOS';
        } elseif ( strpos( $ua, 'Android' ) !== false ) {
            $os = 'Android';
        }

        return $os ? "$browser ($os)" : $browser;
    }

    /**
     * Check if token is current session
     *
     * @param string $token_hash Session token hash.
     * @return bool
     */
    private function is_current_session( $token_hash ) {
        // Ensure token_hash is a valid string
        if ( ! is_string( $token_hash ) || empty( $token_hash ) ) {
            return false;
        }

        $cookie = wp_parse_auth_cookie( '', 'logged_in' );
        if ( ! $cookie || empty( $cookie['token'] ) ) {
            return false;
        }

        $current_hash = hash( 'sha256', $cookie['token'] );
        return hash_equals( $current_hash, $token_hash );
    }

    /**
     * Revoke a specific session
     *
     * @param int    $user_id    User ID.
     * @param string $token_hash Session token verifier.
     * @return bool
     */
    public function revoke_session( $user_id, $token_hash ) {
        // Check if this is the current user's current session - don't allow revoking it
        if ( get_current_user_id() === (int) $user_id ) {
            $current_token = wp_get_session_token();
            if ( $current_token ) {
                $current_verifier = hash( 'sha256', $current_token );
                if ( $current_verifier === $token_hash ) {
                    // Can't revoke your own current session
                    return false;
                }
            }
        }

        // Get sessions directly from user meta - bypass any caching
        wp_cache_delete( $user_id, 'user_meta' );
        $sessions = get_user_meta( $user_id, 'session_tokens', true );
        
        if ( ! is_array( $sessions ) || ! isset( $sessions[ $token_hash ] ) ) {
            return false;
        }

        // Remove the session
        unset( $sessions[ $token_hash ] );

        // Save back to user meta
        if ( empty( $sessions ) ) {
            delete_user_meta( $user_id, 'session_tokens' );
        } else {
            update_user_meta( $user_id, 'session_tokens', $sessions );
        }

        // Clear all related caches
        wp_cache_delete( $user_id, 'user_meta' );
        clean_user_cache( $user_id );

        // Log
        if ( $this->activity_log ) {
            $user = get_userdata( $user_id );
            $this->activity_log->log(
                'user',
                'session_revoked',
                sprintf(
                    /* translators: %s: Username */
                    __( 'Session revoked for user "%s"', 'vigilante' ),
                    $user ? $user->user_login : $user_id
                ),
                array( 'user_id' => $user_id ),
                'info'
            );
        }

        return true;
    }

    /**
     * Revoke all sessions except current
     *
     * @param int  $user_id         User ID.
     * @param bool $include_current Whether to revoke current session too.
     * @return int Number of sessions revoked.
     */
    public function revoke_all_sessions( $user_id, $include_current = false ) {
        $manager = WP_Session_Tokens::get_instance( $user_id );
        $all_sessions = $manager->get_all();
        $count = count( $all_sessions );

        if ( $count === 0 ) {
            return 0;
        }

        if ( $include_current ) {
            // Delete all sessions using WP native method
            $manager->destroy_all();
        } else {
            // For current user, use destroy_others which preserves current session
            if ( get_current_user_id() === $user_id ) {
                $current_token = wp_get_session_token();
                if ( $current_token ) {
                    $manager->destroy_others( $current_token );
                    $count--; // Don't count current session
                } else {
                    // No current token found, destroy all
                    $manager->destroy_all();
                }
            } else {
                // Admin revoking another user's sessions - destroy all of them
                $manager->destroy_all();
            }
        }

        // Log
        if ( $this->activity_log && $count > 0 ) {
            $user = get_userdata( $user_id );
            $this->activity_log->log(
                'user',
                'all_sessions_revoked',
                sprintf(
                    /* translators: 1: Number of sessions, 2: Username */
                    __( '%1$d sessions revoked for user "%2$s"', 'vigilante' ),
                    $count,
                    $user ? $user->user_login : $user_id
                ),
                array( 'user_id' => $user_id, 'count' => $count ),
                'info'
            );
        }

        return max( 0, $count );
    }

    /**
     * Check session limit before login completes (for block_new behavior)
     *
     * @param WP_User $user     User object.
     * @param string  $password Password.
     * @return WP_User|WP_Error
     */
    public function check_session_limit_before_login( $user, $password ) {
        if ( is_wp_error( $user ) ) {
            return $user;
        }

        $settings = $this->options['session_limits'] ?? array();
        $max_sessions = absint( $settings['max_sessions'] ?? 3 );
        $exclude_admins = ! empty( $settings['exclude_admins'] );

        // Skip admins if excluded
        if ( $exclude_admins && user_can( $user, 'administrator' ) ) {
            return $user;
        }

        $sessions = WP_Session_Tokens::get_instance( $user->ID );
        $all_sessions = $sessions->get_all();
        $session_count = count( $all_sessions );

        // Block if already at or over limit
        if ( $session_count >= $max_sessions ) {
            // Log
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'user',
                    'session_limit_blocked',
                    sprintf(
                        /* translators: 1: Username, 2: Max sessions */
                        __( 'Login blocked for "%1$s" - too many active sessions (limit: %2$d)', 'vigilante' ),
                        $user->user_login,
                        $max_sessions
                    ),
                    array( 'user_id' => $user->ID, 'current_sessions' => $session_count, 'limit' => $max_sessions ),
                    'warning'
                );
            }

            // Mark this as a controlled rejection (not a brute force attempt)
            add_filter( 'vigilante_skip_failed_login_count', '__return_true' );

            return new WP_Error(
                'session_limit_exceeded',
                sprintf(
                    /* translators: %d: Maximum sessions allowed */
                    __( '<strong>Session limit:</strong> You have too many active sessions (%d). Please log out from another device first, or contact an administrator.', 'vigilante' ),
                    $max_sessions
                )
            );
        }

        return $user;
    }

    /**
     * Enforce session limit on login
     *
     * @param string  $user_login Username.
     * @param WP_User $user       User object.
     */
    public function enforce_session_limit( $user_login, $user ) {
        $settings = $this->options['session_limits'] ?? array();
        $max_sessions = absint( $settings['max_sessions'] ?? 3 );
        $behavior = $settings['behavior'] ?? 'block_new';
        $exclude_admins = ! empty( $settings['exclude_admins'] );

        // Skip admins if excluded
        if ( $exclude_admins && user_can( $user, 'administrator' ) ) {
            return;
        }

        $sessions = WP_Session_Tokens::get_instance( $user->ID );
        $all_sessions = $sessions->get_all();
        $session_count = count( $all_sessions );

        // Check if over limit (accounting for the session just created)
        if ( $session_count <= $max_sessions ) {
            return;
        }

        if ( 'close_oldest' === $behavior ) {
            // Sort by login time and destroy oldest
            uasort( $all_sessions, function( $a, $b ) {
                return ( $a['login'] ?? 0 ) - ( $b['login'] ?? 0 );
            } );

            $sessions_to_remove = $session_count - $max_sessions;
            $removed = 0;

            foreach ( $all_sessions as $token_hash => $session ) {
                if ( $removed >= $sessions_to_remove ) {
                    break;
                }
                // Don't remove current session
                if ( ! $this->is_current_session( $token_hash ) ) {
                    $sessions->destroy( $token_hash );
                    $removed++;
                }
            }

            // Log
            if ( $this->activity_log && $removed > 0 ) {
                $this->activity_log->log(
                    'user',
                    'session_limit_enforced',
                    sprintf(
                        /* translators: 1: Number of sessions, 2: Username */
                        __( '%1$d oldest sessions closed for user "%2$s" (session limit: %3$d)', 'vigilante' ),
                        $removed,
                        $user->user_login,
                        $max_sessions
                    ),
                    array( 'user_id' => $user->ID, 'removed' => $removed, 'limit' => $max_sessions ),
                    'info'
                );
            }
        }
        // Note: 'block_new' behavior is handled in check_session_limit_before_login
    }

    // =========================================================================
    // Password Expiration - Force password change after X days
    // =========================================================================

    /**
     * Check password expiration on login
     *
     * @param string  $user_login Username.
     * @param WP_User $user       User object.
     */
    public function check_password_expiration( $user_login, $user ) {
        if ( $this->is_password_expired( $user->ID ) ) {
            // Set flag to force password change
            update_user_meta( $user->ID, 'vigilante_must_change_password', true );
        }
    }

    /**
     * Show password expiration warning notice
     */
    public function show_password_expiration_notice() {
        if ( ! is_user_logged_in() ) {
            return;
        }

        $user_id = get_current_user_id();
        $settings = $this->options['password_expiration'] ?? array();

        // Honor both affected_roles AND the per-user exclusion list, and
        // clear stale flags if the user no longer matches the rules.
        if ( ! $this->is_password_expiration_applicable( $user_id ) ) {
            if ( get_user_meta( $user_id, 'vigilante_must_change_password', true ) ) {
                delete_user_meta( $user_id, 'vigilante_must_change_password' );
            }
            return;
        }

        // Check if must change password
        $must_change = get_user_meta( $user_id, 'vigilante_must_change_password', true );
        if ( $must_change ) {
            ?>
            <div class="notice notice-error">
                <p>
                    <strong><?php esc_html_e( 'Password Expired', 'vigilante' ); ?></strong>
                    <?php
                    printf(
                        /* translators: %s: Link to profile */
                        esc_html__( 'Your password has expired. Please %s now.', 'vigilante' ),
                        '<a href="' . esc_url( admin_url( 'profile.php' ) ) . '">' . esc_html__( 'change your password', 'vigilante' ) . '</a>'
                    );
                    ?>
                </p>
            </div>
            <?php
            return;
        }

        // Show warning if expiring soon
        $days_left = $this->get_days_until_expiration( $user_id );
        $warning_days = absint( $settings['warning_days'] ?? 14 );

        if ( $days_left > 0 && $days_left <= $warning_days ) {
            ?>
            <div class="notice notice-warning is-dismissible">
                <p>
                    <?php
                    printf(
                        /* translators: 1: Number of days, 2: Link to profile */
                        esc_html( _n(
                            'Your password will expire in %1$d day. Please %2$s.',
                            'Your password will expire in %1$d days. Please %2$s.',
                            $days_left,
                            'vigilante'
                        ) ),
                        absint( $days_left ),
                        '<a href="' . esc_url( admin_url( 'profile.php' ) ) . '">' . esc_html__( 'change it now', 'vigilante' ) . '</a>'
                    );
                    ?>
                </p>
            </div>
            <?php
        }
    }

    /**
     * Force redirect to password change page
     */
    public function force_password_change_redirect() {
        if ( ! is_user_logged_in() ) {
            return;
        }

        // Don't redirect on AJAX or profile page
        if ( wp_doing_ajax() ) {
            return;
        }

        global $pagenow;
        if ( 'profile.php' === $pagenow ) {
            return;
        }

        $user_id = get_current_user_id();
        $must_change = get_user_meta( $user_id, 'vigilante_must_change_password', true );

        if ( ! $must_change ) {
            return;
        }

        // Re-validate against current settings: the admin may have removed
        // this user's role from affected_roles or added the user to the
        // excluded list after the flag was set. Without this check the flag
        // outlives the configuration change and locks the user in a redirect
        // loop into profile.php.
        if ( ! $this->is_password_expiration_applicable( $user_id ) ) {
            delete_user_meta( $user_id, 'vigilante_must_change_password' );
            return;
        }

        wp_safe_redirect( admin_url( 'profile.php#password' ) );
        exit;
    }

    /**
     * Whether password expiration rules currently apply to a given user
     *
     * Used to detect stale flags after the admin changes affected_roles or
     * the per-user exclusion list.
     *
     * @param int $user_id User ID.
     * @return bool
     */
    private function is_password_expiration_applicable( $user_id ) {
        $settings = $this->options['password_expiration'] ?? array();

        if ( empty( $settings['enabled'] ) ) {
            return false;
        }

        $affected_roles = $settings['affected_roles'] ?? array( 'administrator', 'editor' );
        $excluded_users = array_map( 'absint', $settings['excluded_users'] ?? array() );
        $user = get_userdata( $user_id );

        if ( ! $user || ! array_intersect( $user->roles, $affected_roles ) ) {
            return false;
        }

        if ( in_array( (int) $user_id, $excluded_users, true ) ) {
            return false;
        }

        return true;
    }

    /**
     * Update password change date when password is changed
     *
     * @param int     $user_id       User ID.
     * @param WP_User $old_user_data Old user data.
     */
    public function update_password_change_date( $user_id, $old_user_data ) {
        // Check if password was changed
        $user = get_userdata( $user_id );
        if ( $user->user_pass !== $old_user_data->user_pass ) {
            update_user_meta( $user_id, 'vigilante_password_changed', time() );
            delete_user_meta( $user_id, 'vigilante_must_change_password' );
            delete_user_meta( $user_id, 'vigilante_password_reminder_sent' );

            // Store password hash in history
            $this->add_password_to_history( $user_id, $user->user_pass );
        }
    }

    /**
     * Send password expiry reminder emails (daily cron)
     *
     * Sends a single reminder per user when they enter the warning period.
     * Uses vigilante_password_reminder_sent meta to avoid duplicates.
     */
    public function send_password_expiry_reminders() {
        $settings       = $this->options['password_expiration'] ?? array();
        $affected_roles = $settings['affected_roles'] ?? array( 'administrator', 'editor' );
        $excluded_users = array_map( 'absint', $settings['excluded_users'] ?? array() );
        $warning_days   = absint( $settings['warning_days'] ?? 14 );

        if ( empty( $affected_roles ) ) {
            return;
        }

        $args = array(
            'role__in' => $affected_roles,
            'fields'   => 'ID',
        );

        if ( ! empty( $excluded_users ) ) {
            // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- Small admin-curated exclusion list.
            $args['exclude'] = $excluded_users;
        }

        $users = get_users( $args );

        foreach ( $users as $user_id ) {
            // Skip if reminder already sent for this cycle
            if ( get_user_meta( $user_id, 'vigilante_password_reminder_sent', true ) ) {
                continue;
            }

            $days_left = $this->get_days_until_expiration( $user_id );

            // Send when user enters the warning window
            if ( $days_left > 0 && $days_left <= $warning_days ) {
                $this->send_single_password_reminder( $user_id, $days_left );
                update_user_meta( $user_id, 'vigilante_password_reminder_sent', time() );
            }
        }
    }

    /**
     * Send password expiry reminder to a single user
     *
     * @param int $user_id   User ID.
     * @param int $days_left Days until password expires.
     */
    private function send_single_password_reminder( $user_id, $days_left ) {
        $user = get_userdata( $user_id );
        if ( ! $user ) {
            return;
        }

        $site_name = get_bloginfo( 'name' );

        $subject = sprintf(
            /* translators: 1: Site name, 2: Number of days */
            __( '[%1$s] Your password expires in %2$d days', 'vigilante' ),
            $site_name,
            $days_left
        );

        $body  = Vigilante_Email_Template::p(
            sprintf(
                /* translators: 1: User display name, 2: Number of days */
                __( 'Hi %1$s, your password on this site will expire in %2$d days.', 'vigilante' ),
                $user->display_name,
                $days_left
            )
        );
        $body .= Vigilante_Email_Template::p(
            __( 'Please update your password before it expires to avoid any interruptions.', 'vigilante' )
        );
        $body .= Vigilante_Email_Template::button(
            admin_url( 'profile.php#password' ),
            __( 'Change your password', 'vigilante' )
        );

        Vigilante_Email_Template::send( $user->user_email, $subject, __( 'Password expiry reminder', 'vigilante' ), $body );
    }

    /**
     * Check if an admin password was changed and send alert
     *
     * Hooked independently of password_expiration so monitoring
     * works even without expiration enabled.
     *
     * @param int     $user_id       User ID.
     * @param WP_User $old_user_data Previous user data.
     */
    public function check_admin_password_change( $user_id, $old_user_data ) {
        $user = get_userdata( $user_id );
        if ( ! $user || $user->user_pass === $old_user_data->user_pass ) {
            return;
        }

        if ( ! user_can( $user, 'administrator' ) ) {
            return;
        }

        $current_user_id = get_current_user_id();
        $changed_by_self = ( $current_user_id === $user_id );

        $this->send_admin_monitoring_alert(
            'admin_password_change',
            $changed_by_self
                ? sprintf(
                    /* translators: %s: Username */
                    __( 'Administrator "%s" changed their password', 'vigilante' ),
                    $user->user_login
                )
                : sprintf(
                    /* translators: 1: Target username, 2: Actor username */
                    __( 'Password changed for administrator "%1$s" by "%2$s"', 'vigilante' ),
                    $user->user_login,
                    $current_user_id ? get_userdata( $current_user_id )->user_login : __( 'System', 'vigilante' )
                ),
            array(
                'user_id'         => $user_id,
                'username'        => $user->user_login,
                'changed_by'      => $current_user_id,
                'changed_by_self' => $changed_by_self,
            )
        );
    }

    /**
     * Set initial password change date for new users
     *
     * @param int $user_id User ID.
     */
    public function set_initial_password_date( $user_id ) {
        update_user_meta( $user_id, 'vigilante_password_changed', time() );
    }

    /**
     * Check if new password is in history
     *
     * @param WP_Error $errors Error object.
     * @param bool     $update Whether this is an update.
     * @param WP_User  $user   User object.
     */
    public function check_password_history( $errors, $update, $user ) {
        if ( ! $update ) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( empty( $_POST['pass1'] ) ) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $new_password = sanitize_text_field( wp_unslash( $_POST['pass1'] ) );
        $settings = $this->options['password_expiration'] ?? array();
        $history_count = absint( $settings['password_history'] ?? 3 );

        if ( $history_count === 0 ) {
            return;
        }

        $history = get_user_meta( $user->ID, 'vigilante_password_history', true );
        if ( ! is_array( $history ) ) {
            return;
        }

        // Check if new password matches any in history
        foreach ( array_slice( $history, 0, $history_count ) as $old_hash ) {
            if ( wp_check_password( $new_password, $old_hash ) ) {
                $errors->add(
                    'password_reused',
                    sprintf(
                        /* translators: %d: Number of passwords */
                        __( 'You cannot reuse your last %d passwords. Please choose a different password.', 'vigilante' ),
                        $history_count
                    )
                );
                return;
            }
        }
    }

    /**
     * Add password to history
     *
     * @param int    $user_id       User ID.
     * @param string $password_hash Password hash.
     */
    private function add_password_to_history( $user_id, $password_hash ) {
        $settings = $this->options['password_expiration'] ?? array();
        $history_count = absint( $settings['password_history'] ?? 3 );

        if ( $history_count === 0 ) {
            return;
        }

        $history = get_user_meta( $user_id, 'vigilante_password_history', true );
        if ( ! is_array( $history ) ) {
            $history = array();
        }

        // Add new password to beginning
        array_unshift( $history, $password_hash );

        // Keep only the required number
        $history = array_slice( $history, 0, $history_count + 1 );

        update_user_meta( $user_id, 'vigilante_password_history', $history );
    }

    /**
     * Check if user's password is expired
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function is_password_expired( $user_id ) {
        $settings = $this->options['password_expiration'] ?? array();

        if ( empty( $settings['enabled'] ) ) {
            return false;
        }

        $affected_roles = $settings['affected_roles'] ?? array( 'administrator', 'editor' );
        $excluded_users = array_map( 'absint', $settings['excluded_users'] ?? array() );
        $user = get_userdata( $user_id );

        if ( ! $user || ! array_intersect( $user->roles, $affected_roles ) ) {
            return false;
        }

        if ( in_array( (int) $user_id, $excluded_users, true ) ) {
            return false;
        }

        $expire_days = absint( $settings['expire_days'] ?? 90 );
        $last_change = get_user_meta( $user_id, 'vigilante_password_changed', true );

        // If no record, set it now (first time)
        if ( ! $last_change ) {
            update_user_meta( $user_id, 'vigilante_password_changed', time() );
            return false;
        }

        $days_since_change = ( time() - $last_change ) / DAY_IN_SECONDS;

        return $days_since_change > $expire_days;
    }

    /**
     * Get days until password expires
     *
     * @param int $user_id User ID.
     * @return int Days until expiration, -1 if not applicable.
     */
    public function get_days_until_expiration( $user_id ) {
        $settings = $this->options['password_expiration'] ?? array();

        if ( empty( $settings['enabled'] ) ) {
            return -1;
        }

        $affected_roles = $settings['affected_roles'] ?? array( 'administrator', 'editor' );
        $excluded_users = array_map( 'absint', $settings['excluded_users'] ?? array() );
        $user = get_userdata( $user_id );

        if ( ! $user || ! array_intersect( $user->roles, $affected_roles ) ) {
            return -1;
        }

        if ( in_array( (int) $user_id, $excluded_users, true ) ) {
            return -1;
        }

        $expire_days = absint( $settings['expire_days'] ?? 90 );
        $last_change = get_user_meta( $user_id, 'vigilante_password_changed', true );

        if ( ! $last_change ) {
            return $expire_days;
        }

        $days_since_change = ( time() - $last_change ) / DAY_IN_SECONDS;
        $days_left = $expire_days - $days_since_change;

        return max( 0, floor( $days_left ) );
    }

    // =========================================================================
    // Email Verification - Require email verification before login
    // =========================================================================

    /**
     * Send verification email to new user
     *
     * @param int $user_id User ID.
     */
    public function send_verification_email( $user_id ) {
        $user = get_userdata( $user_id );
        if ( ! $user ) {
            return;
        }

        // Generate verification token
        $token = wp_generate_password( 32, false );
        $token_hash = wp_hash( $token );

        $settings = $this->options['email_verification'] ?? array();
        $expiry_hours = absint( $settings['token_expiry_hours'] ?? 24 );
        $expires = time() + ( $expiry_hours * HOUR_IN_SECONDS );

        // Store token
        update_user_meta( $user_id, 'vigilante_verification_token', $token_hash );
        update_user_meta( $user_id, 'vigilante_verification_expires', $expires );
        update_user_meta( $user_id, 'vigilante_email_verified', false );

        // Build verification URL
        $verify_url = add_query_arg(
            array(
                'vigilante_verify' => '1',
                'user_id'          => $user_id,
                'token'            => $token,
            ),
            wp_login_url()
        );

        $site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Please verify your email address', 'vigilante' ),
            $site_name
        );

        $body  = Vigilante_Email_Template::p(
            sprintf(
                /* translators: 1: Username, 2: Site name */
                __( 'Hello %1$s, thank you for registering on %2$s.', 'vigilante' ),
                $user->display_name,
                $site_name
            )
        );
        $body .= Vigilante_Email_Template::p( __( 'Please verify your email address by clicking the button below.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::button( $verify_url, __( 'Verify email address', 'vigilante' ) );
        $body .= Vigilante_Email_Template::small(
            sprintf(
                /* translators: %d: Expiry hours */
                __( 'This link will expire in %d hours. If you did not create this account, please ignore this email.', 'vigilante' ),
                $expiry_hours
            )
        );

        /**
         * Filters the verification email body
         *
         * @param string  $body       Email HTML body.
         * @param WP_User $user       User object.
         * @param string  $verify_url Verification URL.
         */
        $body = apply_filters( 'vigilante_verification_email_message', $body, $user, $verify_url );

        Vigilante_Email_Template::send( $user->user_email, $subject, __( 'Email verification', 'vigilante' ), $body );

        // Log
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'user',
                'verification_email_sent',
                sprintf(
                    /* translators: %s: Username */
                    __( 'Verification email sent to user "%s"', 'vigilante' ),
                    $user->user_login
                ),
                array( 'user_id' => $user_id, 'email' => $user->user_email ),
                'info'
            );
        }
    }

    /**
     * Block unverified users from logging in
     *
     * @param WP_User $user     User object.
     * @param string  $password Password.
     * @return WP_User|WP_Error
     */
    public function block_unverified_user_login( $user, $password ) {
        if ( is_wp_error( $user ) ) {
            return $user;
        }

        // Check if email is verified
        $verified = get_user_meta( $user->ID, 'vigilante_email_verified', true );

        // If no meta exists, user was created before this feature - allow
        if ( '' === $verified ) {
            return $user;
        }

        if ( ! $verified ) {
            $settings = $this->options['email_verification'] ?? array();
            $allow_resend = ! empty( $settings['allow_resend'] );

            $message = __( '<strong>Email not verified:</strong> Please verify your email address before logging in.', 'vigilante' );

            if ( $allow_resend ) {
                $resend_url = wp_nonce_url(
                    add_query_arg(
                        array(
                            'vigilante_resend' => '1',
                            'user_id'          => $user->ID,
                        ),
                        wp_login_url()
                    ),
                    'vigilante_resend_verification_' . $user->ID,
                    '_vigilante_nonce'
                );
                $message .= ' <a href="' . esc_url( $resend_url ) . '">' . __( 'Resend verification email', 'vigilante' ) . '</a>';
            }

            return new WP_Error( 'email_not_verified', $message );
        }

        return $user;
    }

    /**
     * Handle email verification link
     */
    public function handle_email_verification() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only checking parameter presence for branching, no data modification.
        if ( empty( $_GET['vigilante_verify'] ) ) {
            // Check for resend request  -  user_id is read before wp_verify_nonce()
            // because the nonce action is user-specific. Nonce verified immediately after.
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce verified below after extracting user_id for the action string.
            if ( ! empty( $_GET['vigilante_resend'] ) && ! empty( $_GET['user_id'] ) ) {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce verified on the next line using this value.
                $user_id = absint( $_GET['user_id'] );

                // Verify nonce to prevent CSRF and user-ID probing.
                if ( ! isset( $_GET['_vigilante_nonce'] ) ||
                     ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_vigilante_nonce'] ) ), 'vigilante_resend_verification_' . $user_id ) ) {
                    wp_safe_redirect( add_query_arg( 'vigilante_message', 'invalid', wp_login_url() ) );
                    exit;
                }

                // Rate limiting: allow 1 resend every 5 minutes per user to prevent email spam.
                $transient_key = 'vigilante_resend_' . $user_id;
                if ( false === get_transient( $transient_key ) ) {
                    $this->send_verification_email( $user_id );
                    set_transient( $transient_key, 1, 5 * MINUTE_IN_SECONDS );
                }

                wp_safe_redirect( add_query_arg( 'vigilante_message', 'resent', wp_login_url() ) );
                exit;
            }
            return;
        }

        // Email verification uses a cryptographic token instead of a nonce,
        // since nonces are session-bound and expire  -  unsuitable for email links.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- token-based verification below.
        $user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- token-based verification below.
        $token = isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( $_GET['token'] ) ) : '';

        if ( ! $user_id || ! $token ) {
            wp_safe_redirect( add_query_arg( 'vigilante_message', 'invalid', wp_login_url() ) );
            exit;
        }

        $stored_hash = get_user_meta( $user_id, 'vigilante_verification_token', true );
        $expires = get_user_meta( $user_id, 'vigilante_verification_expires', true );

        // Check expiration
        if ( time() > $expires ) {
            wp_safe_redirect( add_query_arg( 'vigilante_message', 'expired', wp_login_url() ) );
            exit;
        }

        // Verify token
        if ( ! hash_equals( $stored_hash, wp_hash( $token ) ) ) {
            wp_safe_redirect( add_query_arg( 'vigilante_message', 'invalid', wp_login_url() ) );
            exit;
        }

        // Mark as verified
        update_user_meta( $user_id, 'vigilante_email_verified', true );
        delete_user_meta( $user_id, 'vigilante_verification_token' );
        delete_user_meta( $user_id, 'vigilante_verification_expires' );

        $user = get_userdata( $user_id );

        // Log
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'user',
                'email_verified',
                sprintf(
                    /* translators: %s: Username */
                    __( 'Email verified for user "%s"', 'vigilante' ),
                    $user ? $user->user_login : $user_id
                ),
                array( 'user_id' => $user_id ),
                'info'
            );
        }

        // Check if user still needs approval
        $is_pending = get_user_meta( $user_id, 'vigilante_pending_approval', true );

        if ( $is_pending ) {
            // User verified but still pending approval
            wp_safe_redirect(
                add_query_arg(
                    array(
                        'vigilante_registration' => 'verified_pending',
                        '_vigilante_nonce'       => wp_create_nonce( 'vigilante_registration_redirect' ),
                    ),
                    wp_login_url()
                )
            );
            exit;
        }

        // No approval needed - send password setup email
        if ( $user ) {
            $this->send_password_setup_email( $user );
        }

        wp_safe_redirect( add_query_arg( 'vigilante_message', 'verified', wp_login_url() ) );
        exit;
    }

    /**
     * Show verification message on login page
     *
     * @param string $message Login message.
     * @return string
     */
    public function show_verification_message( $message ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( empty( $_GET['vigilante_message'] ) ) {
            return $message;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $status = sanitize_key( $_GET['vigilante_message'] );

        switch ( $status ) {
            case 'verified':
                $message = '<p class="message">' . esc_html__( 'Your email has been verified! Check your inbox for an email with instructions to set your password.', 'vigilante' ) . '</p>';
                break;
            case 'invalid':
                $message = '<p class="message" style="border-left-color: #d63638;">' . esc_html__( 'Invalid verification link.', 'vigilante' ) . '</p>';
                break;
            case 'expired':
                $message = '<p class="message" style="border-left-color: #d63638;">' . esc_html__( 'Verification link has expired. Please request a new one.', 'vigilante' ) . '</p>';
                break;
            case 'resent':
                $message = '<p class="message">' . esc_html__( 'Verification email has been resent. Please check your inbox.', 'vigilante' ) . '</p>';
                break;
        }

        return $message;
    }

    /**
     * Check if user email is verified
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function is_email_verified( $user_id ) {
        $verified = get_user_meta( $user_id, 'vigilante_email_verified', true );
        
        // If no meta exists, consider verified (old users)
        if ( '' === $verified ) {
            return true;
        }

        return (bool) $verified;
    }

    /* =========================================================================
       REGISTRATION FLOW CONTROL
       ========================================================================= */

    /**
     * Suppress WordPress new user notification email when our modules are active.
     * We control when the password setup email is sent.
     *
     * @param array   $email   Email parameters.
     * @param WP_User $user    User object.
     * @param string  $blogname Site name.
     * @return array|false Empty array to suppress, or original to send.
     */
    public function suppress_new_user_email( $email, $user, $blogname ) {
        $registration_approval = $this->options['registration_approval'] ?? array();
        $email_verification = $this->options['email_verification'] ?? array();

        // Check if this user's role requires approval
        $needs_approval = false;
        if ( ! empty( $registration_approval['enabled'] ) ) {
            $affected_roles = $registration_approval['affected_roles'] ?? array( 'subscriber' );
            $needs_approval = ! empty( array_intersect( $user->roles, $affected_roles ) );
        }

        // Check if email verification is enabled
        $needs_verification = ! empty( $email_verification['enabled'] );

        // Suppress WP email if either module applies to this user
        if ( $needs_approval || $needs_verification ) {
            // Return false to completely suppress the email
            return false;
        }

        return $email;
    }

    /**
     * Redirect after registration to show appropriate message.
     *
     * @param string $redirect_to Redirect URL.
     * @return string Modified redirect URL.
     */
    public function custom_registration_redirect( $redirect_to ) {
        $registration_approval = $this->options['registration_approval'] ?? array();
        $email_verification = $this->options['email_verification'] ?? array();

        $approval_enabled = ! empty( $registration_approval['enabled'] );
        $verification_enabled = ! empty( $email_verification['enabled'] );

        // Determine which message to show
        if ( $verification_enabled && $approval_enabled ) {
            $message = 'registered_verify_then_approval';
        } elseif ( $verification_enabled ) {
            $message = 'registered_verify';
        } elseif ( $approval_enabled ) {
            $message = 'registered_pending';
        } else {
            return $redirect_to;
        }

        return add_query_arg(
            array(
                'vigilante_registration' => $message,
                '_vigilante_nonce'       => wp_create_nonce( 'vigilante_registration_redirect' ),
            ),
            wp_login_url()
        );
    }

    /**
     * Show registration pending message on login page.
     *
     * @param string $message Existing message.
     * @return string Modified message.
     */
    public function show_registration_pending_message( $message ) {
        // Verify nonce from the registration redirect before processing GET data.
        if ( ! isset( $_GET['_vigilante_nonce'] ) ||
             ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_vigilante_nonce'] ) ), 'vigilante_registration_redirect' ) ) {
            return $message;
        }

        if ( empty( $_GET['vigilante_registration'] ) ) {
            return $message;
        }

        $status = sanitize_key( $_GET['vigilante_registration'] );

        switch ( $status ) {
            case 'registered_verify':
                $message = '<p class="message">' . 
                    esc_html__( 'Registration complete! Please check your email to verify your address before you can log in.', 'vigilante' ) . 
                    '</p>';
                break;

            case 'registered_pending':
                $message = '<p class="message">' . 
                    esc_html__( 'Registration complete! Your account is pending approval by an administrator. You will receive an email once approved.', 'vigilante' ) . 
                    '</p>';
                break;

            case 'registered_verify_then_approval':
                $message = '<p class="message">' . 
                    esc_html__( 'Registration complete! Please check your email to verify your address. Once verified, your account will be reviewed by an administrator.', 'vigilante' ) . 
                    '</p>';
                break;

            case 'verified_pending':
                $message = '<p class="message">' . 
                    esc_html__( 'Email verified! Your account is now pending approval by an administrator. You will receive an email once approved.', 'vigilante' ) . 
                    '</p>';
                break;
        }

        return $message;
    }

    /**
     * Check if user needs approval (based on role settings).
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function user_needs_approval( $user_id ) {
        $user = get_userdata( $user_id );
        if ( ! $user ) {
            return false;
        }

        $registration_approval = $this->options['registration_approval'] ?? array();
        if ( empty( $registration_approval['enabled'] ) ) {
            return false;
        }

        $affected_roles = $registration_approval['affected_roles'] ?? array( 'subscriber' );
        return ! empty( array_intersect( $user->roles, $affected_roles ) );
    }

    /**
     * Send password setup email to user.
     * This is sent when the user is ready to set their password (after verification/approval).
     *
     * @param WP_User $user User object.
     */
    public function send_password_setup_email( $user ) {
        $site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

        // Generate password reset key
        $key = get_password_reset_key( $user );
        if ( is_wp_error( $key ) ) {
            return;
        }

        $reset_url = network_site_url( "wp-login.php?action=rp&key=$key&login=" . rawurlencode( $user->user_login ), 'login' );

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Set up your password', 'vigilante' ),
            $site_name
        );

        $body  = Vigilante_Email_Template::p(
            sprintf(
                /* translators: 1: Username, 2: Site name */
                __( 'Hello %1$s, your account on %2$s is now active.', 'vigilante' ),
                $user->display_name,
                $site_name
            )
        );
        $body .= Vigilante_Email_Template::p( __( 'Please set your password by clicking the button below.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::button( $reset_url, __( 'Set your password', 'vigilante' ) );
        $body .= Vigilante_Email_Template::small( __( 'If you did not create this account, please ignore this email.', 'vigilante' ) );

        /**
         * Filters the password setup email body
         *
         * @param string  $body      Email HTML body.
         * @param WP_User $user      User object.
         * @param string  $reset_url Password reset URL.
         */
        $body = apply_filters( 'vigilante_password_setup_email_message', $body, $user, $reset_url );

        Vigilante_Email_Template::send( $user->user_email, $subject, __( 'Set up your password', 'vigilante' ), $body );

        // Log
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'user',
                'password_setup_email_sent',
                sprintf(
                    /* translators: %s: Username */
                    __( 'Password setup email sent to user "%s"', 'vigilante' ),
                    $user->user_login
                ),
                array( 'user_id' => $user->ID, 'email' => $user->user_email ),
                'info'
            );
        }
    }
}