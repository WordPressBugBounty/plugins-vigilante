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
     * @param Vigilante_Settings     $settings         Settings instance.
     * @param Vigilante_Activity_Log $activity_log     Activity log instance.
     * @param bool                   $enforcement_only Register only what enforces
     *                                                 state already written to an
     *                                                 account. See
     *                                                 init_enforcement_hooks().
     */
    public function __construct( $settings, $activity_log, $enforcement_only = false ) {
        $this->settings     = $settings;
        $this->activity_log = $activity_log;
        $this->options      = $settings->get_section( 'user_security' );

        if ( $enforcement_only ) {
            $this->init_enforcement_hooks();
            return;
        }

        $this->init_hooks();
    }

    /**
     * The hooks that enforce state already written to an account
     *
     * A forced password reset and a registration waiting for approval are not
     * settings, they are marks on somebody's account, and the action that wrote
     * them already happened: sessions destroyed, emails sent, the activity log
     * saying those accounts cannot get in until they reset or are approved.
     *
     * Until 2.11.10 both were registered inside the module gate, so turning User
     * Security off let every one of those accounts back in with their old
     * password, silently and with the flags still in place saying the opposite.
     * The forced reset is deliberately not destructive on the password (see
     * force_password_reset(), which avoids wp_set_password() so the reset link
     * keeps working), so this filter was the only thing holding the door.
     * Found by the file-by-file review of 2.11.10.
     *
     * These two are therefore registered whether the module is on or off. Both
     * return immediately when the account carries no mark, so the cost on a site
     * that never used either feature is one meta read at login.
     *
     * @since 2.11.10
     */
    private function init_enforcement_hooks() {
        add_filter( 'authenticate', array( $this, 'check_force_reset_on_login' ), 30, 3 );
        add_action( 'after_password_reset', array( $this, 'clear_force_reset_meta' ), 10, 1 );
        add_filter( 'wp_authenticate_user', array( $this, 'block_pending_user_login' ), 15, 2 );
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
        add_action( 'wp_ajax_vigilante_dismiss_insecure_warning', array( $this, 'ajax_dismiss_insecure_warning' ) );

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
            // The blocking half is registered by init_enforcement_hooks(), so an
            // account already waiting keeps waiting if the feature is turned off.
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
            // Enforcement beyond wp-admin: REST and the front end, so an expired
            // password cannot keep operating outside the redirect (2.11.9).
            add_filter( 'rest_authentication_errors', array( $this, 'block_expired_password_rest' ), 20 );
            add_action( 'template_redirect', array( $this, 'force_password_change_frontend' ) );
            add_filter( 'authenticate', array( $this, 'block_expired_password_xmlrpc' ), 30, 1 );
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

        // What enforces marks already written to an account, which stays
        // registered even with the module off. See init_enforcement_hooks().
        $this->init_enforcement_hooks();
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

        // Find insecure accounts first; if there are none there is nothing to warn
        // about and we skip any further state read.
        $found_users = $this->get_insecure_users();

        if ( empty( $found_users ) ) {
            return;
        }

        // The warning is a standing reminder, so it always shows on the Dashboard
        // (index.php). On every other admin screen it is dismissible per
        // administrator, but the dismissal records WHICH insecure usernames were
        // present when it was closed: closing it silences only those. If a new
        // insecure account shows up later, the warning comes back instead of
        // staying hidden forever. The Dashboard always shows it while the issue
        // remains unresolved.
        global $pagenow;
        $is_dashboard = ( 'index.php' === $pagenow );

        if ( ! $is_dashboard ) {
            $dismissed = get_user_meta( get_current_user_id(), 'vigilante_dismissed_insecure_users', true );
            $dismissed = is_array( $dismissed ) ? $dismissed : array();

            // Stay hidden only while every currently-found user was already dismissed.
            if ( empty( array_diff( $found_users, $dismissed ) ) ) {
                return;
            }
        }

        $escaped_users  = array_map( 'esc_html', $found_users );
        $usernames_html = '<code>' . implode( '</code>, <code>', $escaped_users ) . '</code>';
        ?>
        <div class="notice notice-error is-dismissible" data-vigilante-notice="insecure_users">
            <p>
                <strong><?php esc_html_e( 'Security Alert!', 'vigilante' ); ?></strong>
            </p>
            <p>
                <?php
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
        <script>
        ( function () {
            var notice = document.querySelector( '.notice[data-vigilante-notice="insecure_users"]' );
            if ( ! notice ) {
                return;
            }
            // The dismiss button is injected by core after load, so delegate from
            // the notice element and persist the dismissal for this user.
            notice.addEventListener( 'click', function ( e ) {
                if ( ! e.target || ! e.target.classList.contains( 'notice-dismiss' ) ) {
                    return;
                }
                var data = new FormData();
                data.append( 'action', 'vigilante_dismiss_insecure_warning' );
                data.append( 'nonce', '<?php echo esc_js( wp_create_nonce( 'vigilante_dismiss_insecure_warning' ) ); ?>' );
                if ( navigator.sendBeacon ) {
                    navigator.sendBeacon( ajaxurl, data );
                } else {
                    var xhr = new XMLHttpRequest();
                    xhr.open( 'POST', ajaxurl, true );
                    xhr.send( data );
                }
            } );
        } )();
        </script>
        <?php
    }

    /**
     * Persist per-user dismissal of the insecure-usernames warning.
     *
     * Stores the set of insecure usernames present at dismissal time, so the
     * warning stays hidden for this admin only while those exact accounts remain;
     * a new insecure account brings it back. It still re-appears on the Dashboard.
     */
    public function ajax_dismiss_insecure_warning() {
        check_ajax_referer( 'vigilante_dismiss_insecure_warning', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error();
        }

        update_user_meta( get_current_user_id(), 'vigilante_dismissed_insecure_users', $this->get_insecure_users() );

        wp_send_json_success();
    }

    /**
     * List the insecure-by-name accounts currently present.
     *
     * @return string[] Matching logins.
     */
    private function get_insecure_users() {
        $priority_usernames = array( 'admin', 'administrator', 'root', 'test', 'user', 'guest', 'info', 'sysadmin', 'webmaster' );
        $found              = array();

        foreach ( $priority_usernames as $username ) {
            if ( get_user_by( 'login', $username ) ) {
                $found[] = $username;
            }
        }

        return $found;
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

        // Nothing to enforce unless the display name being saved equals the login.
        if ( strcasecmp( $display_name, $user_data->user_login ) !== 0 ) {
            return;
        }

        // The display name equals the login, which is the unsafe state we want to
        // prevent (it exposes the login publicly). Block it — EXCEPT when this same
        // save is also changing the password. That is the forced password-change
        // flow for a legacy "display == login" account: aborting it would dead-lock
        // the change (the password never updates and the user is bounced on every
        // load). WordPress exposes the new plaintext password as $user->user_pass
        // during this hook, so a value different from the stored hash means a
        // password change is in progress; in that case we let the save through.
        $changing_password = isset( $user->user_pass ) && '' !== $user->user_pass && $user->user_pass !== $user_data->user_pass;
        if ( $changing_password ) {
            return;
        }

        $errors->add(
            'display_name_login_match',
            __( '<strong>Error</strong>: Your display name cannot be the same as your login username. The display name is publicly visible and would expose your login credentials.', 'vigilante' )
        );
    }

    /**
     * Validate password strength
     *
     * @param WP_Error $errors Error object.
     * @param bool     $update Whether this is an update.
     * @param WP_User  $user   User object.
     */
    public function validate_password_strength( $errors, $update, $user ) {
        // During user_profile_update_errors WordPress exposes the new password
        // (still plaintext, only slashed) as $user->user_pass. Reading it from the
        // object instead of $_POST keeps this validator free of input/nonce sniffs
        // AND avoids sanitizing the password: sanitize_text_field() would strip
        // "<...>", tabs and repeated spaces, mismeasure the value and wrongly reject
        // valid passwords, aborting a forced change and leaving the old one active.
        if ( ! isset( $user->user_pass ) || '' === $user->user_pass ) {
            return;
        }

        $username = isset( $user->user_login ) ? $user->user_login : '';
        $roles    = array();

        if ( $update && isset( $user->ID ) ) {
            $user_data = get_userdata( $user->ID );
            if ( $user_data ) {
                // On a profile save that doesn't touch the password, user_pass is
                // still the stored hash, not a new plaintext value: nothing to check.
                if ( $user->user_pass === $user_data->user_pass ) {
                    return;
                }
                $username = $user_data->user_login;
                $roles    = $user_data->roles;
            }
        } elseif ( ! empty( $user->role ) ) {
            // New account created from wp-admin: the chosen role is on the object.
            $roles = array( $user->role );
        }

        if ( ! empty( $roles ) && ! $this->password_policy_applies( $roles ) ) {
            return;
        }

        $password        = (string) wp_unslash( $user->user_pass );
        $strength_errors = $this->check_password_strength( $password, $username );

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

        // Registration runs on a public form with no $user object carrying the
        // password, so it must read $_POST. Unlike the profile path there is no
        // "saved but unrecognized" trap here (the account isn't created until the
        // password passes), so the mild mismeasure sanitize_text_field() can cause
        // on exotic characters is an acceptable trade for not suppressing a
        // security sniff on a public endpoint.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $password = sanitize_text_field( wp_unslash( $_POST['user_pass'] ) );

        // New registrations receive the site's default role; skip enforcement if
        // the policy is scoped to roles that don't include it.
        if ( ! $this->password_policy_applies( array( get_option( 'default_role', 'subscriber' ) ) ) ) {
            return $errors;
        }

        $strength_errors = $this->check_password_strength( $password, $sanitized_user_login );

        foreach ( $strength_errors as $error ) {
            $errors->add( 'weak_password', $error );
        }

        return $errors;
    }

    /**
     * Read the granular password policy merged with safe defaults.
     *
     * Defaults reproduce the historical all-requirements behaviour so a site
     * upgrading from before the policy existed keeps the same rules.
     *
     * @return array
     */
    private function get_password_policy() {
        return wp_parse_args(
            $this->options['password_policy'] ?? array(),
            array(
                'require_uppercase' => true,
                'require_lowercase' => true,
                'require_number'    => true,
                'require_special'   => true,
                'block_common'      => true,
                'block_username'    => false,
                'affected_roles'    => array(),
            )
        );
    }

    /**
     * Whether the password policy applies to a user with the given roles.
     *
     * @param array $roles Role slugs.
     * @return bool
     */
    private function password_policy_applies( $roles ) {
        $affected = (array) ( $this->get_password_policy()['affected_roles'] );

        // Empty list = apply to every role.
        if ( empty( $affected ) ) {
            return true;
        }

        return (bool) array_intersect( (array) $roles, $affected );
    }

    /**
     * Check password strength against the configured policy
     *
     * @param string $password Password to check.
     * @param string $username Login name, for the "don't contain username" rule.
     * @return array Array of error messages (empty if password is strong).
     */
    public function check_password_strength( $password, $username = '' ) {
        $errors     = array();
        $min_length = absint( $this->options['min_password_length'] ?? 12 );
        $policy     = $this->get_password_policy();

        // Check length
        if ( strlen( $password ) < $min_length ) {
            $errors[] = sprintf(
                /* translators: %d: Minimum password length */
                __( 'Password must be at least %d characters long.', 'vigilante' ),
                $min_length
            );
        }

        // Character-class requirements (each one is individually optional)
        if ( ! empty( $policy['require_uppercase'] ) && ! preg_match( '/[A-Z]/', $password ) ) {
            $errors[] = __( 'Password must contain at least one uppercase letter.', 'vigilante' );
        }

        if ( ! empty( $policy['require_lowercase'] ) && ! preg_match( '/[a-z]/', $password ) ) {
            $errors[] = __( 'Password must contain at least one lowercase letter.', 'vigilante' );
        }

        if ( ! empty( $policy['require_number'] ) && ! preg_match( '/[0-9]/', $password ) ) {
            $errors[] = __( 'Password must contain at least one number.', 'vigilante' );
        }

        if ( ! empty( $policy['require_special'] ) && ! preg_match( '/[^a-zA-Z0-9]/', $password ) ) {
            $errors[] = __( 'Password must contain at least one special character.', 'vigilante' );
        }

        // Don't allow the username inside the password. Guard on a minimum
        // username length so trivial 1-3 char logins don't reject everything.
        if ( ! empty( $policy['block_username'] ) && '' !== $username
            && strlen( $username ) >= 4 && false !== stripos( $password, $username ) ) {
            $errors[] = __( 'Password must not contain your username.', 'vigilante' );
        }

        // Check for common passwords
        if ( ! empty( $policy['block_common'] ) ) {
            $common_passwords = array(
                'password', '123456', '12345678', 'qwerty', 'abc123',
                'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
                'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
                'bailey', 'passw0rd', 'shadow', '123123', '654321',
            );

            if ( in_array( strtolower( $password ), $common_passwords, true ) ) {
                $errors[] = __( 'This password is too common. Please choose a more unique password.', 'vigilante' );
            }
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
            'skipped'     => 0,
            'emails_sent' => 0,
            'total'       => count( $user_ids ),
        );

        foreach ( $user_ids as $user_id ) {
            // The caller only proved it holds manage_options, which on a network
            // every subsite administrator has. Resetting somebody else's password
            // locks them out, so each target is checked one by one. Skipped users
            // are counted apart from real failures.
            if ( ! current_user_can( 'edit_user', $user_id ) ) {
                $results['skipped']++;
                continue;
            }

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

        // Set pending status, on this site only (see site_user_meta_key()).
        update_user_meta( $user_id, self::site_user_meta_key( 'vigilante_pending_approval' ), true );
        update_user_meta( $user_id, self::site_user_meta_key( 'vigilante_pending_since' ), time() );

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

        if ( self::is_pending_anywhere( $user->ID ) ) {
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
                    '<a href="' . esc_url( admin_url( 'admin.php?page=vigilante&tab=users#vigilante-section-users-pending' ) ) . '">' . esc_html__( 'Review in Vigilant', 'vigilante' ) . '</a>'
                );
                ?>
            </p>
        </div>
        <?php
    }

    /**
     * A user meta key that belongs to one site, even on a network
     *
     * Registration approval is a per-site setting, but user meta is network
     * wide, so a single global key made the pending queue shared: an
     * administrator of one site saw, approved and rejected accounts waiting on
     * another, and clearing the flag cleared it for the whole network. Reported
     * by the wp.org automated review of 2.11.9.
     *
     * On a network the key carries the blog prefix, the way core does with
     * capabilities (wp_2_capabilities), so each site keeps its own queue. On a
     * single site the key is returned unchanged, so nothing has to be migrated
     * there and the stored data of every existing install keeps working.
     *
     * @since 2.11.10
     *
     * Note the default is null and not 0: wpdb::get_blog_prefix() reads null as
     * "the current blog", and 0 as the main site, so passing 0 here gave every
     * subsite the key of the main site and kept the queue shared. Caught by
     * matriz-red-repaso-21110.sh before this shipped.
     *
     * @param string   $key     Base meta key.
     * @param int|null $blog_id Blog to build it for. Current blog when null.
     * @return string
     */
    public static function site_user_meta_key( $key, $blog_id = null ) {
        global $wpdb;

        if ( ! is_multisite() ) {
            return $key;
        }

        return $wpdb->get_blog_prefix( $blog_id ) . $key;
    }

    /**
     * Whether this account is waiting for approval on ANY site of the network
     *
     * The queue is per site and stays per site, because approving somebody is a
     * decision of the site they signed up to. Blocking them is a different
     * question with a different answer, and giving it the same one was a hole:
     * the session cookie WordPress issues is valid on every host of the network
     * (COOKIE_DOMAIN and COOKIEPATH, wp-includes/ms-default-constants.php:58-59
     * and :84-88), so an account held back on demo1 logged in through the main
     * site, where it carried no flag, and walked straight back into demo1 with
     * that cookie. Reproduced over HTTP by the second cross review of 2.11.10.
     * It is the same reasoning that two_factor_required_for() already applies:
     * network-wide cookie, network-wide enforcement.
     *
     * Read from the account's own meta in one pass rather than by asking site by
     * site, so the cost does not grow with the network. The legacy key with no
     * prefix is included because the migration that moves it runs on the first
     * admin page load and until then a waiting account has to keep being
     * blocked; reading both fails closed.
     *
     * @since 2.11.10
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public static function is_pending_anywhere( $user_id ) {
        global $wpdb;

        if ( get_user_meta( $user_id, 'vigilante_pending_approval', true ) ) {
            return true;
        }

        if ( ! is_multisite() ) {
            return false;
        }

        $all = get_user_meta( $user_id );

        if ( ! is_array( $all ) ) {
            return false;
        }

        $pattern = '/^' . preg_quote( $wpdb->base_prefix, '/' ) . '(\d+_)?vigilante_pending_approval$/';

        foreach ( $all as $key => $values ) {
            if ( ! preg_match( $pattern, $key, $m ) ) {
                continue;
            }

            /*
             * A mark left behind by a site that no longer exists asks nobody for
             * anything: deleting a subsite does not touch this plugin's user meta,
             * so the account stayed blocked on the whole network with no queue
             * anywhere to clear it from, in a plugin whose users have no WP-CLI.
             * Found by the third cross review of 2.11.10. get_site() is cached, so
             * this costs nothing in the usual case of no leftovers.
             */
            if ( ! empty( $m[1] ) && ! get_site( (int) rtrim( $m[1], '_' ) ) ) {
                continue;
            }

            foreach ( (array) $values as $value ) {
                if ( ! empty( $value ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get pending users
     *
     * The meta key is what scopes this list to the current site, so on a network
     * the query deliberately does not add the site's own membership filter on
     * top. Core's WP_User_Query turns the default into "{$prefix}capabilities
     * EXISTS" (wp-includes/class-wp-user-query.php:598-604), and an account that
     * is waiting for approval can perfectly well have no role yet: it then held
     * this site's flag, was blocked from logging in, and appeared in no queue at
     * all, so nobody could ever approve or reject it. Found by the second cross
     * review of 2.11.10.
     *
     * @return array Array of pending user objects.
     */
    public function get_pending_users() {
        // phpcs:disable WordPress.DB.SlowDBQuery.slow_db_query_meta_key, WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- Limited results in admin context.
        $args = array(
            'meta_key'   => self::site_user_meta_key( 'vigilante_pending_approval' ),
            'meta_value' => '1',
            'orderby'    => 'registered',
            'order'      => 'DESC',
        );
        // phpcs:enable WordPress.DB.SlowDBQuery.slow_db_query_meta_key, WordPress.DB.SlowDBQuery.slow_db_query_meta_value

        if ( is_multisite() ) {
            $args['blog_id'] = 0;
        }

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
        // Same reasoning as reject_user(): approving an account that never asked
        // for approval is a no-op that reports success and writes misleading meta.
        // Only this site's flag counts, so approving never clears the queue of
        // another site of the network (see site_user_meta_key()).
        if ( ! get_user_meta( $user_id, self::site_user_meta_key( 'vigilante_pending_approval' ), true ) ) {
            return false;
        }

        $user = get_userdata( $user_id );
        if ( ! $user ) {
            return false;
        }

        delete_user_meta( $user_id, self::site_user_meta_key( 'vigilante_pending_approval' ) );
        delete_user_meta( $user_id, self::site_user_meta_key( 'vigilante_pending_since' ) );
        // Por sitio como las dos de arriba: quien aprueba y cuando es un hecho de
        // la cola de ESTE sitio, y dejarlas globales hacia que una aprobacion
        // pisara el registro de otro (cierra B4 de la revision cruzada).
        update_user_meta( $user_id, self::site_user_meta_key( 'vigilante_approved_by' ), $approved_by );
        update_user_meta( $user_id, self::site_user_meta_key( 'vigilante_approved_date' ), time() );

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

        // Only an account actually waiting for approval may be rejected. Without
        // this the handler deletes any user id it is given, and wp_delete_user()
        // with no reassignment takes their posts with them, skipping the dialog
        // core always shows. Deleting a member is the Users screen's job.
        if ( ! get_user_meta( $user_id, self::site_user_meta_key( 'vigilante_pending_approval' ), true ) ) {
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

        /*
         * The mark goes first, because on a network the account may well survive
         * the deletion: wp_delete_user() only calls remove_user_from_blog() there
         * (wp-admin/includes/user.php:440-442), which clears the role and nothing
         * of this plugin's own meta. Leaving it behind made Reject a loop with no
         * way out: the account stayed blocked on every site of the network, the
         * row never left the queue (which since 2.11.10 no longer hides accounts
         * without a role), and pressing Reject again sent the rejection email once
         * more and reported success. Found by the third cross review of 2.11.10.
         */
        delete_user_meta( $user_id, self::site_user_meta_key( 'vigilante_pending_approval' ) );
        delete_user_meta( $user_id, self::site_user_meta_key( 'vigilante_pending_since' ) );

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

        $approve_url = admin_url( 'admin.php?page=vigilante&tab=users#vigilante-section-users-pending' );

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
     * Whether the session store this limit would act on belongs to a whole network
     *
     * WP_Session_Tokens keeps session_tokens in the usermeta table, which is
     * network wide, while this limit is configured per site. So on a network a
     * site administrator setting a low limit would count, and with close_oldest
     * close, the sessions the same user opened on other sites, including an
     * administrator session elsewhere; and block_new would refuse a login over
     * sessions that have nothing to do with this site. Reported by the wp.org
     * automated review of 2.11.9, on the close_oldest half.
     *
     * Until the network-wide policy of 3.1.0, the limit simply does not apply on
     * a network, and the settings screen says so. On a single site nothing
     * changes: there the session store and the setting cover the same thing.
     *
     * @since 2.11.10
     *
     * @return bool
     */
    public static function session_limit_is_network_wide() {
        return is_multisite();
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

        if ( self::session_limit_is_network_wide() ) {
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
        if ( self::session_limit_is_network_wide() ) {
            return;
        }

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
            /*
             * Remove the oldest sessions by editing the session store directly.
             *
             * WP_Session_Tokens::get_all() returns array_values( get_sessions() ),
             * so its keys are 0, 1, 2, not tokens, and destroy() expects a raw
             * token, which is not stored anywhere and cannot be recovered for a
             * session other than the current one. Until 2.11.9 the loop passed
             * those numeric keys to destroy(), which hashed them, matched nothing
             * and closed no session while still counting and logging success, so
             * the cap did nothing under close_oldest. Reported by the wp.org
             * automated review of 2.11.8.
             *
             * The store keeps the sessions as the user meta 'session_tokens',
             * keyed by the verifier hash( 'sha256', token ), which is the value
             * is_current_session() already compares against. So the oldest are
             * removed from that map, keeping the current session whatever its age.
             * On a network the meta is global (one finding of the multisite audit,
             * to be reworked in 3.1.0); here the fix is only to make the removal
             * actually happen.
             */
            $stored = get_user_meta( $user->ID, 'session_tokens', true );

            if ( ! is_array( $stored ) || empty( $stored ) ) {
                return;
            }

            $now     = time();
            $changed = false;

            // Expired sessions are dead weight and count for nothing; drop them first.
            foreach ( $stored as $verifier => $session ) {
                if ( isset( $session['expiration'] ) && (int) $session['expiration'] < $now ) {
                    unset( $stored[ $verifier ] );
                    $changed = true;
                }
            }

            // Oldest first, keeping the current session whatever its login time.
            uasort( $stored, function ( $a, $b ) {
                return ( $a['login'] ?? 0 ) <=> ( $b['login'] ?? 0 );
            } );

            $sessions_to_remove = count( $stored ) - $max_sessions;
            $removed            = 0;

            foreach ( $stored as $verifier => $session ) {
                if ( $removed >= $sessions_to_remove ) {
                    break;
                }
                if ( $this->is_current_session( $verifier ) ) {
                    continue;
                }
                unset( $stored[ $verifier ] );
                $removed++;
                $changed = true;
            }

            if ( $changed ) {
                update_user_meta( $user->ID, 'session_tokens', $stored );
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
            // Only on a single site, for the same reason as in
            // force_password_change_redirect(): on a network the flag belongs to
            // the account, and this site's policy says nothing about the site
            // that set it. The 2.11.8 fix only covered that method, and this
            // notice cleared the flag anyway on the next admin page; found by
            // the cross review of 2.11.8.
            if ( ! is_multisite() && get_user_meta( $user_id, 'vigilante_must_change_password', true ) ) {
                delete_user_meta( $user_id, 'vigilante_must_change_password' );
            }
            return;
        }

        // Check if must change password
        $must_change = get_user_meta( $user_id, 'vigilante_must_change_password', true );
        if ( $must_change ) {
            global $pagenow;
            $on_profile = ( 'profile.php' === $pagenow );
            ?>
            <div class="notice notice-error">
                <p>
                    <strong><?php esc_html_e( 'Password change required', 'vigilante' ); ?></strong>
                    <?php if ( $on_profile ) : ?>
                        <?php esc_html_e( 'Your password has expired. Set a new password in the section below and save your profile to continue.', 'vigilante' ); ?>
                    <?php else : ?>
                        <?php
                        printf(
                            /* translators: %s: Link to profile */
                            esc_html__( 'Your password has expired. Please %s now.', 'vigilante' ),
                            '<a href="' . esc_url( admin_url( 'profile.php#password' ) ) . '">' . esc_html__( 'change your password', 'vigilante' ) . '</a>'
                        );
                        ?>
                    <?php endif; ?>
                </p>
                <?php if ( $on_profile ) : ?>
                    <p>
                        <?php esc_html_e( 'Important: your password is only changed once the profile saves with no errors. If any other error is shown above (for example, your display name cannot match your username), fix it as well — otherwise your new password will not be saved and you will keep being asked to change it.', 'vigilante' ); ?>
                    </p>
                <?php endif; ?>
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
     * Whether this user must change an expired password before doing anything else
     *
     * The flag alone is not enough: it is re-checked against the current policy,
     * because the admin may have taken the user's role out of affected_roles or
     * added the user to the exclusion list after it was set, which would
     * otherwise lock them in a redirect loop. A stale flag is cleared on a
     * single site; on a network the meta is shared by every site and the policy
     * checked is only this site's, so it is left alone and simply not enforced
     * here (a network-wide rework is the 3.1.0 multisite item).
     *
     * @since 2.11.9
     *
     * @param int $user_id User ID.
     * @return bool
     */
    private function must_change_password( $user_id ) {
        if ( ! $user_id ) {
            return false;
        }

        $flagged = (bool) get_user_meta( $user_id, 'vigilante_must_change_password', true );

        if ( ! $this->is_password_expiration_applicable( $user_id ) ) {
            if ( $flagged && ! is_multisite() ) {
                delete_user_meta( $user_id, 'vigilante_must_change_password' );
            }
            return false;
        }

        if ( $flagged ) {
            return true;
        }

        // The flag is set at interactive login (check_password_expiration on
        // wp_login). A session that authenticates only through REST, XML-RPC or
        // an application password never fires wp_login, so the flag can be
        // absent while the password is in fact expired. Compute it on the fly
        // too, so a non-interactive route is not a way around the block. The
        // computation self-seeds the change date on first sight and never locks
        // out a user who has no record yet (see is_password_expired()).
        return $this->is_password_expired( $user_id );
    }

    /**
     * Force a user with an expired password to change it, on wp-admin and AJAX
     *
     * Until 2.11.9 this only redirected wp-admin pages and skipped AJAX, so an
     * expired-password session kept working through admin-ajax, and the REST API
     * and the front end were not covered at all. The wp.org automated review of
     * 2.11.8 flagged it: setting a flag on login is not enforcement if the flag
     * is only read by one redirect. It is now enforced on every entry point,
     * here for wp-admin and AJAX and in the three methods below for REST, the
     * front end and XML-RPC. The only thing an affected user can still do is
     * change the password on profile.php or log out.
     */
    public function force_password_change_redirect() {
        if ( ! is_user_logged_in() || ! $this->must_change_password( get_current_user_id() ) ) {
            return;
        }

        // AJAX: a redirect is useless, so the request is refused. Changing the
        // password is a profile.php form POST, not AJAX, so nothing the user
        // needs to fix this is blocked.
        if ( wp_doing_ajax() ) {
            wp_send_json_error(
                array( 'message' => __( 'Your password has expired. Change it in your profile before continuing.', 'vigilante' ) ),
                403
            );
        }

        // profile.php is where the change happens; do not redirect it onto itself.
        global $pagenow;
        if ( 'profile.php' === $pagenow ) {
            return;
        }

        wp_safe_redirect( admin_url( 'profile.php#password' ) );
        exit;
    }

    /**
     * Refuse REST API requests from a user whose password has expired
     *
     * @since 2.11.9
     *
     * @param WP_Error|null|true $result Result of the earlier authentication checks.
     * @return WP_Error|null|true
     */
    public function block_expired_password_rest( $result ) {
        // Leave any decision another check already made, and do not act on
        // logged-out requests to public endpoints.
        if ( null !== $result && false !== $result ) {
            return $result;
        }

        if ( is_user_logged_in() && $this->must_change_password( get_current_user_id() ) ) {
            return new WP_Error(
                'vigilante_password_expired',
                __( 'Your password has expired. Change it in your profile before using the REST API.', 'vigilante' ),
                array( 'status' => 403 )
            );
        }

        return $result;
    }

    /**
     * Send a user with an expired password to the change page from the front end
     *
     * @since 2.11.9
     */
    public function force_password_change_frontend() {
        if ( is_admin() || ! is_user_logged_in() || ! $this->must_change_password( get_current_user_id() ) ) {
            return;
        }

        wp_safe_redirect( admin_url( 'profile.php#password' ) );
        exit;
    }

    /**
     * Refuse XML-RPC calls from a user whose password has expired
     *
     * The last of the four non-wp-admin entry points. XML-RPC authenticates on
     * every call with the account credentials (a password or an application
     * password), so a session that never touches wp-admin could keep acting
     * through xmlrpc.php while the password sits expired. Scoped to XML-RPC
     * requests so an ordinary login, which the user needs to reach profile.php,
     * is never blocked here. Runs late on authenticate, after core and the
     * application-password handler have resolved the user.
     *
     * @since 2.11.9
     *
     * @param WP_User|WP_Error|null $user Result of the earlier authentication.
     * @return WP_User|WP_Error|null
     */
    public function block_expired_password_xmlrpc( $user ) {
        if ( ! ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
            return $user;
        }

        if ( $user instanceof WP_User && $this->must_change_password( $user->ID ) ) {
            return new WP_Error(
                'vigilante_password_expired',
                __( 'Your password has expired. Change it in your profile before using XML-RPC.', 'vigilante' ),
                array( 'status' => 403 )
            );
        }

        return $user;
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

        // Asking for IDs only means WordPress never primes the usermeta cache, so
        // every get_user_meta() below would hit the database once per user. On a
        // site with many users in these roles that is one query per user, every day.
        if ( ! empty( $users ) ) {
            cache_users( $users );
        }

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
        if ( ! $update || ! isset( $user->ID ) ) {
            return;
        }

        // Read the new password from $user->user_pass (set by WordPress during this
        // hook), not from $_POST: no input/nonce sniff and, crucially, no sanitizing
        // — wp_check_password() must test the exact string WordPress stores, or the
        // reuse check would compare a mangled value and silently miss matches.
        if ( ! isset( $user->user_pass ) || '' === $user->user_pass ) {
            return;
        }

        // Profile save that doesn't change the password: user_pass is still the
        // stored hash, so there is no new value to compare.
        $user_data = get_userdata( $user->ID );
        if ( $user_data && $user->user_pass === $user_data->user_pass ) {
            return;
        }

        $new_password = (string) wp_unslash( $user->user_pass );
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
        /*
         * Never send an account that is already verified back to pending. The
         * resend link below reaches this, and while the pending value was
         * unreadable (see the note on the meta write) that was harmless; with
         * the check working, resending for a verified account would lock its
         * owner out of their own site.
         */
        if ( metadata_exists( 'user', $user_id, 'vigilante_email_verified' )
            && get_user_meta( $user_id, 'vigilante_email_verified', true )
        ) {
            return;
        }

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

        /*
         * '0' and not false. update_user_meta() stores false as an empty string
         * (maybe_serialize() returns it unchanged and wpdb writes it with %s), and
         * an empty string is what get_user_meta() also returns when there is no
         * row at all. So from the moment this feature existed until 2.11.10 the
         * value written to mean "not verified yet" was read back as "this account
         * predates the feature, let it in", and the branch that blocks the login
         * was unreachable. Found by the file-by-file review of 2.11.10. '0' is
         * falsy in PHP and survives the round trip, and the readers below tell an
         * absent row from a stored one with metadata_exists().
         */
        update_user_meta( $user_id, 'vigilante_email_verified', '0' );

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

        /*
         * Only a row that does not exist means "created before this feature".
         * An existing row holding an empty string is an account that older
         * versions marked as pending, and it has to be blocked like any other:
         * reading both the same way is what made this check let everyone in
         * (see send_verification_email()).
         */
        if ( ! metadata_exists( 'user', $user->ID, 'vigilante_email_verified' ) ) {
            return $user;
        }

        $verified = get_user_meta( $user->ID, 'vigilante_email_verified', true );

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
                    /*
                     * Nothing is redirected to the login page until the request
                     * has proved something, and a bad nonce proves nothing. It
                     * used to answer with a redirect to wp_login_url(), which
                     * under a custom login URL IS the secret address, so any
                     * visitor could read it out of the Location header of a
                     * request carrying garbage. Found by the third cross review
                     * of 2.11.10. Returning leaves the request to render the page
                     * it asked for, which tells nobody anything.
                     */
                    return;
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

        // Same as the resend above: no proof, no redirect, so the Location
        // header cannot be used to read the custom login URL.
        if ( ! $user_id || ! $token ) {
            return;
        }

        $stored_hash = (string) get_user_meta( $user_id, 'vigilante_verification_token', true );
        $expires     = (int) get_user_meta( $user_id, 'vigilante_verification_expires', true );

        // The token first. Checking the expiry before it answered "expired" for
        // any account with no verification pending and "invalid" for one waiting,
        // so a wrong link revealed which user ids were waiting (2.11.8). Only the
        // holder of the right token learns that it expired.
        if ( '' === $stored_hash || ! hash_equals( $stored_hash, wp_hash( $token ) ) ) {
            return;
        }

        if ( time() > $expires ) {
            wp_safe_redirect( add_query_arg( 'vigilante_message', 'expired', wp_login_url() ) );
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

        // Anywhere on the network, so the message matches what will actually
        // happen at the login: that is what blocks (see is_pending_anywhere()).
        if ( self::is_pending_anywhere( $user_id ) ) {
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
        // Same reading as block_unverified_user_login(): only an absent row means
        // the account predates the feature. A stored empty string is an account
        // an older version left pending.
        if ( ! metadata_exists( 'user', $user_id, 'vigilante_email_verified' ) ) {
            return true;
        }

        $verified = get_user_meta( $user_id, 'vigilante_email_verified', true );

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