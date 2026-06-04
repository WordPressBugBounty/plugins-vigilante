<?php
/**
 * Two-Factor Email Authentication Class
 *
 * Handles email-based two-factor authentication for WordPress login
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Two_Factor_Email
 *
 * Email OTP verification for login security
 */
class Vigilante_Two_Factor_Email {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Database instance
     *
     * @var Vigilante_Database
     */
    private $database;

    /**
     * Activity log instance
     *
     * @var Vigilante_Activity_Log
     */
    private $activity_log;

    /**
     * Login security instance
     *
     * @var Vigilante_Login_Security|null
     */
    private $login_security;

    /**
     * 2FA options
     *
     * @var array
     */
    private $options;

    /**
     * Session key for pending verification
     *
     * @var string
     */
    const SESSION_KEY = 'vigilante_2fa_pending';

    /**
     * Constructor
     *
     * @param Vigilante_Settings           $settings       Settings instance.
     * @param Vigilante_Database           $database       Database instance.
     * @param Vigilante_Activity_Log       $activity_log   Activity log instance.
     * @param Vigilante_Login_Security|null $login_security Login security instance (optional).
     */
    public function __construct( $settings, $database, $activity_log, $login_security = null ) {
        $this->settings       = $settings;
        $this->database       = $database;
        $this->activity_log   = $activity_log;
        $this->login_security = $login_security;
        
        $login_options  = $settings->get_section( 'login_security' );
        $this->options  = $login_options['two_factor'] ?? array();

        if ( $this->is_enabled() ) {
            $this->init_hooks();
        }
    }

    /**
     * Check if 2FA is enabled
     *
     * @return bool
     */
    public function is_enabled() {
        if ( empty( $this->options['enabled'] ) ) {
            return false;
        }
        // Only active when method is email (or not set, for backward compatibility)
        $method = $this->options['method'] ?? 'email';
        return 'email' === $method;
    }

    /**
     * Initialize hooks
     */
    private function init_hooks() {
        // Intercept successful authentication
        add_filter( 'authenticate', array( $this, 'check_2fa_requirement' ), 100, 3 );
        
        // Handle 2FA verification form
        add_action( 'login_form_vigilante_2fa', array( $this, 'handle_2fa_form' ) );
        
        // Add 2FA form to login page
        add_action( 'login_form', array( $this, 'maybe_show_2fa_form' ) );
        
        // Handle AJAX resend code
        add_action( 'wp_ajax_nopriv_vigilante_resend_2fa_code', array( $this, 'ajax_resend_code' ) );
        
        // Enqueue login styles
        add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_assets' ) );
        
        // Filter login error messages to hide default error when 2FA is pending
        add_filter( 'login_errors', array( $this, 'filter_login_errors' ), 100 );
    }

    /**
     * Filter login error messages
     * 
     * Hide the default "Invalid username or password" when 2FA verification is pending
     *
     * @param string $errors Error messages HTML.
     * @return string Filtered error messages
     */
    public function filter_login_errors( $errors ) {
        // Check if we have a pending 2FA session (try multiple methods)
        $user_id = $this->get_pending_user_id();
        
        if ( $user_id ) {
            // We're in 2FA mode, hide the default WordPress error
            // Clean up the trigger transient since cookie is now working
            $ip = $this->database->get_client_ip();
            delete_transient( 'vigilante_2fa_triggered_' . md5( $ip ) );
            return '';
        }
        
        // Also check if we just triggered 2FA (cookie might not be available yet)
        $ip = $this->database->get_client_ip();
        $just_triggered = get_transient( 'vigilante_2fa_triggered_' . md5( $ip ) );
        
        if ( $just_triggered ) {
            // Don't delete yet - might need it for the form display
            // It will expire in 60 seconds anyway
            return '';
        }
        
        return $errors;
    }

    /**
     * Check if user requires 2FA after successful password authentication
     *
     * @param WP_User|WP_Error $user     User object or error.
     * @param string          $username Username.
     * @param string          $password Password.
     * @return WP_User|WP_Error
     */
    public function check_2fa_requirement( $user, $username, $password ) {
        // Only process successful authentications
        if ( is_wp_error( $user ) || ! ( $user instanceof WP_User ) ) {
            return $user;
        }

        // Check if already verifying 2FA (form submission)
        if ( $this->is_2fa_verification_request() ) {
            return $user;
        }

        // Check if 2FA is required for this user
        if ( ! $this->user_requires_2fa( $user ) ) {
            return $user;
        }

        // Check if device is trusted
        if ( $this->is_device_trusted( $user->ID ) ) {
            return $user;
        }

        // Check if there's a very recent code (less than 60 seconds old) to avoid duplicate emails on rapid retries
        $existing_code = $this->database->get_2fa_code( $user->ID );
        $code_is_recent = $existing_code 
            && strtotime( $existing_code['expires_at'] ) > time() 
            && empty( $existing_code['used'] )
            && ( time() - strtotime( $existing_code['created_at'] ) ) < 60;
        
        if ( $code_is_recent ) {
            // Code was just sent, don't send another email
            $this->set_pending_verification( $user->ID );
            
            return new WP_Error(
                'vigilante_2fa_required',
                __( 'Please enter the verification code sent to your email.', 'vigilante' )
            );
        }

        // Delete any old codes for this user
        $this->database->delete_2fa_code( $user->ID );

        // Generate and send new verification code
        $code = $this->generate_code( $user->ID );
        $this->send_verification_email( $user, $code );

        // Store pending state
        $this->set_pending_verification( $user->ID );

        // Log code sent
        $this->log_event( '2fa_code_sent', $user->ID, __( 'Verification code sent via email', 'vigilante' ) );

        // Return error to stop login and show 2FA form
        return new WP_Error(
            'vigilante_2fa_required',
            __( 'Please enter the verification code sent to your email.', 'vigilante' )
        );
    }

    /**
     * Check if this is a 2FA verification request
     *
     * @return bool
     */
    private function is_2fa_verification_request() {
        // Check for our custom action
        $action = isset( $_REQUEST['action'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        return 'vigilante_2fa' === $action;
    }

    /**
     * Check if user requires 2FA
     *
     * @param WP_User $user User object.
     * @return bool
     */
    public function user_requires_2fa( $user ) {
        // Check if user is explicitly excluded
        $excluded_users = $this->options['excluded_users'] ?? array();
        if ( in_array( $user->ID, array_map( 'absint', $excluded_users ), true ) ) {
            return false;
        }

        // Check if user has an enforced role
        $enforced_roles = $this->options['enforced_roles'] ?? array( 'administrator', 'editor' );
        
        foreach ( $user->roles as $role ) {
            if ( in_array( $role, $enforced_roles, true ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate verification code
     *
     * @param int $user_id User ID.
     * @return string 6-digit code
     */
    private function generate_code( $user_id ) {
        // Generate secure 6-digit code
        $code = sprintf( '%06d', wp_rand( 0, 999999 ) );

        // Calculate expiry
        $expiry_minutes = absint( $this->options['code_expiry_minutes'] ?? 10 );
        $expires_at = gmdate( 'Y-m-d H:i:s', time() + ( $expiry_minutes * 60 ) );

        // Store in database
        $this->database->store_2fa_code( $user_id, $code, $expires_at );

        return $code;
    }

    /**
     * Send verification email
     *
     * @param WP_User $user User object.
     * @param string  $code Verification code.
     * @return bool
     */
    private function send_verification_email( $user, $code ) {
        $site_name = get_bloginfo( 'name' );
        $from_name = $this->options['email_from_name'] ?? '';
        
        if ( empty( $from_name ) ) {
            $from_name = $site_name;
        }

        $expiry_minutes = absint( $this->options['code_expiry_minutes'] ?? 10 );

        $subject = sprintf(
            /* translators: 1: Site name, 2: Verification code */
            __( '[%1$s] Your verification code: %2$s', 'vigilante' ),
            $site_name,
            $code
        );

        $body  = Vigilante_Email_Template::p( __( 'Your verification code is:', 'vigilante' ) );
        $body .= Vigilante_Email_Template::code_box( $code );
        $body .= Vigilante_Email_Template::small(
            sprintf(
                /* translators: %d: Minutes until code expires */
                __( 'This code is valid for %d minutes.', 'vigilante' ),
                $expiry_minutes
            )
        );
        $body .= Vigilante_Email_Template::small( __( 'If you did not attempt to log in, please ignore this message and consider changing your password.', 'vigilante' ) );

        // Use from_name via header (avoids filter contamination)
        $sent = Vigilante_Email_Template::send( $user->user_email, $subject, '', $body, false, $from_name );

        return $sent;
    }

    /**
     * Set pending verification state
     *
     * @param int $user_id User ID.
     * @return string Token for the pending session
     */
    private function set_pending_verification( $user_id ) {
        // Check if there's already a valid token for this user
        $existing_token = $this->get_existing_token_for_user( $user_id );
        
        if ( $existing_token ) {
            $token = $existing_token;
        } else {
            $token = wp_generate_password( 32, false );
        }
        
        set_transient( 
            'vigilante_2fa_pending_' . $token, 
            array(
                'user_id'    => $user_id,
                'created_at' => time(),
            ),
            HOUR_IN_SECONDS 
        );

        // Also store reverse lookup (user_id -> token)
        set_transient( 
            'vigilante_2fa_user_token_' . $user_id, 
            $token,
            HOUR_IN_SECONDS 
        );
        
        // Set a short-lived transient to indicate 2FA was just triggered
        // This helps filter_login_errors() detect 2FA mode before cookie is available
        $ip = $this->database->get_client_ip();
        set_transient( 'vigilante_2fa_triggered_' . md5( $ip ), $user_id, 60 );

        // Store token in cookie for form submission
        if ( ! headers_sent() ) {
            setcookie( 
                'vigilante_2fa_token', 
                $token, 
                array(
                    'expires'  => time() + HOUR_IN_SECONDS,
                    'path'     => COOKIEPATH,
                    'domain'   => COOKIE_DOMAIN,
                    'secure'   => is_ssl(),
                    'httponly' => true,
                    'samesite' => 'Strict',
                )
            );
            // Make token available in current request
            $_COOKIE['vigilante_2fa_token'] = $token;
        }
        
        return $token;
    }

    /**
     * Get existing token for a user if still valid
     *
     * @param int $user_id User ID.
     * @return string|false Token or false if not found
     */
    private function get_existing_token_for_user( $user_id ) {
        $token = get_transient( 'vigilante_2fa_user_token_' . $user_id );
        
        if ( ! $token ) {
            return false;
        }
        
        // Verify the token is still valid
        $data = get_transient( 'vigilante_2fa_pending_' . $token );
        
        if ( ! $data || empty( $data['user_id'] ) || absint( $data['user_id'] ) !== $user_id ) {
            return false;
        }
        
        return $token;
    }

    /**
     * Get pending verification user ID
     *
     * @return int|false User ID or false if not pending
     */
    private function get_pending_user_id() {
        // First try cookie
        $token = isset( $_COOKIE['vigilante_2fa_token'] ) ? sanitize_text_field( wp_unslash( $_COOKIE['vigilante_2fa_token'] ) ) : '';
        
        // Also check POST (for when cookie wasn't set in time)
        if ( empty( $token ) && isset( $_POST['vigilante_2fa_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $token = sanitize_text_field( wp_unslash( $_POST['vigilante_2fa_token'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
        }
        
        if ( empty( $token ) ) {
            return false;
        }

        $data = get_transient( 'vigilante_2fa_pending_' . $token );
        
        if ( ! $data || empty( $data['user_id'] ) ) {
            return false;
        }

        return absint( $data['user_id'] );
    }

    /**
     * Clear pending verification
     */
    private function clear_pending_verification() {
        $token = isset( $_COOKIE['vigilante_2fa_token'] ) ? sanitize_text_field( wp_unslash( $_COOKIE['vigilante_2fa_token'] ) ) : '';
        
        // Also check POST
        if ( empty( $token ) && isset( $_POST['vigilante_2fa_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $token = sanitize_text_field( wp_unslash( $_POST['vigilante_2fa_token'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
        }
        
        if ( ! empty( $token ) ) {
            // Get user ID to clear reverse lookup
            $data = get_transient( 'vigilante_2fa_pending_' . $token );
            if ( $data && ! empty( $data['user_id'] ) ) {
                delete_transient( 'vigilante_2fa_user_token_' . $data['user_id'] );
            }
            
            delete_transient( 'vigilante_2fa_pending_' . $token );
        }

        // Clear cookie
        if ( ! headers_sent() ) {
            setcookie( 
                'vigilante_2fa_token', 
                '', 
                array(
                    'expires'  => time() - YEAR_IN_SECONDS,
                    'path'     => COOKIEPATH,
                    'domain'   => COOKIE_DOMAIN,
                    'secure'   => is_ssl(),
                    'httponly' => true,
                    'samesite' => 'Strict',
                )
            );
        }
        
        unset( $_COOKIE['vigilante_2fa_token'] );
    }

    /**
     * Handle 2FA verification form submission
     */
    public function handle_2fa_form() {
        // Verify nonce
        if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'vigilante_2fa_verify' ) ) {
            return;
        }

        $user_id = $this->get_pending_user_id();
        
        if ( ! $user_id ) {
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        $code = isset( $_POST['vigilante_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['vigilante_2fa_code'] ) ) : '';
        $remember_device = ! empty( $_POST['vigilante_2fa_remember'] );

        // Verify code
        $result = $this->verify_code( $user_id, $code );

        if ( is_wp_error( $result ) ) {
            // Store error for display
            set_transient( 'vigilante_2fa_error_' . $user_id, $result->get_error_message(), 60 );
            
            // Redirect back to login
            wp_safe_redirect( add_query_arg( 'vigilante_2fa', '1', wp_login_url() ) );
            exit;
        }

        // Verification successful
        $this->clear_pending_verification();
        $this->database->mark_2fa_code_used( $user_id );

        // Trust device if requested
        if ( $remember_device ) {
            $this->trust_device( $user_id );
            $this->log_event( '2fa_device_trusted', $user_id, __( 'Device saved as trusted', 'vigilante' ) );
        }

        // Log success
        $this->log_event( '2fa_verification_success', $user_id, __( 'Two-factor verification successful', 'vigilante' ) );

        // Complete login
        $user = get_user_by( 'ID', $user_id );
        wp_set_current_user( $user_id, $user->user_login );
        wp_set_auth_cookie( $user_id, false );
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- wp_login is a WordPress core hook that must be fired on login.
        do_action( 'wp_login', $user->user_login, $user );

        // Redirect to admin dashboard (always use admin_url to avoid issues with popups, 
        // malformed URLs, or query parameters that could cause problems)
        wp_safe_redirect( admin_url() );
        exit;
    }

    /**
     * Verify the submitted code
     *
     * @param int    $user_id User ID.
     * @param string $code    Submitted code.
     * @return true|WP_Error
     */
    private function verify_code( $user_id, $code ) {
        $stored = $this->database->get_2fa_code( $user_id );
        $user   = get_user_by( 'ID', $user_id );

        if ( ! $stored ) {
            return new WP_Error( 'no_code', __( 'No verification code found. Please log in again.', 'vigilante' ) );
        }

        // Check if expired
        if ( strtotime( $stored['expires_at'] ) < time() ) {
            $this->database->delete_2fa_code( $user_id );
            return new WP_Error( 'code_expired', __( 'Verification code has expired. Please log in again.', 'vigilante' ) );
        }

        // Check if already used
        if ( ! empty( $stored['used'] ) ) {
            return new WP_Error( 'code_used', __( 'Verification code has already been used. Please log in again.', 'vigilante' ) );
        }

        // Check max attempts for this specific code
        $max_code_attempts = absint( $this->options['max_attempts'] ?? 3 );
        
        if ( absint( $stored['attempts'] ) >= $max_code_attempts ) {
            $this->log_event( '2fa_max_attempts_exceeded', $user_id, __( 'Maximum verification attempts exceeded', 'vigilante' ), 'warning' );
            $this->database->delete_2fa_code( $user_id );
            $this->clear_pending_verification();
            
            return new WP_Error( 
                'max_attempts', 
                __( 'Too many failed attempts. Please contact the site administrator or try again later.', 'vigilante' ) 
            );
        }

        // Check code
        if ( $code !== $stored['code'] ) {
            // Increment code-specific attempts
            $this->database->increment_2fa_attempts( $user_id );
            
            // Also record as failed login attempt for general lockout system
            if ( $this->login_security && $user ) {
                $this->login_security->record_failed_attempt( $user->user_login, '2fa' );
            }
            
            $attempts_left = $max_code_attempts - ( absint( $stored['attempts'] ) + 1 );
            
            $this->log_event( 
                '2fa_verification_failed', 
                $user_id, 
                sprintf(
                    /* translators: %d: Attempts remaining */
                    __( 'Invalid verification code. %d attempts remaining.', 'vigilante' ),
                    $attempts_left
                ),
                'warning'
            );

            if ( $attempts_left > 0 ) {
                return new WP_Error( 
                    'invalid_code', 
                    sprintf(
                        /* translators: %d: Attempts remaining */
                        __( 'Invalid verification code. %d attempts remaining.', 'vigilante' ),
                        $attempts_left
                    )
                );
            } else {
                return new WP_Error( 
                    'max_attempts', 
                    __( 'Too many failed attempts. Please contact the site administrator or try again later.', 'vigilante' ) 
                );
            }
        }

        return true;
    }

    /**
     * Maybe show 2FA verification form on login page
     */
    public function maybe_show_2fa_form() {
        $user_id = $this->get_pending_user_id();
        
        // If no user_id from cookie/POST, try the trigger transient
        if ( ! $user_id ) {
            $ip = $this->database->get_client_ip();
            $user_id = get_transient( 'vigilante_2fa_triggered_' . md5( $ip ) );
        }
        
        if ( ! $user_id ) {
            return;
        }

        // Get the token for hidden field
        $token = isset( $_COOKIE['vigilante_2fa_token'] ) ? sanitize_text_field( wp_unslash( $_COOKIE['vigilante_2fa_token'] ) ) : '';
        if ( empty( $token ) ) {
            $token = get_transient( 'vigilante_2fa_user_token_' . $user_id );
        }

        // Get any error message
        $error = get_transient( 'vigilante_2fa_error_' . $user_id );
        delete_transient( 'vigilante_2fa_error_' . $user_id );

        $expiry_minutes = absint( $this->options['code_expiry_minutes'] ?? 10 );
        $remember_days  = absint( $this->options['remember_device_days'] ?? 30 );

        // Hide the normal login form and disable required fields
        ?>
        <style>
            /* Hide WordPress default error box in 2FA mode */
            #login_error {
                display: none !important;
            }
            #loginform > p:not(.vigilante-2fa-field),
            #loginform > .user-pass-wrap,
            #loginform > .forgetmenot,
            #loginform > p.submit:not(.vigilante-2fa-submit) {
                display: none !important;
            }
            /* Also hide by ID in case structure varies */
            #user_login, #user_pass, #loginform > p > label[for="user_login"], 
            #loginform > p > label[for="user_pass"], .login-remember {
                display: none !important;
            }
        </style>
        <script>
        (function() {
            // Disable required attribute on hidden original form fields
            var userLogin = document.getElementById('user_login');
            var userPass = document.getElementById('user_pass');
            var originalSubmit = document.querySelector('#loginform > p.submit:not(.vigilante-2fa-submit) input[type="submit"]');
            
            if (userLogin) {
                userLogin.removeAttribute('required');
                userLogin.disabled = true;
            }
            if (userPass) {
                userPass.removeAttribute('required');
                userPass.disabled = true;
            }
            if (originalSubmit) {
                originalSubmit.disabled = true;
            }
        })();
        </script>

        <div class="vigilante-2fa-container">
            <?php if ( $error ) : ?>
                <div class="vigilante-2fa-error">
                    <?php echo esc_html( $error ); ?>
                </div>
            <?php endif; ?>

            <div class="vigilante-2fa-message">
                <p><?php esc_html_e( 'A verification code has been sent to your email.', 'vigilante' ); ?></p>
                <p class="vigilante-2fa-expiry">
                    <?php 
                    printf( 
                        /* translators: %d: Minutes until code expires */
                        esc_html__( 'The code is valid for %d minutes.', 'vigilante' ), 
                        absint( $expiry_minutes )
                    ); 
                    ?>
                </p>
            </div>

            <p class="vigilante-2fa-field">
                <label for="vigilante_2fa_code"><?php esc_html_e( 'Verification Code', 'vigilante' ); ?></label>
                <input type="text" 
                       name="vigilante_2fa_code" 
                       id="vigilante_2fa_code" 
                       class="input" 
                       size="6" 
                       maxlength="6" 
                       pattern="[0-9]{6}" 
                       inputmode="numeric"
                       autocomplete="one-time-code"
                       autofocus
                       required>
            </p>

            <?php if ( ! empty( $this->options['allow_remember_device'] ) ) : ?>
            <p class="vigilante-2fa-field vigilante-2fa-remember">
                <label>
                    <input type="checkbox" name="vigilante_2fa_remember" value="1">
                    <?php 
                    printf( 
                        /* translators: %d: Number of days to remember device */
                        esc_html__( 'Remember this device for %d days', 'vigilante' ), 
                        absint( $remember_days )
                    ); 
                    ?>
                </label>
            </p>
            <?php endif; ?>

            <p class="vigilante-2fa-field vigilante-2fa-submit submit">
                <input type="hidden" name="action" value="vigilante_2fa">
                <input type="hidden" name="vigilante_2fa_token" value="<?php echo esc_attr( $token ); ?>">
                <?php wp_nonce_field( 'vigilante_2fa_verify' ); ?>
                <input type="submit" name="vigilante-2fa-submit" id="vigilante-2fa-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'vigilante' ); ?>">
            </p>

            <p class="vigilante-2fa-resend">
                <a href="#" id="vigilante-resend-code" data-nonce="<?php echo esc_attr( wp_create_nonce( 'vigilante_resend_2fa' ) ); ?>" data-token="<?php echo esc_attr( $token ); ?>">
                    <?php esc_html_e( 'Resend code', 'vigilante' ); ?>
                </a>
                <span class="vigilante-2fa-resend-status"></span>
            </p>
        </div>

        <script>
        document.getElementById('vigilante-resend-code').addEventListener('click', function(e) {
            e.preventDefault();
            var link = this;
            var status = document.querySelector('.vigilante-2fa-resend-status');
            
            link.style.pointerEvents = 'none';
            status.textContent = '<?php echo esc_js( __( 'Sending...', 'vigilante' ) ); ?>';
            
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>');
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.onload = function() {
                link.style.pointerEvents = 'auto';
                if (xhr.status === 200) {
                    var response = JSON.parse(xhr.responseText);
                    if (response.success) {
                        status.textContent = '<?php echo esc_js( __( 'Code sent!', 'vigilante' ) ); ?>';
                        status.className = 'vigilante-2fa-resend-status success';
                    } else {
                        status.textContent = response.data || '<?php echo esc_js( __( 'Error sending code', 'vigilante' ) ); ?>';
                        status.className = 'vigilante-2fa-resend-status error';
                    }
                } else {
                    status.textContent = '<?php echo esc_js( __( 'Error sending code', 'vigilante' ) ); ?>';
                    status.className = 'vigilante-2fa-resend-status error';
                }
                setTimeout(function() { status.textContent = ''; }, 3000);
            };
            xhr.send('action=vigilante_resend_2fa_code&nonce=' + link.dataset.nonce + '&vigilante_2fa_token=' + link.dataset.token);
        });
        </script>
        <?php
    }

    /**
     * AJAX handler for resending verification code
     */
    public function ajax_resend_code() {
        // Verify nonce
        if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nonce'] ) ), 'vigilante_resend_2fa' ) ) {
            wp_send_json_error( __( 'Security check failed.', 'vigilante' ) );
        }

        $user_id = $this->get_pending_user_id();
        
        if ( ! $user_id ) {
            wp_send_json_error( __( 'Session expired. Please log in again.', 'vigilante' ) );
        }

        $user = get_user_by( 'ID', $user_id );
        
        if ( ! $user ) {
            wp_send_json_error( __( 'User not found.', 'vigilante' ) );
        }

        // Delete old code
        $this->database->delete_2fa_code( $user_id );

        // Generate and send new code
        $code = $this->generate_code( $user_id );
        $sent = $this->send_verification_email( $user, $code );

        if ( $sent ) {
            $this->log_event( '2fa_code_resent', $user_id, __( 'Verification code resent', 'vigilante' ) );
            wp_send_json_success( __( 'New code sent to your email.', 'vigilante' ) );
        } else {
            wp_send_json_error( __( 'Failed to send email. Please try again.', 'vigilante' ) );
        }
    }

    /**
     * Check if device is trusted
     *
     * @param int $user_id User ID.
     * @return bool
     */
    private function is_device_trusted( $user_id ) {
        $device_hash = $this->generate_device_hash( $user_id );
        return $this->database->is_device_trusted( $user_id, $device_hash );
    }

    /**
     * Trust the current device
     *
     * @param int $user_id User ID.
     */
    private function trust_device( $user_id ) {
        $device_hash   = $this->generate_device_hash( $user_id );
        $user_agent    = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
        $remember_days = absint( $this->options['remember_device_days'] ?? 30 );
        $expires_at    = gmdate( 'Y-m-d H:i:s', time() + ( $remember_days * DAY_IN_SECONDS ) );

        $this->database->trust_device( $user_id, $device_hash, $user_agent, $expires_at );
    }

    /**
     * Generate device hash
     *
     * No IP address included for GDPR compliance
     *
     * @param int $user_id User ID.
     * @return string
     */
    private function generate_device_hash( $user_id ) {
        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
        $salt       = defined( 'AUTH_SALT' ) ? AUTH_SALT : 'vigilante_fallback_salt';

        return hash( 'sha256', $user_id . $user_agent . $salt );
    }

    /**
     * Enqueue login page assets
     */
    public function enqueue_login_assets() {
        wp_enqueue_style(
            'vigilante-2fa-login',
            VIGILANTE_ASSETS_URL . 'css/two-factor-login.css',
            array(),
            VIGILANTE_VERSION
        );
    }

    /**
     * Send activation notification to affected users
     *
     * @param bool $only_new Only send to users not previously notified.
     * @return array Result with count of sent emails
     */
    public function send_activation_notifications( $only_new = false ) {
        $enforced_roles  = $this->options['enforced_roles'] ?? array( 'administrator', 'editor' );
        $excluded_users  = $this->options['excluded_users'] ?? array();
        $excluded_users  = array_map( 'absint', $excluded_users );
        
        // Get users with enforced roles
        $users = get_users( array(
            'role__in' => $enforced_roles,
            'exclude'  => $excluded_users,
        ) );

        if ( empty( $users ) ) {
            return array(
                'sent'    => 0,
                'skipped' => 0,
                'failed'  => 0,
            );
        }

        $site_name  = get_bloginfo( 'name' );
        $from_name  = $this->options['email_from_name'] ?? '';
        $admin_email = get_option( 'admin_email' );
        
        if ( empty( $from_name ) ) {
            $from_name = $site_name;
        }

        $remember_days = absint( $this->options['remember_device_days'] ?? 30 );

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Two-factor authentication enabled for your account', 'vigilante' ),
            $site_name
        );

        $body  = Vigilante_Email_Template::p(
            sprintf(
                /* translators: %s: Site name */
                __( 'The administrator of %s has enabled two-factor authentication via email for your account.', 'vigilante' ),
                $site_name
            )
        );
        $body .= Vigilante_Email_Template::info_box(
            ! empty( $this->options['allow_remember_device'] )
                ? sprintf(
                    /* translators: %d: Remember days */
                    __( 'After entering your password, you will receive a 6-digit code via email. You can check "Remember this device" to skip verification for %d days.', 'vigilante' ),
                    $remember_days
                )
                : __( 'After entering your password, you will receive a 6-digit code via email that you must enter to complete the login.', 'vigilante' )
        );
        $body .= Vigilante_Email_Template::small(
            sprintf(
                /* translators: %s: Admin email */
                __( 'Add %s to your contacts to ensure verification codes do not go to spam.', 'vigilante' ),
                $admin_email
            )
        );

        $sent    = 0;
        $skipped = 0;
        $failed  = 0;

        foreach ( $users as $user ) {
            // Check if already notified
            if ( $only_new && $this->database->user_was_2fa_notified( $user->ID ) ) {
                $skipped++;
                continue;
            }

            // Pass from_name via header (avoids filter contamination between sends)
            $result = Vigilante_Email_Template::send(
                $user->user_email,
                $subject,
                __( 'Two-factor authentication enabled', 'vigilante' ),
                $body,
                false,
                $from_name
            );

            if ( $result ) {
                $this->database->mark_2fa_notified( $user->ID );
                $sent++;
            } else {
                $failed++;
            }
        }

        // Log event
        $this->log_event( 
            '2fa_notification_sent', 
            0, 
            sprintf(
                /* translators: 1: Sent count, 2: Skipped count, 3: Failed count */
                __( 'Activation notifications sent: %1$d sent, %2$d skipped, %3$d failed', 'vigilante' ),
                $sent,
                $skipped,
                $failed
            )
        );

        return array(
            'sent'    => $sent,
            'skipped' => $skipped,
            'failed'  => $failed,
        );
    }

    /**
     * Log 2FA event
     *
     * @param string $action   Event action.
     * @param int    $user_id  User ID.
     * @param string $message  Event message.
     * @param string $severity Severity level.
     */
    private function log_event( $action, $user_id, $message, $severity = 'info' ) {
        if ( $this->activity_log ) {
            $this->activity_log->log(
                '2fa',
                $action,
                $message,
                array( 'user_id' => $user_id ),
                $severity
            );
        }
    }

    /**
     * Get all trusted devices for a user
     *
     * @param int $user_id User ID.
     * @return array
     */
    public function get_user_trusted_devices( $user_id ) {
        return $this->database->get_trusted_devices( $user_id );
    }

    /**
     * Revoke all trusted devices for a user
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function revoke_all_trusted_devices( $user_id ) {
        return $this->database->revoke_trusted_devices( $user_id );
    }

    /**
     * Clear expired codes and devices (for maintenance)
     *
     * @return array Counts of deleted items
     */
    public function cleanup_expired() {
        return array(
            'codes'   => $this->database->cleanup_expired_2fa_codes(),
            'devices' => $this->database->cleanup_expired_trusted_devices(),
        );
    }
}