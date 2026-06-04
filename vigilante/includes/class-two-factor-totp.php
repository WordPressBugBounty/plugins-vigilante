<?php
/**
 * Two-Factor TOTP Authentication Class
 *
 * Handles authenticator app (TOTP) based two-factor authentication.
 * RFC 6238 compliant, pure PHP implementation.
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Two_Factor_TOTP
 *
 * Authenticator app OTP verification for login security
 */
class Vigilante_Two_Factor_TOTP {

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
     * TOTP time step in seconds
     */
    const TIME_STEP = 30;

    /**
     * TOTP code length
     */
    const CODE_LENGTH = 6;

    /**
     * Number of backup codes to generate
     */
    const BACKUP_CODE_COUNT = 10;

    /**
     * Backup code length
     */
    const BACKUP_CODE_LENGTH = 8;

    /**
     * Secret key length in bytes (160 bits = 20 bytes, standard)
     */
    const SECRET_LENGTH = 20;

    /**
     * Time window tolerance (allows +-2 time steps for clock skew)
     */
    const TIME_WINDOW = 2;

    /**
     * Constructor
     *
     * @param Vigilante_Settings           $settings       Settings instance.
     * @param Vigilante_Database           $database       Database instance.
     * @param Vigilante_Activity_Log       $activity_log   Activity log instance.
     * @param Vigilante_Login_Security|null $login_security Login security instance.
     */
    public function __construct( $settings, $database, $activity_log, $login_security = null ) {
        $this->settings       = $settings;
        $this->database       = $database;
        $this->activity_log   = $activity_log;
        $this->login_security = $login_security;

        $login_options = $settings->get_section( 'login_security' );
        $this->options = $login_options['two_factor'] ?? array();

        if ( $this->is_active() ) {
            $this->init_hooks();
        }
    }

    /**
     * Check if TOTP method is active
     *
     * @return bool
     */
    public function is_active() {
        return ! empty( $this->options['enabled'] )
            && 'totp' === ( $this->options['method'] ?? 'email' );
    }

    /**
     * Initialize hooks
     */
    private function init_hooks() {
        // Intercept authentication
        add_filter( 'authenticate', array( $this, 'check_2fa_requirement' ), 100, 3 );

        // Handle TOTP verification form
        add_action( 'login_form_vigilante_2fa', array( $this, 'handle_2fa_form' ) );

        // Show TOTP form on login page
        add_action( 'login_form', array( $this, 'maybe_show_2fa_form' ) );

        // Enqueue login assets
        add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_assets' ) );

        // Filter login errors
        add_filter( 'login_errors', array( $this, 'filter_login_errors' ), 100 );

        // User profile section (TOTP setup)
        add_action( 'show_user_profile', array( $this, 'render_user_profile_section' ) );
        add_action( 'edit_user_profile', array( $this, 'render_user_profile_section' ) );

        // AJAX handlers for TOTP setup
        add_action( 'wp_ajax_vigilante_totp_verify_setup', array( $this, 'ajax_verify_setup' ) );
        add_action( 'wp_ajax_vigilante_totp_regenerate_backup', array( $this, 'ajax_regenerate_backup_codes' ) );
        add_action( 'wp_ajax_vigilante_totp_reconfigure', array( $this, 'ajax_reconfigure' ) );

        // Admin profile scripts
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_profile_assets' ) );

        // Grace period admin notice
        add_action( 'admin_notices', array( $this, 'show_grace_period_notice' ) );

        // Force redirect to profile when grace period is expired and TOTP not configured
        add_action( 'admin_init', array( $this, 'force_totp_setup_redirect' ) );
    }

    /**
     * Filter login errors to hide default messages during 2FA
     *
     * @param string $errors Login error messages.
     * @return string
     */
    public function filter_login_errors( $errors ) {
        $ip      = $this->database->get_client_ip();
        $user_id = get_transient( 'vigilante_2fa_triggered_' . md5( $ip ) );

        if ( ! $user_id ) {
            return $errors;
        }

        // Only filter errors if user has TOTP configured (verification form will be shown)
        // Don't filter if user needs to set up TOTP (they need to see the setup message)
        $totp_data = $this->database->get_totp_data( $user_id );
        if ( $totp_data && ! empty( $totp_data['is_configured'] ) ) {
            return '';
        }

        return $errors;
    }

    /**
     * Check if user requires 2FA and if TOTP is configured
     *
     * @param WP_User|WP_Error $user     User object or error.
     * @param string           $username Username.
     * @param string           $password Password.
     * @return WP_User|WP_Error
     */
    public function check_2fa_requirement( $user, $username, $password ) {
        if ( is_wp_error( $user ) || ! ( $user instanceof WP_User ) ) {
            return $user;
        }

        // Skip if this is a 2FA verification request
        if ( $this->is_2fa_verification_request() ) {
            return $user;
        }

        // Check if user requires 2FA
        if ( ! $this->user_requires_2fa( $user ) ) {
            return $user;
        }

        // Check if device is trusted
        if ( $this->is_device_trusted( $user->ID ) ) {
            return $user;
        }

        // Check if TOTP is configured for this user
        $totp_data = $this->database->get_totp_data( $user->ID );

        if ( ! $totp_data || empty( $totp_data['is_configured'] ) ) {
            // TOTP not yet set up - always allow login
            // Enforcement happens inside admin via force_totp_setup_redirect()

            if ( ! $totp_data ) {
                // First time - create grace period placeholder
                $grace_days    = absint( $this->options['grace_period_days'] ?? 3 );
                $grace_expires = ( $grace_days > 0 )
                    ? gmdate( 'Y-m-d H:i:s', time() + ( $grace_days * DAY_IN_SECONDS ) )
                    : gmdate( 'Y-m-d H:i:s', time() );
                $this->database->create_totp_placeholder( $user->ID, $grace_expires );
            }

            return $user;
        }

        // TOTP is configured - require verification
        $this->set_pending_verification( $user->ID );

        $this->log_event( 'totp_verification_requested', $user->ID, __( 'TOTP verification requested at login', 'vigilante' ) );

        return new WP_Error(
            'vigilante_2fa_required',
            __( 'Please enter the verification code from your authenticator app.', 'vigilante' )
        );
    }

    /**
     * Check if user requires 2FA
     *
     * @param WP_User $user User object.
     * @return bool
     */
    public function user_requires_2fa( $user ) {
        $excluded_users = $this->options['excluded_users'] ?? array();
        if ( in_array( $user->ID, array_map( 'absint', $excluded_users ), true ) ) {
            return false;
        }

        $enforced_roles = $this->options['enforced_roles'] ?? array( 'administrator', 'editor' );

        foreach ( $user->roles as $role ) {
            if ( in_array( $role, $enforced_roles, true ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user is within the grace period
     *
     * @param int $user_id User ID.
     * @return bool
     */
    private function is_within_grace_period( $user_id ) {
        $grace_days = absint( $this->options['grace_period_days'] ?? 3 );

        if ( 0 === $grace_days ) {
            return false;
        }

        $totp_data = $this->database->get_totp_data( $user_id );

        // If no TOTP row exists, create one with grace period start
        if ( ! $totp_data ) {
            $grace_expires = gmdate( 'Y-m-d H:i:s', time() + ( $grace_days * DAY_IN_SECONDS ) );
            $this->database->create_totp_placeholder( $user_id, $grace_expires );
            return true;
        }

        // Check grace period expiration
        if ( ! empty( $totp_data['grace_period_expires'] ) ) {
            return strtotime( $totp_data['grace_period_expires'] ) > time();
        }

        return false;
    }

    /**
     * Check if this is a 2FA verification form submission
     *
     * @return bool
     */
    private function is_2fa_verification_request() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Just checking action, nonce verified in handler
        $action = isset( $_REQUEST['action'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['action'] ) ) : '';
        return 'vigilante_2fa' === $action;
    }

    /**
     * Handle 2FA verification form submission
     */
    public function handle_2fa_form() {
        if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'vigilante_2fa_verify' ) ) {
            return;
        }

        $user_id = $this->get_pending_user_id();

        if ( ! $user_id ) {
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        $code            = isset( $_POST['vigilante_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['vigilante_2fa_code'] ) ) : '';
        $remember_device = ! empty( $_POST['vigilante_2fa_remember'] );

        // Try TOTP code first, then backup code
        $result = $this->verify_totp_code( $user_id, $code );

        if ( is_wp_error( $result ) ) {
            // Try as backup code
            $backup_result = $this->verify_backup_code( $user_id, $code );

            if ( is_wp_error( $backup_result ) ) {
                // Both failed
                set_transient( 'vigilante_2fa_error_' . $user_id, $result->get_error_message(), 60 );
                wp_safe_redirect( add_query_arg( 'vigilante_2fa', '1', wp_login_url() ) );
                exit;
            }

            // Backup code succeeded
            $this->log_event( 'totp_backup_code_used', $user_id, __( 'Backup code used for authentication', 'vigilante' ), 'warning' );
        }

        // Verification successful
        $this->clear_pending_verification();

        if ( $remember_device ) {
            $this->trust_device( $user_id );
            $this->log_event( 'totp_device_trusted', $user_id, __( 'Device saved as trusted', 'vigilante' ) );
        }

        $this->log_event( 'totp_verification_success', $user_id, __( 'TOTP verification successful', 'vigilante' ) );

        // Complete login
        $user = get_user_by( 'ID', $user_id );
        wp_set_current_user( $user_id, $user->user_login );
        wp_set_auth_cookie( $user_id, false );
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- wp_login is a WordPress core hook
        do_action( 'wp_login', $user->user_login, $user );

        wp_safe_redirect( admin_url() );
        exit;
    }

    /**
     * Show 2FA form on login page
     */
    public function maybe_show_2fa_form() {
        // Don't show 2FA form on logout or other non-auth actions
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Just checking URL params for display logic
        if ( isset( $_GET['loggedout'] ) || isset( $_GET['action'] ) ) {
            $action = isset( $_GET['action'] ) ? sanitize_key( $_GET['action'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if ( isset( $_GET['loggedout'] ) || in_array( $action, array( 'logout', 'lostpassword', 'register', 'rp', 'resetpass' ), true ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                return;
            }
        }

        $user_id = $this->get_pending_user_id();

        if ( ! $user_id ) {
            $ip      = $this->database->get_client_ip();
            $user_id = get_transient( 'vigilante_2fa_triggered_' . md5( $ip ) );
        }

        if ( ! $user_id ) {
            return;
        }

        // Only show if user has TOTP configured
        $totp_data = $this->database->get_totp_data( $user_id );
        if ( ! $totp_data || empty( $totp_data['is_configured'] ) ) {
            return;
        }

        $token = isset( $_COOKIE['vigilante_2fa_token'] ) ? sanitize_text_field( wp_unslash( $_COOKIE['vigilante_2fa_token'] ) ) : '';
        if ( empty( $token ) ) {
            $token = get_transient( 'vigilante_2fa_user_token_' . $user_id );
        }

        $error = get_transient( 'vigilante_2fa_error_' . $user_id );
        delete_transient( 'vigilante_2fa_error_' . $user_id );

        $remember_days = absint( $this->options['remember_device_days'] ?? 30 );

        // Check remaining backup codes
        $backup_remaining = $this->count_remaining_backup_codes( $user_id );
        ?>
        <style>
            #login_error { display: none !important; }
            #loginform > p:not(.vigilante-2fa-field),
            #loginform > .user-pass-wrap,
            #loginform > .forgetmenot,
            #loginform > p.submit:not(.vigilante-2fa-submit) { display: none !important; }
            #user_login, #user_pass, #loginform > p > label[for="user_login"],
            #loginform > p > label[for="user_pass"], .login-remember { display: none !important; }
        </style>
        <script>
        (function() {
            var userLogin = document.getElementById('user_login');
            var userPass = document.getElementById('user_pass');
            var originalSubmit = document.querySelector('#loginform > p.submit:not(.vigilante-2fa-submit) input[type="submit"]');
            if (userLogin) { userLogin.removeAttribute('required'); userLogin.disabled = true; }
            if (userPass) { userPass.removeAttribute('required'); userPass.disabled = true; }
            if (originalSubmit) { originalSubmit.disabled = true; }
        })();
        </script>

        <div class="vigilante-2fa-container vigilante-2fa-totp">
            <?php if ( $error ) : ?>
                <div class="vigilante-2fa-error">
                    <?php echo esc_html( $error ); ?>
                </div>
            <?php endif; ?>

            <div class="vigilante-2fa-message">
                <p class="vigilante-2fa-totp-icon">
                    <span class="dashicons dashicons-smartphone"></span>
                </p>
                <p><?php esc_html_e( 'Enter the 6-digit code from your authenticator app.', 'vigilante' ); ?></p>
                <?php if ( $backup_remaining > 0 ) : ?>
                    <p class="vigilante-2fa-backup-hint">
                        <?php
                        printf(
                            /* translators: %d: Number of backup codes remaining */
                            esc_html__( 'Lost your phone? You can use a backup code instead (%d remaining).', 'vigilante' ),
                            absint( $backup_remaining )
                        );
                        ?>
                    </p>
                <?php endif; ?>
            </div>

            <p class="vigilante-2fa-field">
                <label for="vigilante_2fa_code"><?php esc_html_e( 'Authentication code or backup code', 'vigilante' ); ?></label>
                <input type="text"
                       name="vigilante_2fa_code"
                       id="vigilante_2fa_code"
                       class="input"
                       size="8"
                       maxlength="8"
                       pattern="[a-zA-Z0-9]{6,8}"
                       inputmode="numeric"
                       autocomplete="one-time-code"
                       placeholder="000000"
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
        </div>
        <?php
    }

    // =========================================================================
    // TOTP Algorithm (RFC 6238)
    // =========================================================================

    /**
     * Generate a random TOTP secret
     *
     * @return string Base32-encoded secret.
     */
    public function generate_secret() {
        $random = wp_generate_password( self::SECRET_LENGTH, false, false );
        // Use truly random bytes
        $bytes = '';
        for ( $i = 0; $i < self::SECRET_LENGTH; $i++ ) {
            $bytes .= chr( wp_rand( 0, 255 ) );
        }
        return $this->base32_encode( $bytes );
    }

    /**
     * Generate TOTP code for a given time
     *
     * @param string   $secret Base32-encoded secret.
     * @param int|null $time   Unix timestamp (null = current time).
     * @return string 6-digit code.
     */
    public function generate_code( $secret, $time = null ) {
        if ( null === $time ) {
            $time = time();
        }

        $counter = intval( floor( $time / self::TIME_STEP ) );

        // Pack counter as 8-byte big-endian
        $counter_bytes = pack( 'N*', 0, $counter );

        // Decode secret from Base32
        $key = $this->base32_decode( $secret );

        // HMAC-SHA1
        $hash = hash_hmac( 'sha1', $counter_bytes, $key, true );

        // Dynamic truncation
        $offset = ord( $hash[19] ) & 0x0f;
        $code   = (
            ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 ) |
            ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 ) |
            ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 ) |
            ( ( ord( $hash[ $offset + 3 ] ) & 0xff ) )
        ) % pow( 10, self::CODE_LENGTH );

        return str_pad( (string) $code, self::CODE_LENGTH, '0', STR_PAD_LEFT );
    }

    /**
     * Verify a TOTP code against stored secret
     *
     * @param int    $user_id User ID.
     * @param string $code    Submitted code.
     * @return true|WP_Error
     */
    public function verify_totp_code( $user_id, $code ) {
        // Validate code format (6 digits for TOTP)
        if ( ! preg_match( '/^[0-9]{6}$/', $code ) ) {
            return new WP_Error( 'invalid_format', __( 'Invalid code format. Enter the 6-digit code from your authenticator app.', 'vigilante' ) );
        }

        $totp_data = $this->database->get_totp_data( $user_id );

        if ( ! $totp_data || empty( $totp_data['secret'] ) ) {
            return new WP_Error( 'not_configured', __( 'TOTP is not configured. Please contact the site administrator.', 'vigilante' ) );
        }

        $secret = $this->decrypt_secret( $totp_data['secret'] );

        if ( ! $secret ) {
            return new WP_Error( 'decrypt_failed', __( 'Authentication error. Please contact the site administrator.', 'vigilante' ) );
        }

        // Check code against current and adjacent time steps (clock skew tolerance)
        $now = time();
        for ( $i = -self::TIME_WINDOW; $i <= self::TIME_WINDOW; $i++ ) {
            $expected = $this->generate_code( $secret, $now + ( $i * self::TIME_STEP ) );
            if ( hash_equals( $expected, $code ) ) {
                // Prevent replay: check if this code was already used
                $last_used = get_transient( 'vigilante_totp_last_' . $user_id );
                if ( $last_used === $code ) {
                    return new WP_Error( 'code_reused', __( 'This code has already been used. Wait for a new code.', 'vigilante' ) );
                }
                set_transient( 'vigilante_totp_last_' . $user_id, $code, self::TIME_STEP * 2 );

                // Update last used timestamp
                $this->database->update_totp_last_used( $user_id );

                return true;
            }
        }

        // Track failed attempts
        $remaining = -1;
        if ( $this->login_security ) {
            $user = get_user_by( 'ID', $user_id );
            if ( $user ) {
                $this->login_security->record_failed_attempt( $user->user_login, '2fa' );
                $remaining = $this->login_security->get_remaining_attempts();
            }
        }

        $this->log_event( 'totp_verification_failed', $user_id, __( 'Invalid TOTP code entered', 'vigilante' ), 'warning' );

        if ( $remaining > 0 ) {
            return new WP_Error(
                'invalid_code',
                sprintf(
                    /* translators: %d: Number of attempts remaining */
                    __( 'Invalid verification code. %d attempts remaining before lockout.', 'vigilante' ),
                    $remaining
                )
            );
        }

        return new WP_Error(
            'invalid_code',
            __( 'Invalid verification code. If you have lost access to your authenticator app, contact the site administrator.', 'vigilante' )
        );
    }

    // =========================================================================
    // Backup codes
    // =========================================================================

    /**
     * Generate backup codes for a user
     *
     * @param int $user_id User ID.
     * @return array Plain text backup codes (show to user once).
     */
    public function generate_backup_codes( $user_id ) {
        $codes       = array();
        $hashed      = array();
        $charset     = 'abcdefghjkmnpqrstuvwxyz23456789'; // Avoid confusable chars

        for ( $i = 0; $i < self::BACKUP_CODE_COUNT; $i++ ) {
            $code = '';
            for ( $j = 0; $j < self::BACKUP_CODE_LENGTH; $j++ ) {
                $code .= $charset[ wp_rand( 0, strlen( $charset ) - 1 ) ];
            }
            $codes[]  = $code;
            $hashed[] = wp_hash_password( $code );
        }

        // Store hashed codes
        $this->database->store_totp_backup_codes( $user_id, wp_json_encode( $hashed ) );

        $this->log_event( 'totp_backup_codes_generated', $user_id, __( 'Backup codes generated', 'vigilante' ) );

        return $codes;
    }

    /**
     * Verify a backup code
     *
     * @param int    $user_id User ID.
     * @param string $code    Submitted backup code.
     * @return true|WP_Error
     */
    private function verify_backup_code( $user_id, $code ) {
        // Backup codes are 8 chars, lowercase alphanumeric
        $code = strtolower( trim( $code ) );

        if ( strlen( $code ) !== self::BACKUP_CODE_LENGTH ) {
            return new WP_Error( 'invalid_backup', __( 'Invalid backup code.', 'vigilante' ) );
        }

        $totp_data = $this->database->get_totp_data( $user_id );

        if ( ! $totp_data || empty( $totp_data['backup_codes'] ) ) {
            return new WP_Error( 'no_backup_codes', __( 'No backup codes available.', 'vigilante' ) );
        }

        $stored_hashes = json_decode( $totp_data['backup_codes'], true );

        if ( ! is_array( $stored_hashes ) ) {
            return new WP_Error( 'corrupt_data', __( 'Backup codes data is corrupt.', 'vigilante' ) );
        }

        // Check each stored hash
        foreach ( $stored_hashes as $idx => $hash ) {
            if ( wp_check_password( $code, $hash ) ) {
                // Remove used code
                unset( $stored_hashes[ $idx ] );
                $stored_hashes = array_values( $stored_hashes );
                $this->database->store_totp_backup_codes( $user_id, wp_json_encode( $stored_hashes ) );

                return true;
            }
        }

        return new WP_Error( 'invalid_backup', __( 'Invalid backup code.', 'vigilante' ) );
    }

    /**
     * Count remaining backup codes for a user
     *
     * @param int $user_id User ID.
     * @return int
     */
    public function count_remaining_backup_codes( $user_id ) {
        $totp_data = $this->database->get_totp_data( $user_id );

        if ( ! $totp_data || empty( $totp_data['backup_codes'] ) ) {
            return 0;
        }

        $codes = json_decode( $totp_data['backup_codes'], true );

        return is_array( $codes ) ? count( $codes ) : 0;
    }

    // =========================================================================
    // Secret encryption
    // =========================================================================

    /**
     * Encrypt TOTP secret for database storage
     *
     * @param string $secret Plain Base32 secret.
     * @return string Encrypted string (base64).
     */
    public function encrypt_secret( $secret ) {
        $key = $this->get_encryption_key();
        $iv  = openssl_random_pseudo_bytes( 16 );

        $encrypted = openssl_encrypt( $secret, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );

        if ( false === $encrypted ) {
            return '';
        }

        // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Required for safe binary storage
        return base64_encode( $iv . $encrypted );
    }

    /**
     * Decrypt TOTP secret from database
     *
     * @param string $encrypted Encrypted string (base64).
     * @return string|false Plain Base32 secret or false.
     */
    public function decrypt_secret( $encrypted ) {
        $key = $this->get_encryption_key();

        // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Required for binary data retrieval
        $data = base64_decode( $encrypted, true );

        if ( false === $data || strlen( $data ) < 17 ) {
            return false;
        }

        $iv   = substr( $data, 0, 16 );
        $text = substr( $data, 16 );

        $decrypted = openssl_decrypt( $text, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );

        return ( false !== $decrypted ) ? $decrypted : false;
    }

    /**
     * Get encryption key derived from WordPress salts
     *
     * @return string 32-byte key.
     */
    private function get_encryption_key() {
        $salt = defined( 'AUTH_KEY' ) ? AUTH_KEY : 'vigilante_fallback_key';
        return hash( 'sha256', $salt . 'vigilante_totp', true );
    }

    // =========================================================================
    // Base32 encoding/decoding
    // =========================================================================

    /**
     * Base32 encode
     *
     * @param string $data Raw binary data.
     * @return string Base32-encoded string.
     */
    private function base32_encode( $data ) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $binary   = '';

        for ( $i = 0; $i < strlen( $data ); $i++ ) {
            $binary .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
        }

        $result = '';
        for ( $i = 0; $i < strlen( $binary ); $i += 5 ) {
            $chunk   = substr( $binary, $i, 5 );
            $chunk   = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
            $result .= $alphabet[ intval( $chunk, 2 ) ];
        }

        return $result;
    }

    /**
     * Base32 decode
     *
     * @param string $data Base32-encoded string.
     * @return string Raw binary data.
     */
    private function base32_decode( $data ) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $data     = strtoupper( rtrim( $data, '=' ) );
        $binary   = '';

        for ( $i = 0; $i < strlen( $data ); $i++ ) {
            $pos = strpos( $alphabet, $data[ $i ] );
            if ( false === $pos ) {
                continue;
            }
            $binary .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
        }

        $result = '';
        for ( $i = 0; $i + 8 <= strlen( $binary ); $i += 8 ) {
            $result .= chr( intval( substr( $binary, $i, 8 ), 2 ) );
        }

        return $result;
    }

    // =========================================================================
    // TOTP URI and QR code
    // =========================================================================

    /**
     * Generate otpauth:// URI for authenticator apps
     *
     * @param string $secret     Base32 secret.
     * @param string $user_email User email.
     * @return string
     */
    public function get_totp_uri( $secret, $user_email ) {
        $issuer = get_bloginfo( 'name' );
        $issuer = preg_replace( '/[^a-zA-Z0-9 _-]/', '', $issuer );

        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
            rawurlencode( $issuer ),
            rawurlencode( $user_email ),
            $secret,
            rawurlencode( $issuer ),
            self::CODE_LENGTH,
            self::TIME_STEP
        );
    }

    // =========================================================================
    // User profile section
    // =========================================================================

    /**
     * Render TOTP setup/status section in user profile
     *
     * @param WP_User $user User being edited.
     */
    public function render_user_profile_section( $user ) {
        // Only show for users that require 2FA
        if ( ! $this->user_requires_2fa( $user ) ) {
            return;
        }

        $totp_data  = $this->database->get_totp_data( $user->ID );
        $configured = $totp_data && ! empty( $totp_data['is_configured'] );

        wp_nonce_field( 'vigilante_totp_profile', 'vigilante_totp_nonce' );
        ?>
        <input type="hidden" class="vigilante-totp-user-id" value="<?php echo esc_attr( $user->ID ); ?>">
        <h2><?php esc_html_e( 'Two-Factor Authentication (TOTP)', 'vigilante' ); ?></h2>
        <table class="form-table vigilante-totp-profile" role="presentation">
            <?php if ( $configured ) : ?>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Status', 'vigilante' ); ?></th>
                    <td>
                        <span class="vigilante-totp-status vigilante-totp-active">
                            <span class="dashicons dashicons-yes-alt"></span>
                            <?php esc_html_e( 'Configured and active', 'vigilante' ); ?>
                        </span>
                        <?php if ( ! empty( $totp_data['configured_at'] ) ) : ?>
                            <p class="description">
                                <?php
                                printf(
                                    /* translators: %s: Date and time */
                                    esc_html__( 'Set up on: %s', 'vigilante' ),
                                    esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $totp_data['configured_at'] ) ) )
                                );
                                ?>
                            </p>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Backup codes', 'vigilante' ); ?></th>
                    <td>
                        <?php
                        $remaining = $this->count_remaining_backup_codes( $user->ID );
                        $warning   = $remaining <= 3;
                        ?>
                        <span class="vigilante-totp-backup-count <?php echo $warning ? 'warning' : ''; ?>">
                            <?php
                            printf(
                                /* translators: 1: Remaining codes, 2: Total codes */
                                esc_html__( '%1$d of %2$d remaining', 'vigilante' ),
                                absint( $remaining ),
                                absint( self::BACKUP_CODE_COUNT )
                            );
                            ?>
                        </span>
                        <p>
                            <button type="button" class="button vigilante-totp-regenerate-backup" data-user="<?php echo esc_attr( $user->ID ); ?>">
                                <?php esc_html_e( 'Generate new backup codes', 'vigilante' ); ?>
                            </button>
                        </p>
                        <div class="vigilante-totp-backup-codes-display" style="display:none;"></div>
                    </td>
                </tr>
                <?php if ( current_user_can( 'manage_options' ) || get_current_user_id() === $user->ID ) : ?>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Reconfigure', 'vigilante' ); ?></th>
                    <td>
                        <button type="button" class="button vigilante-totp-reconfigure" data-user="<?php echo esc_attr( $user->ID ); ?>">
                            <?php esc_html_e( 'Set up new authenticator', 'vigilante' ); ?>
                        </button>
                        <p class="description"><?php esc_html_e( 'This will reset your current TOTP setup and require scanning a new QR code.', 'vigilante' ); ?></p>
                    </td>
                </tr>
                <?php endif; ?>
            <?php else : ?>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Status', 'vigilante' ); ?></th>
                    <td>
                        <span class="vigilante-totp-status vigilante-totp-pending">
                            <span class="dashicons dashicons-warning"></span>
                            <?php esc_html_e( 'Not configured', 'vigilante' ); ?>
                        </span>
                        <?php
                        if ( $totp_data && ! empty( $totp_data['grace_period_expires'] ) ) {
                            $grace_end = strtotime( $totp_data['grace_period_expires'] );
                            if ( $grace_end > time() ) {
                                $days_left = max( 1, ceil( ( $grace_end - time() ) / DAY_IN_SECONDS ) );
                                echo '<p class="description vigilante-totp-grace-notice">';
                                printf(
                                    /* translators: %d: Days remaining */
                                    esc_html( _n(
                                        'You have %d day to set up two-factor authentication.',
                                        'You have %d days to set up two-factor authentication.',
                                        $days_left,
                                        'vigilante'
                                    ) ),
                                    absint( $days_left )
                                );
                                echo '</p>';
                            }
                        }
                        ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Setup', 'vigilante' ); ?></th>
                    <td>
                        <div class="vigilante-totp-setup" id="vigilante-totp-setup">
                            <div class="vigilante-totp-setup-loading">
                                <button type="button" class="button button-primary vigilante-totp-start-setup">
                                    <?php esc_html_e( 'Start setup', 'vigilante' ); ?>
                                </button>
                            </div>
                            <div class="vigilante-totp-setup-qr" style="display:none;">
                                <p class="description">
                                    <?php esc_html_e( 'Scan this QR code with your authenticator app (Google Authenticator, Authy, Microsoft Authenticator, etc.)', 'vigilante' ); ?>
                                </p>
                                <div class="vigilante-totp-qr-container"></div>
                                <div class="vigilante-totp-manual-key">
                                    <p><?php esc_html_e( 'Or enter this key manually:', 'vigilante' ); ?></p>
                                    <code class="vigilante-totp-secret-display"></code>
                                </div>
                                <div class="vigilante-totp-verify-setup">
                                    <label for="vigilante_totp_verify_code"><?php esc_html_e( 'Enter code to verify:', 'vigilante' ); ?></label>
                                    <input type="text" id="vigilante_totp_verify_code" maxlength="6" pattern="[0-9]{6}" inputmode="numeric" autocomplete="off">
                                    <button type="button" class="button button-primary vigilante-totp-confirm-setup">
                                        <?php esc_html_e( 'Verify and activate', 'vigilante' ); ?>
                                    </button>
                                    <span class="vigilante-totp-setup-status"></span>
                                </div>
                            </div>
                            <div class="vigilante-totp-setup-success" style="display:none;">
                                <div class="vigilante-totp-success-msg">
                                    <span class="dashicons dashicons-yes-alt"></span>
                                    <?php esc_html_e( 'Two-factor authentication configured successfully!', 'vigilante' ); ?>
                                </div>
                                <div class="vigilante-totp-backup-codes-display"></div>
                            </div>
                        </div>
                    </td>
                </tr>
            <?php endif; ?>
        </table>
        <?php
    }

    /**
     * Enqueue profile page assets (only on user profile pages)
     *
     * @param string $hook Current admin page hook.
     */
    public function enqueue_profile_assets( $hook ) {
        if ( 'profile.php' !== $hook && 'user-edit.php' !== $hook ) {
            return;
        }

        wp_enqueue_style(
            'vigilante-totp-profile',
            VIGILANTE_ASSETS_URL . 'css/two-factor-admin.css',
            array(),
            VIGILANTE_VERSION
        );

        // QR code generator library (bundled locally for WordPress.org compliance)
        wp_enqueue_script(
            'qrcode-js',
            VIGILANTE_ASSETS_URL . 'js/qrcode.min.js',
            array(),
            '1.0.0',
            true
        );

        wp_enqueue_script(
            'vigilante-totp-profile',
            VIGILANTE_ASSETS_URL . 'js/two-factor-admin.js',
            array( 'jquery', 'qrcode-js' ),
            VIGILANTE_VERSION,
            true
        );

        wp_localize_script( 'vigilante-totp-profile', 'vigilanteTOTP', array(
            'ajaxUrl' => admin_url( 'admin-ajax.php' ),
            'nonce'   => wp_create_nonce( 'vigilante_totp_profile' ),
            'strings' => array(
                'verifying'        => __( 'Verifying...', 'vigilante' ),
                'generating'       => __( 'Generating...', 'vigilante' ),
                'success'          => __( 'Success!', 'vigilante' ),
                'error'            => __( 'An error occurred.', 'vigilante' ),
                'confirmRegen'     => __( 'This will invalidate all existing backup codes. Continue?', 'vigilante' ),
                'confirmReconfig'  => __( 'This will reset your current TOTP setup. You will need to scan a new QR code. Continue?', 'vigilante' ),
                'saveBackupCodes'  => __( 'Save these backup codes now. They will not be shown again.', 'vigilante' ),
                'codesRemaining'   => __( 'backup codes remaining', 'vigilante' ),
            ),
        ) );
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

        // Dashicons for the smartphone icon
        wp_enqueue_style( 'dashicons' );
    }

    // =========================================================================
    // AJAX handlers
    // =========================================================================

    /**
     * AJAX: Verify TOTP setup code and activate
     */
    public function ajax_verify_setup() {
        check_ajax_referer( 'vigilante_totp_profile', 'nonce' );

        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        if ( 0 === $user_id ) {
            $user_id = get_current_user_id();
        }
        $code    = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
        $secret  = isset( $_POST['secret'] ) ? sanitize_text_field( wp_unslash( $_POST['secret'] ) ) : '';
        $reconfig = ! empty( $_POST['reconfigure'] );

        // Permission check: user can only set up their own, unless admin
        if ( get_current_user_id() !== $user_id && ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        if ( empty( $code ) || ! preg_match( '/^[0-9]{6}$/', $code ) ) {
            wp_send_json_error( __( 'Enter a valid 6-digit code.', 'vigilante' ) );
        }

        if ( empty( $secret ) || ! preg_match( '/^[A-Z2-7]+=*$/', $secret ) ) {
            wp_send_json_error( __( 'Invalid secret. Please reload and try again.', 'vigilante' ) );
        }

        // Verify the code against the provided secret
        $expected_codes = array();
        $now = time();
        for ( $i = -self::TIME_WINDOW; $i <= self::TIME_WINDOW; $i++ ) {
            $expected_codes[] = $this->generate_code( $secret, $now + ( $i * self::TIME_STEP ) );
        }

        if ( ! in_array( $code, $expected_codes, true ) ) {
            wp_send_json_error( __( 'Invalid code. Make sure your authenticator app is set up correctly and the time is synchronized.', 'vigilante' ) );
        }

        // Encrypt and store secret
        $encrypted = $this->encrypt_secret( $secret );

        if ( empty( $encrypted ) ) {
            wp_send_json_error( __( 'Encryption error. Please try again.', 'vigilante' ) );
        }

        // Save TOTP data
        if ( $reconfig ) {
            $this->database->reset_totp_data( $user_id );
        }

        $this->database->save_totp_data( $user_id, $encrypted );

        // Generate backup codes
        $backup_codes = $this->generate_backup_codes( $user_id );

        $this->log_event( 'totp_configured', $user_id, __( 'TOTP authenticator configured', 'vigilante' ) );

        wp_send_json_success( array(
            'message'      => __( 'Two-factor authentication has been configured successfully.', 'vigilante' ),
            'backup_codes' => $backup_codes,
        ) );
    }

    /**
     * AJAX: Regenerate backup codes
     */
    public function ajax_regenerate_backup_codes() {
        check_ajax_referer( 'vigilante_totp_profile', 'nonce' );

        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        if ( 0 === $user_id ) {
            $user_id = get_current_user_id();
        }

        if ( get_current_user_id() !== $user_id && ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $totp_data = $this->database->get_totp_data( $user_id );

        if ( ! $totp_data || empty( $totp_data['is_configured'] ) ) {
            wp_send_json_error( __( 'TOTP is not configured for this user.', 'vigilante' ) );
        }

        $backup_codes = $this->generate_backup_codes( $user_id );

        wp_send_json_success( array(
            'backup_codes' => $backup_codes,
        ) );
    }

    /**
     * AJAX: Reconfigure TOTP (reset and allow re-setup from profile)
     */
    public function ajax_reconfigure() {
        check_ajax_referer( 'vigilante_totp_profile', 'nonce' );

        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        if ( 0 === $user_id ) {
            $user_id = get_current_user_id();
        }

        if ( get_current_user_id() !== $user_id && ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $this->reset_user_totp( $user_id );

        wp_send_json_success( array(
            'message' => __( 'TOTP has been reset. You can now set up a new authenticator.', 'vigilante' ),
        ) );
    }

    /**
     * Set pending verification state
     *
     * @param int $user_id User ID.
     * @return string Token.
     */
    private function set_pending_verification( $user_id ) {
        $existing_token = get_transient( 'vigilante_2fa_user_token_' . $user_id );

        $token = $existing_token ? $existing_token : wp_generate_password( 32, false );

        set_transient(
            'vigilante_2fa_pending_' . $token,
            array(
                'user_id'    => $user_id,
                'created_at' => time(),
            ),
            HOUR_IN_SECONDS
        );

        set_transient( 'vigilante_2fa_user_token_' . $user_id, $token, HOUR_IN_SECONDS );

        $ip = $this->database->get_client_ip();
        set_transient( 'vigilante_2fa_triggered_' . md5( $ip ), $user_id, 60 );

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
            $_COOKIE['vigilante_2fa_token'] = $token;
        }

        return $token;
    }

    /**
     * Get pending user ID from token
     *
     * @return int|false User ID or false.
     */
    private function get_pending_user_id() {
        $token = '';

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Token is for session identification
        if ( isset( $_POST['vigilante_2fa_token'] ) ) {
            $token = sanitize_text_field( wp_unslash( $_POST['vigilante_2fa_token'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
        } elseif ( isset( $_COOKIE['vigilante_2fa_token'] ) ) {
            $token = sanitize_text_field( wp_unslash( $_COOKIE['vigilante_2fa_token'] ) );
        }

        if ( empty( $token ) ) {
            return false;
        }

        $pending = get_transient( 'vigilante_2fa_pending_' . $token );

        if ( ! $pending || ! isset( $pending['user_id'] ) ) {
            return false;
        }

        return absint( $pending['user_id'] );
    }

    /**
     * Clear pending verification
     */
    private function clear_pending_verification() {
        $token = '';

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Token is for session identification
        if ( isset( $_POST['vigilante_2fa_token'] ) ) {
            $token = sanitize_text_field( wp_unslash( $_POST['vigilante_2fa_token'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
        } elseif ( isset( $_COOKIE['vigilante_2fa_token'] ) ) {
            $token = sanitize_text_field( wp_unslash( $_COOKIE['vigilante_2fa_token'] ) );
        }

        if ( ! empty( $token ) ) {
            delete_transient( 'vigilante_2fa_pending_' . $token );
        }

        if ( ! headers_sent() ) {
            setcookie(
                'vigilante_2fa_token',
                '',
                array(
                    'expires'  => time() - HOUR_IN_SECONDS,
                    'path'     => COOKIEPATH,
                    'domain'   => COOKIE_DOMAIN,
                    'secure'   => is_ssl(),
                    'httponly' => true,
                    'samesite' => 'Strict',
                )
            );
        }
    }

    // =========================================================================
    // Trusted devices (reuses database methods from email 2FA)
    // =========================================================================

    /**
     * Check if current device is trusted
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
     * Generate device hash (no IP for GDPR)
     *
     * @param int $user_id User ID.
     * @return string
     */
    private function generate_device_hash( $user_id ) {
        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
        $salt       = defined( 'AUTH_SALT' ) ? AUTH_SALT : 'vigilante_fallback_salt';
        return hash( 'sha256', $user_id . $user_agent . $salt );
    }

    // =========================================================================
    // =========================================================================
    // Grace period admin notice and forced redirect
    // =========================================================================

    /**
     * Force redirect to profile page when grace period has expired
     * and TOTP is not yet configured.
     *
     * During grace period: user can browse freely, only a notice is shown.
     * After grace period: user is locked to profile page until setup is complete.
     */
    public function force_totp_setup_redirect() {
        // Don't redirect on AJAX requests
        if ( wp_doing_ajax() ) {
            return;
        }

        $user = wp_get_current_user();

        if ( ! $user->ID || ! $this->user_requires_2fa( $user ) ) {
            return;
        }

        $totp_data = $this->database->get_totp_data( $user->ID );

        // Already configured - no redirect needed
        if ( $totp_data && ! empty( $totp_data['is_configured'] ) ) {
            return;
        }

        // No TOTP data at all - first login just happened, allow freely
        if ( ! $totp_data ) {
            return;
        }

        // Check if grace period is still active
        if ( ! empty( $totp_data['grace_period_expires'] ) && strtotime( $totp_data['grace_period_expires'] ) > time() ) {
            // Grace period active - user can browse freely, just notice shown
            return;
        }

        // Grace period expired - force redirect to profile (unless already there)
        global $pagenow;
        if ( 'profile.php' === $pagenow || 'user-edit.php' === $pagenow ) {
            return;
        }

        wp_safe_redirect( admin_url( 'profile.php#vigilante-totp-setup' ) );
        exit;
    }

    /**
     * Show admin notice for users who need to set up TOTP
     */
    public function show_grace_period_notice() {
        $user = wp_get_current_user();

        if ( ! $this->user_requires_2fa( $user ) ) {
            return;
        }

        $totp_data = $this->database->get_totp_data( $user->ID );

        if ( $totp_data && ! empty( $totp_data['is_configured'] ) ) {
            return;
        }

        $profile_url = admin_url( 'profile.php#vigilante-totp-setup' );
        $grace_end   = ( $totp_data && ! empty( $totp_data['grace_period_expires'] ) )
            ? strtotime( $totp_data['grace_period_expires'] )
            : 0;
        $days_left   = ( $grace_end > time() ) ? max( 1, ceil( ( $grace_end - time() ) / DAY_IN_SECONDS ) ) : 0;
        ?>
        <div class="notice notice-warning vigilante-totp-grace-notice">
            <p>
                <span class="dashicons dashicons-shield"></span>
                <strong><?php esc_html_e( 'Two-factor authentication setup required', 'vigilante' ); ?></strong>
                &mdash;
                <?php if ( $days_left > 0 ) : ?>
                    <?php
                    printf(
                        /* translators: %d: Days remaining */
                        esc_html( _n(
                            'You have %d day to set up your authenticator app.',
                            'You have %d days to set up your authenticator app.',
                            $days_left,
                            'vigilante'
                        ) ),
                        absint( $days_left )
                    );
                    ?>
                <?php else : ?>
                    <?php esc_html_e( 'Please set up your authenticator app now.', 'vigilante' ); ?>
                <?php endif; ?>
                <a href="<?php echo esc_url( $profile_url ); ?>"><?php esc_html_e( 'Set up now', 'vigilante' ); ?></a>
            </p>
        </div>
        <?php
    }

    // =========================================================================
    // Admin TOTP reset (called from admin-ajax)
    // =========================================================================

    /**
     * Reset TOTP for a user (admin action)
     *
     * @param int $user_id User ID to reset.
     * @return bool
     */
    public function reset_user_totp( $user_id ) {
        $this->database->reset_totp_data( $user_id );

        // If grace period is configured, set a new one
        $grace_days = absint( $this->options['grace_period_days'] ?? 3 );
        if ( $grace_days > 0 ) {
            $grace_expires = gmdate( 'Y-m-d H:i:s', time() + ( $grace_days * DAY_IN_SECONDS ) );
            $this->database->create_totp_placeholder( $user_id, $grace_expires );
        }

        // Revoke trusted devices
        $this->database->revoke_trusted_devices( $user_id );

        $this->log_event( 'totp_reset', $user_id, __( 'TOTP configuration reset by administrator', 'vigilante' ), 'warning' );

        return true;
    }

    /**
     * Get TOTP setup data for a new setup (generates secret and QR)
     *
     * @param int $user_id User ID.
     * @return array Setup data with secret, uri, and qr_svg.
     */
    public function get_setup_data( $user_id ) {
        $user = get_user_by( 'ID', $user_id );

        if ( ! $user ) {
            return array();
        }

        $secret = $this->generate_secret();
        $uri    = $this->get_totp_uri( $secret, $user->user_email );

        return array(
            'secret' => $secret,
            'uri'    => $uri,
        );
    }

    // =========================================================================
    // HTML styled email for TOTP activation notification
    // =========================================================================

    /**
     * Send TOTP activation notification email
     *
     * @param WP_User $user      User object.
     * @param string  $site_name Site name.
     * @param string  $from_name Email from name.
     * @return bool
     */
    public function send_activation_email( $user, $site_name, $from_name ) {
        $profile_url = admin_url( 'profile.php' );
        $grace_days  = absint( $this->options['grace_period_days'] ?? 3 );

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Set up two-factor authentication for your account', 'vigilante' ),
            $site_name
        );

        $body  = Vigilante_Email_Template::p(
            sprintf(
                /* translators: 1: User display name, 2: Site name */
                __( 'Hello %1$s, the administrator of %2$s has enabled two-factor authentication using an authenticator app for your account.', 'vigilante' ),
                $user->display_name,
                $site_name
            )
        );
        $body .= Vigilante_Email_Template::p( __( 'Install an authenticator app on your phone if you do not have one:', 'vigilante' ) );
        $body .= Vigilante_Email_Template::ul( array(
            '<a href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2">Google Authenticator (Android)</a>',
            '<a href="https://apps.apple.com/app/google-authenticator/id388497605">Google Authenticator (iOS)</a>',
            '<a href="https://authy.com/download/">Authy (Android / iOS)</a>',
            '<a href="https://www.microsoft.com/en-us/security/mobile-authenticator-app">Microsoft Authenticator</a>',
        ) );

        if ( $grace_days > 0 ) {
            $body .= Vigilante_Email_Template::warning_box(
                sprintf(
                    /* translators: %d: Number of days */
                    __( 'You have %d days to complete the setup. After that, you will not be able to access the admin area without configuring your authenticator app.', 'vigilante' ),
                    $grace_days
                )
            );
        } else {
            $body .= Vigilante_Email_Template::alert_box( __( 'You must configure your authenticator app on your next login.', 'vigilante' ) );
        }

        $body .= Vigilante_Email_Template::button( $profile_url, __( 'Set up now', 'vigilante' ) );

        // Pass from_name via header (avoids filter contamination)
        $sent = Vigilante_Email_Template::send(
            $user->user_email,
            $subject,
            __( 'Two-factor authentication enabled', 'vigilante' ),
            $body,
            false,
            $from_name
        );

        return $sent;
    }

    // =========================================================================
    // Logging helper
    // =========================================================================

    /**
     * Log TOTP event
     *
     * @param string $action   Action name.
     * @param int    $user_id  User ID.
     * @param string $message  Message.
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
}
