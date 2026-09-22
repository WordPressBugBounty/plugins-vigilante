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

    use Vigilante_Two_Factor_Session;

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
     * Time window tolerance: +-1 time step (30 seconds) for clock skew.
     * Was 2 until 2.11.0, which accepted five codes at any moment (S2).
     */
    const TIME_WINDOW = 1;

    /**
     * Time steps scanned, on a failure only, to recognise a clock that drifted
     *
     * Ten minutes either way. Nothing outside TIME_WINDOW is ever accepted:
     * these steps only tell a wrong code apart from a right one that arrived
     * with the wrong time on it.
     *
     * @var int
     */
    const SKEW_SCAN_STEPS = 20;

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

        // The mechanics (method, expiry, grace period) come from the main site on
        // a network, so they are the same wherever the login arrives. Whether an
        // account NEEDS a second factor is a separate question with its own
        // answer, see Vigilante_Settings::two_factor_required_for().
        $this->options = null;

        /*
         * Gating here on this site's own setting was the fourth leg of the
         * bypass the first cross review found: with two factor on in one subsite
         * and off in another, the login sent to the permissive one registered
         * nothing at all, and the cookie it issued was valid across the whole
         * network. So on a network the hooks go up wherever the login lands.
         *
         * Which of the two classes actually handles a given login is NOT decided
         * here any more. The second cross review found that registering both was
         * a downgrade (a network set to use an authenticator app also mailed
         * codes), and the third found that picking one here by the main site's
         * method was a hole (with the main site on totp and a subsite asking for
         * email, the account had no enrolment and the login went through). Both
         * come from the same mistake: the method is a property of the account, not
         * of the site the login arrives at. So both classes register and each one
         * asks Vigilante_Settings::two_factor_handler_for() whether this login is
         * theirs. Registering a filter costs nothing; the election does not run
         * until a login is known to need a second factor.
         *
         * Nothing is read from the options here on a network, and that is on
         * purpose too: this constructor runs on init on EVERY request of every
         * site, and reading the main site's policy here meant a switch_to_blog()
         * plus the whole autoloaded option set of the main site on every front
         * page view of every subsite (measured: 318 rows, 89 KB).
         */
        if ( is_multisite() || ! empty( $this->policy()['enabled'] ) ) {
            $this->init_hooks();
        }
    }

    /**
     * Check if TOTP method is active
     *
     * @return bool
     */
    public function is_active() {
        return ! empty( $this->policy()['enabled'] )
            && 'totp' === ( $this->policy()['method'] ?? 'email' );
    }

    /**
     * Initialize hooks
     */
    private function init_hooks() {
        $this->init_session_hooks();

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
     * Resolved from the pending token only; the lookup by IP address that used
     * to live here leaked one user's pending state to another behind a proxy (S3).
     *
     * @param string $errors Login error messages.
     * @return string
     */
    public function filter_login_errors( $errors ) {
        $user_id = $this->get_pending_user_id();

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

        // An application password is a second factor of its own. The core
        // action that flags it only fires when those were the credentials (S16).
        if ( $this->authenticated_with_app_password( $user ) ) {
            return $user;
        }

        /*
         * There is deliberately no "already verifying, let it through" shortcut
         * here any more. Until 2.11.0 a request carrying action=vigilante_2fa,
         * the form nonce and a pending token returned $user at this point, and
         * all three are in the hands of whoever knows the password: the nonce
         * is printed on the form served to the pending visitor, and the token is
         * issued to that same visitor. wp-login.php never reached this filter
         * with that action, because login_form_vigilante_2fa ends the request,
         * but any other login form that calls wp_signon(), the WooCommerce one
         * for instance, does reach it and completed the login without a second
         * factor (S19, found in the 2.11.0 cross review and reproduced). The
         * verification form authenticates on its own path, handle_2fa_form(),
         * which never passes through wp_authenticate(): nothing legitimate
         * needed the shortcut.
         */

        // Check if user requires 2FA
        if ( ! $this->user_requires_2fa( $user ) ) {
            return $user;
        }

        // And whether this class is the one that must ask. Both are registered on
        // a network; the election is per account (see two_factor_handler_for()).
        if ( ! $this->handles_second_factor( $user, 'totp' ) ) {
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
                $grace_days    = absint( $this->policy()['grace_period_days'] ?? 3 );
                $grace_expires = ( $grace_days > 0 )
                    ? gmdate( 'Y-m-d H:i:s', time() + ( $grace_days * DAY_IN_SECONDS ) )
                    : gmdate( 'Y-m-d H:i:s', time() );
                $this->database->create_totp_placeholder( $user->ID, $grace_expires );
            }

            return $user;
        }

        // TOTP is configured - require verification. REST and XML-RPC have no
        // form to show, so the login is refused without a pending session (S16).
        if ( $this->is_api_request() ) {
            return $this->api_requires_2fa_error();
        }

        $this->set_pending_verification( $user->ID );

        $this->log_event( 'totp_verification_requested', $user->ID, __( 'TOTP verification requested at login', 'vigilante' ) );

        /*
         * This rejection is ours, not a wrong password: the credentials were
         * right and the account is being asked for its second factor. Until
         * 2.11.12 nothing marked it, and wp_authenticate() fires wp_login_failed
         * for every WP_Error that is not empty_username or empty_password
         * (wp-includes/pluggable.php, wp_authenticate()), so Login Security
         * counted one failed attempt for every correct password. With the
         * defaults (5 per address and hour, 3 codes per verification session)
         * two real tries were enough to lock the address out for 30 minutes,
         * and the activity log filled with failed logins that never happened.
         * The rejection is recognised by its error code, which
         * Vigilante_Login_Security::CONTROLLED_REJECTIONS lists along with the
         * six other refusals the plugin issues itself.
         */
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
        // One answer for the whole network: two factor is required if any site
        // the account belongs to asks for it, with that site's own enforced roles
        // and exclusions. See Vigilante_Settings::two_factor_required_for().
        return Vigilante_Settings::two_factor_required_for( $user );
    }

    /**
     * Check if user is within the grace period
     *
     * @param int $user_id User ID.
     * @return bool
     */
    private function is_within_grace_period( $user_id ) {
        $grace_days = absint( $this->policy()['grace_period_days'] ?? 3 );

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
     * Handle 2FA verification form submission
     */
    public function handle_2fa_form() {
        /*
         * Y solo ella la verifica. Volver aqui no deja pasar nada: la otra clase
         * esta enganchada a la misma accion y termina la peticion por su cuenta,
         * que es lo que evita el fallthrough a wp_signon() que avisa el comentario
         * de abajo.
         */
        if ( ! $this->pending_belongs_to( 'totp' ) ) {
            return;
        }

        // The pending user is resolved first so that a failed nonce can be
        // explained on the form and recorded (S15). Both failure paths end the
        // request: a bare return would let wp-login.php fall through to its
        // default case and call wp_signon(), completing the login without the
        // second factor.
        $user_id = $this->get_pending_user_id();

        if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'vigilante_2fa_verify' ) ) {
            $this->handle_invalid_nonce( $user_id );
        }

        if ( ! $user_id ) {
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        // Attempt limit per pending session (S2). Until 2.11.0 nothing counted
        // here: the lockout only runs on the authenticate filter, which this
        // form never passes through. The limit is checked before any code is
        // verified so that a session past it costs nothing, since a backup
        // code check alone is up to ten wp_check_password() calls.
        $max_attempts = absint( $this->policy()['max_attempts'] ?? 3 );

        if ( $max_attempts < 1 ) {
            $max_attempts = 3;
        }

        if ( $this->get_pending_attempts() >= $max_attempts ) {
            $this->log_event( 'totp_max_attempts_exceeded', $user_id, __( 'Maximum verification attempts exceeded', 'vigilante' ), 'warning' );
            $this->clear_pending_verification();

            // Until 2.11.12 this redirect carried no message: the visitor landed
            // on the password form with no idea the verification session had
            // been closed, typed the password again, and that correct password
            // counted as one more failed login.
            $this->redirect_to_login_with_notice( 'attempts' );
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
                $this->increment_pending_attempts();
                set_transient( 'vigilante_2fa_error_' . $user_id, $result->get_error_message(), 60 );
                wp_safe_redirect( add_query_arg( 'vigilante_2fa', '1', wp_login_url() ) );
                exit;
            }

            // Backup code succeeded
            $this->log_event( 'totp_backup_code_used', $user_id, __( 'Backup code used for authentication', 'vigilante' ), 'warning' );
        }

        // Verification successful. Read before the session is cleared: that is
        // where the redirect_to of the original login is kept.
        $redirect_to = $this->pending_login_redirect();

        $this->clear_pending_verification();

        // Trust device if requested (and if the option allows it, see trust_device)
        if ( $remember_device && $this->trust_device( $user_id ) ) {
            $this->log_event( 'totp_device_trusted', $user_id, __( 'Device saved as trusted', 'vigilante' ) );
        }

        $this->log_event( 'totp_verification_success', $user_id, __( 'TOTP verification successful', 'vigilante' ) );

        // Complete login
        $user = get_user_by( 'ID', $user_id );
        wp_set_current_user( $user_id, $user->user_login );
        wp_set_auth_cookie( $user_id, false );
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- wp_login is a WordPress core hook
        do_action( 'wp_login', $user->user_login, $user );

        wp_safe_redirect( $redirect_to );
        exit;
    }

    /**
     * Show 2FA form on login page
     */
    public function maybe_show_2fa_form() {
        // Solo la clase que atiende esta verificacion pinta su formulario.
        if ( ! $this->pending_belongs_to( 'totp' ) ) {
            return;
        }

        // Don't show 2FA form on logout or other non-auth actions
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Just checking URL params for display logic
        if ( isset( $_GET['loggedout'] ) || isset( $_GET['action'] ) ) {
            $action = isset( $_GET['action'] ) ? sanitize_key( $_GET['action'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if ( isset( $_GET['loggedout'] ) || in_array( $action, array( 'logout', 'lostpassword', 'register', 'rp', 'resetpass' ), true ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                return;
            }
        }

        // Only the visitor presenting the pending token gets the form. There is
        // no fallback by IP address and no lookup of the token by user (S3).
        $session = $this->get_pending_session();

        if ( ! $session ) {
            return;
        }

        $user_id = $session['user_id'];
        $token   = $session['token'];

        // Only show if user has TOTP configured
        $totp_data = $this->database->get_totp_data( $user_id );
        if ( ! $totp_data || empty( $totp_data['is_configured'] ) ) {
            return;
        }

        $error = get_transient( 'vigilante_2fa_error_' . $user_id );
        delete_transient( 'vigilante_2fa_error_' . $user_id );

        $remember_days = absint( $this->policy()['remember_device_days'] ?? 30 );

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
                       maxlength="20"
                       pattern="[a-zA-Z0-9 -]{6,20}"
                       inputmode="numeric"
                       autocomplete="one-time-code"
                       placeholder="000000"
                       autofocus
                       required>
            </p>

            <?php if ( ! empty( $this->policy()['allow_remember_device'] ) ) : ?>
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
        // Truly random bytes, Base32 encoded.
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
        // Password managers show the code in two groups of three and paste it
        // that way ("123 456"). sanitize_text_field() does not touch inner
        // spaces, so until 2.11.12 a correct code pasted from 1Password was
        // answered "Invalid code format" with no hint of why. Separators are
        // presentation, never part of the code: drop everything that is not a
        // digit before validating.
        $code = preg_replace( '/\D/', '', (string) $code );

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

        // A correct code from a device whose clock disagrees with the server's
        // matches a time step outside the window. It is never accepted here: the
        // window stays at what the RFC recommends. It is only recognised, so the
        // answer says "the clocks disagree" instead of the same "invalid code"
        // someone gets for a typo, which is what turns this into a support
        // thread. A random guess matching any of these steps is 1 in 24.000.
        $skew_seconds = 0;
        for ( $i = -self::SKEW_SCAN_STEPS; $i <= self::SKEW_SCAN_STEPS; $i++ ) {
            if ( abs( $i ) <= self::TIME_WINDOW ) {
                continue;
            }

            if ( hash_equals( $this->generate_code( $secret, $now + ( $i * self::TIME_STEP ) ), $code ) ) {
                $skew_seconds = $i * self::TIME_STEP;
                break;
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

        if ( 0 !== $skew_seconds ) {
            $minutes = max( 1, (int) round( abs( $skew_seconds ) / MINUTE_IN_SECONDS ) );

            $this->log_event(
                'totp_clock_skew',
                $user_id,
                sprintf(
                    /* translators: %d: Minutes of difference between the server clock and the authenticator app. */
                    __( 'A valid TOTP code was rejected: the server clock and the authenticator app differ by about %d minutes', 'vigilante' ),
                    $minutes
                ),
                'warning'
            );

            return new WP_Error(
                'clock_skew',
                sprintf(
                    /* translators: %d: Minutes of difference between the server clock and the authenticator app. */
                    __( 'That code is correct, but the server clock and your authenticator app differ by about %d minutes, so it cannot be accepted. Ask your host to fix the server time, or check the time settings of your app.', 'vigilante' ),
                    $minutes
                )
            );
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
        // Backup codes are 8 chars, lowercase alphanumeric. Whatever separators
        // the holder pasted in (spaces, dashes) are presentation, same as in a
        // TOTP code, and go before the length is measured.
        $code = strtolower( preg_replace( '/[^A-Za-z0-9]/', '', (string) $code ) );

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
     * @return string Encrypted string (base64), or empty string without a key.
     */
    public function encrypt_secret( $secret ) {
        $key = $this->get_encryption_key();

        if ( '' === $key ) {
            return '';
        }

        $iv = openssl_random_pseudo_bytes( 16 );

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

        if ( '' === $key ) {
            return false;
        }

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
     * Whether the site defines the key the authenticator secret is encrypted with
     *
     * @return bool
     */
    public function has_encryption_key() {
        return defined( 'AUTH_KEY' )
            && is_string( AUTH_KEY )
            && '' !== AUTH_KEY
            && 'put your unique phrase here' !== AUTH_KEY;
    }

    /**
     * Get encryption key derived from WordPress salts
     *
     * Until 2.11.0 a site without AUTH_KEY fell back to a literal written in
     * this file, which gave every such site the same key and made the
     * encryption cosmetic (S13). Without AUTH_KEY there is no key: setup
     * refuses and says why, and nothing is encrypted with a known value.
     *
     * @return string 32-byte key, or empty string when the site has none.
     */
    private function get_encryption_key() {
        if ( ! $this->has_encryption_key() ) {
            return '';
        }

        return hash( 'sha256', AUTH_KEY . 'vigilante_totp', true );
    }

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

        /*
         * And only for accounts this class actually asks. Since 2.11.10 the hooks
         * of both second factor classes go up whenever the feature is on, because
         * which one asks is decided per account and not per site, so without this
         * an install configured for a code by email would show an authenticator
         * app section to everybody. An account already enrolled keeps seeing it
         * while a second factor is required of it, whatever method the site asks
         * for, or it would have no way to manage or remove an enrolment it
         * already has.
         *
         * Since 2.11.11 an enrolment is not used while no site asks that account
         * for an app (see Vigilante_Settings::two_factor_handler_for()), and the
         * section says so instead of "Configured and active": the enrolment is
         * kept, comes back into use as soon as an app is asked for, and its owner
         * can still remove it or renew the backup codes from here. Removing it
         * there does not lead to a new QR code, because nothing asks for one, so
         * that button says what it does instead of "Set up new authenticator".
         */
        $in_use = $this->handles_second_factor( $user, 'totp', $configured );

        if ( ! $configured && ! $in_use ) {
            return;
        }

        wp_nonce_field( 'vigilante_totp_profile', 'vigilante_totp_nonce' );
        ?>
        <input type="hidden" class="vigilante-totp-user-id" value="<?php echo esc_attr( $user->ID ); ?>">
        <h2><?php esc_html_e( 'Two-Factor Authentication (TOTP)', 'vigilante' ); ?></h2>
        <table class="form-table vigilante-totp-profile" role="presentation">
            <?php if ( $configured ) : ?>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Status', 'vigilante' ); ?></th>
                    <td>
                        <?php if ( $in_use ) : ?>
                            <span class="vigilante-totp-status vigilante-totp-active">
                                <span class="dashicons dashicons-yes-alt"></span>
                                <?php esc_html_e( 'Configured and active', 'vigilante' ); ?>
                            </span>
                        <?php else : ?>
                            <span class="vigilante-totp-status vigilante-totp-inactive">
                                <span class="dashicons dashicons-info-outline"></span>
                                <?php esc_html_e( 'Configured, not in use', 'vigilante' ); ?>
                            </span>
                            <p class="description"><?php esc_html_e( 'Login for this account is verified with a code sent by email for now. This authenticator setup is kept and will be asked for again if an authenticator app becomes required for this account.', 'vigilante' ); ?></p>
                        <?php endif; ?>
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
                    <?php if ( $in_use ) : ?>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Reconfigure', 'vigilante' ); ?></th>
                    <td>
                        <button type="button" class="button vigilante-totp-reconfigure" data-user="<?php echo esc_attr( $user->ID ); ?>">
                            <?php esc_html_e( 'Set up new authenticator', 'vigilante' ); ?>
                        </button>
                        <p class="description"><?php esc_html_e( 'This will reset your current TOTP setup and require scanning a new QR code.', 'vigilante' ); ?></p>
                    </td>
                </tr>
                    <?php else : ?>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Remove', 'vigilante' ); ?></th>
                    <td>
                        <button type="button" class="button vigilante-totp-reconfigure vigilante-totp-remove" data-user="<?php echo esc_attr( $user->ID ); ?>" data-confirm="<?php esc_attr_e( 'This will remove the authenticator setup of this account and forget its trusted devices. Login keeps using the code sent by email. Continue?', 'vigilante' ); ?>">
                            <?php esc_html_e( 'Remove authenticator setup', 'vigilante' ); ?>
                        </button>
                        <p class="description"><?php esc_html_e( 'Removes this authenticator setup and forgets the trusted devices of this account. If an authenticator app becomes required later, a new one can be set up then.', 'vigilante' ); ?></p>
                    </td>
                </tr>
                    <?php endif; ?>
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
                                    <input type="text" id="vigilante_totp_verify_code" maxlength="20" pattern="[0-9 -]{6,20}" inputmode="numeric" autocomplete="off">
                                    <button type="button" class="button button-primary vigilante-totp-confirm-setup">
                                        <?php esc_html_e( 'Verify and activate', 'vigilante' ); ?>
                                    </button>
                                    <span class="vigilante-totp-setup-status"></span>
                                    <p class="description vigilante-totp-server-time">
                                        <?php
                                        printf(
                                            /* translators: %s: Server time in UTC, as YYYY-MM-DD HH:MM:SS. */
                                            esc_html__( 'Codes are tied to the clock. This server reads %s UTC right now; if that is more than half a minute away from the clock of the device running your app, no code will ever be accepted.', 'vigilante' ),
                                            esc_html( gmdate( 'Y-m-d H:i:s' ) )
                                        );
                                        ?>
                                    </p>
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
        // edit_user, not manage_options: on a network every subsite administrator
        // holds manage_options, and map_meta_cap denies edit_user against a user
        // they do not administer. On a single site an administrator still passes.
        if ( get_current_user_id() !== $user_id && ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        // Same normalisation as verify_totp_code(): separators are presentation.
        $code = preg_replace( '/\D/', '', (string) $code );

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

        if ( ! $this->has_encryption_key() ) {
            wp_send_json_error( __( 'This site does not define the AUTH_KEY security key, so the authenticator secret cannot be stored securely. Add the WordPress security keys to the site configuration and try again.', 'vigilante' ) );
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

        // edit_user, not manage_options: on a network every subsite administrator
        // holds manage_options, and map_meta_cap denies edit_user against a user
        // they do not administer. On a single site an administrator still passes.
        if ( get_current_user_id() !== $user_id && ! current_user_can( 'edit_user', $user_id ) ) {
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

        // edit_user, not manage_options: on a network every subsite administrator
        // holds manage_options, and map_meta_cap denies edit_user against a user
        // they do not administer. On a single site an administrator still passes.
        if ( get_current_user_id() !== $user_id && ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        $this->reset_user_totp( $user_id );

        wp_send_json_success( array(
            'message' => __( 'TOTP has been reset. You can now set up a new authenticator.', 'vigilante' ),
        ) );
    }

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

        /*
         * Only an account this class asks for its app: the same election as the
         * login and the profile section. Asking only whether some second factor
         * is required was enough while this class registered only on sites set to
         * an app; since 2.11.10 it registers wherever two factor is on, and an
         * account verified by email with a leftover row from a grace period was
         * sent to profile.php from every screen of the dashboard, where the setup
         * section is not shown to it, so nothing let it out.
         *
         * Asked first, and as if the account had no enrolment, because the row
         * read below is the expensive part: on a network, for an account with no
         * enrolment, it searches the table of every site the account can reach,
         * and most accounts verified by email have none. Assuming no enrolment
         * changes nothing here: with one, the answer can only move to the app,
         * and an enrolled account leaves at "already configured" anyway. This
         * also answers no when nothing is required, so it replaces
         * user_requires_2fa().
         */
        if ( ! $user->ID || ! $this->handles_second_factor( $user, 'totp', false ) ) {
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

        // Same election, in the same order and for the same reasons, as
        // force_totp_setup_redirect(): since 2.11.10 an account verified by email
        // was told on every screen to set up an app.
        if ( ! $user->ID || ! $this->handles_second_factor( $user, 'totp', false ) ) {
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
        $grace_days = absint( $this->policy()['grace_period_days'] ?? 3 );
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
     * Get TOTP setup data for a new setup
     *
     * @param int $user_id User ID.
     * @return array Setup data with secret and uri. The QR code is drawn in the
     *               browser from the uri, and always was.
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
        $grace_days  = absint( $this->policy()['grace_period_days'] ?? 3 );

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
