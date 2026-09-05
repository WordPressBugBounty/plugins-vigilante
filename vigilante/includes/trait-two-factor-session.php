<?php
/**
 * Shared two-factor session and trusted-device logic
 *
 * Used by Vigilante_Two_Factor_Email and Vigilante_Two_Factor_TOTP. Until
 * 2.11.0 both classes carried their own copy of this code, byte for byte,
 * which is how the trusted-device check kept identifying a browser by its
 * User-Agent in two places at once (S1 of the 28 Aug 2026 audit).
 *
 * The using class must provide $this->database (Vigilante_Database),
 * $this->options (the two_factor settings array) and log_event().
 *
 * @package Vigilante
 * @since 2.11.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Trait Vigilante_Two_Factor_Session
 */
trait Vigilante_Two_Factor_Session {

    /**
     * User ID authenticated through an application password in this request, or 0.
     *
     * Set by the core action application_password_did_authenticate, which only
     * fires when the credentials were an application password. That is a second
     * factor of its own, so the interactive verification does not apply (S16).
     *
     * @var int
     */
    private $app_password_user_id = 0;

    // =========================================================================
    // Names
    // =========================================================================

    /**
     * Cookie carrying the pending-verification token.
     *
     * @return string
     */
    private function pending_cookie_name() {
        return 'vigilante_2fa_token';
    }

    /**
     * Cookie carrying the trusted-device secret.
     *
     * @return string
     */
    private function device_cookie_name() {
        return 'vigilante_2fa_device';
    }

    // =========================================================================
    // Request context (S16)
    // =========================================================================

    /**
     * Register the hook that flags application-password logins.
     *
     * Called from the module's init_hooks().
     */
    protected function init_session_hooks() {
        add_action( 'application_password_did_authenticate', array( $this, 'remember_app_password_user' ) );
    }

    /**
     * Remember which user authenticated with an application password.
     *
     * @param WP_User $user Authenticated user.
     */
    public function remember_app_password_user( $user ) {
        if ( $user instanceof WP_User ) {
            $this->app_password_user_id = (int) $user->ID;
        }
    }

    /**
     * Whether this user was authenticated with an application password in this request.
     *
     * @param WP_User|mixed $user User being authenticated.
     * @return bool
     */
    private function authenticated_with_app_password( $user ) {
        return $user instanceof WP_User
            && $this->app_password_user_id > 0
            && (int) $user->ID === $this->app_password_user_id;
    }

    /**
     * Whether the request comes through REST or XML-RPC, where no form can be shown.
     *
     * @return bool
     */
    private function is_api_request() {
        if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
            return true;
        }

        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            return true;
        }

        return false;
    }

    /**
     * The error returned to an API login that still needs its second factor.
     *
     * No pending session is created and no code is sent: a connector that
     * retries with the main password used to trigger one email per attempt.
     *
     * @return WP_Error
     */
    private function api_requires_2fa_error() {
        return new WP_Error(
            'vigilante_2fa_required',
            __( 'This account requires two-factor authentication. Log in from a browser, or use an application password for API access.', 'vigilante' )
        );
    }

    // =========================================================================
    // Pending verification session (S3, S15)
    // =========================================================================

    /**
     * Set pending verification state
     *
     * The token travels only in an HttpOnly cookie (and in the hidden field of
     * the form the cookie holder is shown). There is no lookup by IP address:
     * behind a proxy or a CDN that used to hand one user's pending session to
     * whoever shared the apparent address (S3).
     *
     * @param int $user_id User ID.
     * @return string Token for the pending session
     */
    private function set_pending_verification( $user_id ) {
        $user_id = absint( $user_id );
        $token   = $this->get_existing_token_for_user( $user_id );
        $data    = $token ? get_transient( 'vigilante_2fa_pending_' . $token ) : false;

        if ( ! $token ) {
            $token = wp_generate_password( 32, false );
        }

        // The attempt counter survives a fresh password login within the hour,
        // so re-authenticating does not reset it (S2).
        $attempts = ( is_array( $data ) && isset( $data['attempts'] ) ) ? absint( $data['attempts'] ) : 0;

        set_transient(
            'vigilante_2fa_pending_' . $token,
            array(
                'user_id'    => $user_id,
                'created_at' => time(),
                'attempts'   => $attempts,
            ),
            HOUR_IN_SECONDS
        );

        // Reverse lookup (user_id -> token), used only to reuse the token on a
        // repeated password login. It is never handed to a visitor.
        set_transient( 'vigilante_2fa_user_token_' . $user_id, $token, HOUR_IN_SECONDS );

        $this->set_cookie( $this->pending_cookie_name(), $token, time() + HOUR_IN_SECONDS, 'Strict' );

        // Make the token available in the current request.
        $_COOKIE[ $this->pending_cookie_name() ] = $token;

        return $token;
    }

    /**
     * Get the existing pending token for a user if still valid
     *
     * @param int $user_id User ID.
     * @return string|false Token or false if not found
     */
    private function get_existing_token_for_user( $user_id ) {
        $token = get_transient( 'vigilante_2fa_user_token_' . absint( $user_id ) );

        if ( ! $token ) {
            return false;
        }

        $data = get_transient( 'vigilante_2fa_pending_' . $token );

        if ( ! is_array( $data ) || empty( $data['user_id'] ) || absint( $data['user_id'] ) !== absint( $user_id ) ) {
            return false;
        }

        return $token;
    }

    /**
     * The pending token presented by this request, from the form or the cookie.
     *
     * @return string Token or empty string.
     */
    private function get_pending_token() {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Session token, not form data: the verification form nonce is checked in handle_2fa_form() before anything acts on it.
        if ( isset( $_POST['vigilante_2fa_token'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Same token as the line above.
            return sanitize_text_field( wp_unslash( $_POST['vigilante_2fa_token'] ) );
        }

        if ( isset( $_COOKIE[ $this->pending_cookie_name() ] ) ) {
            return sanitize_text_field( wp_unslash( $_COOKIE[ $this->pending_cookie_name() ] ) );
        }

        return '';
    }

    /**
     * The pending session presented by this request.
     *
     * @return array|false Session data (user_id, created_at, attempts, token) or false.
     */
    private function get_pending_session() {
        $token = $this->get_pending_token();

        if ( '' === $token ) {
            return false;
        }

        $data = get_transient( 'vigilante_2fa_pending_' . $token );

        if ( ! is_array( $data ) || empty( $data['user_id'] ) ) {
            return false;
        }

        $data['user_id']  = absint( $data['user_id'] );
        $data['attempts'] = isset( $data['attempts'] ) ? absint( $data['attempts'] ) : 0;
        $data['token']    = $token;

        return $data;
    }

    /**
     * Get pending verification user ID
     *
     * @return int|false User ID or false if not pending
     */
    private function get_pending_user_id() {
        $session = $this->get_pending_session();

        return $session ? $session['user_id'] : false;
    }

    /**
     * Failed attempts recorded on the pending session presented by this request.
     *
     * @return int
     */
    private function get_pending_attempts() {
        $session = $this->get_pending_session();

        return $session ? $session['attempts'] : 0;
    }

    /**
     * Record one more failed attempt on the pending session.
     *
     * @return int Attempts after the increment, or 0 if there is no session.
     */
    private function increment_pending_attempts() {
        $session = $this->get_pending_session();

        if ( ! $session ) {
            return 0;
        }

        $token = $session['token'];
        unset( $session['token'] );
        $session['attempts']++;

        set_transient( 'vigilante_2fa_pending_' . $token, $session, HOUR_IN_SECONDS );

        return $session['attempts'];
    }

    /**
     * Clear pending verification
     */
    private function clear_pending_verification() {
        $token = $this->get_pending_token();

        if ( '' !== $token ) {
            $data = get_transient( 'vigilante_2fa_pending_' . $token );

            if ( is_array( $data ) && ! empty( $data['user_id'] ) ) {
                delete_transient( 'vigilante_2fa_user_token_' . absint( $data['user_id'] ) );
            }

            delete_transient( 'vigilante_2fa_pending_' . $token );
        }

        $this->set_cookie( $this->pending_cookie_name(), '', time() - YEAR_IN_SECONDS, 'Strict' );
        unset( $_COOKIE[ $this->pending_cookie_name() ] );
    }

    /**
     * End a form submission whose nonce did not verify (S15).
     *
     * Until 2.11.0 this redirected to the login screen with no message and no
     * record; the pending cookie was still set, so the form came back with no
     * explanation. Now the holder of a pending session sees why and the
     * attempt is logged. Either way the request ends here: a bare return would
     * let wp-login.php fall through to wp_signon() without the second factor.
     *
     * @param int|false $user_id Pending user, if any.
     */
    private function handle_invalid_nonce( $user_id ) {
        if ( $user_id ) {
            set_transient(
                'vigilante_2fa_error_' . $user_id,
                __( 'The verification form expired. Please try again.', 'vigilante' ),
                60
            );

            $this->log_event( '2fa_nonce_failed', $user_id, __( 'Verification form submitted with an invalid or expired nonce', 'vigilante' ), 'warning' );

            wp_safe_redirect( add_query_arg( 'vigilante_2fa', '1', wp_login_url() ) );
            exit;
        }

        wp_safe_redirect( wp_login_url() );
        exit;
    }

    // =========================================================================
    // Trusted devices (S1, S4)
    // =========================================================================

    /**
     * Check if the current device is trusted
     *
     * The device presents a random secret from an HttpOnly cookie and only its
     * SHA-256 is stored. Until 2.11.0 the identity was a hash of the User-Agent,
     * so anyone with the password who reproduced the browser string skipped the
     * second factor (S1). The option is enforced here as well: with it off no
     * stored row is honoured, whatever the form sent (S4).
     *
     * @param int $user_id User ID.
     * @return bool
     */
    private function is_device_trusted( $user_id ) {
        if ( empty( $this->options['allow_remember_device'] ) ) {
            return false;
        }

        $token = $this->present_device_token();

        if ( '' === $token ) {
            return false;
        }

        return $this->database->is_device_trusted( absint( $user_id ), hash( 'sha256', $token ) );
    }

    /**
     * Trust the current device
     *
     * Ignored silently when the option is off: a cached form may still send
     * the checkbox, and that is no reason to refuse the login (S4).
     *
     * @param int $user_id User ID.
     * @return bool True if a device row was written.
     */
    private function trust_device( $user_id ) {
        if ( empty( $this->options['allow_remember_device'] ) ) {
            return false;
        }

        try {
            $token = bin2hex( random_bytes( 32 ) );
        } catch ( Exception $e ) {
            return false;
        }

        $user_agent    = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
        $remember_days = absint( $this->options['remember_device_days'] ?? 30 );

        if ( $remember_days < 1 ) {
            $remember_days = 30;
        }

        $expires = time() + ( $remember_days * DAY_IN_SECONDS );

        // The User-Agent is kept as a label for the device list only; it plays
        // no part in recognising the device.
        $written = $this->database->trust_device(
            absint( $user_id ),
            hash( 'sha256', $token ),
            $user_agent,
            gmdate( 'Y-m-d H:i:s', $expires )
        );

        if ( ! $written ) {
            return false;
        }

        // Lax, not Strict: the cookie has to travel on the GET that brings the
        // user back to wp-login.php from another site.
        $this->set_cookie( $this->device_cookie_name(), $token, $expires, 'Lax' );

        return true;
    }

    /**
     * The device secret presented by this request, if well formed.
     *
     * @return string 64 hex characters or empty string.
     */
    private function present_device_token() {
        if ( ! isset( $_COOKIE[ $this->device_cookie_name() ] ) ) {
            return '';
        }

        $token = sanitize_text_field( wp_unslash( $_COOKIE[ $this->device_cookie_name() ] ) );

        return preg_match( '/^[0-9a-f]{64}$/', $token ) ? $token : '';
    }

    // =========================================================================
    // Cookies
    // =========================================================================

    /**
     * Set a plugin cookie with the attributes every 2FA cookie shares.
     *
     * @param string $name     Cookie name.
     * @param string $value    Value (empty to clear).
     * @param int    $expires  Expiry timestamp.
     * @param string $samesite Lax or Strict.
     */
    private function set_cookie( $name, $value, $expires, $samesite ) {
        if ( headers_sent() ) {
            return;
        }

        setcookie(
            $name,
            $value,
            array(
                'expires'  => $expires,
                'path'     => COOKIEPATH,
                'domain'   => COOKIE_DOMAIN,
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => $samesite,
            )
        );
    }
}
