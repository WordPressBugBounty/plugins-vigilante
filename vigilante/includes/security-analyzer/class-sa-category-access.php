<?php
/**
 * Security Analyzer — Access/Auth category (20 pts).
 *
 * Checks: wp_login_path (5), xmlrpc (5), wp_admin_direct (2),
 * rest_users_me (2), login_rate_limit (3), two_factor_enabled (3).
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Authentication and access-control checks.
 */
class Vigilante_SA_Category_Access {

    const SLUG = 'access';

    /**
     * @var Vigilante_Settings
     */
    private $settings;

    public function __construct( Vigilante_Settings $settings ) {
        $this->settings = $settings;
    }

    /**
     * Run the category.
     *
     * @param string $phase 'fast' | 'slow' | 'all'.
     * @return Vigilante_SA_Check_Result[]
     */
    public function run( $phase = 'all' ) {
        $results = array();

        if ( 'fast' === $phase || 'all' === $phase ) {
            $results[] = $this->check_custom_login_url();
            $results[] = $this->check_xmlrpc_setting();
            $results[] = $this->check_login_rate_limit();
            $results[] = $this->check_two_factor_enabled();
        }

        if ( 'slow' === $phase || 'all' === $phase ) {
            $results[] = $this->check_wp_admin_direct();
            $results[] = $this->check_rest_users_me();
        }

        return $results;
    }

    private function check_custom_login_url() {
        $args = array(
            'id'       => 'wp_login_path',
            'category' => self::SLUG,
            'max'      => 5,
            'label'    => __( 'Custom login URL', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'login', 'field-custom-login-url' ),
        );

        $url = trim( (string) $this->settings->get_option( 'login_security', 'custom_login_url', '' ) );
        if ( '' === $url ) {
            $args['detail'] = __( 'The login page is still the default /wp-login.php — a known bot target.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %s: slug */
            __( 'Custom login URL set to /%s. Remember to bookmark it.', 'vigilante' ),
            $url
        );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_xmlrpc_setting() {
        $args = array(
            'id'       => 'xmlrpc',
            'category' => self::SLUG,
            'max'      => 5,
            'label'    => __( 'XML-RPC status', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'login', 'field-disable-xmlrpc' ),
        );

        $disabled = (int) $this->settings->get_option( 'login_security', 'disable_xmlrpc', 0 );
        if ( $disabled ) {
            $args['detail'] = __( 'Vigilant XML-RPC block is enabled in settings; brute-force and pingback amplification vectors closed.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'XML-RPC is still enabled. Unless Jetpack or a mobile app requires it, disable it under Login.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_login_rate_limit() {
        $args = array(
            'id'       => 'login_rate_limit',
            'category' => self::SLUG,
            'max'      => 3,
            'label'    => __( 'Brute-force lockout threshold', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'login', 'field-max-attempts' ),
        );

        $max = (int) $this->settings->get_option( 'login_security', 'max_attempts', 0 );
        $args['data'] = array( 'max_attempts' => $max );

        if ( 0 === $max ) {
            $args['detail'] = __( 'Login lockout is not configured. Any IP can try passwords without limit.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }
        if ( $max > 10 ) {
            $args['detail'] = sprintf(
                /* translators: %d: configured attempts */
                __( 'Lockout after %d attempts is too permissive. Lower it to 5 or fewer.', 'vigilante' ),
                $max
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }
        if ( $max > 5 ) {
            $args['detail'] = sprintf(
                /* translators: %d: configured attempts */
                __( 'Lockout after %d attempts is acceptable but tighter is better.', 'vigilante' ),
                $max
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: configured attempts */
            __( 'Lockout after %d failed attempts.', 'vigilante' ),
            $max
        );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_two_factor_enabled() {
        $args = array(
            'id'       => 'two_factor_enabled',
            'category' => self::SLUG,
            'max'      => 3,
            'label'    => __( 'Two-factor authentication status', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'login', 'vigilante-section-login-2fa' ),
        );

        $two_factor = $this->settings->get_option( 'login_security', 'two_factor', array() );
        if ( ! empty( $two_factor['enabled'] ) ) {
            $method = isset( $two_factor['method'] ) ? $two_factor['method'] : 'email';
            $args['detail'] = sprintf(
                /* translators: %s: 2FA method */
                __( '2FA enabled globally using %s.', 'vigilante' ),
                strtoupper( $method )
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'Two-factor authentication is disabled. Enable it at least for administrators.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_wp_admin_direct() {
        $args = array(
            'id'       => 'wp_admin_direct',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( '/wp-admin/ public access', 'vigilante' ),
            'fix_link' => '',
        );

        $url      = trailingslashit( admin_url() );
        $response = Vigilante_SA_Helpers::get( $url, array( 'redirection' => 0 ) );

        if ( is_wp_error( $response ) ) {
            $args['detail'] = __( 'Could not probe /wp-admin/.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $code     = (int) wp_remote_retrieve_response_code( $response );
        $location = (string) wp_remote_retrieve_header( $response, 'location' );

        // Anonymous access to /wp-admin/ is considered safe when it either
        // redirects to a login page (typical) or is blocked/hidden (4xx).
        // A 200 with an HTML body is the only truly bad outcome.
        if ( in_array( $code, array( 301, 302, 303, 307, 308 ), true ) && $location ) {
            $args['detail'] = __( '/wp-admin/ redirected anonymous visits to the login page.', 'vigilante' );
            $args['data']   = array( 'code' => $code, 'location' => $location );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        // 4xx => camouflaged URL, firewall rule, or permission denied. All good.
        if ( $code >= 400 && $code < 500 ) {
            $args['detail'] = sprintf(
                /* translators: %d: HTTP status code */
                __( '/wp-admin/ returned %d to anonymous visitors.', 'vigilante' ),
                $code
            );
            $args['data'] = array( 'code' => $code );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        if ( 200 === $code ) {
            $args['detail'] = __( '/wp-admin/ returned 200 OK to an anonymous request. Verify nothing sensitive is exposed.', 'vigilante' );
            $args['data']   = array( 'code' => $code );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        // 5xx or other weirdness — server issue, not a hardening problem on our side.
        $args['detail'] = sprintf(
            /* translators: %d: HTTP status code */
            __( '/wp-admin/ responded with %d. This usually indicates a server error rather than a security issue.', 'vigilante' ),
            $code
        );
        $args['data'] = array( 'code' => $code );
        return Vigilante_SA_Check_Result::warn( $args );
    }

    private function check_rest_users_me() {
        $args = array(
            'id'       => 'rest_users_me',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'REST /wp/v2/users/me access', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'rest-api', 'vigilante-section-rest-api-main' ),
        );

        $url      = rest_url( 'wp/v2/users/me' );
        $response = Vigilante_SA_Helpers::get( $url, array( 'redirection' => 0 ) );

        if ( is_wp_error( $response ) ) {
            $args['detail'] = __( 'Could not probe /wp/v2/users/me.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $code = (int) wp_remote_retrieve_response_code( $response );
        if ( 401 === $code ) {
            $args['detail'] = __( 'The endpoint returns 401 to unauthenticated requests.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }
        if ( 403 === $code ) {
            $args['detail'] = __( 'The endpoint returns 403 to unauthenticated requests.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: HTTP status code */
            __( '/wp/v2/users/me responded with %d — should be 401 for anonymous.', 'vigilante' ),
            $code
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }
}
