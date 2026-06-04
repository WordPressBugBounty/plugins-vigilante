<?php
/**
 * Security Analyzer — SSL/TLS category (12 pts).
 *
 * Checks: ssl_present (2), ssl_cert_valid (2), ssl_cert_expiry (2),
 * https_redirect (1), tls_version (1), mixed_content (2), force_ssl_admin (2).
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * SSL/TLS checks.
 *
 * Fast checks: is_ssl(), constants, settings.
 * Slow checks: cert parsing, HTTP redirect probe, mixed content regex.
 */
class Vigilante_SA_Category_SSL {

    const SLUG = 'ssl';

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
            $results[] = $this->check_ssl_present();
            $results[] = $this->check_force_ssl_admin();
        }

        if ( 'slow' === $phase || 'all' === $phase ) {
            $cert = Vigilante_SA_Helpers::probe_tls();
            $results[] = $this->check_ssl_cert_valid( $cert );
            $results[] = $this->check_ssl_cert_expiry( $cert );
            $results[] = $this->check_https_redirect();
            $results[] = $this->check_tls_version( $cert );
            $results[] = $this->check_mixed_content();
        }

        return $results;
    }

    private function check_ssl_present() {
        $has_ssl  = is_ssl();
        $home_url = (string) get_option( 'home' );
        $site_url = (string) get_option( 'siteurl' );
        $urls_ok  = 0 === strpos( $home_url, 'https://' ) && 0 === strpos( $site_url, 'https://' );

        $args = array(
            'id'       => 'ssl_present',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'HTTPS status', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-force-https' ),
        );

        if ( $has_ssl && $urls_ok ) {
            $args['detail'] = __( 'Site uses HTTPS; both home and siteurl URLs start with https://.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }
        if ( $has_ssl && ! $urls_ok ) {
            $args['detail'] = __( 'HTTPS is active but one of the WordPress URLs (home/siteurl) still uses http://. Update them under Settings → General.', 'vigilante' );
            return Vigilante_SA_Check_Result::warn( $args );
        }
        $args['detail'] = __( 'HTTPS is not active. Enable a TLS certificate in your host and force HTTPS redirection.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_ssl_cert_valid( $cert ) {
        $args = array(
            'id'       => 'ssl_cert_valid',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'TLS certificate', 'vigilante' ),
            'fix_link' => '',
        );

        if ( empty( $cert ) || empty( $cert['valid'] ) ) {
            $args['detail'] = __( 'Could not read a valid TLS certificate for the public domain. Check your hosting or CDN.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $now = time();
        if ( $cert['valid_from'] > 0 && $now < $cert['valid_from'] ) {
            $args['detail'] = __( 'The certificate is not yet valid (notBefore in the future). Check the server clock.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }
        if ( $cert['valid_to'] > 0 && $now > $cert['valid_to'] ) {
            $args['detail'] = __( 'The certificate has expired. Renew it immediately in your host.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $args['detail'] = sprintf(
            /* translators: 1: issuer CN, 2: subject CN */
            __( 'Issued by %1$s for %2$s.', 'vigilante' ),
            $cert['issuer'] ? $cert['issuer'] : __( '(unknown)', 'vigilante' ),
            $cert['subject'] ? $cert['subject'] : __( '(unknown)', 'vigilante' )
        );
        $args['data'] = array(
            'issuer'  => $cert['issuer'],
            'subject' => $cert['subject'],
        );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_ssl_cert_expiry( $cert ) {
        $args = array(
            'id'       => 'ssl_cert_expiry',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Certificate expiry', 'vigilante' ),
            'fix_link' => '',
        );

        if ( empty( $cert ) || empty( $cert['valid'] ) || null === $cert['days_left'] ) {
            $args['detail'] = __( 'Could not read the certificate expiry.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $days         = (int) $cert['days_left'];
        $args['data'] = array( 'days_left' => $days );

        if ( $days < 0 ) {
            $args['detail'] = sprintf(
                /* translators: %d: days since expiry */
                __( 'The certificate expired %d days ago.', 'vigilante' ),
                abs( $days )
            );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        if ( $days < 14 ) {
            $args['detail'] = sprintf(
                /* translators: %d: days remaining */
                __( 'The certificate expires in %d days. Schedule renewal now.', 'vigilante' ),
                $days
            );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        if ( $days < 30 ) {
            $args['detail'] = sprintf(
                /* translators: %d: days remaining */
                __( 'The certificate expires in %d days. Plan renewal soon.', 'vigilante' ),
                $days
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: days remaining */
            __( '%d days until the certificate expires.', 'vigilante' ),
            $days
        );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_https_redirect() {
        $args = array(
            'id'       => 'https_redirect',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'HTTP → HTTPS redirect', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-force-https' ),
        );

        $http_url = set_url_scheme( home_url( '/' ), 'http' );
        $response = Vigilante_SA_Helpers::get( $http_url, array( 'redirection' => 0 ) );

        if ( is_wp_error( $response ) ) {
            $args['detail'] = __( 'Could not probe the HTTP version of the site (firewall may be blocking self-requests).', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $code     = (int) wp_remote_retrieve_response_code( $response );
        $location = (string) wp_remote_retrieve_header( $response, 'location' );

        if ( $code >= 300 && $code < 400 && 0 === strpos( $location, 'https://' ) ) {
            $args['detail'] = __( 'HTTP requests received a 3xx redirect to an https:// URL.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'The site is reachable over plain HTTP without a redirect to HTTPS.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_tls_version( $cert ) {
        $args = array(
            'id'       => 'tls_version',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'TLS version', 'vigilante' ),
            'fix_link' => '',
        );

        if ( empty( $cert ) || empty( $cert['tls_version'] ) ) {
            $args['detail'] = __( 'Could not determine the negotiated TLS version.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $version      = $cert['tls_version'];
        $args['data'] = array( 'tls_version' => $version );

        if ( stripos( $version, 'TLSv1.3' ) !== false || stripos( $version, 'TLSv1.2' ) !== false ) {
            $args['detail'] = sprintf(
                /* translators: %s: TLS version like TLSv1.3 */
                __( 'The server negotiated %s.', 'vigilante' ),
                $version
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %s: TLS version */
            __( 'The server negotiated %s. Ask your host to disable TLS 1.0/1.1.', 'vigilante' ),
            $version
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_mixed_content() {
        $args = array(
            'id'       => 'mixed_content',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Mixed content on the homepage', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-main' ),
        );

        $fix_setting = (int) $this->settings->get_option( 'security_headers', 'fix_mixed_content', 0 );
        $probe       = Vigilante_SA_Helpers::probe_home();

        if ( null === $probe ) {
            $args['detail'] = __( 'Could not fetch the homepage to scan for insecure resources.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        // Count http:// occurrences in src/href attributes on HTTPS pages only.
        if ( ! is_ssl() ) {
            $args['detail'] = __( 'HTTPS is not active yet, so mixed content cannot be evaluated.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $matches = array();
        preg_match_all( '#(src|href)=["\']http://[^"\']+["\']#i', $probe['body'], $matches );
        $count = isset( $matches[0] ) ? count( $matches[0] ) : 0;

        $args['data'] = array(
            'insecure_refs'      => $count,
            'fix_setting_active' => (bool) $fix_setting,
        );

        if ( 0 === $count ) {
            $args['detail'] = $fix_setting
                ? __( 'No insecure references in the homepage HTML; mixed-content fix is enabled in settings.', 'vigilante' )
                : __( 'No insecure references found in the homepage HTML.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        if ( $fix_setting ) {
            $args['detail'] = sprintf(
                /* translators: %d: number of insecure references */
                __( '%d http:// references still leaked despite the mixed-content fix being enabled. Inspect the theme or a plugin output.', 'vigilante' ),
                $count
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: number of insecure references */
            __( '%d insecure http:// references found. Enable the mixed-content fix under Security Headers.', 'vigilante' ),
            $count
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_force_ssl_admin() {
        $args = array(
            'id'       => 'force_ssl_admin',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'FORCE_SSL_ADMIN constant', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'wp-hardening', 'field-force-ssl-admin' ),
        );

        $active = defined( 'FORCE_SSL_ADMIN' ) && FORCE_SSL_ADMIN;
        if ( $active ) {
            $args['detail'] = __( 'FORCE_SSL_ADMIN is defined as true; admin and login traffic requires HTTPS.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        if ( ! is_ssl() ) {
            $args['detail'] = __( 'HTTPS is not active yet, so enforcing SSL for the admin area is not applicable.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $args['detail'] = __( 'FORCE_SSL_ADMIN is not set. Enable it from the WP Hardening tab so admin and login cookies only travel over HTTPS.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }
}
