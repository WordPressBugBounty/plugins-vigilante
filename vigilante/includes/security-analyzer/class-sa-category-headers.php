<?php
/**
 * Security Analyzer — HTTP headers category (18 pts).
 *
 * Reads the actual headers served from the homepage and cross-checks them
 * with the Vigilante Security Headers settings. When a setting is enabled
 * but the header is missing in the response the result is a WARN with the
 * useful "configured but not applied" diagnostic.
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * HTTP security headers checks.
 */
class Vigilante_SA_Category_Headers {

    const SLUG = 'headers';

    /**
     * @var Vigilante_Settings
     */
    private $settings;

    public function __construct( Vigilante_Settings $settings ) {
        $this->settings = $settings;
    }

    /**
     * Run the category. All checks need the home probe, so they're all in slow phase.
     *
     * @param string $phase 'fast' | 'slow' | 'all'.
     * @return Vigilante_SA_Check_Result[]
     */
    public function run( $phase = 'all' ) {
        if ( 'fast' === $phase ) {
            return array();
        }

        $probe    = Vigilante_SA_Helpers::probe_home();
        $headers  = ( $probe && isset( $probe['headers'] ) ) ? $probe['headers'] : array();
        $sec_hdrs = $this->settings->get_section( 'security_headers' );

        $results = array();
        $results[] = $this->check_csp( $headers, $sec_hdrs );
        $results[] = $this->check_hsts( $headers, $sec_hdrs );
        $results[] = $this->check_x_frame( $headers );
        $results[] = $this->check_x_content_type( $headers );
        $results[] = $this->check_referrer_policy( $headers );
        $results[] = $this->check_permissions_policy( $headers );
        $results[] = $this->check_coop( $headers );
        $results[] = $this->check_corp( $headers );
        $results[] = $this->check_server_signature( $headers );

        // If the probe failed entirely, mark all as SKIP.
        if ( null === $probe ) {
            foreach ( $results as $r ) {
                $r->state  = Vigilante_SA_Check_Result::STATE_SKIP;
                $r->score  = 0;
                $r->detail = __( 'Could not fetch the homepage to read response headers.', 'vigilante' );
            }
        }

        return $results;
    }

    private function check_csp( $headers, $sec_hdrs ) {
        $args = array(
            'id'       => 'csp',
            'category' => self::SLUG,
            'max'      => 4,
            'label'    => __( 'Content-Security-Policy', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-csp' ),
        );

        $setting_on = ! empty( $sec_hdrs['csp']['enabled'] );
        $header     = $this->header_value( $headers, array( 'content-security-policy', 'content-security-policy-report-only' ) );

        if ( $header ) {
            $args['detail'] = sprintf(
                /* translators: %s: header value (truncated) */
                __( 'CSP delivered: %s', 'vigilante' ),
                $this->truncate( $header, 80 )
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        if ( $setting_on ) {
            $args['detail'] = __( 'CSP is enabled in Vigilant but the Content-Security-Policy header is not reaching the browser. A server rule or CDN is likely stripping it.', 'vigilante' );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $args['detail'] = __( 'Content-Security-Policy is not enabled. Turn it on under Security Headers → CSP.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_hsts( $headers, $sec_hdrs ) {
        $args = array(
            'id'       => 'hsts',
            'category' => self::SLUG,
            'max'      => 3,
            'label'    => __( 'Strict-Transport-Security', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-hsts' ),
        );

        $setting_on = ! empty( $sec_hdrs['hsts']['enabled'] );
        $header     = $this->header_value( $headers, array( 'strict-transport-security' ) );

        if ( $header ) {
            $args['detail'] = sprintf(
                /* translators: %s: HSTS header value */
                __( 'HSTS header value: %s', 'vigilante' ),
                $header
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        if ( $setting_on ) {
            $args['detail'] = __( 'HSTS is enabled in Vigilant but the header is not being served (often caused by caching layers or HTTP-level servers).', 'vigilante' );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $args['detail'] = __( 'HSTS is disabled. Enable it after confirming HTTPS works correctly to prevent downgrade attacks.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_x_frame( $headers ) {
        $args = array(
            'id'       => 'x_frame',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'X-Frame-Options', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-main' ),
        );

        $header = $this->header_value( $headers, array( 'x-frame-options' ) );
        if ( $header ) {
            $args['detail'] = sprintf(
                /* translators: %s: x-frame-options value */
                __( 'X-Frame-Options header value: %s', 'vigilante' ),
                $header
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'X-Frame-Options header is missing. Attackers could embed your site in an iframe for click-jacking.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_x_content_type( $headers ) {
        $args = array(
            'id'       => 'x_content_type',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'X-Content-Type-Options', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-main' ),
        );

        $header = $this->header_value( $headers, array( 'x-content-type-options' ) );
        if ( $header && stripos( $header, 'nosniff' ) !== false ) {
            $args['detail'] = __( 'X-Content-Type-Options header set to nosniff.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'X-Content-Type-Options: nosniff is missing. The browser may interpret files as a type other than declared.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_referrer_policy( $headers ) {
        $args = array(
            'id'       => 'referrer_policy',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Referrer-Policy', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-main' ),
        );

        $header = $this->header_value( $headers, array( 'referrer-policy' ) );
        if ( $header ) {
            $args['detail'] = sprintf(
                /* translators: %s: referrer policy value */
                __( 'Referrer-Policy: %s', 'vigilante' ),
                $header
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'Referrer-Policy header is missing. The browser decides what to leak in the Referer by default.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_permissions_policy( $headers ) {
        $args = array(
            'id'       => 'permissions_policy',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Permissions-Policy', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-main' ),
        );

        $header = $this->header_value( $headers, array( 'permissions-policy', 'feature-policy' ) );
        if ( $header ) {
            $args['detail'] = sprintf(
                /* translators: %s: header value (truncated) */
                __( 'Permissions-Policy header value: %s', 'vigilante' ),
                $this->truncate( $header, 80 )
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'Permissions-Policy is missing. Browsers allow all capabilities (geolocation, camera, etc.) by default.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_coop( $headers ) {
        $args = array(
            'id'       => 'coop',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'Cross-Origin-Opener-Policy', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-cross-origin' ),
        );

        $header = $this->header_value( $headers, array( 'cross-origin-opener-policy' ) );
        if ( $header ) {
            /* translators: %s: value of the Cross-Origin-Opener-Policy HTTP header */
            $args['detail'] = sprintf( __( 'COOP: %s', 'vigilante' ), $header );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'Cross-Origin-Opener-Policy is missing. Recommended to isolate the browsing context.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_corp( $headers ) {
        $args = array(
            'id'       => 'corp',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'Cross-Origin-Resource-Policy', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-cross-origin' ),
        );

        $header = $this->header_value( $headers, array( 'cross-origin-resource-policy' ) );
        if ( $header ) {
            /* translators: %s: value of the Cross-Origin-Resource-Policy HTTP header */
            $args['detail'] = sprintf( __( 'CORP: %s', 'vigilante' ), $header );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'Cross-Origin-Resource-Policy is missing. Cross-origin fetches are unrestricted.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_server_signature( $headers ) {
        $args = array(
            'id'       => 'server_signature',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'Server fingerprint exposure', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-fingerprint' ),
        );

        $server      = $this->header_value( $headers, array( 'server' ) );
        $x_powered   = $this->header_value( $headers, array( 'x-powered-by' ) );
        $leaks       = array();

        if ( $server && preg_match( '#[\d\.]+#', $server ) ) {
            $leaks[] = 'Server: ' . $server;
        }
        if ( $x_powered ) {
            $leaks[] = 'X-Powered-By: ' . $x_powered;
        }

        if ( empty( $leaks ) ) {
            $args['detail'] = __( 'No server or PHP version information found in response headers.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %s: comma-separated leaked headers */
            __( 'Version information leaked through response headers: %s', 'vigilante' ),
            implode( ' | ', $leaks )
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    /**
     * Read a header value from the normalized map, trying multiple key variants.
     *
     * @param array<string,string> $headers Normalized lowercase headers.
     * @param string[]             $keys    Candidate keys.
     * @return string Value or empty string.
     */
    private function header_value( $headers, $keys ) {
        foreach ( $keys as $key ) {
            $k = strtolower( $key );
            if ( isset( $headers[ $k ] ) && '' !== trim( $headers[ $k ] ) ) {
                return $headers[ $k ];
            }
        }
        return '';
    }

    private function truncate( $text, $len ) {
        $text = (string) $text;
        if ( strlen( $text ) <= $len ) {
            return $text;
        }
        return substr( $text, 0, $len ) . '…';
    }
}
