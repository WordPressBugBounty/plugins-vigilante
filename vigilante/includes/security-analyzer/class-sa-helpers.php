<?php
/**
 * Security Analyzer — Shared helpers.
 *
 * HTTP/SSL probes, grade calculation, admin URL builder, PHP EOL table.
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Static utilities for the Security Analyzer categories.
 */
class Vigilante_SA_Helpers {

    /**
     * Cached GET of home URL headers+body. Lives in a runtime static so
     * multiple checks within the same scan don't hit the front-end twice.
     *
     * @var array|null
     */
    private static $home_probe = null;

    /**
     * Cached TLS/cert info for home URL.
     *
     * @var array|null
     */
    private static $tls_info = null;

    /**
     * PHP End-of-Life table (YYYY-MM-DD). Hardcoded to avoid external API.
     * Source: https://www.php.net/supported-versions.php
     * Update with each Vigilante release if a PHP branch enters or exits support.
     *
     * @return array<string,string>
     */
    public static function php_eol_table() {
        return array(
            '7.4' => '2022-11-28',
            '8.0' => '2023-11-26',
            '8.1' => '2025-12-31',
            '8.2' => '2026-12-31',
            '8.3' => '2027-12-31',
            '8.4' => '2028-12-31',
        );
    }

    /**
     * Return expected major.minor key for the current PHP runtime (e.g. "8.2").
     *
     * @return string
     */
    public static function current_php_branch() {
        return PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    }

    /**
     * Compute a 0-100 score and A..E grade aligned with the Dashboard palette.
     *
     * @param int $earned  Points earned.
     * @param int $maximum Total available points (should be <=100).
     * @return array { int score, string grade }
     */
    public static function compute_grade( $earned, $maximum ) {
        $maximum = max( 1, (int) $maximum );
        $score   = (int) round( ( max( 0, (int) $earned ) / $maximum ) * 100 );
        $score   = max( 0, min( 100, $score ) );

        // A is reserved for a perfect score — a single missing point drops to B.
        if ( 100 === $score ) {
            $grade = 'A';
        } elseif ( $score >= 70 ) {
            $grade = 'B';
        } elseif ( $score >= 50 ) {
            $grade = 'C';
        } elseif ( $score >= 30 ) {
            $grade = 'D';
        } else {
            $grade = 'E';
        }

        return array(
            'score' => $score,
            'grade' => $grade,
        );
    }

    /**
     * Build a fix link pointing to a specific Vigilante tab + section/field.
     *
     * Format: admin.php?page=vigilante&tab=<tab>#<anchor>
     * Where <anchor> is either vigilante-section-<section> or field-<slug>.
     *
     * @param string $tab    Tab slug (dashboard, firewall, headers, etc).
     * @param string $anchor Anchor without leading "#".
     * @return string
     */
    public static function build_fix_url( $tab, $anchor = '' ) {
        $url = admin_url( 'admin.php?page=vigilante&tab=' . rawurlencode( $tab ) );
        if ( $anchor ) {
            $url .= '#' . $anchor;
        }
        return $url;
    }

    /**
     * Fetch the front-end homepage once per scan and cache the result.
     * Returns null if the request could not be completed.
     *
     * @param bool $force_refresh Bust the in-memory cache.
     * @return array|null { int code, array headers, string body }
     */
    public static function probe_home( $force_refresh = false ) {
        if ( ! $force_refresh && null !== self::$home_probe ) {
            return self::$home_probe;
        }

        $response = wp_remote_get(
            home_url( '/' ),
            array(
                'timeout'     => 4,
                'redirection' => 2,
                'sslverify'   => true,
                'headers'     => array(
                    'User-Agent' => 'Vigilant-Security-Analyzer/1.0',
                ),
            )
        );

        if ( is_wp_error( $response ) ) {
            self::$home_probe = null;
            return null;
        }

        self::$home_probe = array(
            'code'    => (int) wp_remote_retrieve_response_code( $response ),
            'headers' => self::normalize_headers( wp_remote_retrieve_headers( $response ) ),
            'body'    => (string) wp_remote_retrieve_body( $response ),
        );
        return self::$home_probe;
    }

    /**
     * Fetch any URL with hardened defaults. Returns WP_Error or response array.
     *
     * @param string $url     Full URL.
     * @param array  $extra   Extra wp_remote_get arguments.
     * @return array|WP_Error
     */
    public static function get( $url, array $extra = array() ) {
        $args = array_merge(
            array(
                'timeout'     => 3,
                'redirection' => 0,
                'sslverify'   => true,
                'headers'     => array(
                    'User-Agent' => 'Vigilant-Security-Analyzer/1.0',
                ),
            ),
            $extra
        );
        return wp_remote_get( $url, $args );
    }

    /**
     * Normalize Requests_Utility_CaseInsensitiveDictionary (or plain array) to a lowercase-keyed array.
     *
     * @param mixed $headers Response headers from wp_remote_retrieve_headers.
     * @return array<string,string>
     */
    public static function normalize_headers( $headers ) {
        $result = array();
        if ( is_object( $headers ) && method_exists( $headers, 'getAll' ) ) {
            foreach ( $headers->getAll() as $key => $value ) {
                $result[ strtolower( $key ) ] = is_array( $value ) ? implode( ', ', $value ) : (string) $value;
            }
            return $result;
        }
        if ( is_array( $headers ) ) {
            foreach ( $headers as $key => $value ) {
                $result[ strtolower( $key ) ] = is_array( $value ) ? implode( ', ', $value ) : (string) $value;
            }
        }
        return $result;
    }

    /**
     * Inspect the SSL certificate of the site via stream_socket_client.
     * Returns an array with { valid, issuer, valid_from, valid_to, days_left, tls_version } or null on failure.
     *
     * @param bool $force_refresh Bust in-memory cache.
     * @return array|null
     */
    public static function probe_tls( $force_refresh = false ) {
        if ( ! $force_refresh && null !== self::$tls_info ) {
            return self::$tls_info;
        }

        if ( ! function_exists( 'stream_socket_client' ) || ! function_exists( 'openssl_x509_parse' ) ) {
            self::$tls_info = null;
            return null;
        }

        $host = wp_parse_url( home_url(), PHP_URL_HOST );
        $port = (int) wp_parse_url( home_url(), PHP_URL_PORT );
        if ( ! $host ) {
            self::$tls_info = null;
            return null;
        }
        if ( ! $port ) {
            $port = 443;
        }

        $context = stream_context_create(
            array(
                'ssl' => array(
                    'capture_peer_cert' => true,
                    'verify_peer'       => false, // We read info; verification is a separate concern.
                    'verify_peer_name'  => false,
                    'SNI_enabled'       => true,
                    'peer_name'         => $host,
                ),
            )
        );

        // phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged
        $client = @stream_socket_client(
            'ssl://' . $host . ':' . $port,
            $err_no,
            $err_str,
            3,
            STREAM_CLIENT_CONNECT,
            $context
        );
        // phpcs:enable

        if ( ! $client ) {
            self::$tls_info = array(
                'valid'     => false,
                'error'     => $err_str ? $err_str : 'connect_failed',
            );
            return self::$tls_info;
        }

        $params = stream_context_get_params( $client );
        $info   = array(
            'valid'        => false,
            'issuer'       => '',
            'subject'      => '',
            'valid_from'   => 0,
            'valid_to'     => 0,
            'days_left'    => null,
            'tls_version'  => '',
        );

        if ( isset( $params['options']['ssl']['peer_certificate'] ) ) {
            $parsed = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );
            if ( is_array( $parsed ) ) {
                $info['valid']      = true;
                $info['issuer']     = isset( $parsed['issuer']['CN'] ) ? $parsed['issuer']['CN'] : '';
                $info['subject']    = isset( $parsed['subject']['CN'] ) ? $parsed['subject']['CN'] : '';
                $info['valid_from'] = isset( $parsed['validFrom_time_t'] ) ? (int) $parsed['validFrom_time_t'] : 0;
                $info['valid_to']   = isset( $parsed['validTo_time_t'] ) ? (int) $parsed['validTo_time_t'] : 0;
                if ( $info['valid_to'] ) {
                    $info['days_left'] = (int) floor( ( $info['valid_to'] - time() ) / DAY_IN_SECONDS );
                }
            }
        }

        // Detect negotiated TLS version from stream meta.
        $meta = stream_get_meta_data( $client );
        if ( isset( $meta['crypto']['protocol'] ) ) {
            $info['tls_version'] = (string) $meta['crypto']['protocol'];
        }

        // Close the TLS socket. $client is a network stream resource (not a filesystem
        // file handle), so WP_Filesystem does not apply here — fclose() is correct.
        fclose( $client ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose

        self::$tls_info = $info;
        return self::$tls_info;
    }

    /**
     * Reset memoized probe caches. Called at the start of each scan.
     */
    public static function reset_cache() {
        self::$home_probe = null;
        self::$tls_info   = null;
    }

    /**
     * Human-readable relative time for "last scan" display.
     *
     * @param int $timestamp Unix timestamp.
     * @return string
     */
    public static function human_time_diff( $timestamp ) {
        if ( $timestamp <= 0 ) {
            return __( 'Never', 'vigilante' );
        }
        return sprintf(
            /* translators: %s: human-readable duration */
            __( '%s ago', 'vigilante' ),
            human_time_diff( $timestamp, time() )
        );
    }

    /**
     * Simple filesystem existence test with URL-based fallback. Some hosts hide
     * files that exist on disk, so file_exists is the authoritative local check
     * and the URL probe is a defensive secondary signal.
     *
     * @param string $relative Path relative to ABSPATH (e.g. "readme.html").
     * @return bool
     */
    public static function abspath_file_exists( $relative ) {
        $path = trailingslashit( ABSPATH ) . ltrim( $relative, '/' );
        return file_exists( $path );
    }

    /**
     * Check whether a public URL returns HTTP 200. Used to confirm exposure of
     * sensitive files when file_exists flagged them.
     *
     * @param string $relative Path relative to site root.
     * @return bool True if URL returns 2xx.
     */
    public static function public_url_returns_ok( $relative ) {
        $url      = trailingslashit( home_url() ) . ltrim( $relative, '/' );
        $response = self::get( $url, array( 'redirection' => 0 ) );
        if ( is_wp_error( $response ) ) {
            return false;
        }
        $code = (int) wp_remote_retrieve_response_code( $response );
        return $code >= 200 && $code < 300;
    }
}
