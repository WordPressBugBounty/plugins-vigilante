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
     * Headers in which a comma is never part of the value
     *
     * A comma in one of them is two sends merged into one line, such as
     * "DENY, SAMEORIGIN": a server, a CDN or WordPress itself joins repeated
     * headers. Content-Security-Policy, Referrer-Policy and Permissions-Policy
     * carry real commas and are not listed.
     *
     * @since 3.0.8
     */
    const SINGLE_VALUE_HEADERS = array(
        'x-frame-options',
        'x-content-type-options',
        'strict-transport-security',
        'cross-origin-opener-policy',
        'cross-origin-resource-policy',
    );

    /**
     * Cached GET of home URL headers+body. Lives in a runtime static so
     * multiple checks within the same scan don't hit the front-end twice.
     *
     * @var array|null
     */
    private static $home_probe = null;

    /**
     * Who served a verification screen instead of the home page in this
     * scan, or '' when the home page was the site
     *
     * @var string
     */
    private static $home_challenge = '';

    /**
     * Who served a verification screen to the last request made by get(),
     * or '' when that answer was the site
     *
     * @var string
     */
    private static $last_challenge = '';

    /**
     * The home page generated now, once per scan: false until asked
     *
     * @var array|null|false
     */
    private static $fresh_probe = false;

    /**
     * A static file of WordPress, once per scan: false until asked
     *
     * @var array|null|false
     */
    private static $static_probe = false;

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
            '8.5' => '2029-12-31',
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

        return array(
            'score' => $score,
            'grade' => self::grade_for_score( $score ),
        );
    }

    /**
     * The letter a 0-100 score earns
     *
     * One scale for every letter the plugin shows: the Security Check, each of
     * its categories and the Test Headers button. Until 3.0.4 there were two,
     * so the same letter meant two things on the same screen: the Dashboard
     * gave its Configuration Score an A from 90 and the Security Check only at
     * 100, and a B ran from 70 to 99, which put a site with thirteen failing
     * checks one letter away from a perfect one. The configuration level of
     * the Dashboard no longer carries a letter: it is a bar
     * (Vigilante_Admin::render_configuration_card()).
     *
     * A is a perfect score and nothing else. The admin script mirrors these
     * thresholds in VigilanteAnalyzer.qualityTag (assets/js/admin.js).
     *
     * @since 3.0.5
     *
     * @param int $score Score from 0 to 100.
     * @return string A, B, C, D or E.
     */
    public static function grade_for_score( $score ) {
        $score = max( 0, min( 100, (int) $score ) );

        if ( 100 === $score ) {
            return 'A';
        }
        if ( $score >= 85 ) {
            return 'B';
        }
        if ( $score >= 70 ) {
            return 'C';
        }
        if ( $score >= 50 ) {
            return 'D';
        }
        return 'E';
    }

    /**
     * What a check says when the setting is saved and the module that applies it is off
     *
     * A setting inside a module does nothing while the module is switched off:
     * its class is never loaded. A check that reads the setting alone reports a
     * protection that is not running.
     *
     * @since 3.0.5
     *
     * @param Vigilante_Settings $settings Settings.
     * @param string             $module   Module key, for example login_security.
     * @return string
     */
    public static function module_off_detail( Vigilante_Settings $settings, $module ) {
        return sprintf(
            /* translators: %s: name of a Vigilant module, for example Login Security */
            __( 'The %s module is switched off, so what is set there is saved but not applied. Switch the module on from the Dashboard.', 'vigilante' ),
            self::module_label( $settings, $module )
        );
    }

    /**
     * What a check says when the module it reads from is off
     *
     * @since 3.0.5
     *
     * @param Vigilante_Settings $settings Settings.
     * @param string             $module   Module key, for example file_integrity.
     * @return string
     */
    public static function module_idle_detail( Vigilante_Settings $settings, $module ) {
        return sprintf(
            /* translators: %s: name of a Vigilant module, for example File Integrity */
            __( 'The %s module is switched off, so there is nothing recent for this check to read. Switch the module on from the Dashboard.', 'vigilante' ),
            self::module_label( $settings, $module )
        );
    }

    /**
     * Name of a module as the Dashboard shows it
     *
     * @since 3.0.5
     *
     * @param Vigilante_Settings $settings Settings.
     * @param string             $module   Module key.
     * @return string
     */
    private static function module_label( Vigilante_Settings $settings, $module ) {
        $labels = $settings->get_module_labels();

        return isset( $labels[ $module ] ) ? (string) $labels[ $module ] : (string) $module;
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
        // A new look at the home page is a new look at all of it: the copy
        // generated now and the static file are asked for again too.
        self::$fresh_probe  = false;
        self::$static_probe = false;

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

        self::$home_challenge = '';

        if ( is_wp_error( $response ) ) {
            self::$home_probe = null;
            return null;
        }

        // A verification screen is not the home page: everything read from it
        // would be about that screen (B96). Answered as no answer, so each
        // check says it could not measure, and says why.
        $challenge = self::challenge_of_response( $response );
        if ( '' !== $challenge ) {
            self::$home_challenge = $challenge;
            self::$home_probe     = null;
            return null;
        }

        self::$home_probe = array(
            'code'    => (int) wp_remote_retrieve_response_code( $response ),
            'headers' => self::normalize_headers( wp_remote_retrieve_headers( $response ) ),
            // Every value of each header, as it arrived: the line above joins
            // a header sent twice into one, and the checks read it as good.
            'lists'   => self::header_lists( wp_remote_retrieve_headers( $response ) ),
            'body'    => (string) wp_remote_retrieve_body( $response ),
        );
        return self::$home_probe;
    }

    /**
     * The home page generated now, with a query string that page caches do
     * not usually keep
     *
     * probe_home() reads what a visitor gets, which may be a copy a cache made
     * before the last change: after switching a header on, the scan read the
     * old copy and said it was missing (B74, measured on aulawp.com on 9 Oct
     * 2026). The score stays with what the visitor gets; this copy only says
     * why. The same request the Security Check of herramientas.ayudawp.com
     * makes since 11.6.
     *
     * @since 3.0.8
     *
     * @return array|null { int code, array headers, array lists } or null without a usable answer.
     */
    public static function probe_fresh_home() {
        if ( false === self::$fresh_probe ) {
            $url               = add_query_arg( 'vigilante-nocache', (string) time(), home_url( '/' ) );
            self::$fresh_probe = self::headers_of( self::get( $url, array( 'timeout' => 4, 'redirection' => 2 ) ) );
        }
        return self::$fresh_probe;
    }

    /**
     * An image every WordPress ships, which the web server sends without PHP
     *
     * On some hosting (PHP as CGI: IONOS shared, measured on 13 Oct 2026 on
     * reformasbarcelona.info) the Header rules of .htaccess reach the files
     * the server sends by itself and not the pages PHP generates. Until 3.0.8
     * the scan then said that mod_headers was off, and the hosting rightly
     * answered that it was not (B90). Asked for with includes_url(), because
     * WordPress may live in a subfolder.
     *
     * @since 3.0.8
     *
     * @return array|null { int code, array headers, array lists } or null without a usable answer.
     */
    public static function probe_static_file() {
        if ( false === self::$static_probe ) {
            self::$static_probe = self::headers_of( self::get( includes_url( 'images/w-logo-blue.png' ), array( 'timeout' => 4 ) ) );
        }
        return self::$static_probe;
    }

    /**
     * Status and headers of an answer of get(), without its body
     *
     * @since 3.0.8
     *
     * @param array|WP_Error $response Answer.
     * @return array|null
     */
    private static function headers_of( $response ) {
        if ( is_wp_error( $response ) ) {
            return null;
        }
        return array(
            'code'    => (int) wp_remote_retrieve_response_code( $response ),
            'headers' => self::normalize_headers( wp_remote_retrieve_headers( $response ) ),
            'lists'   => self::header_lists( wp_remote_retrieve_headers( $response ) ),
        );
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
        $response = wp_remote_get( $url, $args );

        // Same as the home page: a verification screen answered with 403 read
        // as a protected file or a protected user list, and one answered with
        // 202 as a page that was there (B96). The checks treat an error as
        // "not measured", and with_challenge() says why.
        self::$last_challenge = is_wp_error( $response ) ? '' : self::challenge_of_response( $response );
        if ( '' !== self::$last_challenge ) {
            return new WP_Error( 'vigilante_challenge', self::$last_challenge );
        }

        return $response;
    }

    /**
     * Who served a verification screen instead of the page, or ''
     *
     * Adapted from the detector of the tools of herramientas.ayudawp.com
     * (includes/challenge-lib.php, 11.6), with two differences that come from
     * what Vigilant asks for. A status alone is never a screen: these checks
     * ask for /.env or for the list of users expecting exactly a 403 from the
     * site itself. And /cdn-cgi/challenge-platform is not a signature: the
     * JS Detections of Cloudflare put it into ordinary pages, a small 403
     * included. A signature in an answer of more than 20,000 bytes is not a
     * screen either: it is a page that names the firewall. Nor is one in a
     * 2xx answer, which is a file or a page that was served.
     *
     * @since 3.0.8
     *
     * @param int    $code    HTTP status.
     * @param array  $headers Headers, any case.
     * @param string $body    Body.
     * @return string SiteGround, Cloudflare, Sucuri, Imperva, DataDome, AWS WAF, Wordfence, Vigilant or ''.
     */
    public static function challenge_of( $code, array $headers, $body ) {
        $headers = array_change_key_case( $headers, CASE_LOWER );
        $body    = (string) $body;

        if ( isset( $headers['sg-captcha'] ) ) {
            return 'SiteGround';
        }
        if ( isset( $headers['cf-mitigated'] ) && false !== stripos( (string) $headers['cf-mitigated'], 'challenge' ) ) {
            return 'Cloudflare';
        }
        // AWS WAF says what it did in its own header, also on the 202 of its
        // challenge (first blind review of 3.0.8).
        if ( isset( $headers['x-amzn-waf-action'] ) && preg_match( '/challenge|captcha|block/i', (string) $headers['x-amzn-waf-action'] ) ) {
            return 'AWS WAF';
        }
        // The challenge of the Under Attack mode of Vigilant itself
        // (Vigilante_Under_Attack::render_challenge_page()).
        if ( 503 === (int) $code && false !== strpos( $body, 'name="vigilante_ua_response"' ) ) {
            return 'Vigilant';
        }
        // The body is only searched in an answer that is not a 2xx. A file that
        // is served is what the checks are there to see, and its own content
        // can carry a signature: a public .env with a DATADOME_API_KEY line, or
        // a debug.log that quotes the block page of Wordfence, read as a screen
        // would have passed as "not measured" instead of reachable. The screens
        // that answer 2xx are recognised by their header (SiteGround, 202).
        $code = (int) $code;
        if ( ( $code >= 200 && $code < 300 ) || '' === $body || strlen( $body ) > 20000 ) {
            return '';
        }

        // Only marks of the screen itself. The tags that DataDome
        // (js.datadome.co) and AWS WAF (its jsapi.js) put into ordinary pages
        // turned a small 403 or 404 of the site into a screen, so DataDome is
        // recognised by the address of its captcha and AWS WAF by its header
        // (first blind review of 3.0.8). The block page of Cloudflare carries
        // its Ray ID and no cf-mitigated header.
        $signatures = array(
            'SiteGround' => '~/\.well-known/sgcaptcha/~i',
            'Cloudflare' => '~cf-browser-verification|__cf_chl_|<title>\s*Just a moment\.\.\.|Cloudflare Ray ID|Attention Required! \| Cloudflare~i',
            'Sucuri'     => '~sucuri_cloudproxy|Sucuri WebSite Firewall~i',
            // _Incapsula_Resource alone is the script Imperva puts into the
            // pages it serves (second blind review of 3.0.8).
            'Imperva'    => '~Incapsula incident|<iframe[^>]+_Incapsula_Resource~i',
            'DataDome'   => '~captcha-delivery\.com~i',
            'Wordfence'  => '~Your access to this site has been limited~i',
        );
        foreach ( $signatures as $vendor => $pattern ) {
            if ( 1 === preg_match( $pattern, $body ) ) {
                return $vendor;
            }
        }
        return '';
    }

    /**
     * challenge_of() for an answer of wp_remote_get()
     *
     * @since 3.0.8
     *
     * @param array $response Response.
     * @return string
     */
    private static function challenge_of_response( $response ) {
        return self::challenge_of(
            (int) wp_remote_retrieve_response_code( $response ),
            self::normalize_headers( wp_remote_retrieve_headers( $response ) ),
            (string) wp_remote_retrieve_body( $response )
        );
    }

    /**
     * Who answered the home page of this scan with a verification screen, or ''
     *
     * @since 3.0.8
     *
     * @return string
     */
    public static function home_challenge() {
        return self::$home_challenge;
    }

    /**
     * Why a request got no usable answer, when it was a verification screen
     *
     * @since 3.0.8
     *
     * @param string $vendor What challenge_of() said.
     * @return string Empty for no vendor.
     */
    public static function challenge_sentence( $vendor ) {
        if ( '' === (string) $vendor ) {
            return '';
        }
        if ( 'Vigilant' === $vendor ) {
            return __( 'The answer was the challenge page of the Under Attack mode of Vigilant, which is on: while it lasts, this check cannot read the site. Not scored.', 'vigilante' );
        }
        return sprintf(
            /* translators: %s: name of a firewall or anti-bot service, such as Cloudflare or SiteGround */
            __( 'The answer was a screen of %s (a verification, a block or an error page) instead of the site, so what it says is about that screen and not about the site. Not scored.', 'vigilante' ),
            $vendor
        );
    }

    /**
     * The detail of a check that could not measure, with the reason when the
     * answer was a verification screen
     *
     * @since 3.0.8
     *
     * @param string $detail What the check says when it gets no answer.
     * @param bool   $home   True for the home page probe, false for the last request of get().
     * @return string
     */
    public static function with_challenge( $detail, $home = false ) {
        $sentence = self::challenge_sentence( $home ? self::$home_challenge : self::$last_challenge );
        return '' === $sentence ? $detail : $detail . ' ' . $sentence;
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
     * Every value of each header, lowercase-keyed
     *
     * WordPress keeps a header that arrives more than once as a list, and
     * normalize_headers() joins it into one line, so "X-Frame-Options: DENY"
     * twice read as one good header. For the browser it is not the same: two
     * different X-Frame-Options forbid framing everywhere, of two HSTS only
     * the first counts, and two CSP apply together. The headers that never
     * carry a comma are also split on it, because two sends can arrive
     * already joined.
     *
     * @since 3.0.8
     *
     * @param mixed $headers Response headers from wp_remote_retrieve_headers.
     * @return array<string,string[]>
     */
    public static function header_lists( $headers ) {
        $raw = array();
        if ( is_object( $headers ) && method_exists( $headers, 'getAll' ) ) {
            $raw = $headers->getAll();
        } elseif ( is_array( $headers ) ) {
            $raw = $headers;
        }

        $lists = array();
        foreach ( (array) $raw as $key => $value ) {
            $key    = strtolower( (string) $key );
            $single = in_array( $key, self::SINGLE_VALUE_HEADERS, true );
            $values = array();
            foreach ( (array) $value as $one ) {
                foreach ( $single ? explode( ',', (string) $one ) : array( (string) $one ) as $part ) {
                    $part = trim( $part );
                    if ( '' !== $part ) {
                        $values[] = $part;
                    }
                }
            }
            $lists[ $key ] = $values;
        }
        return $lists;
    }

    /**
     * Whether a Content-Security-Policy value is the one Vigilant sends from PHP
     *
     * Vigilante_Https_Enforcer::emit_upgrade_insecure_requests() sends a second
     * policy with that directive alone, on purpose, next to the one of the
     * .htaccess block. It restricts nothing, so it is neither a repeated header
     * to remove nor a sign that the block of .htaccess is being applied.
     *
     * @since 3.0.8
     *
     * @param string $value One CSP value.
     * @return bool
     */
    public static function is_upgrade_only_csp( $value ) {
        return 'upgrade-insecure-requests' === strtolower( trim( (string) $value, " \t;" ) );
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
        self::$home_probe     = null;
        self::$tls_info       = null;
        self::$home_challenge = '';
        self::$last_challenge = '';
        self::$fresh_probe    = false;
        self::$static_probe   = false;
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
        return 'reachable' === self::public_url_state( $relative );
    }

    /**
     * Whether a public URL can be fetched, cannot, or could not be asked
     *
     * Three answers, because a request that fails is not a file that is
     * protected: until 3.0.4 a timeout read as "not reachable" and the check
     * passed without having measured anything.
     *
     * @since 3.0.5
     *
     * @param string $relative Path relative to site root.
     * @return string reachable (2xx), blocked (any other answer) or unknown (no answer).
     */
    public static function public_url_state( $relative ) {
        $url      = trailingslashit( home_url() ) . ltrim( $relative, '/' );
        $response = self::get( $url, array( 'redirection' => 0 ) );

        if ( is_wp_error( $response ) ) {
            return 'unknown';
        }

        $code = (int) wp_remote_retrieve_response_code( $response );

        return ( $code >= 200 && $code < 300 ) ? 'reachable' : 'blocked';
    }

    /**
     * What a check says when the request it depends on got no answer
     *
     * @since 3.0.5
     *
     * @param string $what What was asked for, for example /.env.
     * @return string
     */
    public static function unreachable_detail( $what ) {
        // A verification screen is an answer, but not one from the site.
        if ( '' !== self::$last_challenge ) {
            return sprintf(
                /* translators: %s: a path of the site, for example /.env */
                __( 'The request for %s got an answer that is not from the site, so whether it is reachable from the web could not be checked.', 'vigilante' ),
                $what
            ) . ' ' . self::challenge_sentence( self::$last_challenge );
        }

        return sprintf(
            /* translators: %s: a path of the site, for example /.env */
            __( 'The request for %s got no answer from this server, so whether it is reachable from the web could not be checked. Not scored.', 'vigilante' ),
            $what
        );
    }
}
