<?php
/**
 * Security Analyzer — Reputation / blacklist category (informational, 0 pts).
 *
 * DNS-based reputation lookups against public blacklists. Zero HTTP APIs, no
 * account required: everything is a cheap DNS A-record query. Because a listing
 * can be transient (a shared IP or mass scanner's fault), these checks are
 * informational — they surface listings without deducting from the overall score.
 *
 * Queried blacklists:
 *   - Spamhaus ZEN (zen.spamhaus.org) — aggregated SBL+XBL+PBL.
 *   - Barracuda BRBL (b.barracudacentral.org).
 *   - SpamCop SCBL (bl.spamcop.net).
 *
 * The server IP is resolved from the site URL's host (same physical host in
 * most self-hosted WP installs). Reverse the octets and prepend them to each
 * blacklist zone; a successful A lookup means the IP is listed.
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * DNS-based reputation checks (all informational).
 */
class Vigilante_SA_Category_Reputation {

    const SLUG = 'reputation';

    /**
     * Blacklists we query. DNS-only, no authentication.
     *
     * @var array<string,array{label:string,zone:string,info_url:string}>
     */
    private static $blacklists = array(
        'spamhaus'  => array(
            'label'    => 'Spamhaus ZEN',
            'zone'     => 'zen.spamhaus.org',
            'info_url' => 'https://check.spamhaus.org/',
        ),
        'barracuda' => array(
            'label'    => 'Barracuda BRBL',
            'zone'     => 'b.barracudacentral.org',
            'info_url' => 'https://www.barracudacentral.org/rbl/removal-request',
        ),
        'spamcop'   => array(
            'label'    => 'SpamCop SCBL',
            'zone'     => 'bl.spamcop.net',
            'info_url' => 'https://www.spamcop.net/bl.shtml',
        ),
    );

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
     * All reputation checks require DNS + external network, so they live in the
     * 'slow' phase.
     *
     * @param string $phase 'fast' | 'slow' | 'all'.
     * @return Vigilante_SA_Check_Result[]
     */
    public function run( $phase = 'all' ) {
        if ( 'fast' === $phase ) {
            return array();
        }

        $results = array();

        $ip = $this->resolve_site_ip();

        // Intro/diagnostic row telling the user what was tested and on what IP.
        $results[] = $this->build_intro( $ip );

        if ( '' === $ip ) {
            // Without an IP we can't query — return just the intro (already explains why).
            return $results;
        }

        foreach ( self::$blacklists as $key => $meta ) {
            $results[] = $this->check_blacklist( $key, $meta, $ip );
        }

        return $results;
    }

    /**
     * Introductory info row that documents the IP we tested.
     *
     * @param string $ip
     * @return Vigilante_SA_Check_Result
     */
    private function build_intro( $ip ) {
        $args = array(
            'id'       => 'reputation_overview',
            'category' => self::SLUG,
            'max'      => 0,
            'label'    => __( 'Site IP for blacklist queries', 'vigilante' ),
            'fix_link' => '',
        );

        if ( '' === $ip ) {
            $args['detail'] = __( 'Could not resolve the site\'s public IP (DNS lookup failed). Reputation checks skipped — this is typically a transient resolver issue.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $args['detail'] = sprintf(
            /* translators: 1: site host, 2: resolved IPv4 */
            __( '%1$s resolves to %2$s. We query public DNS blacklists (DNSBLs) against this address. These checks are informational — a listing does not deduct from your score.', 'vigilante' ),
            wp_parse_url( home_url(), PHP_URL_HOST ),
            $ip
        );
        $args['data'] = array( 'ip' => $ip );
        return Vigilante_SA_Check_Result::info( $args );
    }

    /**
     * Query a single DNSBL for the given IP.
     *
     * @param string $key  Slug (spamhaus|barracuda|spamcop).
     * @param array  $meta Metadata (label, zone, info_url).
     * @param string $ip   IPv4 address.
     * @return Vigilante_SA_Check_Result
     */
    private function check_blacklist( $key, array $meta, $ip ) {
        $args = array(
            'id'       => 'reputation_' . $key,
            'category' => self::SLUG,
            'max'      => 0,
            'label'    => sprintf(
                /* translators: %s: blacklist name */
                __( '%s blacklist', 'vigilante' ),
                $meta['label']
            ),
            'fix_link' => $meta['info_url'],
        );

        $reversed = $this->reverse_ip( $ip );
        if ( '' === $reversed ) {
            $args['detail'] = __( 'Invalid IPv4 address, skipping.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $hostname = $reversed . '.' . $meta['zone'];

        // Use gethostbynamel() to avoid long single-host timeouts and get all A records back.
        // Listings typically respond with 127.0.0.x codes; non-listings return no record.
        $records = @gethostbynamel( $hostname ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

        if ( false === $records || empty( $records ) ) {
            $args['detail'] = sprintf(
                /* translators: %s: blacklist name */
                __( 'Not listed on %s.', 'vigilante' ),
                $meta['label']
            );
            return Vigilante_SA_Check_Result::info( $args );
        }

        // Any returned record (typically 127.0.0.x) means listed. Informational in terms
        // of scoring (max=0), but visually flagged as a warning so it stands out.
        $codes = array_filter( (array) $records, 'is_string' );
        $args['detail'] = sprintf(
            /* translators: 1: blacklist name, 2: response codes (127.0.0.x) */
            __( 'Listed on %1$s (response: %2$s). Shared hosting? Check if the listing belongs to your IP range and request delisting from the blacklist operator.', 'vigilante' ),
            $meta['label'],
            implode( ', ', $codes )
        );
        $args['data'] = array( 'response' => array_values( $codes ) );
        return Vigilante_SA_Check_Result::warn( $args );
    }

    /**
     * Resolve the site's public IPv4 address.
     *
     * @return string IPv4 or '' on failure.
     */
    private function resolve_site_ip() {
        $host = wp_parse_url( home_url(), PHP_URL_HOST );
        if ( ! $host ) {
            return '';
        }

        // Already an IP? Short-circuit.
        if ( filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return $host;
        }

        $ip = @gethostbyname( $host ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        if ( $ip === $host ) {
            return ''; // gethostbyname returns the input on failure.
        }
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return ''; // DNSBLs we use are IPv4-only.
        }
        return $ip;
    }

    /**
     * Reverse an IPv4 address (1.2.3.4 → 4.3.2.1). Return '' if invalid.
     *
     * @param string $ip
     * @return string
     */
    private function reverse_ip( $ip ) {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return '';
        }
        $parts = array_reverse( explode( '.', $ip ) );
        return implode( '.', $parts );
    }
}
