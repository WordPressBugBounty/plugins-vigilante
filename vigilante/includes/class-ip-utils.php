<?php
/**
 * IP matching utilities
 *
 * Shared IP/pattern matching for the firewall and login modules. Supports
 * exact addresses, CIDR ranges and wildcards, for both IPv4 and IPv6.
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_IP_Utils
 *
 * Stateless helpers. All methods are static.
 */
class Vigilante_IP_Utils {

    /**
     * Check whether an IP matches a single pattern.
     *
     * Supported pattern forms (IPv4 and IPv6 alike):
     * - Exact address: 203.0.113.5 / 2a02:c207::1
     * - CIDR range:    203.0.113.0/24 / 2a02:c207::/32
     * - Wildcard:      203.0.113.* / 2a02:c207:*
     *
     * @param string $ip      IP address to test.
     * @param string $pattern Pattern to match against.
     * @return bool True on match.
     */
    public static function matches( $ip, $pattern ) {
        $ip      = trim( (string) $ip );
        $pattern = trim( (string) $pattern );

        if ( '' === $ip || '' === $pattern ) {
            return false;
        }

        // Exact match (also covers fully-written IPv6).
        if ( $ip === $pattern ) {
            return true;
        }

        // CIDR notation.
        if ( false !== strpos( $pattern, '/' ) ) {
            return self::cidr_match( $ip, $pattern );
        }

        // Wildcard notation.
        if ( false !== strpos( $pattern, '*' ) ) {
            return self::wildcard_match( $ip, $pattern );
        }

        return false;
    }

    /**
     * Check whether an IP matches any pattern in a list.
     *
     * @param string $ip   IP address to test.
     * @param array  $list List of patterns.
     * @return bool True if any pattern matches.
     */
    public static function in_list( $ip, $list ) {
        if ( empty( $list ) || ! is_array( $list ) ) {
            return false;
        }

        foreach ( $list as $pattern ) {
            if ( self::matches( $ip, (string) $pattern ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a string is a pattern this class can actually match.
     *
     * The counterpart of matches(): everything this returns true for is
     * something the matcher understands, and everything else is noise that
     * would sit in an IP list looking effective while matching nothing. Kept
     * next to the matcher on purpose, so validation and matching cannot drift
     * apart again.
     *
     * @since 2.9.9
     *
     * @param string $pattern Candidate pattern.
     * @return bool
     */
    public static function is_valid_pattern( $pattern ) {
        $pattern = trim( (string) $pattern );

        if ( '' === $pattern ) {
            return false;
        }

        // Exact address, IPv4 or IPv6.
        if ( filter_var( $pattern, FILTER_VALIDATE_IP ) ) {
            return true;
        }

        // CIDR range: same criterion cidr_match() applies, family included.
        if ( false !== strpos( $pattern, '/' ) ) {
            $parts = explode( '/', $pattern, 2 );
            if ( 2 !== count( $parts ) ) {
                return false;
            }

            $subnet = trim( $parts[0] );
            $bits   = trim( $parts[1] );

            if ( '' === $bits || ! ctype_digit( $bits ) ) {
                return false;
            }

            if ( ! filter_var( $subnet, FILTER_VALIDATE_IP ) ) {
                return false;
            }

            $packed = inet_pton( $subnet );
            if ( false === $packed ) {
                return false;
            }

            return ( (int) $bits <= strlen( $packed ) * 8 );
        }

        // Wildcard: what is left once the asterisks are gone has to be a
        // plausible prefix, of one family only.
        if ( false !== strpos( $pattern, '*' ) ) {
            return self::is_valid_wildcard( $pattern );
        }

        return false;
    }

    /**
     * Split a list into the patterns that can match and the ones that cannot.
     *
     * @since 2.9.9
     *
     * @param array|string $list List of patterns, or a newline separated string.
     * @return array{valid: string[], rejected: string[]}
     */
    public static function split_list( $list ) {
        if ( is_string( $list ) ) {
            $list = preg_split( '/[\r\n]+/', $list );
        }

        $valid    = array();
        $rejected = array();

        foreach ( (array) $list as $entry ) {
            $entry = trim( (string) $entry );

            if ( '' === $entry ) {
                continue;
            }

            if ( self::is_valid_pattern( $entry ) ) {
                $valid[] = $entry;
            } else {
                $rejected[] = $entry;
            }
        }

        return array(
            'valid'    => array_values( array_unique( $valid ) ),
            'rejected' => array_values( array_unique( $rejected ) ),
        );
    }

    /**
     * Whether a wildcard pattern is plausible for one address family.
     *
     * A bare '*' is rejected on purpose: as a whitelist it would let everyone
     * in and as a blacklist it would lock everyone out, and nobody types that
     * meaning to.
     *
     * @since 2.9.9
     *
     * @param string $pattern Wildcard pattern.
     * @return bool
     */
    private static function is_valid_wildcard( $pattern ) {
        $bare = str_replace( '*', '', $pattern );

        if ( '' === $bare || '.' === $bare || ':' === $bare ) {
            return false;
        }

        // IPv6 when there is a colon, IPv4 otherwise. The two never mix.
        if ( false !== strpos( $pattern, ':' ) ) {
            if ( ! preg_match( '/^[0-9A-Fa-f:*]+$/', $pattern ) ) {
                return false;
            }

            $groups = explode( ':', $pattern );
            if ( count( $groups ) > 8 ) {
                return false;
            }

            foreach ( $groups as $group ) {
                if ( '' === $group || '*' === $group ) {
                    continue;
                }
                if ( ! preg_match( '/^[0-9A-Fa-f]{1,4}\*?$/', $group ) ) {
                    return false;
                }
            }

            return true;
        }

        if ( ! preg_match( '/^[0-9.*]+$/', $pattern ) ) {
            return false;
        }

        $octets = explode( '.', $pattern );
        if ( count( $octets ) > 4 ) {
            return false;
        }

        foreach ( $octets as $octet ) {
            if ( '' === $octet || '*' === $octet ) {
                continue;
            }
            // A partial octet such as 2* is a prefix, so it is not range checked.
            if ( ! preg_match( '/^[0-9]{1,3}\*?$/', $octet ) ) {
                return false;
            }
            if ( '*' !== substr( $octet, -1 ) && (int) $octet > 255 ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Match an IP against a CIDR range. Works for IPv4 and IPv6.
     *
     * The comparison is done on the packed binary form, so the textual
     * representation of an IPv6 address (compressed or not) does not matter.
     *
     * @param string $ip   IP address to test.
     * @param string $cidr CIDR range (e.g. 203.0.113.0/24 or 2a02::/32).
     * @return bool True on match.
     */
    private static function cidr_match( $ip, $cidr ) {
        $parts = explode( '/', $cidr, 2 );
        if ( 2 !== count( $parts ) ) {
            return false;
        }

        $subnet = trim( $parts[0] );
        $bits   = trim( $parts[1] );

        // Prefix length must be a plain integer.
        if ( '' === $bits || ! ctype_digit( $bits ) ) {
            return false;
        }
        $bits = (int) $bits;

        // Validate both addresses before packing so inet_pton never warns.
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || ! filter_var( $subnet, FILTER_VALIDATE_IP ) ) {
            return false;
        }

        $ip_packed     = inet_pton( $ip );
        $subnet_packed = inet_pton( $subnet );
        if ( false === $ip_packed || false === $subnet_packed ) {
            return false;
        }

        // Different address family (4 bytes for IPv4, 16 for IPv6).
        if ( strlen( $ip_packed ) !== strlen( $subnet_packed ) ) {
            return false;
        }

        $max_bits = strlen( $ip_packed ) * 8;
        if ( $bits < 0 || $bits > $max_bits ) {
            return false;
        }

        // Compare whole bytes first.
        $whole_bytes = intdiv( $bits, 8 );
        if ( $whole_bytes > 0 && substr( $ip_packed, 0, $whole_bytes ) !== substr( $subnet_packed, 0, $whole_bytes ) ) {
            return false;
        }

        // Then the remaining bits of the partial byte, if any.
        $remaining = $bits % 8;
        if ( $remaining > 0 ) {
            $mask    = 0xFF << ( 8 - $remaining ) & 0xFF;
            $ip_byte = ord( $ip_packed[ $whole_bytes ] );
            $sub_byte = ord( $subnet_packed[ $whole_bytes ] );
            if ( ( $ip_byte & $mask ) !== ( $sub_byte & $mask ) ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Match an IP against a wildcard pattern (e.g. 203.0.113.* or 2a02:c207:*).
     *
     * Operates on the textual form. The '*' stands for any run of characters;
     * every other character is matched literally, so it works for the dots of
     * IPv4 and the colons of IPv6.
     *
     * @param string $ip      IP address to test.
     * @param string $pattern Wildcard pattern.
     * @return bool True on match.
     */
    private static function wildcard_match( $ip, $pattern ) {
        $quoted = preg_quote( $pattern, '/' );
        $regex  = '/^' . str_replace( '\*', '.*', $quoted ) . '$/';

        return (bool) preg_match( $regex, $ip );
    }

    /**
     * Proxy headers an admin may declare as trusted, mapped to their $_SERVER key.
     *
     * @return array<string,string>
     */
    public static function trusted_header_map() {
        return array(
            'cf-connecting-ip' => 'HTTP_CF_CONNECTING_IP',
            'x-forwarded-for'  => 'HTTP_X_FORWARDED_FOR',
            'x-real-ip'        => 'HTTP_X_REAL_IP',
        );
    }

    /**
     * The proxy header the admin has declared as trusted, or '' for none.
     *
     * @return string
     */
    public static function trusted_proxy_header() {
        $options = get_option( 'vigilante_options' );
        if ( is_array( $options ) && ! empty( $options['firewall']['trusted_proxy_header'] ) ) {
            $header = (string) $options['firewall']['trusted_proxy_header'];
            if ( isset( self::trusted_header_map()[ $header ] ) ) {
                return $header;
            }
        }
        return '';
    }

    /**
     * Resolve the client IP from a $_SERVER-like array.
     *
     * Only the real TCP peer (REMOTE_ADDR) is trusted by default, because it
     * cannot be spoofed. A forwarded-for / connecting-ip header is honoured
     * ONLY when the admin has explicitly declared their site sits behind that
     * proxy; otherwise any visitor could forge the header and impersonate any
     * IP (bypassing the whitelist, evading the blacklist, poisoning the rate
     * limiter, etc.).
     *
     * @param array  $server         A $_SERVER-like array.
     * @param string $trusted_header One of the keys in trusted_header_map(), or '' for none.
     * @return string Validated IP, or '0.0.0.0' when none could be determined.
     */
    public static function resolve_client_ip( $server, $trusted_header = '' ) {
        $map = self::trusted_header_map();

        if ( '' !== $trusted_header && isset( $map[ $trusted_header ] ) ) {
            $key = $map[ $trusted_header ];
            if ( ! empty( $server[ $key ] ) ) {
                $value = (string) $server[ $key ];
                // X-Forwarded-For may be a "client, proxy1, proxy2" chain; the
                // original client is the first entry.
                if ( false !== strpos( $value, ',' ) ) {
                    $parts = explode( ',', $value );
                    $value = $parts[0];
                }
                $value = trim( $value );
                if ( filter_var( $value, FILTER_VALIDATE_IP ) ) {
                    return $value;
                }
            }
        }

        if ( ! empty( $server['REMOTE_ADDR'] ) ) {
            $remote = trim( (string) $server['REMOTE_ADDR'] );
            if ( filter_var( $remote, FILTER_VALIDATE_IP ) ) {
                return $remote;
            }
        }

        return '0.0.0.0';
    }

    /**
     * Current request client IP, honouring the configured trusted proxy header.
     *
     * Reads only the needed headers, each sanitized at the point of access, so
     * the input-sanitization sniff is satisfied without any suppression.
     *
     * @return string
     */
    public static function get_client_ip() {
        $trusted = self::trusted_proxy_header();
        $server  = array();

        if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
            $server['REMOTE_ADDR'] = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }

        if ( '' !== $trusted ) {
            $map = self::trusted_header_map();
            $key = $map[ $trusted ];
            if ( isset( $_SERVER[ $key ] ) ) {
                $server[ $key ] = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
            }
        }

        return self::resolve_client_ip( $server, $trusted );
    }
}
