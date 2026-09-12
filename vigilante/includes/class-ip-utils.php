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

        // Exact match, comparing what the addresses ARE and not how they are
        // written (see same_address()).
        if ( self::same_address( $ip, $pattern ) ) {
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
     * Whether an address is in a list, matching exact addresses and CIDR only.
     *
     * The strict cousin of in_list(), for deciding identity rather than
     * filtering traffic. A wildcard entry (1.2.* or a bare *) is never honoured
     * here: a proxy the site delegates its client IP to is a specific machine
     * or a specific range, and a wildcard in that role is the trust-everyone
     * footgun that would reopen the forwarded-header spoofing (6.1) this release
     * closes, since matches() turns a bare * into /^.*$/ and trusts every peer.
     * Kept apart from in_list() on purpose, so the firewall whitelist keeps its
     * wildcards while the proxy-trust decision cannot grow one.
     *
     * @since 2.11.9
     *
     * @param string $ip   Address to test.
     * @param array  $list List of exact addresses or CIDR ranges.
     * @return bool
     */
    public static function in_list_ip_or_cidr( $ip, $list ) {
        if ( empty( $list ) || ! is_array( $list ) ) {
            return false;
        }

        $ip = trim( (string) $ip );
        if ( '' === $ip ) {
            return false;
        }

        foreach ( $list as $pattern ) {
            $pattern = trim( (string) $pattern );

            if ( '' === $pattern || false !== strpos( $pattern, '*' ) ) {
                continue;
            }

            if ( self::same_address( $ip, $pattern ) ) {
                return true;
            }

            if ( false !== strpos( $pattern, '/' ) ) {
                // A range too wide to name anything is ignored here as well as
                // rejected on the way in: an entry can arrive by import or from
                // an older version, and it must not turn every peer into a
                // trusted proxy. See proxy_prefix_is_sane().
                if ( ! self::proxy_prefix_is_sane( $pattern ) ) {
                    continue;
                }

                if ( self::cidr_match( $ip, $pattern ) ) {
                    return true;
                }
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
     * Whether a string is a proxy address this class trusts to set a header.
     *
     * A valid pattern that is not a wildcard: an exact address or a CIDR range.
     * The counterpart of in_list_ip_or_cidr() for the save path, so a wildcard
     * typed into the trusted proxies field is rejected with feedback instead of
     * sitting there matching nothing (or, before the strict matcher, everything).
     *
     * @since 2.11.9
     *
     * @param string $pattern Candidate pattern.
     * @return bool
     */
    public static function is_valid_proxy( $pattern ) {
        $pattern = trim( (string) $pattern );

        if ( false !== strpos( $pattern, '*' ) || ! self::is_valid_pattern( $pattern ) ) {
            return false;
        }

        return self::proxy_prefix_is_sane( $pattern );
    }

    /**
     * Whether a CIDR entry is narrow enough to name a proxy
     *
     * A prefix length of zero matches every address, so 0.0.0.0/0 and ::/0 say
     * exactly what the rejected '*' says, written as a CIDR. Rejecting the
     * wildcard and accepting those was the same footgun with another spelling:
     * with either one in the list every peer counts as a trusted proxy and any
     * visitor picks the address the firewall sees, which is the forwarded-header
     * spoofing (6.1) this list exists to prevent. Found by the file-by-file
     * review of 2.11.10.
     *
     * Stopping at zero was not enough, and that is the second cross review of
     * 2.11.10: 0.0.0.0/1 and 128.0.0.0/1 are two accepted entries that between
     * them cover the whole internet, with the same effect and no warning. So the
     * question is not "is it zero" but "can this range name a proxy". The floors
     * are 8 for IPv4, the widest range that still names something real (the
     * classic private network is 10.0.0.0/8), and 7 for IPv6, because fc00::/7 is
     * how the whole IPv6 private space is written and this very class treats it
     * as the own network in is_own_network(). A first version put the IPv6 floor
     * at 16 and refused fc00::/7, fd00::/8 (what Docker hands out) and fe80::/10,
     * so a list that already held one of them stopped honouring the header
     * altogether and every visitor came out with the proxy's address: the tool
     * contradicting itself about what a private network is. Found by the third
     * cross review of 2.11.10. With 7, ::/0 and 2000::/3, which is all of the
     * routable internet, are still refused.
     *
     * Measured against what the CDNs publish, and all of them pass: Cloudflare
     * (/13, /15, /29), Fastly (/16, /32), Akamai (/10, /11, /13, /24), Sucuri
     * (/22, /23), Bunny (/32), CloudFront (/15) and Google (/16, /22).
     *
     * Kept deliberately as a floor and not as a warning: an entry this wide is
     * indistinguishable from the wildcard that is already refused, and the cost
     * of being wrong is that any visitor chooses their own address.
     *
     * @since 2.11.10
     *
     * @param string $pattern Address or CIDR range.
     * @return bool True when it is an exact address or a narrow enough range.
     */
    public static function proxy_prefix_is_sane( $pattern ) {
        $pattern = trim( (string) $pattern );

        if ( false === strpos( $pattern, '/' ) ) {
            return true;
        }

        $parts = explode( '/', $pattern, 2 );

        if ( 2 !== count( $parts ) ) {
            return false;
        }

        $subnet = trim( $parts[0] );
        $bits   = (int) trim( $parts[1] );
        $packed = inet_pton( $subnet );

        if ( false === $packed ) {
            return false;
        }

        $minimo = ( 4 === strlen( $packed ) ) ? 8 : 7;

        return ( $bits >= $minimo );
    }

    /**
     * Whether two written addresses are the same address
     *
     * Comparing the strings was enough for IPv4 and wrong for IPv6, where the
     * same address has many spellings: 2001:DB8::1, 2001:db8::1 and
     * 2001:0db8:0000:0000:0000:0000:0000:0001 are one address written three
     * ways, and only the last two compared equal to each other. It mattered
     * because the .htaccess side normalises with inet_pton()/inet_ntop() before
     * writing its rule, so Apache exempted a peer that PHP did not recognise,
     * which is the direction that opens something: measured against a real
     * Apache by the second cross review of 2.11.10.
     *
     * Falls back to the string comparison when either side is not an address, so
     * nothing that used to match stops matching.
     *
     * @since 2.11.10
     *
     * @param string $a First address.
     * @param string $b Second address.
     * @return bool
     */
    public static function same_address( $a, $b ) {
        if ( $a === $b ) {
            return true;
        }

        $pa = inet_pton( $a );
        $pb = inet_pton( $b );

        if ( false === $pa || false === $pb ) {
            return false;
        }

        return ( $pa === $pb );
    }

    /**
     * Split a list into the proxy addresses that are valid and the ones that are not.
     *
     * Like split_list(), but rejecting wildcards: the trusted proxies list feeds
     * an identity decision, and only exact addresses and CIDR ranges belong there.
     *
     * @since 2.11.9
     *
     * @param array|string $list List of patterns, or a newline separated string.
     * @return array{valid: string[], rejected: string[]}
     */
    public static function split_list_ip_or_cidr( $list ) {
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

            if ( self::is_valid_proxy( $entry ) ) {
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
     * The proxy IPs/CIDRs the admin declared their forwarded header comes from.
     *
     * @since 2.11.9
     *
     * @return string[]
     */
    public static function trusted_proxies() {
        $options = get_option( 'vigilante_options' );
        $list    = ( is_array( $options ) && isset( $options['firewall']['trusted_proxies'] ) ) ? $options['firewall']['trusted_proxies'] : array();
        return is_array( $list ) ? $list : array();
    }

    /**
     * Cloudflare's published edge ranges, so CF-Connecting-IP verifies itself.
     *
     * From https://www.cloudflare.com/ips/ (stable, changes rarely). Bundled so
     * a site behind Cloudflare does not have to list them by hand; if they ever
     * change, the admin can add the new ones to the trusted proxies list.
     *
     * @since 2.11.9
     *
     * @return string[]
     */
    public static function cloudflare_ranges() {
        return array(
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
            '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
            '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
        );
    }

    /**
     * Whether the TCP peer may be trusted to have set the forwarded header
     *
     * The reviewer of 2.11.8 was right: honouring CF-Connecting-IP,
     * X-Forwarded-For or X-Real-IP without checking who sent them lets any
     * visitor whose request reaches PHP directly forge the address the firewall,
     * the whitelist and the rate limiter act on. So the header is honoured only
     * when the real connection, REMOTE_ADDR, is a proxy we have reason to trust:
     *
     * - an exact address or CIDR range in the admin's trusted proxies list
     *   (wins for any header); a wildcard there is ignored, see
     *   in_list_ip_or_cidr();
     * - for CF-Connecting-IP, one of Cloudflare's published ranges, since only
     *   Cloudflare sends that header;
     * - with no list configured, an address of your own network (a reverse proxy
     *   in front of PHP, a load balancer in a private subnet), which a visitor
     *   hitting a public origin directly is not.
     *
     * A public load balancer that connects from a public address needs its IPs
     * in the trusted proxies list; until then its header is not honoured and the
     * connection address is used, which is safe.
     *
     * @since 2.11.9
     *
     * @param string   $remote          Validated REMOTE_ADDR.
     * @param string   $header          Trusted header key.
     * @param string[] $trusted_proxies Configured proxy IPs/CIDRs.
     * @return bool
     */
    private static function peer_is_trusted_proxy( $remote, $header, $trusted_proxies ) {
        // A dual-stack proxy connects as ::ffff:10.0.0.5; read it as the IPv4 it
        // is, so a private reverse proxy is recognised as own network and a peer
        // listed by its IPv4 matches. client_from_chain() already unmaps, this
        // keeps the two sides symmetric (found by the cross review of 2.11.9).
        $remote = self::unmap_ipv4( $remote );

        if ( ! empty( $trusted_proxies ) && self::in_list_ip_or_cidr( $remote, $trusted_proxies ) ) {
            return true;
        }

        if ( 'cf-connecting-ip' === $header && self::in_list_ip_or_cidr( $remote, self::cloudflare_ranges() ) ) {
            return true;
        }

        return empty( $trusted_proxies ) && self::is_own_network( $remote );
    }

    /**
     * Resolve the client IP from a $_SERVER-like array.
     *
     * Only the real TCP peer (REMOTE_ADDR) is trusted by default, because it
     * cannot be spoofed. A forwarded-for / connecting-ip header is honoured only
     * when the admin has declared their site sits behind that proxy AND the
     * connection actually comes from a proxy we trust (see
     * peer_is_trusted_proxy()); otherwise any visitor could forge the header and
     * impersonate any IP, bypassing the whitelist, evading the blacklist and
     * poisoning the rate limiter. Reported by the wp.org review of 2.11.8.
     *
     * @param array    $server          A $_SERVER-like array.
     * @param string   $trusted_header  One of the keys in trusted_header_map(), or '' for none.
     * @param string[] $trusted_proxies Configured proxy IPs/CIDRs.
     * @return string Validated IP, or '0.0.0.0' when none could be determined.
     */
    public static function resolve_client_ip( $server, $trusted_header = '', $trusted_proxies = array() ) {
        $map    = self::trusted_header_map();
        $remote = '';

        if ( ! empty( $server['REMOTE_ADDR'] ) ) {
            $candidate = trim( (string) $server['REMOTE_ADDR'] );
            if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
                $remote = $candidate;
            }
        }

        if ( '' !== $trusted_header && isset( $map[ $trusted_header ] ) && '' !== $remote
            && ! empty( $server[ $map[ $trusted_header ] ] )
            && self::peer_is_trusted_proxy( $remote, $trusted_header, $trusted_proxies )
        ) {
            $value = self::client_from_chain( (string) $server[ $map[ $trusted_header ] ] );
            if ( '' !== $value ) {
                return $value;
            }
        }

        return '' !== $remote ? $remote : '0.0.0.0';
    }

    /**
     * The visitor address in a forwarded header, read from the proxy's end
     *
     * A proxy adds the address it received the connection from to the END of
     * X-Forwarded-For, and keeps whatever the visitor sent in front of it. So
     * in "a, b, c" the visitor wrote a and b, and only c was written by the
     * proxy the site trusts. Until 2.11.7 this took the first entry, the one
     * the visitor chooses, and on a site set to X-Forwarded-For anybody could
     * pick the address the firewall saw: out of the blacklist, into the
     * whitelist, a new address per request for the rate limit and the login
     * lockout. Found by the audit of the firewall for 2.11.8.
     *
     * Read from the right, an address of the site's own network (see
     * is_own_network()) is taken as one more proxy and passed over, and the
     * first address outside it is the visitor. When there is none, the nearest
     * valid address is. An entry that is not an address stops the reading,
     * since nothing left of it can be told apart from what the visitor wrote,
     * and the caller falls back to the connection address.
     *
     * The first version of this, in the same release, told the two apart with
     * FILTER_FLAG_NO_PRIV_RANGE and FILTER_FLAG_NO_RES_RANGE, and what those
     * flags cover changes with the PHP version: from 8.3 an IPv4 address
     * written as IPv6 (::ffff:a.b.c.d, as a dual stack proxy writes it) counts
     * as reserved, so it was passed over and the visitor's own entry won
     * again. Found by the cross review of 2.11.8. The ranges are written out
     * now, and a mapped address is read as the IPv4 it is.
     *
     * Behind a CDN with a reverse proxy in front of PHP that adds to the
     * header, or a load balancer that adds its own public address, this reads
     * the address of that CDN or balancer. That is the price of not believing
     * the visitor; the header of the CDN itself is the setting that fits
     * there, and the Firewall tab says so when the administrator's own request
     * shows that shape.
     *
     * @since 2.11.8
     *
     * @param string $value Header value.
     * @return string Address, or '' when there is none to trust.
     */
    public static function client_from_chain( $value ) {
        $entries = array_reverse( array_map( 'trim', explode( ',', (string) $value ) ) );
        $nearest = '';

        foreach ( $entries as $entry ) {
            $address = self::unmap_ipv4( $entry );

            if ( ! filter_var( $address, FILTER_VALIDATE_IP ) ) {
                break;
            }

            if ( ! self::is_own_network( $address ) ) {
                return $address;
            }

            if ( '' === $nearest ) {
                $nearest = $address;
            }
        }

        return $nearest;
    }

    /**
     * The X-Forwarded-For header of this request, when the site trusts it
     *
     * Only for showing: the Firewall tab compares both readings of the
     * administrator's own request. The firewall resolves the address with
     * get_client_ip(). It lives here so that every read of a proxy header stays
     * in this class, which a permanent harness checks.
     *
     * @since 2.11.8
     *
     * @return string Header value, or '' when it is not trusted or not sent.
     */
    public static function trusted_forwarded_for() {
        if ( 'x-forwarded-for' !== self::trusted_proxy_header() || ! isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            return '';
        }

        return sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
    }

    /**
     * Whether an address belongs to a network no visitor comes from
     *
     * Private, loopback, link-local and the shared address space providers use
     * inside their own networks, for IPv4 and IPv6. Written out rather than
     * taken from filter_var() flags, whose ranges change between PHP versions.
     *
     * @since 2.11.8
     *
     * @param string $address Valid IP address, IPv4 written as IPv4.
     * @return bool
     */
    public static function is_own_network( $address ) {
        $ranges = array(
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '100.64.0.0/10',
            '::1/128',
            'fc00::/7',
            'fe80::/10',
        );

        foreach ( $ranges as $range ) {
            if ( self::cidr_match( $address, $range ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * An IPv4 address written as IPv6, as the IPv4 address it is
     *
     * Covers both spellings, ::ffff:203.0.113.7 and ::ffff:cb00:7107. Anything
     * else comes back as it was.
     *
     * @since 2.11.8
     *
     * @param string $address Address as written in the header.
     * @return string
     */
    public static function unmap_ipv4( $address ) {
        if ( ! filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            return $address;
        }

        $packed = inet_pton( $address );

        if ( false !== $packed && 16 === strlen( $packed ) && str_repeat( "\0", 10 ) . "\xff\xff" === substr( $packed, 0, 12 ) ) {
            $ipv4 = inet_ntop( substr( $packed, 12 ) );

            return false === $ipv4 ? $address : $ipv4;
        }

        return $address;
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

        return self::resolve_client_ip( $server, $trusted, self::trusted_proxies() );
    }
}
