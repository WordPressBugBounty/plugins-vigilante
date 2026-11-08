<?php
/**
 * Security Analyzer — WP information exposure category (18 pts).
 *
 * Checks: meta_generator (2), rest_users_enum (3), author_scanning (2),
 * wp_version_public (1), readme_exists (1), license_exists (1),
 * rsd_link (1), wlw_manifest (1), shortlink (1), active_theme_info (info, 5 pts
 * reserved for bonus "theme up-to-date" when applicable).
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * WordPress exposure checks.
 */
class Vigilante_SA_Category_WP_Exposure {

    const SLUG = 'wp_exposure';

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
            $results[] = $this->check_readme_exists();
            $results[] = $this->check_license_exists();
            $results[] = $this->check_rsd_link();
            $results[] = $this->check_wlw_manifest();
            $results[] = $this->check_shortlink();
            $results[] = $this->check_active_theme_info();
        }

        if ( 'slow' === $phase || 'all' === $phase ) {
            $results[] = $this->check_meta_generator();
            $results[] = $this->check_rest_users_enum();
            $results[] = $this->check_author_scanning();
            $results[] = $this->check_wp_version_public();
        }

        return $results;
    }

    private function check_meta_generator() {
        $args = array(
            'id'       => 'meta_generator',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( '<meta name="generator"> in HTML', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'wp-hardening', 'vigilante-section-hardening-headers' ),
        );

        // The tag is removed by the head cleaner, which only loads with the
        // WordPress Hardening module on: with it off, a tag that is still
        // there is not "a plugin or a theme", it is the setting not running.
        $remove_generator = (int) ( $this->settings->is_module_enabled( 'wp_hardening' )
            && $this->settings->get_option( 'wp_hardening', 'remove_wp_generator', 0 ) );
        $probe            = Vigilante_SA_Helpers::probe_home();

        if ( null === $probe ) {
            $args['detail'] = Vigilante_SA_Helpers::with_challenge( __( 'Could not fetch the homepage to inspect HTML meta tags.', 'vigilante' ), true );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        // Any attribute order: until 3.0.11 this asked for name to come first,
        // and Divi prints <meta content="Divi v.5.11.1" name="generator"/>,
        // so its sites read clean (B118).
        $generators = self::generator_contents( $probe['body'] );
        if ( null === $generators ) {
            $args['detail'] = __( 'Could not finish reading the homepage HTML to look for generator meta tags.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        if ( empty( $generators ) ) {
            $args['detail'] = __( 'No <meta name="generator"> tag found in the homepage HTML.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['data']['generators'] = $generators;
        $named                      = implode( ', ', $generators );

        $wordpress = false;
        foreach ( $generators as $generator ) {
            if ( 0 === stripos( $generator, 'WordPress' ) ) {
                $wordpress = true;
                break;
            }
        }

        if ( $remove_generator ) {
            $args['detail'] = sprintf(
                /* translators: %s: content of the generator meta tags found, e.g. "Divi v.5.11.1" */
                __( 'The "remove generator" setting is on, but the homepage still has generator meta tags (%s): they come from a plugin or the theme, which print them on their own.', 'vigilante' ),
                $named
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        if ( $wordpress ) {
            $args['detail'] = sprintf(
                /* translators: %s: content of the generator meta tags found, e.g. "WordPress 7.1" */
                __( 'The homepage exposes the WordPress version through a <meta name="generator"> tag (%s).', 'vigilante' ),
                $named
            );
        } else {
            $args['detail'] = sprintf(
                /* translators: %s: content of the generator meta tags found, e.g. "Divi v.5.11.1" */
                __( 'The homepage has generator meta tags (%s) that name the software behind the site and its version.', 'vigilante' ),
                $named
            );
        }
        return Vigilante_SA_Check_Result::fail( $args );
    }

    /**
     * The content of every <meta name="generator"> tag of a page
     *
     * Attributes in any order, quoted or not. Each content is cut to 80
     * characters.
     *
     * @since 3.0.11
     *
     * @param string $html Page HTML.
     * @return string[]|null The contents, or null when PCRE gave up on the page.
     */
    public static function generator_contents( $html ) {
        // A quoted value may hold ">" (content="a>b"): the tag ends at the first
        // ">" outside quotes.
        $count = preg_match_all( '#<meta\b((?:[^>"\']|"[^"]*"|\'[^\']*\')*)>#i', (string) $html, $tags );
        if ( false === $count ) {
            return null;
        }

        $found = array();
        foreach ( $tags[1] as $attributes ) {
            // The attributes one by one, so that "name=generator" written
            // inside the value of another attribute does not count (third
            // blind review of 3.0.11), and neither does data-name. The first
            // of a repeated attribute wins, as in a browser.
            $parsed = preg_match_all( '#([^\s=/>"\']+)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>"\']+)))?#', $attributes, $pairs, PREG_SET_ORDER );
            if ( false === $parsed ) {
                return null;
            }
            $attrs = array();
            foreach ( $pairs as $pair ) {
                $key = strtolower( $pair[1] );
                if ( isset( $attrs[ $key ] ) ) {
                    continue;
                }
                if ( isset( $pair[4] ) && '' !== $pair[4] ) {
                    $attrs[ $key ] = $pair[4];
                } elseif ( isset( $pair[3] ) && '' !== $pair[3] ) {
                    $attrs[ $key ] = $pair[3];
                } else {
                    $attrs[ $key ] = isset( $pair[2] ) ? $pair[2] : '';
                }
            }
            if ( ! isset( $attrs['name'] ) || 'generator' !== strtolower( trim( $attrs['name'] ) ) ) {
                continue;
            }
            $content = trim( html_entity_decode( isset( $attrs['content'] ) ? $attrs['content'] : '', ENT_QUOTES, 'UTF-8' ) );
            if ( '' === $content ) {
                $content = '?';
            }
            $found[] = function_exists( 'mb_substr' ) ? mb_substr( $content, 0, 80 ) : substr( $content, 0, 80 );
        }

        return array_values( array_unique( $found ) );
    }

    private function check_rest_users_enum() {
        $args = array(
            'id'       => 'rest_users_enum',
            'category' => self::SLUG,
            'max'      => 3,
            'label'    => __( 'REST: public list of users (/wp/v2/users)', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'rest-api', 'field-block-user-enumeration' ),
        );

        // The sub-toggle is only effective when the REST hardening module itself
        // is enabled, and the switch that loads its class is the one of the
        // Dashboard (modules.rest_api_security). Until 3.0.4 only the copy
        // inside the section was read here, which stays on with the module off.
        $module_on   = (int) ( $this->settings->is_module_enabled( 'rest_api_security' )
            && $this->settings->get_option( 'rest_api_security', 'enabled', 0 ) );
        $sub_on      = (int) $this->settings->get_option( 'rest_api_security', 'block_user_enumeration', 0 );
        $setting_on  = $module_on && $sub_on;
        $args['data'] = array(
            'rest_module_enabled' => (bool) $module_on,
            'block_sub_toggle'    => (bool) $sub_on,
        );

        $url      = rest_url( 'wp/v2/users' );
        $response = Vigilante_SA_Helpers::get( $url, array( 'redirection' => 0 ) );

        if ( is_wp_error( $response ) ) {
            $args['detail'] = Vigilante_SA_Helpers::with_challenge( __( 'Could not probe the REST users endpoint.', 'vigilante' ) );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $code = (int) wp_remote_retrieve_response_code( $response );
        $body = (string) wp_remote_retrieve_body( $response );
        $args['data']['code'] = $code;

        // 401/403 => protected at the auth layer (e.g. Vigilante REST mode = authenticated_only).
        if ( in_array( $code, array( 401, 403 ), true ) ) {
            $args['detail'] = __( 'REST /wp/v2/users requires authentication.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        // 404 with rest_no_route => Vigilante's rest_endpoints filter removed the route. Correct protection.
        if ( 404 === $code ) {
            if ( false !== strpos( $body, 'rest_no_route' ) || false !== strpos( $body, '"code":"rest_no_route"' ) ) {
                $args['detail'] = __( 'REST /wp/v2/users route is unregistered for anonymous clients.', 'vigilante' );
                return Vigilante_SA_Check_Result::pass( $args );
            }
            $args['detail'] = __( 'REST /wp/v2/users returned 404 to the anonymous probe (likely a firewall rule).', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        if ( 200 === $code ) {
            $decoded = json_decode( $body, true );
            if ( is_array( $decoded ) && empty( $decoded ) ) {
                $args['detail'] = __( 'REST /wp/v2/users returned an empty list to the unauthenticated probe.', 'vigilante' );
                return Vigilante_SA_Check_Result::pass( $args );
            }
            if ( is_array( $decoded ) && ! empty( $decoded ) ) {
                $args['data']['users_leaked'] = count( $decoded );

                // Most common trap: sub-toggle is on but the REST hardening module master is off.
                if ( $sub_on && ! $module_on ) {
                    $args['detail'] = __( 'The "block user enumeration" option is on, but the REST API hardening module itself is disabled — so the filter never runs. Enable the REST API module to activate the block.', 'vigilante' );
                    return Vigilante_SA_Check_Result::fail( $args );
                }

                // Both flags on + still returning data → cache/CDN/priority override.
                if ( $setting_on ) {
                    $args['detail'] = sprintf(
                        /* translators: %d: number of users returned by the probe */
                        _n(
                            'Block is fully enabled, but the probe still sees %d user record. A page cache, CDN, or higher-priority plugin filter is overriding the block: flush caches and scan again.',
                            'Block is fully enabled, but the probe still sees %d user records. A page cache, CDN, or higher-priority plugin filter is overriding the block: flush caches and scan again.',
                            count( $decoded ),
                            'vigilante'
                        ),
                        count( $decoded )
                    );
                    return Vigilante_SA_Check_Result::warn( $args );
                }

                // Nothing on at all → real exposure.
                $args['detail'] = sprintf(
                    /* translators: %d: number of users leaked */
                    _n(
                        'The REST users endpoint exposes %d user record publicly.',
                        'The REST users endpoint exposes %d user records publicly.',
                        count( $decoded ),
                        'vigilante'
                    ),
                    count( $decoded )
                );
                return Vigilante_SA_Check_Result::fail( $args );
            }
        }

        // Anything else (5xx, odd proxies): trust the Vigilante setting as authoritative
        // only when BOTH flags are on (module + sub-toggle).
        if ( $setting_on ) {
            $args['detail'] = sprintf(
                /* translators: %d: HTTP status code */
                __( 'Probe returned status %d; Vigilant user-enumeration block is enabled in settings.', 'vigilante' ),
                $code
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: HTTP status code */
            __( 'The REST users endpoint responded with status %d — manual review recommended.', 'vigilante' ),
            $code
        );
        return Vigilante_SA_Check_Result::warn( $args );
    }

    private function check_author_scanning() {
        $args = array(
            'id'       => 'author_scanning',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( '?author=N enumeration', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'users', 'field-block-author-scanning' ),
        );

        // The sub-toggle is only effective when the User Security module is enabled.
        // If the master module is off, the class is never instantiated and the hook is
        // never registered — the sub-toggle alone does nothing. Detect both so we can
        // tell the user exactly which switch is missing.
        $module_on  = (int) $this->settings->is_module_enabled( 'user_security' );
        $sub_on     = (int) $this->settings->get_option( 'user_security', 'block_author_scanning', 0 );
        $setting_on = $module_on && $sub_on;

        $url      = add_query_arg( 'author', 1, home_url( '/' ) );
        $response = Vigilante_SA_Helpers::get( $url, array( 'redirection' => 0 ) );

        if ( is_wp_error( $response ) ) {
            $args['detail'] = Vigilante_SA_Helpers::with_challenge( __( 'Could not probe ?author=1.', 'vigilante' ) );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $code     = (int) wp_remote_retrieve_response_code( $response );
        $location = (string) wp_remote_retrieve_header( $response, 'location' );
        $args['data'] = array(
            'code'             => $code,
            'location'         => $location,
            'module_enabled'   => (bool) $module_on,
            'block_sub_toggle' => (bool) $sub_on,
        );

        // Stock WP redirects /?author=1 to /author/USERNAME/ — that's the leak.
        if ( $code >= 300 && $code < 400 && $location && preg_match( '#/author/([^/?]+)#i', $location, $m ) ) {
            $args['data']['leaked_login'] = $m[1];

            // Common configuration trap: sub-toggle on but master module off.
            if ( $sub_on && ! $module_on ) {
                $args['detail'] = sprintf(
                    /* translators: %s: leaked username */
                    __( 'Author scanning still leaks the username "%s". The "Block author scanning" option is on, but the User Security module itself is disabled — so the protection never runs. Enable the module from the Dashboard modules grid.', 'vigilante' ),
                    $m[1]
                );
                return Vigilante_SA_Check_Result::fail( $args );
            }

            // Both flags on but the probe still leaks. Until 3.0.11 this always
            // blamed a cache, without checking, and on the site where it was
            // seen the redirect was generated by PHP at that moment: a plugin
            // that called redirect_canonical() before Vigilant (B119, B122).
            // The request is repeated past any page cache, and the cache is only
            // named when the answer says it came from one.
            if ( $setting_on ) {
                $args['data']['cause'] = $this->author_leak_cause( $url );

                if ( 'unknown' === $args['data']['cause'] ) {
                    $args['detail'] = sprintf(
                        /* translators: %s: leaked username */
                        __( 'Author scanning still leaks the username "%s" even though the protection is enabled, and the same request past any page cache got no usable answer, so the cause is not known. If you use a page cache or CDN, purge it and re-scan; if it keeps leaking, something on the site sends ?author=N to the author page before Vigilant can block it, usually another plugin or the theme.', 'vigilante' ),
                        $m[1]
                    );
                } elseif ( 'cache' === $args['data']['cause'] ) {
                    $args['detail'] = sprintf(
                        /* translators: %s: leaked username */
                        __( 'Author scanning still leaks the username "%s" even though the protection is enabled. The answer comes from a cache or CDN, and the same request past the cache does not leak: purge your page cache and re-scan.', 'vigilante' ),
                        $m[1]
                    );
                } else {
                    $args['detail'] = sprintf(
                        /* translators: %s: leaked username */
                        __( 'Author scanning still leaks the username "%s" even though the protection is enabled, and not from a cache: the site generates that redirect at the moment. Something on the site sends ?author=N to the author page before Vigilant can block it, usually another plugin or the theme. Deactivate plugins one by one (Health Check troubleshooting mode does it only for you) until ?author=1 goes to the home page.', 'vigilante' ),
                        $m[1]
                    );
                }
                return Vigilante_SA_Check_Result::warn( $args );
            }

            // Both flags off: clean FAIL.
            $args['detail'] = sprintf(
                /* translators: %s: leaked username */
                __( 'Author scanning leaks the username "%s" via redirect to /author/NAME/.', 'vigilante' ),
                $m[1]
            );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        // Any 3xx redirect that does NOT point to /author/NAME/ is a valid protection
        // (Vigilant's block_author_scan redirects to home_url() with 301).
        if ( $code >= 300 && $code < 400 ) {
            $args['detail'] = __( '?author=1 redirected to a URL that does not contain /author/<username>/.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        if ( 200 === $code || 404 === $code || 403 === $code ) {
            $args['detail'] = __( '?author=1 response did not contain an author username.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        // Anything else: trust the setting if it's on.
        if ( $setting_on ) {
            $args['detail'] = sprintf(
                /* translators: %d: HTTP status code */
                __( '?author=1 returned %d; Vigilant author-scanning block is enabled in settings.', 'vigilante' ),
                $code
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: HTTP status code */
            __( '?author=1 returned %d. Manual review recommended.', 'vigilante' ),
            $code
        );
        return Vigilante_SA_Check_Result::warn( $args );
    }

    /**
     * Why ?author=1 leaks with the protection on: a cache, or the site itself
     *
     * @since 3.0.11
     *
     * The same request is repeated past any page cache, with a query string
     * nothing caches. If that one leaks too, the site generates the redirect
     * now; if it does not, what leaked was a stored page. Cache headers are
     * not trusted to tell: there are too many names (the first version of
     * this listed six and missed DietPress, FastCGI, Kinsta and Nginx, second
     * blind review of 3.0.11). Only a redirect decides: an error, a normal
     * page, a verification screen or a rate limit says nothing.
     *
     * @param string $url The probed address.
     * @return string 'cache', 'site' or 'unknown'.
     */
    private function author_leak_cause( $url ) {
        $fresh = Vigilante_SA_Helpers::get( add_query_arg( 'vigilante-nocache', (string) time(), $url ), array( 'redirection' => 0 ) );
        if ( is_wp_error( $fresh ) ) {
            return 'unknown';
        }

        $code = (int) wp_remote_retrieve_response_code( $fresh );
        if ( $code < 300 || $code >= 400 ) {
            return 'unknown';
        }

        $location = (string) wp_remote_retrieve_header( $fresh, 'location' );
        if ( preg_match( '#/author/([^/?]+)#i', $location ) ) {
            return 'site';
        }

        // Only the block itself proves that the fresh request reached
        // WordPress and the protection ran: it sends the visitor to the home
        // page (block_author_scan()). A redirect anywhere else, a login page or
        // a CDN rule for unknown query strings, says nothing about a cache
        // (third blind review of 3.0.11). Cut by hand, not with wp_parse_url().
        $host_of = function ( $url ) {
            return preg_match( '#^[a-z][a-z0-9+.-]*://([^/?\#:]*)#i', (string) $url, $m ) ? strtolower( $m[1] ) : '';
        };
        $path_of = function ( $url ) {
            $path = (string) preg_replace( '#^[a-z][a-z0-9+.-]*://[^/?\#]*#i', '', (string) $url );
            $path = (string) preg_replace( '#[?\#].*$#s', '', $path );
            return untrailingslashit( '' === $path ? '/' : $path );
        };
        $home      = home_url( '/' );
        $same_host = '' === $host_of( $location ) || $host_of( $location ) === $host_of( $home );

        return ( '' !== $location && $same_host && $path_of( $location ) === $path_of( $home ) ) ? 'cache' : 'unknown';
    }

    private function check_wp_version_public() {
        $args = array(
            'id'       => 'wp_version_public',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'WordPress version in assets', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'wp-hardening', 'field-remove-wp-version-assets' ),
        );

        $probe = Vigilante_SA_Helpers::probe_home();
        if ( null === $probe ) {
            $args['detail'] = Vigilante_SA_Helpers::with_challenge( __( 'Could not read homepage HTML.', 'vigilante' ), true );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $version = get_bloginfo( 'version' );
        $leaked  = false;
        if ( $version && strpos( $probe['body'], '?ver=' . $version ) !== false ) {
            $leaked = true;
        }
        if ( $version && preg_match( '#content=["\']WordPress ' . preg_quote( $version, '#' ) . '["\']#i', $probe['body'] ) ) {
            $leaked = true;
        }

        if ( $leaked ) {
            $args['detail'] = sprintf(
                /* translators: %s: WordPress version */
                __( 'The exact WordPress version (%s) is present in homepage asset URLs.', 'vigilante' ),
                $version
            );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $args['detail'] = __( 'No WordPress version markers found in homepage asset URLs.', 'vigilante' );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_readme_exists() {
        $args = array(
            'id'       => 'readme_exists',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'readme.html presence', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'vigilante-section-firewall-server' ),
        );

        if ( ! Vigilante_SA_Helpers::abspath_file_exists( 'readme.html' ) ) {
            $args['detail'] = __( 'readme.html is not present at the WordPress root.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'readme.html is present at the site root and leaks the WordPress version to anyone who visits it.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_license_exists() {
        $args = array(
            'id'       => 'license_exists',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'license.txt presence', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'vigilante-section-firewall-server' ),
        );

        if ( ! Vigilante_SA_Helpers::abspath_file_exists( 'license.txt' ) ) {
            $args['detail'] = __( 'license.txt is not present at the WordPress root.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'license.txt is reachable publicly at the site root.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_rsd_link() {
        return $this->boolean_setting_check(
            'rsd_link',
            'wp_hardening',
            'remove_rsd_link',
            __( 'RSD link in HTML', 'vigilante' ),
            __( 'RSD link removal setting is enabled.', 'vigilante' ),
            __( 'The RSD link is still rendered in the HTML head. Disable it under WP Hardening.', 'vigilante' ),
            1,
            Vigilante_SA_Helpers::build_fix_url( 'wp-hardening', 'vigilante-section-hardening-headers' )
        );
    }

    private function check_wlw_manifest() {
        return $this->boolean_setting_check(
            'wlw_manifest',
            'wp_hardening',
            'remove_wlw_manifest',
            __( 'Windows Live Writer manifest in HTML', 'vigilante' ),
            __( 'WLW manifest removal setting is enabled.', 'vigilante' ),
            __( 'The WLW manifest link is still rendered. Disable it under WP Hardening.', 'vigilante' ),
            1,
            Vigilante_SA_Helpers::build_fix_url( 'wp-hardening', 'vigilante-section-hardening-headers' )
        );
    }

    private function check_shortlink() {
        return $this->boolean_setting_check(
            'shortlink',
            'wp_hardening',
            'remove_shortlink',
            __( 'Shortlink header', 'vigilante' ),
            __( 'Shortlink header removal setting is enabled.', 'vigilante' ),
            __( 'The Shortlink header is still rendered. Disable it under WP Hardening.', 'vigilante' ),
            1,
            Vigilante_SA_Helpers::build_fix_url( 'wp-hardening', 'vigilante-section-hardening-headers' )
        );
    }

    /**
     * The active theme, as information
     *
     * Not scored since 3.0.5. It used to be worth 5 points, the heaviest check
     * of this category, for a theme with no update pending: nothing an
     * attacker sees, and the same thing the theme_updates check of the
     * internal category already scores.
     */
    private function check_active_theme_info() {
        $theme = wp_get_theme();
        $args  = array(
            'id'       => 'active_theme_info',
            'category' => self::SLUG,
            'label'    => __( 'Active theme', 'vigilante' ),
            'fix_link' => '',
        );

        if ( ! $theme || ! $theme->exists() ) {
            $args['detail'] = __( 'Could not read active theme metadata.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $name    = $theme->get( 'Name' );
        $version = $theme->get( 'Version' );
        $author  = $theme->get( 'Author' );

        $args['data']   = array(
            'name'    => $name,
            'version' => $version,
            'author'  => $author,
        );
        $args['detail'] = sprintf(
            /* translators: 1: theme name, 2: version, 3: author */
            __( '%1$s %2$s by %3$s.', 'vigilante' ),
            $name,
            $version,
            wp_strip_all_tags( (string) $author )
        );

        if ( ! function_exists( 'get_theme_updates' ) ) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $updates = function_exists( 'get_theme_updates' ) ? get_theme_updates() : array();
        $slug    = $theme->get_stylesheet();

        if ( isset( $updates[ $slug ] ) ) {
            $args['detail'] .= ' ' . __( 'An update is available.', 'vigilante' );
        }

        return Vigilante_SA_Check_Result::info( $args );
    }

    /**
     * Shared helper for the three "remove X from head" boolean checks.
     */
    private function boolean_setting_check( $id, $section, $key, $label, $pass_detail, $fail_detail, $max, $fix_link ) {
        $args = array(
            'id'       => $id,
            'category' => self::SLUG,
            'max'      => $max,
            'label'    => $label,
            'fix_link' => $fix_link,
        );

        $enabled = (int) $this->settings->get_option( $section, $key, 0 );

        // The section is also the module that applies the setting: with the
        // module off the class that removes the tag never loads, and until
        // 3.0.4 this passed on the saved value alone.
        if ( $enabled && ! $this->settings->is_module_enabled( $section ) ) {
            $args['detail'] = Vigilante_SA_Helpers::module_off_detail( $this->settings, $section );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        if ( $enabled ) {
            $args['detail'] = $pass_detail;
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = $fail_detail;
        return Vigilante_SA_Check_Result::fail( $args );
    }
}
