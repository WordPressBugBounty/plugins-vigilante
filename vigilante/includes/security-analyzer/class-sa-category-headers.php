<?php
/**
 * Security Analyzer — HTTP headers category (18 pts).
 *
 * Reads the actual headers served from the homepage and cross-checks them
 * with what Vigilant writes to .htaccess. A header that Vigilant sends and
 * that does not reach the browser fails, saying so and why: the points are
 * for what arrives.
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

    /**
     * Whether the Security Headers module is on, set by run()
     *
     * @var bool
     */
    private $module_on = true;

    /**
     * Vigilant blocks found in the .htaccess files above this site, once read
     *
     * @var array|null
     */
    private $blocks_above = null;

    /**
     * Names of the headers the block of Vigilant sets, in lowercase, set by run()
     *
     * @var string[]
     */
    private $written = array();

    /**
     * Why a header that Vigilant sends is not arriving, as a sentence
     *
     * @var string
     */
    private $cause = '';

    /**
     * Whether that cause is the whole block not being applied (and not one
     * header being removed on the way)
     *
     * @var bool
     */
    private $block_not_applied = false;

    /**
     * Whether some check found a header that Vigilant sends and does not
     * arrive, so the cause has to be said
     *
     * @var bool
     */
    private $cause_needed = false;

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

        // The headers are written to .htaccess only while the Security Headers
        // module is on, and taken out when it is switched off. What is set in
        // its tab is then saved but not sent, and until 3.0.4 these checks read
        // "enabled in Vigilant but not reaching the browser" and gave half the
        // points for it.
        $this->module_on = $this->settings->is_module_enabled( 'security_headers' );
        $this->note_what_vigilant_sends( $headers, $probe ? (int) $probe['code'] : 0 );

        $results = array();
        $results[] = $this->check_csp( $headers, $sec_hdrs );
        $results[] = $this->check_hsts( $headers, $sec_hdrs );
        $results[] = $this->check_x_frame( $headers );
        $results[] = $this->check_x_content_type( $headers );
        $results[] = $this->check_referrer_policy( $headers );
        $results[] = $this->check_permissions_policy( $headers );
        $results[] = $this->check_coop( $headers, $sec_hdrs );
        $results[] = $this->check_corp( $headers, $sec_hdrs );
        $results[] = $this->check_server_signature( $headers );

        // If the probe failed entirely, mark all as SKIP.
        if ( null === $probe ) {
            foreach ( $results as $r ) {
                $r->state  = Vigilante_SA_Check_Result::STATE_SKIP;
                $r->score  = 0;
                $r->detail = __( 'Could not fetch the homepage to read response headers.', 'vigilante' );
            }

            return $results;
        }

        $this->note_headers_from_above( $results );

        // The reason is the same for every header of the block, so it is said
        // once, in a row of its own that scores nothing, and not after each
        // of them: nine rows ending in the same three lines were not read.
        if ( $this->cause_needed && '' !== $this->cause ) {
            array_unshift(
                $results,
                Vigilante_SA_Check_Result::info(
                    array(
                        'id'       => 'headers_not_arriving',
                        'category' => self::SLUG,
                        'label'    => __( 'Why these headers do not arrive', 'vigilante' ),
                        'detail'   => $this->cause,
                    )
                )
            );
        }

        return $results;
    }

    /**
     * Say where a header comes from when this site is not the one sending it
     *
     * A WordPress in a subfolder also receives the headers of the block that
     * the Vigilant of the installation above keeps in its own .htaccess:
     * Apache applies every .htaccess on the way down. With the module off here
     * the header still arrives, the check passes, and nothing on this screen
     * explained why switching the module off changed nothing. The CSP check
     * has said so since 2.9.9; this does it for the rest.
     *
     * @since 3.0.5
     *
     * @param Vigilante_SA_Check_Result[] $results Results of this category.
     */
    private function note_headers_from_above( array $results ) {
        if ( $this->module_on ) {
            return;
        }

        $files = array();
        foreach ( $this->vigilant_blocks_above() as $file => $markers ) {
            foreach ( (array) $markers as $marker ) {
                if ( false !== strpos( (string) $marker, 'Security Headers' ) ) {
                    $files[] = $file;
                    break;
                }
            }
        }

        if ( empty( $files ) ) {
            return;
        }

        $note = sprintf(
            /* translators: %s: absolute path of one or more .htaccess files */
            __( 'This site is not sending it: the Security Headers module is off here. A Vigilant block in %s, a directory above this site, applies here too, and this installation neither sees nor controls it.', 'vigilante' ),
            implode( ', ', $files )
        );

        $from_above = array( 'hsts', 'x_frame', 'x_content_type', 'referrer_policy', 'permissions_policy', 'coop', 'corp' );

        foreach ( $results as $r ) {
            if ( Vigilante_SA_Check_Result::STATE_PASS === $r->state && in_array( $r->id, $from_above, true ) ) {
                $r->detail .= ' ' . $note;
            }
        }
    }

    /**
     * What the block of Vigilant sets, and why it may not be arriving
     *
     * Read from the rules Vigilant writes and not from the settings one by
     * one, because the rules are what the server gets. Until 3.0.4 only the
     * CSP and HSTS checks said "switched on but not arriving", with half the
     * points; the other six said that the header was missing, next to a link
     * to a setting that was already on.
     *
     * The cause is the likely one and is worded as such. It is looked for in
     * this order, each step being what the next one takes for granted: the
     * rules are in .htaccess, the home page answered with a normal page, and
     * only then whether other headers of the same block arrive. A header
     * that arrives may come from the hosting and not from Vigilant, so with
     * the rules missing from .htaccess nothing is said about them being
     * applied, and an error page from a layer in between is not read as a
     * server that lacks a module.
     *
     * @since 3.0.5
     *
     * @param array $headers Response headers from the home page probe.
     * @param int   $code    HTTP status of that answer, 0 when there was none.
     */
    private function note_what_vigilant_sends( $headers, $code = 0 ) {
        $this->written           = array();
        $this->cause             = '';
        $this->block_not_applied = false;
        $this->cause_needed      = false;

        if ( ! $this->module_on || ! class_exists( 'Vigilante_Security_Headers' ) ) {
            return;
        }

        $sender = new Vigilante_Security_Headers( $this->settings );
        if ( preg_match_all( '/^\s*Header\s+(?:always\s+)?set\s+([A-Za-z-]+)\s/mi', (string) $sender->generate_rules_content(), $found ) ) {
            $this->written = array_values( array_unique( array_map( 'strtolower', $found[1] ) ) );
        }
        if ( empty( $this->written ) ) {
            return;
        }

        $arriving = 0;
        foreach ( $this->written as $name ) {
            if ( '' !== $this->header_value( $headers, array( $name ) ) ) {
                ++$arriving;
            }
        }

        $this->block_not_applied = ( 0 === $arriving );

        if ( ! $sender->are_rules_active() ) {
            $this->block_not_applied = true;
            $this->cause             = __( 'The rules of Vigilant are not in .htaccess: this server may not read that file, as nginx does not, or the file could not be written.', 'vigilante' );
            return;
        }

        if ( $code > 0 && ( $code < 200 || $code > 299 ) ) {
            $this->cause = sprintf(
                /* translators: %d: HTTP status code, such as 503 */
                __( 'The home page answered with HTTP %d instead of a normal page, and that answer may come from a layer that does not add these headers: look into that first.', 'vigilante' ),
                $code
            );
            return;
        }

        if ( $arriving > 0 ) {
            // Counted by name: whether they come from this block or from
            // the hosting cannot be told from the answer, hence "likely".
            $this->cause = __( 'Headers that Vigilant also sets do arrive, so the likely cause is something removing the others on the way: a server rule, a caching layer or a CDN.', 'vigilante' );
            return;
        }

        $this->cause = __( 'None of the headers Vigilant sends is arriving, although its rules are in .htaccess, so the server is not applying them. On Apache that usually means that its mod_headers module is not enabled: ask your hosting.', 'vigilante' );
    }

    /**
     * The result for a header that Vigilant sends and that does not arrive
     *
     * It says only that, and run() adds the cause once for all of them. It
     * carries no link: the setting it would lead to is already on.
     *
     * @since 3.0.5
     *
     * @param array    $args  Arguments of the check, with its label.
     * @param string[] $names Names the header can travel under.
     * @return Vigilante_SA_Check_Result|null Null when Vigilant is not sending it.
     */
    private function sent_but_missing( $args, $names ) {
        foreach ( (array) $names as $name ) {
            if ( in_array( strtolower( (string) $name ), $this->written, true ) ) {
                $this->cause_needed = true;
                unset( $args['fix_link'] );
                $args['detail'] = sprintf(
                    /* translators: %s: name of an HTTP header, such as X-Frame-Options */
                    __( '%s is switched on in Vigilant, but the header does not reach the browser.', 'vigilante' ),
                    $args['label']
                );
                return Vigilante_SA_Check_Result::fail( $args );
            }
        }
        return null;
    }

    private function check_csp( $headers, $sec_hdrs ) {
        $args = array(
            'id'       => 'csp',
            'category' => self::SLUG,
            'max'      => 4,
            'label'    => __( 'Content-Security-Policy', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-csp' ),
        );

        $saved_on   = ! empty( $sec_hdrs['csp']['enabled'] );
        $setting_on = $saved_on && $this->module_on;
        $header     = $this->header_value( $headers, array( 'content-security-policy', 'content-security-policy-report-only' ) );

        if ( $header ) {
            // A policy is arriving that Vigilant is not sending. Usually another
            // plugin or the server itself, which is fine. But it is also what a
            // site in a subfolder gets from the block a Vigilant installed one
            // directory up left behind, and then the settings screen and the
            // browser disagree with no way to tell why from here.
            if ( ! $setting_on ) {
                $ghosts = $this->vigilant_blocks_above();

                if ( ! empty( $ghosts ) ) {
                    $args['detail'] = sprintf(
                        /* translators: 1: CSP header value (truncated), 2: absolute path of the .htaccess file. */
                        __( 'A Content-Security-Policy is reaching the browser (%1$s) while CSP is off in Vigilant. It comes from a Vigilant block in %2$s, a directory above this site: Apache applies it here too, and this installation neither sees nor controls it. Remove that block, or manage the policy from the site that owns it.', 'vigilante' ),
                        $this->truncate( $header, 60 ),
                        implode( ', ', array_keys( $ghosts ) )
                    );
                    return Vigilante_SA_Check_Result::warn( $args );
                }

                $args['detail'] = sprintf(
                    /* translators: %s: header value (truncated) */
                    __( 'CSP delivered by something other than Vigilant: %s', 'vigilante' ),
                    $this->truncate( $header, 80 )
                );
                return Vigilante_SA_Check_Result::pass( $args );
            }

            $args['detail'] = sprintf(
                /* translators: %s: header value (truncated) */
                __( 'CSP delivered: %s', 'vigilante' ),
                $this->truncate( $header, 80 )
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $missing = $this->sent_but_missing( $args, array( 'content-security-policy', 'content-security-policy-report-only' ) );
        if ( $missing ) {
            return $missing;
        }

        if ( $setting_on ) {
            // Switched on with a policy that has nothing in it, and with no
            // X-Frame-Options to turn into frame-ancestors: no line is written
            // (Vigilante_Security_Headers::generate_rules_content()). Until
            // 3.0.4 this was a warning with half the points that blamed a
            // server rule or a CDN.
            $args['detail'] = __( 'CSP is switched on in Vigilant, but its policy has no directives, so no header is written for it.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        if ( $saved_on ) {
            $args['detail'] = Vigilante_SA_Helpers::module_off_detail( $this->settings, 'security_headers' );
            return Vigilante_SA_Check_Result::fail( $args );
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

        $saved_on   = ! empty( $sec_hdrs['hsts']['enabled'] );
        $setting_on = $saved_on && $this->module_on;
        $header     = $this->header_value( $headers, array( 'strict-transport-security' ) );

        if ( $header ) {
            $args['detail'] = sprintf(
                /* translators: %s: HSTS header value */
                __( 'HSTS header value: %s', 'vigilante' ),
                $header
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $missing = $this->sent_but_missing( $args, array( 'strict-transport-security' ) );
        if ( $missing ) {
            return $missing;
        }

        if ( $setting_on ) {
            // Not reached while the rules are what they are today: with HSTS
            // on a line is always written, and sent_but_missing() answered
            // above. Kept so that a header that is on and does not arrive
            // never scores, whatever the rules do tomorrow.
            $args['detail'] = sprintf(
                /* translators: %s: name of an HTTP header, such as X-Frame-Options */
                __( '%s is switched on in Vigilant, but the header does not reach the browser.', 'vigilante' ),
                $args['label']
            );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        if ( $saved_on ) {
            $args['detail'] = Vigilante_SA_Helpers::module_off_detail( $this->settings, 'security_headers' );
            return Vigilante_SA_Check_Result::fail( $args );
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

        $missing = $this->sent_but_missing( $args, array( 'x-frame-options' ) );
        if ( $missing ) {
            return $missing;
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

        $missing = $header ? null : $this->sent_but_missing( $args, array( 'x-content-type-options' ) );
        if ( $missing ) {
            return $missing;
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

        $missing = $this->sent_but_missing( $args, array( 'referrer-policy' ) );
        if ( $missing ) {
            return $missing;
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

        $missing = $this->sent_but_missing( $args, array( 'permissions-policy' ) );
        if ( $missing ) {
            return $missing;
        }

        $args['detail'] = __( 'Permissions-Policy is missing. Browsers allow all capabilities (geolocation, camera, etc.) by default.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    /**
     * Cross-Origin-Opener-Policy.
     *
     * Switched off on purpose from the Headers tab is a legitimate configuration,
     * not a finding: COOP severs the window.opener link when another origin opens
     * this site, which is exactly what external tools such as Google Tag Assistant
     * rely on. Those runs report INFO so the check stays visible without dragging
     * the score down. WARN could not do that job: with a max of 1 it scores
     * floor( 1 / 2 ) = 0, the very same zero as a FAIL, and the grade scale keeps
     * "A" for a perfect 100/100.
     *
     * @param array $headers  Response headers from the home page probe.
     * @param array $sec_hdrs The security_headers settings section.
     * @return Vigilante_SA_Check_Result
     */
    private function check_coop( $headers, $sec_hdrs ) {
        $args = array(
            'id'       => 'coop',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'Cross-Origin-Opener-Policy', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'headers', 'vigilante-section-headers-cross-origin' ),
        );

        $header = $this->header_value( $headers, array( 'cross-origin-opener-policy' ) );

        if ( $header && 'unsafe-none' !== strtolower( trim( $header ) ) ) {
            /* translators: %s: value of the Cross-Origin-Opener-Policy HTTP header */
            $args['detail'] = sprintf( __( 'COOP: %s', 'vigilante' ), $header );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        // No header at all, or an explicit unsafe-none. Was that this site's choice?
        $policies   = ( isset( $sec_hdrs['cross_origin_policies'] ) && is_array( $sec_hdrs['cross_origin_policies'] ) ) ? $sec_hdrs['cross_origin_policies'] : array();
        $configured = isset( $policies['opener_policy'] ) ? (string) $policies['opener_policy'] : '';

        if ( '' === $configured || 'unsafe-none' === $configured ) {
            $args['detail'] = __( 'Cross-Origin-Opener-Policy is switched off in Vigilant. Windows opened by other sites keep their link to yours, which is what external tools such as Google Tag Assistant need. Not scored.', 'vigilante' );
            return Vigilante_SA_Check_Result::info( $args );
        }

        if ( ! $this->module_on ) {
            $args['detail'] = Vigilante_SA_Helpers::module_off_detail( $this->settings, 'security_headers' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $missing = $header ? null : $this->sent_but_missing( $args, array( 'cross-origin-opener-policy' ) );
        if ( $missing ) {
            return $missing;
        }

        $args['detail'] = __( 'Cross-Origin-Opener-Policy is missing. Recommended to isolate the browsing context.', 'vigilante' );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    /**
     * Cross-Origin-Resource-Policy. Same reasoning as check_coop() for the INFO state.
     *
     * @param array $headers  Response headers from the home page probe.
     * @param array $sec_hdrs The security_headers settings section.
     * @return Vigilante_SA_Check_Result
     */
    private function check_corp( $headers, $sec_hdrs ) {
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

        $policies   = ( isset( $sec_hdrs['cross_origin_policies'] ) && is_array( $sec_hdrs['cross_origin_policies'] ) ) ? $sec_hdrs['cross_origin_policies'] : array();
        $configured = isset( $policies['resource_policy'] ) ? (string) $policies['resource_policy'] : '';

        if ( '' === $configured ) {
            $args['detail'] = __( 'Cross-Origin-Resource-Policy is switched off in Vigilant, so other sites may load your images and files as usual. Not scored.', 'vigilante' );
            return Vigilante_SA_Check_Result::info( $args );
        }

        if ( ! $this->module_on ) {
            $args['detail'] = Vigilante_SA_Helpers::module_off_detail( $this->settings, 'security_headers' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $missing = $this->sent_but_missing( $args, array( 'cross-origin-resource-policy' ) );
        if ( $missing ) {
            return $missing;
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
        // The same block that sets the headers removes X-Powered-By: while it
        // is not being applied, that one stays too. Why it is not applied is
        // in the row run() adds for all of them.
        if ( $x_powered && $this->block_not_applied ) {
            $this->cause_needed = true;
            // The sentence above ends in the value of a header, not in a full stop.
            $args['detail'] = rtrim( $args['detail'], " .\t\n" ) . '. ' . __( 'Vigilant is set to remove X-Powered-By.', 'vigilante' );
        }
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

    /**
     * Vigilant blocks found in .htaccess files above this installation
     *
     * @since 2.9.9
     *
     * @return array<string,string[]> Absolute file path => markers found inside.
     */
    private function vigilant_blocks_above() {
        // Asked by the CSP check and by the note for the other headers: the
        // walk up the directories is done once per scan.
        if ( null !== $this->blocks_above ) {
            return $this->blocks_above;
        }

        if ( ! class_exists( 'Vigilante_Htaccess_Manager' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        }

        $this->blocks_above = (array) Vigilante_Htaccess_Manager::get_instance()->find_blocks_above();

        return $this->blocks_above;
    }

}
