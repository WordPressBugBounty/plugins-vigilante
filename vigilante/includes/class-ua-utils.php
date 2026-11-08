<?php
/**
 * User-Agent utilities
 *
 * One place decides what a line of the User-Agent blacklist would block, so the
 * save, the import, the Firewall tab, the Dashboard and the activity log popup
 * cannot tell different stories about the same line.
 *
 * @package Vigilante
 * @since   3.0.11
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_UA_Utils
 */
class Vigilante_UA_Utils {

    /**
     * Verdicts, from the one that weighs most to the one that weighs least.
     *
     * Own, site and browser keep the line out of the list when it is new.
     * Engine is stored with a warning. Ok is stored as it is.
     */
    const VERDICT_OWN     = 'own';
    const VERDICT_SITE    = 'site';
    const VERDICT_BROWSER = 'browser';
    const VERDICT_ENGINE  = 'engine';
    const VERDICT_OK      = 'ok';

    /**
     * The User-Agent of the browsers people use, as they send it.
     *
     * Chrome, Edge and Safari send the same string to everybody on the same
     * version and system (Chrome's User-Agent reduction freezes the system
     * part: macOS always reads 10_15_7, Windows 10.0, Android "10; K"), and
     * bots copy these strings to pass as a visitor. A blacklist line contained
     * in one of them blocks every person who uses that browser: on 7 Nov 2026
     * a line copied from a bot that pretended to be Chrome on Mac locked an
     * administrator out of her own site (B123).
     *
     * The browser versions here go stale; normalize() takes them out of both
     * sides, so a line written for a newer version is still recognised.
     *
     * @return array<int, array{label: string, ua: string}>
     */
    public static function browser_references() {
        return array(
            array(
                'label' => __( 'Chrome on Mac', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Chrome on Windows', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Chrome on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'Chrome on iPhone', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/156.0.0.0 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'Edge on Windows', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0',
            ),
            array(
                'label' => __( 'Safari on Mac', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.1 Safari/605.1.15',
            ),
            array(
                'label' => __( 'Safari on iPhone', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.1 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'Firefox on Windows', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            array(
                'label' => __( 'Firefox on Mac', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            array(
                'label' => __( 'Firefox on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Android 15; Mobile; rv:157.0) Gecko/157.0 Firefox/157.0',
            ),
            // Added after the first blind review of 3.0.11: without them a whole
            // Chrome on Linux User-Agent, or "X11", was stored and blocked
            // everybody on Linux.
            array(
                'label' => __( 'Chrome on Linux', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Firefox on Linux', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            array(
                'label' => __( 'Chrome on ChromeOS', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Opera on Windows', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 OPR/141.0.0.0',
            ),
            array(
                'label' => __( 'Samsung Internet on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 15; SAMSUNG SM-S931B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/29.0 Chrome/156.0.0.0 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'Firefox on iPhone', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/157.0 Mobile/15E148 Safari/605.1.15',
            ),
            array(
                'label' => __( 'Edge on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36 EdgA/156.0.0.0',
            ),
            // Added after the second blind review: the system versions are not
            // taken out (Windows NT 5.1 has to stay apart from 10.0), so the
            // ones still in use are listed as browsers send them.
            array(
                'label' => __( 'Firefox on Ubuntu', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            array(
                'label' => __( 'Firefox on Fedora', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            array(
                'label' => __( 'Safari on iPad', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPad; CPU OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.1 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'Chrome on iPad', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPad; CPU OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/156.0.0.0 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'Safari on an older iPhone', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.7 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'Edge on iPhone', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.1 EdgiOS/156.0.0.0 Mobile/15E148 Safari/605.1.15',
            ),
            array(
                'label' => __( 'Firefox on an Android tablet', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Android 14; Tablet; rv:157.0) Gecko/157.0 Firefox/157.0',
            ),
            array(
                'label' => __( 'Samsung Internet on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/29.0 Chrome/156.0.0.0 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'Android apps that show web pages (WebView)', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 12; Pixel 6 Build/SQ3A.220705.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Mobile Safari/537.36',
            ),
        );
    }

    /**
     * Search engines a line can block by accident. Stored with a warning.
     *
     * @return array<int, array{label: string, ua: string}>
     */
    public static function engine_references() {
        return array(
            array(
                'label' => 'Googlebot',
                'ua'    => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            ),
            array(
                'label' => 'Googlebot',
                'ua'    => 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            ),
            array(
                'label' => 'Bingbot',
                'ua'    => 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            ),
        );
    }

    /**
     * The User-Agent WordPress sends when it calls itself (WP-Cron, the REST
     * API and loopback tests of Site Health), built as WP_Http builds it
     * (wp-includes/class-wp-http.php, the user-agent argument).
     *
     * @return string
     */
    public static function site_user_agent() {
        $default = 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' );
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter, applied as WP_Http applies it so the value matches what the site sends.
        $filtered = apply_filters( 'http_headers_useragent', $default, home_url( '/' ) );

        return is_string( $filtered ) ? $filtered : $default;
    }

    /**
     * The User-Agent of the request being served, as the firewall reads it.
     *
     * Only used to stop administrators from blacklisting their own browser:
     * it is chosen by the caller, who is the administrator saving, and all it
     * can do is keep a line out of the list they are writing.
     *
     * @return string
     */
    public static function current_user_agent() {
        return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
    }

    /**
     * Lower case, with the version numbers people's browsers vary in taken out.
     *
     * The browser's own versions, and the systems that people keep using in
     * many versions: Android together with the device that follows it, iOS
     * and iPadOS, macOS and the processor of Linux. Until the third blind
     * review of 3.0.11 only the first were taken out, and "Android 14",
     * "iPhone OS 17_5" or the whole User-Agent of a Samsung of another model
     * were stored and blocked the people who use them. A device named on its
     * own ("SM-S918B") is still not recognised: nothing lists every phone.
     *
     * Windows stays as it is, on purpose: Windows NT 5.1 (XP) is a usual
     * signature of bots, and somebody may block it.
     *
     * @param string $value A User-Agent or a blacklist line.
     * @return string
     */
    public static function normalize( $value ) {
        $rules = array(
            '#\b(chrome|crios|firefox|fxios|edg|edga|edgios|opr|version|samsungbrowser)/[0-9][0-9.]*#' => '$1/0',
            '#\brv:[0-9][0-9.]*#'                                                                      => 'rv:0',
            '#\bandroid [0-9][0-9.]*(?:; [^;)]*)?#'                                                    => 'android 0; device',
            '#\b(?:iphone )?os [0-9][0-9_.]*#'                                                         => 'os 0',
            '#\bmac os x [0-9][0-9_.]*#'                                                               => 'mac os x 0',
            '#\blinux (?:x86_64|aarch64|arm[a-z0-9]*|i[3-6]86)#'                                       => 'linux arch',
        );

        $value = strtolower( (string) $value );
        foreach ( $rules as $pattern => $replacement ) {
            $value = (string) preg_replace( $pattern, $replacement, $value );
        }

        return $value;
    }

    /**
     * Whether a blacklist line would match a given User-Agent.
     *
     * Compared as written and with the browser versions taken out of both
     * sides: the first catches a fragment of a version number, the second a
     * whole User-Agent copied from a newer browser than the references.
     *
     * @param string $line       Blacklist line, trimmed.
     * @param string $user_agent User-Agent.
     * @return bool
     */
    public static function line_hits( $line, $user_agent ) {
        if ( '' === $line || '' === $user_agent ) {
            return false;
        }

        if ( false !== strpos( strtolower( $user_agent ), strtolower( $line ) ) ) {
            return true;
        }

        // An empty needle would match everything; normalize() only returns ''
        // for a line that was empty, or if PCRE failed, and neither is a hit.
        $normalized = self::normalize( $line );
        if ( '' === $normalized ) {
            return false;
        }

        return false !== strpos( self::normalize( $user_agent ), $normalized );
    }

    /**
     * What a blacklist line would block.
     *
     * @param string $line     Blacklist line.
     * @param string $saver_ua User-Agent of the person saving, '' when there is none.
     * @return array{verdict: string, labels: string[]}
     */
    public static function classify_blacklist_line( $line, $saver_ua = '' ) {
        $line = trim( (string) $line );

        // empty() as the firewall reads the list (first_match()): a line "0"
        // matches nothing there, so it blocks nobody.
        if ( empty( $line ) ) {
            return array( 'verdict' => self::VERDICT_OK, 'labels' => array() );
        }

        if ( '' !== $saver_ua && self::line_hits( $line, (string) $saver_ua ) ) {
            return array( 'verdict' => self::VERDICT_OWN, 'labels' => array() );
        }

        if ( self::line_hits( $line, self::site_user_agent() ) ) {
            return array( 'verdict' => self::VERDICT_SITE, 'labels' => array() );
        }

        $labels = array();
        foreach ( self::browser_references() as $reference ) {
            if ( self::line_hits( $line, $reference['ua'] ) ) {
                $labels[] = $reference['label'];
            }
        }
        if ( ! empty( $labels ) ) {
            return array( 'verdict' => self::VERDICT_BROWSER, 'labels' => array_values( array_unique( $labels ) ) );
        }

        foreach ( self::engine_references() as $reference ) {
            if ( self::line_hits( $line, $reference['ua'] ) ) {
                $labels[] = $reference['label'];
            }
        }
        if ( ! empty( $labels ) ) {
            return array( 'verdict' => self::VERDICT_ENGINE, 'labels' => array_values( array_unique( $labels ) ) );
        }

        return array( 'verdict' => self::VERDICT_OK, 'labels' => array() );
    }

    /**
     * Whether a verdict keeps a new line out of the blacklist.
     *
     * @param string $verdict Verdict.
     * @return bool
     */
    public static function blocks_people( $verdict ) {
        return in_array( $verdict, array( self::VERDICT_OWN, self::VERDICT_SITE, self::VERDICT_BROWSER ), true );
    }

    /**
     * Split a submitted blacklist into what is stored and what is not.
     *
     * A line that was already stored keeps applying unless $drop_stored is
     * true, which only the explicit save of the Firewall tab asks for: the
     * settings sanitize callback runs on every write of the option, and
     * dropping stored lines there would change what a site has saved on the
     * save of any other tab or on an update, without anybody deciding it.
     *
     * @param array  $lines       Submitted lines.
     * @param array  $stored      Lines stored before this write.
     * @param string $saver_ua    User-Agent of the person saving.
     * @param bool   $drop_stored Whether stored lines that block people go too.
     * @return array{kept: string[], rejected: array<int, array{line: string, verdict: string, labels: string[]}>, warned: array<int, array{line: string, verdict: string, labels: string[]}>}
     */
    public static function filter_blacklist( $lines, $stored, $saver_ua, $drop_stored = false ) {
        $stored = array_map( 'trim', array_map( 'strval', (array) $stored ) );
        $result = array(
            'kept'     => array(),
            'rejected' => array(),
            'warned'   => array(),
        );

        foreach ( (array) $lines as $line ) {
            if ( ! is_string( $line ) ) {
                continue;
            }
            $line = trim( $line );
            if ( '' === $line ) {
                continue;
            }

            $verdict = self::classify_blacklist_line( $line, $saver_ua );
            $was_stored = in_array( $line, $stored, true );

            if ( self::blocks_people( $verdict['verdict'] ) && ( ! $was_stored || $drop_stored ) ) {
                $result['rejected'][] = array_merge( array( 'line' => $line ), $verdict );
                continue;
            }

            if ( self::VERDICT_ENGINE === $verdict['verdict'] && ! $was_stored ) {
                $result['warned'][] = array_merge( array( 'line' => $line ), $verdict );
            }

            $result['kept'][] = $line;
        }

        return $result;
    }

    /**
     * Stored lines that block people, for the tab and the Dashboard.
     *
     * The User-Agent of whoever is looking is left out on purpose: what is
     * stored has to read the same for every administrator.
     *
     * @param array $stored Stored blacklist.
     * @return array<int, array{line: string, verdict: string, labels: string[]}>
     */
    public static function stored_lines_blocking_people( $stored ) {
        $found = array();
        foreach ( (array) $stored as $line ) {
            if ( ! is_string( $line ) || '' === trim( $line ) ) {
                continue;
            }
            $verdict = self::classify_blacklist_line( $line, '' );
            if ( self::blocks_people( $verdict['verdict'] ) ) {
                $found[] = array_merge( array( 'line' => trim( $line ) ), $verdict );
            }
        }

        return $found;
    }

    /**
     * The first line of a list contained in a User-Agent, as the firewall reads
     * it: by substring, case-insensitive.
     *
     * @param string $user_agent User-Agent.
     * @param array  $list       List lines.
     * @return string The line, or '' when none matches.
     */
    public static function first_match( $user_agent, $list ) {
        $user_agent = strtolower( (string) $user_agent );
        if ( '' === $user_agent ) {
            return '';
        }

        foreach ( (array) $list as $entry ) {
            if ( ! is_string( $entry ) ) {
                continue;
            }
            $entry = trim( $entry );
            // empty() and not '' on purpose: the firewall has always skipped a
            // line reading "0", and a line that matched every User-Agent with
            // a zero in it would block nearly everybody after an update.
            if ( ! empty( $entry ) && false !== strpos( $user_agent, strtolower( $entry ) ) ) {
                return $entry;
            }
        }

        return '';
    }

    /**
     * A line cut for a notice: whole User-Agents run to 130 characters.
     *
     * @param string $line Line.
     * @return string
     */
    public static function short( $line ) {
        $line = (string) $line;
        $len  = function_exists( 'mb_strlen' ) ? mb_strlen( $line ) : strlen( $line );
        if ( $len <= 60 ) {
            return $line;
        }

        return ( function_exists( 'mb_substr' ) ? mb_substr( $line, 0, 57 ) : substr( $line, 0, 57 ) ) . '…';
    }

    /**
     * The sentence that says why a line is not stored, or what it blocks.
     *
     * Plain text: whoever prints it escapes it.
     *
     * @param array $entry An entry from filter_blacklist() or stored_lines_blocking_people().
     * @return string
     */
    public static function explain( $entry ) {
        $labels = isset( $entry['labels'] ) ? (array) $entry['labels'] : array();

        switch ( isset( $entry['verdict'] ) ? $entry['verdict'] : '' ) {
            case self::VERDICT_OWN:
                return __( 'It is in the User-Agent of your own browser, so it would block you and everyone who uses the same browser.', 'vigilante' );
            case self::VERDICT_SITE:
                return __( 'It is in the requests WordPress sends to itself, so scheduled tasks would stop running and the Site Health tests would fail.', 'vigilante' );
            case self::VERDICT_BROWSER:
                return sprintf(
                    /* translators: %s: comma separated list of browsers, e.g. "Chrome on Mac, Safari on Mac". */
                    __( 'Normal browsers send it too (%s), so it blocks the people who use them. To stop a bot that pretends to be a browser, block its IP.', 'vigilante' ),
                    implode( ', ', $labels )
                );
            case self::VERDICT_ENGINE:
                return sprintf(
                    /* translators: %s: search engine crawlers, e.g. "Googlebot". */
                    __( 'It blocks %s. If you only want to keep it from indexing the site, robots.txt is the better tool.', 'vigilante' ),
                    implode( ', ', $labels )
                );
        }

        return '';
    }
}
