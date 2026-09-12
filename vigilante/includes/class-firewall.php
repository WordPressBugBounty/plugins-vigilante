<?php
/**
 * Firewall Class
 *
 * WordPress-optimized firewall protection
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Firewall
 *
 * Provides firewall protection against common attacks
 */
class Vigilante_Firewall {

    /**
     * Rate limiting window, in seconds.
     *
     * The "Requests per Minute" setting is measured over this window.
     *
     * @var int
     */
    const RATE_LIMIT_WINDOW = 60;

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Activity log instance
     *
     * @var Vigilante_Activity_Log
     */
    private $activity_log;

    /**
     * Firewall options
     *
     * @var array
     */
    private $options;

    /**
     * Current request data
     *
     * @var array
     */
    private $request_data = array();

    /**
     * Memoized haystack the pattern checks run against
     *
     * @since 2.9.9
     *
     * @var string|null
     */
    private $haystack = null;

    /**
     * Constructor
     *
     * @param Vigilante_Settings    $settings     Settings instance.
     * @param Vigilante_Activity_Log $activity_log Activity log instance.
     */
    public function __construct( $settings, $activity_log ) {
        $this->settings     = $settings;
        $this->activity_log = $activity_log;
        $this->options      = $settings->get_section( 'firewall' );

        // Run firewall checks - must be after plugin init (priority 1)
        add_action( 'init', array( $this, 'run_firewall' ), 2 );

        // Rate limiting
        if ( ! empty( $this->options['rate_limiting']['enabled'] ) ) {
            add_action( 'init', array( $this, 'check_rate_limit' ), 2 );
        }
    }

    /**
     * Run all firewall checks
     */
    public function run_firewall() {
        // Skip for whitelisted IPs
        if ( $this->is_ip_whitelisted() ) {
            return;
        }

        /*
         * The User-Agent whitelist no longer skips the firewall.
         *
         * Until 2.11.1 a matching User-Agent returned here, before the IP
         * blacklist and every request check, so anyone who guessed a
         * configured substring ("ManageWP", "MainWP") walked past the SQL
         * injection, script injection, file inclusion, traversal, bot and
         * HTTP method rules by setting a header they control. A header a
         * client chooses cannot stand in for an identity. Reported by the
         * automated security review of wp.org on 9 sep 2026 and fixed in
         * 2.11.2.
         *
         * What the option is actually for is keeping a remote manager from
         * being turned away as a bot, so that is all it does now: it exempts
         * the User-Agent rules, resolved further down, and nothing else. The
         * list is empty by default, so only sites that had configured one were
         * ever exposed.
         */
        $ua_whitelisted = $this->is_ua_whitelisted();

        // Gather request data first: a block is logged with the address it
        // turned away, and until 2.11.1 the blacklist ran before this, so the
        // entry for a blacklisted IP recorded no address at all.
        $this->gather_request_data();

        // Check if IP is blacklisted
        if ( $this->is_ip_blacklisted() ) {
            $this->block_request( 'ip_blacklisted', __( 'IP address is blacklisted', 'vigilante' ) );
        }

        // Check if User-Agent is blacklisted (after gathering request data).
        // An explicitly whitelisted agent still wins over the blacklist, which
        // is what an administrator who wrote it there expects.
        if ( ! $ua_whitelisted && $this->is_ua_blacklisted() ) {
            $this->block_request( 'ua_blacklisted', __( 'User-Agent is blacklisted', 'vigilante' ) );
        }

        // Run security checks
        // NOTE: These are PHP-based checks that complement htaccess rules
        // Some protections exist in both layers for defense in depth
        $checks = array(
            // PHP request filtering (complements htaccess block_bad_query_strings)
            'block_bad_query_strings'   => 'check_query_strings',
            'block_sql_injection'       => 'check_sql_injection',
            'block_xss_attacks'         => 'check_xss_attacks',
            'block_file_inclusion'      => 'check_file_inclusion',
            'block_directory_traversal' => 'check_directory_traversal',
            // Bot protection (complements htaccess block_bad_bots)
            'block_bad_bots'            => 'check_bad_bots',
            'block_empty_user_agent'    => 'check_empty_user_agent',
        );

        // The rules a whitelisted User-Agent is exempt from, and only these.
        $ua_rules = array( 'block_bad_bots', 'block_empty_user_agent' );

        foreach ( $checks as $option => $method ) {
            if ( $ua_whitelisted && in_array( $option, $ua_rules, true ) ) {
                continue;
            }

            if ( ! empty( $this->options[ $option ] ) && method_exists( $this, $method ) ) {
                $result = $this->$method();
                if ( is_string( $result ) ) {
                    $this->block_request( $option, $result );
                }
            }
        }

        // Check HTTP method if limit_http_methods is enabled
        if ( ! empty( $this->options['limit_http_methods'] ) ) {
            $this->check_http_method();
        }
    }

    /**
     * Gather current request data
     */
    private function gather_request_data() {
        $this->haystack = null;

        $this->request_data = array(
            'uri'         => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
            'query_string'=> isset( $_SERVER['QUERY_STRING'] ) ? sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '',
            /*
             * Copies that keep the percent encoding, used only as the haystack
             * of the pattern checks and never logged, printed or stored.
             *
             * They exist because sanitize_text_field() deletes every %XX
             * sequence instead of decoding it: the copies above are the payload
             * with the evidence removed, so an encoded attack was invisible to
             * every rule that reads them. Measured on 22 aug 2026 against 2.9.8,
             * ?x=%3Cscript%3E, javascript%3A, php%3A%2F%2F and GLOBALS%5B all
             * reached the checks as harmless text and went straight through.
             *
             * No sanitizer is applied, and that is the point: every one of them
             * destroys exactly what has to be matched. sanitize_text_field()
             * deletes the %XX sequences and strips tags. esc_url_raw() is worse
             * here: measured on 22 aug 2026, it returns an empty string for a
             * query that carries an unencoded :// , which is precisely the
             * remote inclusion shape, so it would blind the firewall instead of
             * arming it. These two values are never echoed, never stored and
             * never reach a query; they are the haystack of preg_match() and
             * nothing else.
             */
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- inspection buffer for the pattern checks, see the note above. Sanitizing it is what hid the attacks. Never output, stored nor queried.
            'uri_raw'     => isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '',
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- same as uri_raw.
            'query_raw'   => isset( $_SERVER['QUERY_STRING'] ) ? wp_unslash( $_SERVER['QUERY_STRING'] ) : '',
            'user_agent'  => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
            'referer'     => isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '',
            'method'      => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET',
            'ip'          => $this->get_client_ip(),
        );
    }

    /**
     * What the pattern checks run against: the request as it arrived, plus its decoded form
     *
     * Both forms on purpose. Some patterns look for the encoded shape, such as
     * the null byte %00 or the %5b of GLOBALS[, and others for the decoded one,
     * such as <script or ../. Feeding only one of the two leaves half the rules
     * looking at something that cannot match.
     *
     * Decoded once, not twice: a second pass catches a bit more evasion and
     * brings in false positives that are not worth it.
     *
     * @since 2.9.9
     *
     * @return string
     */
    private function inspection_haystack() {
        if ( null !== $this->haystack ) {
            return $this->haystack;
        }

        $raw     = trim( (string) $this->request_data['uri_raw'] . ' ' . (string) $this->request_data['query_raw'] );
        $decoded = rawurldecode( $raw );

        $this->haystack = ( $raw === $decoded ) ? $raw : $raw . ' ' . $decoded;

        return $this->haystack;
    }

    /**
     * Check for malicious query strings
     *
     * @return string|false Error message or false if safe.
     */
    private function check_query_strings() {
        $query = $this->request_data['query_raw'];

        if ( empty( $query ) ) {
            return false;
        }

        // Length is measured on the query alone, the rest of the patterns run
        // against the whole request in both its raw and decoded forms.
        $haystack = $this->inspection_haystack();

        // Dangerous patterns
        $patterns = array(
            // Too long query strings
            '/^.{4000,}$/s' => __( 'Query string too long', 'vigilante' ),
            
            // Null bytes
            '/(\x00|%00)/i' => __( 'Null byte detected', 'vigilante' ),
            
            // PHP wrappers
            '/php:\/\//i' => __( 'PHP wrapper detected', 'vigilante' ),
            '/data:\/\//i' => __( 'Data wrapper detected', 'vigilante' ),
            
            // Globals/Request manipulation
            '/(globals|mosconfig)(\[|\%5b)/i' => __( 'Global manipulation attempt', 'vigilante' ),
            '/_request(\[|\%5b)/i' => __( 'Request manipulation attempt', 'vigilante' ),
            
            // Config file access
            '/wp-config\.php/i' => __( 'Config file access attempt', 'vigilante' ),
            
            // Common attack patterns
            '/(\<|%3c).*script.*(\>|%3e)/i' => __( 'Script tag detected', 'vigilante' ),
            '/document\.(cookie|location|write)/i' => __( 'DOM manipulation attempt', 'vigilante' ),
        );

        foreach ( $patterns as $pattern => $message ) {
            // The length rule is anchored, so it has to see the query on its
            // own; every other pattern gets the whole request.
            $subject = ( '/^.{4000,}$/s' === $pattern ) ? $query : $haystack;

            if ( preg_match( $pattern, $subject ) ) {
                return $message;
            }
        }

        return false;
    }

    /**
     * Check for SQL injection attempts
     *
     * @return string|false Error message or false if safe.
     */
    private function check_sql_injection() {
        // Skip SQL injection checks for authenticated admin users on admin pages
        // WordPress handles sanitization for these requests
        if ( is_admin() && is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
            return false;
        }

        $to_check = array(
            $this->inspection_haystack(),
        );

        // Check POST data, but exclude content fields that may contain legitimate code/text
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( ! empty( $_POST ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $post_data = $_POST;
            
            // Remove fields that commonly contain user content (posts, comments, etc.)
            // These are sanitized by WordPress core
            $excluded_fields = array(
                'content',
                'post_content',
                'comment',
                'description',
                'excerpt',
                'post_excerpt',
                'message',
                'bio',
                'acf',           // Advanced Custom Fields
                'meta',          // Post meta
                'tax_input',     // Taxonomy input
                '_content',      // Various content fields
            );

            foreach ( $excluded_fields as $field ) {
                unset( $post_data[ $field ] );
            }

            // Only check remaining POST data if not empty
            if ( ! empty( $post_data ) ) {
                $to_check[] = wp_json_encode( $post_data );
            }
        }

        $combined = implode( ' ', array_filter( $to_check ) );

        if ( empty( $combined ) ) {
            return false;
        }

        // SQL injection patterns - focused on actual attack vectors
        $patterns = array(
            // Union based injection - high confidence attack pattern
            '/union\s+(all\s+)?select/i' => __( 'UNION SELECT detected', 'vigilante' ),
            
            // SQL commands in URL/query string context (not in POST body)
            // More specific pattern to reduce false positives
            '/[\'\"]\s*(;|--|#)\s*(select|insert|update|delete|drop|truncate|alter|create)/i' => __( 'SQL command injection attempt', 'vigilante' ),
            
            // Hex encoding of SQL - typically used in attacks
            '/0x[0-9a-f]{16,}/i' => __( 'Hex encoding detected', 'vigilante' ),
            
            // Benchmark/sleep attacks - time-based SQL injection
            '/(benchmark|sleep)\s*\(\s*\d/i' => __( 'Time-based injection attempt', 'vigilante' ),
            
            // Information schema access
            '/information_schema\.(tables|columns|schemata)/i' => __( 'Schema access attempt', 'vigilante' ),
            
            // Load file - file read attempt
            '/load_file\s*\(/i' => __( 'Load file attempt', 'vigilante' ),
            
            // Into outfile - file write attempt
            '/into\s+(out|dump)file/i' => __( 'File write attempt', 'vigilante' ),
            
            // Stacked queries with dangerous commands
            '/;\s*(drop|truncate|delete\s+from|update\s+\w+\s+set)/i' => __( 'Stacked query injection', 'vigilante' ),
        );

        foreach ( $patterns as $pattern => $message ) {
            if ( preg_match( $pattern, $combined ) ) {
                return $message;
            }
        }

        return false;
    }

    /**
     * Check for XSS attacks
     *
     * @return string|false Error message or false if safe.
     */
    private function check_xss_attacks() {
        $combined = $this->inspection_haystack();

        if ( empty( $combined ) ) {
            return false;
        }

        // Already carries the decoded form, see inspection_haystack().
        $decoded = $combined;

        // XSS patterns
        $patterns = array(
            // Script tags
            '/<script[^>]*>/i' => __( 'Script tag detected', 'vigilante' ),
            
            /*
             * Event handlers. Two shapes, because the rule used to be a bare
             * \bon\w+\s*= and that matches any parameter whose name starts
             * with "on": only=, once=, online= and onboarding= were all
             * answered with a 403 on every site with the firewall on, and the
             * owner never saw it because it only hits visitors.
             */
            '/<[^>]*\bon\w+\s*=/i' => __( 'Event handler detected', 'vigilante' ),
            '/\bon(abort|blur|change|click|contextmenu|copy|cut|dblclick|drag\w*|drop|error|focus\w*|input|invalid|key\w+|load\w*|mouse\w+|paste|pointer\w+|reset|resize|scroll|select|submit|toggle|touch\w+|transitionend|animation\w+|wheel)\s*=\s*["\']?\s*[\w.$]+\s*\(/i' => __( 'Event handler detected', 'vigilante' ),
            
            // JavaScript protocol
            '/javascript\s*:/i' => __( 'JavaScript protocol detected', 'vigilante' ),
            
            // VBScript
            '/vbscript\s*:/i' => __( 'VBScript detected', 'vigilante' ),
            
            // Data URL
            '/data\s*:[^,]*base64/i' => __( 'Base64 data URL detected', 'vigilante' ),
            
            // Expression (IE)
            '/expression\s*\(/i' => __( 'CSS expression detected', 'vigilante' ),
            
            // Iframe injection
            '/<iframe[^>]*>/i' => __( 'Iframe injection detected', 'vigilante' ),
            
            // Object/embed
            '/<(object|embed|applet)[^>]*>/i' => __( 'Object tag detected', 'vigilante' ),
        );

        foreach ( $patterns as $pattern => $message ) {
            if ( preg_match( $pattern, $decoded ) ) {
                return $message;
            }
        }

        return false;
    }

    /**
     * Check for file inclusion attacks
     *
     * @return string|false Error message or false if safe.
     */
    private function check_file_inclusion() {
        $combined = $this->inspection_haystack();

        if ( empty( $combined ) ) {
            return false;
        }

        // Remote inclusion is decided on the parsed values, not on the raw
        // string. Until 2.9.9 any '=' followed by an absolute URL tripped this
        // rule, and legitimate links carry those all the time: a redirect_to
        // back to the site itself, a return_url, a payment gateway callback.
        // What makes it an inclusion attempt is the target being somewhere
        // else, so a URL pointing at this very site is left alone.
        //
        // The core endpoint that resolves an embed takes an external URL as
        // its whole job, so it is exempted rather than made to look innocent.
        // Only this check is skipped: the PHP wrappers and the system paths
        // below still run on that route, for everyone.
        if ( ! $this->is_core_embed_proxy_request() && $this->has_remote_inclusion() ) {
            return __( 'Remote file inclusion attempt', 'vigilante' );
        }

        // File inclusion patterns
        $patterns = array(
            // PHP wrappers
            '/(php|zip|glob|phar|ssh2|rar|ogg|expect):\/\//i' => __( 'PHP wrapper detected', 'vigilante' ),
            
            // System files
            '/\/etc\/(passwd|shadow|hosts)/i' => __( 'System file access attempt', 'vigilante' ),
            '/\/proc\/self/i' => __( 'Proc access attempt', 'vigilante' ),
            
            // Windows paths
            '/[a-z]:\\\\(windows|winnt)/i' => __( 'Windows path detected', 'vigilante' ),
        );

        foreach ( $patterns as $pattern => $message ) {
            if ( preg_match( $pattern, $combined ) ) {
                return $message;
            }
        }

        return false;
    }

    /**
     * Parameter names a remote inclusion payload travels in
     *
     * An inclusion needs its value to reach an include() or a require(), so it
     * arrives in the parameter a vulnerable script treats as a path. These are
     * the names those scripts use, and the ones every RFI scanner probes.
     *
     * Deliberately absent: url, redirect, redirect_to, return, return_url,
     * callback and the rest of the link-carrying names. Carrying a URL is what
     * those are for. Matching them is what turned WordPress core's own oembed
     * proxy into a 403 for anyone using the block editor, reported on 9 sep
     * 2026 and fixed in 2.11.1.
     *
     * @since 2.11.1
     *
     * @var string[]
     */
    private static $inclusion_param_names = array(
        // The value is read as a file
        'file', 'files', 'filename', 'file_name', 'filepath', 'file_path',
        'archivo', 'arquivo', 'fichier', 'datei',
        // ...or as the place to read it from
        'path', 'paths', 'dir', 'directory', 'folder', 'root', 'base',
        'basepath', 'base_path', 'abs_path', 'absolute_path',
        'mosconfig_absolute_path',
        // ...or as the page a front controller includes
        'page', 'pag', 'pagina', 'pageweb', 'pg', 'seite',
        'include', 'includes', 'inc', 'incl', 'require', 'load', 'loadfile',
        'open', 'read', 'readfile', 'show', 'display', 'view', 'content',
        // ...or as a template, which is a file by another name
        'template', 'templates', 'tpl', 'tmpl', 'theme', 'skin', 'style',
        'layout', 'doc', 'document', 'module', 'mod', 'plugin', 'controller',
        'class', 'func', 'function', 'lang', 'language',
        // ...or as configuration, or straight into a shell
        'conf', 'config', 'cfg', 'src', 'source', 'download',
        'cmd', 'exec', 'shell', 'system',
    );

    /**
     * Extensions a remote inclusion payload is served with
     *
     * The point of the target is that it carries code, or text the vulnerable
     * script will treat as code. Media extensions are not here on purpose: an
     * embedded .mp4 or .jpg from a CDN is what the editor sends all day.
     *
     * @since 2.11.1
     *
     * @var string[]
     */
    private static $inclusion_extensions = array(
        'php', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8',
        'phps', 'phtml', 'pht', 'phar', 'inc', 'txt', 'log', 'ini', 'cfg',
        'conf', 'asp', 'aspx', 'jsp', 'jspx', 'cgi', 'pl', 'py', 'rb', 'sh',
        'bash', 'exe', 'dll', 'so', 'bak', 'old', 'env',
    );

    /**
     * Whether the request carries a remote file inclusion attempt
     *
     * Works on the parsed parameters rather than on a pattern match over the
     * whole string, for two reasons: a link back to the site itself is not
     * mistaken for an attack, and an encoded payload is seen for what it is.
     * The copy of the query string kept for logging goes through
     * sanitize_text_field(), which strips every %XX sequence instead of
     * decoding it, so the encoded form never looked like a URL there.
     *
     * Until 2.11.0 an external URL in any parameter was the whole signature,
     * and that is not what an inclusion looks like, it is what a link looks
     * like. WordPress core's own /wp-json/oembed/1.0/proxy?url=... is the
     * clearest case: the block editor asks the site to resolve a YouTube URL,
     * the rule read it as RFI, and embedding was dead on every site with the
     * rule on while the classic editor kept working, because it posts the same
     * URL to admin-ajax instead of putting it in a query string. Since 2.11.1
     * an external URL is an inclusion attempt when it travels in a parameter
     * that is read as a path, or when it points at something includable.
     *
     * @since 2.9.9
     *
     * @return bool
     */
    private function has_remote_inclusion() {
        $query = $this->request_data['query_raw'];

        if ( '' === $query ) {
            return false;
        }

        // parse_str() decodes as it splits, so this sees the same values PHP
        // would have put in $_GET, without reading the superglobal.
        $params = array();
        parse_str( $query, $params );

        $home_host = $this->normalize_host( wp_parse_url( home_url(), PHP_URL_HOST ) );

        foreach ( $this->flatten_query_params( $params ) as $pair ) {
            list( $names, $value ) = $pair;

            if ( ! preg_match_all( '/(?:https?|ftp):\/\/[^\s\'"<>]+/i', $value, $matches ) ) {
                continue;
            }

            foreach ( $matches[0] as $url ) {
                $host = $this->normalize_host( wp_parse_url( $url, PHP_URL_HOST ) );

                // A URL pointing at this very site is not an inclusion.
                if ( '' !== $host && $host === $home_host ) {
                    continue;
                }

                if ( $this->looks_like_inclusion( $names, $url ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Query parameters as (name segments, value) pairs
     *
     * Keeps every segment of a nested name, so opts[file]=http://... is seen
     * as the inclusion parameter it is and not as an anonymous value.
     *
     * @since 2.11.1
     *
     * @param array    $params   Parsed parameters.
     * @param string[] $inherited Name segments of the parent levels.
     * @return array List of array( string[] $names, string $value ).
     */
    private function flatten_query_params( $params, $inherited = array() ) {
        $pairs = array();

        foreach ( $params as $key => $value ) {
            $names = array_merge( $inherited, array( strtolower( (string) $key ) ) );

            if ( is_array( $value ) ) {
                $pairs = array_merge( $pairs, $this->flatten_query_params( $value, $names ) );
                continue;
            }

            if ( is_scalar( $value ) ) {
                $pairs[] = array( $names, (string) $value );
            }
        }

        return $pairs;
    }

    /**
     * Whether an external URL in this parameter is an inclusion attempt
     *
     * Two independent signals, either is enough: the parameter is one a
     * vulnerable script reads as a path, or the target is something that gets
     * included rather than linked. The trailing '?' and the null byte are the
     * two ways a payload truncates whatever the script appends to it.
     *
     * What this deliberately no longer catches, so nobody reads its silence as
     * coverage: an external URL with no includable extension travelling in a
     * parameter whose name is not on the list. That shape is a link, which is
     * why the site's own search box and every return_url tripped the rule
     * before. A payload in it still has to reach an include() in some other
     * plugin's code to do anything, and the wrappers, the system paths and the
     * traversal rules below are untouched.
     *
     * @since 2.11.1
     *
     * @param string[] $names Name segments of the parameter.
     * @param string   $url   The external URL found in its value.
     * @return bool
     */
    private function looks_like_inclusion( $names, $url ) {
        foreach ( $names as $name ) {
            if ( in_array( $name, self::$inclusion_param_names, true ) ) {
                return true;
            }
        }

        // ftp:// is never how a page links to something; it is how a payload
        // is fetched.
        if ( 0 === stripos( $url, 'ftp://' ) ) {
            return true;
        }

        // Truncation of the suffix the vulnerable script appends.
        if ( '?' === substr( $url, -1 ) || false !== stripos( $url, '%00' ) || false !== strpos( $url, "\0" ) ) {
            return true;
        }

        $path = (string) wp_parse_url( $url, PHP_URL_PATH );

        if ( '' === $path ) {
            return false;
        }

        $extension = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );

        return ( '' !== $extension && in_array( $extension, self::$inclusion_extensions, true ) );
    }

    /**
     * The REST route of the current request, or '' when it is not a REST call
     *
     * Read from the request itself because REST_REQUEST is not defined yet:
     * the firewall runs on init, and rest_api_loaded() defines it later, on
     * parse_request. Both shapes are covered, the pretty /wp-json/<route> and
     * the plain ?rest_route=<route>, and the prefix is asked for rather than
     * assumed, since rest_url_prefix filters it.
     *
     * @since 2.11.1
     *
     * @return string Route with a leading slash, or '' when there is none.
     */
    private function current_rest_route() {
        $params = array();
        parse_str( (string) ( $this->request_data['query_raw'] ?? '' ), $params );

        if ( isset( $params['rest_route'] ) && is_string( $params['rest_route'] ) ) {
            return '/' . ltrim( $params['rest_route'], '/' );
        }

        $uri    = (string) ( $this->request_data['uri_raw'] ?? '' );
        $path   = (string) wp_parse_url( $uri, PHP_URL_PATH );
        $needle = '/' . trim( rest_get_url_prefix(), '/' ) . '/';
        $at     = strpos( $path, $needle );

        if ( false === $at ) {
            return '';
        }

        return '/' . ltrim( substr( $path, $at + strlen( $needle ) ), '/' );
    }

    /**
     * Whether this is a logged-in editor asking core to resolve an embed
     *
     * /wp-json/oembed/1.0/proxy is where the block editor sends the URL the
     * author pasted, so an external URL there is the request, not an attack.
     * The exemption is not the route on its own: it asks for the capability
     * that route's own permission_callback asks for, so an anonymous scanner
     * probing it is still blocked and still logged. The other core embed
     * route, /oembed/1.0/embed, only ever answers for this site's own URLs,
     * which the check already leaves alone.
     *
     * @since 2.11.1
     *
     * @return bool
     */
    private function is_core_embed_proxy_request() {
        if ( 0 !== strpos( $this->current_rest_route(), '/oembed/1.0/proxy' ) ) {
            return false;
        }

        return ( is_user_logged_in() && current_user_can( 'edit_posts' ) );
    }

    /**
     * Host in a comparable form: lowercase and without a leading www.
     *
     * @since 2.9.9
     *
     * @param string|null $host Host to normalize.
     * @return string
     */
    private function normalize_host( $host ) {
        $host = strtolower( trim( (string) $host ) );

        return ( 0 === strpos( $host, 'www.' ) ) ? substr( $host, 4 ) : $host;
    }

    /**
     * Check for directory traversal attacks
     *
     * @return string|false Error message or false if safe.
     */
    private function check_directory_traversal() {
        $combined = $this->inspection_haystack();

        if ( empty( $combined ) ) {
            return false;
        }

        // Directory traversal patterns
        $patterns = array(
            '/\.\.\//i' => __( 'Directory traversal detected', 'vigilante' ),
            '/\.\.%2f/i' => __( 'Encoded traversal detected', 'vigilante' ),
            '/%2e%2e\//i' => __( 'Double encoded traversal', 'vigilante' ),
            '/\.\.%5c/i' => __( 'Backslash traversal detected', 'vigilante' ),
        );

        foreach ( $patterns as $pattern => $message ) {
            if ( preg_match( $pattern, $combined ) ) {
                return $message;
            }
        }

        return false;
    }

    /**
     * Check for PHP execution in uploads
     *
     * @return string|false Error message or false if safe.
     */
    private function check_php_in_uploads() {
        $uri = $this->inspection_haystack();

        // Check if accessing PHP in uploads directory
        if ( preg_match( '/\/wp-content\/uploads\/.*\.ph(p[345s]?|tml)/i', $uri ) ) {
            return __( 'PHP execution in uploads blocked', 'vigilante' );
        }

        return false;
    }

    /**
     * Check for bad bots
     *
     * @return string|false Error message or false if safe.
     */
    private function check_bad_bots() {
        $user_agent = strtolower( $this->request_data['user_agent'] );

        if ( empty( $user_agent ) ) {
            return false;
        }

        // Known malicious bots and scanners
        // NOTE: Matching is done via strpos() on the full User-Agent string,
        // so entries must be specific enough to avoid false positives with
        // legitimate services, plugins, or WordPress loopback requests.
        // Generic short words (e.g. 'scan', 'ninja', 'titan') must stay out
        // of BOTH this list and the htaccess one: the htaccess regex matches
        // bare substrings too, and unlike this layer it runs before PHP, so
        // the ua_whitelist cannot rescue a false positive there.
        $bad_bots = array(
            'ahrefsbot',
            'semrushbot',
            'dotbot',
            'mj12bot',
            'blexbot',
            'linkdexbot',
            'aspiegelbot',
            'alexibot',
            'backlink',
            'bandit',
            'batchftp',
            'bigfoot',
            'blackwidow',
            'blowfish',
            'botalot',
            'builtbottough',
            'bullseye',
            'cheesebot',
            'cherrypicker',
            'chinaclaw',
            'copyrightcheck',
            'crescent',
            'curl/',
            'dittospyder',
            'dragonfly',
            'easydl',
            'ebingbong',
            'ecatch',
            'eirgrabber',
            'emailcollector',
            'emailsiphon',
            'emailwolf',
            'erocrawler',
            'exabot',
            'expressweb',
            'eyenetie',
            'flashget',
            'flunky',
            'frontpage',
            'getright',
            'getweb',
            'go-ahead-got-it',
            'gotit',
            'grabnet',
            'grafula',
            'harvest',
            'hloader',
            'hmview',
            'httplib',
            'httrack',
            'humanlinks',
            'ia_archiver',
            'imagestripper',
            'imagesucker',
            'indy library',
            'infonavirobot',
            'infotekies',
            'intelliseek',
            'interget',
            'intraformant',
            'jakarta',
            'jennybot',
            'jetcar',
            'kenjin',
            'larbin',
            'leechftp',
            'lexibot',
            'libweb',
            'likse',
            'linkscan',
            'linkwalker',
            'lnspiderguy',
            'lwp',
            'magnet',
            'mag-net',
            'markwatch',
            'mass downloader',
            'masscan',
            'microsoft.url',
            'midown',
            'miixpc',
            'missigua',
            'moget',
            'nameprotect',
            'navroad',
            'nearsite',
            'net vampire',
            'netants',
            'netcraft',
            'netmechanic',
            'netspider',
            'nextgensearchbot',
            'nibbler',
            'nicerspro',
            'niki-bot',
            'npbot',
            'offline explorer',
            'offline navigator',
            'openfind',
            'outfoxbot',
            'pagegrabber',
            'pavuk',
            'pcbrowser',
            'php/',
            'pockey',
            'prowebwalker',
            'psycheclone',
            'python-urllib',
            'python-requests',
            'python/',
            'queryn',
            'reget',
            'repomonkey',
            'siphon',
            'siteexplorer',
            'sitesnagger',
            'slurp',
            'smartdownload',
            'snapbot',
            'snoopy',
            'sogou',
            'spacebison',
            'spankbot',
            'sqworm',
            'superbot',
            'superhttp',
            'surfbot',
            'suzuran',
            'szukacz',
            'takeout',
            'teleport',
            'telesoft',
            'thenomad',
            'tighttwatbot',
            'true_robot',
            'turingos',
            'turnitinbot',
            'voideye',
            'webalta',
            'webbandit',
            'webcollector',
            'webcopier',
            'webdup',
            'webenhancer',
            'webfetch',
            'webgo',
            'webmasterworldforumbot',
            'webpictures',
            'webreaper',
            'websauger',
            'webspider',
            'webstripper',
            'websucker',
            'webwhacker',
            'webzip',
            'widow',
            'wisenut',
            'wwwoffle',
            'xaldon',
            'xxxyy',
            'zeus',
            'zermelo',
            'zyborg',
        );

        foreach ( $bad_bots as $bot ) {
            if ( strpos( $user_agent, $bot ) !== false ) {
                return sprintf(
                    /* translators: %s: Bot name */
                    __( 'Bad bot blocked: %s', 'vigilante' ),
                    $bot
                );
            }
        }

        return false;
    }

    /**
     * Check for empty user agent
     *
     * @return string|false Error message or false if safe.
     */
    private function check_empty_user_agent() {
        if ( empty( $this->request_data['user_agent'] ) ) {
            return __( 'Empty user agent blocked', 'vigilante' );
        }
        return false;
    }

    /**
     * Whether the request is addressed to the REST API itself
     *
     * The method filter lets the REST API through, and until 2.11.8 it asked
     * whether "/wp-json/" appeared anywhere in the address, query string
     * included: TRACE /?x=/wp-json/ skipped the filter and reached a page that
     * is not the REST API at all. Found by the audit of the firewall for
     * 2.11.8. Core routes the pretty REST URLs from the start of the home
     * path, directly or through index.php, so the path has to start there.
     * The ?rest_route= form never matched the old test and still does not:
     * widening the exemption was not the point.
     *
     * @since 2.11.8
     *
     * @return bool
     */
    private function is_rest_api_request() {
        /*
         * The path is cut by hand, not with wp_parse_url(): with two leading
         * slashes that reads "//wp-json/..." as a host, and WordPress still routes
         * it to the REST API. And both the home path and the root are accepted,
         * for the language folders some multilingual plugins add to home_url().
         * Both from the cross review of 2.11.8.
         */
        $path   = preg_replace( '#/{2,}#', '/', (string) preg_replace( '/[?#].*$/s', '', (string) ( $this->request_data['uri_raw'] ?? '' ) ) );
        $home   = trailingslashit( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) );
        $prefix = trim( rest_get_url_prefix(), '/' );

        foreach ( array_unique( array( $home, '/' ) ) as $root ) {
            foreach ( array( $root . $prefix, $root . 'index.php/' . $prefix ) as $base ) {
                if ( $path === $base || 0 === strpos( (string) $path, $base . '/' ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check HTTP method
     *
     * Logged-in users with edit capabilities are excluded to ensure
     * Gutenberg, REST API, and page builders work correctly.
     */
    private function check_http_method() {
        // Skip for authenticated users who can edit content
        // They need OPTIONS, PUT, PATCH, DELETE for Gutenberg, REST API, and page builders
        if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
            return;
        }

        // Skip for WordPress REST API requests
        // The REST API uses PUT, DELETE, PATCH for legitimate operations and has its own
        // authentication and authorization layer — no need to filter methods here
        if ( $this->is_rest_api_request() ) {
            return;
        }

        $method = strtoupper( $this->request_data['method'] );
        $allowed_methods = isset( $this->options['allowed_http_methods'] ) 
            ? $this->options['allowed_http_methods'] 
            : array( 'GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE' );
        $allowed = array_map( 'strtoupper', $allowed_methods );

        if ( ! in_array( $method, $allowed, true ) ) {
            $this->block_request(
                'http_method',
                sprintf(
                    /* translators: %s: HTTP method */
                    __( 'HTTP method %s not allowed', 'vigilante' ),
                    $method
                )
            );
        }
    }

    /**
     * Upper bound of the vigilante_firewall_blocks index
     *
     * The index only feeds the admin screen; enforcement reads a transient per
     * IP. Under a distributed attack the oldest entries are dropped first, so
     * the option cannot grow without limit (S6).
     *
     * @since 2.11.0
     */
    const MAX_TRACKED_BLOCKS = 500;

    /**
     * Add a block to the bounded admin index
     *
     * Prunes expired entries on every write, not only when an administrator
     * opens the Firewall tab, and keeps at most MAX_TRACKED_BLOCKS entries,
     * dropping the oldest by blocked_at.
     *
     * @since 2.11.0
     *
     * @param string $ip    Blocked address.
     * @param array  $block Block data (expires, blocked_at, duration, reason, strikes).
     */
    private static function index_block( $ip, $block ) {
        $blocks = get_option( 'vigilante_firewall_blocks', array() );
        $now    = time();

        if ( ! is_array( $blocks ) ) {
            $blocks = array();
        }

        foreach ( $blocks as $blocked_ip => $data ) {
            if ( ! is_array( $data ) || ! isset( $data['expires'] ) || $now >= (int) $data['expires'] ) {
                unset( $blocks[ $blocked_ip ] );
            }
        }

        $blocks[ $ip ] = $block;

        if ( count( $blocks ) > self::MAX_TRACKED_BLOCKS ) {
            uasort(
                $blocks,
                static function ( $a, $b ) {
                    return (int) ( $a['blocked_at'] ?? 0 ) <=> (int) ( $b['blocked_at'] ?? 0 );
                }
            );
            $blocks = array_slice( $blocks, count( $blocks ) - self::MAX_TRACKED_BLOCKS, null, true );
        }

        update_option( 'vigilante_firewall_blocks', $blocks, false );
    }

    /**
     * Check rate limiting
     */
    public function check_rate_limit() {
        // Skip rate limiting for whitelisted IPs
        if ( $this->is_ip_whitelisted() ) {
            return;
        }

        // Skip rate limiting for logged-in administrators
        if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
            return;
        }

        // Allow other code to opt out. Under Attack mode used this until 2.11.8
        // to exempt visitors who had passed the JS challenge, which exempted a
        // bot that solved it once, too; it now raises their limit instead,
        // through vigilante_rate_limit_requests below.
        if ( apply_filters( 'vigilante_skip_rate_limit', false ) ) {
            return;
        }

        $ip         = $this->get_client_ip();
        $rate_limit = $this->options['rate_limiting'];

        /*
         * What the count and the block are kept under: the address, unless a
         * filter narrows it. Under Attack mode gives visitors who passed its
         * challenge a count of their own, because counting them with everybody
         * else at their address let one unverified client behind the same NAT
         * lock them out for fifteen minutes with its own block. Found by the
         * cross review of 2.11.8, the same shape as the challenge nonce the
         * automated review reported on 2.11.7.
         */
        $key  = (string) apply_filters( 'vigilante_rate_limit_key', $ip );
        $key  = '' !== $key ? $key : $ip;
        $hash = md5( $key );

        // Check if already blocked (fast path). The active block lives in a
        // transient keyed by IP, so this path, which runs on every
        // unauthenticated request, reads one row and not the whole index of
        // blocked addresses. Until 2.11.0 it loaded vigilante_firewall_blocks
        // entire, an array with no upper bound that a distributed attack grew
        // by one entry per new address, so the firewall amplified the attack it
        // was blocking (S6). The transient expires with the block itself.
        $block = get_transient( 'vigilante_rate_block_' . $hash );
        if ( is_array( $block ) && isset( $block['expires'] ) && time() < (int) $block['expires'] ) {
            if ( ! headers_sent() ) {
                status_header( 429 );
                nocache_headers();
            }
            wp_die(
                esc_html__( 'Rate limit exceeded. Please try again later.', 'vigilante' ),
                esc_html__( 'Too Many Requests', 'vigilante' ),
                array( 'response' => 429 )
            );
        }

        $max_requests = absint( $rate_limit['requests_per_minute'] );

        // Allow Under Attack mode (or other filters) to override threshold
        $max_requests = absint( apply_filters( 'vigilante_rate_limit_requests', $max_requests ) );

        // Fixed window, anchored to the timestamp of its first request.
        //
        // The count used to live in a transient whose TTL was renewed on every
        // hit, which is a window that never closes: any IP going less than 60 s
        // between requests kept accumulating, so the effective limit was not
        // "requests per minute" but "requests since the last full minute of
        // silence". A logged-in editor publishing several posts in a row could
        // pile up 150+ requests while never exceeding 60 in any single minute,
        // and got a 429. Storing the window start makes the reset explicit
        // instead of relying on the transient expiring.
        $transient_key = 'vigilante_rate_' . $hash;
        $window        = get_transient( $transient_key );
        $now           = time();

        // Counts stored before 2.9.5 were a bare integer with no window start.
        // There is no way to tell how old such a count is, so open a new window.
        if ( ! is_array( $window ) || ! isset( $window['start'], $window['count'] ) ) {
            $window = array(
                'start' => $now,
                'count' => 0,
            );
        }

        // Window elapsed: start counting again, even under continuous traffic.
        if ( ( $now - absint( $window['start'] ) ) >= self::RATE_LIMIT_WINDOW ) {
            $window = array(
                'start' => $now,
                'count' => 0,
            );
        }

        // Count this request, then allow up to $max_requests per window.
        $window['count'] = absint( $window['count'] ) + 1;
        $request_count   = $window['count'];

        if ( $request_count > $max_requests ) {
            $base_duration = absint( $rate_limit['block_duration'] );

            // Allow Under Attack mode (or other filters) to override duration
            $base_duration = absint( apply_filters( 'vigilante_rate_limit_duration', $base_duration ) );

            $duration      = $base_duration;
            $strikes       = 1;

            // Progressive blocking: double duration on each repeat offense
            if ( ! empty( $rate_limit['progressive'] ) ) {
                $strikes_key = 'vigilante_strikes_' . $hash;
                $strikes     = absint( get_transient( $strikes_key ) ) + 1;

                $max_duration = absint( $rate_limit['max_block_duration'] ?? 86400 );
                $duration     = min(
                    $base_duration * pow( 2, $strikes - 1 ),
                    $max_duration
                );

                // Persist strikes for 24h so they accumulate across blocks
                set_transient( $strikes_key, $strikes, 86400 );
            }

            $block = array(
                'expires'    => time() + $duration,
                'blocked_at' => time(),
                'duration'   => $duration,
                'reason'     => 'rate_limit',
                'strikes'    => $strikes,
                'key'        => $key,
            );

            // The block itself, read by the fast path above on every request.
            set_transient( 'vigilante_rate_block_' . $hash, $block, $duration );

            // The bounded index the admin screen lists.
            self::index_block( $ip, $block );

            $this->block_request( 'rate_limit', __( 'Rate limit exceeded. Please try again later.', 'vigilante' ), 429 );
        }

        // The TTL only garbage-collects the payload once the IP goes quiet; what
        // bounds the count is the window reset above, not the expiry.
        set_transient( $transient_key, $window, self::RATE_LIMIT_WINDOW );
    }

    /**
     * Block a request
     *
     * @param string $reason      Reason code for blocking.
     * @param string $message     Message to log.
     * @param int    $status_code HTTP status code.
     */
    private function block_request( $reason, $message, $status_code = 403 ) {
        // Log the block
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'firewall',
                'blocked',
                $message,
                array(
                    'reason'      => $reason,
                    'request_uri' => $this->loggable_uri(),
                    'ip'          => $this->get_client_ip(),
                    'user_agent'  => $this->request_data['user_agent'] ?? '',
                ),
                'warning'
            );
        }

        // Set response headers
        if ( ! headers_sent() ) {
            status_header( $status_code );
            nocache_headers();
        }

        // A REST client gets the refusal in the shape it can read. Until
        // 2.11.0 every block answered with the HTML "Forbidden" page, so the
        // block editor could only show its own generic message and the reason
        // was reachable only by opening the activity log. Same status code,
        // same message, the envelope core uses for an error.
        if ( '' !== $this->current_rest_route() ) {
            wp_send_json(
                array(
                    'code'    => 'vigilante_firewall_blocked',
                    'message' => $message,
                    'data'    => array( 'status' => $status_code ),
                ),
                $status_code
            );
        }

        // Return appropriate response
        if ( 429 === $status_code ) {
            wp_die(
                esc_html( $message ),
                esc_html__( 'Too Many Requests', 'vigilante' ),
                array( 'response' => 429 )
            );
        }

        wp_die(
            esc_html( $message ),
            esc_html__( 'Forbidden', 'vigilante' ),
            array( 'response' => 403 )
        );
    }

    /**
     * Upper bound of the address stored with a logged block
     *
     * @since 2.11.1
     */
    const MAX_LOGGED_URI = 512;

    /**
     * The blocked address, in a form that still says what was blocked
     *
     * The copy kept for logging goes through sanitize_text_field(), which
     * deletes every %XX sequence instead of decoding it. A browser percent
     * encodes the URL it puts in a parameter, so a blocked embed was recorded
     * as "/wp-json/oembed/1.0/proxy?url=httpswww.youtube.comwatchv..." and the
     * owner could not tell what the request had been. Reported on 9 sep 2026.
     *
     * Nothing is sanitized away here beyond control characters, and that is
     * the point. The value is stored, never executed: it is escaped where it
     * is shown, by escapeHtml() in the log detail and by csvCell() in the
     * export. Invalid UTF-8 is stripped because wp_json_encode() returns false
     * on it, which would have thrown away the whole entry's context.
     *
     * @since 2.11.1
     *
     * @return string
     */
    private function loggable_uri() {
        $uri = (string) ( $this->request_data['uri_raw'] ?? '' );
        $uri = (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $uri );
        $uri = wp_check_invalid_utf8( $uri, true );

        if ( strlen( $uri ) > self::MAX_LOGGED_URI ) {
            $uri = substr( $uri, 0, self::MAX_LOGGED_URI ) . '...';
        }

        return $uri;
    }

    /**
     * Check if current IP is whitelisted
     *
     * @return bool
     */
    private function is_ip_whitelisted() {
        $whitelist = $this->options['ip_whitelist'] ?? array();

        return Vigilante_IP_Utils::in_list( $this->get_client_ip(), $whitelist );
    }

    /**
     * Check if current IP is blacklisted
     *
     * @return bool
     */
    private function is_ip_blacklisted() {
        $blacklist = $this->options['ip_blacklist'] ?? array();

        return Vigilante_IP_Utils::in_list( $this->get_client_ip(), $blacklist );
    }

    /**
     * Check if current User-Agent is whitelisted
     *
     * Partial matching: if the request UA contains any whitelisted string,
     * it bypasses all firewall checks. Useful for services like ManageWP, MainWP, etc.
     *
     * @return bool
     */
    private function is_ua_whitelisted() {
        $whitelist = $this->options['ua_whitelist'] ?? array();

        if ( empty( $whitelist ) ) {
            return false;
        }

        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

        if ( empty( $user_agent ) ) {
            return false;
        }

        $ua_lower = strtolower( $user_agent );

        foreach ( $whitelist as $allowed ) {
            $allowed = trim( $allowed );
            if ( ! empty( $allowed ) && false !== strpos( $ua_lower, strtolower( $allowed ) ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if current User-Agent is blacklisted
     *
     * Partial matching: if the request UA contains any blacklisted string, block it.
     *
     * @return bool
     */
    private function is_ua_blacklisted() {
        $blacklist = $this->options['ua_blacklist'] ?? array();

        if ( empty( $blacklist ) ) {
            return false;
        }

        $user_agent = $this->request_data['user_agent'] ?? '';

        if ( empty( $user_agent ) ) {
            return false;
        }

        $ua_lower = strtolower( $user_agent );

        foreach ( $blacklist as $blocked ) {
            $blocked = trim( $blocked );
            if ( ! empty( $blocked ) && false !== strpos( $ua_lower, strtolower( $blocked ) ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get client IP address
     *
     * Delegates to the shared resolver, which only trusts REMOTE_ADDR unless a
     * proxy header has been explicitly declared in settings.
     *
     * @return string
     */
    private function get_client_ip() {
        return Vigilante_IP_Utils::get_client_ip();
    }

    // =========================================================================
    // BLOCK MANAGEMENT (static, for admin UI)
    // =========================================================================

    /**
     * Get currently active firewall blocks
     *
     * Cleans expired entries on each call.
     *
     * @return array Active blocks keyed by IP address.
     */
    public static function get_active_blocks() {
        $blocks = get_option( 'vigilante_firewall_blocks', array() );
        $now    = time();
        $dirty  = false;

        foreach ( $blocks as $ip => $data ) {
            if ( $now >= $data['expires'] ) {
                unset( $blocks[ $ip ] );
                $dirty = true;
            }
        }

        if ( $dirty ) {
            update_option( 'vigilante_firewall_blocks', $blocks, false );
        }

        return $blocks;
    }

    /**
     * Manually unblock an IP from rate limit blocks
     *
     * @param string $ip IP address to unblock.
     * @return bool Whether the IP was found and removed.
     */
    public static function unblock_ip( $ip ) {
        $blocks = get_option( 'vigilante_firewall_blocks', array() );

        if ( ! isset( $blocks[ $ip ] ) ) {
            return false;
        }

        // The address, and the narrower key the block was kept under, if any
        // (a verified visitor of Under Attack mode, since 2.11.8).
        $keys = array( $ip );

        if ( is_array( $blocks[ $ip ] ) && ! empty( $blocks[ $ip ]['key'] ) && is_string( $blocks[ $ip ]['key'] ) ) {
            $keys[] = $blocks[ $ip ]['key'];
        }

        unset( $blocks[ $ip ] );
        update_option( 'vigilante_firewall_blocks', $blocks, false );

        // Clean related transients
        foreach ( array_unique( $keys ) as $key ) {
            $hash = md5( $key );
            delete_transient( 'vigilante_rate_block_' . $hash );
            delete_transient( 'vigilante_rate_' . $hash );
            delete_transient( 'vigilante_strikes_' . $hash );
        }

        return true;
    }
}