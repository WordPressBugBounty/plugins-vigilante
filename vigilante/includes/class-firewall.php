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

        // Skip for whitelisted User-Agents (ManageWP, MainWP, etc.)
        if ( $this->is_ua_whitelisted() ) {
            return;
        }

        // Check if IP is blacklisted
        if ( $this->is_ip_blacklisted() ) {
            $this->block_request( 'ip_blacklisted', __( 'IP address is blacklisted', 'vigilante' ) );
        }

        // Gather request data
        $this->gather_request_data();

        // Check if User-Agent is blacklisted (after gathering request data)
        if ( $this->is_ua_blacklisted() ) {
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

        foreach ( $checks as $option => $method ) {
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
        if ( $this->has_remote_inclusion() ) {
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
     * Whether the request carries a URL that points outside this site
     *
     * Works on the parsed parameters rather than on a pattern match over the
     * whole string, for two reasons: a link back to the site itself is not
     * mistaken for an attack, and an encoded payload is seen for what it is.
     * The copy of the query string kept for logging goes through
     * sanitize_text_field(), which strips every %XX sequence instead of
     * decoding it, so the encoded form never looked like a URL there.
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

        $values = array();
        array_walk_recursive(
            $params,
            function ( $value ) use ( &$values ) {
                if ( is_scalar( $value ) ) {
                    $values[] = (string) $value;
                }
            }
        );

        $home_host = $this->normalize_host( wp_parse_url( home_url(), PHP_URL_HOST ) );

        foreach ( $values as $value ) {
            if ( ! preg_match_all( '/(?:https?|ftp):\/\/[^\s\'"<>]+/i', $value, $matches ) ) {
                continue;
            }

            foreach ( $matches[0] as $url ) {
                $host = $this->normalize_host( wp_parse_url( $url, PHP_URL_HOST ) );

                if ( '' === $host || $host !== $home_host ) {
                    return true;
                }
            }
        }

        return false;
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
        $rest_prefix = rest_get_url_prefix(); // Typically 'wp-json'
        if ( false !== strpos( $this->request_data['uri'], '/' . $rest_prefix . '/' ) ) {
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

        // Allow other modules to opt out — Under Attack mode uses this so that
        // visitors who already passed the JS challenge don't burn the
        // aggressive 30 req/min cap loading a normal page's assets.
        if ( apply_filters( 'vigilante_skip_rate_limit', false ) ) {
            return;
        }

        $ip         = $this->get_client_ip();
        $rate_limit = $this->options['rate_limiting'];

        // Check if already blocked (fast path). The active block lives in a
        // transient keyed by IP, so this path, which runs on every
        // unauthenticated request, reads one row and not the whole index of
        // blocked addresses. Until 2.11.0 it loaded vigilante_firewall_blocks
        // entire, an array with no upper bound that a distributed attack grew
        // by one entry per new address, so the firewall amplified the attack it
        // was blocking (S6). The transient expires with the block itself.
        $block = get_transient( 'vigilante_rate_block_' . md5( $ip ) );
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
        $transient_key = 'vigilante_rate_' . md5( $ip );
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
                $strikes_key = 'vigilante_strikes_' . md5( $ip );
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
            );

            // The block itself, read by the fast path above on every request.
            set_transient( 'vigilante_rate_block_' . md5( $ip ), $block, $duration );

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
                    'reason'    => $reason,
                    'uri'       => $this->request_data['uri'] ?? '',
                    'ip'        => $this->get_client_ip(),
                    'user_agent'=> $this->request_data['user_agent'] ?? '',
                ),
                'warning'
            );
        }

        // Set response headers
        if ( ! headers_sent() ) {
            status_header( $status_code );
            nocache_headers();
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

        unset( $blocks[ $ip ] );
        update_option( 'vigilante_firewall_blocks', $blocks, false );

        // Clean related transients
        $hash = md5( $ip );
        delete_transient( 'vigilante_rate_block_' . $hash );
        delete_transient( 'vigilante_rate_' . $hash );
        delete_transient( 'vigilante_strikes_' . $hash );

        return true;
    }
}