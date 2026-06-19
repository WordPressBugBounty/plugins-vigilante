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
        $this->request_data = array(
            'uri'         => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
            'query_string'=> isset( $_SERVER['QUERY_STRING'] ) ? sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '',
            'user_agent'  => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
            'referer'     => isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '',
            'method'      => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET',
            'ip'          => $this->get_client_ip(),
        );
    }

    /**
     * Check for malicious query strings
     *
     * @return string|false Error message or false if safe.
     */
    private function check_query_strings() {
        $query = $this->request_data['query_string'];

        if ( empty( $query ) ) {
            return false;
        }

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
            if ( preg_match( $pattern, $query ) ) {
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
            $this->request_data['query_string'],
            $this->request_data['uri'],
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
        $to_check = array(
            $this->request_data['query_string'],
            $this->request_data['uri'],
        );

        $combined = implode( ' ', array_filter( $to_check ) );

        if ( empty( $combined ) ) {
            return false;
        }

        // URL decode for checking
        $decoded = urldecode( $combined );

        // XSS patterns
        $patterns = array(
            // Script tags
            '/<script[^>]*>/i' => __( 'Script tag detected', 'vigilante' ),
            
            // Event handlers
            '/\bon\w+\s*=/i' => __( 'Event handler detected', 'vigilante' ),
            
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
        $uri = $this->request_data['uri'];
        $query = $this->request_data['query_string'];
        $combined = $uri . ' ' . $query;

        if ( empty( $combined ) ) {
            return false;
        }

        // File inclusion patterns
        $patterns = array(
            // Remote file inclusion
            '/=\s*(https?|ftp):\/\//i' => __( 'Remote file inclusion attempt', 'vigilante' ),
            
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
     * Check for directory traversal attacks
     *
     * @return string|false Error message or false if safe.
     */
    private function check_directory_traversal() {
        $uri = $this->request_data['uri'];
        $query = $this->request_data['query_string'];
        $combined = urldecode( $uri . ' ' . $query );

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
        $uri = $this->request_data['uri'];

        // Check if accessing PHP in uploads directory
        if ( preg_match( '/\/wp-content\/uploads\/.*\.ph(p[345s]?|tml)/i', $uri ) ) {
            return __( 'PHP execution in uploads blocked', 'vigilante' );
        }

        return false;
    }

    /**
     * Check for access to sensitive files
     *
     * @return string|false Error message or false if safe.
     */
    private function check_sensitive_files() {
        $uri = strtolower( $this->request_data['uri'] );

        // Sensitive file patterns
        $sensitive_patterns = array(
            '/\.htaccess$/i',
            '/\.htpasswd$/i',
            '/wp-config\.php$/i',
            '/wp-config-sample\.php$/i',
            '/readme\.html$/i',
            '/licen(se|cia)\.txt$/i',
            '/xmlrpc\.php$/i', // If XML-RPC is disabled
            '/\.git/i',
            '/\.svn/i',
            '/\.env$/i',
            '/composer\.(json|lock)$/i',
            '/package(-lock)?\.json$/i',
            '/\.sql$/i',
            '/\.bak$/i',
            '/\.old$/i',
            '/\.log$/i',
            '/\.ini$/i',
            '/debug\.log$/i',
            '/error_log$/i',
        );

        foreach ( $sensitive_patterns as $pattern ) {
            if ( preg_match( $pattern, $uri ) ) {
                return __( 'Access to sensitive file blocked', 'vigilante' );
            }
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
        // Generic short words (e.g. 'scan', 'ninja', 'titan') are excluded
        // here but covered by the htaccess layer with regex patterns.
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
            'custo',
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

        // Check if already blocked via queryable option (fast path)
        $active_blocks = get_option( 'vigilante_firewall_blocks', array() );
        if ( isset( $active_blocks[ $ip ] ) ) {
            if ( time() < $active_blocks[ $ip ]['expires'] ) {
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
            // Expired — clean up
            unset( $active_blocks[ $ip ] );
            update_option( 'vigilante_firewall_blocks', $active_blocks, false );
        }

        $max_requests = absint( $rate_limit['requests_per_minute'] );

        // Allow Under Attack mode (or other filters) to override threshold
        $max_requests = absint( apply_filters( 'vigilante_rate_limit_requests', $max_requests ) );

        // Use transients for request counting (1 minute window)
        $transient_key = 'vigilante_rate_' . md5( $ip );
        $request_count = get_transient( $transient_key );

        if ( false === $request_count ) {
            // First request in this window
            set_transient( $transient_key, 1, 60 );
            return;
        }

        $request_count = absint( $request_count );

        if ( $request_count >= $max_requests ) {
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

            // Store block in queryable option for admin UI
            $active_blocks[ $ip ] = array(
                'expires'    => time() + $duration,
                'blocked_at' => time(),
                'duration'   => $duration,
                'reason'     => 'rate_limit',
                'strikes'    => $strikes,
            );
            update_option( 'vigilante_firewall_blocks', $active_blocks, false );

            $this->block_request( 'rate_limit', __( 'Rate limit exceeded. Please try again later.', 'vigilante' ), 429 );
        }

        // Increment counter
        set_transient( $transient_key, $request_count + 1, 60 );
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