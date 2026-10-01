<?php
/**
 * HTTPS Enforcer Class
 *
 * Forces HTTPS across the site
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Https_Enforcer
 *
 * Enforces HTTPS connections and fixes mixed content
 */
class Vigilante_Https_Enforcer {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * HTTPS options
     *
     * @var array
     */
    private $options;

    /**
     * Whether the output buffer was started by this class
     *
     * @var bool
     */
    private $ob_started = false;

    /**
     * Nesting level of the buffer opened by this class.
     *
     * Recorded so shutdown can tell whether the buffer on top is still ours.
     *
     * @var int
     */
    private $ob_level = 0;

    /**
     * Constructor
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    public function __construct( $settings ) {
        $this->settings = $settings;
        $this->options  = $settings->get_section( 'security_headers' );

        if ( empty( $this->options['enabled'] ) ) {
            return;
        }

        // Redirect HTTP to HTTPS
        if ( ! empty( $this->options['redirect_http_to_https'] ) ) {
            add_action( 'template_redirect', array( $this, 'redirect_to_https' ), 1 );
            add_action( 'admin_init', array( $this, 'redirect_to_https' ), 1 );
        }

        // Fix mixed content
        if ( ! empty( $this->options['fix_mixed_content'] ) ) {
            add_action( 'wp_loaded', array( $this, 'start_output_buffer' ) );
            add_action( 'shutdown', array( $this, 'end_output_buffer' ), 0 );
            add_filter( 'script_loader_src', array( $this, 'fix_url_scheme' ), 10, 1 );
            add_filter( 'style_loader_src', array( $this, 'fix_url_scheme' ), 10, 1 );
            add_filter( 'wp_get_attachment_url', array( $this, 'fix_url_scheme' ), 10, 1 );
            add_filter( 'the_content', array( $this, 'fix_content_urls' ), 999 );
            add_filter( 'widget_text', array( $this, 'fix_content_urls' ), 999 );

        }

        // Its own setting since 2.9.8: the rewriters above are same-domain and
        // harmless, this one governs everybody else's resources too.
        if ( ! empty( $this->options['upgrade_insecure_requests'] ) ) {
            add_action( 'send_headers', array( $this, 'emit_upgrade_insecure_requests' ) );
        }
    }

    /**
     * Redirect HTTP requests to HTTPS
     */
    public function redirect_to_https() {
        // Skip if already HTTPS
        if ( is_ssl() ) {
            return;
        }

        /*
         * Only redirect when the site itself declares HTTPS. A site whose home
         * URL is still http:// has not moved to HTTPS, and sending every request
         * to an address that may not answer takes it offline outright. Read from
         * the home option (which honours the WP_HOME constant through the
         * option_home filter) rather than home_url(), so the answer is the
         * address the site declares and not one derived from the current
         * request. A site already on HTTPS has an https home URL and keeps
         * redirecting exactly as before.
         */
        if ( 0 !== strpos( (string) get_option( 'home' ), 'https://' ) ) {
            return;
        }

        // Skip CLI
        if ( defined( 'WP_CLI' ) && WP_CLI ) {
            return;
        }

        // Skip AJAX requests
        if ( wp_doing_ajax() ) {
            return;
        }

        // Skip cron
        if ( wp_doing_cron() ) {
            return;
        }

        // Build HTTPS URL
        $redirect_url = $this->build_https_url();

        if ( '' === $redirect_url ) {
            return;
        }

        // Redirect with 301 (permanent)
        $this->send_redirect( $redirect_url );
    }

    /**
     * Send the permanent redirect to the HTTPS address.
     *
     * wp_safe_redirect() only knows the home host, and answers any other with
     * a 301 to admin_url(). The admin area of a site whose WordPress lives on a
     * host of its own is built on the siteurl host, so that host is added to
     * the allowed ones for this one call. It is the site's own declaration, read
     * from the siteurl option; the host of the URL being sent is deliberately
     * not the one that is allowed, so a URL that was not built from the two
     * options still falls back to admin_url() instead of being let through.
     *
     * @param string $url Absolute https URL, built by build_https_url().
     */
    private function send_redirect( $url ) {
        $siteurl_host = $this->host_of( (string) get_option( 'siteurl' ) );

        if ( '' !== $siteurl_host ) {
            add_filter(
                'allowed_redirect_hosts',
                static function ( $hosts ) use ( $siteurl_host ) {
                    $hosts   = (array) $hosts;
                    $hosts[] = $siteurl_host;

                    return $hosts;
                }
            );
        }

        wp_safe_redirect( $url, 301 );
        exit;
    }

    /**
     * The host of a URL, cut by hand as wp_parse_url() damages raw UTF-8.
     *
     * Like parse_url() for an ordinary URL: no port, an IPv6 literal keeps its
     * brackets. A user in the option is not taken off, so a value such as
     * https://user@host gives "user@host", which matches no host and fails
     * safe.
     *
     * @param string $url URL, as stored in an option.
     * @return string Host, or '' when the URL has none.
     */
    private function host_of( $url ) {
        return preg_match( '~^https?://(\[[^\]]+\]|[^/:?#]+)~i', $url, $m ) ? $m[1] : '';
    }

    /**
     * The HTTPS address of the request being redirected.
     *
     * Made of two things and nothing else: the host the site declares
     * (declared_authority()) and the target the client asked for, as it was
     * sent (Vigilante_IP_Utils::request_uri(), whose docblock lists the few
     * things it does not keep).
     *
     * It used to be the Host header plus sanitize_text_field() over the target,
     * and both were wrong. sanitize_text_field() deletes every %XX octet, so
     * http://site/categor%C3%ADa/ was sent to https://site/categora/, a 404
     * (measured on 1 oct 2026 against 3.0.1; a Cyrillic path became //, and
     * every parameter lost its encoded characters). And the Host is picked by
     * whoever makes the request: wp_safe_redirect() refuses a host that is not
     * the site's, but what it does then is not refuse, it is send a 301 to the
     * admin URL. A visit to the www alias of the site, or to the bare domain
     * when home has the www, or to the server by its IP, was sent permanently
     * to /wp-admin/ before WordPress' own canonical redirect, which runs later,
     * could send it to the same page. The declared host is the one core
     * canonicalizes to as well.
     *
     * A site that served other hostnames of its own through
     * allowed_redirect_hosts now gets the declared host for all of them, which
     * is what a canonical redirect is.
     *
     * @return string Absolute https URL, or '' when the site declares no host to send it to.
     */
    private function build_https_url() {
        $authority = $this->declared_authority();

        if ( '' === $authority ) {
            return '';
        }

        $uri = Vigilante_IP_Utils::request_uri();

        // A target in origin form starts with a slash. Anything else (OPTIONS *,
        // an absolute-form request line, a bare @host) must not be glued to the
        // authority, where it could be read as something other than a path.
        if ( '' === $uri || '/' !== $uri[0] ) {
            $uri = '/';
        }

        return 'https://' . $authority . $uri;
    }

    /**
     * The host, with its port if it has one, the site declares for this request.
     *
     * The admin area is built on the siteurl option, which is where core itself
     * sends admin_url(), and everything else on the home option, the one the
     * guard in redirect_to_https() reads. They are the same host on almost
     * every site. They differ when WordPress is served from a host of its own,
     * as in a decoupled site, and then an http visit to the admin area has to
     * stay on the admin host and a visit to the public site on the public one.
     * Cut by hand, as wp_parse_url() damages raw UTF-8.
     *
     * Known limits, found by the cross review, none of them a configuration a
     * real site has. A siteurl declared as http:// still gives its authority,
     * port included, to the https address: with home https and siteurl
     * http://host:8080 the admin goes to https://host:8080, where it used to go
     * to the home port. And a siteurl on a host of its own that is an IPv6
     * literal or a raw UTF-8 IDN is not matched by wp_validate_redirect(), so
     * the visit falls back to admin_url() and, without FORCE_SSL_ADMIN, can
     * loop. If a site ever has one of them, take the siteurl authority only
     * when it is https, and encode the host.
     *
     * @return string Authority, or '' when the site declares none.
     */
    private function declared_authority() {
        if ( is_admin() && preg_match( '~^https?://([^/?#]+)~i', (string) get_option( 'siteurl' ), $m ) ) {
            return $m[1];
        }

        if ( preg_match( '~^https://([^/?#]+)~i', (string) get_option( 'home' ), $m ) ) {
            return $m[1];
        }

        return '';
    }

    /**
     * Send the CSP upgrade-insecure-requests directive on the front end.
     *
     * The mixed-content rewriter only fixes same-domain URLs (its patterns
     * are anchored to home_url()), so references to EXTERNAL http://
     * resources survived and the Security Check kept flagging them, which
     * read as "Fix mixed content does nothing". This directive makes the
     * browser upgrade every subrequest, external ones included.
     *
     * Always emitted, without checking the CSP module settings: Vigilant's
     * own CSP travels via .htaccess, so "csp enabled" in the options does
     * not guarantee the header is actually served (Nginx, unwritable
     * .htaccess, mod_headers missing). Multiple CSP headers stack in the
     * browser (every policy applies) and this directive alone restricts
     * nothing, so a duplicate is harmless while a missed emission is not.
     *
     * @since 2.9.3
     */
    public function emit_upgrade_insecure_requests() {
        if ( ! is_ssl() || headers_sent() ) {
            return;
        }

        header( 'Content-Security-Policy: upgrade-insecure-requests', false );
    }

    /**
     * Start output buffering to fix mixed content
     */
    public function start_output_buffer() {
        if ( ! is_ssl() ) {
            return;
        }

        // The rewriter only touches complete HTML documents (fix_output_buffer()
        // bails on anything without <html or <!DOCTYPE), so buffering the admin,
        // AJAX and REST responses pays for a buffer and a callback that can never
        // do any work. On a WooCommerce site the cart-fragments endpoint alone is
        // dozens of those per visitor.
        if ( is_admin() || wp_doing_ajax() || $this->is_rest_request() ) {
            return;
        }

        ob_start( array( $this, 'fix_output_buffer' ) );
        $this->ob_started = true;
        $this->ob_level   = ob_get_level();
    }

    /**
     * Whether the current request is a REST API request.
     *
     * REST_REQUEST is only defined once the request is being served, which is
     * after wp_loaded, so the REST route prefix is checked as well.
     *
     * @return bool
     */
    private function is_rest_request() {
        if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
            return true;
        }

        $uri = Vigilante_IP_Utils::request_uri();

        if ( '' === $uri ) {
            return false;
        }

        // The path is cut by hand: wp_parse_url() turns the raw UTF-8 bytes
        // 0x80-0x9F and 0xAD into underscores.
        $path   = (string) substr( $uri, 0, strcspn( $uri, '?#' ) );
        $prefix = '/' . trim( rest_get_url_prefix(), '/' ) . '/';

        return 0 === strpos( $path, $prefix );
    }

    /**
     * Explicitly close the output buffer on shutdown.
     *
     * Ensures the buffer opened by start_output_buffer() is always
     * properly closed within the same logical flow.
     */
    public function end_output_buffer() {
        // Only flush when the buffer on top is exactly the one we opened. Testing
        // for "is there any buffer at all" would close somebody else's buffer when
        // another plugin opened one after ours and had not closed it yet, leaving
        // ours open on top of that. When the levels do not match, doing nothing is
        // the safe move: PHP flushes what is left at the end of the request.
        if ( $this->ob_started && ob_get_level() === $this->ob_level ) {
            ob_end_flush();
            $this->ob_started = false;
        }
    }

    /**
     * Fix URLs in output buffer
     *
     * @param string $content Buffer content.
     * @return string
     */
    public function fix_output_buffer( $content ) {
        if ( empty( $content ) ) {
            return $content;
        }

        // Only process HTML content
        if ( strpos( $content, '<html' ) === false && strpos( $content, '<!DOCTYPE' ) === false ) {
            return $content;
        }

        return $this->replace_http_with_https( $content );
    }

    /**
     * Replace HTTP URLs with HTTPS
     *
     * @param string $content Content to process.
     * @return string
     */
    private function replace_http_with_https( $content ) {
        // Get site URL without protocol
        $site_url = preg_replace( '/^https?:\/\//', '', home_url() );
        $site_url = preg_quote( $site_url, '/' );

        // Replace HTTP with HTTPS for same domain
        $patterns = array(
            // Standard URLs
            '/http:\/\/' . $site_url . '/i' => 'https://' . str_replace( '\\', '', $site_url ),
            
            // srcset attributes
            '/http:\/\/(' . $site_url . '[^"\'\s]*)/i' => 'https://$1',
        );

        foreach ( $patterns as $pattern => $replacement ) {
            $content = preg_replace( $pattern, $replacement, $content );
        }

        // Fix protocol-relative URLs that should be HTTPS
        $content = preg_replace(
            '/(<(script|link|img|iframe|source|video|audio)[^>]*(?:src|href|srcset)=["\'])\/\//i',
            '$1https://',
            $content
        );

        return $content;
    }

    /**
     * Fix URL scheme for enqueued scripts/styles
     *
     * @param string $url URL to fix.
     * @return string
     */
    public function fix_url_scheme( $url ) {
        if ( empty( $url ) || ! is_ssl() ) {
            return $url;
        }

        // Only fix URLs from the same domain
        $site_host = wp_parse_url( home_url(), PHP_URL_HOST );
        $url_host = wp_parse_url( $url, PHP_URL_HOST );

        if ( $site_host === $url_host ) {
            $url = set_url_scheme( $url, 'https' );
        }

        return $url;
    }

    /**
     * Fix URLs in content
     *
     * @param string $content Content to process.
     * @return string
     */
    public function fix_content_urls( $content ) {
        if ( empty( $content ) || ! is_ssl() ) {
            return $content;
        }

        return $this->replace_http_with_https( $content );
    }

    /**
     * Check if site is properly configured for HTTPS
     *
     * @return array Status information.
     */
    public function get_https_status() {
        $status = array(
            'ssl_available'     => is_ssl(),
            'siteurl_https'     => strpos( get_option( 'siteurl' ), 'https://' ) === 0,
            'home_https'        => strpos( get_option( 'home' ), 'https://' ) === 0,
            'force_ssl_admin'   => defined( 'FORCE_SSL_ADMIN' ) && FORCE_SSL_ADMIN,
            'force_ssl_login'   => defined( 'FORCE_SSL_LOGIN' ) && FORCE_SSL_LOGIN,
            'certificate_valid' => $this->check_ssl_certificate(),
        );

        $status['fully_configured'] = $status['ssl_available'] 
            && $status['siteurl_https'] 
            && $status['home_https']
            && $status['certificate_valid'];

        return $status;
    }

    /**
     * Check if SSL certificate is valid
     *
     * @return bool
     */
    private function check_ssl_certificate() {
        $url = str_replace( 'http://', 'https://', home_url() );
        
        $response = wp_remote_get( $url, array(
            'sslverify' => true,
            'timeout'   => 10,
        ));

        return ! is_wp_error( $response );
    }

    /**
     * Get list of mixed content issues (for diagnostics)
     *
     * @return array
     */
    public function scan_for_mixed_content() {
        $issues = array();

        // Check common options that might contain HTTP URLs
        $options_to_check = array(
            'siteurl',
            'home',
            'stylesheet_url',
            'template_url',
        );

        foreach ( $options_to_check as $option ) {
            $value = get_option( $option );
            if ( $value && strpos( $value, 'http://' ) === 0 ) {
                $issues[] = array(
                    'type'   => 'option',
                    'name'   => $option,
                    'value'  => $value,
                );
            }
        }

        // Check for HTTP URLs in recent posts content
        global $wpdb;
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $posts_with_http = $wpdb->get_results(
            "SELECT ID, post_title FROM {$wpdb->posts} 
             WHERE post_status = 'publish' 
             AND (post_content LIKE '%http://%' OR post_content LIKE '%src=\"http://%')
             LIMIT 10"
        );

        foreach ( $posts_with_http as $post ) {
            $issues[] = array(
                'type'   => 'post',
                'id'     => $post->ID,
                'title'  => $post->post_title,
            );
        }

        return $issues;
    }
}