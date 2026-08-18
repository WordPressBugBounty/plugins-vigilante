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

            // The rewriters above only cover same-domain URLs; external
            // http:// references need the browser-side CSP directive.
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
        $redirect_url = 'https://' . ( isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '' );
        $redirect_url .= isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

        // Redirect with 301 (permanent)
        wp_safe_redirect( $redirect_url, 301 );
        exit;
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

        if ( ! isset( $_SERVER['REQUEST_URI'] ) ) {
            return false;
        }

        $path   = wp_parse_url( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), PHP_URL_PATH );
        $prefix = '/' . trim( rest_get_url_prefix(), '/' ) . '/';

        return is_string( $path ) && 0 === strpos( $path, $prefix );
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
     * Update WordPress site URLs to HTTPS
     *
     * @return bool
     */
    public function update_site_urls() {
        $siteurl = get_option( 'siteurl' );
        $home = get_option( 'home' );
        $updated = false;

        if ( strpos( $siteurl, 'http://' ) === 0 ) {
            update_option( 'siteurl', str_replace( 'http://', 'https://', $siteurl ) );
            $updated = true;
        }

        if ( strpos( $home, 'http://' ) === 0 ) {
            update_option( 'home', str_replace( 'http://', 'https://', $home ) );
            $updated = true;
        }

        return $updated;
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