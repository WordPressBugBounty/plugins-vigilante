<?php
/**
 * Login Security Class
 *
 * Handles login protection, brute force prevention and lockouts
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Login_Security
 *
 * Manages login security features
 */
class Vigilante_Login_Security {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Database instance
     *
     * @var Vigilante_Database
     */
    private $database;

    /**
     * Activity log instance
     *
     * @var Vigilante_Activity_Log
     */
    private $activity_log;

    /**
     * Login security options
     *
     * @var array
     */
    private $options;

    /**
     * Custom login slug
     *
     * @var string
     */
    private $custom_login_slug = '';

    /**
     * Whether the current login error carries a Vigilant-specific code
     * that must bypass the generic-message mask in hide_login_errors().
     * Set by detect_specific_login_error() (hooked to wp_login_errors).
     *
     * @var bool
     */
    private $show_specific_login_error = false;

    /**
     * Whether we are rendering the login action specifically.
     *
     * The login_errors filter that hide_login_errors() masks is fired by
     * login_header() on every wp-login.php screen (login, register,
     * lostpassword, resetpass). Only the login action also fires
     * wp_login_errors, so detect_specific_login_error() runs solely there
     * and flips this flag. When it stays false the generic mask is skipped,
     * so registration / lost-password / reset-password keep their real
     * validation errors instead of "Invalid username or password".
     *
     * @var bool
     */
    private $in_login_context = false;

    /**
     * Constructor
     *
     * @param Vigilante_Settings     $settings     Settings instance.
     * @param Vigilante_Database     $database     Database instance.
     * @param Vigilante_Activity_Log $activity_log Activity log instance.
     */
    public function __construct( $settings, $database, $activity_log ) {
        $this->settings     = $settings;
        $this->database     = $database;
        $this->activity_log = $activity_log;
        $this->options      = $settings->get_section( 'login_security' );

        $this->init_hooks();
    }

    /**
     * Initialize hooks
     */
    private function init_hooks() {
        // Check lockout before authentication
        add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 3 );

        // Track login attempts
        add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ) );
        add_action( 'wp_login', array( $this, 'handle_successful_login' ), 10, 2 );

        // Hide login errors
        if ( ! empty( $this->options['hide_login_errors'] ) ) {
            add_filter( 'wp_login_errors', array( $this, 'detect_specific_login_error' ), 10, 2 );
            add_filter( 'login_errors', array( $this, 'hide_login_errors' ) );
            add_filter( 'shake_error_codes', array( $this, 'remove_shake_errors' ) );
        }

        // Disable application passwords
        if ( ! empty( $this->options['disable_application_passwords'] ) ) {
            add_filter( 'wp_is_application_passwords_available', '__return_false' );
        }

        // Notify on admin login
        if ( ! empty( $this->options['notify_on_admin_login'] ) ) {
            add_action( 'wp_login', array( $this, 'notify_admin_login' ), 10, 2 );
        }

        // Add lockout info to login form
        add_action( 'login_form', array( $this, 'show_remaining_attempts' ) );

        // Custom login URL
        if ( ! empty( $this->options['custom_login_url'] ) ) {
            $this->init_custom_login();
        }
    }

    /**
     * Initialize custom login URL functionality
     * 
     * Uses request interception instead of rewrite rules for reliability
     */
    private function init_custom_login() {
        $custom_url = sanitize_title( $this->options['custom_login_url'] );
        
        if ( empty( $custom_url ) ) {
            return;
        }

        // Store custom URL for use in other methods
        $this->custom_login_slug = $custom_url;

        // Intercept requests early - this is the key hook
        add_action( 'wp_loaded', array( $this, 'wp_loaded_handler' ) );
        
        // Filter login URL
        add_filter( 'login_url', array( $this, 'filter_login_url' ), 10, 3 );
        add_filter( 'logout_url', array( $this, 'filter_logout_url' ), 10, 2 );
        add_filter( 'lostpassword_url', array( $this, 'filter_lostpassword_url' ), 10, 2 );
        add_filter( 'register_url', array( $this, 'filter_register_url' ) );

        // After requesting "lost password", core redirects to wp-login.php?checkemail=confirm
        // which is blocked by block_wp_login_access (no whitelisted action) and yields a 404.
        // Send the user to the custom login URL instead so the confirmation message renders.
        add_filter( 'lostpassword_redirect', array( $this, 'filter_lostpassword_redirect' ) );
        
        // Block direct wp-login.php access (always when custom URL is set)
        add_action( 'login_init', array( $this, 'block_wp_login_access' ), 1 );
        
        // Site URL filter for login form action
        add_filter( 'site_url', array( $this, 'filter_site_url' ), 10, 4 );
        
        // Redirect to home after logout instead of wp-login.php
        add_filter( 'logout_redirect', array( $this, 'filter_logout_redirect' ), 10, 3 );
        
        // Block wp-admin access for non-logged users - execute immediately
        $this->block_wp_admin_access();

        // Intercept redirects to wp-login.php from wp-admin and show 404 instead
        add_filter( 'wp_redirect', array( $this, 'intercept_admin_redirect' ), 1, 2 );

        // Block core's /login and /wp-login.php pretty-URL shortcuts.
        // Priority 1: must win over redirect_canonical() (10) and
        // wp_redirect_admin_locations() (1000), which would 302 the
        // shortcut to wp_login_url() — the hidden URL — leaking the slug.
        add_action( 'template_redirect', array( $this, 'block_login_shortcuts' ), 1 );
    }

    /**
     * Intercept redirects to wp-login.php from wp-admin
     * Shows 404 instead of redirecting to login
     *
     * @param string $location The redirect location.
     * @param int    $status   The redirect status code.
     * @return string
     */
    public function intercept_admin_redirect( $location, $status ) {

        // Only intercept if custom login URL is set
        if ( empty( $this->options['custom_login_url'] ) ) {
            return $location;
        }

        // Check if this is a redirect to the login screen. Besides literal
        // wp-login.php, auth_redirect() targets wp_login_url(), which the
        // login_url filter has already rewritten to the hidden slug — so a
        // redirect to the custom login URL must be caught too, or an
        // anonymous POST to /wp-admin would leak the slug in the Location
        // header (the login_url filter runs for every wp_login_url() call).
        if ( strpos( $location, 'wp-login.php' ) === false && ! $this->is_hidden_login_url( $location ) ) {
            return $location;
        }
        
        // Check if the redirect is coming from wp-admin area
        $request = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        
        
        // If accessing wp-admin and being redirected to login, show 404 instead
        if ( self::is_wp_admin_request() ) {
            // Don't intercept admin-ajax.php or admin-post.php
            if ( self::is_open_admin_endpoint() ) {
                return $location;
            }

            // Allow whitelisted IPs (e.g. remote managers like MainWP/ManageWP).
            if ( $this->is_ip_exempt_from_hiding() ) {
                return $location;
            }
            
            
            // Log the attempt
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'login',
                    'hidden_admin_access',
                    __( 'Attempt to access hidden wp-admin', 'vigilante' ),
                    array( 'request_uri' => $request ),
                    'warning'
                );
            }

            $this->serve_404();
        }

        return $location;
    }

    /**
     * Whether a URL points at the hidden custom login screen.
     *
     * Matches the exact URL, with or without trailing slash, and with a
     * query string. Prefix-matching the bare slug is deliberately avoided
     * so a slug like "acceso" does not match "accesorios".
     *
     * @since 2.9.3
     * @param string $url URL to test.
     * @return bool
     */
    private function is_hidden_login_url( $url ) {
        if ( empty( $this->custom_login_slug ) ) {
            return false;
        }

        $hidden = home_url( $this->custom_login_slug . '/' );
        $bare   = untrailingslashit( $hidden );

        return 0 === strpos( $url, $hidden )
            || $url === $bare
            || 0 === strpos( $url, $bare . '?' );
    }

    /**
     * The request path as sent by the client, query string stripped.
     *
     * Unlike get_request_path(), the result is NOT made relative to
     * home_url(): the admin area can hang from a different path than the
     * site itself (WP_SITEURL vs WP_HOME), so wp-admin matching needs the
     * raw path.
     *
     * @since 2.9.4
     * @return string
     */
    private static function get_request_uri_path() {
        $request = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

        if ( '' === $request ) {
            return '';
        }

        if ( false !== strpos( $request, '?' ) ) {
            $request = strstr( $request, '?', true );
        }

        return untrailingslashit( $request );
    }

    /**
     * Whether the current request targets the real wp-admin area.
     *
     * Replaces a strpos() for "/wp-admin" over the whole REQUEST_URI. That
     * test also matched the query string, so /?redirect_to=/wp-admin/ turned
     * the home page into a 404 and an un-encoded redirect_to broke the hidden
     * login screen itself; it matched any front-end path merely starting with
     * those characters (/wp-admin-tips/); and it dragged scanner hits on
     * non-existent subdirectories (/blog/wp-admin/) into the blocking path,
     * where they were answered from 'init' instead of by WordPress' own 404.
     *
     * Two independent signals, ORed so neither is a single point of failure:
     * is_admin(), set by the wp-admin bootstrap and immune to filters, and a
     * path comparison against admin_url() for the rare setup that serves the
     * admin directory through the front controller. Prefix matching requires
     * a following slash, the same precaution is_hidden_login_url() takes.
     *
     * @since 2.9.4
     * @return bool
     */
    private static function is_wp_admin_request() {
        if ( is_admin() ) {
            return true;
        }

        $path = self::get_request_uri_path();

        if ( '' === $path ) {
            return false;
        }

        $admin_path = wp_parse_url( admin_url(), PHP_URL_PATH );

        if ( empty( $admin_path ) ) {
            return false;
        }

        $admin_path = untrailingslashit( $admin_path );

        return $path === $admin_path || 0 === strpos( $path, $admin_path . '/' );
    }

    /**
     * Whether the request targets an admin entry point that must stay open.
     *
     * admin-ajax.php and admin-post.php are used by logged-out visitors on
     * the front end (WooCommerce fragments, form handlers), so hiding
     * wp-admin must never touch them. Matched as the exact admin path plus
     * the file name: the old check ran over the whole REQUEST_URI, so
     * /wp-admin/edit.php?x=admin-ajax.php slipped past the block, and a bare
     * basename() would do the same for a PATH_INFO style request such as
     * /wp-admin/options-general.php/admin-ajax.php. Falls back to the file
     * name only when admin_url() gives nothing to compare against, so a
     * broken filter can never take AJAX down for logged-out visitors.
     *
     * @since 2.9.4
     * @return bool
     */
    private static function is_open_admin_endpoint() {
        $path = self::get_request_uri_path();

        if ( '' === $path ) {
            return false;
        }

        $endpoints  = array( 'admin-ajax.php', 'admin-post.php' );
        $admin_path = wp_parse_url( admin_url(), PHP_URL_PATH );

        if ( empty( $admin_path ) ) {
            return in_array( basename( $path ), $endpoints, true );
        }

        $admin_path = untrailingslashit( $admin_path );

        foreach ( $endpoints as $endpoint ) {
            if ( $path === $admin_path . '/' . $endpoint ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Block access to wp-admin for non-logged users
     * Shows 404 instead of redirecting to login
     */
    public function block_wp_admin_access() {
        // Only if custom login URL is set
        if ( empty( $this->options['custom_login_url'] ) ) {
            return;
        }

        // Get the request URI
        $request = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        
        
        // Check if accessing wp-admin
        if ( ! self::is_wp_admin_request() ) {
            return;
        }

        // Allow admin-ajax.php and admin-post.php
        if ( self::is_open_admin_endpoint() ) {
            return;
        }
        
        // Allow if user is logged in
        if ( is_user_logged_in() ) {
            return;
        }
        
        // Allow POST requests
        $request_method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
        if ( 'POST' === $request_method ) {
            return;
        }

        // Allow whitelisted IPs (e.g. remote managers like MainWP/ManageWP).
        if ( $this->is_ip_exempt_from_hiding() ) {
            return;
        }
        
        
        // Log the attempt
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'login',
                'hidden_admin_access',
                __( 'Attempt to access hidden wp-admin', 'vigilante' ),
                array( 'request_uri' => $request ),
                'warning'
            );
        }

        $this->serve_404();
    }

    /**
     * Handle requests on wp_loaded
     * This intercepts requests to our custom login URL
     */
    public function wp_loaded_handler() {
        global $pagenow;
        
        // Get the request path
        $request = $this->get_request_path();
        
        
        // Check if accessing our custom login URL
        if ( $this->is_custom_login_request( $request ) ) {
            
            // Set flag that we're coming from custom login
            if ( ! defined( 'VIGILANTE_CUSTOM_LOGIN' ) ) {
                define( 'VIGILANTE_CUSTOM_LOGIN', true );
            }
            
            // Set pagenow to wp-login.php for compatibility
            $pagenow = 'wp-login.php';
            
            // Initialize global variables expected by wp-login.php (PHP 8.x strict)
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Required by WordPress core wp-login.php
            global $user_login, $error;
            $user_login = '';
            $error      = '';
            
            // Load the login page
            require_once ABSPATH . 'wp-login.php';
            exit;
        }
    }

    /**
     * Block direct access to wp-login.php
     * Uses login_init hook which fires inside wp-login.php
     */
    public function block_wp_login_access() {
        
        // If we came from our custom login URL, allow access
        if ( defined( 'VIGILANTE_CUSTOM_LOGIN' ) && VIGILANTE_CUSTOM_LOGIN ) {
            return;
        }
        
        // Allow POST requests (form submissions)
        $request_method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
        if ( 'POST' === $request_method ) {
            return;
        }
        
        // Allow AJAX requests
        if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
            return;
        }
        
        // Check for specific allowed actions that need wp-login.php
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $action = isset( $_GET['action'] ) ? sanitize_key( $_GET['action'] ) : '';
        $allowed_actions = array( 'postpass', 'logout', 'rp', 'resetpass', 'confirmaction', 'lostpassword', 'retrievepassword' );


        if ( in_array( $action, $allowed_actions, true ) ) {
            return;
        }

        // Allow informational query strings that core appends without an action,
        // e.g. ?checkemail=confirm after a lost-password request and ?password=changed
        // after a successful reset. These render the corresponding success message
        // inside wp-login.php and would otherwise 404.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( isset( $_GET['checkemail'] ) || isset( $_GET['password'] ) ) {
            return;
        }
        
        // Check if user already logged in - redirect to admin
        if ( is_user_logged_in() ) {
            wp_safe_redirect( admin_url() );
            exit;
        }

        // Log the attempt
        if ( $this->activity_log ) {
            $request = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
            $this->activity_log->log(
                'login',
                'hidden_login_access',
                __( 'Attempt to access hidden wp-login.php', 'vigilante' ),
                array( 'request_uri' => $request ),
                'warning'
            );
        }
        
        // Return 404
        $this->serve_404();
    }

    /**
     * Block WordPress' pretty-URL login shortcuts (/login, /wp-login.php).
     *
     * Core's wp_redirect_admin_locations() (template_redirect, priority
     * 1000) turns a 404 on those paths into wp_redirect( wp_login_url() ).
     * With a custom login URL active wp_login_url() IS the hidden slug, so
     * that 302 would hand the secret to anyone typing /login, while /admin
     * correctly ends in a 404. Runs only when the request is already a 404:
     * if a real page named "login" exists, core does not redirect either
     * and this must not interfere.
     *
     * @since 2.9.3
     */
    public function block_login_shortcuts() {
        if ( ! is_404() ) {
            return;
        }

        $request = strtolower( $this->get_request_path() );

        if ( ! in_array( $request, array( 'login', 'wp-login.php' ), true ) ) {
            return;
        }

        if ( $this->activity_log ) {
            $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
            $this->activity_log->log(
                'login',
                'hidden_login_access',
                __( 'Attempt to access hidden wp-login.php', 'vigilante' ),
                array( 'request_uri' => $request_uri ),
                'warning'
            );
        }

        $this->serve_404();
    }

    /**
     * Get the request path without query string
     *
     * @return string
     */
    private function get_request_path() {
        $request = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        
        // Remove query string
        if ( false !== strpos( $request, '?' ) ) {
            $request = strstr( $request, '?', true );
        }
        
        // Get path relative to home URL
        $home_path = wp_parse_url( home_url(), PHP_URL_PATH );
        if ( ! empty( $home_path ) ) {
            $request = str_replace( $home_path, '', $request );
        }
        
        // Clean up the path
        $request = ltrim( $request, '/' );
        $request = rtrim( $request, '/' );
        
        return $request;
    }

    /**
     * Check if this is a request to our custom login URL
     *
     * @param string $request The request path.
     * @return bool
     */
    private function is_custom_login_request( $request ) {
        return $request === $this->custom_login_slug;
    }

    /**
     * Filter the login URL
     *
     * @param string $login_url    The login URL.
     * @param string $redirect     The redirect URL.
     * @param bool   $force_reauth Whether to force reauth.
     * @return string
     */
    public function filter_login_url( $login_url, $redirect = '', $force_reauth = false ) {
        $login_url = home_url( $this->custom_login_slug . '/' );
        
        if ( ! empty( $redirect ) ) {
            $login_url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $login_url );
        }
        
        if ( $force_reauth ) {
            $login_url = add_query_arg( 'reauth', '1', $login_url );
        }
        
        return $login_url;
    }

    /**
     * Filter logout URL
     *
     * @param string $logout_url The logout URL.
     * @param string $redirect   The redirect URL.
     * @return string
     */
    public function filter_logout_url( $logout_url, $redirect = '' ) {
        $args = array( 'action' => 'logout' );
        
        if ( ! empty( $redirect ) ) {
            $args['redirect_to'] = rawurlencode( $redirect );
        }
        
        $logout_url = add_query_arg( $args, home_url( $this->custom_login_slug . '/' ) );
        $logout_url = wp_nonce_url( $logout_url, 'log-out' );
        
        return $logout_url;
    }

    /**
     * Filter lost password URL
     *
     * @param string $lostpassword_url The lost password URL.
     * @param string $redirect         The redirect URL.
     * @return string
     */
    public function filter_lostpassword_url( $lostpassword_url, $redirect = '' ) {
        $args = array( 'action' => 'lostpassword' );
        
        if ( ! empty( $redirect ) ) {
            $args['redirect_to'] = rawurlencode( $redirect );
        }
        
        return add_query_arg( $args, home_url( $this->custom_login_slug . '/' ) );
    }

    /**
     * Filter register URL
     *
     * @param string $register_url The register URL.
     * @return string
     */
    public function filter_register_url( $register_url ) {
        return add_query_arg( 'action', 'register', home_url( $this->custom_login_slug . '/' ) );
    }

    /**
     * Redirect after a successful lost-password request to the custom login URL
     *
     * Without this filter, core sends the user to wp-login.php?checkemail=confirm,
     * which 404s when the custom login URL is enabled (block_wp_login_access only
     * whitelists requests with a known action= parameter). Sending the user back
     * to the custom login URL with the same query string lets wp-login.php render
     * the "Check your email" confirmation correctly.
     *
     * @param string $redirect_to The default redirect URL.
     * @return string
     */
    public function filter_lostpassword_redirect( $redirect_to ) {
        return add_query_arg( 'checkemail', 'confirm', home_url( $this->custom_login_slug . '/' ) );
    }

    /**
     * Filter site_url to replace wp-login.php in login form action
     *
     * @param string      $url     The complete site URL.
     * @param string      $path    Path relative to the site URL.
     * @param string|null $scheme  Scheme to give the site URL context.
     * @param int|null    $blog_id Site ID, or null for the current site.
     * @return string
     */
    public function filter_site_url( $url, $path, $scheme, $blog_id ) {
        if ( 'login_post' === $scheme || 'login' === $scheme ) {
            if ( strpos( $path, 'wp-login.php' ) !== false ) {
                $url = str_replace( 'wp-login.php', $this->custom_login_slug . '/', $url );
            }
        }
        return $url;
    }

    /**
     * Filter logout redirect to go to home instead of wp-login.php
     *
     * @param string  $redirect_to           The redirect destination URL.
     * @param string  $requested_redirect_to The requested redirect destination URL.
     * @param WP_User $user                  The WP_User object for the logged out user.
     * @return string
     */
    public function filter_logout_redirect( $redirect_to, $requested_redirect_to, $user ) {
        // If no specific redirect requested, go to home page
        if ( empty( $requested_redirect_to ) || strpos( $redirect_to, 'wp-login.php' ) !== false ) {
            return home_url( '/' );
        }
        return $redirect_to;
    }

    /**
     * Show 404 page (full version with theme template)
     * Use this only when WordPress is fully loaded (login_init, template_redirect, etc.)
     */
    private function show_404() {

        global $wp_query;

        // Set 404 status
        status_header( 404 );
        nocache_headers();

        // $wp_query always exists by now: wp-settings.php creates it before
        // 'init' fires, and serve_404() only routes here once 'wp_loaded' has
        // passed. Earlier versions called wp() when it was missing, a branch
        // that was never reachable and that misled a performance analysis into
        // blaming the main query for the cost of the render.
        if ( isset( $wp_query ) && is_object( $wp_query ) ) {
            $wp_query->set_404();
        }

        // Try to get the theme's 404 template
        $template = get_query_template( '404' );


        if ( $template && file_exists( $template ) ) {
            include $template;
            exit;
        }

        // Block themes have no 404.php; resolve their 404 template the same
        // way core's template-loader does, so those sites also get the
        // theme's 404 instead of the plain fallback page.
        if ( function_exists( 'locate_block_template' ) ) {
            $template = locate_block_template( '', '404', array( '404' ) );

            if ( $template && file_exists( $template ) ) {
                include $template;
                exit;
            }
        }

        // Fallback to simple 404
        $this->show_404_simple();
    }

    /**
     * Serve the hidden-URL 404 through a single decision point.
     *
     * All blocking paths call this helper so the response never diverges by
     * accident. Rendering a theme template is only safe once 'wp_loaded' has
     * fired: that is the point the rest of the stack assumes has passed
     * before any template runs, and WooCommerce for one does not set up the
     * cart until then. block_wp_login_access() runs at 'login_init' and
     * block_login_shortcuts() at 'template_redirect', both after 'wp_loaded',
     * so those keep the themed 404; block_wp_admin_access() runs inside
     * 'init' and gets the simple page.
     *
     * 2.9.3 gated this on 'after_setup_theme', which has already fired by
     * 'init'. The wp-admin path therefore included the theme's 404.php from
     * inside 'init' on every blocked request, filling debug.log with
     * _doing_it_wrong notices and costing a full page render per rejection.
     *
     * @since 2.9.3
     */
    private function serve_404() {
        if ( did_action( 'wp_loaded' ) && ! is_admin() ) {
            $this->show_404();
        }

        $this->show_404_simple();
    }

    /**
     * Show simple 404 page (for early execution before WordPress is fully loaded)
     * Use this when intercepting requests very early (plugins_loaded, admin init, etc.)
     */
    private function show_404_simple() {
        status_header( 404 );
        nocache_headers();
        
        // Use wp_die which is the WordPress standard for early termination
        wp_die(
            sprintf(
                '<h1>%s</h1><p>%s</p><p><a href="%s">%s</a></p>',
                esc_html__( 'Page not found', 'vigilante' ),
                esc_html__( 'The page you are looking for does not exist.', 'vigilante' ),
                esc_url( home_url( '/' ) ),
                esc_html__( 'Go to homepage', 'vigilante' )
            ),
            esc_html__( '404 Not Found', 'vigilante' ),
            array(
                'response'  => 404,
                'back_link' => false,
            )
        );
    }

    /**
     * Check if user is locked out
     *
     * @param WP_User|WP_Error|null $user     User object or error.
     * @param string                $username Username.
     * @param string                $password Password.
     * @return WP_User|WP_Error
     */
    public function check_lockout( $user, $username, $password ) {
        // Skip if already error or empty credentials
        if ( empty( $username ) || empty( $password ) ) {
            return $user;
        }

        $ip = $this->database->get_client_ip();

        // Check IP whitelist
        if ( $this->is_ip_whitelisted( $ip ) ) {
            return $user;
        }

        // Check if locked out
        $lockout = $this->database->is_locked_out( $ip );

        if ( $lockout ) {
            $remaining = strtotime( $lockout['lockout_until'] ) - time();
            $minutes = ceil( $remaining / 60 );

            // Log the blocked attempt
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'login',
                    'lockout_blocked',
                    sprintf(
                        /* translators: %s: Username */
                        __( 'Login attempt blocked due to lockout: %s', 'vigilante' ),
                        $username
                    ),
                    array(
                        'ip'          => $ip,
                        'username'    => $username,
                        'lockout_until' => $lockout['lockout_until'],
                    ),
                    'warning'
                );
            }

            // This rejection is ours, not a wrong password. wp_authenticate()
            // still fires wp_login_failed for it, and until 2.11.0 that counted
            // the blocked attempt as one more failure, which rewrote the row's
            // status and produced a fresh lockout, with its critical entry and
            // its email, on every POST made during the lockout (S8).
            add_filter( 'vigilante_skip_failed_login_count', '__return_true' );

            return new WP_Error(
                'vigilante_lockout',
                sprintf(
                    /* translators: %d: Minutes remaining */
                    __( '<strong>Error</strong>: Too many failed login attempts. Please try again in %d minutes.', 'vigilante' ),
                    $minutes
                )
            );
        }

        return $user;
    }

    /**
     * Handle failed login attempt
     *
     * @param string $username Username that failed.
     */
    public function handle_failed_login( $username ) {
        // Skip counting if this is a Vigilante-controlled rejection
        // (pending approval, session limit, email verification, etc.)
        if ( apply_filters( 'vigilante_skip_failed_login_count', false ) ) {
            return;
        }

        $ip = $this->database->get_client_ip();

        // Skip whitelisted IPs
        if ( $this->is_ip_whitelisted( $ip ) ) {
            return;
        }

        // Record the attempt
        $this->database->record_login_attempt( $ip, $username, 'failed' );

        // Log the attempt
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'login',
                'failed',
                sprintf(
                    /* translators: %s: Username */
                    __( 'Failed login attempt for username: %s', 'vigilante' ),
                    $username
                ),
                array(
                    'ip'       => $ip,
                    'username' => $username,
                ),
                'warning'
            );
        }

        // Check if should be locked out
        $this->maybe_lockout( $ip, $username );
    }

    /**
     * Check if IP should be locked out
     *
     * @param string $ip       IP address.
     * @param string $username Username.
     */
    public function maybe_lockout( $ip, $username ) {
        $max_attempts = absint( $this->options['max_attempts'] ?? 5 );
        $lockout_duration = absint( $this->options['lockout_duration'] ?? 1800 );

        // Get failed attempts in the last hour
        $failed_count = $this->database->get_failed_attempt_count( $ip, 60 );

        if ( $failed_count >= $max_attempts ) {
            // Already locked out: every further POST during the lockout used to
            // write another critical entry and send another email (S8). The
            // lockout itself is what check_lockout() enforces; nothing to add.
            if ( $this->database->is_locked_out( $ip ) ) {
                return;
            }

            // Calculate lockout duration with increment
            if ( ! empty( $this->options['lockout_increment'] ) ) {
                $previous_lockouts = $this->get_previous_lockout_count( $ip );
                $lockout_duration = min(
                    $lockout_duration * pow( 2, $previous_lockouts ),
                    absint( $this->options['max_lockout_duration'] ?? 86400 )
                );
            }

            // Set lockout
            $this->database->set_lockout( $ip, $lockout_duration );

            // Log the lockout
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'login',
                    'lockout',
                    sprintf(
                        /* translators: 1: IP address, 2: Duration in minutes */
                        __( 'IP %1$s locked out for %2$d minutes', 'vigilante' ),
                        $ip,
                        ceil( $lockout_duration / 60 )
                    ),
                    array(
                        'ip'         => $ip,
                        'username'   => $username,
                        'attempts'   => $failed_count,
                        'duration'   => $lockout_duration,
                    ),
                    'critical'
                );
            }

            // Send notification if enabled
            if ( ! empty( $this->options['notify_on_lockout'] ) ) {
                $this->send_lockout_notification( $ip, $username, $failed_count, $lockout_duration );
            }
        }
    }

    /**
     * Record a failed login attempt (public wrapper)
     *
     * Use this method from external modules (like 2FA) to integrate with the lockout system.
     *
     * @param string $username Username or identifier.
     * @param string $context  Context for logging (e.g., 'password', '2fa').
     */
    public function record_failed_attempt( $username, $context = 'password' ) {
        $ip = $this->database->get_client_ip();

        // Skip whitelisted IPs
        if ( $this->is_ip_whitelisted( $ip ) ) {
            return;
        }

        // Record the attempt
        $this->database->record_login_attempt( $ip, $username, 'failed' );

        // Log the attempt
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'login',
                'failed',
                sprintf(
                    /* translators: 1: Username, 2: Context (password/2fa) */
                    __( 'Failed login attempt for %1$s (%2$s verification)', 'vigilante' ),
                    $username,
                    $context
                ),
                array(
                    'ip'       => $ip,
                    'username' => $username,
                    'context'  => $context,
                ),
                'warning'
            );
        }

        // Check if should be locked out
        $this->maybe_lockout( $ip, $username );
    }

    /**
     * Get remaining attempts before lockout
     *
     * @return int Remaining attempts, or -1 if whitelisted
     */
    public function get_remaining_attempts() {
        $ip = $this->database->get_client_ip();

        if ( $this->is_ip_whitelisted( $ip ) ) {
            return -1;
        }

        $max_attempts = absint( $this->options['max_attempts'] ?? 5 );
        $failed_count = $this->database->get_failed_attempt_count( $ip, 60 );

        return max( 0, $max_attempts - $failed_count );
    }

    /**
     * Get count of previous lockouts for an IP
     *
     * @param string $ip IP address.
     * @return int
     */
    private function get_previous_lockout_count( $ip ) {
        $transient_key = 'vigilante_lockout_count_' . md5( $ip );
        $count = get_transient( $transient_key );

        if ( false === $count ) {
            $count = 0;
        }

        // Increment and store
        set_transient( $transient_key, $count + 1, DAY_IN_SECONDS );

        return $count;
    }

    /**
     * Handle successful login
     *
     * @param string  $user_login Username.
     * @param WP_User $user       User object.
     */
    public function handle_successful_login( $user_login, $user ) {
        $ip = $this->database->get_client_ip();

        // Clear any failed attempts for this IP
        $this->database->reset_login_attempts( $ip );

        // Log the successful login
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'login',
                'success',
                sprintf(
                    /* translators: %s: Username */
                    __( 'Successful login: %s', 'vigilante' ),
                    $user_login
                ),
                array(
                    'ip'      => $ip,
                    'user_id' => $user->ID,
                    'role'    => implode( ', ', $user->roles ),
                ),
                'info'
            );
        }
    }

    /**
     * Detect Vigilant-specific error codes on the login page
     *
     * Hooked to 'wp_login_errors' (which receives the full WP_Error object,
     * unlike 'login_errors' that only sees the rendered message string).
     * If any of the codes we recognize is present, sets a flag so that
     * hide_login_errors() lets the message through. Matching by code is
     * locale-independent — checking the message string would break on
     * translated sites because __() returns the translation, not the
     * original English text.
     *
     * @param WP_Error $errors      Errors object.
     * @param string   $redirect_to Redirect URL.
     * @return WP_Error
     */
    public function detect_specific_login_error( $errors, $redirect_to ) {
        // wp_login_errors only fires for the login action, so reaching this
        // method means we are on the login screen — not register, lost-password
        // or reset-password, where masking the message makes no sense.
        $this->in_login_context = true;

        if ( ! ( $errors instanceof WP_Error ) || ! $errors->has_errors() ) {
            return $errors;
        }

        $allowed_codes = array(
            // Login Security
            'vigilante_lockout',
            // User Security
            'vigilante_force_reset',
            // pending_approval, email_not_verified and session_limit_exceeded
            // are deliberately NOT here since 2.11.0: they are only raised once
            // the password is correct, so letting them through told an
            // unauthenticated visitor which accounts exist (S10). Those users
            // learn their status from the registration and verification emails.
            // Two-Factor Email
            'no_code',
            'code_expired',
            'code_used',
            // Two-Factor TOTP
            'code_reused',
            'invalid_format',
            'not_configured',
            'decrypt_failed',
            'invalid_backup',
            'no_backup_codes',
            'corrupt_data',
        );

        foreach ( $errors->get_error_codes() as $code ) {
            if ( in_array( $code, $allowed_codes, true ) ) {
                $this->show_specific_login_error = true;
                break;
            }
        }

        return $errors;
    }

    /**
     * Hide login error messages
     *
     * Only masks errors on the login action. Register, lost-password and
     * reset-password share the login_errors filter but must keep their real
     * validation messages.
     *
     * @param string $error Error message.
     * @return string
     */
    public function hide_login_errors( $error ) {
        // The login_errors filter is fired by login_header() on every
        // wp-login.php screen, not just the login form. On register,
        // lost-password and reset-password the generic "Invalid username or
        // password" is meaningless, so only mask when we are actually on the
        // login action (detect_specific_login_error, hooked to the
        // login-only wp_login_errors filter, sets this flag).
        if ( ! $this->in_login_context ) {
            return $error;
        }

        // Primary check: a recognized Vigilant error code was seen on the
        // wp_login_errors filter — let the message through verbatim.
        if ( $this->show_specific_login_error ) {
            return $error;
        }

        // Fallback: English string match. Kept for cases where the message
        // arrives without going through wp_login_errors (e.g. a third-party
        // plugin filtering 'login_errors' directly), and as a safety net for
        // any allowed code we may have missed in detect_specific_login_error().
        // Note: this fallback won't match on translated sites — the
        // code-based check above is the locale-safe path.
        $allowed_patterns = array(
            'vigilante_lockout',
            // The pending-approval, unverified-email and session-limit strings
            // were removed in 2.11.0 for the same reason as their codes above (S10).
            'verification code',
            'authenticator app',
            'two-factor',
            'grace period',
            'Password reset required',
        );

        foreach ( $allowed_patterns as $pattern ) {
            if ( stripos( $error, $pattern ) !== false ) {
                return $error;
            }
        }

        return __( '<strong>Error</strong>: Invalid username or password.', 'vigilante' );
    }

    /**
     * Remove shake animation error codes
     *
     * Keeps Vigilante-specific error codes to show the shake animation
     *
     * @param array $codes Error codes.
     * @return array
     */
    public function remove_shake_errors( $codes ) {
        // Keep shake for Vigilante-specific errors that indicate real problems
        // Do NOT include 2FA codes - the form transition should be smooth.
        // The three account-status codes are not here either since 2.11.0: a
        // shake that only plays for existing accounts is the same tell as the
        // message it replaced (S10).
        return array(
            'vigilante_lockout',
            'vigilante_force_reset',
        );
    }


    /**
     * Disable XML-RPC pingback method
     *
     * @param array $methods XML-RPC methods.
     * @return array
     */
    /**
     * Notify admin of admin login
     *
     * @param string  $user_login Username.
     * @param WP_User $user       User object.
     */
    public function notify_admin_login( $user_login, $user ) {
        // Only notify for admin users
        if ( ! user_can( $user, 'administrator' ) ) {
            return;
        }

        $ip = $this->database->get_client_ip();
        $to = $this->get_notification_email();

        $site_name = get_bloginfo( 'name' );
        $subject = sprintf(
            /* translators: 1: Site name, 2: Username */
            __( '[%1$s] Administrator login: %2$s', 'vigilante' ),
            $site_name,
            $user_login
        );

        $body  = Vigilante_Email_Template::p( __( 'An administrator login has been detected on your site.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::data_table( array(
            __( 'User', 'vigilante' )       => $user_login,
            __( 'IP address', 'vigilante' ) => $ip,
            __( 'Date/Time', 'vigilante' )  => wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ),
        ) );
        $body .= Vigilante_Email_Template::warning_box( __( 'If this was not you, please check your site security immediately.', 'vigilante' ) );

        Vigilante_Email_Template::send( $to, $subject, __( 'Administrator login detected', 'vigilante' ), $body );
    }

    /**
     * Send lockout notification email
     *
     * @param string $ip       IP address.
     * @param string $username Username.
     * @param int    $attempts Number of attempts.
     * @param int    $duration Lockout duration in seconds.
     */
    private function send_lockout_notification( $ip, $username, $attempts, $duration ) {
        $to = $this->get_notification_email();
        $site_name = get_bloginfo( 'name' );

        $subject = sprintf(
            /* translators: %s: Site name */
            __( '[%s] Login lockout triggered', 'vigilante' ),
            $site_name
        );

        $body  = Vigilante_Email_Template::alert_box( __( 'A login lockout has been triggered on your site. The IP address has been temporarily blocked.', 'vigilante' ) );
        $body .= Vigilante_Email_Template::data_table( array(
            __( 'IP address', 'vigilante' )       => $ip,
            __( 'Username attempted', 'vigilante' ) => $username,
            __( 'Failed attempts', 'vigilante' )  => (string) $attempts,
            __( 'Lockout duration', 'vigilante' ) => ceil( $duration / 60 ) . ' ' . __( 'minutes', 'vigilante' ),
            __( 'Date/Time', 'vigilante' )        => wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ),
        ) );
        $body .= Vigilante_Email_Template::button( admin_url( 'admin.php?page=vigilante&tab=login' ), __( 'View lockouts', 'vigilante' ) );

        Vigilante_Email_Template::send( $to, $subject, __( 'Login lockout triggered', 'vigilante' ), $body, true );
    }

    /**
     * Show remaining attempts on login form
     */
    public function show_remaining_attempts() {
        $ip = $this->database->get_client_ip();

        if ( $this->is_ip_whitelisted( $ip ) ) {
            return;
        }

        $max_attempts = absint( $this->options['max_attempts'] ?? 5 );
        $failed_count = $this->database->get_failed_attempt_count( $ip, 60 );

        if ( $failed_count > 0 && $failed_count < $max_attempts ) {
            $remaining = $max_attempts - $failed_count;
            ?>
            <p class="vigilante-login-warning" style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin-bottom: 15px;">
                <?php
                printf(
                    /* translators: %d: Number of remaining attempts */
                    esc_html( _n(
                        'Warning: %d login attempt remaining before lockout.',
                        'Warning: %d login attempts remaining before lockout.',
                        $remaining,
                        'vigilante'
                    ) ),
                    absint( $remaining )
                );
                ?>
            </p>
            <?php
        }
    }

    /**
     * Check if IP is whitelisted
     *
     * @param string $ip IP address.
     * @return bool
     */
    private function is_ip_whitelisted( $ip ) {
        $whitelist = $this->options['ip_whitelist'] ?? array();

        return Vigilante_IP_Utils::in_list( $ip, $whitelist );
    }

    /**
     * Turn away an anonymous wp-admin request before WordPress finishes booting
     *
     * The modules are built on init priority 1, so a request that was going to
     * be refused had already paid for the whole boot: the theme, every plugin
     * and every init callback. Measured on a real site, a rejected
     * /wp-admin/index.php cost as much as serving a page.
     *
     * Only the case that can be judged with certainty this early is handled
     * here, an anonymous GET with no session cookie at all; everything else
     * falls through to the usual path untouched. The cookie is only checked for
     * presence: resolving the user here would run is_user_logged_in() before
     * other plugins register their determine_current_user filters, which is how
     * token, JWT and SSO logins are wired.
     *
     * @since 2.9.9
     *
     * @param array $options The plugin options, already read by the caller.
     */
    public static function maybe_block_hidden_admin_early( $options ) {
        if ( self::is_open_admin_endpoint() ) {
            return;
        }

        if ( '' === sanitize_title( $options['login_security']['custom_login_url'] ) ) {
            return;
        }

        if ( self::has_session_cookie() ) {
            return;
        }

        $whitelist = isset( $options['firewall']['ip_whitelist'] ) ? (array) $options['firewall']['ip_whitelist'] : array();

        if ( ! empty( $whitelist ) && Vigilante_IP_Utils::in_list( Vigilante_IP_Utils::get_client_ip(), $whitelist ) ) {
            return;
        }

        /*
         * Last, and only for a request that was about to be turned away: whether
         * anybody is actually there.
         *
         * A remote manager signs its own call with a token and asks for the
         * dashboard before holding any cookie; its connector resolves the user
         * through determine_current_user and only then, on 'init', sets the
         * cookie and redirects. Turning the request away here, three hooks
         * earlier, means the connector never reaches the point where it would
         * have logged itself in, so it reads the 404 as a site that is broken
         * and retries the whole job. Observed in the wild with
         * ModularConnector/3.2.1, whose every request landed here.
         *
         * Which is also why this went unnoticed for two releases: a connector
         * that already holds a cookie by the time it asks for the dashboard
         * leaves at has_session_cookie() above and never reaches this line. How
         * many connectors work that way is not something to guess at here; what
         * is certain is that reports only came from sites where one did not.
         *
         * The criterion is the one block_wp_admin_access() has always applied,
         * brought to the door 2.9.9 put in front of it. It costs nothing on the
         * ordinary request, which left long before reaching this line, and
         * nothing on the database either: with no cookie to validate, the three
         * core determine_current_user callbacks all decline without a query. The
         * rejection below already pays for an INSERT into the activity log, and
         * resolves this very same user one step later to record who was refused.
         */
        if ( get_current_user_id() ) {
            return;
        }

        self::log_early_hidden_admin_attempt();

        status_header( 404 );
        nocache_headers();

        /*
         * Deliberately not translated. This runs on plugins_loaded, where asking
         * for a translation triggers the just in time text domain notice of
         * WordPress 6.7 and returns the English string anyway. The reader is an
         * anonymous request to an address that is supposed to look absent.
         */
        wp_die(
            '<h1>Page not found</h1><p>The page you are looking for does not exist.</p>',
            '404 Not Found',
            array(
                'response'  => 404,
                'back_link' => false,
            )
        );
    }

    /**
     * Whether the request carries a WordPress session cookie, without resolving it
     *
     * @since 2.9.9
     *
     * @return bool
     */
    private static function has_session_cookie() {
        if ( defined( 'LOGGED_IN_COOKIE' ) && isset( $_COOKIE[ LOGGED_IN_COOKIE ] ) ) {
            return true;
        }

        foreach ( array_keys( (array) $_COOKIE ) as $name ) {
            if ( 0 === strpos( (string) $name, 'wordpress_logged_in_' ) || 0 === strpos( (string) $name, 'wordpress_sec_' ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Record an early rejection in the activity log
     *
     * @since 2.9.9
     */
    private static function log_early_hidden_admin_attempt() {
        require_once VIGILANTE_INCLUDES_DIR . 'class-settings.php';
        require_once VIGILANTE_INCLUDES_DIR . 'class-database.php';
        require_once VIGILANTE_INCLUDES_DIR . 'class-activity-log.php';

        $request = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

        $activity_log = new Vigilante_Activity_Log( new Vigilante_Settings(), new Vigilante_Database() );
        $activity_log->log(
            'login',
            'hidden_admin_access',
            'Attempt to access hidden wp-admin',
            array( 'request_uri' => $request ),
            'warning'
        );
    }

    /**
     * Whether the current request comes from an IP that may bypass the
     * hidden wp-admin masking.
     *
     * Reads the firewall's global IP whitelist (the visible "IP whitelist"
     * box) so trusted services such as MainWP or ManageWP, which reach
     * wp-admin without a WordPress session cookie, are not turned away with
     * a 404. This relaxes only the URL masking, never authentication: an
     * exempt IP still has to log in normally.
     *
     * wp-admin only, and that is the point. Until 2.9.9 the same exemption
     * also applied to the two wp-login.php paths, where it did not serve that
     * purpose and did real harm: block_wp_login_access() handed the real login
     * form to any whitelisted IP with the custom login URL active, and
     * block_login_shortcuts() is precisely what stops core's
     * wp_redirect_admin_locations() from answering /login with a 302 to
     * wp_login_url(), which under a custom login URL is the secret slug. So
     * exempting it did not merely expose the form, it handed the slug over in
     * the Location header. Remote managers never needed either one: both
     * blockers already let every POST through, which is how they authenticate.
     *
     * @return bool
     */
    private function is_ip_exempt_from_hiding() {
        $whitelist = $this->settings->get_option( 'firewall', 'ip_whitelist', array() );

        if ( empty( $whitelist ) ) {
            return false;
        }

        return Vigilante_IP_Utils::in_list( $this->database->get_client_ip(), $whitelist );
    }

    /**
     * Get notification email
     *
     * @return string
     */
    /**
     * Get notification recipients (centralized)
     *
     * @return array Array of email addresses.
     */
    private function get_notification_email() {
        return Vigilante_Email_Template::get_admin_recipients();
    }

    /**
     * Manually clear lockout for an IP
     *
     * @param string $ip IP address.
     * @return bool
     */
    public function clear_lockout( $ip ) {
        return $this->database->clear_lockout( $ip );
    }

    /**
     * Get currently locked out IPs
     *
     * @return array
     */
    public function get_locked_out_ips() {
        return $this->database->get_locked_out_ips();
    }

    /**
     * Get login statistics
     *
     * @param int $days Days to look back.
     * @return array
     */
    public function get_statistics( $days = 7 ) {
        global $wpdb;

        $table = esc_sql( $this->database->get_login_attempts_table() );
        $since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $stats = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT 
                    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_attempts,
                    COUNT(CASE WHEN status = 'lockout' THEN 1 END) as lockouts,
                    COUNT(DISTINCT ip_address) as unique_ips,
                    COUNT(DISTINCT username) as unique_usernames
                FROM `{$table}`
                WHERE last_attempt >= %s",
                $since
            ),
            ARRAY_A
        );
        // phpcs:enable

        return $stats ? $stats : array(
            'failed_attempts'  => 0,
            'lockouts'         => 0,
            'unique_ips'       => 0,
            'unique_usernames' => 0,
        );
    }
}

/**
 * Disabled XML-RPC Server class
 */
class Vigilante_Disabled_XMLRPC_Server {
    /**
     * Constructor - return error for any request
     */
    public function __construct() {
        // Return error for any XML-RPC request
        header( 'HTTP/1.1 403 Forbidden' );
        header( 'Content-Type: text/plain' );
        die( 'XML-RPC is disabled' );
    }
}