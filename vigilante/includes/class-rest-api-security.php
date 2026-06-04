<?php
/**
 * REST API Security Class
 *
 * Manages REST API access restrictions
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Rest_Api_Security
 *
 * Controls access to WordPress REST API endpoints
 */
class Vigilante_Rest_Api_Security {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * REST API options
     *
     * @var array
     */
    private $options;

    /**
     * Constructor
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    public function __construct( $settings ) {
        $this->settings = $settings;
        $this->options  = $settings->get_section( 'rest_api_security' );

        if ( empty( $this->options['enabled'] ) ) {
            return;
        }

        // Apply REST API restrictions
        add_filter( 'rest_authentication_errors', array( $this, 'restrict_rest_api' ), 99 );

        // Block user enumeration
        if ( ! empty( $this->options['block_user_enumeration'] ) ) {
            add_filter( 'rest_endpoints', array( $this, 'restrict_user_endpoints' ) );
        }

        // Disable JSONP
        if ( ! empty( $this->options['disable_jsonp'] ) ) {
            add_filter( 'rest_jsonp_enabled', '__return_false' );
        }
    }

    /**
     * Restrict REST API access based on settings
     *
     * @param WP_Error|null|bool $result Current authentication status.
     * @return WP_Error|null|bool
     */
    public function restrict_rest_api( $result ) {
        // If already an error, return it
        if ( is_wp_error( $result ) ) {
            return $result;
        }

        // Logged in users always have access
        if ( is_user_logged_in() ) {
            return $result;
        }

        // Get current mode
        $mode = $this->options['mode'] ?? 'selective';

        // Open mode - allow all
        if ( 'open' === $mode ) {
            return $result;
        }

        // Authenticated only - block all unauthenticated except hard-coded
        // essentials (oEmbed, Site Health) and endpoints from compatible
        // plugins. Does NOT honour the selective-mode "public list".
        if ( 'authenticated_only' === $mode ) {
            if ( $this->is_allowed_unauthenticated_endpoint() ) {
                return $result;
            }

            return new WP_Error(
                'rest_not_logged_in',
                'REST API access requires authentication.',
                array( 'status' => 401 )
            );
        }

        // Selective mode - allow plugin-compat endpoints and the user-managed
        // "public" list, block anything in protected_endpoints, let everything
        // else through.
        if ( 'selective' === $mode ) {
            if ( $this->is_plugin_compatibility_endpoint() ) {
                return $result;
            }

            if ( $this->is_selective_public_endpoint() ) {
                return $result;
            }

            if ( $this->is_protected_endpoint() ) {
                return new WP_Error(
                    'rest_forbidden',
                    'This endpoint requires authentication.',
                    array( 'status' => 403 )
                );
            }
        }

        return $result;
    }

    /**
     * Check if current request is to a protected endpoint
     *
     * @return bool
     */
    private function is_protected_endpoint() {
        $current_route = $this->get_current_route();

        if ( empty( $current_route ) ) {
            return false;
        }

        $protected = $this->options['protected_endpoints'] ?? array();

        foreach ( $protected as $endpoint ) {
            $endpoint = trim( $endpoint );
            if ( empty( $endpoint ) ) {
                continue;
            }
            // Prefix match: /wp/v2/users matches /wp/v2/users and /wp/v2/users/123
            if ( strpos( $current_route, $endpoint ) === 0 ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if current route matches one of the user-managed "publicly allowed"
     * endpoints used by selective mode. Defaults: /wp/v2/posts, /wp/v2/pages,
     * /wp/v2/categories, /wp/v2/tags, /oembed/.
     *
     * Kept separate from plugin-compatibility so the two reasons for letting
     * a request through stay distinguishable.
     *
     * @return bool
     */
    private function is_selective_public_endpoint() {
        $current_route = $this->get_current_route();
        if ( empty( $current_route ) ) {
            return false;
        }

        $allowed_public = $this->options['allowed_public_endpoints'] ?? array();

        foreach ( $allowed_public as $endpoint ) {
            if ( strpos( $current_route, $endpoint ) === 0 ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Backward-compatible wrapper: combines compat plugin endpoints and the
     * selective-mode public list. Kept in case any external code calls it.
     *
     * @return bool
     */
    private function is_plugin_allowed_endpoint() {
        return $this->is_plugin_compatibility_endpoint() || $this->is_selective_public_endpoint();
    }

    /**
     * Check if the current route matches a known plugin-compatibility prefix
     * (WooCommerce, Contact Form 7, Gravity Forms, WPForms, Elementor, Jetpack).
     *
     * Only returns true when the corresponding compatibility toggle is on. Used
     * by both is_plugin_allowed_endpoint() (selective mode) and
     * is_allowed_unauthenticated_endpoint() (authenticated_only mode), so that
     * authenticated_only doesn't accidentally let public endpoints through but
     * still doesn't break installed e-commerce / form plugins that legitimately
     * call REST without a logged-in user.
     *
     * @return bool
     */
    private function is_plugin_compatibility_endpoint() {
        $current_route = $this->get_current_route();

        if ( empty( $current_route ) ) {
            return false;
        }

        $compatibility = $this->options['plugin_compatibility'] ?? array();

        // WooCommerce
        if ( ! empty( $compatibility['woocommerce'] ) ) {
            if ( preg_match( '/^\/(wc|wc-blocks|wc-auth)\//i', $current_route ) ) {
                return true;
            }
        }

        // Contact Form 7
        if ( ! empty( $compatibility['contact_form_7'] ) ) {
            if ( preg_match( '/^\/contact-form-7\//i', $current_route ) ) {
                return true;
            }
        }

        // Gravity Forms
        if ( ! empty( $compatibility['gravity_forms'] ) ) {
            if ( preg_match( '/^\/(gf|gravityforms)\//i', $current_route ) ) {
                return true;
            }
        }

        // WPForms
        if ( ! empty( $compatibility['wpforms'] ) ) {
            if ( preg_match( '/^\/wpforms\//i', $current_route ) ) {
                return true;
            }
        }

        // Elementor
        if ( ! empty( $compatibility['elementor'] ) ) {
            if ( preg_match( '/^\/elementor\//i', $current_route ) ) {
                return true;
            }
        }

        // Jetpack
        if ( ! empty( $compatibility['jetpack'] ) ) {
            if ( preg_match( '/^\/jetpack\//i', $current_route ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if endpoint is allowed for unauthenticated access (basic needs)
     *
     * @return bool
     */
    private function is_allowed_unauthenticated_endpoint() {
        $current_route = $this->get_current_route();

        // Always allow these for basic functionality
        $always_allowed = array(
            '/oembed/',      // oEmbed for embeds
            '/wp-site-health/', // Site health
        );

        foreach ( $always_allowed as $endpoint ) {
            if ( strpos( $current_route, $endpoint ) === 0 ) {
                return true;
            }
        }

        // In authenticated_only mode we do NOT honour the 'allowed_public_endpoints'
        // list — that list is the "what counts as public" definition for the
        // selective mode. authenticated_only is meant to be strict, so only
        // hard-coded essentials above plus compatibility endpoints from
        // installed plugins are let through.
        return $this->is_plugin_compatibility_endpoint();
    }

    /**
     * Get current REST API route
     *
     * @return string
     */
    private function get_current_route() {
        $rest_route = '';

        if ( isset( $GLOBALS['wp']->query_vars['rest_route'] ) ) {
            $rest_route = $GLOBALS['wp']->query_vars['rest_route'];
        } elseif ( isset( $_GET['rest_route'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $rest_route = sanitize_text_field( wp_unslash( $_GET['rest_route'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        }

        // Clean up route
        $rest_route = '/' . ltrim( $rest_route, '/' );

        return $rest_route;
    }

    /**
     * Restrict user endpoints for unauthenticated users
     *
     * @param array $endpoints REST endpoints.
     * @return array
     */
    public function restrict_user_endpoints( $endpoints ) {
        if ( is_user_logged_in() ) {
            return $endpoints;
        }

        // Remove user endpoints
        $user_endpoints = array(
            '/wp/v2/users',
            '/wp/v2/users/(?P<id>[\d]+)',
            '/wp/v2/users/me',
        );

        foreach ( $user_endpoints as $endpoint ) {
            if ( isset( $endpoints[ $endpoint ] ) ) {
                unset( $endpoints[ $endpoint ] );
            }
        }

        return $endpoints;
    }

    /**
     * Block author query parameter enumeration
     */
    public function block_author_enumeration() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( ! is_admin() && isset( $_GET['author'] ) ) {
            wp_safe_redirect( home_url(), 301 );
            exit;
        }
    }

    /**
     * Get REST API security status
     *
     * @return array
     */
    public function get_status() {
        return array(
            'enabled'              => ! empty( $this->options['enabled'] ),
            'mode'                 => $this->options['mode'] ?? 'selective',
            'user_enum_blocked'    => ! empty( $this->options['block_user_enumeration'] ),
            'jsonp_disabled'       => ! empty( $this->options['disable_jsonp'] ),
            'protected_endpoints'  => count( $this->options['protected_endpoints'] ?? array() ),
            'allowed_endpoints'    => count( $this->options['allowed_public_endpoints'] ?? array() ),
        );
    }

    /**
     * Test if a specific endpoint would be accessible
     *
     * @param string $endpoint Endpoint to test.
     * @param bool   $authenticated Whether user is authenticated.
     * @return array Test result.
     */
    public function test_endpoint_access( $endpoint, $authenticated = false ) {
        $result = array(
            'endpoint'      => $endpoint,
            'authenticated' => $authenticated,
            'allowed'       => false,
            'reason'        => '',
        );

        // Logged in users always have access
        if ( $authenticated ) {
            $result['allowed'] = true;
            $result['reason'] = 'Authenticated users have full access';
            return $result;
        }

        $mode = $this->options['mode'] ?? 'selective';

        if ( 'open' === $mode ) {
            $result['allowed'] = true;
            $result['reason'] = 'REST API is in open mode';
            return $result;
        }

        if ( 'authenticated_only' === $mode ) {
            $result['allowed'] = false;
            $result['reason'] = 'REST API requires authentication';
            return $result;
        }

        // Selective mode
        $protected = $this->options['protected_endpoints'] ?? array();
        
        foreach ( $protected as $protected_endpoint ) {
            $protected_endpoint = trim( $protected_endpoint );
            if ( empty( $protected_endpoint ) ) {
                continue;
            }
            if ( strpos( $endpoint, $protected_endpoint ) === 0 ) {
                $result['allowed'] = false;
                $result['reason'] = 'Endpoint is protected';
                return $result;
            }
        }

        $result['allowed'] = true;
        $result['reason'] = 'Endpoint is not protected';
        return $result;
    }
}