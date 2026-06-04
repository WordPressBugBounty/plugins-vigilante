<?php
/**
 * Head Cleaner Class
 *
 * Handles removal of unnecessary head tags that expose information
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Head_Cleaner
 *
 * Removes unnecessary elements from wp_head for security purposes
 */
class Vigilante_Head_Cleaner {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Head cleaner options
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
        $this->options  = $settings->get_section( 'wp_hardening' );

        $this->init_hooks();
    }

    /**
     * Initialize hooks
     */
    private function init_hooks() {
        add_action( 'init', array( $this, 'clean_head' ) );
    }

    /**
     * Clean up wp_head output
     */
    public function clean_head() {
        // Remove WordPress generator meta tag (hides version)
        if ( ! empty( $this->options['remove_wp_generator'] ) ) {
            remove_action( 'wp_head', 'wp_generator' );
            add_filter( 'the_generator', '__return_empty_string' );
        }

        // Strip the WordPress version from enqueued script/style URLs
        // (?ver=X.Y.Z). The "Remove Generator" option above only hides
        // the <meta name="generator"> tag, leaving the version visible in
        // every asset URL.
        if ( ! empty( $this->options['remove_wp_version_assets'] ) ) {
            add_filter( 'style_loader_src', array( $this, 'strip_wp_version_from_src' ), 9999, 1 );
            add_filter( 'script_loader_src', array( $this, 'strip_wp_version_from_src' ), 9999, 1 );
        }

        // Remove RSD link (not needed for most sites)
        if ( ! empty( $this->options['remove_rsd_link'] ) ) {
            remove_action( 'wp_head', 'rsd_link' );
        }

        // Remove Windows Live Writer manifest (obsolete)
        if ( ! empty( $this->options['remove_wlw_manifest'] ) ) {
            remove_action( 'wp_head', 'wlwmanifest_link' );
        }

        // Remove shortlink
        if ( ! empty( $this->options['remove_shortlink'] ) ) {
            remove_action( 'wp_head', 'wp_shortlink_wp_head', 10 );
            remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
        }

        // Remove adjacent posts links
        if ( ! empty( $this->options['remove_adjacent_posts'] ) ) {
            remove_action( 'wp_head', 'adjacent_posts_rel_link_wp_head', 10 );
            remove_action( 'wp_head', 'adjacent_posts_rel_link', 10 );
            remove_action( 'wp_head', 'start_post_rel_link', 10 );
            remove_action( 'wp_head', 'parent_post_rel_link', 10 );
            remove_action( 'wp_head', 'index_rel_link' );
        }

        // Remove REST API link from header
        if ( ! empty( $this->options['remove_rest_api_link'] ) ) {
            remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
            remove_action( 'template_redirect', 'rest_output_link_header', 11 );
        }

        // Remove oEmbed links
        if ( ! empty( $this->options['remove_oembed_links'] ) ) {
            remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
            remove_action( 'wp_head', 'wp_oembed_add_host_js' );
        }
    }

    /**
     * Strip the WordPress version from an enqueued asset URL.
     *
     * Only removes the "ver" query argument when it matches the current
     * WordPress version, so versions injected by plugins/themes (used for
     * legitimate cache busting) are preserved.
     *
     * @param string $src Asset URL.
     * @return string Filtered URL.
     */
    public function strip_wp_version_from_src( $src ) {
        if ( ! is_string( $src ) || '' === $src || false === strpos( $src, 'ver=' ) ) {
            return $src;
        }

        $wp_version = get_bloginfo( 'version' );
        if ( ! $wp_version ) {
            return $src;
        }

        // Match both ?ver=X.Y.Z and &ver=X.Y.Z exactly. Use the WP helper so
        // we cover URL-encoded variants and avoid touching unrelated arguments.
        $parts = wp_parse_url( $src );
        if ( empty( $parts['query'] ) ) {
            return $src;
        }

        parse_str( $parts['query'], $query );
        if ( ! isset( $query['ver'] ) || (string) $query['ver'] !== (string) $wp_version ) {
            return $src;
        }

        return remove_query_arg( 'ver', $src );
    }

    /**
     * Get list of removable items for security
     *
     * @return array
     */
    public static function get_removable_items() {
        return array(
            'remove_wp_generator'      => __( 'WordPress version meta tag', 'vigilante' ),
            'remove_wp_version_assets' => __( 'WordPress version in asset URLs (?ver=)', 'vigilante' ),
            'remove_rsd_link'          => __( 'RSD (Really Simple Discovery) link', 'vigilante' ),
            'remove_wlw_manifest'      => __( 'Windows Live Writer manifest link', 'vigilante' ),
            'remove_shortlink'         => __( 'Shortlink', 'vigilante' ),
            'remove_adjacent_posts'    => __( 'Adjacent posts rel links', 'vigilante' ),
            'remove_rest_api_link'     => __( 'REST API link', 'vigilante' ),
            'remove_oembed_links'      => __( 'oEmbed discovery links', 'vigilante' ),
        );
    }
}
