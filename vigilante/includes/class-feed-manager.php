<?php
/**
 * Feed Manager Class
 *
 * Handles RSS/Atom feed management
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Feed_Manager
 *
 * Manages RSS/Atom feeds
 */
class Vigilante_Feed_Manager {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Feed manager options
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
        // Completely disable feeds
        if ( ! empty( $this->options['disable_feeds'] ) ) {
            add_action( 'do_feed', array( $this, 'disable_feed' ), 1 );
            add_action( 'do_feed_rdf', array( $this, 'disable_feed' ), 1 );
            add_action( 'do_feed_rss', array( $this, 'disable_feed' ), 1 );
            add_action( 'do_feed_rss2', array( $this, 'disable_feed' ), 1 );
            add_action( 'do_feed_atom', array( $this, 'disable_feed' ), 1 );
            
            // Remove feed links from head
            remove_action( 'wp_head', 'feed_links', 2 );
            remove_action( 'wp_head', 'feed_links_extra', 3 );
            
            return;
        }

        // Disable only if no content
        if ( ! empty( $this->options['disable_if_no_content'] ) ) {
            add_action( 'template_redirect', array( $this, 'maybe_disable_feed' ) );
        }

        // Delay feed publication
        if ( ! empty( $this->options['delay_feed_publish'] ) && $this->options['delay_feed_publish'] > 0 ) {
            add_filter( 'posts_where', array( $this, 'delay_feed_posts' ), 10, 2 );
        }

        // Disable comment feeds
        if ( ! empty( $this->options['disable_feed_comments'] ) ) {
            add_action( 'do_feed_rss2_comments', array( $this, 'disable_feed' ), 1 );
            add_action( 'do_feed_atom_comments', array( $this, 'disable_feed' ), 1 );
        }

        // Remove WordPress version from feeds
        if ( ! empty( $this->options['remove_feed_version'] ) ) {
            add_filter( 'the_generator', '__return_empty_string' );
        }
    }

    /**
     * Disable feed - redirect to homepage
     */
    public function disable_feed() {
        wp_safe_redirect( home_url(), 301 );
        exit;
    }

    /**
     * Disable feeds if no content exists
     */
    public function maybe_disable_feed() {
        if ( ! is_feed() ) {
            return;
        }

        $post_count = wp_count_posts( 'post' );
        
        if ( ! $post_count || 0 === (int) $post_count->publish ) {
            wp_safe_redirect( home_url(), 301 );
            exit;
        }
    }

    /**
     * Delay posts from appearing in feeds
     *
     * @param string   $where    WHERE clause.
     * @param WP_Query $wp_query Query object.
     * @return string
     */
    public function delay_feed_posts( $where, $wp_query ) {
        if ( ! $wp_query->is_feed() ) {
            return $where;
        }

        global $wpdb;

        $minutes = absint( $this->options['delay_feed_publish'] );
        $delay = gmdate( 'Y-m-d H:i:s', strtotime( "-{$minutes} minutes" ) );

        $where .= $wpdb->prepare( " AND {$wpdb->posts}.post_date_gmt < %s", $delay );

        return $where;
    }

    /**
     * Get feed statistics
     *
     * @return array
     */
    public function get_feed_stats() {
        $post_count = wp_count_posts( 'post' );

        return array(
            'published_posts' => $post_count ? (int) $post_count->publish : 0,
            'feeds_disabled'  => ! empty( $this->options['disable_feeds'] ),
            'delay_minutes'   => $this->options['delay_feed_publish'] ?? 0,
        );
    }
}
