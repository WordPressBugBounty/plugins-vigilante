<?php
/**
 * Comment Security Class
 *
 * Handles comment security settings and spam protection
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Comment_Security
 *
 * Manages comment security features
 */
class Vigilante_Comment_Security {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Comment security options
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
        // XML-RPC exposure: one three-way setting. Lives here rather than under
        // Login because this class already owns the xmlrpc_methods filter, and
        // because the module gate for this tab is modules.wp_hardening: keeping
        // the setting and the code it drives under the same gate avoids the trap
        // of a switch that looks on while the class that reads it never runs.
        $xmlrpc_mode = self::resolve_xmlrpc_mode( $this->settings );

        if ( 'full' === $xmlrpc_mode ) {
            add_filter( 'xmlrpc_enabled', '__return_false' );
            add_filter( 'wp_xmlrpc_server_class', array( $this, 'disable_xmlrpc_server' ) );
            remove_action( 'wp_head', 'rsd_link' );
            remove_action( 'wp_head', 'wlwmanifest_link' );
        } elseif ( 'pingback' === $xmlrpc_mode ) {
            add_filter( 'xmlrpc_methods', array( $this, 'disable_pingback_methods' ) );
        }

        // Disable pingbacks/trackbacks
        if ( ! empty( $this->options['disable_pingbacks'] ) ) {
            add_filter( 'xmlrpc_methods', array( $this, 'disable_pingback_methods' ) );
            add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
            add_filter( 'pings_open', '__return_false', 9999 );
        }

        if ( ! empty( $this->options['disable_trackbacks'] ) ) {
            add_filter( 'pings_open', '__return_false', 9999 );
        }

        // Close old comments (high priority to override WP native if needed)
        if ( ! empty( $this->options['close_old_comments'] ) ) {
            add_filter( 'comments_open', array( $this, 'close_old_comments' ), 9999, 2 );
        }

        // Honeypot
        if ( ! empty( $this->options['honeypot_enabled'] ) ) {
            add_action( 'comment_form', array( $this, 'add_honeypot_field' ) );
            add_filter( 'preprocess_comment', array( $this, 'check_honeypot' ) );
        }

        // Link limit check
        if ( ! empty( $this->options['link_limit'] ) ) {
            add_filter( 'preprocess_comment', array( $this, 'check_link_limit' ) );
        }

        // Block patterns
        if ( ! empty( $this->options['block_patterns'] ) ) {
            add_filter( 'preprocess_comment', array( $this, 'check_blocked_patterns' ) );
        }

        // Block IPs
        if ( ! empty( $this->options['block_ips'] ) ) {
            add_filter( 'preprocess_comment', array( $this, 'check_blocked_ips' ) );
        }
    }

    /**
     * Disable pingback XML-RPC methods
     *
     * @param array $methods XML-RPC methods.
     * @return array
     */
    /**
     * Resolve the XML-RPC mode.
     *
     * The setting used to be two independent checkboxes under Login that could
     * be on at the same time and contradict each other ("disable everything"
     * plus "disable only pingback"). It is now a single three-way choice stored
     * in wp_hardening.xmlrpc_mode, next to the pingback settings it relates to.
     *
     * Sites upgrading have neither, only the old pair under login_security, so
     * their choice is read from there and nothing changes for them until they
     * save the tab. An install with none of the three gets 'full', which is what
     * the old defaults did (disable_xmlrpc shipped on and took precedence).
     *
     * Public and static so this class, the settings screen and the Security
     * Check all resolve the value the same way and cannot drift apart.
     *
     * @param Vigilante_Settings $settings Settings instance.
     * @return string 'full', 'pingback' or 'none'.
     */
    public static function resolve_xmlrpc_mode( $settings ) {
        $hardening = $settings->get_section( 'wp_hardening' );
        $mode      = isset( $hardening['xmlrpc_mode'] ) ? (string) $hardening['xmlrpc_mode'] : '';

        if ( in_array( $mode, array( 'full', 'pingback', 'none' ), true ) ) {
            return $mode;
        }

        // Legacy pair under Login, only meaningful when one of them was stored.
        $login = $settings->get_section( 'login_security' );
        if ( array_key_exists( 'disable_xmlrpc', $login )
            || array_key_exists( 'disable_xmlrpc_pingback', $login ) ) {
            if ( ! empty( $login['disable_xmlrpc'] ) ) {
                return 'full';
            }
            if ( ! empty( $login['disable_xmlrpc_pingback'] ) ) {
                return 'pingback';
            }
            return 'none';
        }

        return 'full';
    }

    /**
     * Replace the XML-RPC server class with one that answers nothing.
     *
     * @return string
     */
    public function disable_xmlrpc_server() {
        return 'wp_xmlrpc_server_disabled';
    }

    public function disable_pingback_methods( $methods ) {
        unset( $methods['pingback.ping'] );
        unset( $methods['pingback.extensions.getPingbacks'] );
        return $methods;
    }

    /**
     * Remove X-Pingback header
     *
     * @param array $headers HTTP headers.
     * @return array
     */
    public function remove_pingback_header( $headers ) {
        unset( $headers['X-Pingback'] );
        return $headers;
    }

    /**
     * Close comments on old posts
     *
     * @param bool $open    Whether comments are open.
     * @param int  $post_id Post ID.
     * @return bool
     */
    public function close_old_comments( $open, $post_id ) {
        $post = get_post( $post_id );

        if ( ! $post ) {
            return $open;
        }

        // Don't close comments on WooCommerce products (reviews)
        if ( 'product' === $post->post_type ) {
            return 'open' === $post->comment_status;
        }

        if ( ! $open ) {
            return $open;
        }

        $days = absint( $this->options['close_after_days'] ?? 30 );
        $post_date = strtotime( $post->post_date );
        $cutoff    = strtotime( "-{$days} days" );

        if ( $post_date < $cutoff ) {
            return false;
        }

        return $open;
    }

    /**
     * Add honeypot field to comment form
     */
    public function add_honeypot_field() {
        ?>
        <p class="vigilante-hp-field" style="display:none !important;">
            <label for="vigilante_hp_website"><?php esc_html_e( 'Website', 'vigilante' ); ?></label>
            <input type="text" name="vigilante_hp_website" id="vigilante_hp_website" value="" autocomplete="off" tabindex="-1" />
        </p>
        <?php
    }

    /**
     * Check honeypot field
     *
     * @param array $commentdata Comment data.
     * @return array
     */
    public function check_honeypot( $commentdata ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( ! empty( $_POST['vigilante_hp_website'] ) ) {
            wp_die(
                esc_html__( 'Your comment could not be submitted. Please try again.', 'vigilante' ),
                esc_html__( 'Comment Blocked', 'vigilante' ),
                array( 'response' => 403, 'back_link' => true )
            );
        }

        return $commentdata;
    }

    /**
     * Check for excessive links in comment
     *
     * @param array $commentdata Comment data.
     * @return array
     */
    public function check_link_limit( $commentdata ) {
        $limit = absint( $this->options['link_limit'] ?? 2 );
        $content = $commentdata['comment_content'];

        // Count links
        $link_count = preg_match_all( '/<a\s/i', $content, $matches );
        $link_count += preg_match_all( '/https?:\/\//i', $content, $matches );

        // Remove duplicates from the count
        $link_count = $link_count / 2;

        if ( $link_count > $limit ) {
            wp_die(
                sprintf(
                    /* translators: %d: Maximum number of links allowed */
                    esc_html__( 'Your comment contains too many links. Maximum allowed: %d', 'vigilante' ),
                    absint( $limit )
                ),
                esc_html__( 'Comment Blocked', 'vigilante' ),
                array( 'response' => 403, 'back_link' => true )
            );
        }

        return $commentdata;
    }

    /**
     * Check for blocked patterns in comment
     *
     * @param array $commentdata Comment data.
     * @return array
     */
    public function check_blocked_patterns( $commentdata ) {
        $patterns = $this->options['block_patterns'] ?? array();

        if ( empty( $patterns ) ) {
            return $commentdata;
        }

        $content = strtolower( $commentdata['comment_content'] . ' ' . $commentdata['comment_author'] );

        foreach ( $patterns as $pattern ) {
            $pattern = trim( strtolower( $pattern ) );
            if ( ! empty( $pattern ) && strpos( $content, $pattern ) !== false ) {
                wp_die(
                    esc_html__( 'Your comment could not be submitted. It contains blocked content.', 'vigilante' ),
                    esc_html__( 'Comment Blocked', 'vigilante' ),
                    array( 'response' => 403, 'back_link' => true )
                );
            }
        }

        return $commentdata;
    }

    /**
     * Check for blocked IPs
     *
     * @param array $commentdata Comment data.
     * @return array
     */
    public function check_blocked_ips( $commentdata ) {
        $blocked_ips = $this->options['block_ips'] ?? array();

        if ( empty( $blocked_ips ) ) {
            return $commentdata;
        }

        $commenter_ip = isset( $_SERVER['REMOTE_ADDR'] ) 
            ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) 
            : '';

        foreach ( $blocked_ips as $blocked_ip ) {
            $blocked_ip = trim( $blocked_ip );
            if ( $blocked_ip === $commenter_ip ) {
                wp_die(
                    esc_html__( 'Your comment could not be submitted.', 'vigilante' ),
                    esc_html__( 'Comment Blocked', 'vigilante' ),
                    array( 'response' => 403, 'back_link' => true )
                );
            }
        }

        return $commentdata;
    }

    /**
     * Apply comment security settings to WordPress options
     */
    public function apply_settings() {
        // Disable pingbacks
        if ( ! empty( $this->options['disable_pingbacks'] ) ) {
            update_option( 'default_pingback_flag', 0 );
        }

        // Disable trackbacks
        if ( ! empty( $this->options['disable_trackbacks'] ) ) {
            update_option( 'default_ping_status', 'closed' );
        }

        // Require moderation
        if ( ! empty( $this->options['require_moderation'] ) ) {
            update_option( 'comment_moderation', 1 );
        }

        // Require name and email
        if ( ! empty( $this->options['require_name_email'] ) ) {
            update_option( 'require_name_email', 1 );
        }

        // Require registration
        if ( ! empty( $this->options['require_registration'] ) ) {
            update_option( 'comment_registration', 1 );
        }
    }

    /**
     * Get spam statistics
     *
     * @return array
     */
    public function get_spam_stats() {
        global $wpdb;

        $stats = array(
            'total_comments'   => 0,
            'approved'         => 0,
            'pending'          => 0,
            'spam'             => 0,
            'trash'            => 0,
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $counts = $wpdb->get_results(
            "SELECT comment_approved, COUNT(*) as count FROM {$wpdb->comments} GROUP BY comment_approved",
            ARRAY_A
        );

        foreach ( $counts as $count ) {
            switch ( $count['comment_approved'] ) {
                case '1':
                    $stats['approved'] = absint( $count['count'] );
                    break;
                case '0':
                    $stats['pending'] = absint( $count['count'] );
                    break;
                case 'spam':
                    $stats['spam'] = absint( $count['count'] );
                    break;
                case 'trash':
                    $stats['trash'] = absint( $count['count'] );
                    break;
            }
        }

        $stats['total_comments'] = $stats['approved'] + $stats['pending'] + $stats['spam'] + $stats['trash'];

        return $stats;
    }
}