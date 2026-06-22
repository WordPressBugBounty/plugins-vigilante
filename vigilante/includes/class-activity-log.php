<?php
/**
 * Activity Log Class
 *
 * Handles security event logging with configurable retention.
 * Master switch: modules.activity_log toggle on the dashboard.
 * Per-type flags: log_logins, log_post_changes, etc. in activity_log settings.
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Activity_Log
 *
 * Manages activity logging
 */
class Vigilante_Activity_Log {

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
     * Map event_type to its settings flag.
     * Types not in this map (firewall, system, security, settings) always log.
     *
     * @var array
     */
    private static $type_flag_map = array(
        'login'   => 'log_logins',
        'user'    => 'log_user_changes',
        'content' => 'log_post_changes',
        'plugin'  => 'log_plugin_changes',
        'theme'   => 'log_theme_changes',
        'comment' => 'log_comments',
        'media'   => 'log_media',
        'file'    => 'log_file_changes',
    );

    /**
     * Post IDs already logged in this request (deduplication for post_updated)
     *
     * @var array
     */
    private $logged_post_ids = array();

    /**
     * Constructor
     *
     * @param Vigilante_Settings $settings Settings instance.
     * @param Vigilante_Database $database Database instance.
     */
    public function __construct( $settings, $database ) {
        $this->settings = $settings;
        $this->database = $database;

        // Only register hooks if the module is enabled
        if ( $this->settings->is_module_enabled( 'activity_log' ) ) {
            $this->init_hooks();
        }
    }

    /**
     * Get current activity_log options (fresh from settings, not cached)
     *
     * @return array
     */
    private function get_current_options() {
        return $this->settings->get_section( 'activity_log' );
    }

    /**
     * Initialize logging hooks.
     * These cover events from WordPress core actions.
     * External modules (firewall, login-security, etc.) call log() directly
     * and are filtered by the per-type map in log().
     */
    private function init_hooks() {
        $options = $this->get_current_options();

        // Post changes (status transitions + content edits)
        if ( ! empty( $options['log_post_changes'] ) ) {
            add_action( 'transition_post_status', array( $this, 'log_post_status_change' ), 10, 3 );
            add_action( 'post_updated', array( $this, 'log_post_content_change' ), 10, 3 );
            add_action( 'delete_post', array( $this, 'log_post_delete' ) );
        }

        // Plugin changes (activation, deactivation, install, update, delete)
        if ( ! empty( $options['log_plugin_changes'] ) ) {
            add_action( 'activated_plugin', array( $this, 'log_plugin_activated' ) );
            add_action( 'deactivated_plugin', array( $this, 'log_plugin_deactivated' ) );
            add_action( 'upgrader_process_complete', array( $this, 'log_upgrader_event' ), 10, 2 );
            add_action( 'deleted_plugin', array( $this, 'log_plugin_deleted' ), 10, 2 );
        }

        // Theme changes (switch, install, update via upgrader)
        if ( ! empty( $options['log_theme_changes'] ) ) {
            add_action( 'switch_theme', array( $this, 'log_theme_switch' ), 10, 3 );
            if ( empty( $options['log_plugin_changes'] ) ) {
                // Only add upgrader hook if not already registered by plugin changes
                add_action( 'upgrader_process_complete', array( $this, 'log_upgrader_event' ), 10, 2 );
            }
        }

        // Option changes (blacklist approach)
        if ( ! empty( $options['log_option_changes'] ) ) {
            add_action( 'updated_option', array( $this, 'log_option_update' ), 10, 3 );
        }

        // Comment changes
        if ( ! empty( $options['log_comments'] ) ) {
            add_action( 'wp_insert_comment', array( $this, 'log_comment_insert' ), 10, 2 );
            add_action( 'transition_comment_status', array( $this, 'log_comment_status_change' ), 10, 3 );
            add_action( 'delete_comment', array( $this, 'log_comment_delete' ) );
        }

        // Media uploads and deletions
        if ( ! empty( $options['log_media'] ) ) {
            add_action( 'add_attachment', array( $this, 'log_media_upload' ) );
            add_action( 'delete_attachment', array( $this, 'log_media_delete' ) );
        }
    }

    /**
     * Log an event.
     *
     * Gate checks (in order):
     * 1. Module master switch (modules.activity_log)
     * 2. Per-type flag via $type_flag_map (types not in the map always pass)
     * 3. Sub-check: failed logins respect log_failed_logins
     * 4. User/IP exclusions
     *
     * @param string $type     Event type.
     * @param string $action   Event action.
     * @param string $message  Event message.
     * @param array  $data     Additional data.
     * @param string $severity Severity level: info, warning, critical.
     * @return int|false Log ID or false.
     */
    public function log( $type, $action, $message, $data = array(), $severity = 'info' ) {
        // Gate 1: Module master switch
        if ( ! $this->settings->is_module_enabled( 'activity_log' ) ) {
            return false;
        }

        // Gate 2: Per-type flag
        $current_options = $this->get_current_options();

        if ( isset( self::$type_flag_map[ $type ] ) ) {
            $flag = self::$type_flag_map[ $type ];
            if ( empty( $current_options[ $flag ] ) ) {
                return false;
            }
        }

        // Gate 3: Failed logins sub-check
        if ( 'login' === $type && in_array( $action, array( 'failed', 'lockout' ), true ) ) {
            if ( empty( $current_options['log_failed_logins'] ) ) {
                return false;
            }
        }

        // Gate 4: User/IP exclusions (fresh from settings)
        $user_id = get_current_user_id();

        $excluded_users = $current_options['excluded_users'] ?? array();
        if ( in_array( $user_id, array_map( 'absint', $excluded_users ), true ) ) {
            return false;
        }

        $ip = $this->database->get_client_ip();

        $excluded_ips = $current_options['excluded_ips'] ?? array();
        if ( in_array( $ip, $excluded_ips, true ) ) {
            return false;
        }

        // Extract object info BEFORE storing remainder as extra_data (avoids duplication)
        $object_type = '';
        $object_id   = 0;
        $object_name = '';

        if ( isset( $data['object_type'] ) ) {
            $object_type = $data['object_type'];
            unset( $data['object_type'] );
        }
        if ( isset( $data['object_id'] ) ) {
            $object_id = $data['object_id'];
            unset( $data['object_id'] );
        }
        if ( isset( $data['object_name'] ) ) {
            $object_name = $data['object_name'];
            unset( $data['object_name'] );
        }

        $log_data = array(
            'event_type'    => $type,
            'event_action'  => $action,
            'event_message' => $message,
            'user_id'       => $user_id,
            'ip_address'    => $ip,
            'severity'      => $severity,
            'object_type'   => $object_type,
            'object_id'     => $object_id,
            'object_name'   => $object_name,
            'extra_data'    => $data,
        );

        $log_id = $this->database->insert_activity_log( $log_data );

        if ( $log_id ) {
            /**
             * Fires after a security event passed every gate and was persisted.
             *
             * Lets the Audit Alerts engine react to events without coupling to
             * each module: it only fires for events that were actually logged
             * (module on, type flag on, not excluded).
             *
             * @param string $type     Event type (login, user, plugin, firewall, ...).
             * @param string $action   Event action (failed, created, deactivated, ...).
             * @param string $severity Severity level: info, warning, critical.
             * @param array  $context  Event context: message, user_id, ip,
             *                          object_type, object_id, object_name,
             *                          extra_data, log_id.
             */
            do_action(
                'vigilante_event_logged',
                $type,
                $action,
                $severity,
                array(
                    'message'     => $message,
                    'user_id'     => $user_id,
                    'ip'          => $ip,
                    'object_type' => $object_type,
                    'object_id'   => $object_id,
                    'object_name' => $object_name,
                    'extra_data'  => $data,
                    'log_id'      => $log_id,
                )
            );
        }

        return $log_id;
    }

    // =========================================================================
    // POST / CONTENT EVENTS
    // =========================================================================

    /**
     * Log post status change
     *
     * @param string  $new_status New status.
     * @param string  $old_status Old status.
     * @param WP_Post $post       Post object.
     */
    public function log_post_status_change( $new_status, $old_status, $post ) {
        if ( wp_is_post_autosave( $post ) || wp_is_post_revision( $post ) ) {
            return;
        }
        if ( $new_status === $old_status ) {
            return;
        }

        $skip_types = array( 'nav_menu_item', 'revision', 'attachment' );
        if ( in_array( $post->post_type, $skip_types, true ) ) {
            return;
        }

        // Mark to prevent duplicate from post_updated
        $this->logged_post_ids[ $post->ID ] = true;

        $action   = 'updated';
        $severity = 'info';

        if ( 'auto-draft' === $old_status && 'draft' === $new_status ) {
            $action = 'created';
        } elseif ( 'publish' === $new_status ) {
            $action = 'published';
        } elseif ( 'trash' === $new_status ) {
            $action = 'trashed';
            $severity = 'warning';
        }

        $this->log(
            'content',
            $action,
            sprintf(
                /* translators: 1: Post type, 2: Post title, 3: Old status, 4: New status */
                __( '%1$s "%2$s" status changed: %3$s -> %4$s', 'vigilante' ),
                ucfirst( $post->post_type ),
                $post->post_title,
                $old_status,
                $new_status
            ),
            array(
                'object_type' => $post->post_type,
                'object_id'   => $post->ID,
                'object_name' => $post->post_title,
                'old_status'  => $old_status,
                'new_status'  => $new_status,
            ),
            $severity
        );
    }

    /**
     * Log post content change (edits without status change).
     * Skipped if transition_post_status already logged this post in this request.
     *
     * @param int     $post_id     Post ID.
     * @param WP_Post $post_after  Post object after update.
     * @param WP_Post $post_before Post object before update.
     */
    public function log_post_content_change( $post_id, $post_after, $post_before ) {
        if ( isset( $this->logged_post_ids[ $post_id ] ) ) {
            return;
        }
        if ( wp_is_post_autosave( $post_after ) || wp_is_post_revision( $post_after ) ) {
            return;
        }

        $skip_types = array( 'nav_menu_item', 'revision', 'attachment', 'customize_changeset' );
        if ( in_array( $post_after->post_type, $skip_types, true ) ) {
            return;
        }
        if ( 'auto-draft' === $post_after->post_status ) {
            return;
        }

        // Only log if title, content, or excerpt actually changed
        $changed = (
            $post_before->post_title !== $post_after->post_title ||
            $post_before->post_content !== $post_after->post_content ||
            $post_before->post_excerpt !== $post_after->post_excerpt
        );
        if ( ! $changed ) {
            return;
        }

        $this->log(
            'content',
            'edited',
            sprintf(
                /* translators: 1: Post type, 2: Post title */
                __( '%1$s "%2$s" content edited', 'vigilante' ),
                ucfirst( $post_after->post_type ),
                $post_after->post_title
            ),
            array(
                'object_type' => $post_after->post_type,
                'object_id'   => $post_id,
                'object_name' => $post_after->post_title,
            ),
            'info'
        );
    }

    /**
     * Log post deletion
     *
     * @param int $post_id Post ID.
     */
    public function log_post_delete( $post_id ) {
        $post = get_post( $post_id );
        if ( ! $post || wp_is_post_revision( $post ) ) {
            return;
        }

        $skip_types = array( 'nav_menu_item', 'revision' );
        if ( in_array( $post->post_type, $skip_types, true ) ) {
            return;
        }

        $this->log(
            'content',
            'deleted',
            sprintf(
                /* translators: 1: Post type, 2: Post title */
                __( '%1$s "%2$s" permanently deleted', 'vigilante' ),
                ucfirst( $post->post_type ),
                $post->post_title
            ),
            array(
                'object_type' => $post->post_type,
                'object_id'   => $post->ID,
                'object_name' => $post->post_title,
            ),
            'warning'
        );
    }

    // =========================================================================
    // PLUGIN EVENTS
    // =========================================================================

    /**
     * Log plugin activation
     *
     * @param string $plugin Plugin path.
     */
    public function log_plugin_activated( $plugin ) {
        $plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );

        $this->log(
            'plugin',
            'activated',
            sprintf(
                /* translators: %s: Plugin name */
                __( 'Plugin activated: %s', 'vigilante' ),
                $plugin_data['Name']
            ),
            array(
                'object_type' => 'plugin',
                'object_name' => $plugin_data['Name'],
                'plugin_path' => $plugin,
                'version'     => $plugin_data['Version'],
            ),
            'info'
        );
    }

    /**
     * Log plugin deactivation
     *
     * @param string $plugin Plugin path.
     */
    public function log_plugin_deactivated( $plugin ) {
        $plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );

        $this->log(
            'plugin',
            'deactivated',
            sprintf(
                /* translators: %s: Plugin name */
                __( 'Plugin deactivated: %s', 'vigilante' ),
                $plugin_data['Name']
            ),
            array(
                'object_type' => 'plugin',
                'object_name' => $plugin_data['Name'],
                'plugin_path' => $plugin,
            ),
            'warning'
        );
    }

    /**
     * Log plugin/theme install or update via upgrader
     *
     * @param WP_Upgrader $upgrader Upgrader instance.
     * @param array       $options  Update options.
     */
    public function log_upgrader_event( $upgrader, $options ) {
        $action_type = $options['action'] ?? '';
        $item_type   = $options['type'] ?? '';

        // Plugin update/install
        if ( 'plugin' === $item_type ) {
            if ( 'update' === $action_type && isset( $options['plugins'] ) ) {
                foreach ( $options['plugins'] as $plugin ) {
                    $plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
                    $this->log(
                        'plugin',
                        'updated',
                        sprintf(
                            /* translators: 1: Plugin name, 2: Version */
                            __( 'Plugin updated: %1$s to version %2$s', 'vigilante' ),
                            $plugin_data['Name'],
                            $plugin_data['Version']
                        ),
                        array(
                            'object_type' => 'plugin',
                            'object_name' => $plugin_data['Name'],
                            'version'     => $plugin_data['Version'],
                        ),
                        'info'
                    );
                }
            } elseif ( 'install' === $action_type ) {
                $result = $upgrader->result ?? array();
                $name   = __( 'Unknown plugin', 'vigilante' );
                if ( ! empty( $result['destination_name'] ) ) {
                    $plugin_dir = WP_PLUGIN_DIR . '/' . $result['destination_name'];
                    if ( is_dir( $plugin_dir ) ) {
                        $plugins = get_plugins( '/' . $result['destination_name'] );
                        if ( ! empty( $plugins ) ) {
                            $first = reset( $plugins );
                            $name  = $first['Name'] ?? $result['destination_name'];
                        }
                    }
                }
                $this->log(
                    'plugin',
                    'installed',
                    sprintf(
                        /* translators: %s: Plugin name */
                        __( 'Plugin installed: %s', 'vigilante' ),
                        $name
                    ),
                    array(
                        'object_type' => 'plugin',
                        'object_name' => $name,
                    ),
                    'info'
                );
            }
        }

        // Theme update/install
        if ( 'theme' === $item_type ) {
            if ( 'update' === $action_type && isset( $options['themes'] ) ) {
                foreach ( $options['themes'] as $theme_slug ) {
                    $theme = wp_get_theme( $theme_slug );
                    $this->log(
                        'theme',
                        'updated',
                        sprintf(
                            /* translators: 1: Theme name, 2: Version */
                            __( 'Theme updated: %1$s to version %2$s', 'vigilante' ),
                            $theme->get( 'Name' ),
                            $theme->get( 'Version' )
                        ),
                        array(
                            'object_type' => 'theme',
                            'object_name' => $theme->get( 'Name' ),
                            'version'     => $theme->get( 'Version' ),
                        ),
                        'info'
                    );
                }
            } elseif ( 'install' === $action_type ) {
                $result = $upgrader->result ?? array();
                $slug   = ! empty( $result['destination_name'] ) ? $result['destination_name'] : '';
                $name   = $slug;
                if ( $slug ) {
                    $theme = wp_get_theme( $slug );
                    if ( $theme->exists() ) {
                        $name = $theme->get( 'Name' );
                    }
                }
                if ( empty( $name ) ) {
                    $name = __( 'Unknown theme', 'vigilante' );
                }
                $this->log(
                    'theme',
                    'installed',
                    sprintf(
                        /* translators: %s: Theme name */
                        __( 'Theme installed: %s', 'vigilante' ),
                        $name
                    ),
                    array(
                        'object_type' => 'theme',
                        'object_name' => $name,
                    ),
                    'info'
                );
            }
        }
    }

    /**
     * Log plugin deletion
     *
     * @param string $plugin Plugin path.
     * @param bool   $deleted Whether deletion was successful.
     */
    public function log_plugin_deleted( $plugin, $deleted ) {
        if ( ! $deleted ) {
            return;
        }

        $this->log(
            'plugin',
            'deleted',
            sprintf(
                /* translators: %s: Plugin path */
                __( 'Plugin deleted: %s', 'vigilante' ),
                $plugin
            ),
            array(
                'object_type' => 'plugin',
                'plugin_path' => $plugin,
            ),
            'warning'
        );
    }

    // =========================================================================
    // THEME EVENTS
    // =========================================================================

    /**
     * Log theme switch
     *
     * @param string   $new_name  New theme name.
     * @param WP_Theme $new_theme New theme object.
     * @param WP_Theme $old_theme Old theme object.
     */
    public function log_theme_switch( $new_name, $new_theme, $old_theme ) {
        $this->log(
            'theme',
            'switched',
            sprintf(
                /* translators: 1: Old theme name, 2: New theme name */
                __( 'Theme switched from %1$s to %2$s', 'vigilante' ),
                $old_theme->get( 'Name' ),
                $new_name
            ),
            array(
                'object_type' => 'theme',
                'object_name' => $new_name,
                'old_theme'   => $old_theme->get( 'Name' ),
                'new_theme'   => $new_name,
            ),
            'warning'
        );
    }

    // =========================================================================
    // OPTION / SETTINGS EVENTS
    // =========================================================================

    /**
     * WordPress core options relevant for security auditing.
     * Only these (plus user-configured extras) are tracked.
     *
     * @var array
     */
    private static $core_tracked_options = array(
        // Site identity and URLs (compromise indicators)
        'siteurl',
        'home',
        'blogname',
        'blogdescription',
        'admin_email',
        // User management (security-critical)
        'users_can_register',
        'default_role',
        // Active components
        'active_plugins',
        'template',
        'stylesheet',
        // Visibility and access
        'blog_public',
        'permalink_structure',
        // Comments policy
        'default_comment_status',
        'comment_moderation',
        'comment_registration',
        'require_name_email',
        'close_comments_for_old_posts',
        'default_pingback_flag',
        'default_ping_status',
        // Homepage and reading
        'show_on_front',
        'page_on_front',
        'page_for_posts',
        'posts_per_page',
        // Privacy and locale
        'wp_page_for_privacy_policy',
        'timezone_string',
        'WPLANG',
        // Mail configuration
        'mailserver_url',
        'mailserver_login',
    );

    /**
     * Log option update.
     * Tracks curated WordPress core options + user-configured extras.
     * Vigilante internal options are always skipped (logged via apply_section_changes).
     *
     * @param string $option    Option name.
     * @param mixed  $old_value Old value.
     * @param mixed  $new_value New value.
     */
    public function log_option_update( $option, $old_value, $new_value ) {
        // Always skip Vigilante internal options (already logged via apply_section_changes)
        if ( strpos( $option, 'vigilante_' ) !== false ) {
            return;
        }

        // Skip if values are identical
        if ( $old_value === $new_value ) {
            return;
        }

        // Check curated whitelist
        $tracked = in_array( $option, self::$core_tracked_options, true );

        // Check user-configured extras
        if ( ! $tracked ) {
            $current_options = $this->get_current_options();
            $user_tracked    = $current_options['tracked_options'] ?? array();
            foreach ( $user_tracked as $pattern ) {
                $pattern = trim( $pattern );
                if ( empty( $pattern ) ) {
                    continue;
                }
                // Exact match or prefix match (e.g. 'woocommerce_' tracks all WooCommerce options)
                if ( $option === $pattern || ( substr( $pattern, -1 ) === '_' && strpos( $option, $pattern ) === 0 ) ) {
                    $tracked = true;
                    break;
                }
            }
        }

        if ( ! $tracked ) {
            return;
        }

        $this->log(
            'settings',
            'option_updated',
            sprintf(
                /* translators: %s: Option name */
                __( 'Option updated: %s', 'vigilante' ),
                $option
            ),
            array(
                'option_name' => $option,
            ),
            'info'
        );
    }

    // =========================================================================
    // COMMENT EVENTS
    // =========================================================================

    /**
     * Log comment insert
     *
     * @param int        $comment_id Comment ID.
     * @param WP_Comment $comment    Comment object.
     */
    public function log_comment_insert( $comment_id, $comment ) {
        $this->log(
            'comment',
            'created',
            sprintf(
                /* translators: 1: Comment author, 2: Post ID */
                __( 'New comment by %1$s on post #%2$d', 'vigilante' ),
                $comment->comment_author,
                $comment->comment_post_ID
            ),
            array(
                'object_type'    => 'comment',
                'object_id'      => $comment_id,
                'comment_author' => $comment->comment_author,
                'post_id'        => $comment->comment_post_ID,
            ),
            'info'
        );
    }

    /**
     * Log comment status change (approve, unapprove, spam, trash)
     *
     * @param string     $new_status New comment status.
     * @param string     $old_status Old comment status.
     * @param WP_Comment $comment    Comment object.
     */
    public function log_comment_status_change( $new_status, $old_status, $comment ) {
        // Skip if status didn't actually change
        if ( $new_status === $old_status ) {
            return;
        }

        $status_labels = array(
            'approved'     => __( 'approved', 'vigilante' ),
            'unapproved'   => __( 'held for moderation', 'vigilante' ),
            'hold'         => __( 'held for moderation', 'vigilante' ),
            'spam'         => __( 'marked as spam', 'vigilante' ),
            'trash'        => __( 'trashed', 'vigilante' ),
        );

        $action   = sanitize_key( $new_status );
        $label    = isset( $status_labels[ $new_status ] ) ? $status_labels[ $new_status ] : $new_status;
        $severity = in_array( $new_status, array( 'spam', 'trash' ), true ) ? 'warning' : 'info';

        $this->log(
            'comment',
            $action,
            sprintf(
                /* translators: 1: Comment author, 2: Comment ID, 3: Status label */
                __( 'Comment by %1$s (ID: %2$d) %3$s', 'vigilante' ),
                $comment->comment_author,
                $comment->comment_ID,
                $label
            ),
            array(
                'object_type' => 'comment',
                'object_id'   => $comment->comment_ID,
                'old_status'  => $old_status,
                'new_status'  => $new_status,
                'post_id'     => $comment->comment_post_ID,
            ),
            $severity
        );
    }

    /**
     * Log comment deleted
     *
     * @param int $comment_id Comment ID.
     */
    public function log_comment_delete( $comment_id ) {
        $this->log(
            'comment',
            'deleted',
            sprintf(
                /* translators: %d: Comment ID */
                __( 'Comment permanently deleted (ID: %d)', 'vigilante' ),
                $comment_id
            ),
            array(
                'object_type' => 'comment',
                'object_id'   => $comment_id,
            ),
            'warning'
        );
    }

    // =========================================================================
    // MEDIA EVENTS
    // =========================================================================

    /**
     * Log media upload
     *
     * @param int $attachment_id Attachment ID.
     */
    public function log_media_upload( $attachment_id ) {
        $attachment = get_post( $attachment_id );

        $this->log(
            'media',
            'uploaded',
            sprintf(
                /* translators: %s: File name */
                __( 'Media uploaded: %s', 'vigilante' ),
                $attachment->post_title
            ),
            array(
                'object_type' => 'attachment',
                'object_id'   => $attachment_id,
                'object_name' => $attachment->post_title,
                'mime_type'   => $attachment->post_mime_type,
            ),
            'info'
        );
    }

    /**
     * Log media deletion
     *
     * @param int $attachment_id Attachment ID.
     */
    public function log_media_delete( $attachment_id ) {
        $attachment = get_post( $attachment_id );

        if ( $attachment ) {
            $this->log(
                'media',
                'deleted',
                sprintf(
                    /* translators: %s: File name */
                    __( 'Media deleted: %s', 'vigilante' ),
                    $attachment->post_title
                ),
                array(
                    'object_type' => 'attachment',
                    'object_id'   => $attachment_id,
                    'object_name' => $attachment->post_title,
                ),
                'warning'
            );
        }
    }

    // =========================================================================
    // QUERY, CLEANUP & EXPORT
    // =========================================================================

    /**
     * Get logs with pagination
     *
     * @param array $args Query arguments.
     * @return array
     */
    public function get_logs( $args = array() ) {
        return $this->database->get_activity_logs( $args );
    }

    /**
     * Get total logs count
     *
     * @param array $args Query arguments.
     * @return int
     */
    public function get_logs_count( $args = array() ) {
        return $this->database->get_activity_logs_count( $args );
    }

    /**
     * Cleanup old logs based on retention settings (uses fresh options)
     */
    public function cleanup_old_logs() {
        $options        = $this->get_current_options();
        $retention_days = absint( $options['retention_days'] ?? 30 );
        $max_entries    = absint( $options['max_entries'] ?? 10000 );

        // Delete by age
        $this->database->cleanup_old_activity_logs( $retention_days );

        // Delete by count if needed
        $count = $this->database->get_activity_logs_count();
        if ( $count > $max_entries ) {
            $to_delete = $count - $max_entries;
            global $wpdb;
            $table = $this->database->get_activity_log_table();

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query(
                $wpdb->prepare(
                    'DELETE FROM %i ORDER BY created_at ASC LIMIT %d',
                    $table,
                    $to_delete
                )
            );
        }
    }

    /**
     * Clear all logs
     *
     * @return bool
     */
    public function clear_all_logs() {
        return $this->database->truncate_activity_log();
    }

    /**
     * Export logs to array
     *
     * @param array $args Query arguments.
     * @return array
     */
    public function export_logs( $args = array() ) {
        $args['per_page'] = 9999;
        return $this->get_logs( $args );
    }

    // =========================================================================
    // STATIC HELPERS
    // =========================================================================

    /**
     * Get available event types
     *
     * @return array
     */
    public static function get_event_types() {
        return array(
            'login'    => __( 'Login Events', 'vigilante' ),
            'user'     => __( 'User Events', 'vigilante' ),
            'content'  => __( 'Content Events', 'vigilante' ),
            'plugin'   => __( 'Plugin Events', 'vigilante' ),
            'theme'    => __( 'Theme Events', 'vigilante' ),
            'settings' => __( 'Settings Events', 'vigilante' ),
            'comment'  => __( 'Comment Events', 'vigilante' ),
            'media'    => __( 'Media Events', 'vigilante' ),
            'firewall' => __( 'Firewall Events', 'vigilante' ),
            'file'     => __( 'File Events', 'vigilante' ),
            'security' => __( 'Security Events', 'vigilante' ),
            'system'   => __( 'System Events', 'vigilante' ),
        );
    }

    /**
     * Get severity levels
     *
     * @return array
     */
    public static function get_severity_levels() {
        return array(
            'info'     => __( 'Info', 'vigilante' ),
            'warning'  => __( 'Warning', 'vigilante' ),
            'critical' => __( 'Critical', 'vigilante' ),
        );
    }
}