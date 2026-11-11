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

        // Secrets API, WordPress 7.2 and later: the action does not exist
        // before, so this costs nothing there. It passes fingerprints, never
        // values. Whatever the checkboxes say, like the firewall blocks: the
        // security type answers to none.
        add_action( 'wp_secret_changed', array( $this, 'log_secret_changed' ), 10, 7 );
    }

    /**
     * Log an event.
     *
     * Gate checks (in order):
     * 1. Module master switch (modules.activity_log)
     * 2. Per-type flag via $type_flag_map (types not in the map always pass)
     * 3. Login: each of its two checkboxes governs its own half (see below)
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

        // The user type also carries attack traffic, which is not a change to a
        // user: unchecking "User changes" silenced those blocks and, with them,
        // the audit alerts, which only fire for stored events (B120, the same
        // family as the login half fixed in 2.11.10). They answer to no
        // checkbox, like the firewall blocks.
        $user_attack = array( 'author_scan_blocked', 'insecure_username_blocked', 'session_limit_blocked' );

        if ( isset( self::$type_flag_map[ $type ] ) && 'login' !== $type && ! ( 'user' === $type && in_array( $action, $user_attack, true ) ) ) {
            $flag = self::$type_flag_map[ $type ];
            if ( empty( $current_options[ $flag ] ) ) {
                return false;
            }
        }

        /*
         * Gate 3: login is the one type with two checkboxes, offered side by
         * side as "Successful logins" and "Failed login attempts". Until 2.11.10
         * the per-type gate above cut first, so unchecking the first one also
         * silenced the second and with it everything security relevant this type
         * carries: failed attempts, lockouts, logins blocked by a forced reset
         * and the probes of the hidden wp-admin and login. The audit alerts of
         * the login category went quiet at the same time, because they only fire
         * for events that get stored, so a site under attack looked calm on both
         * screens. Found by the file-by-file review of 2.11.10.
         *
         * Each checkbox governs its own half now: a successful login answers to
         * log_logins, and everything else about login, which is attack traffic,
         * answers to log_failed_logins.
         */
        if ( 'login' === $type ) {
            /*
             * Written as the list of what is attack traffic, not as "everything
             * that is not a success": login_url_notified is an administrative
             * notice and answering to the failed-attempts checkbox made it
             * disappear for anyone who had that one unchecked, which is a record
             * 2.11.9 did keep. Found by the cross review of 2.11.10.
             */
            $attack = array( 'failed', 'lockout', 'lockout_blocked', 'hidden_admin_access', 'hidden_login_access', 'force_reset_login_blocked' );
            $flag   = in_array( $action, $attack, true ) ? 'log_failed_logins' : 'log_logins';

            if ( empty( $current_options[ $flag ] ) ) {
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
    // SECRETS API (WordPress 7.2)
    // =========================================================================

    /**
     * Fingerprints a secret had, per scope, so a return to one can be seen.
     */
    const SECRET_PRINTS_OPTION = 'vigilante_secret_prints';

    /**
     * How long a value a secret stopped having counts as recent, in seconds.
     */
    const SECRET_RETURN_WINDOW = 86400;

    /**
     * Log a change of a secret of the Secrets API
     *
     * The action of core passes the name, what happened and two fingerprints,
     * never a value (wp-includes/secrets/class-wp-secrets-libsodium-provider.php:433-461
     * in 7.2-beta5). The fingerprints are keyed by the master key of the site
     * (WP_Secrets_Cipher::fingerprint()), the same ones core keeps next to each
     * record, so keeping them reveals nothing the database did not already
     * hold. A new WP_SECRETS_KEY does not change them: rotating it only wraps
     * the same master key again (WP_Secrets_Key_Manager::rotate_site_key()).
     *
     * A secret that goes back, within a day, to a value it had before and
     * that was replaced by another is logged as critical, so the audit alerts
     * send it: a rotated key put back to the old one is what somebody who knew
     * the old one would do. An administrator undoing a change by hand does the
     * same, and the message says so. A secret deleted and created again with
     * the same value is not a return: it is what disconnecting and connecting
     * an integration again does (the first blind review of 3.0.13). A deleted
     * value that comes back after the secret had another one is (the second).
     *
     * @since 3.0.13
     *
     * @param string $name            Namespaced name of the secret.
     * @param string $action          created, updated, deleted, imported or retired.
     * @param int    $actor_id        User who made the change, or 0.
     * @param int    $timestamp       When.
     * @param string $old_fingerprint Previous fingerprint, or ''.
     * @param string $new_fingerprint New fingerprint, or '' when deleted.
     * @param bool   $network         Whether the secret belongs to the network.
     */
    public function log_secret_changed( $name, $action, $actor_id = 0, $timestamp = 0, $old_fingerprint = '', $new_fingerprint = '', $network = false ) {
        if ( ! is_string( $name ) || '' === $name || ! is_string( $action ) ) {
            return;
        }

        $name    = substr( $name, 0, 191 );
        $old     = self::clean_fingerprint( $old_fingerprint );
        $new     = self::clean_fingerprint( $new_fingerprint );
        $network = $network && is_multisite();
        $when    = ( is_numeric( $timestamp ) && (int) $timestamp > 0 ) ? (int) $timestamp : time();

        $returned = false;
        if ( in_array( $action, array( 'created', 'updated', 'imported' ), true ) && '' !== $new && $new !== $old ) {
            $returned = $this->secret_had_print( $name, $network, $new, $when, $action );
        }

        // What the secret stops having, kept for a day, and how: a value that
        // was replaced by another, or one that went with the secret.
        if ( in_array( $action, array( 'updated', 'imported', 'deleted' ), true ) && '' !== $old && $old !== $new ) {
            $this->remember_secret_print( $name, $network, $old, $when, 'deleted' === $action ? 'deleted' : 'replaced' );
        }

        switch ( $action ) {
            case 'created':
                /* translators: %s: name of a secret of the WordPress Secrets API */
                $message = __( 'Secret created: %s', 'vigilante' );
                break;
            case 'updated':
                /* translators: %s: name of a secret of the WordPress Secrets API */
                $message = __( 'Secret changed: %s', 'vigilante' );
                break;
            case 'deleted':
                /* translators: %s: name of a secret of the WordPress Secrets API */
                $message = __( 'Secret deleted: %s', 'vigilante' );
                break;
            case 'imported':
                /* translators: %s: name of a secret of the WordPress Secrets API */
                $message = __( 'Secret imported: %s', 'vigilante' );
                break;
            case 'retired':
                /* translators: %s: name of a secret of the WordPress Secrets API */
                $message = __( 'Previous value of a secret discarded after a key change: %s', 'vigilante' );
                break;
            default:
                /* translators: %s: name of a secret of the WordPress Secrets API */
                $message = __( 'Secret modified: %s', 'vigilante' );
        }

        $message = sprintf( $message, $name );

        if ( $returned ) {
            $message .= ' ' . __( 'It went back to a value it had less than a day ago. If nobody here undid a change on purpose, find out which user or plugin made it: whoever knew the old value can use it again.', 'vigilante' );
        }

        $this->log(
            'security',
            $returned ? 'secret_returned' : 'secret_' . sanitize_key( $action ),
            $message,
            array(
                'object_type' => 'secret',
                'object_name' => $name,
                'scope'       => $network ? 'network' : 'site',
                'actor_id'    => (int) $actor_id,
                // The first eight characters are enough to tell two apart.
                'old_print'   => substr( $old, 0, 8 ),
                'new_print'   => substr( $new, 0, 8 ),
            ),
            $returned ? 'critical' : 'info'
        );
    }

    /**
     * A fingerprint as core writes it (hexadecimal), or ''
     *
     * @param mixed $value Value passed by the action.
     * @return string
     */
    private static function clean_fingerprint( $value ) {
        if ( ! is_string( $value ) || 1 !== preg_match( '/^[a-f0-9]{8,128}$/i', $value ) ) {
            return '';
        }

        return strtolower( $value );
    }

    /**
     * Fingerprints a secret stopped having within the window, per scope
     *
     * A network secret is the same on every site, so its history is a network
     * option; a site secret's is an option of its site. Autoload off: it is
     * only read when a secret changes.
     *
     * @param bool $network Network scope.
     * @return array<string,array<int,array{0:string,1:int}>>
     */
    private static function secret_prints( $network ) {
        $stored = $network ? get_site_option( self::SECRET_PRINTS_OPTION, array() ) : get_option( self::SECRET_PRINTS_OPTION, array() );

        return is_array( $stored ) ? $stored : array();
    }

    /**
     * Whether a secret had this fingerprint within the window
     *
     * @param string $name    Secret.
     * @param bool   $network Scope.
     * @param string $print   Fingerprint it has now.
     * @param int    $when    Time of the change.
     * @param string $action  What the change is.
     * @return bool
     */
    private function secret_had_print( $name, $network, $print, $when, $action = 'updated' ) {
        $prints = self::secret_prints( $network );

        $entries = array_values( (array) ( $prints[ $name ] ?? array() ) );
        $last    = count( $entries ) - 1;

        foreach ( $entries as $at => $entry ) {
            // A value that went with the secret is skipped only when this
            // change is the creation right after that deletion: creating it
            // again with the same value. Once the secret had another value in
            // between, getting the deleted one back is a return.
            $recreated = in_array( $action, array( 'created', 'imported' ), true ) && $at === $last;
            if ( ! is_array( $entry ) || ! isset( $entry[0], $entry[1] ) || ( 'deleted' === ( $entry[2] ?? '' ) && $recreated ) ) {
                continue;
            }

            if ( $print === $entry[0] && $when - (int) $entry[1] <= self::SECRET_RETURN_WINDOW ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Keep a fingerprint a secret has just stopped having
     *
     * Entries older than the window are dropped on every write, a value seen
     * again replaces its older entry, and at most 25 values per secret and 200
     * secrets are kept, so nothing grows for good. 25 and not 10, the first
     * figure: with ten, ten changes in a row pushed the old value out and the
     * return went unseen (the second blind review).
     *
     * @param string $name    Secret.
     * @param bool   $network Scope.
     * @param string $print   Fingerprint it had.
     * @param int    $when    When it stopped having it.
     * @param string $how     replaced or deleted.
     */
    private function remember_secret_print( $name, $network, $print, $when, $how = 'replaced' ) {
        $prints = self::secret_prints( $network );
        $kept   = array();

        foreach ( $prints as $secret => $entries ) {
            if ( ! is_string( $secret ) || ! is_array( $entries ) ) {
                continue;
            }

            foreach ( $entries as $entry ) {
                if ( is_array( $entry ) && isset( $entry[0], $entry[1] ) && is_string( $entry[0] ) && $when - (int) $entry[1] <= self::SECRET_RETURN_WINDOW ) {
                    $kept[ $secret ][] = array( $entry[0], (int) $entry[1], 'deleted' === ( $entry[2] ?? '' ) ? 'deleted' : 'replaced' );
                }
            }
        }

        // The secret that changed goes last, so the cap below drops others.
        $own = array_values(
            array_filter(
                $kept[ $name ] ?? array(),
                static function ( $entry ) use ( $print ) {
                    return $entry[0] !== $print;
                }
            )
        );
        unset( $kept[ $name ] );
        $own[]         = array( $print, $when, 'deleted' === $how ? 'deleted' : 'replaced' );
        $kept[ $name ] = array_slice( $own, -25 );

        if ( count( $kept ) > 200 ) {
            $kept = array_slice( $kept, -200, null, true );
        }

        if ( $network ) {
            update_site_option( self::SECRET_PRINTS_OPTION, $kept );
        } else {
            update_option( self::SECRET_PRINTS_OPTION, $kept, false );
        }
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
     * The message of an entry as it is shown
     *
     * Messages are stored already translated, in the language of the request
     * that wrote them, except the one the fast path of the hidden login writes
     * on plugins_loaded, before a translation can be asked for: WordPress 6.7
     * warns about a text domain loaded too early and gives English anyway
     * (Vigilante_Login_Security::log_early_hidden_admin_attempt()). That one is
     * translated here, when it is shown, which also covers the entries written
     * before 3.0.8. The export of the log goes through the same AJAX handler
     * as the table (vigilante_get_logs), so it is translated too.
     *
     * @since 3.0.8
     *
     * @param string $action  event_action of the entry.
     * @param string $message event_message as stored.
     * @return string
     */
    public static function display_message( $action, $message ) {
        $message = (string) $message;
        if ( 'hidden_admin_access' === (string) $action && 'Attempt to access hidden wp-admin' === $message ) {
            return __( 'Attempt to access hidden wp-admin', 'vigilante' );
        }
        return $message;
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
     * What the log popup says about an entry's address and User-Agent
     *
     * Matched as the firewall matches: the IP lists with ranges and
     * wildcards, the User-Agent lists by part of the string. Until 3.0.11 the
     * popup compared for equality, so a User-Agent blocked by a line that is
     * only part of it read "not in the blacklist" (B123).
     *
     * @since 3.0.11
     *
     * @param string $ip         Entry address.
     * @param string $user_agent Entry User-Agent.
     * @param mixed  $extra_data Entry extra data.
     * @param array  $firewall   Firewall settings section.
     * @return array
     */
    public static function list_flags( $ip, $user_agent, $extra_data, $firewall ) {
        if ( ! class_exists( 'Vigilante_UA_Utils' ) ) {
            require_once __DIR__ . '/class-ua-utils.php';
        }
        if ( ! class_exists( 'Vigilante_IP_Utils' ) ) {
            require_once __DIR__ . '/class-ip-utils.php';
        }

        $ip         = (string) $ip;
        $user_agent = (string) $user_agent;
        $firewall   = is_array( $firewall ) ? $firewall : array();
        $list       = function ( $key ) use ( $firewall ) {
            return ( isset( $firewall[ $key ] ) && is_array( $firewall[ $key ] ) ) ? $firewall[ $key ] : array();
        };

        $ua_white = '' !== $user_agent ? Vigilante_UA_Utils::first_match( $user_agent, $list( 'ua_whitelist' ) ) : '';
        $ua_black = '' !== $user_agent ? Vigilante_UA_Utils::first_match( $user_agent, $list( 'ua_blacklist' ) ) : '';

        return array(
            'is_ip_whitelisted'  => ( '' !== $ip && Vigilante_IP_Utils::in_list( $ip, $list( 'ip_whitelist' ) ) ),
            'is_ip_blacklisted'  => ( '' !== $ip && Vigilante_IP_Utils::in_list( $ip, $list( 'ip_blacklist' ) ) ),
            'is_ua_whitelisted'  => ( '' !== $ua_white ),
            'is_ua_blacklisted'  => ( '' !== $ua_black ),
            'ua_whitelist_line'  => $ua_white,
            'ua_blacklist_line'  => $ua_black,
            'matched_line'       => self::extract_context_value( $extra_data, 'matched_line' ),
        );
    }

    /**
     * One scalar value stored in an entry's extra data, as a string
     *
     * @since 3.0.11
     *
     * @param mixed  $extra_data The extra_data column, JSON or already decoded.
     * @param string $key        Key.
     * @return string The value, or '' when it is missing or not scalar.
     */
    public static function extract_context_value( $extra_data, $key ) {
        if ( is_string( $extra_data ) ) {
            $extra_data = json_decode( $extra_data, true );
        }

        if ( ! is_array( $extra_data ) || ! isset( $extra_data[ $key ] ) || ! is_scalar( $extra_data[ $key ] ) ) {
            return '';
        }

        return (string) $extra_data[ $key ];
    }

    /**
     * The address a logged event was recorded for, when the event carries one
     *
     * Every blocking module stores the request it turned away under
     * 'request_uri' in the entry's extra data, but nothing ever showed it. The
     * address is what tells a firewall hit on a legitimate page apart from a
     * scanner probe, and a remote manager being refused apart from an intruder,
     * so an owner looking at a surprising entry had no way to tell which one
     * they were reading.
     *
     * That first sentence was not true of the firewall, which is the module
     * that logs the most: it stored the address under 'uri', so the column
     * this method feeds was empty for every one of its blocks, and diagnosing
     * one meant reading the table by hand. Fixed in the firewall in 2.11.1;
     * 'uri' is read here as well so the entries already on disk show it too.
     *
     * @since 2.10.2
     *
     * @param string|array|null $extra_data The entry's extra data, as stored.
     * @return string The recorded address, or '' when the entry carries none.
     */
    public static function extract_request_uri( $extra_data ) {
        if ( is_string( $extra_data ) ) {
            $extra_data = json_decode( $extra_data, true );
        }

        if ( ! is_array( $extra_data ) ) {
            return '';
        }

        $key = isset( $extra_data['request_uri'] ) ? 'request_uri' : 'uri';

        if ( ! isset( $extra_data[ $key ] ) ) {
            return '';
        }

        // Nothing writes anything but a string here, but the value comes back
        // from a longtext column that any past version could have filled, and
        // casting an array would emit a notice and print the word "Array".
        if ( ! is_scalar( $extra_data[ $key ] ) ) {
            return '';
        }

        return (string) $extra_data[ $key ];
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