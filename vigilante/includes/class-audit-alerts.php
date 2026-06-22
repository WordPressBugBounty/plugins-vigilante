<?php
/**
 * Audit Alerts engine
 *
 * Alerting layer that sits on top of Security Audit. It subscribes to the
 * `vigilante_event_logged` action (fired by Vigilante_Activity_Log::log()
 * after an event passes every gate) and emails the configured recipients when:
 *
 *  - #38 Immediate: a logged event reaches the configured minimum severity.
 *  - #10 Threshold: a category exceeds its event count within a time window.
 *
 * It is a passive subscriber: it never reaches into the security modules, so
 * the per-module emails that already exist (User Security admin monitoring,
 * Plugin Status, Login Security, File Integrity) keep working untouched. The
 * engine only runs when the Security Audit (activity_log) module is enabled.
 *
 * Throttling: a per-category cooldown turns an event storm into a single
 * email, and an anti-duplicate cooldown groups identical immediate events.
 * Counters and cooldowns live in per-site transients, never in
 * vigilante_options, keeping the export/import settings feature clean.
 *
 * @package Vigilante
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Audit_Alerts
 */
class Vigilante_Audit_Alerts {

    /**
     * Shared prefix for every transient this engine writes.
     */
    const TRANSIENT_PREFIX = 'vigilante_aa_';

    /**
     * Categories the threshold leg can watch. These are Activity Log
     * `event_type` values. Used for defaults, the UI and uninstall cleanup.
     *
     * @return array Map of category slug => translated label.
     */
    public static function category_labels() {
        return array(
            // Security-facing categories first.
            'firewall' => __( 'Firewall', 'vigilante' ),
            'login'    => __( 'Login', 'vigilante' ),
            'user'     => __( 'Users', 'vigilante' ),
            'plugin'   => __( 'Plugins', 'vigilante' ),
            'file'     => __( 'File integrity', 'vigilante' ),
            'security' => __( 'Security', 'vigilante' ),
            'system'   => __( 'System', 'vigilante' ),
            'settings' => __( 'Settings', 'vigilante' ),
            // Content/activity categories that can also log warnings.
            'theme'    => __( 'Themes', 'vigilante' ),
            'content'  => __( 'Content', 'vigilante' ),
            'comment'  => __( 'Comments', 'vigilante' ),
            'media'    => __( 'Media', 'vigilante' ),
        );
    }

    /**
     * Severity ranking for the immediate-alert minimum-severity comparison.
     *
     * @var array
     */
    private static $severity_rank = array(
        'info'     => 1,
        'warning'  => 2,
        'critical' => 3,
    );

    /**
     * Settings instance.
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Activity log instance (kept for parity with other modules; unused here).
     *
     * @var Vigilante_Activity_Log|null
     */
    private $activity_log;

    /**
     * Constructor.
     *
     * @param Vigilante_Settings          $settings     Settings instance.
     * @param Vigilante_Activity_Log|null $activity_log Activity log instance.
     */
    public function __construct( $settings, $activity_log = null ) {
        $this->settings     = $settings;
        $this->activity_log = $activity_log;

        add_action( 'vigilante_event_logged', array( $this, 'on_event_logged' ), 10, 4 );
    }

    // =========================================================================
    // Event handling
    // =========================================================================

    /**
     * Single entry point for every logged security event.
     *
     * @param string $type     Event type (login, user, plugin, firewall, ...).
     * @param string $action   Event action.
     * @param string $severity Severity: info, warning, critical.
     * @param array  $context  Event context from the activity log.
     */
    public function on_event_logged( $type, $action, $severity, $context ) {
        // System/maintenance noise never triggers an alert.
        if ( 'system' === $type ) {
            return;
        }

        $config = (array) $this->settings->get_section( 'audit_alerts' );
        if ( empty( $config ) ) {
            return;
        }

        // Shared anti-repeat cooldown applied to both legs.
        $cooldown = isset( $config['cooldown_minutes'] ) ? max( 0, (int) $config['cooldown_minutes'] ) : 60;

        $immediate = isset( $config['immediate'] ) ? (array) $config['immediate'] : array();
        if ( ! empty( $immediate['enabled'] ) ) {
            $this->maybe_immediate_alert( $type, $action, $severity, $context, $immediate, $cooldown );
        }

        $threshold = isset( $config['threshold'] ) ? (array) $config['threshold'] : array();
        if ( ! empty( $threshold['enabled'] ) ) {
            $this->record_and_check_threshold( $type, $severity, $threshold, $cooldown );
        }
    }

    /**
     * #38 Immediate alert: email right away if the event is severe enough.
     *
     * @param string $type      Event type.
     * @param string $action    Event action.
     * @param string $severity  Event severity.
     * @param array  $context   Event context.
     * @param array  $immediate Immediate-leg settings.
     * @param int    $cooldown  Shared anti-repeat cooldown, in minutes.
     */
    private function maybe_immediate_alert( $type, $action, $severity, $context, $immediate, $cooldown ) {
        $min        = isset( $immediate['min_severity'] ) ? $immediate['min_severity'] : 'critical';
        $event_rank = isset( self::$severity_rank[ $severity ] ) ? self::$severity_rank[ $severity ] : 1;
        $min_rank   = isset( self::$severity_rank[ $min ] ) ? self::$severity_rank[ $min ] : 3;

        if ( $event_rank < $min_rank ) {
            return;
        }

        // Don't repeat the same event type+action within the cooldown, so a
        // burst of the same kind of event becomes one email, not a storm.
        $cooldown = max( 0, (int) $cooldown );
        $key      = self::TRANSIENT_PREFIX . 'imm_' . md5( $type . ':' . $action );

        if ( $cooldown > 0 && get_transient( $key ) ) {
            return;
        }

        $this->send_immediate_email( $type, $action, $severity, $context );

        if ( $cooldown > 0 ) {
            set_transient( $key, 1, $cooldown * MINUTE_IN_SECONDS );
        }
    }

    /**
     * #10 Threshold alert: count warning/critical events per category and email
     * when a category exceeds its configured count within the window, respecting
     * the cooldown. Info-level events (a normal login, a saved post) are ignored
     * so routine activity does not trip the alert.
     *
     * @param string $type      Event type (acts as the category).
     * @param string $severity  Event severity (only warning/critical is counted).
     * @param array  $threshold Threshold-leg settings.
     * @param int    $cooldown  Shared anti-repeat cooldown, in minutes.
     */
    private function record_and_check_threshold( $type, $severity, $threshold, $cooldown ) {
        // Count only meaningful events; routine info-level activity is not a spike.
        if ( 'warning' !== $severity && 'critical' !== $severity ) {
            return;
        }

        $categories = isset( $threshold['categories'] ) ? (array) $threshold['categories'] : array();

        // Only watch categories the user configured with a positive limit.
        if ( ! isset( $categories[ $type ] ) ) {
            return;
        }
        $limit = (int) $categories[ $type ];
        if ( $limit <= 0 ) {
            return;
        }

        $window         = isset( $threshold['window'] ) ? $threshold['window'] : '1h';
        $window_seconds = $this->window_to_seconds( $window );

        // Sliding window via the transient TTL: each event renews the TTL, so a
        // sustained burst keeps counting; if events stop, the window expires.
        $count_key = self::TRANSIENT_PREFIX . 'count_' . $type;
        $count     = (int) get_transient( $count_key ) + 1;
        set_transient( $count_key, $count, $window_seconds );

        if ( $count < $limit ) {
            return;
        }

        // Threshold reached. Honour the shared cooldown for this category so one
        // storm is one email even though the counter keeps climbing.
        $cooldown     = max( 0, (int) $cooldown );
        $cooldown_key = self::TRANSIENT_PREFIX . 'cooldown_' . $type;

        if ( $cooldown > 0 && get_transient( $cooldown_key ) ) {
            return;
        }

        $this->send_threshold_email( $type, $count, $limit, $window );

        // Reset the counter so the next window starts clean, then start cooldown.
        delete_transient( $count_key );
        if ( $cooldown > 0 ) {
            set_transient( $cooldown_key, 1, $cooldown * MINUTE_IN_SECONDS );
        }
    }

    // =========================================================================
    // Email builders
    // =========================================================================

    /**
     * Build and send the immediate-alert email.
     *
     * @param string $type     Event type.
     * @param string $action   Event action.
     * @param string $severity Event severity.
     * @param array  $context  Event context.
     */
    private function send_immediate_email( $type, $action, $severity, $context ) {
        $recipients = Vigilante_Email_Template::get_admin_recipients();
        if ( empty( $recipients ) ) {
            return;
        }

        $type_label = $this->type_label( $type );
        $message    = isset( $context['message'] ) ? (string) $context['message'] : '';

        $subject = sprintf(
            /* translators: 1: site name, 2: event category label */
            __( '[Vigilant] Security alert on %1$s: %2$s', 'vigilante' ),
            wp_specialchars_decode( get_bloginfo( 'name' ) ),
            $type_label
        );

        $body  = Vigilante_Email_Template::alert_box( '' !== $message ? $message : $type_label );

        $rows = array(
            __( 'Event', 'vigilante' )    => $type_label . ( '' !== $action ? ' / ' . $action : '' ),
            __( 'Severity', 'vigilante' ) => $this->severity_label( $severity ),
            __( 'When', 'vigilante' )     => $this->now_label(),
        );
        if ( ! empty( $context['ip'] ) ) {
            $rows[ __( 'IP address', 'vigilante' ) ] = $context['ip'];
        }
        if ( ! empty( $context['object_name'] ) ) {
            $rows[ __( 'Subject', 'vigilante' ) ] = $context['object_name'];
        }
        $body .= Vigilante_Email_Template::data_table( $rows );

        $body .= Vigilante_Email_Template::small(
            __( 'This event matched your immediate alert rule. Similar events within the cooldown window are grouped into this notice, so check the full audit for the complete picture.', 'vigilante' )
        );
        $body .= Vigilante_Email_Template::button( $this->audit_url(), __( 'View Security Audit', 'vigilante' ) );

        Vigilante_Email_Template::send( $recipients, $subject, __( 'Security alert', 'vigilante' ), $body, true );
    }

    /**
     * Build and send the threshold-alert email.
     *
     * @param string $type   Event type (category).
     * @param int    $count  Events counted in the window.
     * @param int    $limit  Configured threshold.
     * @param string $window Window slug (1h/6h/24h).
     */
    private function send_threshold_email( $type, $count, $limit, $window ) {
        $recipients = Vigilante_Email_Template::get_admin_recipients();
        if ( empty( $recipients ) ) {
            return;
        }

        $type_label   = $this->type_label( $type );
        $window_label = $this->window_label( $window );

        $subject = sprintf(
            /* translators: 1: site name, 2: event category label */
            __( '[Vigilant] Unusual activity on %1$s: %2$s', 'vigilante' ),
            wp_specialchars_decode( get_bloginfo( 'name' ) ),
            $type_label
        );

        $body = Vigilante_Email_Template::warning_box(
            sprintf(
                /* translators: 1: number of events, 2: category label, 3: time window */
                __( '%1$d %2$s events were recorded within %3$s, above your alert threshold.', 'vigilante' ),
                $count,
                $type_label,
                $window_label
            )
        );

        $body .= Vigilante_Email_Template::data_table(
            array(
                __( 'Category', 'vigilante' )  => $type_label,
                __( 'Events', 'vigilante' )    => $count,
                __( 'Threshold', 'vigilante' ) => $limit,
                __( 'Window', 'vigilante' )    => $window_label,
                __( 'When', 'vigilante' )      => $this->now_label(),
            )
        );

        $body .= Vigilante_Email_Template::small(
            __( 'Further events in this category will not re-alert until the cooldown passes.', 'vigilante' )
        );
        $body .= Vigilante_Email_Template::button( $this->audit_url(), __( 'View Security Audit', 'vigilante' ) );

        Vigilante_Email_Template::send( $recipients, $subject, __( 'Unusual activity detected', 'vigilante' ), $body, true );
    }

    // =========================================================================
    // Active-state helpers (used by Dashboard, Configuration Score, Analyzer)
    // =========================================================================

    /**
     * Whether the immediate-alert leg is active.
     *
     * @param array $config The audit_alerts settings section.
     * @return bool
     */
    public static function immediate_is_active( array $config ) {
        return ! empty( $config['immediate']['enabled'] );
    }

    /**
     * Whether the threshold leg is active with at least one category watched.
     *
     * @param array $config The audit_alerts settings section.
     * @return bool
     */
    public static function threshold_is_active( array $config ) {
        if ( empty( $config['threshold']['enabled'] ) ) {
            return false;
        }
        $categories = isset( $config['threshold']['categories'] ) ? (array) $config['threshold']['categories'] : array();
        foreach ( $categories as $limit ) {
            if ( (int) $limit > 0 ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether any alert leg is active.
     *
     * @param array $config The audit_alerts settings section.
     * @return bool
     */
    public static function has_active_alerts( array $config ) {
        return self::immediate_is_active( $config ) || self::threshold_is_active( $config );
    }

    // =========================================================================
    // Small helpers
    // =========================================================================

    /**
     * Translate a window slug to seconds.
     *
     * @param string $window 1h | 6h | 24h.
     * @return int Seconds.
     */
    private function window_to_seconds( $window ) {
        switch ( $window ) {
            case '30m':
                return 30 * MINUTE_IN_SECONDS;
            case '6h':
                return 6 * HOUR_IN_SECONDS;
            case '24h':
                return DAY_IN_SECONDS;
            case '1h':
            default:
                return HOUR_IN_SECONDS;
        }
    }

    /**
     * Human label for a window slug.
     *
     * @param string $window 1h | 6h | 24h.
     * @return string
     */
    private function window_label( $window ) {
        switch ( $window ) {
            case '30m':
                return __( '30 minutes', 'vigilante' );
            case '6h':
                return __( '6 hours', 'vigilante' );
            case '24h':
                return __( '24 hours', 'vigilante' );
            case '1h':
            default:
                return __( '1 hour', 'vigilante' );
        }
    }

    /**
     * Human label for an event category / type.
     *
     * @param string $type Event type.
     * @return string
     */
    private function type_label( $type ) {
        $labels = self::category_labels();
        if ( isset( $labels[ $type ] ) ) {
            return $labels[ $type ];
        }
        return ucfirst( str_replace( '_', ' ', $type ) );
    }

    /**
     * Human label for a severity.
     *
     * @param string $severity info | warning | critical.
     * @return string
     */
    private function severity_label( $severity ) {
        switch ( $severity ) {
            case 'critical':
                return __( 'Critical', 'vigilante' );
            case 'warning':
                return __( 'Warning', 'vigilante' );
            case 'info':
            default:
                return __( 'Info', 'vigilante' );
        }
    }

    /**
     * Localized "now" timestamp for the email body.
     *
     * @return string
     */
    private function now_label() {
        return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );
    }

    /**
     * URL to the Security Audit recent-activity feed.
     *
     * @return string
     */
    private function audit_url() {
        return admin_url( 'admin.php?page=vigilante&tab=activity-log#vigilante-section-audit-recent' );
    }
}
