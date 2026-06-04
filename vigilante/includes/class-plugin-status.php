<?php
/**
 * Plugin Status Checker
 *
 * Detects installed plugins whose slug has been closed in the WordPress.org
 * repository. Closures usually mean security issues, guideline violations,
 * malware, or supply chain compromises.
 *
 * Runs daily via WP-Cron. Logs to Security Audit with severity "critical"
 * and sends an email alert on the first detection (per slug) when File
 * Integrity's instant_alert toggle is on.
 *
 * @package Vigilante
 * @since   2.6.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Plugin_Status
 *
 * Periodic check of installed plugin slugs against the WordPress.org
 * plugin information API. Tracks per-slug state across runs so 404s
 * after a previously-alive observation are treated as removals
 * (typical of closures hidden by Security Issue takedowns).
 */
class Vigilante_Plugin_Status {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Activity log instance
     *
     * @var Vigilante_Activity_Log|null
     */
    private $activity_log;

    /**
     * Option name holding the per-slug state map.
     */
    const STATE_OPTION = 'vigilante_plugin_status_state';

    /**
     * Option name holding the timestamp of the last completed sweep.
     */
    const LAST_CHECK_OPTION = 'vigilante_plugin_status_last_check';

    /**
     * Option name holding the list of slugs the admin has chosen to ignore
     * (still tracked, still shown in a "Ignored" subsection, but excluded
     * from the main results list and from the email digest).
     */
    const IGNORED_OPTION = 'vigilante_ignored_closed_plugins';

    /**
     * Cron hook fired daily.
     */
    const CRON_HOOK = 'vigilante_plugin_status_check';

    /**
     * Per-request HTTP timeout in seconds.
     */
    const HTTP_TIMEOUT = 5;

    /**
     * Maximum total seconds the sweep is allowed to spend on HTTP calls.
     * If exceeded, the remaining slugs are deferred to the next run.
     */
    const SCAN_BUDGET = 60;

    /**
     * Per-slug transient TTL in seconds. Manual "Check Now" presses within
     * this window reuse the cached API response; the scheduled daily cron
     * is longer than this, so it always fetches fresh data.
     */
    const TRANSIENT_TTL = 3600;

    /**
     * Sweep start time for budget control.
     *
     * @var float
     */
    private $sweep_started_at = 0.0;

    /**
     * Constructor
     *
     * @param Vigilante_Settings          $settings     Settings instance.
     * @param Vigilante_Activity_Log|null $activity_log Activity log instance.
     */
    public function __construct( $settings, $activity_log = null ) {
        $this->settings     = $settings;
        $this->activity_log = $activity_log;

        if ( $this->is_enabled() ) {
            $this->schedule_cron();
        }
    }

    /**
     * Whether the daily check is enabled.
     *
     * @return bool
     */
    private function is_enabled() {
        if ( ! $this->settings ) {
            return false;
        }
        $options = $this->settings->get_section( 'file_integrity' );
        return ! empty( $options['check_closed_plugins'] );
    }

    /**
     * Ensure the daily cron is registered.
     */
    private function schedule_cron() {
        if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
            wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
        }
    }

    /**
     * Cron callback. Always runs (the hook is registered globally so the
     * event still fires even if the toggle was flipped after scheduling);
     * the early-exit here is the actual gate.
     */
    public function run_scheduled_check() {
        if ( ! $this->is_enabled() ) {
            return;
        }
        $this->check_all_plugins();
    }

    /**
     * Sweep all installed plugins.
     *
     * @param bool $force_fresh    When true, the per-slug transient cache is
     *                             bypassed so every plugin is re-queried from
     *                             wp.org. Used by entry points that must
     *                             re-evaluate immediately (manual scan, etc.).
     * @param bool $suppress_email When true, no per-transition alert email is
     *                             sent. Used by the file-integrity scan which
     *                             folds closed plugins into its own digest
     *                             email so the user doesn't get two emails for
     *                             the same finding.
     * @return array Current state map after the sweep (slug => entry).
     */
    public function check_all_plugins( $force_fresh = false, $suppress_email = false ) {
        $this->sweep_started_at = microtime( true );

        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugins = get_plugins();
        $state   = $this->get_state();

        // Build a set of currently-installed slugs so we can prune state for
        // plugins that were uninstalled since the last sweep.
        $installed_slugs = array();

        foreach ( $plugins as $plugin_file => $plugin_data ) {
            $slug = dirname( $plugin_file );

            // Skip single-file plugins (no folder, no wp.org slug to query).
            if ( '.' === $slug || '' === $slug ) {
                continue;
            }

            $installed_slugs[ $slug ] = true;

            // Honour the time budget. Plugins not reached in this run keep
            // their previous state and will be evaluated in the next cron.
            if ( $this->is_budget_exceeded() ) {
                break;
            }

            $previous = isset( $state[ $slug ] ) ? $state[ $slug ] : null;
            $signal   = $this->check_plugin_status( $slug, $force_fresh );

            if ( null === $signal ) {
                // Transient error; preserve previous entry, just bump last_checked.
                if ( null !== $previous ) {
                    $previous['last_checked'] = time();
                    $state[ $slug ]           = $previous;
                }
                continue;
            }

            $new_entry = $this->build_entry( $slug, $plugin_data, $previous, $signal );
            $this->handle_transition( $slug, $previous, $new_entry, $plugin_data, $suppress_email );
            $state[ $slug ] = $new_entry;
        }

        // Prune state entries whose plugins are no longer installed locally.
        foreach ( array_keys( $state ) as $stored_slug ) {
            if ( ! isset( $installed_slugs[ $stored_slug ] ) ) {
                unset( $state[ $stored_slug ] );
            }
        }

        update_option( self::STATE_OPTION, $state, false );
        update_option( self::LAST_CHECK_OPTION, time(), false );

        // Auto-purge ignored slugs whose current state is no longer in an
        // alert tier (closed/removed). The "Ignore" decision applies to a
        // specific closure finding; once the plugin is back to open in
        // wp.org (or has been pruned from the state for any reason) the
        // ignore is no longer relevant and would otherwise silence a future
        // re-closure. Cleaning the list here keeps the security guarantee
        // that a fresh closure always alerts.
        $ignored = $this->get_ignored_slugs();
        if ( ! empty( $ignored ) ) {
            $still_alert = array();
            foreach ( $ignored as $slug ) {
                if ( isset( $state[ $slug ]['state'] ) && in_array( $state[ $slug ]['state'], array( 'closed', 'removed' ), true ) ) {
                    $still_alert[] = $slug;
                }
            }
            if ( count( $still_alert ) !== count( $ignored ) ) {
                update_option( self::IGNORED_OPTION, array_values( $still_alert ), false );
            }
        }

        return $state;
    }

    /**
     * Query the wp.org plugin information API for a single slug.
     *
     * @param string $slug        Plugin folder slug.
     * @param bool   $force_fresh When true, skip the transient cache and re-query
     *                            even if we have a recent answer for this slug.
     * @return array|null Signal array with keys:
     *                    - status:           'open' | 'closed' | 'not_found' | null
     *                    - closed_date:      string (only when status=closed)
     *                    - closed_reason:    string (only when status=closed)
     *                    - closed_reason_text: string (only when status=closed)
     *                    Returns null when the call failed transiently
     *                    (timeout / 5xx). The caller preserves prior state.
     */
    public function check_plugin_status( $slug, $force_fresh = false ) {
        $cache_key = 'vigilante_plugin_status_' . md5( $slug );
        if ( ! $force_fresh ) {
            $cached = get_transient( $cache_key );
            if ( false !== $cached && is_array( $cached ) ) {
                return $cached;
            }
        } else {
            delete_transient( $cache_key );
        }

        $url = sprintf(
            'https://api.wordpress.org/plugins/info/1.0/%s.json',
            rawurlencode( $slug )
        );

        $response = wp_remote_get(
            $url,
            array(
                'timeout'    => self::HTTP_TIMEOUT,
                'user-agent' => 'Vigilant/' . VIGILANTE_VERSION . '; ' . home_url(),
            )
        );

        if ( is_wp_error( $response ) ) {
            return null;
        }

        $code = wp_remote_retrieve_response_code( $response );
        $body = wp_remote_retrieve_body( $response );

        // Only real server errors are transient. Note: the 1.0 endpoint serves
        // closed plugins with HTTP 404 but a valid JSON body that still carries
        // closed_date and closed:true — so we must parse the body first instead
        // of short-circuiting on the status code.
        if ( $code >= 500 ) {
            return null;
        }

        $signal = null;
        $data   = ( '' !== $body ) ? json_decode( $body, true ) : null;

        if ( ! is_array( $data ) || empty( $data ) ) {
            $signal = array( 'status' => 'not_found' );
        } elseif ( ! empty( $data['closed'] ) || ! empty( $data['closed_date'] ) ) {
            // Confirmed closed: wp.org explicitly flagged it. The wp.org 1.0
            // payload uses `reason` / `reason_text` (often `false` when the
            // takedown reason is not public) and `description` for the human
            // readable explanation. We surface all three so the UI can pick
            // the most informative non-empty value.
            $reason      = isset( $data['reason'] ) && is_string( $data['reason'] ) ? sanitize_text_field( $data['reason'] ) : '';
            $reason_text = isset( $data['reason_text'] ) && is_string( $data['reason_text'] ) ? sanitize_text_field( $data['reason_text'] ) : '';
            $description = isset( $data['description'] ) && is_string( $data['description'] ) ? wp_strip_all_tags( $data['description'] ) : '';

            // If no reason_text was provided, fall back to the description
            // (typical pattern when wp.org keeps the reason private but ships
            // a generic "This plugin has been closed as of …" message).
            if ( '' === $reason_text && '' !== $description ) {
                $reason_text = $description;
            }

            $signal = array(
                'status'             => 'closed',
                'closed_date'        => isset( $data['closed_date'] ) ? sanitize_text_field( (string) $data['closed_date'] ) : '',
                'closed_reason'      => $reason,
                'closed_reason_text' => $reason_text,
            );
        } elseif ( isset( $data['error'] ) ) {
            // Error payload without a closed flag (e.g. "Plugin not found.").
            // The state tracker decides if this is a removal of a known slug
            // or just a slug that was never in wp.org.
            $signal = array( 'status' => 'not_found' );
        } elseif ( ! empty( $data['name'] ) || ! empty( $data['version'] ) || ! empty( $data['slug'] ) ) {
            $signal = array( 'status' => 'open' );
        } else {
            $signal = array( 'status' => 'not_found' );
        }

        set_transient( $cache_key, $signal, self::TRANSIENT_TTL );
        return $signal;
    }

    /**
     * Combine the API signal with the prior state to produce the new state entry.
     *
     * Logic:
     *  - signal=open                       → state=open
     *  - signal=closed                     → state=closed
     *  - signal=not_found AND prior=open   → state=removed (high confidence)
     *  - signal=not_found AND prior=null   → state=not_in_repo (premium/custom)
     *  - signal=not_found AND prior=closed → keep state=closed (still closed)
     *  - signal=not_found AND prior=removed→ keep state=removed
     *  - signal=not_found AND prior=not_in_repo → keep state=not_in_repo
     *
     * @param string     $slug        Plugin slug.
     * @param array      $plugin_data WP plugin header data.
     * @param array|null $previous    Prior state entry or null.
     * @param array      $signal      API signal returned by check_plugin_status().
     * @return array New state entry.
     */
    private function build_entry( $slug, $plugin_data, $previous, $signal ) {
        $now      = time();
        $name     = isset( $plugin_data['Name'] ) ? (string) $plugin_data['Name'] : $slug;
        $version  = isset( $plugin_data['Version'] ) ? (string) $plugin_data['Version'] : '';
        $previous = is_array( $previous ) ? $previous : array();

        $new_state = '';

        switch ( $signal['status'] ) {
            case 'open':
                $new_state = 'open';
                break;
            case 'closed':
                $new_state = 'closed';
                break;
            case 'not_found':
            default:
                $prior_state = isset( $previous['state'] ) ? $previous['state'] : '';
                if ( 'open' === $prior_state ) {
                    $new_state = 'removed';
                } elseif ( in_array( $prior_state, array( 'closed', 'removed', 'not_in_repo' ), true ) ) {
                    $new_state = $prior_state;
                } else {
                    $new_state = 'not_in_repo';
                }
                break;
        }

        $entry = array(
            'state'        => $new_state,
            'name'         => $name,
            'version'      => $version,
            'last_checked' => $now,
        );

        // Preserve fields that should survive across runs.
        if ( ! empty( $previous['first_detected'] ) ) {
            $entry['first_detected'] = (int) $previous['first_detected'];
        }
        if ( ! empty( $previous['last_alive'] ) ) {
            $entry['last_alive'] = (int) $previous['last_alive'];
        }

        if ( 'open' === $new_state ) {
            $entry['last_alive'] = $now;
        }

        if ( 'closed' === $new_state ) {
            $entry['closed_date']        = isset( $signal['closed_date'] ) ? $signal['closed_date'] : '';
            $entry['closed_reason']      = isset( $signal['closed_reason'] ) ? $signal['closed_reason'] : '';
            $entry['closed_reason_text'] = isset( $signal['closed_reason_text'] ) ? $signal['closed_reason_text'] : '';
        } elseif ( 'closed' === ( $previous['state'] ?? '' ) && 'closed' === $new_state ) {
            // Carry forward closure metadata when staying in 'closed'.
            $entry['closed_date']        = $previous['closed_date'] ?? '';
            $entry['closed_reason']      = $previous['closed_reason'] ?? '';
            $entry['closed_reason_text'] = $previous['closed_reason_text'] ?? '';
        } elseif ( 'removed' === $new_state ) {
            // No metadata for removals; record the reason in a stable shape so
            // the UI can show something meaningful.
            $entry['closed_date']        = '';
            $entry['closed_reason']      = 'removed';
            $entry['closed_reason_text'] = '';
        }

        // First-detection marker on the first transition into closed/removed.
        $is_alert_state    = in_array( $new_state, array( 'closed', 'removed' ), true );
        $was_alert_state   = in_array( ( $previous['state'] ?? '' ), array( 'closed', 'removed' ), true );
        if ( $is_alert_state && ! $was_alert_state ) {
            $entry['first_detected'] = $now;
        }

        return $entry;
    }

    /**
     * Act on the transition between previous and new state: log to Security
     * Audit and (optionally) send a per-transition alert email.
     *
     * @param string     $slug           Plugin slug.
     * @param array|null $previous       Prior state entry or null.
     * @param array      $new_entry      New state entry just built.
     * @param array      $plugin_data    WP plugin header data.
     * @param bool       $suppress_email When true, no email is sent regardless
     *                                   of the transition. Used by the file
     *                                   integrity scan path so the closed
     *                                   plugins are folded into its digest
     *                                   email instead of triggering a second
     *                                   one.
     */
    private function handle_transition( $slug, $previous, $new_entry, $plugin_data, $suppress_email = false ) {
        $previous_state = is_array( $previous ) && isset( $previous['state'] ) ? $previous['state'] : '';
        $new_state      = $new_entry['state'];

        if ( $previous_state === $new_state ) {
            // Stable state, dedupe.
            return;
        }

        $alert_states = array( 'closed', 'removed' );

        // Transition INTO an alert state — log critical and (optionally) email.
        if ( in_array( $new_state, $alert_states, true ) && ! in_array( $previous_state, $alert_states, true ) ) {
            $this->log_closure( $slug, $new_entry );
            if ( ! $suppress_email && ! in_array( $slug, $this->get_ignored_slugs(), true ) ) {
                $this->maybe_send_alert_email( $slug, $new_entry );
            }
            return;
        }

        // Reopen: closed/removed → open.
        if ( 'open' === $new_state && in_array( $previous_state, $alert_states, true ) ) {
            $this->log_reopen( $slug, $new_entry );
            return;
        }

        // closed → removed, or removed → closed: still an alert situation, but
        // the slug was already known as compromised. Log a softer entry so
        // the audit trail captures the change, no email.
        if ( in_array( $new_state, $alert_states, true ) && in_array( $previous_state, $alert_states, true ) ) {
            $this->log_state_change( $slug, $previous_state, $new_entry );
        }
    }

    /**
     * Log a new closure to Security Audit (critical).
     *
     * @param string $slug      Plugin slug.
     * @param array  $new_entry New state entry.
     */
    private function log_closure( $slug, $new_entry ) {
        if ( ! $this->activity_log ) {
            return;
        }

        $name   = $new_entry['name'];
        $state  = $new_entry['state'];

        if ( 'closed' === $state ) {
            $message = sprintf(
                /* translators: %s: plugin name */
                __( 'Plugin "%s" appears as closed in the WordPress.org repository', 'vigilante' ),
                $name
            );
        } else {
            $message = sprintf(
                /* translators: %s: plugin name */
                __( 'Plugin "%s" has been removed from the WordPress.org repository (likely closed for security reasons)', 'vigilante' ),
                $name
            );
        }

        $this->activity_log->log(
            'plugin',
            'closed_detected',
            $message,
            array(
                'object_type'        => 'plugin',
                'object_name'        => $slug,
                'slug'               => $slug,
                'plugin_name'        => $name,
                'version'            => $new_entry['version'],
                'detected_state'     => $state,
                'closed_date'        => $new_entry['closed_date'] ?? '',
                'closed_reason'      => $new_entry['closed_reason'] ?? '',
                'closed_reason_text' => $new_entry['closed_reason_text'] ?? '',
            ),
            'critical'
        );
    }

    /**
     * Log a reopen (closed/removed → open) to Security Audit (info).
     *
     * @param string $slug      Plugin slug.
     * @param array  $new_entry New state entry.
     */
    private function log_reopen( $slug, $new_entry ) {
        if ( ! $this->activity_log ) {
            return;
        }

        $this->activity_log->log(
            'plugin',
            'closed_reopened',
            sprintf(
                /* translators: %s: plugin name */
                __( 'Plugin "%s" is listed again as active in the WordPress.org repository', 'vigilante' ),
                $new_entry['name']
            ),
            array(
                'object_type' => 'plugin',
                'object_name' => $slug,
                'slug'        => $slug,
                'plugin_name' => $new_entry['name'],
                'version'     => $new_entry['version'],
            ),
            'info'
        );
    }

    /**
     * Log a closed→removed or removed→closed transition (still an alert
     * state, no email since it was already known compromised).
     *
     * @param string $slug           Plugin slug.
     * @param string $previous_state Previous state value.
     * @param array  $new_entry      New state entry.
     */
    private function log_state_change( $slug, $previous_state, $new_entry ) {
        if ( ! $this->activity_log ) {
            return;
        }

        $this->activity_log->log(
            'plugin',
            'closed_state_changed',
            sprintf(
                /* translators: 1: plugin name, 2: previous state, 3: new state */
                __( 'Plugin "%1$s" closure state changed from %2$s to %3$s', 'vigilante' ),
                $new_entry['name'],
                $previous_state,
                $new_entry['state']
            ),
            array(
                'object_type'    => 'plugin',
                'object_name'    => $slug,
                'slug'           => $slug,
                'previous_state' => $previous_state,
                'new_state'      => $new_entry['state'],
            ),
            'warning'
        );
    }

    /**
     * Send an alert email on the first detection of a closed/removed plugin.
     * Gated by File Integrity's instant_alert toggle, consistent with how the
     * file integrity scan handles suspicious-file alerts.
     *
     * @param string $slug      Plugin slug.
     * @param array  $new_entry New state entry.
     */
    private function maybe_send_alert_email( $slug, $new_entry ) {
        $fi_options = $this->settings->get_section( 'file_integrity' );
        if ( empty( $fi_options['instant_alert'] ) ) {
            return;
        }

        if ( ! class_exists( 'Vigilante_Email_Template' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-email-template.php';
        }

        $recipients = Vigilante_Email_Template::get_admin_recipients();
        if ( empty( $recipients ) ) {
            return;
        }

        $site_name = get_bloginfo( 'name' );
        $state     = $new_entry['state'];

        $subject = sprintf(
            /* translators: 1: Site name, 2: plugin slug */
            __( '[%1$s] Vigilant: Closed plugin detected — %2$s', 'vigilante' ),
            $site_name,
            $slug
        );

        if ( 'closed' === $state ) {
            $intro = sprintf(
                /* translators: %s: plugin name */
                __( 'Vigilant detected that the plugin "%s" has been closed in the WordPress.org repository.', 'vigilante' ),
                $new_entry['name']
            );
        } else {
            $intro = sprintf(
                /* translators: %s: plugin name */
                __( 'Vigilant detected that the plugin "%s" has been removed from the WordPress.org repository. This usually indicates a closure for security reasons where the public metadata has been hidden.', 'vigilante' ),
                $new_entry['name']
            );
        }

        $body  = Vigilante_Email_Template::p( $intro );
        $body .= Vigilante_Email_Template::alert_box( __( 'Closed or removed plugins should be deactivated and replaced as soon as possible. They no longer receive security updates and the repository team has flagged them as a risk.', 'vigilante' ) );

        $rows = array(
            __( 'Plugin', 'vigilante' )  => $new_entry['name'],
            __( 'Slug', 'vigilante' )    => $slug,
            __( 'Version', 'vigilante' ) => $new_entry['version'] !== '' ? $new_entry['version'] : __( 'unknown', 'vigilante' ),
            __( 'State', 'vigilante' )   => 'closed' === $state ? __( 'Closed', 'vigilante' ) : __( 'Removed', 'vigilante' ),
        );
        if ( ! empty( $new_entry['closed_date'] ) ) {
            $rows[ __( 'Closure date', 'vigilante' ) ] = $new_entry['closed_date'];
        }
        if ( ! empty( $new_entry['closed_reason_text'] ) ) {
            $rows[ __( 'Reason', 'vigilante' ) ] = $new_entry['closed_reason_text'];
        }
        $body .= Vigilante_Email_Template::data_table( $rows );

        $body .= Vigilante_Email_Template::button(
            admin_url( 'admin.php?page=vigilante&tab=file-integrity' ),
            __( 'Review in Vigilant', 'vigilante' )
        );

        Vigilante_Email_Template::send( $recipients, $subject, __( 'Closed plugin detected', 'vigilante' ), $body, true );
    }

    /**
     * Get the stored state map (slug => entry).
     *
     * @return array
     */
    public function get_state() {
        $state = get_option( self::STATE_OPTION, array() );
        return is_array( $state ) ? $state : array();
    }

    /**
     * Get slugs currently in an alert state (closed or removed).
     *
     * @param bool $include_ignored When true, slugs the admin has chosen to
     *                              ignore are returned alongside the active
     *                              ones. Default false (matches what the
     *                              main UI list and the email digest show).
     * @return array Subset of the state map keyed by slug.
     */
    public function get_closed_plugins( $include_ignored = false ) {
        $state   = $this->get_state();
        $ignored = $include_ignored ? array() : $this->get_ignored_slugs();
        $out     = array();
        foreach ( $state as $slug => $entry ) {
            if ( ! isset( $entry['state'] ) ) {
                continue;
            }
            if ( ! in_array( $entry['state'], array( 'closed', 'removed' ), true ) ) {
                continue;
            }
            if ( in_array( $slug, $ignored, true ) ) {
                continue;
            }
            $out[ $slug ] = $entry;
        }
        return $out;
    }

    /**
     * Get the closed/removed slugs the admin has ignored. Used by the UI to
     * render the "Ignored Closed Plugins" subsection separately from the
     * active list, so the user does not lose track of what is intentionally
     * being silenced.
     *
     * @return array Subset of the state map keyed by slug.
     */
    public function get_ignored_closed_plugins() {
        $state   = $this->get_state();
        $ignored = $this->get_ignored_slugs();
        $out     = array();
        foreach ( $ignored as $slug ) {
            if ( isset( $state[ $slug ]['state'] ) && in_array( $state[ $slug ]['state'], array( 'closed', 'removed' ), true ) ) {
                $out[ $slug ] = $state[ $slug ];
            }
        }
        return $out;
    }

    /**
     * Get the raw list of ignored slugs.
     *
     * @return array
     */
    public function get_ignored_slugs() {
        $ignored = get_option( self::IGNORED_OPTION, array() );
        return is_array( $ignored ) ? $ignored : array();
    }

    /**
     * Mark a slug as ignored. Idempotent.
     *
     * @param string $slug Plugin slug.
     * @return bool True on success, false on invalid input.
     */
    public function ignore_slug( $slug ) {
        $slug = sanitize_key( $slug );
        if ( '' === $slug ) {
            return false;
        }
        $ignored = $this->get_ignored_slugs();
        if ( ! in_array( $slug, $ignored, true ) ) {
            $ignored[] = $slug;
            update_option( self::IGNORED_OPTION, $ignored, false );
        }
        return true;
    }

    /**
     * Stop ignoring a slug. Idempotent.
     *
     * @param string $slug Plugin slug.
     * @return bool True on success, false on invalid input.
     */
    public function unignore_slug( $slug ) {
        $slug = sanitize_key( $slug );
        if ( '' === $slug ) {
            return false;
        }
        $ignored = $this->get_ignored_slugs();
        $key     = array_search( $slug, $ignored, true );
        if ( false !== $key ) {
            unset( $ignored[ $key ] );
            update_option( self::IGNORED_OPTION, array_values( $ignored ), false );
        }
        return true;
    }

    /**
     * Drop the entire ignore list.
     */
    public function clear_ignored() {
        delete_option( self::IGNORED_OPTION );
    }

    /**
     * Get timestamp of the last completed sweep.
     *
     * @return int Unix timestamp (0 if never run).
     */
    public function get_last_check_time() {
        return (int) get_option( self::LAST_CHECK_OPTION, 0 );
    }

    /**
     * Clear stored scan state (state map + last_check timestamp). Not called
     * from "Clear Previous Results" any more — that button leaves the plugin
     * status untouched. This method is left available for explicit resets
     * (debug mu-plugin, future Reset to Defaults paths). The ignore list is
     * preserved here; the dedicated "Clear All Ignored Closed + Removed
     * Plugins" button is the explicit way to drop ignores.
     */
    public function clear_results() {
        delete_option( self::STATE_OPTION );
        delete_option( self::LAST_CHECK_OPTION );
    }

    /**
     * Whether the sweep has consumed its time budget.
     *
     * @return bool
     */
    private function is_budget_exceeded() {
        if ( 0.0 === $this->sweep_started_at ) {
            return false;
        }
        return ( microtime( true ) - $this->sweep_started_at ) > self::SCAN_BUDGET;
    }
}
