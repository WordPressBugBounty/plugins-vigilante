<?php
/**
 * Security Analyzer — AJAX handlers (trait).
 *
 * Mixed into Vigilante_Admin via `use Vigilante_Admin_Analyzer_Ajax;`.
 * All handlers require `manage_options` and a valid vigilante_admin_nonce.
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Trait carrying the three analyzer AJAX endpoints.
 */
trait Vigilante_Admin_Analyzer_Ajax {

    /**
     * POST vigilante_analyzer_run
     *   payload: { phase: 'fast'|'slow'|'all' }
     *   returns: the scan report (from Vigilante_Security_Analyzer::run_scan()).
     */
    public function ajax_analyzer_run() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ), 403 );
        }

        $phase = isset( $_POST['phase'] ) ? sanitize_key( wp_unslash( $_POST['phase'] ) ) : 'all';
        if ( ! in_array( $phase, array( 'fast', 'slow', 'all' ), true ) ) {
            $phase = 'all';
        }

        try {
            $analyzer = $this->get_security_analyzer();
            if ( ! $analyzer ) {
                wp_send_json_error( __( 'Security Analyzer is not available.', 'vigilante' ) );
            }
            // Run the phase (persists and merges with prior state).
            $analyzer->run_scan( $phase );
            // Return the merged state so the UI progressively shows everything seen so far.
            $merged = $analyzer->get_last_scan();
            if ( empty( $merged ) ) {
                wp_send_json_error( __( 'Scan returned no data.', 'vigilante' ) );
            }
            $merged['phase']   = $phase;
            $merged['catalog'] = $analyzer->get_catalog();
            wp_send_json_success( $merged );
        } catch ( Exception $e ) {
            wp_send_json_error( 'Exception: ' . $e->getMessage() );
        } catch ( Error $e ) {
            wp_send_json_error( 'Error: ' . $e->getMessage() );
        }
    }

    /**
     * POST vigilante_analyzer_history
     *   returns: up to HISTORY_LIMIT entries of { ran_at, score, grade, categories[...] }.
     */
    public function ajax_analyzer_history() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ), 403 );
        }

        $analyzer = $this->get_security_analyzer();
        if ( ! $analyzer ) {
            wp_send_json_error( __( 'Security Analyzer is not available.', 'vigilante' ) );
        }

        $limit   = isset( $_POST['limit'] ) ? max( 1, min( 60, (int) $_POST['limit'] ) ) : 30;
        $history = $analyzer->get_score_history( $limit );

        wp_send_json_success(
            array(
                'history' => array_values( $history ),
                'limit'   => $limit,
            )
        );
    }

    /**
     * POST vigilante_analyzer_dismiss_notice
     *   payload: { key: string }
     *   marks a one-time analyzer notice (e.g. "enable weekly email") as dismissed.
     */
    public function ajax_analyzer_dismiss_notice() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ), 403 );
        }

        $key = isset( $_POST['key'] ) ? sanitize_key( wp_unslash( $_POST['key'] ) ) : '';
        if ( '' === $key ) {
            wp_send_json_error( __( 'Missing key.', 'vigilante' ) );
        }

        $dismissed = get_option( 'vigilante_dismissed_notices', array() );
        if ( ! is_array( $dismissed ) ) {
            $dismissed = array();
        }
        $dismissed[ 'analyzer_' . $key ] = time();
        update_option( 'vigilante_dismissed_notices', $dismissed, false );

        wp_send_json_success();
    }

    /**
     * POST vigilante_analyzer_save_settings
     *   payload: { weekly_scan_enabled: 0|1, email_on_regression: 0|1 }
     *   Saves the `security_analyzer` subsection of vigilante_options.
     */
    public function ajax_analyzer_save_settings() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ), 403 );
        }

        if ( ! isset( $this->settings ) || ! $this->settings ) {
            wp_send_json_error( __( 'Settings not available.', 'vigilante' ) );
        }

        $weekly_enabled = ! empty( $_POST['weekly_scan_enabled'] ) ? 1 : 0;
        $email_regress  = ! empty( $_POST['email_on_regression'] ) ? 1 : 0;

        $section = array(
            'weekly_scan_enabled' => (bool) $weekly_enabled,
            'email_on_regression' => (bool) $email_regress,
        );

        $this->settings->update_section( 'security_analyzer', $section );

        // Keep the cron schedule in sync with the toggle.
        $hook = 'vigilante_analyzer_weekly_scan';
        if ( $weekly_enabled ) {
            if ( ! wp_next_scheduled( $hook ) ) {
                wp_schedule_event( time() + DAY_IN_SECONDS, 'weekly', $hook );
            }
        } else {
            $timestamp = wp_next_scheduled( $hook );
            if ( $timestamp ) {
                wp_unschedule_event( $timestamp, $hook );
            }
            wp_unschedule_hook( $hook );
        }

        wp_send_json_success(
            array(
                'weekly_scan_enabled' => (bool) $weekly_enabled,
                'email_on_regression' => (bool) $email_regress,
            )
        );
    }

    /**
     * Lazy-load the Vigilante_Security_Analyzer instance.
     *
     * @return Vigilante_Security_Analyzer|null
     */
    protected function get_security_analyzer() {
        if ( ! isset( $this->settings ) || ! $this->settings ) {
            return null;
        }
        if ( ! class_exists( 'Vigilante_Security_Analyzer' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-security-analyzer.php';
        }
        $activity_log = isset( $this->activity_log ) ? $this->activity_log : null;
        return new Vigilante_Security_Analyzer( $this->settings, $activity_log );
    }
}
