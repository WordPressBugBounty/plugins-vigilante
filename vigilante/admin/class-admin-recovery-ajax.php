<?php
/**
 * AJAX handlers for the Security Headers settings recovery
 *
 * Mixed into Vigilante_Admin via `use Vigilante_Admin_Recovery_Ajax;`.
 * Kept apart so class-admin-ajax.php does not grow further.
 *
 * All handlers require `manage_options` and a valid vigilante_admin_nonce.
 *
 * @package Vigilante
 * @since 2.10.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Trait Vigilante_Admin_Recovery_Ajax
 */
trait Vigilante_Admin_Recovery_Ajax {

    /**
     * Shared gate for the three handlers.
     */
    private function recovery_ajax_gate() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( __( 'Permission denied.', 'vigilante' ) );
        }

        // On a network the .htaccess belongs to the whole network, and only the
        // main site decides what goes in it.
        if ( ! Vigilante_Settings::can_write_shared_files() ) {
            wp_send_json_error( Vigilante_Settings::get_shared_files_notice() );
        }
    }

    /**
     * Write the recovered header settings.
     */
    public function ajax_headers_recovery_restore() {
        $this->recovery_ajax_gate();

        $result = Vigilante_Htaccess_Recovery::restore( $this->settings );

        if ( is_wp_error( $result ) ) {
            wp_send_json_error( $result->get_error_message() );
        }

        if ( $this->activity_log ) {
            $this->activity_log->log(
                'system',
                'headers_settings_restored',
                __( 'The Security Headers settings were restored from the .htaccess snapshot taken before the 2.9.8 migration reset them.', 'vigilante' ),
                array(),
                'info'
            );
        }

        wp_send_json_success( __( 'Settings restored. The .htaccess rules were rewritten to match.', 'vigilante' ) );
    }

    /**
     * Put the settings back as they were before restoring.
     */
    public function ajax_headers_recovery_undo() {
        $this->recovery_ajax_gate();

        $result = Vigilante_Htaccess_Recovery::undo( $this->settings );

        if ( is_wp_error( $result ) ) {
            wp_send_json_error( $result->get_error_message() );
        }

        wp_send_json_success( __( 'The restore was undone.', 'vigilante' ) );
    }

    /**
     * Stop offering the recovery, changing nothing.
     */
    public function ajax_headers_recovery_dismiss() {
        $this->recovery_ajax_gate();

        Vigilante_Htaccess_Recovery::dismiss();

        wp_send_json_success( __( 'Dismissed. No setting was changed.', 'vigilante' ) );
    }
}
