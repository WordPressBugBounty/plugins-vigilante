<?php
/**
 * Audit Alerts AJAX handlers
 *
 * Kept in a separate trait (same pattern as class-admin-analyzer-ajax.php) so
 * the main class-admin-ajax.php does not keep growing. Settings are saved
 * through the generic ajax_save_settings handler (data-section="audit_alerts");
 * this trait only adds the "Send test email" endpoint.
 *
 * @package Vigilante
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Trait Vigilante_Admin_Audit_Alerts_Ajax
 */
trait Vigilante_Admin_Audit_Alerts_Ajax {

    /**
     * Send a test email to the configured recipients.
     *
     * Shared by the "Send test email" button in Notification settings, File
     * Integrity and Audit Alerts.
     */
    public function ajax_send_test_email() {
        check_ajax_referer( 'vigilante_admin_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'Permission denied.', 'vigilante' ) ) );
        }

        $recipients = Vigilante_Email_Template::get_admin_recipients();
        if ( empty( $recipients ) ) {
            wp_send_json_error(
                array(
                    'message' => __( 'No notification recipients are configured. Set them in Settings & Tools.', 'vigilante' ),
                )
            );
        }

        $sent = Vigilante_Email_Template::send_test();

        if ( $sent ) {
            wp_send_json_success(
                array(
                    'message' => sprintf(
                        /* translators: %s: comma-separated list of recipient email addresses */
                        __( 'Test email sent to %s.', 'vigilante' ),
                        implode( ', ', $recipients )
                    ),
                )
            );
        }

        wp_send_json_error(
            array(
                'message' => __( 'WordPress could not send the email. Check your site mail configuration.', 'vigilante' ),
            )
        );
    }
}
