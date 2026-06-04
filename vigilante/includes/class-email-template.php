<?php
/**
 * Email Template Helper
 *
 * Centralized HTML email builder for consistent styling
 * across all plugin notifications.
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Email_Template
 *
 * Provides reusable HTML email components
 */
class Vigilante_Email_Template {

    /**
     * Send an HTML email using the standard template
     *
     * Uses direct headers instead of wp_mail filters to prevent
     * filter contamination between consecutive wp_mail() calls.
     *
     * @param string|array $to        Recipient(s).
     * @param string       $subject   Email subject.
     * @param string       $title     Header title.
     * @param string       $body      Body HTML (use helper methods to build).
     * @param bool         $alert     Whether this is an alert (red header accent).
     * @param string       $from_name Optional custom From name.
     * @return bool
     */
    public static function send( $to, $subject, $title, $body, $alert = false, $from_name = '' ) {
        $html    = self::wrap( $title, $body, $alert );
        $headers = array( 'Content-Type: text/html; charset=UTF-8' );

        // Set From header directly (avoids wp_mail_from_name filter pollution)
        if ( ! empty( $from_name ) ) {
            // Use WordPress default from email (same logic as wp_mail core)
            $sitename = wp_parse_url( network_home_url(), PHP_URL_HOST );
            if ( 'www.' === substr( $sitename, 0, 4 ) ) {
                $sitename = substr( $sitename, 4 );
            }
            $from_email = 'wordpress@' . $sitename;

            /**
             * Filters the from email for Vigilante emails.
             *
             * @param string $from_email Default from email.
             */
            $from_email = apply_filters( 'vigilante_email_from', $from_email );

            $headers[] = 'From: ' . sanitize_text_field( $from_name ) . ' <' . sanitize_email( $from_email ) . '>';
        }

        $result = wp_mail( $to, $subject, $html, $headers );

        if ( ! $result && defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            $recipient = is_array( $to ) ? implode( ', ', $to ) : $to;
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug logging
            error_log( 'Vigilant email failed: to=' . $recipient . ' subject=' . $subject );
        }

        return $result;
    }

    /**
     * Get centralized admin notification recipients
     *
     * Reads from the email settings section and builds the
     * recipient list. All admin notifications should use this
     * method instead of resolving recipients individually.
     *
     * @return array Array of valid email addresses.
     */
    public static function get_admin_recipients() {
        $options       = get_option( 'vigilante_options', array() );
        $email_settings = isset( $options['email'] ) ? $options['email'] : array();

        $recipients = array();

        // Include WordPress admin email if enabled (default: true)
        $send_to_admin = isset( $email_settings['send_to_admin_email'] )
            ? (bool) $email_settings['send_to_admin_email']
            : true;

        if ( $send_to_admin ) {
            $admin_email = get_option( 'admin_email' );
            if ( ! empty( $admin_email ) && is_email( $admin_email ) ) {
                $recipients[] = $admin_email;
            }
        }

        // Parse additional recipients (supports array and legacy string format)
        $additional_raw = isset( $email_settings['additional_recipients'] )
            ? $email_settings['additional_recipients']
            : array();

        // Normalize to array
        if ( is_string( $additional_raw ) ) {
            // Legacy string format or corrupted data: split by newlines, commas, semicolons
            $additional_list = preg_split( '/[\r\n,;]+/', trim( $additional_raw ) );
        } else {
            $additional_list = (array) $additional_raw;
        }

        foreach ( $additional_list as $line ) {
            $email = sanitize_email( trim( $line ) );
            if ( ! empty( $email ) && is_email( $email ) && ! in_array( $email, $recipients, true ) ) {
                $recipients[] = $email;
            }
        }

        // Fallback: only use admin email if settings were never configured
        // (send_to_admin_email key doesn't exist at all, not just false)
        if ( empty( $recipients ) && ! array_key_exists( 'send_to_admin_email', $email_settings ) ) {
            $fallback = get_option( 'admin_email' );
            if ( ! empty( $fallback ) && is_email( $fallback ) ) {
                $recipients[] = $fallback;
            }
        }

        /**
         * Filters the admin notification recipients.
         *
         * Allows developers to modify the recipient list for
         * all administrative email notifications.
         *
         * @param array $recipients Array of email addresses.
         */
        return apply_filters( 'vigilante_notification_recipients', $recipients );
    }

    /**
     * Wrap body content in the standard email shell
     *
     * @param string $title Header title.
     * @param string $body  Body HTML.
     * @param bool   $alert Red accent header.
     * @return string Full HTML email.
     */
    public static function wrap( $title, $body, $alert = false ) {
        $site_name = get_bloginfo( 'name' );
        $header_bg = $alert ? '#d63638' : '#1d2327';

        $html  = '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>';
        $html .= '<body style="margin:0;padding:0;background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Oxygen-Sans,Ubuntu,Cantarell,\'Helvetica Neue\',sans-serif;-webkit-text-size-adjust:100%;">';
        $html .= '<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f0f1;padding:32px 0;">';
        $html .= '<tr><td align="center">';
        $html .= '<table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:6px;overflow:hidden;border:1px solid #c3c4c7;">';

        // Header
        $html .= '<tr><td style="background:' . esc_attr( $header_bg ) . ';padding:18px 28px;">';
        $html .= '<table width="100%" cellpadding="0" cellspacing="0"><tr>';
        $html .= '<td style="color:#ffffff;font-size:14px;font-weight:600;">' . esc_html__( 'Vigilant', 'vigilante' ) . '</td>';
        $html .= '<td align="right" style="color:rgba(255,255,255,0.6);font-size:12px;">' . esc_html( $site_name ) . '</td>';
        $html .= '</tr></table>';
        $html .= '</td></tr>';

        // Title
        if ( ! empty( $title ) ) {
            $html .= '<tr><td style="padding:24px 28px 0;">';
            $html .= '<h1 style="margin:0;font-size:18px;font-weight:600;color:#1d2327;line-height:1.4;">' . esc_html( $title ) . '</h1>';
            $html .= '</td></tr>';
        }

        // Body
        $html .= '<tr><td style="padding:16px 28px 28px;">';
        $html .= $body;
        $html .= '</td></tr>';

        // Footer
        $html .= '<tr><td style="padding:16px 28px;background:#f6f7f7;border-top:1px solid #dcdcde;">';
        $html .= '<p style="color:#787c82;font-size:11px;margin:0;text-align:center;line-height:1.5;">';
        $html .= esc_html( $site_name ) . ' &mdash; ' . esc_url( home_url() );
        $html .= '</p></td></tr>';

        $html .= '</table></td></tr></table></body></html>';

        return $html;
    }

    // =========================================================================
    // Body content helpers
    // =========================================================================

    /**
     * Paragraph
     *
     * @param string $text    Text content (will be escaped).
     * @param string $color   Text color.
     * @param bool   $bold    Whether to bold.
     * @return string
     */
    public static function p( $text, $color = '#1d2327', $bold = false ) {
        $weight = $bold ? 'font-weight:600;' : '';
        return '<p style="color:' . esc_attr( $color ) . ';font-size:14px;line-height:1.6;margin:0 0 14px;' . $weight . '">' . esc_html( $text ) . '</p>';
    }

    /**
     * Raw HTML paragraph (for content with links etc.)
     *
     * @param string $html  HTML content (caller must escape).
     * @param string $color Text color.
     * @return string
     */
    public static function p_raw( $html, $color = '#1d2327' ) {
        return '<p style="color:' . esc_attr( $color ) . ';font-size:14px;line-height:1.6;margin:0 0 14px;">' . $html . '</p>';
    }

    /**
     * Small text paragraph
     *
     * @param string $text Text content.
     * @return string
     */
    public static function small( $text ) {
        return '<p style="color:#787c82;font-size:12px;line-height:1.5;margin:0 0 14px;">' . esc_html( $text ) . '</p>';
    }

    /**
     * Data table (key-value pairs)
     *
     * @param array $rows Associative array of label => value.
     * @return string
     */
    public static function data_table( $rows ) {
        $html = '<table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 16px;font-size:13px;">';
        foreach ( $rows as $label => $value ) {
            $html .= '<tr>';
            $html .= '<td style="padding:6px 12px 6px 0;color:#787c82;white-space:nowrap;vertical-align:top;">' . esc_html( $label ) . '</td>';
            $html .= '<td style="padding:6px 0;color:#1d2327;word-break:break-all;">' . esc_html( $value ) . '</td>';
            $html .= '</tr>';
        }
        $html .= '</table>';
        return $html;
    }

    /**
     * Highlighted info box (blue left border)
     *
     * @param string $text Text content.
     * @return string
     */
    public static function info_box( $text ) {
        return '<div style="background:#f0f6fc;border-left:4px solid #2271b1;border-radius:0 4px 4px 0;padding:12px 16px;margin:0 0 16px;">'
            . '<p style="color:#1d2327;font-size:13px;line-height:1.5;margin:0;">' . esc_html( $text ) . '</p></div>';
    }

    /**
     * Warning box (orange left border)
     *
     * @param string $text Text content.
     * @return string
     */
    public static function warning_box( $text ) {
        return '<div style="background:#fdf8e8;border-left:4px solid #dba617;border-radius:0 4px 4px 0;padding:12px 16px;margin:0 0 16px;">'
            . '<p style="color:#1d2327;font-size:13px;line-height:1.5;margin:0;">' . esc_html( $text ) . '</p></div>';
    }

    /**
     * Alert/error box (red left border)
     *
     * @param string $text Text content.
     * @return string
     */
    public static function alert_box( $text ) {
        return '<div style="background:#fcf0f1;border-left:4px solid #d63638;border-radius:0 4px 4px 0;padding:12px 16px;margin:0 0 16px;">'
            . '<p style="color:#1d2327;font-size:13px;line-height:1.5;margin:0;font-weight:500;">' . esc_html( $text ) . '</p></div>';
    }

    /**
     * Success box (green left border)
     *
     * @param string $text Text content.
     * @return string
     */
    public static function success_box( $text ) {
        return '<div style="background:#edfaef;border-left:4px solid #00a32a;border-radius:0 4px 4px 0;padding:12px 16px;margin:0 0 16px;">'
            . '<p style="color:#1d2327;font-size:13px;line-height:1.5;margin:0;">' . esc_html( $text ) . '</p></div>';
    }

    /**
     * Highlighted code/value display (e.g., verification codes)
     *
     * @param string $code  Code or value to display.
     * @param string $label Optional label above the code.
     * @return string
     */
    public static function code_box( $code, $label = '' ) {
        $html = '<div style="text-align:center;margin:0 0 16px;">';
        if ( ! empty( $label ) ) {
            $html .= '<p style="color:#787c82;font-size:13px;margin:0 0 8px;">' . esc_html( $label ) . '</p>';
        }
        $html .= '<div style="background:#f0f6fc;border:2px solid #2271b1;border-radius:8px;padding:14px 24px;display:inline-block;">';
        $html .= '<span style="font-size:28px;font-weight:700;letter-spacing:6px;font-family:Consolas,Monaco,monospace;color:#1d2327;">';
        $html .= esc_html( $code );
        $html .= '</span></div></div>';
        return $html;
    }

    /**
     * URL display box (for login URLs, links, etc.)
     *
     * Unlike code_box, uses normal font size and word-break
     * to handle long URLs without overflowing.
     *
     * @param string $url   URL to display.
     * @param string $label Optional label above the URL.
     * @return string
     */
    public static function url_box( $url, $label = '' ) {
        $html = '<div style="text-align:center;margin:0 0 16px;">';
        if ( ! empty( $label ) ) {
            $html .= '<p style="color:#787c82;font-size:13px;margin:0 0 8px;">' . esc_html( $label ) . '</p>';
        }
        $html .= '<div style="background:#f0f6fc;border:2px solid #2271b1;border-radius:8px;padding:14px 20px;">';
        $html .= '<a href="' . esc_url( $url ) . '" style="font-size:16px;font-weight:600;font-family:Consolas,Monaco,monospace;color:#2271b1;text-decoration:none;word-break:break-all;">';
        $html .= esc_html( $url );
        $html .= '</a></div></div>';
        return $html;
    }

    /**
     * CTA button
     *
     * @param string $url  Button URL.
     * @param string $text Button text.
     * @param string $bg   Background color.
     * @return string
     */
    public static function button( $url, $text, $bg = '#2271b1' ) {
        return '<p style="text-align:center;margin:20px 0 16px;">'
            . '<a href="' . esc_url( $url ) . '" style="display:inline-block;background:' . esc_attr( $bg ) . ';color:#ffffff;text-decoration:none;padding:10px 28px;border-radius:4px;font-size:14px;font-weight:600;">'
            . esc_html( $text ) . '</a></p>';
    }

    /**
     * Simple unordered list
     *
     * @param array $items List items (HTML allowed, caller must escape).
     * @return string
     */
    public static function ul( $items ) {
        $html = '<ul style="color:#1d2327;font-size:13px;line-height:1.6;margin:0 0 16px;padding-left:20px;">';
        foreach ( $items as $item ) {
            $html .= '<li style="margin-bottom:4px;">' . wp_kses( $item, array( 'a' => array( 'href' => array() ), 'strong' => array(), 'code' => array() ) ) . '</li>';
        }
        $html .= '</ul>';
        return $html;
    }

    /**
     * Horizontal divider
     *
     * @return string
     */
    public static function hr() {
        return '<hr style="border:none;border-top:1px solid #dcdcde;margin:20px 0;">';
    }
}