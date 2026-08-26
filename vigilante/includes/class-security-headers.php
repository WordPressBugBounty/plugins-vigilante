<?php
/**
 * Security Headers Class
 *
 * Manages HTTP security headers via .htaccess
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Security_Headers
 *
 * Applies HTTP security headers via .htaccess for Apache/LiteSpeed servers
 */
class Vigilante_Security_Headers {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Header options
     *
     * @var array
     */
    private $options;

    /**
     * Block markers
     */
    const MARKER_START = '# BEGIN Vigilante Security Headers';
    const MARKER_END   = '# END Vigilante Security Headers';

    /**
     * Constructor
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    public function __construct( $settings ) {
        $this->settings = $settings;
        $this->options  = $settings->get_section( 'security_headers' );
    }

    /**
     * Apply security headers to .htaccess
     *
     * @return bool|WP_Error
     */
    /**
     * @param bool $automatic True when Vigilant is refreshing the block by
     *                        itself rather than because someone pressed Save.
     *                        See Vigilante_Htaccess_Manager::add_block().
     */
    public function apply_rules( $automatic = false ) {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        
        $manager = Vigilante_Htaccess_Manager::get_instance();

        if ( ! $manager->is_apache() ) {
            return new WP_Error( 'not_apache', __( 'Server is not Apache/LiteSpeed', 'vigilante' ) );
        }

        if ( ! $manager->is_writable() ) {
            return new WP_Error( 'not_writable', __( '.htaccess is not writable', 'vigilante' ) );
        }

        $rules = $this->generate_rules_content();

        $result = $manager->add_block( self::MARKER_START, self::MARKER_END, $rules, 'top', $automatic );

        if ( true === $result ) {
            /** This action is documented in class-wpconfig-security.php */
            do_action( 'vigilante_critical_file_written', '.htaccess' );
        }

        return $result;
    }

    /**
     * Remove security headers from .htaccess
     *
     * @return bool|WP_Error
     */
    public function remove_rules() {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        
        $manager = Vigilante_Htaccess_Manager::get_instance();

        $result = $manager->remove_block( self::MARKER_START, self::MARKER_END );

        if ( true === $result ) {
            /** This action is documented in class-wpconfig-security.php */
            do_action( 'vigilante_critical_file_written', '.htaccess' );
        }

        return $result;
    }

    /**
     * Check if rules are active
     *
     * @return bool
     */
    public function are_rules_active() {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        
        $manager = Vigilante_Htaccess_Manager::get_instance();

        return $manager->block_exists( self::MARKER_START );
    }

    /**
     * Check if CSP is restrictive (could break WordPress admin/editor)
     *
     * WordPress block editor (Gutenberg) requires:
     * - script-src: 'unsafe-inline' 'unsafe-eval' (for React)
     * - style-src: 'unsafe-inline' (for dynamic styles)
     * - frame-src: blob: (for iframe previews)
     * - worker-src: blob: (for web workers)
     * - connect-src: blob: (for the client-side media processing of WP 7.1+)
     *
     * @return bool True if CSP would likely break the admin interface.
     */
    public function is_csp_restrictive() {
        if ( empty( $this->options['csp']['enabled'] ) ) {
            return false;
        }

        // If report-only mode, it won't actually block anything
        if ( ! empty( $this->options['csp']['report_only'] ) ) {
            return false;
        }

        $directives = $this->options['csp']['directives'] ?? array();

        // Check script-src for required values
        $script_src = $directives['script-src'] ?? '';
        if ( ! empty( $script_src ) ) {
            // Gutenberg needs 'unsafe-inline' and 'unsafe-eval'
            $has_unsafe_inline = ( false !== strpos( $script_src, "'unsafe-inline'" ) );
            $has_unsafe_eval   = ( false !== strpos( $script_src, "'unsafe-eval'" ) );
            $has_nonce         = ( false !== strpos( $script_src, "'nonce-" ) );

            // If no unsafe-inline and no nonce, it's restrictive
            if ( ! $has_unsafe_inline && ! $has_nonce ) {
                return true;
            }

            // Gutenberg specifically needs unsafe-eval for React
            if ( ! $has_unsafe_eval && ! $has_nonce ) {
                return true;
            }
        }

        // Check style-src for required values
        $style_src = $directives['style-src'] ?? '';
        if ( ! empty( $style_src ) ) {
            $has_unsafe_inline = ( false !== strpos( $style_src, "'unsafe-inline'" ) );
            $has_nonce         = ( false !== strpos( $style_src, "'nonce-" ) );

            if ( ! $has_unsafe_inline && ! $has_nonce ) {
                return true;
            }
        }

        // Check frame-src for blob: (required by Gutenberg for iframe previews)
        $frame_src = $directives['frame-src'] ?? '';
        if ( ! empty( $frame_src ) && false === strpos( $frame_src, 'blob:' ) ) {
            // Only restrictive if frame-src is set and doesn't include blob:
            // Check if it's set to 'none' which would definitely block
            if ( false !== strpos( $frame_src, "'none'" ) ) {
                return true;
            }
            // If frame-src is explicitly set without blob:, it's restrictive
            return true;
        }

        // Check worker-src for blob: (required for web workers)
        $worker_src = $directives['worker-src'] ?? '';
        if ( ! empty( $worker_src ) && false === strpos( $worker_src, 'blob:' ) ) {
            if ( false !== strpos( $worker_src, "'none'" ) ) {
                return true;
            }
        }

        // Check connect-src for blob:. WordPress 7.1 processes images in the
        // browser before uploading them, and @wordpress/vips fetches its
        // WebAssembly binary from a blob: URL. fetch() answers to connect-src,
        // and 'self' does not cover blob:, so without it the upload fails while
        // WordPress still believes the feature is supported (its own detection
        // only tests blob: workers, which worker-src above already allows).
        $connect_src = $directives['connect-src'] ?? '';
        if ( ! empty( $connect_src ) && false === strpos( $connect_src, 'blob:' ) ) {
            return true;
        }

        return false;
    }

    /**
     * Get specific CSP issues that could affect WordPress
     *
     * @return array List of issues with directives.
     */
    public function get_csp_compatibility_issues() {
        $issues = array();

        if ( empty( $this->options['csp']['enabled'] ) ) {
            return $issues;
        }

        if ( ! empty( $this->options['csp']['report_only'] ) ) {
            return $issues;
        }

        $directives = $this->options['csp']['directives'] ?? array();

        // Check script-src
        $script_src = $directives['script-src'] ?? '';
        if ( ! empty( $script_src ) ) {
            if ( false === strpos( $script_src, "'unsafe-inline'" ) && false === strpos( $script_src, "'nonce-" ) ) {
                $issues[] = array(
                    'directive' => 'script-src',
                    'issue'     => __( 'Missing \'unsafe-inline\' - may break admin scripts', 'vigilante' ),
                    'severity'  => 'high',
                );
            }
            if ( false === strpos( $script_src, "'unsafe-eval'" ) ) {
                $issues[] = array(
                    'directive' => 'script-src',
                    'issue'     => __( 'Missing \'unsafe-eval\' - will break the block editor (Gutenberg)', 'vigilante' ),
                    'severity'  => 'high',
                );
            }
        }

        // Check style-src
        $style_src = $directives['style-src'] ?? '';
        if ( ! empty( $style_src ) && false === strpos( $style_src, "'unsafe-inline'" ) ) {
            $issues[] = array(
                'directive' => 'style-src',
                'issue'     => __( 'Missing \'unsafe-inline\' - may break admin styles', 'vigilante' ),
                'severity'  => 'medium',
            );
        }

        // Check frame-src
        $frame_src = $directives['frame-src'] ?? '';
        if ( ! empty( $frame_src ) && false === strpos( $frame_src, 'blob:' ) ) {
            $issues[] = array(
                'directive' => 'frame-src',
                'issue'     => __( 'Missing \'blob:\' - will break the block editor previews', 'vigilante' ),
                'severity'  => 'high',
            );
        }

        // Check worker-src
        $worker_src = $directives['worker-src'] ?? '';
        if ( ! empty( $worker_src ) && false === strpos( $worker_src, 'blob:' ) ) {
            $issues[] = array(
                'directive' => 'worker-src',
                'issue'     => __( 'Missing \'blob:\' - may break background processing', 'vigilante' ),
                'severity'  => 'low',
            );
        }

        // Check connect-src
        $connect_src = $directives['connect-src'] ?? '';
        if ( ! empty( $connect_src ) && false === strpos( $connect_src, 'blob:' ) ) {
            $issues[] = array(
                'directive' => 'connect-src',
                'issue'     => __( 'Missing \'blob:\' - will break image uploads from the editor on WordPress 7.1 and later', 'vigilante' ),
                'severity'  => 'high',
            );
        }

        return $issues;
    }

    /**
     * Make a settings value safe to interpolate into an .htaccess directive.
     *
     * Every value below is written inside a double-quoted argument of a
     * "Header always set" line. Two characters break out of that argument:
     *
     * - A line break ends the directive and turns whatever follows into a new
     *   Apache directive, which is arbitrary server configuration.
     * - A double quote closes the argument early and leaves the remainder as
     *   stray arguments, which Apache rejects with a 500.
     *
     * No header value this plugin writes legitimately contains either: CSP
     * source expressions use single quotes ('self', 'unsafe-inline'), and the
     * rest are single-token values from fixed lists. Applied at generation time
     * rather than at save time so the guard holds however the value reached the
     * option (a crafted request, an imported settings file, a direct write).
     *
     * @param mixed $value Raw settings value.
     * @return string
     */
    private function sanitize_header_value( $value ) {
        return str_replace( array( '"', "\r", "\n" ), '', (string) $value );
    }

    /**
     * Generate rules content (without markers)
     *
     * Public since 2.10.0: it is also "what this configuration would write right
     * now", which is what Vigilante_Htaccess_Recovery compares the file against.
     *
     * @return string
     */
    public function generate_rules_content() {
        $rules = array();
        
        $rules[] = '# Vigilante - Security Headers';
        $rules[] = '# Generated: ' . gmdate( 'Y-m-d H:i:s' ) . ' UTC';

        // Check if CSP is restrictive (could break admin interface)
        $is_csp_restrictive = $this->is_csp_restrictive();

        // If CSP is restrictive, we need to skip it for wp-admin to prevent breaking the admin interface
        if ( $is_csp_restrictive ) {
            $rules[] = '';
            $rules[] = '# Skip restrictive CSP for WordPress admin area to prevent breaking the editor';
            $rules[] = '<IfModule mod_setenvif.c>';
            $rules[] = '    SetEnvIf Request_URI "^/wp-admin" VIGILANTE_SKIP_CSP';
            $rules[] = '    SetEnvIf Request_URI "admin-ajax\\.php$" VIGILANTE_SKIP_CSP';
            $rules[] = '    SetEnvIf Request_URI "wp-login\\.php$" VIGILANTE_SKIP_CSP';
            $rules[] = '</IfModule>';
        }

        $rules[] = '';
        $rules[] = '<IfModule mod_headers.c>';

        // X-Frame-Options
        if ( ! empty( $this->options['x_frame_options'] ) ) {
            $value = $this->options['x_frame_options'];
            $rules[] = '    # Clickjacking protection';
            $rules[] = '    Header always set X-Frame-Options "' . $this->sanitize_header_value( $value ) . '"';
        }

        // X-Content-Type-Options
        if ( ! empty( $this->options['x_content_type_options'] ) ) {
            $rules[] = '    # Prevent MIME type sniffing';
            $rules[] = '    Header always set X-Content-Type-Options "nosniff"';
        }

        // Referrer-Policy
        if ( ! empty( $this->options['referrer_policy'] ) ) {
            $value = $this->options['referrer_policy'];
            $rules[] = '    # Referrer Policy';
            $rules[] = '    Header always set Referrer-Policy "' . $this->sanitize_header_value( $value ) . '"';
        }

        // Strict-Transport-Security (HSTS)
        if ( ! empty( $this->options['hsts']['enabled'] ) ) {
            $hsts = $this->options['hsts'];
            $value = 'max-age=' . absint( $hsts['max_age'] );

            if ( ! empty( $hsts['include_subdomains'] ) ) {
                $value .= '; includeSubDomains';
            }

            if ( ! empty( $hsts['preload'] ) ) {
                $value .= '; preload';
            }

            $rules[] = '    # HTTP Strict Transport Security';
            $rules[] = '    Header always set Strict-Transport-Security "' . $value . '"';
        }

        // Permissions-Policy
        if ( ! empty( $this->options['permissions_policy']['enabled'] ) ) {
            $permissions = $this->options['permissions_policy'];
            $directives = array();

            $policy_items = array(
                'geolocation', 'microphone', 'camera', 'payment',
                'usb', 'magnetometer', 'gyroscope', 'accelerometer',
            );

            foreach ( $policy_items as $item ) {
                if ( isset( $permissions[ $item ] ) ) {
                    $directives[] = $item . '=' . $permissions[ $item ];
                }
            }

            if ( ! empty( $directives ) ) {
                $rules[] = '    # Permissions Policy';
                $rules[] = '    Header always set Permissions-Policy "' . $this->sanitize_header_value( implode( ', ', $directives ) ) . '"';
            }
        }

        // Content-Security-Policy
        if ( ! empty( $this->options['csp']['enabled'] ) ) {
            $csp = $this->options['csp'];
            $directives = array();

            // Synchronize frame-ancestors with X-Frame-Options
            $frame_ancestors_value = '';
            if ( ! empty( $this->options['x_frame_options'] ) ) {
                if ( 'DENY' === $this->options['x_frame_options'] ) {
                    $frame_ancestors_value = "'none'";
                } elseif ( 'SAMEORIGIN' === $this->options['x_frame_options'] ) {
                    $frame_ancestors_value = "'self'";
                }
            }

            if ( ! empty( $csp['directives'] ) && is_array( $csp['directives'] ) ) {
                foreach ( $csp['directives'] as $directive => $value ) {
                    // Override frame-ancestors with synchronized value if X-Frame-Options is set
                    if ( 'frame-ancestors' === $directive && ! empty( $frame_ancestors_value ) ) {
                        $directives[] = $directive . ' ' . $frame_ancestors_value;
                    } elseif ( true === $value ) {
                        $directives[] = $directive;
                    } elseif ( false !== $value && ! empty( $value ) ) {
                        $directives[] = $directive . ' ' . $value;
                    }
                }
            }

            // Add frame-ancestors if not already present but X-Frame-Options is set
            if ( ! empty( $frame_ancestors_value ) ) {
                $has_frame_ancestors = false;
                foreach ( $directives as $dir ) {
                    if ( 0 === strpos( $dir, 'frame-ancestors' ) ) {
                        $has_frame_ancestors = true;
                        break;
                    }
                }
                if ( ! $has_frame_ancestors ) {
                    $directives[] = 'frame-ancestors ' . $frame_ancestors_value;
                }
            }

            if ( ! empty( $directives ) ) {
                $header_value = implode( '; ', $directives );

                // The value travels inside a double-quoted argument of the
                // "Header always set" line below. A double quote in a directive
                // would close that argument early and leave the rest of the
                // policy as stray arguments, which Apache rejects with a 500.
                // CSP source expressions use single quotes ('self',
                // 'unsafe-inline'), never double ones, so no legitimate policy
                // can be affected. Done here rather than at save time so the
                // guard holds however the value reached the option.
                $header_value = $this->sanitize_header_value( $header_value );

                if ( ! empty( $csp['report_uri'] ) ) {
                    $header_value .= '; report-uri ' . $this->sanitize_header_value( esc_url( $csp['report_uri'] ) );
                }

                $header_name = ! empty( $csp['report_only'] ) 
                    ? 'Content-Security-Policy-Report-Only' 
                    : 'Content-Security-Policy';

                $rules[] = '    # Content Security Policy';

                // If CSP is restrictive, only apply it outside wp-admin
                if ( $is_csp_restrictive ) {
                    $rules[] = '    # Note: Restrictive CSP skipped for wp-admin to prevent breaking the block editor';
                    $rules[] = '    Header always set ' . $header_name . ' "' . $header_value . '" env=!VIGILANTE_SKIP_CSP';
                } else {
                    $rules[] = '    Header always set ' . $header_name . ' "' . $header_value . '"';
                }
            }
        }

        /*
         * Cross-Origin policies.
         *
         * Allow-listed rather than escaped, for the same reason sanitize_header_value()
         * runs at generation time: these three became editable in 2.10.0 and their value
         * is written verbatim inside a Header directive. Only the tokens the specs define
         * are ever emitted, so an unexpected value (a crafted request, an imported
         * settings file, a direct write to the option) drops the header instead of
         * reaching the .htaccess.
         *
         * COEP deliberately omits unsafe-none: it is the browser default, so emitting it
         * adds nothing. That was the behaviour before this list existed and it is kept.
         */
        if ( ! empty( $this->options['cross_origin_policies'] ) ) {
            $policies = $this->options['cross_origin_policies'];

            $coep = isset( $policies['embedder_policy'] ) ? (string) $policies['embedder_policy'] : '';
            if ( in_array( $coep, array( 'require-corp', 'credentialless' ), true ) ) {
                $rules[] = '    Header always set Cross-Origin-Embedder-Policy "' . $coep . '"';
            }

            $coop = isset( $policies['opener_policy'] ) ? (string) $policies['opener_policy'] : '';
            if ( in_array( $coop, array( 'unsafe-none', 'same-origin-allow-popups', 'same-origin' ), true ) ) {
                $rules[] = '    Header always set Cross-Origin-Opener-Policy "' . $coop . '"';
            }

            $corp = isset( $policies['resource_policy'] ) ? (string) $policies['resource_policy'] : '';
            if ( in_array( $corp, array( 'same-site', 'same-origin', 'cross-origin' ), true ) ) {
                $rules[] = '    Header always set Cross-Origin-Resource-Policy "' . $corp . '"';
            }
        }

        // Remove X-Powered-By
        $rules[] = '    # Hide PHP version';
        $rules[] = '    Header always unset X-Powered-By';

        $rules[] = '</IfModule>';

        return implode( "\n", $rules );
    }

    /**
     * Get security grade based on enabled headers
     *
     * @return array
     */
    public function get_security_grade() {
        $score = 0;
        $enabled = array();
        $missing = array();
        $warnings = array();

        // X-Frame-Options (15 points)
        if ( ! empty( $this->options['x_frame_options'] ) ) {
            $score += 15;
            $enabled[] = 'X-Frame-Options: ' . $this->options['x_frame_options'];
        } else {
            $missing[] = 'X-Frame-Options';
        }

        // X-Content-Type-Options (15 points)
        if ( ! empty( $this->options['x_content_type_options'] ) ) {
            $score += 15;
            $enabled[] = 'X-Content-Type-Options: nosniff';
        } else {
            $missing[] = 'X-Content-Type-Options';
        }

        // HSTS (20 points)
        if ( ! empty( $this->options['hsts']['enabled'] ) ) {
            $hsts = $this->options['hsts'];
            if ( $hsts['max_age'] >= 31536000 ) {
                $score += 20;
            } else {
                $score += 10;
                $warnings[] = 'HSTS max-age should be at least 1 year (31536000 seconds)';
            }
            $enabled[] = 'Strict-Transport-Security';
        } else {
            $missing[] = 'Strict-Transport-Security (HSTS)';
        }

        // CSP (30 points; absorbs the 10 points freed by retiring the deprecated X-XSS-Protection)
        if ( ! empty( $this->options['csp']['enabled'] ) ) {
            if ( empty( $this->options['csp']['report_only'] ) ) {
                $score += 30;
                $enabled[] = 'Content-Security-Policy';
                
                // Add warning if CSP is restrictive
                if ( $this->is_csp_restrictive() ) {
                    $warnings[] = __( 'Restrictive CSP detected. Admin area is automatically excluded to prevent breaking the dashboard and block editor.', 'vigilante' );
                }

                // Check for specific compatibility issues
                $csp_issues = $this->get_csp_compatibility_issues();
                foreach ( $csp_issues as $issue ) {
                    if ( 'high' === $issue['severity'] ) {
                        $warnings[] = sprintf(
                            /* translators: 1: CSP directive name, 2: Issue description */
                            __( 'CSP %1$s: %2$s', 'vigilante' ),
                            $issue['directive'],
                            $issue['issue']
                        );
                    }
                }
            } else {
                $score += 15;
                $enabled[] = 'Content-Security-Policy-Report-Only';
                $warnings[] = 'CSP is in report-only mode (recommended for testing)';
            }
        } else {
            $missing[] = 'Content-Security-Policy';
        }

        // Referrer-Policy (10 points)
        if ( ! empty( $this->options['referrer_policy'] ) ) {
            $score += 10;
            $enabled[] = 'Referrer-Policy: ' . $this->options['referrer_policy'];
        } else {
            $missing[] = 'Referrer-Policy';
        }

        // Permissions-Policy (10 points)
        if ( ! empty( $this->options['permissions_policy']['enabled'] ) ) {
            $score += 10;
            $enabled[] = 'Permissions-Policy';
        } else {
            $missing[] = 'Permissions-Policy';
        }

        // Calculate grade
        if ( $score >= 90 ) {
            $grade = 'A';
        } elseif ( $score >= 80 ) {
            $grade = 'B';
        } elseif ( $score >= 70 ) {
            $grade = 'C';
        } elseif ( $score >= 60 ) {
            $grade = 'D';
        } else {
            $grade = 'F';
        }

        return array(
            'grade'    => $grade,
            'score'    => $score,
            'headers'  => $enabled,
            'missing'  => $missing,
            'warnings' => $warnings,
        );
    }
}