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
    public function apply_rules() {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        
        $manager = Vigilante_Htaccess_Manager::get_instance();

        if ( ! $manager->is_apache() ) {
            return new WP_Error( 'not_apache', __( 'Server is not Apache/LiteSpeed', 'vigilante' ) );
        }

        if ( ! $manager->is_writable() ) {
            return new WP_Error( 'not_writable', __( '.htaccess is not writable', 'vigilante' ) );
        }

        $rules = $this->generate_rules_content();

        $result = $manager->add_block( self::MARKER_START, self::MARKER_END, $rules, 'top' );

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

        return $issues;
    }

    /**
     * Generate rules content (without markers)
     *
     * @return string
     */
    private function generate_rules_content() {
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
            $rules[] = '    Header always set X-Frame-Options "' . esc_attr( $value ) . '"';
        }

        // X-Content-Type-Options
        if ( ! empty( $this->options['x_content_type_options'] ) ) {
            $rules[] = '    # Prevent MIME type sniffing';
            $rules[] = '    Header always set X-Content-Type-Options "nosniff"';
        }

        // X-XSS-Protection
        if ( ! empty( $this->options['x_xss_protection'] ) ) {
            $rules[] = '    # XSS Protection (legacy but still useful)';
            $rules[] = '    Header always set X-XSS-Protection "1; mode=block"';
        }

        // Referrer-Policy
        if ( ! empty( $this->options['referrer_policy'] ) ) {
            $value = $this->options['referrer_policy'];
            $rules[] = '    # Referrer Policy';
            $rules[] = '    Header always set Referrer-Policy "' . esc_attr( $value ) . '"';
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
                $rules[] = '    Header always set Permissions-Policy "' . implode( ', ', $directives ) . '"';
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

                if ( ! empty( $csp['report_uri'] ) ) {
                    $header_value .= '; report-uri ' . esc_url( $csp['report_uri'] );
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

        // Cross-Origin policies
        if ( ! empty( $this->options['cross_origin_policies'] ) ) {
            $policies = $this->options['cross_origin_policies'];

            if ( ! empty( $policies['embedder_policy'] ) && 'unsafe-none' !== $policies['embedder_policy'] ) {
                $rules[] = '    Header always set Cross-Origin-Embedder-Policy "' . esc_attr( $policies['embedder_policy'] ) . '"';
            }

            if ( ! empty( $policies['opener_policy'] ) ) {
                $rules[] = '    Header always set Cross-Origin-Opener-Policy "' . esc_attr( $policies['opener_policy'] ) . '"';
            }

            if ( ! empty( $policies['resource_policy'] ) ) {
                $rules[] = '    Header always set Cross-Origin-Resource-Policy "' . esc_attr( $policies['resource_policy'] ) . '"';
            }
        }

        // Remove X-Powered-By
        $rules[] = '    # Hide PHP version';
        $rules[] = '    Header always unset X-Powered-By';

        $rules[] = '</IfModule>';

        return implode( "\n", $rules );
    }

    /**
     * Get headers preview
     *
     * @return array
     */
    public function get_headers_preview() {
        $headers = array();

        if ( ! empty( $this->options['x_frame_options'] ) ) {
            $headers['X-Frame-Options'] = $this->options['x_frame_options'];
        }

        if ( ! empty( $this->options['x_content_type_options'] ) ) {
            $headers['X-Content-Type-Options'] = 'nosniff';
        }

        if ( ! empty( $this->options['x_xss_protection'] ) ) {
            $headers['X-XSS-Protection'] = '1; mode=block';
        }

        if ( ! empty( $this->options['referrer_policy'] ) ) {
            $headers['Referrer-Policy'] = $this->options['referrer_policy'];
        }

        if ( ! empty( $this->options['hsts']['enabled'] ) ) {
            $hsts = $this->options['hsts'];
            $value = 'max-age=' . absint( $hsts['max_age'] );
            if ( ! empty( $hsts['include_subdomains'] ) ) {
                $value .= '; includeSubDomains';
            }
            if ( ! empty( $hsts['preload'] ) ) {
                $value .= '; preload';
            }
            $headers['Strict-Transport-Security'] = $value;
        }

        return $headers;
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

        // X-XSS-Protection (10 points)
        if ( ! empty( $this->options['x_xss_protection'] ) ) {
            $score += 10;
            $enabled[] = 'X-XSS-Protection: 1; mode=block';
        } else {
            $missing[] = 'X-XSS-Protection';
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

        // CSP (20 points)
        if ( ! empty( $this->options['csp']['enabled'] ) ) {
            if ( empty( $this->options['csp']['report_only'] ) ) {
                $score += 20;
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
                $score += 10;
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