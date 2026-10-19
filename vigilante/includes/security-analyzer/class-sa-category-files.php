<?php
/**
 * Security Analyzer — Sensitive files category (9 pts).
 *
 * Checks: debug_log_public (2), env_file (2), git_config (1),
 * wp_config_backups (2), uploads_listing (1), phpinfo_adminer (1),
 * wp_cron_public (informative since 3.0.7).
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Sensitive-file exposure checks.
 */
class Vigilante_SA_Category_Files {

    const SLUG = 'files';

    /**
     * @var Vigilante_Settings
     */
    private $settings;

    public function __construct( Vigilante_Settings $settings ) {
        $this->settings = $settings;
    }

    /**
     * Run the category.
     *
     * @param string $phase 'fast' | 'slow' | 'all'.
     * @return Vigilante_SA_Check_Result[]
     */
    public function run( $phase = 'all' ) {
        $results = array();

        // All checks do both a filesystem test and a URL probe — both need phase 'slow'
        // because the URL probe is what confirms actual public exposure.
        if ( 'fast' === $phase ) {
            return $results;
        }

        $results[] = $this->check_debug_log();
        $results[] = $this->check_env_file();
        $results[] = $this->check_git_config();
        $results[] = $this->check_wp_config_backups();
        $results[] = $this->check_uploads_listing();
        $results[] = $this->check_phpinfo_adminer();
        $results[] = $this->check_wp_cron_public();

        return $results;
    }

    private function check_debug_log() {
        $path = WP_CONTENT_DIR . '/debug.log';
        $args = array(
            'id'       => 'debug_log_public',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'debug.log public access', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'wp-hardening', 'field-wp-debug' ),
        );

        if ( ! file_exists( $path ) ) {
            $args['detail'] = __( 'No wp-content/debug.log file present.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $state = Vigilante_SA_Helpers::public_url_state( 'wp-content/debug.log' );

        if ( 'reachable' === $state ) {
            $args['detail'] = __( 'wp-content/debug.log is reachable publicly. Errors and paths are leaking.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        // No answer is not a file that is protected.
        if ( 'unknown' === $state ) {
            $args['detail'] = Vigilante_SA_Helpers::unreachable_detail( '/wp-content/debug.log' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $args['detail'] = __( 'wp-content/debug.log exists but is not publicly reachable.', 'vigilante' );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_env_file() {
        $args = array(
            'id'       => 'env_file',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( '.env exposure', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'vigilante-section-firewall-server' ),
        );

        $state = Vigilante_SA_Helpers::public_url_state( '.env' );

        if ( 'reachable' === $state ) {
            $args['detail'] = __( 'A public /.env file is reachable at the site root. This typically leaks credentials.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        if ( 'unknown' === $state ) {
            $args['detail'] = Vigilante_SA_Helpers::unreachable_detail( '/.env' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $args['detail'] = __( 'No public /.env file is reachable.', 'vigilante' );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_git_config() {
        $args = array(
            'id'       => 'git_config',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( '.git/config exposure', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'vigilante-section-firewall-server' ),
        );

        $state = Vigilante_SA_Helpers::public_url_state( '.git/config' );

        if ( 'reachable' === $state ) {
            $args['detail'] = __( 'A public /.git/config file is reachable. The repository contents may be cloneable.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        if ( 'unknown' === $state ) {
            $args['detail'] = Vigilante_SA_Helpers::unreachable_detail( '/.git/config' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $args['detail'] = __( 'No public /.git/config file is reachable.', 'vigilante' );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_wp_config_backups() {
        $args = array(
            'id'       => 'wp_config_backups',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'wp-config backup files', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'vigilante-section-firewall-server' ),
        );

        $candidates = array(
            'wp-config.php.bak',
            'wp-config.php.old',
            'wp-config.php.txt',
            'wp-config.php.save',
            'wp-config.php~',
            'wp-config-sample.php.bak',
        );

        list( $leaked, $unknown ) = $this->reachable_among( $candidates );

        if ( empty( $leaked ) && ! empty( $unknown ) ) {
            $args['data']   = array( 'unknown' => $unknown );
            $args['detail'] = Vigilante_SA_Helpers::unreachable_detail( '/' . implode( ', /', $unknown ) );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        if ( empty( $leaked ) ) {
            $args['detail'] = __( 'No wp-config backup variants are present or reachable.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['data']   = array( 'files' => $leaked );
        $args['detail'] = sprintf(
            /* translators: %s: comma-separated files */
            __( 'Backup copies of wp-config.php are reachable: %s', 'vigilante' ),
            implode( ', ', $leaked )
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_uploads_listing() {
        $args = array(
            'id'       => 'uploads_listing',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'Directory listing in /uploads', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'field-disable-directory-browsing' ),
        );

        $upload_dir = wp_get_upload_dir();
        if ( empty( $upload_dir['baseurl'] ) ) {
            $args['detail'] = __( 'Could not determine uploads URL.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $response = Vigilante_SA_Helpers::get( trailingslashit( $upload_dir['baseurl'] ), array( 'redirection' => 0 ) );
        if ( is_wp_error( $response ) ) {
            $args['detail'] = Vigilante_SA_Helpers::with_challenge( __( 'Could not probe the uploads directory URL.', 'vigilante' ) );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $body = (string) wp_remote_retrieve_body( $response );
        $code = (int) wp_remote_retrieve_response_code( $response );

        // Indicators that Apache-style directory listing is on.
        $indicators = array( 'Index of /', '<title>Index of', 'Parent Directory</a>' );
        $open       = false;
        foreach ( $indicators as $needle ) {
            if ( 200 === $code && false !== stripos( $body, $needle ) ) {
                $open = true;
                break;
            }
        }

        if ( $open ) {
            $args['detail'] = __( 'Directory listing is enabled for the uploads folder. Turn off indexing in .htaccess.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $args['detail'] = __( 'No directory listing markers found in the /uploads/ response.', 'vigilante' );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_phpinfo_adminer() {
        $args = array(
            'id'       => 'phpinfo_adminer',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'phpinfo / adminer / installer scripts', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'vigilante-section-firewall-server' ),
        );

        $candidates = array(
            'phpinfo.php',
            'info.php',
            'adminer.php',
            'installer.php',
            'install.php', // WP's own install.php is fine; this check catches third-party installers.
            'test.php',
        );

        // WP core install.php is always present during setup: not asked for.
        list( $leaked, $unknown ) = $this->reachable_among( array_diff( $candidates, array( 'install.php' ) ) );

        if ( empty( $leaked ) && ! empty( $unknown ) ) {
            $args['data']   = array( 'unknown' => $unknown );
            $args['detail'] = Vigilante_SA_Helpers::unreachable_detail( '/' . implode( ', /', $unknown ) );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        if ( empty( $leaked ) ) {
            $args['detail'] = __( 'No phpinfo, adminer or third-party installer scripts are reachable.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['data']   = array( 'files' => $leaked );
        $args['detail'] = sprintf(
            /* translators: %s: comma-separated files */
            __( 'Developer/debug scripts reachable: %s. Delete them immediately.', 'vigilante' ),
            implode( ', ', $leaked )
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    /**
     * wp-cron.php, as information
     *
     * It scores nothing since 3.0.7. Until 3.0.6 a reachable wp-cron.php was a
     * warning on every untouched WordPress, and the way out it offered was
     * "Protect wp-cron.php", which denied every request to the file, the cron
     * job of the server included, and the scheduled tasks stopped. A request
     * to wp-cron.php only runs the tasks that are already due, under a lock
     * (wp-cron.php in WordPress 7.1.3, lines 84 and 92-114), so a reachable
     * file is not worth points. What is worth saying is the other case: a
     * server that refuses it refuses the cron job that calls its address too.
     *
     * @return Vigilante_SA_Check_Result
     */
    private function check_wp_cron_public() {
        $args = array(
            'id'       => 'wp_cron_public',
            'category' => self::SLUG,
            'max'      => 0,
            'label'    => __( 'wp-cron.php public access', 'vigilante' ),
        );

        // A savvy user might define DISABLE_WP_CRON outside the plugin, so the
        // constant in force is read, not the setting.
        $constant_active = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;

        $url      = home_url( '/wp-cron.php?doing_wp_cron=probe' );
        $response = Vigilante_SA_Helpers::get( $url, array( 'redirection' => 0, 'timeout' => 2 ) );
        if ( is_wp_error( $response ) ) {
            // No answer proves nothing either way: a firewall that drops the
            // request looks the same from here as a server that was slow.
            $args['detail'] = Vigilante_SA_Helpers::unreachable_detail( '/wp-cron.php' );
            $args['data']   = array( 'constant_active' => $constant_active );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $code         = (int) wp_remote_retrieve_response_code( $response );
        $args['data'] = array(
            'code'            => $code,
            'constant_active' => $constant_active,
        );

        if ( in_array( $code, array( 401, 403 ), true ) ) {
            $args['detail'] = sprintf(
                /* translators: %d: HTTP status code */
                __( 'wp-cron.php answers %d, so the server refuses it. A cron job that calls its address (wget, curl or the cron of a hosting panel) gets the same answer, and so does WordPress when a visit starts the scheduled tasks. They only run if the server runs wp-cron.php with PHP.', 'vigilante' ),
                $code
            );
            return Vigilante_SA_Check_Result::info( $args );
        }

        // A redirect is not what wp-cron.php answers by itself either: the
        // request never reached the file (the cross review of 3.0.7 found it
        // described as reachable).
        if ( $code < 200 || $code >= 300 ) {
            $args['detail'] = sprintf(
                /* translators: %d: HTTP status code */
                __( 'wp-cron.php answers %d, which is not what WordPress answers by itself. Scheduled tasks may not be running.', 'vigilante' ),
                $code
            );
            return Vigilante_SA_Check_Result::info( $args );
        }

        $args['detail'] = __( 'wp-cron.php can be reached, as on any WordPress. A request to it only runs the scheduled tasks that are already due, one run at a time, so it scores nothing.', 'vigilante' );

        if ( $constant_active ) {
            $args['detail'] .= ' ' . __( 'DISABLE_WP_CRON is set, so visits no longer start the tasks and a cron job of the server has to call wp-cron.php.', 'vigilante' );
        }

        return Vigilante_SA_Check_Result::info( $args );
    }

    /**
     * Which of these files of the site root are on disk and can be fetched
     *
     * @since 3.0.5
     *
     * @param string[] $candidates Paths relative to ABSPATH.
     * @return array Two lists: the ones a request reached, and the ones that
     *               are on disk but whose request got no answer.
     */
    private function reachable_among( array $candidates ) {
        $leaked  = array();
        $unknown = array();

        foreach ( $candidates as $rel ) {
            if ( ! Vigilante_SA_Helpers::abspath_file_exists( $rel ) ) {
                continue;
            }

            $state = Vigilante_SA_Helpers::public_url_state( $rel );

            if ( 'reachable' === $state ) {
                $leaked[] = $rel;
            } elseif ( 'unknown' === $state ) {
                $unknown[] = $rel;
            }
        }

        return array( $leaked, $unknown );
    }
}
