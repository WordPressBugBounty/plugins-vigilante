<?php
/**
 * Security Analyzer — Sensitive files category (10 pts).
 *
 * Checks: debug_log_public (2), env_file (2), git_config (1),
 * wp_config_backups (2), uploads_listing (1), phpinfo_adminer (1),
 * wp_cron_public (1).
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

        if ( Vigilante_SA_Helpers::public_url_returns_ok( 'wp-content/debug.log' ) ) {
            $args['detail'] = __( 'wp-content/debug.log is reachable publicly. Errors and paths are leaking.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
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
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'vigilante-section-firewall-file-protection' ),
        );

        if ( Vigilante_SA_Helpers::public_url_returns_ok( '.env' ) ) {
            $args['detail'] = __( 'A public /.env file is reachable at the site root. This typically leaks credentials.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
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
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'vigilante-section-firewall-file-protection' ),
        );

        if ( Vigilante_SA_Helpers::public_url_returns_ok( '.git/config' ) ) {
            $args['detail'] = __( 'A public /.git/config file is reachable. The repository contents may be cloneable.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
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
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'vigilante-section-firewall-file-protection' ),
        );

        $candidates = array(
            'wp-config.php.bak',
            'wp-config.php.old',
            'wp-config.php.txt',
            'wp-config.php.save',
            'wp-config.php~',
            'wp-config-sample.php.bak',
        );

        $leaked = array();
        foreach ( $candidates as $rel ) {
            if ( Vigilante_SA_Helpers::abspath_file_exists( $rel ) && Vigilante_SA_Helpers::public_url_returns_ok( $rel ) ) {
                $leaked[] = $rel;
            }
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
            $args['detail'] = __( 'Could not probe the uploads directory URL.', 'vigilante' );
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
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'vigilante-section-firewall-file-protection' ),
        );

        $candidates = array(
            'phpinfo.php',
            'info.php',
            'adminer.php',
            'installer.php',
            'install.php', // WP's own install.php is fine; this check catches third-party installers.
            'test.php',
        );

        $leaked = array();
        foreach ( $candidates as $rel ) {
            if ( 'install.php' === $rel ) {
                // Skip WP core install.php (always present during setup).
                continue;
            }
            if ( Vigilante_SA_Helpers::abspath_file_exists( $rel ) && Vigilante_SA_Helpers::public_url_returns_ok( $rel ) ) {
                $leaked[] = $rel;
            }
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

    private function check_wp_cron_public() {
        $args = array(
            'id'       => 'wp_cron_public',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'wp-cron.php public access', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'field-protect-wp-cron' ),
        );

        // Two separate protections, both off by default and both controlled by Vigilant.
        // DISABLE_WP_CRON (wp-config constant) stops WordPress from auto-spawning cron on
        // page views — does NOT block direct HTTP access to /wp-cron.php. The .htaccess
        // rule (firewall.protect_wp_cron) is what actually blocks external cron-spam
        // abuse. Both depend on the host having a real server-side cron job calling
        // wp-cron.php from CLI. Read both Vigilant settings AND the runtime constant —
        // a savvy user might define DISABLE_WP_CRON manually outside the plugin.
        $constant_active   = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
        $disable_setting   = (int) $this->settings->get_option( 'wp_hardening', 'disable_wp_cron', 0 );
        $htaccess_setting  = (int) $this->settings->get_option( 'firewall', 'protect_wp_cron', 0 );

        $url      = home_url( '/wp-cron.php?doing_wp_cron=probe' );
        $response = Vigilante_SA_Helpers::get( $url, array( 'redirection' => 0, 'timeout' => 2 ) );
        if ( is_wp_error( $response ) ) {
            $args['detail'] = __( 'Could not reach wp-cron.php from this server. If a firewall is blocking it, that is the desired state.', 'vigilante' );
            $args['data']   = array(
                'constant_active'  => $constant_active,
                'disable_setting'  => (bool) $disable_setting,
                'htaccess_setting' => (bool) $htaccess_setting,
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $code = (int) wp_remote_retrieve_response_code( $response );
        $args['data'] = array(
            'code'             => $code,
            'constant_active'  => $constant_active,
            'disable_setting'  => (bool) $disable_setting,
            'htaccess_setting' => (bool) $htaccess_setting,
        );

        // 403/401: blocked at the server level — best case.
        if ( in_array( $code, array( 401, 403 ), true ) ) {
            if ( $htaccess_setting && $constant_active ) {
                $args['detail'] = __( 'Vigilant is blocking external HTTP access to wp-cron.php via .htaccess, and DISABLE_WP_CRON is set in wp-config. Make sure your host has a real server-side cron job calling wp-cron.php from CLI.', 'vigilante' );
            } elseif ( $htaccess_setting ) {
                $args['detail'] = __( 'Vigilant\'s .htaccess rule blocks /wp-cron.php at the server level. Consider also enabling DISABLE_WP_CRON in WP Hardening so WordPress stops trying to auto-spawn cron on page views.', 'vigilante' );
            } else {
                $args['detail'] = __( 'Server returned 403/401 for /wp-cron.php; direct external access is blocked at the server level.', 'vigilante' );
            }
            return Vigilante_SA_Check_Result::pass( $args );
        }

        // 200/204/302: reachable. Differentiate by which protections are active so the
        // detail message tells the user exactly what's left to do.
        if ( $constant_active && $htaccess_setting ) {
            // Settings on but probe still goes through — usually a cache/CDN bypassing
            // .htaccess, or .htaccess not being loaded by the server (nginx, IIS).
            $args['detail'] = __( 'Both DISABLE_WP_CRON and Vigilant\'s .htaccess block are active, but /wp-cron.php is still reachable. Either a cache/CDN is serving an old response, or your server doesn\'t honor .htaccess (nginx/IIS) — check the server config or purge the cache.', 'vigilante' );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        if ( $constant_active ) {
            $args['detail'] = __( 'DISABLE_WP_CRON is set in wp-config (good — your host runs real cron), but /wp-cron.php is still reachable publicly. The constant only stops WordPress from auto-spawning cron on page views; it does not block direct HTTP access. To fully harden, enable "Protect wp-cron.php" in Firewall &rarr; File Protection.', 'vigilante' );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        if ( $htaccess_setting ) {
            $args['detail'] = __( 'Vigilant is configured to block /wp-cron.php at the server level, but the URL is still reachable. Check that .htaccess is being honored by your server (nginx/IIS users need an equivalent rule), then re-scan.', 'vigilante' );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $args['detail'] = __( '/wp-cron.php is publicly reachable. WordPress is using the default page-view trigger, which is functional but lets attackers spam the URL to exhaust resources. If your host supports real cron, enable both "Disable WP Cron" (WP Hardening) and "Protect wp-cron.php" (Firewall) and add a server-side cron job calling wp-cron.php from CLI.', 'vigilante' );
        return Vigilante_SA_Check_Result::warn( $args );
    }
}
