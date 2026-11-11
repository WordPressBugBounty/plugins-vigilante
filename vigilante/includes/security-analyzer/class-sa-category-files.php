<?php
/**
 * Security Analyzer — Sensitive files category (10 pts).
 *
 * Checks: debug_log_public (2), env_file (2), git_config (1),
 * wp_config_backups (2), uploads_listing (1), upgrade_folders (1, since
 * 3.0.13), phpinfo_adminer (1), wp_cron_public (informative since 3.0.7).
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
        $results[] = $this->check_upgrade_folders();
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

    /**
     * Whether the server refuses requests to the folders where WordPress unpacks updates
     *
     * Measured, not read from the setting: it asks for a PHP file that does
     * not exist inside wp-content/upgrade/ and for one beside it, outside, and
     * passes only when the first is refused and the second is not. A server
     * that refuses both could be refusing every unknown file of wp-content, and
     * then nothing tells whether a real file of an update would be served, so
     * that is not scored. Neither is an answer that is not about the file (a
     * verification screen, a rate limit, a server error, a redirect). An
     * untouched WordPress fails: the folder is served like any other, and a
     * file of an update can be called by its address while the update lasts
     * (CVE-2026-119977).
     *
     * A PHP file, because that is what the attack asks for. The first version
     * asked for a .txt, and the first blind review of 3.0.13 measured a server
     * that hands PHP files to PHP-FPM with ProxyPassMatch: it never reads
     * .htaccess for them, so the real setup-config.php was served with the
     * rule in place while the .txt was refused and the row passed.
     *
     * The address is built from site_url() and the path of the content folder
     * inside ABSPATH, which is what the rule covers, and no redirect is
     * followed, as in the other checks: WP_CONTENT_URL can point to a CDN that
     * has no such folder, and the row would have measured that host.
     *
     * @since 3.0.13
     *
     * @return Vigilante_SA_Check_Result
     */
    private function check_upgrade_folders() {
        $args = array(
            'id'       => 'upgrade_folders',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'Web access to the update folders (wp-content/upgrade)', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'firewall', 'field-protect-upgrade-folders' ),
        );

        $base = self::upgrade_probe_base();
        if ( '' === $base ) {
            $args['detail'] = __( 'The content folder of this site is not inside the WordPress folder, at an address of this site, so whether files of an update can be reached from the web was not checked. Not scored.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $name    = 'vigilante-check-' . substr( md5( (string) wp_rand() ), 0, 12 ) . '.php';
        $inside  = self::upgrade_probe_code( $base . 'upgrade/' . $name );
        $outside = null === $inside ? null : self::upgrade_probe_code( $base . $name );

        if ( null === $inside || null === $outside ) {
            $args['detail'] = Vigilante_SA_Helpers::unreachable_detail( '/wp-content/upgrade/' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $refused  = static function ( $code ) {
            return 401 === $code || 403 === $code;
        };
        $answered = static function ( $code ) {
            return 404 === $code || ( $code >= 200 && $code < 300 );
        };

        if ( $refused( $inside ) && $answered( $outside ) ) {
            $args['detail'] = __( 'The server refuses requests to wp-content/upgrade/, where WordPress unpacks updates.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        if ( ! $answered( $inside ) || ! $answered( $outside ) ) {
            $args['detail'] = sprintf(
                /* translators: 1: HTTP status of a request inside wp-content/upgrade/, 2: HTTP status of a request outside it */
                __( 'The server answered %1$d inside wp-content/upgrade/ and %2$d outside it, so whether files of an update can be reached from the web could not be told. Not scored.', 'vigilante' ),
                $inside,
                $outside
            );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $args['detail'] = __( 'Files in wp-content/upgrade/, where WordPress unpacks updates, can be requested from the web while an update lasts.', 'vigilante' ) . ' ' . $this->upgrade_folders_cause();
        return Vigilante_SA_Check_Result::fail( $args );
    }

    /**
     * Address of the content folder for the probes, with a trailing slash, or ''
     *
     * From site_url() and the path of WP_CONTENT_DIR inside ABSPATH, which is
     * where the .htaccess of Vigilant applies. A content folder outside ABSPATH
     * is asked at content_url() only while that is on the host of the site.
     *
     * @since 3.0.13
     *
     * @return string
     */
    private static function upgrade_probe_base() {
        $root    = untrailingslashit( wp_normalize_path( ABSPATH ) );
        $content = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );

        if ( '' !== $root && 0 === strpos( $content, $root . '/' ) ) {
            return trailingslashit( trailingslashit( site_url() ) . substr( $content, strlen( $root ) + 1 ) );
        }

        $site_host    = strtolower( (string) wp_parse_url( site_url(), PHP_URL_HOST ) );
        $content_host = strtolower( (string) wp_parse_url( content_url(), PHP_URL_HOST ) );

        return ( '' !== $site_host && $site_host === $content_host ) ? trailingslashit( content_url() ) : '';
    }

    /**
     * Status of one request of check_upgrade_folders(), or null with no answer
     *
     * A query string of its own on every request, so a cache in front of the
     * site cannot answer with what it kept from the last check. No redirect is
     * followed: one is not the server refusing or serving the file.
     *
     * @since 3.0.13
     *
     * @param string $url Address to ask for.
     * @return int|null
     */
    private static function upgrade_probe_code( $url ) {
        $response = Vigilante_SA_Helpers::get( add_query_arg( 'v', (string) time(), $url ), array( 'redirection' => 0 ) );

        if ( is_wp_error( $response ) ) {
            return null;
        }

        return (int) wp_remote_retrieve_response_code( $response );
    }

    /**
     * Why the update folders are open, read from the file before the settings
     *
     * The rule lives in the .htaccess the whole network shares, so the file
     * says whether it is written, and the settings only add why not where this
     * site owns that file. Elsewhere it is the network administrator's call.
     *
     * @since 3.0.13
     *
     * @return string
     */
    private function upgrade_folders_cause() {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-protection.php';

        $manager = Vigilante_Htaccess_Manager::get_instance();

        if ( ! $manager->is_apache() ) {
            return __( 'This server does not read .htaccess, so Vigilant cannot close them: block /wp-content/upgrade/ and /wp-content/upgrade-temp-backup/ in the server configuration.', 'vigilante' );
        }

        if ( false !== strpos( (string) $manager->get_content(), '/+upgrade(-temp-backup)?/' ) ) {
            return __( 'The rule of Update Folders is in .htaccess, but the answer for PHP files does not come from it. The usual causes: a server that hands them to PHP-FPM with ProxyPassMatch, which never reads .htaccess for them, a hosting that does not read that file at all, or a proxy in front that answers for them first. Block the two folders in the server configuration, or ask the hosting how PHP files are passed.', 'vigilante' );
        }

        // This file is loaded late, from disk, when the analyzer runs. In the
        // cron run in which WordPress updates Vigilant, the protection class
        // in memory is still the one of the version being replaced, which has
        // no such method, and a weekly scan falling due in that run would end
        // in a fatal error (L2 of poc/tareas-305.sh; vigilante/CLAUDE.md).
        if ( method_exists( 'Vigilante_Htaccess_Protection', 'upgrade_folders_location' ) && null === Vigilante_Htaccess_Protection::upgrade_folders_location() ) {
            return __( 'On this site the content folder is outside the WordPress folder, or its address has characters the rule cannot use, so Vigilant does not write it: block those folders in the server configuration.', 'vigilante' );
        }

        if ( ! Vigilante_Settings::owns_shared_files() ) {
            return __( 'The network administrator can switch on Update Folders in the Firewall tab of the main site.', 'vigilante' );
        }

        if ( ! $this->settings->is_module_enabled( 'firewall' ) ) {
            return Vigilante_SA_Helpers::module_off_detail( $this->settings, 'firewall' );
        }

        $firewall = $this->settings->get_section( 'firewall' );

        if ( empty( $firewall['protect_upgrade_folders'] ) ) {
            return __( 'Switch on Update Folders in Firewall, Server Protection.', 'vigilante' );
        }

        return __( 'Update Folders is on but its rule is not in .htaccess yet: save the Firewall tab once.', 'vigilante' );
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
