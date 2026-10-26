<?php
/**
 * Security Analyzer — Internal-exclusive category (43 pts).
 *
 * The differential of this analyzer vs any external scanner. Each check
 * reads data that is impossible to observe from the outside.
 *
 * Checks:
 *  - php_version_eol (3)
 *  - php_security_fixes (3)  ← v3.0.9: the release, not only the branch,
 *                              against the critical PHP security releases
 *                              this version knows about (PHP2Shell).
 *  - wp_core_updates (3)
 *  - plugin_updates (2)
 *  - theme_updates (1)
 *  - inactive_plugins (2)
 *  - closed_plugins (3)  ← v2.6.0: reads the cached state from the daily
 *                          Vigilante_Plugin_Status check; no extra HTTP call.
 *  - self_integrity (10)  ← v3.0.0: reads the cached state written by
 *                          Vigilante_Self_Integrity; no FS hashing, no HTTP.
 *  - file_permissions (2)
 *  - salts_default (2)
 *  - table_prefix (2)
 *  - admin_username (2)
 *  - admins_without_2fa (2)
 *  - vigilante_modules_off (2)
 *  - activity_log_errors (1)
 *  - file_integrity_status (1)
 *  - audit_alerts_active (2)  ← v2.8.0: warns when Security Audit is on but no
 *                              audit alert is configured; skips when off.
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Internal-only checks.
 */
class Vigilante_SA_Category_Internal {

    const SLUG = 'internal';

    /**
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * @var Vigilante_Activity_Log|null
     */
    private $activity_log;

    /**
     * @param Vigilante_Settings         $settings
     * @param Vigilante_Activity_Log|null $activity_log
     */
    public function __construct( Vigilante_Settings $settings, $activity_log = null ) {
        $this->settings     = $settings;
        $this->activity_log = $activity_log;
    }

    /**
     * Run the category. All checks are fast (no HTTP).
     *
     * @param string $phase 'fast' | 'slow' | 'all'.
     * @return Vigilante_SA_Check_Result[]
     */
    public function run( $phase = 'all' ) {
        if ( 'slow' === $phase ) {
            return array();
        }

        $results   = array();
        $results[] = $this->check_php_version();
        $results[] = $this->check_php_security_fixes();
        $results[] = $this->check_wp_core_updates();
        $results[] = $this->check_plugin_updates();
        $results[] = $this->check_theme_updates();
        $results[] = $this->check_inactive_plugins();
        $results[] = $this->check_closed_plugins();
        $results[] = $this->check_self_integrity();
        $results[] = $this->check_file_permissions();
        $results[] = $this->check_salts_default();
        $results[] = $this->check_table_prefix();
        $results[] = $this->check_admin_username();
        $results[] = $this->check_admins_without_2fa();
        $results[] = $this->check_vigilante_modules_off();
        $results[] = $this->check_activity_log_errors();
        $results[] = $this->check_file_integrity_status();
        $results[] = $this->check_audit_alerts_active();

        return $results;
    }

    private function check_php_version() {
        $args = array(
            'id'       => 'php_version_eol',
            'category' => self::SLUG,
            'max'      => 3,
            'label'    => __( 'PHP version support', 'vigilante' ),
            'fix_link' => '',
        );

        $branch = Vigilante_SA_Helpers::current_php_branch();
        $table  = Vigilante_SA_Helpers::php_eol_table();
        $args['data'] = array(
            'php_branch'   => $branch,
            'php_full'     => PHP_VERSION,
        );

        if ( ! isset( $table[ $branch ] ) ) {
            $args['detail'] = sprintf(
                /* translators: %s: PHP branch like 8.1 */
                __( 'PHP %s is unknown to the built-in EOL table. Verify with your host.', 'vigilante' ),
                $branch
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $eol_timestamp = strtotime( $table[ $branch ] );
        $args['data']['eol_date'] = $table[ $branch ];

        if ( time() > $eol_timestamp ) {
            $args['detail'] = sprintf(
                /* translators: 1: php branch, 2: EOL date */
                __( 'PHP %1$s reached end-of-life on %2$s. Upgrade to a supported branch immediately.', 'vigilante' ),
                $branch,
                $table[ $branch ]
            );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $months_left = (int) floor( ( $eol_timestamp - time() ) / ( 30 * DAY_IN_SECONDS ) );
        $args['data']['months_left'] = $months_left;
        if ( $months_left <= 6 ) {
            $args['detail'] = sprintf(
                /* translators: 1: branch, 2: months */
                __( 'PHP %1$s reaches end-of-life in roughly %2$d months. Start planning the upgrade.', 'vigilante' ),
                $branch,
                $months_left
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $args['detail'] = sprintf(
            /* translators: 1: branch, 2: EOL date */
            __( 'PHP %1$s within support window (EOL %2$s).', 'vigilante' ),
            $branch,
            $table[ $branch ]
        );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    /**
     * Whether the running PHP has the fixes of the critical security releases this version knows about
     *
     * The row above only looks at the branch, so a PHP 8.5.3 passed it while
     * PHP2Shell, fixed in 8.5.12, let anyone run code on the server. Nothing
     * in WordPress says so either: the Serve Happy API behind the dashboard
     * and Site Health answers by branch too (measured on 25 Oct 2026, it
     * calls 8.5.3 and 8.1.33 secure).
     *
     * @since 3.0.9
     *
     * @return Vigilante_SA_Check_Result
     */
    private function check_php_security_fixes() {
        return self::php_fixes_result( PHP_MAJOR_VERSION, PHP_MINOR_VERSION, PHP_RELEASE_VERSION, PHP_EXTRA_VERSION );
    }

    /**
     * Critical PHP security releases known to this version of Vigilant, newest first
     *
     * For each one, the first release of every supported branch that carries
     * the fix. A branch older than every branch listed gets no fix, because it
     * was past its end of life when the fix came out, and a branch newer than
     * every branch listed came out with it.
     *
     * Hardcoded like Vigilante_SA_Helpers::php_eol_table(), so Security Check
     * stays offline. Source: the security announcements of
     * https://www.php.net/. Add an entry with the Vigilant release that
     * follows a critical security release of PHP, not for every monthly
     * release: being one release behind is not a finding.
     *
     * Kept in this file and not in the helpers: the categories are read from
     * disk when the analyzer is created, so in the cron run in which WordPress
     * updates Vigilant this file can be new while a class loaded earlier is
     * old (the fatal error of score_tone(), 3.0.5).
     *
     * @since 3.0.9
     *
     * @return array[] Each with 'name', 'cves' (string[]), 'date' (Y-m-d), 'what' (what the flaws allow) and 'fixed' (branch => first fixed release).
     */
    public static function php_security_fixes() {
        return array(
            array(
                'name'  => 'PHP2Shell',
                'cves'  => array( 'CVE-2026-109618', 'CVE-2026-109619' ),
                'date'  => '2026-10-21',
                'what'  => __( 'critical flaws that let anyone run code on the server', 'vigilante' ),
                'fixed' => array(
                    '8.2' => '8.2.35',
                    '8.3' => '8.3.36',
                    '8.4' => '8.4.27',
                    '8.5' => '8.5.12',
                ),
            ),
        );
    }

    /**
     * Where a PHP release stands against a list of critical security releases
     *
     * @since 3.0.9
     *
     * @param int     $major   Major version.
     * @param int     $minor   Minor version.
     * @param int     $release Release within the branch.
     * @param array[] $fixes   As php_security_fixes() returns them.
     * @return array {
     *     @type string     $state    'fixed'; 'behind', an older release of a branch that got every fix it lacks;
     *                                or 'no_fix', a branch that did not get one of them.
     *     @type string     $required For 'behind', the first release of the branch with every fix.
     *     @type array|null $advisory The newest entry it lacks, or the newest entry when it lacks none.
     * }
     */
    public static function php_fix_status( $major, $minor, $release, $fixes ) {
        $branch  = (int) $major . '.' . (int) $minor;
        $current = $branch . '.' . (int) $release;
        $status  = array(
            'state'    => 'fixed',
            'required' => '',
            'advisory' => null,
        );
        $newest  = null;
        $missing = null;

        foreach ( (array) $fixes as $advisory ) {
            $fixed = ( isset( $advisory['fixed'] ) && is_array( $advisory['fixed'] ) ) ? $advisory['fixed'] : array();
            if ( empty( $fixed ) ) {
                continue;
            }

            if ( null === $newest ) {
                $newest = $advisory;
            }

            if ( isset( $fixed[ $branch ] ) ) {
                if ( version_compare( $current, $fixed[ $branch ], '>=' ) ) {
                    continue;
                }
                if ( '' === $status['required'] || version_compare( $fixed[ $branch ], $status['required'], '>' ) ) {
                    $status['required'] = $fixed[ $branch ];
                }
                if ( 'no_fix' !== $status['state'] ) {
                    $status['state'] = 'behind';
                }
            } else {
                $branches = array_map( 'strval', array_keys( $fixed ) );
                usort( $branches, 'version_compare' );
                if ( version_compare( $branch, end( $branches ), '>' ) ) {
                    continue;
                }
                $status['state'] = 'no_fix';
            }

            if ( null === $missing ) {
                $missing = $advisory;
            }
        }

        $status['advisory'] = ( 'fixed' === $status['state'] ) ? $newest : $missing;

        return $status;
    }

    /**
     * The row for a given PHP release
     *
     * Public and static so a harness can ask about any release: the constants
     * of the running PHP cannot be changed.
     *
     * Most fixes reach a site as a new release of PHP. Some Linux
     * distributions apply them to the release they ship instead, and keep its
     * number: Debian and Ubuntu add their own mark to it (PHP_EXTRA_VERSION),
     * so a marked build below the fix, or on a branch PHP no longer fixes, is
     * a warning that the number cannot tell, not a failure. A distribution
     * that adds no mark cannot be told apart from an old release, and the
     * failure says how to check.
     *
     * @since 3.0.9
     *
     * @param int    $major   PHP_MAJOR_VERSION.
     * @param int    $minor   PHP_MINOR_VERSION.
     * @param int    $release PHP_RELEASE_VERSION.
     * @param string $extra   PHP_EXTRA_VERSION.
     * @return Vigilante_SA_Check_Result
     */
    public static function php_fixes_result( $major, $minor, $release, $extra ) {
        $branch  = (int) $major . '.' . (int) $minor;
        $version = $branch . '.' . (int) $release . (string) $extra;
        $status  = self::php_fix_status( $major, $minor, $release, self::php_security_fixes() );
        $item    = $status['advisory'];

        $args = array(
            'id'       => 'php_security_fixes',
            'category' => self::SLUG,
            'max'      => 3,
            'label'    => __( 'PHP security fixes', 'vigilante' ),
            'fix_link' => '',
            'data'     => array(
                'php_full' => $version,
                'state'    => $status['state'],
                'required' => $status['required'],
            ),
        );

        if ( ! is_array( $item ) ) {
            $args['detail'] = __( 'Vigilant has no critical PHP security release to compare with.', 'vigilante' );
            return Vigilante_SA_Check_Result::info( $args );
        }

        $name = (string) $item['name'];
        $cves = implode( ', ', (array) $item['cves'] );
        $what = (string) $item['what'];
        $args['data']['advisory'] = $name;

        // A test release (8.5.12RC1, 8.6.0RC3) carries the number of the
        // release it leads to; any other mark is a build of a distribution.
        $test_release = (bool) preg_match( '/^-?(dev|alpha|beta|rc)/i', (string) $extra );
        $marked       = '' !== (string) $extra && ! $test_release;

        // Some distributions keep fixing a branch after PHP stops: Ubuntu
        // 22.04 ships 8.1 with its own mark (8.1.2-1ubuntu2.23), and saying
        // that it lacks the fix was not known to be true (first blind review
        // of 3.0.9). The row about the branch already fails it: every branch
        // Vigilant runs on (7.4 and later) is in php_eol_table().
        if ( 'no_fix' === $status['state'] && $marked ) {
            $args['detail'] = sprintf(
                /* translators: 1: PHP version as PHP reports it, 2: name of the security release like PHP2Shell, 3: CVE identifiers, 4: what the flaws allow, like "critical flaws that let anyone run code on the server" */
                __( 'The version number of PHP %1$s carries an addition by whoever built it, as Linux distributions do, and some keep fixing a branch after PHP stops. So the number cannot tell whether this PHP has the fixes of %2$s (%3$s), %4$s, which PHP did not publish for this branch. Ask your host to confirm it, or move to a supported branch.', 'vigilante' ),
                $version,
                $name,
                $cves,
                $what
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        if ( 'no_fix' === $status['state'] ) {
            $args['detail'] = sprintf(
                /* translators: 1: PHP branch like 8.1, 2: name of the security release like PHP2Shell, 3: CVE identifiers, 4: what the flaws allow, like "critical flaws that let anyone run code on the server" */
                __( 'PHP %1$s no longer receives security fixes, so it does not have those of %2$s (%3$s), %4$s. Update to a supported branch.', 'vigilante' ),
                $branch,
                $name,
                $cves,
                $what
            );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        // A fix can arrive in any test release or only in the stable one.
        if ( $test_release ) {
            $args['detail'] = sprintf(
                /* translators: 1: PHP version as PHP reports it, 2: name of the security release like PHP2Shell, 3: CVE identifiers, 4: what the flaws allow, like "critical flaws that let anyone run code on the server" */
                __( 'PHP %1$s is a test release, and its number cannot tell whether it has the fixes of %2$s (%3$s), %4$s. Use a stable release of PHP on a live site.', 'vigilante' ),
                $version,
                $name,
                $cves,
                $what
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        if ( 'behind' === $status['state'] && $marked ) {
            $args['detail'] = sprintf(
                /* translators: 1: PHP version as PHP reports it, 2: first release of its branch with the fix, 3: name of the security release like PHP2Shell, 4: CVE identifiers, 5: what the flaws allow, like "critical flaws that let anyone run code on the server" */
                __( 'The version number of PHP %1$s carries an addition by whoever built it, as Linux distributions do, and they can apply fixes without changing the number. So the number cannot tell whether this PHP has the fixes of %3$s (%4$s), %5$s, which reached its branch in %2$s. Ask your host to confirm it.', 'vigilante' ),
                $version,
                $status['required'],
                $name,
                $cves,
                $what
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        if ( 'behind' === $status['state'] ) {
            $args['detail'] = sprintf(
                /* translators: 1: PHP version, 2: first release of its branch with the fix, 3: name of the security release like PHP2Shell, 4: CVE identifiers, 5: what the flaws allow, like "critical flaws that let anyone run code on the server" */
                __( 'PHP %1$s is older than %2$s, the first release of its branch with the fixes of %3$s (%4$s), %5$s. Update PHP, or ask your host to. Some Linux distributions apply fixes without changing the version number: your host can tell you whether yours has them.', 'vigilante' ),
                $version,
                $status['required'],
                $name,
                $cves,
                $what
            );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $args['detail'] = sprintf(
            /* translators: 1: PHP version, 2: name of the security release like PHP2Shell, 3: CVE identifiers, 4: month and year of that release */
            __( 'PHP %1$s has the fixes of %2$s (%3$s), the last critical security release of PHP that this version of Vigilant knows about (%4$s).', 'vigilante' ),
            $version,
            $name,
            $cves,
            wp_date( 'F Y', (int) strtotime( $item['date'] . ' 12:00:00 UTC' ) )
        );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_wp_core_updates() {
        $args = array(
            'id'       => 'wp_core_updates',
            'category' => self::SLUG,
            'max'      => 3,
            'label'    => __( 'WordPress core version', 'vigilante' ),
            'fix_link' => admin_url( 'update-core.php' ),
        );

        if ( ! function_exists( 'get_core_updates' ) ) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $updates = function_exists( 'get_core_updates' ) ? get_core_updates() : array();

        $has_update = false;
        $next_version = '';
        if ( is_array( $updates ) ) {
            foreach ( $updates as $u ) {
                if ( isset( $u->response ) && 'upgrade' === $u->response ) {
                    $has_update   = true;
                    $next_version = isset( $u->version ) ? $u->version : '';
                    break;
                }
            }
        }

        $args['data'] = array(
            'current' => get_bloginfo( 'version' ),
            'next'    => $next_version,
        );

        if ( $has_update ) {
            $args['detail'] = sprintf(
                /* translators: 1: current version, 2: new version */
                __( 'Core can update from %1$s to %2$s. Apply the update now.', 'vigilante' ),
                get_bloginfo( 'version' ),
                $next_version
            );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %s: wp version */
            __( 'Running WordPress %s — no core update pending.', 'vigilante' ),
            get_bloginfo( 'version' )
        );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_plugin_updates() {
        $args = array(
            'id'       => 'plugin_updates',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Plugin updates', 'vigilante' ),
            'fix_link' => admin_url( 'plugins.php?plugin_status=upgrade' ),
        );

        if ( ! function_exists( 'get_plugin_updates' ) ) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $updates = function_exists( 'get_plugin_updates' ) ? get_plugin_updates() : array();
        $count   = is_array( $updates ) ? count( $updates ) : 0;
        $args['data'] = array( 'count' => $count );

        if ( 0 === $count ) {
            $args['detail'] = __( 'All active plugins on their latest version.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }
        if ( $count <= 2 ) {
            $args['detail'] = sprintf(
                /* translators: %d: count */
                _n( '%d plugin has an update available.', '%d plugins have updates available.', $count, 'vigilante' ),
                $count
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: count */
            _n( '%d plugin is outdated.', '%d plugins are outdated. Apply updates as soon as possible.', $count, 'vigilante' ),
            $count
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_theme_updates() {
        $args = array(
            'id'       => 'theme_updates',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'Theme updates', 'vigilante' ),
            'fix_link' => admin_url( 'themes.php' ),
        );

        if ( ! function_exists( 'get_theme_updates' ) ) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $updates = function_exists( 'get_theme_updates' ) ? get_theme_updates() : array();
        $count   = is_array( $updates ) ? count( $updates ) : 0;
        $args['data'] = array( 'count' => $count );

        if ( 0 === $count ) {
            $args['detail'] = __( 'All installed themes on their latest version.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: count */
            _n( '%d theme needs updating.', '%d themes need updating.', $count, 'vigilante' ),
            $count
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_inactive_plugins() {
        $args = array(
            'id'       => 'inactive_plugins',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Inactive plugins', 'vigilante' ),
            'fix_link' => admin_url( 'plugins.php?plugin_status=inactive' ),
        );

        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        // Always read fresh: some caches can stale-serve this option on admin-ajax.
        wp_cache_delete( 'alloptions', 'options' );

        $plugins_map = (array) get_plugins();
        $all         = array_keys( $plugins_map );
        $active      = (array) get_option( 'active_plugins', array() );

        if ( is_multisite() ) {
            $network_active = array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) );
            $active         = array_merge( $active, $network_active );
        }

        $inactive = array_values( array_diff( $all, $active ) );
        $count    = count( $inactive );

        // Build a friendly sample of the first few inactive plugin names.
        $sample_names = array();
        foreach ( array_slice( $inactive, 0, 5 ) as $file ) {
            $sample_names[] = isset( $plugins_map[ $file ]['Name'] ) && $plugins_map[ $file ]['Name']
                ? $plugins_map[ $file ]['Name']
                : $file;
        }

        $args['data'] = array(
            'count'         => $count,
            'total_known'   => count( $all ),
            'total_active'  => count( array_unique( $active ) ),
            'sample_names'  => $sample_names,
        );

        if ( 0 === $count ) {
            $args['detail'] = __( 'No inactive plugins installed.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }
        if ( $count <= 2 ) {
            $args['detail'] = sprintf(
                /* translators: 1: count, 2: sample names */
                _n(
                    '%1$d plugin is installed but inactive (%2$s).',
                    '%1$d plugins are installed but inactive (%2$s).',
                    $count,
                    'vigilante'
                ),
                $count,
                implode( ', ', $sample_names )
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $args['detail'] = sprintf(
            /* translators: 1: count, 2: sample names */
            __( '%1$d inactive plugins installed (e.g. %2$s). Delete what you no longer use — inactive code still lives on disk and can be exploited.', 'vigilante' ),
            $count,
            implode( ', ', $sample_names )
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    /**
     * Closed + Removed plugins (v2.6.0).
     *
     * Reads the cached state map populated by Vigilante_Plugin_Status (daily
     * cron + Run Scan Now). No extra HTTP call here. Ignored slugs are
     * filtered out — if the admin chose to silence a slug it stays out of
     * the score too, mirroring how the rest of Vigilant treats ignored items.
     */
    private function check_closed_plugins() {
        $args = array(
            'id'       => 'closed_plugins',
            'category' => self::SLUG,
            'max'      => 3,
            'label'    => __( 'Closed or removed plugins', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'file-integrity', 'vigilante-section-fi-last-scan' ),
        );

        $fi_options    = (array) $this->settings->get_section( 'file_integrity' );
        $check_enabled = ! empty( $fi_options['check_closed_plugins'] );

        // The daily check belongs to File Integrity and only runs with that
        // module on (vigilante.php). With it off, whatever is stored is the
        // answer of the last day it ran.
        if ( ! $this->settings->is_module_enabled( 'file_integrity' ) ) {
            $args['detail'] = Vigilante_SA_Helpers::module_idle_detail( $this->settings, 'file_integrity' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        // A protection somebody switched off is not one that could not be
        // measured: it scores nothing, and it stays in the total.
        if ( ! $check_enabled ) {
            $args['detail'] = __( 'The "Closed plugins" check is disabled in File Integrity > Scan Scope.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        if ( ! class_exists( 'Vigilante_Plugin_Status' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-plugin-status.php';
        }
        $checker      = new Vigilante_Plugin_Status( $this->settings, $this->activity_log );
        $closed       = $checker->get_closed_plugins();
        $last_check   = $checker->get_last_check_time();
        $ignored_slugs = $checker->get_ignored_slugs();

        $args['data'] = array(
            'closed_count'  => count( $closed ),
            'ignored_count' => count( $ignored_slugs ),
            'last_check'    => $last_check,
        );

        if ( 0 === $last_check ) {
            $args['detail'] = __( 'The daily closed-plugins check has not run yet. It will run automatically within the next 24 hours, or with the next "Run Scan Now".', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        if ( empty( $closed ) ) {
            if ( ! empty( $ignored_slugs ) ) {
                $args['detail'] = sprintf(
                    /* translators: %d: count of ignored slugs */
                    _n(
                        'No active closed plugins. %d slug is on the ignore list and excluded from this check.',
                        'No active closed plugins. %d slugs are on the ignore list and excluded from this check.',
                        count( $ignored_slugs ),
                        'vigilante'
                    ),
                    count( $ignored_slugs )
                );
            } else {
                $args['detail'] = __( 'No installed plugin is currently closed in the WordPress.org repository.', 'vigilante' );
            }
            return Vigilante_SA_Check_Result::pass( $args );
        }

        // Build a friendly sample of names for the detail message.
        $sample = array();
        foreach ( array_slice( $closed, 0, 5, true ) as $slug => $entry ) {
            $sample[] = isset( $entry['name'] ) && $entry['name'] ? $entry['name'] : $slug;
        }

        $args['detail'] = sprintf(
            /* translators: 1: count, 2: sample names */
            _n(
                '%1$d plugin installed on this site is currently closed or removed in the WordPress.org repository (%2$s). Closures usually indicate malware, security issues, guideline violations or supply chain compromises. Uninstall and replace as soon as possible.',
                '%1$d plugins installed on this site are currently closed or removed in the WordPress.org repository (%2$s). Closures usually indicate malware, security issues, guideline violations or supply chain compromises. Uninstall and replace as soon as possible.',
                count( $closed ),
                'vigilante'
            ),
            count( $closed ),
            implode( ', ', $sample )
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    /**
     * Vigilant self-integrity state (self-protection, 3.0.0).
     *
     * Reads the cached vigilante_self_integrity_state option written by
     * Vigilante_Self_Integrity: no filesystem hashing and no HTTP here, so
     * the check is fast-phase safe. The wording is the shared guidance
     * catalogue, so this check, the File Integrity box, the audit details and
     * the alert email say the same thing about the same finding.
     *
     * It is the heaviest single check of the analyzer (10 points) and a
     * critical result caps the whole score in build_report(): every other
     * result is computed by the same code whose files were changed.
     */
    private function check_self_integrity() {
        $args = array(
            'id'       => 'self_integrity',
            'category' => self::SLUG,
            'max'      => 10,
            'label'    => __( 'Vigilant self-protection', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'file-integrity', 'vigilante-section-fi-self' ),
        );

        $enabled    = Vigilante_Self_Integrity::is_on();
        $state      = Vigilante_Self_Integrity::display_state();
        $tone       = Vigilante_Self_Integrity::tone( $state, $enabled );
        $findings   = Vigilante_Self_Integrity::state_findings( $state, $enabled );
        $files      = isset( $state['files_checked'] ) ? (int) $state['files_checked'] : 0;
        $anchors    = ( isset( $state['anchors'] ) && is_array( $state['anchors'] ) ) ? $state['anchors'] : array();

        // What decides the points: tasks that Vigilant had to schedule again,
        // while that is only a warning, do not take any away. The files are as
        // verified as they were, and that is what these ten points are for.
        // This file is loaded when the analyzer is created, and the class it
        // asks is loaded with the plugin: in the cron run in which WordPress
        // updates Vigilant, the class in memory is the one of the version
        // before, which may not have the method yet.
        $score_tone = method_exists( 'Vigilante_Self_Integrity', 'score_tone' ) ? Vigilante_Self_Integrity::score_tone( $state, $enabled ) : $tone;

        $args['data'] = array(
            'status'        => isset( $state['last_status'] ) ? (string) $state['last_status'] : '',
            'tone'          => $tone,
            'score_tone'    => $score_tone,
            'files_checked' => $files,
            'anchors'       => count( array_filter( $anchors ) ),
            'findings'      => count( $findings ),
            'last_check'    => isset( $state['last_check'] ) ? (int) $state['last_check'] : 0,
        );

        // Worst finding first: it is the one that decides the tone, so it is
        // the one to explain.
        $worst = null;
        foreach ( $findings as $finding ) {
            $severity = isset( $finding['severity'] ) ? (string) $finding['severity'] : '';
            if ( 'critical' === $severity ) {
                $worst = $finding;
                break;
            }
            if ( 'warning' === $severity && null === $worst ) {
                $worst = $finding;
            }
        }

        if ( null !== $worst ) {
            $guidance = Vigilante_Self_Integrity_Guidance::for_finding( $worst );
        } else {
            $guidance = Vigilante_Self_Integrity_Guidance::for_status(
                array(
                    'status'  => isset( $state['last_status'] ) ? $state['last_status'] : '',
                    'files'   => $files,
                    'anchors' => $anchors,
                    'enabled' => $enabled,
                    'has_run' => ! empty( $state['last_check'] ),
                )
            );
        }

        $detail = $guidance['title'] . '. ' . $guidance['meaning'];
        if ( ! empty( $guidance['steps'] ) ) {
            $detail .= ' ' . $guidance['steps'][0];
        }
        $count = count( $findings );
        if ( $count > 1 ) {
            $detail .= ' ' . sprintf(
                /* translators: %d: number of findings about Vigilant own files */
                _n(
                    '%d finding in total: File Integrity lists every one, with what it means and what to do.',
                    '%d findings in total: File Integrity lists every one, with what each one means and what to do.',
                    $count,
                    'vigilante'
                ),
                $count
            );
        }
        $args['detail'] = $detail;

        if ( 'none' === $tone ) {
            return Vigilante_SA_Check_Result::skip( $args );
        }
        // Switched off by code counts as a failure, not as a check that did not
        // apply: somebody had to write that filter.
        if ( 'critical' === $tone || 'off' === $tone ) {
            return Vigilante_SA_Check_Result::fail( $args );
        }
        if ( 'warning' === $score_tone ) {
            return Vigilante_SA_Check_Result::warn( $args );
        }
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_file_permissions() {
        $args = array(
            'id'       => 'file_permissions',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Core file permissions', 'vigilante' ),
            'fix_link' => '',
        );

        // WordPress also loads wp-config.php from the directory above its own
        // when that directory is not another installation (wp-load.php). Until
        // 3.0.4 only ABSPATH was looked at, and a site set up that way passed
        // without its file having been read.
        $wp_config = ABSPATH . 'wp-config.php';
        if ( ! file_exists( $wp_config ) ) {
            $above     = dirname( ABSPATH );
            $wp_config = ( @file_exists( $above . '/wp-config.php' ) && ! @file_exists( $above . '/wp-settings.php' ) ) // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir may forbid the directory above; same call and same silencing as wp-load.php.
                ? $above . '/wp-config.php'
                : '';
        }

        $htaccess  = ABSPATH . '.htaccess';
        $issues    = array();
        $config_perm = ( '' !== $wp_config ) ? @fileperms( $wp_config ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A file that cannot be read is reported below, not as a PHP warning.

        if ( false === $config_perm ) {
            $args['detail'] = __( 'wp-config.php could not be found or read from here, so its permissions could not be checked. Not scored.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        // Anything more permissive than 0644 is worth flagging.
        if ( ( $config_perm & 0777 ) & 0022 ) {
            $issues[] = sprintf( 'wp-config.php: %s', self::octal( $config_perm & 0777 ) );
        }

        if ( file_exists( $htaccess ) ) {
            $perm = fileperms( $htaccess ) & 0777;
            if ( $perm & 0022 ) {
                $issues[] = sprintf( '.htaccess: %s', self::octal( $perm ) );
            }
        }

        $args['data'] = array( 'issues' => $issues );

        if ( empty( $issues ) ) {
            $args['detail'] = __( 'wp-config.php and .htaccess are not world-writable.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %s: comma-separated list of files with octal perms */
            __( 'World-writable permissions detected: %s. Ask your host to tighten them.', 'vigilante' ),
            implode( ', ', $issues )
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_salts_default() {
        $args = array(
            'id'       => 'salts_default',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Secret keys (salts)', 'vigilante' ),
            'fix_link' => '',
        );

        $keys = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
                       'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );

        $missing_or_weak = array();
        foreach ( $keys as $k ) {
            if ( ! defined( $k ) ) {
                $missing_or_weak[] = $k;
                continue;
            }
            $val = constant( $k );
            if ( ! is_string( $val ) || strlen( $val ) < 32 ) {
                $missing_or_weak[] = $k;
                continue;
            }
            if ( false !== stripos( $val, 'put your unique phrase here' ) ) {
                $missing_or_weak[] = $k;
            }
        }

        $args['data'] = array( 'weak_keys' => $missing_or_weak );

        if ( empty( $missing_or_weak ) ) {
            $args['detail'] = __( 'All WordPress secret keys are defined and at least 32 characters long.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %s: comma-separated key names */
            __( 'These secret keys look weak or default: %s. Regenerate them from https://api.wordpress.org/secret-key/1.1/salt/', 'vigilante' ),
            implode( ', ', $missing_or_weak )
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_table_prefix() {
        global $wpdb;
        $args = array(
            'id'       => 'table_prefix',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Database prefix', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'wp-hardening', 'vigilante-section-hardening-database' ),
        );

        $prefix       = $wpdb ? $wpdb->prefix : 'wp_';
        $args['data'] = array( 'prefix' => $prefix );

        if ( 'wp_' === $prefix ) {
            $args['detail'] = __( 'The database prefix is still the default "wp_". Change it to a custom prefix.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %s: custom table prefix */
            __( 'Using a custom database prefix: %s', 'vigilante' ),
            $prefix
        );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_admin_username() {
        $args = array(
            'id'       => 'admin_username',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Administrator named "admin"', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'users', 'vigilante-section-users-password' ),
        );

        $user = get_user_by( 'login', 'admin' );
        if ( $user instanceof WP_User && in_array( 'administrator', (array) $user->roles, true ) ) {
            $args['detail'] = __( 'A user named "admin" with administrator role exists. Create a new admin account and delete this one.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $args['detail'] = __( 'No administrator is named "admin".', 'vigilante' );
        return Vigilante_SA_Check_Result::pass( $args );
    }

    private function check_admins_without_2fa() {
        $args = array(
            'id'       => 'admins_without_2fa',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Administrators with 2FA enrolled', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'login', 'vigilante-section-login-2fa' ),
        );

        $two_factor = $this->settings->get_option( 'login_security', 'two_factor', array() );

        // On a network the second factor is enforced on every site and the
        // requirement is the union of what each site of the account asks for
        // (Vigilante_Settings::two_factor_required_for()), so this site's own
        // switch does not settle it. On a single site it does, together with
        // the Login Security module that loads the two classes.
        if ( ! is_multisite() ) {
            if ( empty( $two_factor['enabled'] ) ) {
                $args['detail'] = __( '2FA is not enabled globally, so no administrator is protected with a second factor.', 'vigilante' );
                return Vigilante_SA_Check_Result::fail( $args );
            }

            if ( ! $this->settings->is_module_enabled( 'login_security' ) ) {
                $args['detail'] = Vigilante_SA_Helpers::module_off_detail( $this->settings, 'login_security' );
                return Vigilante_SA_Check_Result::fail( $args );
            }
        }

        $admins = get_users(
            array(
                'role'   => 'administrator',
                'fields' => array( 'ID', 'user_login' ),
            )
        );
        if ( empty( $admins ) ) {
            $args['detail'] = __( 'No administrators found (?).', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $method            = isset( $two_factor['method'] ) ? $two_factor['method'] : 'email';
        $unenrolled        = array();
        $not_asked         = 0;
        $enrolled_count    = 0;

        foreach ( $admins as $admin ) {
            // Asked the way the login asks: the enforced roles and the excluded
            // users decide who gets a second factor at all. Until 3.0.4 an
            // administrator left out by either counted here as protected.
            $account = get_userdata( $admin->ID );

            if ( ! $account || ! Vigilante_Settings::two_factor_required_for( $account ) ) {
                $not_asked++;
                $unenrolled[] = $admin->user_login;
                continue;
            }

            $methods  = Vigilante_Settings::two_factor_methods_for( $account );
            $enrolled = false;
            foreach ( ( empty( $methods ) ? array( $method ) : $methods ) as $asked ) {
                if ( $this->is_user_enrolled( $admin->ID, $asked ) ) {
                    $enrolled = true;
                    break;
                }
            }

            if ( $enrolled ) {
                $enrolled_count++;
            } else {
                $unenrolled[] = $admin->user_login;
            }
        }

        $total = count( $admins );
        $args['data'] = array(
            'total'         => $total,
            'enrolled'      => $enrolled_count,
            'unenrolled'    => $unenrolled,
            'not_asked'     => $not_asked,
            'method'        => $method,
        );

        if ( 0 === count( $unenrolled ) ) {
            $args['detail'] = sprintf(
                /* translators: %d: number of administrators with 2FA enrolled */
                _n( '%d administrator has 2FA enrolled.', '%d administrators have 2FA enrolled.', $total, 'vigilante' ),
                $total
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = sprintf(
            /* translators: 1: unenrolled count, 2: total admins, 3: comma-separated logins */
            __( '%1$d of %2$d administrators do not have 2FA set up: %3$s', 'vigilante' ),
            count( $unenrolled ),
            $total,
            implode( ', ', array_slice( $unenrolled, 0, 5 ) )
        );

        if ( $not_asked > 0 ) {
            $args['detail'] .= ' ' . sprintf(
                /* translators: %d: number of administrator accounts */
                _n(
                    '%d of them is not asked for a second factor at all: the role is not among the enforced roles, or the account is in the excluded users.',
                    '%d of them are not asked for a second factor at all: the role is not among the enforced roles, or the account is in the excluded users.',
                    $not_asked,
                    'vigilante'
                ),
                $not_asked
            );
        }

        return count( $unenrolled ) === $total
            ? Vigilante_SA_Check_Result::fail( $args )
            : Vigilante_SA_Check_Result::warn( $args );
    }

    private function check_vigilante_modules_off() {
        $args = array(
            'id'       => 'vigilante_modules_off',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Core Vigilant modules', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'dashboard', 'vigilante-section-dashboard-modules' ),
        );

        $critical    = array( 'firewall', 'login_security', 'file_integrity', 'security_headers' );
        $off         = array();
        $module_names = array(
            'firewall'         => __( 'Firewall', 'vigilante' ),
            'login_security'   => __( 'Login Security', 'vigilante' ),
            'file_integrity'   => __( 'File Integrity', 'vigilante' ),
            'security_headers' => __( 'Security Headers', 'vigilante' ),
        );

        foreach ( $critical as $mod ) {
            if ( ! $this->settings->is_module_enabled( $mod ) ) {
                $off[] = isset( $module_names[ $mod ] ) ? $module_names[ $mod ] : $mod;
            }
        }

        $args['data'] = array( 'off' => $off );

        if ( empty( $off ) ) {
            $args['detail'] = __( 'Firewall, Login Security, File Integrity and Security Headers modules all detected as enabled.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %s: comma-separated module names */
            __( 'Critical modules are disabled: %s. Re-enable them from the Dashboard.', 'vigilante' ),
            implode( ', ', $off )
        );
        return count( $off ) >= 2
            ? Vigilante_SA_Check_Result::fail( $args )
            : Vigilante_SA_Check_Result::warn( $args );
    }

    private function check_audit_alerts_active() {
        $args = array(
            'id'       => 'audit_alerts_active',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Audit alerts configured', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'activity-log', 'vigilante-section-audit-alerts' ),
        );

        // Alerts ride on top of Security Audit; with the module off there is
        // nothing to alert on. That is a protection switched off, not a check
        // that could not be measured: it scores nothing and stays in the
        // total, or switching the module off would raise the score.
        if ( ! $this->settings->is_module_enabled( 'activity_log' ) ) {
            $args['detail'] = __( 'Security Audit is disabled, so audit alerts do not apply. Enable Security Audit to use them.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        if ( ! class_exists( 'Vigilante_Audit_Alerts' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-audit-alerts.php';
        }

        $config    = (array) $this->settings->get_section( 'audit_alerts' );
        $immediate = Vigilante_Audit_Alerts::immediate_is_active( $config );
        $threshold = Vigilante_Audit_Alerts::threshold_is_active( $config );

        $args['data'] = array(
            'immediate' => $immediate,
            'threshold' => $threshold,
        );

        if ( $immediate || $threshold ) {
            $active = array();
            if ( $immediate ) {
                $active[] = __( 'immediate', 'vigilante' );
            }
            if ( $threshold ) {
                $active[] = __( 'threshold', 'vigilante' );
            }
            $args['detail'] = sprintf(
                /* translators: %s: comma-separated list of active alert types */
                __( 'Audit alerts are active (%s). Important events will reach you by email.', 'vigilante' ),
                implode( ', ', $active )
            );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $args['detail'] = __( 'No audit alerts are configured. Turn on immediate or threshold alerts so important events reach you by email.', 'vigilante' );
        return Vigilante_SA_Check_Result::warn( $args );
    }

    private function check_activity_log_errors() {
        $args = array(
            'id'       => 'activity_log_errors',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'Critical activity in the last 24 hours', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'activity-log', 'vigilante-section-audit-recent' ),
        );

        // With Security Audit off nothing is being recorded, so an empty day
        // is not a quiet one. Asked before the service below: off is a
        // failure whether or not this scan was handed the log.
        if ( ! $this->settings->is_module_enabled( 'activity_log' ) ) {
            $args['detail'] = Vigilante_SA_Helpers::module_idle_detail( $this->settings, 'activity_log' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        if ( ! $this->activity_log || ! method_exists( $this->activity_log, 'get_logs_count' ) ) {
            $args['detail'] = __( 'Activity log service not available for this scan.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        // Only `critical`: the log has no `high` severity, and the query that
        // asked for it until 3.0.4 always came back with zero.
        $since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
        $count = (int) $this->activity_log->get_logs_count(
            array(
                'severity'  => 'critical',
                'date_from' => $since,
            )
        );
        $args['data'] = array(
            'count'          => $count,
            'count_critical' => $count,
        );

        if ( 0 === $count ) {
            $args['detail'] = __( 'No high or critical events in the last 24 hours.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }
        if ( $count <= 3 ) {
            $args['detail'] = sprintf(
                /* translators: %d: count */
                _n( '%d high-severity event in the last 24 hours.', '%d high-severity events in the last 24 hours.', $count, 'vigilante' ),
                $count
            );
            return Vigilante_SA_Check_Result::warn( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: count */
            __( '%d high or critical events in the last 24 hours. Review the audit log.', 'vigilante' ),
            $count
        );
        return Vigilante_SA_Check_Result::fail( $args );
    }

    private function check_file_integrity_status() {
        $args = array(
            'id'       => 'file_integrity_status',
            'category' => self::SLUG,
            'max'      => 1,
            'label'    => __( 'File integrity scan', 'vigilante' ),
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'file-integrity', 'vigilante-section-fi-last-scan' ),
        );

        // With the module off no scan runs, and the result of the last one
        // that did stays stored: until 3.0.4 it went on passing here.
        if ( ! $this->settings->is_module_enabled( 'file_integrity' ) ) {
            $args['detail'] = Vigilante_SA_Helpers::module_idle_detail( $this->settings, 'file_integrity' );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $last = get_option( 'vigilante_last_integrity_results' );

        // A scan that started and was stopped before saving (since 3.0.8). This
        // file loads late, from disk: in the cron run in which WordPress updates
        // Vigilant, the class in memory is the old one and has no such methods,
        // so both are asked for.
        $unfinished_text = '';
        if ( method_exists( 'Vigilante_File_Integrity', 'unfinished_scan' ) && method_exists( 'Vigilante_File_Integrity', 'unfinished_scan_text' ) ) {
            $unfinished = Vigilante_File_Integrity::unfinished_scan();
            if ( is_array( $unfinished ) ) {
                $unfinished_text = Vigilante_File_Integrity::unfinished_scan_text( $unfinished );
            }
        }

        if ( ! is_array( $last ) ) {
            if ( '' !== $unfinished_text ) {
                $args['detail'] = $unfinished_text;
                return Vigilante_SA_Check_Result::warn( $args );
            }
            $args['detail'] = __( 'No file integrity scan recorded yet. Run one from the File Integrity tab.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $suspicious = isset( $last['suspicious'] ) ? count( (array) $last['suspicious'] ) : 0;
        $modified   = isset( $last['modified'] ) ? count( (array) $last['modified'] ) : 0;

        $args['data'] = array(
            'suspicious' => $suspicious,
            'modified'   => $modified,
        );

        // A scan that could not check everything is not a clean bill: what
        // it did not reach was not looked at. Until now a partial scan with
        // nothing found passed here like a complete one.
        $partial = Vigilante_File_Integrity::is_partial( $last );

        $args['data']['partial'] = $partial;

        // A `new` of the scanner is only a `new`: no hooks, no scan.
        $scanner       = new Vigilante_File_Integrity( $this->settings );
        $excluded_code = $scanner->excluded_code_folders();

        $args['data']['excluded_code'] = count( $excluded_code );

        if ( 0 === $suspicious && 0 === $modified ) {
            // Clean, but it is the result of a scan older than one that did
            // not finish: said before anything else.
            if ( '' !== $unfinished_text ) {
                $args['detail'] = $unfinished_text;
                return Vigilante_SA_Check_Result::warn( $args );
            }

            if ( $partial ) {
                $args['detail'] = __( 'The last file integrity scan found nothing in what it checked, but it could not check everything. File Integrity lists what was left out.', 'vigilante' );
                return Vigilante_SA_Check_Result::warn( $args );
            }

            // Nor is a result that is older than the schedule allows: a scan
            // the server stops halfway stores nothing, one that WordPress
            // never starts does not either, and the last one that did finish
            // stays as "the last scan" for as long as that goes on.
            $last_scan = (int) get_option( 'vigilante_last_integrity_scan', 0 );
            $frequency = (string) $this->settings->get_option( 'file_integrity', 'scan_frequency', 'daily' );

            if ( $this->settings->is_module_enabled( 'file_integrity' ) && Vigilante_File_Integrity::is_scan_overdue( $last_scan, $frequency ) ) {
                $args['detail'] = sprintf(
                    /* translators: %s: How long ago, such as "5 days" */
                    __( 'The last file integrity scan that finished is from %s ago, and scans are scheduled. Either the scheduled tasks of WordPress are not running or the scans are not finishing: run one from File Integrity.', 'vigilante' ),
                    human_time_diff( $last_scan )
                );
                return Vigilante_SA_Check_Result::warn( $args );
            }

            // Nor is a scan that Excluded Paths keeps out of whole folders of
            // code: it finishes, finds nothing, and never looked there.
            if ( ! empty( $excluded_code ) ) {
                $args['detail'] = sprintf(
                    /* translators: %s: Comma separated list of folders */
                    __( 'The last file integrity scan found nothing, but Excluded Paths holds whole folders of plugins or themes, or the uploads folder, and no scan looks inside them: %s.', 'vigilante' ),
                    implode( ', ', $excluded_code )
                );
                return Vigilante_SA_Check_Result::warn( $args );
            }

            $args['detail'] = __( 'Last file integrity scan returned no suspicious or modified files.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        $partial_note = $partial ? ' ' . __( 'That scan could not check everything: File Integrity lists what was left out.', 'vigilante' ) : '';

        if ( '' !== $unfinished_text ) {
            $partial_note .= ' ' . $unfinished_text;
        }

        if ( ! empty( $excluded_code ) ) {
            $partial_note .= ' ' . __( 'Whole folders of plugins or themes, or the uploads folder, are in Excluded Paths, and no scan looks inside them.', 'vigilante' );
        }

        if ( $suspicious > 0 ) {
            $args['detail'] = sprintf(
                /* translators: %d: count */
                _n( '%d suspicious file flagged by the last integrity scan.', '%d suspicious files flagged by the last integrity scan.', $suspicious, 'vigilante' ),
                $suspicious
            ) . $partial_note;
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: count */
            _n( '%d modified file recorded by the last integrity scan — review in File Integrity.', '%d modified files recorded by the last integrity scan.', $modified, 'vigilante' ),
            $modified
        ) . $partial_note;
        return Vigilante_SA_Check_Result::warn( $args );
    }

    /**
     * Whether the given user is enrolled in 2FA for the active method.
     *
     * @param int    $user_id User ID.
     * @param string $method  'email' | 'totp'.
     * @return bool
     */
    private function is_user_enrolled( $user_id, $method ) {
        if ( 'totp' === $method ) {
            // TOTP stores enrollment in the database via Vigilante_Database->get_totp_data().
            if ( class_exists( 'Vigilante_Database' ) ) {
                $database = new Vigilante_Database();
                if ( method_exists( $database, 'get_totp_data' ) ) {
                    $data = $database->get_totp_data( $user_id );
                    return is_array( $data ) && ! empty( $data['is_configured'] );
                }
            }
            return false;
        }

        // For email 2FA, enrollment is implicit once the user has a verified email
        // and the global setting is on. We conservatively consider any admin enrolled
        // because email codes will be delivered on login.
        $user = get_userdata( $user_id );
        return $user && ! empty( $user->user_email ) && is_email( $user->user_email );
    }

    /**
     * Format octal permissions like "644".
     */
    private static function octal( $perm ) {
        return substr( sprintf( '%o', $perm ), -3 );
    }
}
