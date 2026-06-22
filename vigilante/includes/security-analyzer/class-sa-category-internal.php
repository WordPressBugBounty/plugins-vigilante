<?php
/**
 * Security Analyzer — Internal-exclusive category (30 pts).
 *
 * The differential of this analyzer vs any external scanner. Each check
 * reads data that is impossible to observe from the outside.
 *
 * Checks:
 *  - php_version_eol (3)
 *  - wp_core_updates (3)
 *  - plugin_updates (2)
 *  - theme_updates (1)
 *  - inactive_plugins (2)
 *  - closed_plugins (3)  ← v2.6.0: reads the cached state from the daily
 *                          Vigilante_Plugin_Status check; no extra HTTP call.
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
        $results[] = $this->check_wp_core_updates();
        $results[] = $this->check_plugin_updates();
        $results[] = $this->check_theme_updates();
        $results[] = $this->check_inactive_plugins();
        $results[] = $this->check_closed_plugins();
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

        if ( ! $check_enabled ) {
            $args['detail'] = __( 'The "Closed plugins" check is disabled in File Integrity > Scan Scope.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
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

    private function check_file_permissions() {
        $args = array(
            'id'       => 'file_permissions',
            'category' => self::SLUG,
            'max'      => 2,
            'label'    => __( 'Core file permissions', 'vigilante' ),
            'fix_link' => '',
        );

        $wp_config = ABSPATH . 'wp-config.php';
        $htaccess  = ABSPATH . '.htaccess';
        $issues    = array();

        if ( file_exists( $wp_config ) ) {
            $perm = fileperms( $wp_config ) & 0777;
            // Anything more permissive than 0644 is worth flagging.
            if ( $perm & 0022 ) {
                $issues[] = sprintf( 'wp-config.php: %s', self::octal( $perm ) );
            }
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
            'fix_link' => Vigilante_SA_Helpers::build_fix_url( 'users', 'vigilante-section-users-main' ),
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
        if ( empty( $two_factor['enabled'] ) ) {
            $args['detail'] = __( '2FA is not enabled globally, so no administrator is protected with a second factor.', 'vigilante' );
            return Vigilante_SA_Check_Result::fail( $args );
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
        $enrolled_count    = 0;

        foreach ( $admins as $admin ) {
            $enrolled = $this->is_user_enrolled( $admin->ID, $method );
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
        // nothing to alert on, so the check does not apply.
        if ( ! $this->settings->is_module_enabled( 'activity_log' ) ) {
            $args['detail'] = __( 'Security Audit is disabled, so audit alerts do not apply. Enable Security Audit to use them.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
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

        if ( ! $this->activity_log || ! method_exists( $this->activity_log, 'get_logs_count' ) ) {
            $args['detail'] = __( 'Activity log service not available for this scan.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
        $count_critical = (int) $this->activity_log->get_logs_count(
            array(
                'severity'  => 'critical',
                'date_from' => $since,
            )
        );
        $count_high = (int) $this->activity_log->get_logs_count(
            array(
                'severity'  => 'high',
                'date_from' => $since,
            )
        );
        $count        = $count_critical + $count_high;
        $args['data'] = array(
            'count'          => $count,
            'count_critical' => $count_critical,
            'count_high'     => $count_high,
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

        $last = get_option( 'vigilante_last_integrity_results' );
        if ( ! is_array( $last ) ) {
            $args['detail'] = __( 'No file integrity scan recorded yet. Run one from the File Integrity tab.', 'vigilante' );
            return Vigilante_SA_Check_Result::skip( $args );
        }

        $suspicious = isset( $last['suspicious'] ) ? count( (array) $last['suspicious'] ) : 0;
        $modified   = isset( $last['modified'] ) ? count( (array) $last['modified'] ) : 0;

        $args['data'] = array(
            'suspicious' => $suspicious,
            'modified'   => $modified,
        );

        if ( 0 === $suspicious && 0 === $modified ) {
            $args['detail'] = __( 'Last file integrity scan returned no suspicious or modified files.', 'vigilante' );
            return Vigilante_SA_Check_Result::pass( $args );
        }

        if ( $suspicious > 0 ) {
            $args['detail'] = sprintf(
                /* translators: %d: count */
                _n( '%d suspicious file flagged by the last integrity scan.', '%d suspicious files flagged by the last integrity scan.', $suspicious, 'vigilante' ),
                $suspicious
            );
            return Vigilante_SA_Check_Result::fail( $args );
        }

        $args['detail'] = sprintf(
            /* translators: %d: count */
            _n( '%d modified file recorded by the last integrity scan — review in File Integrity.', '%d modified files recorded by the last integrity scan.', $modified, 'vigilante' ),
            $modified
        );
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
