<?php
/**
 * File Integrity Class
 *
 * Handles file integrity monitoring and scanning
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_File_Integrity
 *
 * Manages file integrity checks against WordPress.org checksums
 */
class Vigilante_File_Integrity {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Database instance
     *
     * @var Vigilante_Database
     */
    private $database;

    /**
     * Activity log instance
     *
     * @var Vigilante_Activity_Log
     */
    private $activity_log;

    /**
     * File integrity options
     *
     * @var array
     */
    private $options;

    /**
     * WordPress version
     *
     * @var string
     */
    private $wp_version;

    /**
     * Ignored files list
     *
     * @var array
     */
    private $ignored_files;

    /**
     * Scan start time for timeout control
     *
     * @var float
     */
    private $scan_start_time = 0;

    /**
     * Seconds a scan runs for at most
     *
     * A scan is one request, and it starts from the beginning every time. On
     * a site too large for this, what comes last is left unchecked on every
     * scan, so the results say what was not reached (see not_checked_lines()).
     */
    const MAX_SCAN_SECONDS = 60;

    /**
     * Maximum scan time in seconds (default 60s for thorough scanning)
     *
     * @var int
     */
    private $max_scan_time = self::MAX_SCAN_SECONDS;

    /**
     * Option that marks a scan in progress, without autoload
     *
     * Written when a scan starts and deleted when its result is saved. A
     * scan that PHP or the server stops halfway leaves it behind, and that
     * is the only trace of it: until 3.0.8 such a scan left nothing, and the
     * tab went on showing the last result that did finish, or nothing at all
     * when it was the button, which cleared the previous result first.
     *
     * @since 3.0.8
     */
    const RUNNING_OPTION = 'vigilante_integrity_scan_running';

    /**
     * Option with the scan that did not finish, found by the next one that
     * started, without autoload. Deleted when a scan finishes.
     *
     * @since 3.0.8
     */
    const UNFINISHED_OPTION = 'vigilante_integrity_scan_unfinished';

    /**
     * Seconds left in the request below which the closed-plugins check is
     * left out of the scan
     *
     * It asks WordPress.org once per installed plugin, outside the scan
     * clock: 27.6 s for 57 plugins in Testing on 4 Oct 2026. The daily check
     * of plugin status runs it anyway.
     *
     * @since 3.0.8
     */
    const CLOSED_PLUGINS_SECONDS = 35;

    /**
     * Seconds a request for the checksums of WordPress.org may wait
     *
     * Also what the margin of a scan cut to the limit of PHP has to cover
     * where PHP counts clock time (see fit_to_time_limit()).
     *
     * @since 3.0.8
     */
    const CHECKSUM_TIMEOUT = 10;

    /**
     * Token of the scan this instance started, to tell its marker apart
     *
     * @var string
     */
    private $scan_token = '';

    /**
     * Limit of PHP for this request when it is below what a scan needs and
     * the server would not raise it, 0 otherwise
     *
     * @var int
     */
    private $php_limit = 0;

    /**
     * Seconds of processor time the scan may use, where that is what PHP
     * counts and the limit is short, 0 otherwise
     *
     * @var float
     */
    private $cpu_budget = 0;

    /**
     * Processor time of the process when the scan started, null when it
     * cannot be read
     *
     * @var float|null
     */
    private $cpu_at_start = null;

    /**
     * Whether the short limit of PHP is what stopped the scan
     *
     * @var bool
     */
    private $cut_by_php_limit = false;

    /**
     * What max_execution_time counts, when it is not the one of this
     * platform: only the release checks set it, to measure the other
     * platform's path (cpu or wall; empty to detect it)
     *
     * @var string
     */
    private static $limit_clock = '';

    /**
     * Processor time of the process when this file was loaded, which is
     * when the plugin loads (vigilante_load_plugin() on plugins_loaded):
     * the start of the request, give or take the boot of WordPress
     *
     * @var float|null
     */
    private static $cpu_at_load = null;

    /**
     * Largest file the search for hidden code reads, in bytes
     *
     * It used to be 512,000, and a larger file was not opened at all: in a
     * plugin with no official copy that left it out of the results as if it
     * were clean. There is still a cap because the file is read whole, but
     * what is above it is reported as not searched instead of being passed
     * over (see search_file()).
     */
    const MAX_SEARCHED_BYTES = 8388608;

    /**
     * Seconds a scan gives to the folders of wp-content that belong to nothing
     *
     * @var int
     */
    private $content_folders_time = 10;

    /**
     * Whether an expression of the search for hidden code gave up on the file
     * being searched (see found())
     *
     * @var bool
     */
    private $search_failed = false;

    /**
     * Option name for critical files baseline hashes.
     *
     * @var string
     */
    const BASELINE_OPTION = 'vigilante_critical_files_baseline';

    /**
     * Option that records which version last redacted the stored baseline.
     *
     * @since 2.11.2
     */
    const BASELINE_REDACTION_OPTION = 'vigilante_baseline_redaction';

    /**
     * Network option recording that the one-off sweep of per-site baselines ran.
     *
     * @since 2.11.3
     */
    const BASELINE_SWEEP_OPTION = 'vigilante_baseline_sweep';

    /**
     * The migration the sweep marker stands for.
     *
     * A literal, not VIGILANTE_VERSION, and the difference is the whole point.
     * 2.11.3 stored the running version, so every release after it rearmed the
     * sweep: the first dashboard load on the main site walked the network with
     * switch_to_blog() to find nothing, because there was nothing left to find,
     * for ever, at the price of the one walk the marker exists to avoid.
     *
     * A plain boolean would fix that too, and would also leave no way to fire a
     * second network sweep the day another migration needs one. A literal costs
     * nothing today and keeps that door open. The redaction marker keeps the
     * running version on purpose: there the point IS to run again when the list
     * of what has to be redacted grows, and the cost of reopening it is one
     * option read rather than a walk of the network.
     *
     * And it must be a value NO version ever wrote into this option. The first
     * draft used '2.11.3', which is precisely what 2.11.3 wrote there, as its
     * own VIGILANTE_VERSION and BEFORE starting the walk: out in the wild that
     * value means "started, maybe unfinished". Reading it as "finished" left
     * every network whose 2.11.3 walk was cut short unswept for good, subsites
     * still holding the database password and the eight keys. Reproduced on the
     * Multisite install by a third cross review. The price of the new value is
     * that networks that did finish in 2.11.3 walk once more and find nothing.
     *
     * @since 2.11.4
     */
    const BASELINE_SWEEP_MIGRATION = 'network-sweep-done';

    /**
     * Network option with the fingerprint of every block Vigilant itself wrote
     * into wp-config.php or the root .htaccess.
     *
     * The integrity scan leaves Vigilant's own blocks out of the hash, so that
     * rewriting them is not reported as somebody else's change. Until 2.11.5 it
     * left out whatever sat between the markers, without looking. From 2.11.5 a
     * block is left out only if its content is exactly what Vigilant wrote, as
     * recorded here at write time.
     *
     * @since 2.11.5
     */
    const OWNED_BLOCKS_OPTION = 'vigilante_owned_blocks';

    /**
     * Network option marking that the blocks already on disk have been claimed.
     *
     * @since 2.11.5
     */
    const OWNED_BLOCKS_CLAIM_OPTION = 'vigilante_owned_blocks_claim';

    /**
     * Value stored when the claim is done. Deliberately not a version number:
     * that is the lesson of BASELINE_SWEEP_MIGRATION above.
     *
     * @since 2.11.5
     */
    const OWNED_BLOCKS_CLAIMED = 'claimed';

    /**
     * What replaces a secret value kept in the baseline.
     *
     * Fixed forever: if this string ever changes, every stored baseline
     * suddenly differs from the freshly redacted file and every site reports a
     * change to wp-config.php that never happened.
     *
     * @since 2.11.2
     */
    const REDACTED_MARKER = '[redacted by Vigilant]';

    /**
     * Constant names whose value is checked even where the file does not name them
     *
     * The eight WordPress keys and salts and the database credentials. Until
     * 2.11.7 this list, plus names that read like a credential, was what got
     * redacted, and a real wp-config.php collects secrets under any name:
     * FTP_PASS, SMTP passwords, cloud keys inside serialize( array( ... ) ),
     * any const. Since 2.11.8 every value is redacted and this list only feeds
     * the output check of baseline_content().
     *
     * @since 2.11.2
     *
     * @var string[]
     */
    private static $secret_constants = array(
        'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST',
        'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
        'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
    );

    /**
     * Core constants whose value stays readable in the baseline copy
     *
     * Where the site lives, where its folders are, how much memory it gets:
     * none of it is a secret and all of it is what a diff of wp-config.php is
     * read for. Every other value is redacted. A list of what is secret can
     * never be complete, which is how 2.11.2 to 2.11.7 missed FTP_PASS; a list
     * of what is not can be short and still be right.
     *
     * @since 2.11.8
     *
     * @var string[]
     */
    private static $readable_constants = array(
        'ABSPATH', 'WPINC', 'WP_HOME', 'WP_SITEURL', 'WP_CONTENT_DIR', 'WP_CONTENT_URL',
        'WP_PLUGIN_DIR', 'WP_PLUGIN_URL', 'WPMU_PLUGIN_DIR', 'WPMU_PLUGIN_URL', 'UPLOADS',
        'WP_LANG_DIR', 'WP_TEMP_DIR', 'WP_DEBUG_LOG', 'WP_MEMORY_LIMIT', 'WP_MAX_MEMORY_LIMIT',
        'WP_ENVIRONMENT_TYPE', 'WP_DEVELOPMENT_MODE', 'WP_AUTO_UPDATE_CORE', 'FS_METHOD',
        'DB_CHARSET', 'DB_COLLATE', 'DOMAIN_CURRENT_SITE', 'PATH_CURRENT_SITE', 'NOBLOGREDIRECT',
        'COOKIE_DOMAIN', 'COOKIEPATH', 'SITECOOKIEPATH', 'ADMIN_COOKIE_PATH', 'PLUGINS_COOKIE_PATH',
        'WP_DEFAULT_THEME', 'WPLANG',
        // Numeric core settings. Since 2.11.10 a number in the value of a
        // define() is redacted like any other value, so the ones that are known
        // not to be credentials are listed here to keep the diff useful.
        'AUTOSAVE_INTERVAL', 'WP_POST_REVISIONS', 'EMPTY_TRASH_DAYS', 'WP_CRON_LOCK_TIMEOUT',
        'FS_CHMOD_DIR', 'FS_CHMOD_FILE', 'SITE_ID_CURRENT_SITE', 'BLOG_ID_CURRENT_SITE',
    );

    /**
     * Read the critical files baseline, from where it belongs
     *
     * Both watched files, wp-config.php and the root .htaccess, belong to the
     * whole network: there is one of each per installation, not one per site.
     * Keeping the baseline in a per-site option meant every site of a network
     * stored its own copy of the same wp-config.php, so a network of fifty
     * sites held fifty copies of the same credentials, and a cleanup that ran
     * on one site left the other forty nine untouched. Reported by @calzbert on
     * 10 sep 2026 and reproduced on the Multisite install. Since 2.11.3 there
     * is one baseline per network.
     *
     * No is_multisite() branch on purpose, and this is worth reading before
     * anyone adds one back: the core functions already make the distinction.
     * Verified in the installed core, wp-includes/option.php, where
     * get_network_option() falls back to get_option() on a single site and
     * update_network_option() falls back to update_option( $option, $value,
     * false ), autoload already off, which is exactly what this needs. Two
     * branches doing the same thing are two branches that can drift apart,
     * and one of them did during this very change.
     *
     * @since 2.11.3
     *
     * @return array
     */
    private function read_baseline() {
        $baseline = get_site_option( self::BASELINE_OPTION, array() );

        return is_array( $baseline ) ? $baseline : array();
    }

    /**
     * Store the critical files baseline where read_baseline() looks for it
     *
     * @since 2.11.3
     *
     * @param array $baseline Baseline to store.
     * @return bool
     */
    private function write_baseline( $baseline ) {
        return update_site_option( self::BASELINE_OPTION, $baseline );
    }

    /**
     * Fingerprint of a block exactly as the integrity scan reads it back
     *
     * @since 2.11.5
     *
     * @param string $block Block from start marker to end marker, inclusive.
     * @return string
     */
    private static function block_fingerprint( $block ) {
        return md5( str_replace( array( "\r\n", "\r" ), "\n", (string) $block ) );
    }

    /**
     * Record a block Vigilant has just written
     *
     * Called by the writers right after a verified write, so the scan can tell
     * Vigilant's block from anything else carrying the same markers. By default
     * it replaces the earlier record for that marker: after a write, only the
     * block just written is Vigilant's.
     *
     * @since 2.11.5
     *
     * @param string $filename     'wp-config.php' or '.htaccess'.
     * @param string $marker_start Start marker of the block.
     * @param string $block        Block from start marker to end marker, inclusive.
     * @param bool   $replace      Drop earlier records for the same marker first.
     * @return bool
     */
    public static function remember_owned_block( $filename, $marker_start, $block, $replace = true ) {
        $owned = get_site_option( self::OWNED_BLOCKS_OPTION, array() );
        $owned = is_array( $owned ) ? $owned : array();
        $file  = ( isset( $owned[ $filename ] ) && is_array( $owned[ $filename ] ) ) ? $owned[ $filename ] : array();

        if ( $replace ) {
            foreach ( $file as $fingerprint => $marker ) {
                if ( $marker === $marker_start ) {
                    unset( $file[ $fingerprint ] );
                }
            }
        }

        $file[ self::block_fingerprint( $block ) ] = $marker_start;
        $owned[ $filename ]                         = $file;

        return update_site_option( self::OWNED_BLOCKS_OPTION, $owned );
    }

    /**
     * Forget the blocks recorded for a marker, once Vigilant has removed them
     *
     * @since 2.11.5
     *
     * @param string $filename     'wp-config.php' or '.htaccess'.
     * @param string $marker_start Start marker of the block.
     * @return bool
     */
    public static function forget_owned_blocks( $filename, $marker_start ) {
        $owned = get_site_option( self::OWNED_BLOCKS_OPTION, array() );

        if ( ! is_array( $owned ) || empty( $owned[ $filename ] ) || ! is_array( $owned[ $filename ] ) ) {
            return true;
        }

        $changed = false;

        foreach ( $owned[ $filename ] as $fingerprint => $marker ) {
            if ( $marker === $marker_start ) {
                unset( $owned[ $filename ][ $fingerprint ] );
                $changed = true;
            }
        }

        return $changed ? update_site_option( self::OWNED_BLOCKS_OPTION, $owned ) : true;
    }

    /**
     * Whether a block is one Vigilant wrote
     *
     * @since 2.11.5
     *
     * @param string $filename 'wp-config.php' or '.htaccess'.
     * @param string $block    Block from start marker to end marker, inclusive.
     * @return bool
     */
    private static function is_owned_block( $filename, $block ) {
        $owned = get_site_option( self::OWNED_BLOCKS_OPTION, array() );

        return is_array( $owned )
            && isset( $owned[ $filename ] )
            && is_array( $owned[ $filename ] )
            && isset( $owned[ $filename ][ self::block_fingerprint( $block ) ] );
    }

    /**
     * Whether the blocks already on disk have been claimed
     *
     * @since 2.11.5
     *
     * @return bool
     */
    private function owned_blocks_claimed() {
        return self::OWNED_BLOCKS_CLAIMED === get_site_option( self::OWNED_BLOCKS_CLAIM_OPTION );
    }

    /**
     * The baseline copy of a critical file, with no secret in it
     *
     * The integrity scan keeps a copy of wp-config.php so it can show which
     * lines changed. Until 2.11.1 that copy was the file itself minus the
     * plugin's own blocks, so the options table held the database password and
     * the eight authentication keys and salts, and anybody who later read the
     * database or a backup of it got them without ever touching the
     * filesystem. Reported by the automated security review of wp.org on 9 sep
     * 2026 and fixed in 2.11.2.
     *
     * The hash is still taken over the whole file, so a change to a secret is
     * still detected; what changes is that the diff cannot show it, which is
     * the right trade.
     *
     * @since 2.11.2
     *
     * @param string $filename   Critical file name.
     * @param string $normalized Normalized content.
     * @return string Content safe to store, or '' when it cannot be made safe.
     */
    private function baseline_content( $filename, $normalized ) {
        if ( '.htaccess' === $filename ) {
            return $this->redact_server_secrets( $normalized );
        }

        if ( 'wp-config.php' !== $filename ) {
            return $normalized;
        }

        // Calculados una sola vez: los usa la redaccion (para no conservar un
        // numero que ademas este en vigor) y el control de salida de abajo.
        $live_values = $this->values_in_force( $normalized );
        $redacted    = $this->redact_secrets( $normalized, $live_values );

        /*
         * Belt and braces, and this is the part that matters: the redaction
         * above is the thing most likely to miss a shape nobody thought of,
         * and the cost of missing one is a secret in the database. So the
         * result is checked against the values actually in force, and if any
         * of them survived, nothing is stored at all. The scan then reports the
         * change without a line diff, which the interface already handles,
         * instead of leaking.
         *
         * Until 2.11.7 the check covered the twelve constants of WordPress and
         * nothing else, so a value the regular expression missed went straight
         * through it. It now covers every constant the file names and every
         * environment variable it reads.
         *
         * It runs against the copy that is actually stored. A value in force
         * that sits inside the value of a readable constant, such as a Redis
         * prefix equal to the domain inside WP_HOME, is not a secret left
         * behind, so that one alone is not looked for; without that, every such
         * site would lose its diff. The first version of this checked a
         * stricter copy instead, and a secret inside a kept include path went
         * straight past it (cross review of 2.11.8).
         *
         * Only values of eight characters or more are checked: DB_NAME is
         * often something like "local" or "wp", and looking for that inside a
         * PHP file matches by accident every time.
         */
        if ( '' === $redacted ) {
            return '';
        }

        $shown = $this->readable_values_in_force();

        foreach ( $live_values as $value ) {
            foreach ( $shown as $readable ) {
                if ( false !== strpos( $readable, $value ) ) {
                    continue 2;
                }
            }

            if ( false !== strpos( $redacted, $value ) ) {
                return '';
            }
        }

        return $redacted;
    }

    /**
     * Replace every value in wp-config.php with a marker
     *
     * Reads the file as PHP tokens and replaces every string in it: quoted,
     * with variables inside, heredoc and nowdoc. What stays is what names a
     * thing rather than holding it: the name passed to define(), defined(),
     * constant() and getenv(), the name in putenv( 'NAME=value' ), array keys,
     * an index such as $_ENV['NAME'], and strings of a single character that
     * are not the value of a define(). Also the value of the constants in
     * $readable_constants, the table prefix and a path passed to require or
     * include, which are not secrets and are what a diff of this file is read
     * for. A path is kept only while it looks like one, and only up to where
     * its expression ends.
     *
     * Until 2.11.7 this was a regular expression over define() with a list of
     * names, and it missed FTP_PASS, SMTP passwords, cloud keys inside
     * serialize( array( ... ) ), every const and every value read with a
     * fallback. Measured while preparing 2.11.8: 10 of 15 real shapes stored
     * their secret.
     *
     * The marker always goes in single quotes, whatever the original used, so
     * a copy redacted by an earlier version and the same file redacted today
     * read the same line for line.
     *
     * @since 2.11.2
     * @since 2.11.8 Reads tokens and redacts every value.
     *
     * @param string $content Normalized wp-config.php content.
     * @return string Redacted content, or '' when it cannot be read as tokens.
     */
    private function redact_secrets( $content, $live_values = array() ) {
        if ( ! function_exists( 'token_get_all' ) ) {
            return '';
        }

        $marker     = "'" . self::REDACTED_MARKER . "'";
        $tokens     = self::merged_tokens( token_get_all( (string) $content ) );
        $count      = count( $tokens );
        $names      = defined( 'T_NAME_FULLY_QUALIFIED' ) ? array( T_STRING, T_NAME_FULLY_QUALIFIED ) : array( T_STRING );
        $includes   = array( T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE );
        $out           = '';
        $depth         = 0;
        $keep_until    = -1;
        $define_at     = -1;
        $in_include    = false;
        $include_depth = 0;
        $include_ends  = array( T_CLOSE_TAG, T_BOOLEAN_OR, T_BOOLEAN_AND, T_LOGICAL_OR, T_LOGICAL_AND, T_COALESCE );

        for ( $i = 0; $i < $count; $i++ ) {
            list( $type, $text, $plain ) = $tokens[ $i ];

            if ( '(' === $type ) {
                $depth++;
            } elseif ( ')' === $type ) {
                // The closing parenthesis of a readable define(), or of any define().
                if ( $depth === $keep_until ) {
                    $keep_until = -1;
                }
                if ( $depth === $define_at ) {
                    $define_at = -1;
                }
                $depth--;

                // A parenthesis that closes around the include ends its path.
                if ( $in_include && $depth < $include_depth ) {
                    $in_include = false;
                }
            } elseif ( in_array( $type, $includes, true ) ) {
                $in_include    = true;
                $include_depth = $depth;
            } elseif ( $in_include && ( in_array( $type, array( ';', '{', '}', '?', ':', ',' ), true ) || in_array( $type, $include_ends, true ) ) ) {
                /*
                 * The path of an include ends where its expression does. The
                 * first version of this only ended it at ';', so the value in
                 * `( include 'db.php' ) || define( 'FTP_PASS', '...' )`, in a
                 * ternary after require, or after a closing tag, was kept.
                 * Found by the cross review of 2.11.8.
                 */
                $in_include = false;
            }

            if ( T_COMMENT === $type || T_DOC_COMMENT === $type ) {
                $out .= $this->redact_comment( $text );
                continue;
            }

            if ( T_INLINE_HTML === $type ) {
                $out .= ( '' === trim( $text ) ) ? $text : $marker;
                continue;
            }

            /*
             * A value that is not a quoted string is still a value. Until
             * 2.11.10 only string tokens were looked at, so
             * define( 'SERVICE_TOKEN', 12345678 ) put the live token in the copy
             * kept in the database. Reported by the wp.org automated review of
             * 2.11.9.
             *
             * The first fix here redacted a number only in the value position of
             * a define(), which is the shape that was reported and not the shape
             * of the problem. The second cross review of 2.11.10 measured nine
             * more: a negative number, one in parentheses, one inside
             * array( ... ), one in a ternary, a const, and four that are not
             * constants at all and so the output check cannot catch either, the
             * worst of them the documented way of configuring Redis,
             * $redis_server = array( 'auth' => 12345678 ). So a number is now
             * treated like a string: redacted unless the place it sits in is one
             * of the few that cannot hold a credential, which is how the rest of
             * this function has been written since 2.11.8 (a list of what may be
             * shown, never a list of what is secret).
             *
             * Losing a number from the diff costs little and buys the same trade
             * as everywhere else: the hash still covers the whole file, so a
             * change is detected even where the diff can no longer show it. The
             * numeric core settings are in $readable_constants so the diff of a
             * normal wp-config.php keeps saying what it used to.
             */
            if ( T_LNUMBER === $type || T_DNUMBER === $type ) {
                $nprev   = self::significant_token( $tokens, $i, -1 );
                $nnext   = self::significant_token( $tokens, $i, 1 );
                $nptype  = ( null === $nprev ) ? null : $tokens[ $nprev ][0];
                $nntype  = ( null === $nnext ) ? null : $tokens[ $nnext ][0];
                $nbefore = ( '[' === $nptype ) ? self::significant_token( $tokens, $nprev, -1 ) : null;
                $nbtoken = ( null === $nbefore ) ? array( null, null ) : $tokens[ $nbefore ];
                $nvalue  = ( -1 !== $define_at && $depth === $define_at && ',' === $nptype );

                $nkeep = $keep_until >= 0
                    || T_DOUBLE_ARROW === $nntype
                    || ( '[' === $nptype && ']' === $nntype && in_array( $nbtoken[0], array( T_VARIABLE, T_STRING, ']', ')', '}' ), true ) )
                    || ( strlen( $text ) <= 1 && ! $nvalue );

                /*
                 * Except when that same number is a value actually in force. The
                 * positions kept above are kept because a credential does not live
                 * in them, which is true, but it says nothing about the number
                 * itself: with
                 *   define( 'SERVICE_TOKEN', 12345678 );
                 *   $a = $config[12345678];
                 * the value was redacted in the define and kept in the index, so it
                 * survived, and the output check below did what it is there for and
                 * threw the whole copy away. No leak, but the diff of that
                 * wp-config.php was lost for good, which is the regression 2.11.8
                 * fixed, coming back through the numbers added in 2.11.10. Found by
                 * the third cross review.
                 *
                 * Strings are deliberately NOT treated this way: there, a value in
                 * force sitting in a kept position (an include path, an array key)
                 * can BE the secret, and losing the diff is the right answer. It is
                 * what poc/wpconfig-baseline-secretos.sh checks and it stays.
                 */
                if ( $nkeep && in_array( $text, $live_values, true ) ) {
                    $nkeep = false;
                }

                $out .= $nkeep ? $text : $marker;
                continue;
            }

            if ( 'string' !== $type ) {
                $out .= $text;
                continue;
            }

            $prev  = self::significant_token( $tokens, $i, -1 );
            $next  = self::significant_token( $tokens, $i, 1 );
            $ptype = ( null === $prev ) ? null : $tokens[ $prev ][0];
            $ntype = ( null === $next ) ? null : $tokens[ $next ][0];
            $call  = ( '(' === $ptype ) ? self::significant_token( $tokens, $prev, -1 ) : null;
            $inner = $plain ? substr( $text, 1, -1 ) : null;

            if ( $plain && null !== $call && in_array( $tokens[ $call ][0], $names, true ) ) {
                $function = strtolower( ltrim( $tokens[ $call ][1], '\\' ) );

                if ( in_array( $function, array( 'define', 'defined', 'constant', 'getenv' ), true ) ) {
                    if ( 'define' === $function ) {
                        $define_at = $depth;

                        if ( in_array( $inner, self::$readable_constants, true ) ) {
                            $keep_until = $depth;
                        }
                    }
                    $out .= $text;
                    continue;
                }

                if ( 'putenv' === $function && false !== strpos( $inner, '=' ) ) {
                    $out .= "'" . substr( $inner, 0, strpos( $inner, '=' ) + 1 ) . self::REDACTED_MARKER . "'";
                    continue;
                }
            }

            // The token before an opening bracket or an assignment, when there is one.
            $before = ( '[' === $ptype || '=' === $ptype ) ? self::significant_token( $tokens, $prev, -1 ) : null;
            $btoken = ( null === $before ) ? array( null, null ) : $tokens[ $before ];

            /*
             * The value of a define() is redacted whatever its length, as it was
             * up to 2.11.7, so an empty password reads the same in a copy stored
             * then as in today's; the first version of this kept strings of one
             * character there and a file awaiting review showed credential lines
             * nobody had touched (cross review of 2.11.8).
             */
            $is_define_value = ( -1 !== $define_at && $depth === $define_at && ',' === $ptype );
            $is_path         = $in_include && $plain
                && preg_match( '#^[A-Za-z0-9_./\-]+$#', (string) $inner )
                && ( false !== strpos( (string) $inner, '/' ) || '.php' === substr( (string) $inner, -4 ) );

            $keep = ( $plain && strlen( $inner ) <= 1 && ! $is_define_value )
                || T_DOUBLE_ARROW === $ntype
                || ( '[' === $ptype && ']' === $ntype && in_array( $btoken[0], array( T_VARIABLE, T_STRING, ']', ')', '}' ), true ) )
                || $keep_until >= 0
                || $is_path
                || ( '=' === $ptype && ';' === $ntype && T_VARIABLE === $btoken[0] && '$table_prefix' === $btoken[1] );

            $out .= $keep ? $text : $marker;
        }

        return $out;
    }

    /**
     * PHP tokens with every string folded into a single token
     *
     * The tokenizer splits a string with variables inside, a heredoc and a
     * backtick command into several tokens. For the redaction each of them is
     * one value, so they come back as a single token of type 'string'. The
     * third field says whether it is a plain quoted literal.
     *
     * @since 2.11.8
     *
     * @param array $raw Output of token_get_all().
     * @return array List of array( type, text, plain ).
     */
    private static function merged_tokens( $raw ) {
        $tokens = array();
        $count  = count( $raw );

        for ( $i = 0; $i < $count; $i++ ) {
            $token = $raw[ $i ];

            if ( '"' === $token || '`' === $token ) {
                $text = $token;
                for ( $i++; $i < $count; $i++ ) {
                    $text .= is_array( $raw[ $i ] ) ? $raw[ $i ][1] : $raw[ $i ];
                    if ( $raw[ $i ] === $token ) {
                        break;
                    }
                }
                $tokens[] = array( 'string', $text, false );
                continue;
            }

            if ( is_array( $token ) && T_START_HEREDOC === $token[0] ) {
                $text = $token[1];
                for ( $i++; $i < $count; $i++ ) {
                    $text .= is_array( $raw[ $i ] ) ? $raw[ $i ][1] : $raw[ $i ];
                    if ( is_array( $raw[ $i ] ) && T_END_HEREDOC === $raw[ $i ][0] ) {
                        break;
                    }
                }
                $tokens[] = array( 'string', $text, false );
                continue;
            }

            // An unterminated string comes back as T_ENCAPSED_AND_WHITESPACE
            // on its own, and it is a value like any other.
            if ( is_array( $token ) && ( T_CONSTANT_ENCAPSED_STRING === $token[0] || T_ENCAPSED_AND_WHITESPACE === $token[0] ) ) {
                $tokens[] = array( 'string', $token[1], T_CONSTANT_ENCAPSED_STRING === $token[0] );
                continue;
            }

            $tokens[] = is_array( $token ) ? array( $token[0], $token[1], false ) : array( $token, $token, false );
        }

        return $tokens;
    }

    /**
     * Index of the nearest token that is not whitespace or a comment
     *
     * @since 2.11.8
     *
     * @param array $tokens Output of merged_tokens().
     * @param int   $from   Index to start from, not included.
     * @param int   $step   -1 to look back, 1 to look ahead.
     * @return int|null
     */
    private static function significant_token( $tokens, $from, $step ) {
        $count = count( $tokens );

        for ( $i = $from + $step; $i >= 0 && $i < $count; $i += $step ) {
            if ( ! in_array( $tokens[ $i ][0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
                return $i;
            }
        }

        return null;
    }

    /**
     * Redact a comment, keeping its plain words
     *
     * To the tokenizer a comment is text, and wp-config.php files keep old
     * credentials in them, commented out or in a note. The first version of
     * this, in the same release, redacted what was between quotes: an
     * apostrophe in prose ("Don't use 'the-old-password'") paired with the
     * opening quote of the secret and left it out, and a secret without quotes
     * was never touched. Found by the cross review of 2.11.8.
     *
     * So it works the other way round. A comment keeps its plain words
     * (lowercase, capitalised or uppercase letters, or two capitalised parts
     * such as WordPress, and docblock tags), constant names, and anything
     * shorter than eight characters; every other run of characters, a URL, a
     * key, a password with a digit in it, becomes the marker. The value of a
     * commented-out define() goes in single quotes whatever its length, as in
     * code and as 2.11.2 to 2.11.7 wrote it, so a copy stored by those
     * versions reads the same line for line. What this cannot tell from prose
     * is a password made only of plain letters; the output check still
     * catches it when it is a value in force.
     *
     * @since 2.11.8
     *
     * @param string $comment Comment token text.
     * @return string
     */
    private function redact_comment( $comment ) {
        $marker   = self::REDACTED_MARKER;
        $readable = self::$readable_constants;

        // Only the text between the delimiters is redacted: "/**#@-*/" in
        // wp-config-sample.php is a single run of eight characters, and
        // replacing it whole took the comment markers with it.
        if ( ! preg_match( '#\A(/\*\*?|//|\#)(.*?)(\*/)?\z#s', $comment, $parts ) ) {
            $parts = array( $comment, '', $comment );
        }

        $open    = $parts[1];
        $close   = isset( $parts[3] ) ? $parts[3] : '';
        $comment = preg_replace_callback(
            '/(\bdefine\s*\(\s*([\'"])((?:\\\\.|(?!\2).)*)\2\s*,\s*)([\'"])((?:\\\\.|(?!\4).)*)\4/i',
            function ( $match ) use ( $marker, $readable ) {
                return in_array( $match[3], $readable, true ) ? $match[0] : $match[1] . "'" . $marker . "'";
            },
            $parts[2]
        );

        if ( null === $comment ) {
            return '';
        }

        $redacted = preg_replace_callback(
            '/[^\s\'"`(),;\[\]{}<>=]+/u',
            function ( $match ) use ( $marker ) {
                $word = $match[0];
                $core = rtrim( $word, '.:!?' );

                // Plain words only, without hyphens: a passphrase written as
                // lowercase words joined by hyphens reads as prose otherwise, and
                // the PoC of this very fix caught one surviving.
                if ( strlen( $core ) < 8
                    || preg_match( '/^@?(?:\p{Lu}?\p{Ll}+|\p{Lu}+)$/u', $core )
                    || preg_match( '/^\p{Lu}\p{Ll}+\p{Lu}\p{Ll}+$/u', $core )
                    || preg_match( '/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/', $core )
                ) {
                    return $word;
                }

                return $marker . substr( $word, strlen( $core ) );
            },
            $comment
        );

        // A failed replacement, on invalid UTF-8 for one, drops the comment
        // rather than keep it whole.
        return ( null === $redacted ) ? '' : $open . $redacted . $close;
    }

    /**
     * Values in force of what a wp-config.php names
     *
     * Every user constant whose name appears in the file, the twelve of
     * WordPress wherever they were defined, and the environment variables the
     * file reads or sets. Arrays are walked to their leaves, since define()
     * takes arrays. Strings and numbers both: the first version of this counted
     * numbers and wiped the diff of any file with a large number in force (cross
     * review of 2.11.8), so they were dropped, and 2.11.10 had to bring them
     * back because a credential written as a number, which the wp.org review of
     * 2.11.9 reported, is exactly what this check has to be able to see. The
     * eight character floor is what keeps the old problem away. The readable
     * constants are left out, and so is anything shorter than that.
     *
     * @since 2.11.8
     *
     * @param string $content Normalized wp-config.php content.
     * @return string[]
     */
    private function values_in_force( $content ) {
        $defined = get_defined_constants( true );
        $user    = isset( $defined['user'] ) ? $defined['user'] : array();
        $names   = self::$secret_constants;
        $values  = array();

        if ( preg_match_all( '/[A-Za-z_][A-Za-z0-9_]*/', (string) $content, $words ) ) {
            $names = array_merge( $names, $words[0] );
        }

        foreach ( array_unique( $names ) as $name ) {
            if ( array_key_exists( $name, $user ) && ! in_array( $name, self::$readable_constants, true ) ) {
                $values = array_merge( $values, self::string_leaves( $user[ $name ] ) );
            }
        }

        if ( preg_match_all( '/\b(?:getenv|putenv)\s*\(\s*[\'"]([A-Za-z_][A-Za-z0-9_]*)|\$_ENV\s*\[\s*[\'"]([A-Za-z_][A-Za-z0-9_]*)/', (string) $content, $env ) ) {
            foreach ( array_filter( array_merge( $env[1], $env[2] ) ) as $name ) {
                $value = getenv( $name );

                if ( is_string( $value ) ) {
                    $values[] = $value;
                }
            }
        }

        $long = array();

        foreach ( $values as $value ) {
            if ( strlen( $value ) >= 8 ) {
                $long[ $value ] = $value;
            }
        }

        return array_values( $long );
    }

    /**
     * Every string inside a constant value
     *
     * @since 2.11.8
     *
     * @param mixed $value Constant value.
     * @return string[]
     */
    private static function string_leaves( $value ) {
        if ( is_array( $value ) ) {
            $leaves = array();

            foreach ( $value as $item ) {
                $leaves = array_merge( $leaves, self::string_leaves( $item ) );
            }

            return $leaves;
        }

        if ( is_string( $value ) ) {
            return array( $value );
        }

        /*
         * A number is a value too. Until 2.11.10 this returned nothing for one,
         * so the output check had no way to see a credential written as
         * define( 'SERVICE_TOKEN', 12345678 ) and the redaction was left without
         * its safety net there. Booleans and null stay out on purpose: as text
         * they are '1' and '', which would match half the file.
         */
        return ( is_int( $value ) || is_float( $value ) ) ? array( (string) $value ) : array();
    }

    /**
     * Values in force of the readable constants, the ones kept in the copy
     *
     * @since 2.11.8
     *
     * @return string[]
     */
    private function readable_values_in_force() {
        $values = array();

        foreach ( self::$readable_constants as $name ) {
            if ( defined( $name ) ) {
                $values = array_merge( $values, self::string_leaves( constant( $name ) ) );
            }
        }

        return $values;
    }

    /**
     * Replace the values a root .htaccess can carry as credentials
     *
     * The .htaccess is not a secrets file, but it can hold a few: an
     * environment variable handed to PHP with SetEnv, an Authorization header
     * set for a backend, or a php_value with a password, a key, a licence or a
     * session store address with its auth in it. The directive and its name
     * stay, the value goes. Line based, which is how Apache reads it too. Since
     * the cross review of 2.11.8 also any request or response header whose name
     * reads like a credential (X-Api-Key, a cookie, a signature) and a
     * RewriteCond that compares against key=, token= or the like, the way a
     * staging site is opened with a secret in the query string. What it cannot
     * see is a credential written in any other shape.
     *
     * @since 2.11.8
     *
     * @param string $content Normalized .htaccess content.
     * @return string
     */
    private function redact_server_secrets( $content ) {
        $redacted = preg_replace(
            array(
                '/^([ \t]*SetEnv[ \t]+\S+[ \t]+)\S.*$/mi',
                '/^([ \t]*(?:RequestHeader|Header)[ \t]+(?:always[ \t]+)?\S+[ \t]+[\w-]*(?:auth|key|token|secret|pass|cookie|sig)[\w-]*[ \t]+)\S.*$/mi',
                '/^([ \t]*php_(?:admin_)?value[ \t]+\S*(?:pass|pw|secret|key|token|licen|auth|save_path)\S*[ \t]+)\S.*$/mi',
                '/^([ \t]*RewriteCond[ \t]+\S+[ \t]+)\S*(?:key|token|secret|pass|auth|sig)[\w-]*=\S*/mi',
            ),
            '${1}' . self::REDACTED_MARKER,
            (string) $content
        );

        return ( null === $redacted ) ? '' : $redacted;
    }

    /**
     * Promote a per-site baseline to the network record before dropping it
     *
     * Up to 2.11.2 the baseline was a per-site option, so on a network every
     * site kept its own copy of the same two files. Those copies go, but what a
     * copy records is which version of the file the owner approved, and that
     * has to survive: rebuilding the baseline from disk would take whatever is
     * there right now as approved, so a wp-config.php modified and still
     * awaiting review would be blessed in silence.
     *
     * WHICH copy becomes the network record is not a detail, and 2.11.3 got it
     * wrong. This runs from the scan, under wp-cron, on whichever site gets
     * traffic first, and the sweep from the main site can be hours away because
     * it waits for a network administrator to open a dashboard. So on a network
     * with traffic spread around, the record of the whole installation was
     * whatever the first subsite to scan happened to hold.
     *
     * That is harmless while every copy agrees, which is the ordinary case. The
     * reason they can disagree is the very thing 2.11.3 fixed: until then,
     * approving a change to wp-config.php took manage_options, which on a
     * network the administrator of every subsite holds. If a change was
     * approved on some subsite while the main site still had it pending review,
     * promoting that subsite's copy retires a warning nobody decided to retire.
     *
     * Hence the order, file by file: what the network record already holds
     * wins, then the main site, then the site this runs on. Between the copies,
     * the main site beats a subsite, which is @calzbert's point, reported after
     * reading the 2.11.3 diff.
     *
     * What this does NOT protect, said plainly because an earlier wording
     * claimed more: if the network record already holds a file, that entry
     * wins, even when it was written from disk by the .htaccess writer on
     * init:20 while a third-party edit was pending review. What survives is a
     * file the network record does not hold yet, which is the wp-config.php
     * case that 2.11.3 lost. The .htaccess case is pre-existing and needs the
     * writers to pass their before-hash, see update_critical_file_baseline().
     *
     * @since 2.11.4
     *
     * @param array|null $per_site Baseline stored for the site this runs on.
     * @return bool True when the network record covers everything the per-site
     *              copy had, which is the only case where dropping it is safe.
     */
    private function promote_per_site_baseline( $per_site ) {
        $network = get_site_option( self::BASELINE_OPTION, array() );

        if ( ! is_array( $network ) ) {
            $network = array();
        }

        /*
         * Three sources, filled in one from another, file by file. It used to
         * be all or nothing: if the network record existed at all, this
         * returned at once and the caller dropped the per-site copy anyway.
         *
         * That looked safe and was not, because the network record can be born
         * holding ONE of the two files. maybe_sync_server_files() runs on init
         * and rewrites the root .htaccess by itself, and the writer calls
         * update_critical_file_baseline( '.htaccess' ), which creates the
         * network option with that single entry. init runs before admin_init,
         * so on a network on Apache this is the ordinary order of an update,
         * not a race: the cleanup then found the option "already there", kept
         * nothing, and deleted the per-site copies that held the approved
         * record of wp-config.php. The next scan met a file it had never seen
         * and stored whatever was on disk as approved, which is the silent
         * blessing this whole function exists to prevent. Reproduced on the
         * Multisite install on 10 sep 2026, found by a cross review.
         *
         * Order of authority: what the network already says wins, then the main
         * site, then the site this runs on. Nothing is ever overwritten and
         * nothing is dropped for being late.
         */
        $sources = array( $network );

        if ( ! is_main_site() ) {
            $from_main = get_blog_option( get_main_site_id(), self::BASELINE_OPTION, null );

            if ( is_array( $from_main ) ) {
                $sources[] = $from_main;
            }
        }

        if ( is_array( $per_site ) ) {
            $sources[] = $per_site;
        }

        $merged = array();

        foreach ( $sources as $source ) {
            foreach ( $source as $filename => $data ) {
                if ( isset( $merged[ $filename ] ) || ! is_array( $data ) || ! isset( $data['hash'] ) ) {
                    continue;
                }

                // Only the content carries secrets; the hash and the size,
                // which are what say "this is the version that was approved",
                // go over untouched.
                if ( isset( $data['content'] ) && is_string( $data['content'] ) ) {
                    $data['content'] = $this->baseline_content( $filename, $data['content'] );
                }

                $merged[ $filename ] = $data;
            }
        }

        if ( array_diff_key( $merged, $network ) ) {
            $this->write_baseline( $merged );
        }

        if ( ! is_array( $per_site ) ) {
            return true;
        }

        /*
         * Is every file this copy had a record of now on the network record?
         * Only then may the caller drop it. And the question is asked of what
         * is STORED, not of $merged, which is only what this request MEANT to
         * store. Asking $merged makes the answer true by construction, because
         * the copy is one of the sources above, so the guard could never fire
         * and redact_in_place() in the caller was unreachable code.
         *
         * The write does not always land, and the case that matters is not a
         * broken database, it is the same race as the bug this function fixes.
         * On a network updating from 2.11.2 the network option does not exist
         * yet, so update_network_option() takes the $old_value === false branch
         * and delegates to add_network_option() (wp-includes/option.php:2434).
         * If another request created the option in between, that call either
         * returns false without writing (option.php:2201) or, when this process
         * still holds "does not exist" in its own notoptions cache, skips the
         * check and INSERTs a second row: wp_sitemeta has no unique index on
         * meta_key, so the record ends up duplicated and get_network_option()
         * hands back whichever row comes first. Reproduced on the Multisite
         * install on 10 sep 2026, with the .htaccess writer of init:20 racing a
         * promotion: two rows, the approved hash of wp-config.php out of reach,
         * and the per-site copy deleted all the same. Found by a cross review.
         *
         * Both cache keys go before rereading, and that is not belt and braces.
         * add_network_option() caches the value it believes it wrote
         * (option.php:2221), so a plain read hands back the very array that did
         * not survive; and a stale notoptions would answer "no such option"
         * without touching the database, which reads as "nothing is covered".
         * Measured: without dropping the cache this guard still returns true.
         */
        $network_id = get_current_network_id();
        wp_cache_delete( $network_id . ':' . self::BASELINE_OPTION, 'site-options' );
        wp_cache_delete( $network_id . ':notoptions', 'site-options' );

        $stored = get_site_option( self::BASELINE_OPTION, array() );

        if ( ! is_array( $stored ) ) {
            return false;
        }

        foreach ( $per_site as $filename => $data ) {
            if ( is_array( $data ) && isset( $data['hash'] ) && ! isset( $stored[ $filename ] ) ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Strip the secrets from a per-site copy that cannot be dropped yet
     *
     * The copy stays because it holds the only record of an approved file, but
     * what it must not keep for one more minute is the database password and
     * the eight keys and salts. The two things are separable and this is where
     * they get separated.
     *
     * @since 2.11.4
     *
     * @param array $per_site Baseline stored for the current site.
     * @return void
     */
    private function redact_in_place( $per_site ) {
        $changed = false;

        foreach ( $per_site as $filename => $data ) {
            if ( ! is_array( $data ) || ! isset( $data['content'] ) || ! is_string( $data['content'] ) ) {
                continue;
            }

            $safe = $this->baseline_content( $filename, $data['content'] );

            if ( $safe !== $data['content'] ) {
                $per_site[ $filename ]['content'] = $safe;
                $changed = true;
            }
        }

        if ( $changed ) {
            update_option( self::BASELINE_OPTION, $per_site );
        }
    }

    /**
     * Network option recording the version whose results cleanup walked the network
     *
     * @since 2.11.8
     */
    const RESULTS_SWEEP_OPTION = 'vigilante_results_sweep';

    /**
     * Clean the stored scan results of every site of the network, once per version
     *
     * redact_stored_results() runs per site from admin_init and from the scan,
     * so a subsite with the module off whose dashboard nobody opens kept the
     * lines of wp-config.php its last scan stored, with whatever that version
     * failed to redact. Same gap 2.11.3 and 2.11.4 closed for the baseline copy;
     * found for the results by the cross review of 2.11.8. It runs from the
     * network sweep, for a network administrator on the main site, and has its
     * own marker because the baseline sweep is already done on every network
     * that updated through 2.11.4.
     *
     * @since 2.11.8
     */
    private function maybe_sweep_network_results() {
        if ( VIGILANTE_VERSION === get_site_option( self::RESULTS_SWEEP_OPTION ) ) {
            return;
        }

        update_site_option( self::RESULTS_SWEEP_OPTION, VIGILANTE_VERSION );

        $site_ids = get_sites(
            array(
                'fields'                 => 'ids',
                'number'                 => 0,
                'network_id'             => get_current_network_id(),
                'update_site_meta_cache' => false,
            )
        );

        foreach ( $site_ids as $site_id ) {
            switch_to_blog( $site_id );
            $this->redact_stored_results();
            restore_current_blog();
        }
    }

    /**
     * The diff of a shared file as a site that does not own it gets it
     *
     * No lines, and a flag the screens read to say where the lines are.
     *
     * @since 2.11.8
     *
     * @return array
     */
    public static function network_only_diff() {
        return array(
            'added'       => array(),
            'removed'     => array(),
            'unavailable' => true,
            'network'     => true,
        );
    }

    /**
     * Take out of the last stored scan what the baseline copy no longer keeps
     *
     * The results of the last scan are an option of each site, and the diff of
     * a critical file travels inside them line by line, redacted the way the
     * version that ran the scan redacted. Until 2.11.7 that let FTP_PASS and
     * friends through, and on a network every subsite with the module on kept
     * its own copy of the lines. This runs once per version with the rest of
     * the cleanup:
     *
     * - Where the shared files do not belong to this site, no line is kept.
     * - Lines of wp-config.php are dropped. A single line cannot be read as
     *   PHP reliably (half a heredoc is just words), and the next scan rebuilds
     *   them from the whole file.
     * - Lines of .htaccess are directives, one per line, and are redacted in
     *   place.
     *
     * @since 2.11.8
     */
    private function redact_stored_results() {
        $results = get_option( 'vigilante_last_integrity_results' );

        if ( ! is_array( $results ) || empty( $results['modified'] ) || ! is_array( $results['modified'] ) ) {
            return;
        }

        $owns    = Vigilante_Settings::owns_shared_files();
        $changed = false;

        foreach ( $results['modified'] as $index => $item ) {
            if ( ! is_array( $item ) || 'critical_config' !== ( $item['type'] ?? '' ) || ! isset( $item['diff'] ) || ! is_array( $item['diff'] ) ) {
                continue;
            }

            if ( ! $owns ) {
                if ( empty( $item['diff']['network'] ) ) {
                    $results['modified'][ $index ]['diff'] = self::network_only_diff();
                    $changed = true;
                }
                continue;
            }

            if ( 'wp-config.php' === ( $item['file'] ?? '' ) ) {
                if ( ! empty( $item['diff']['added'] ) || ! empty( $item['diff']['removed'] ) ) {
                    $results['modified'][ $index ]['diff'] = array(
                        'added'       => array(),
                        'removed'     => array(),
                        'unavailable' => true,
                        'rescan'      => true,
                    );
                    $changed = true;
                }
                continue;
            }

            foreach ( array( 'added', 'removed' ) as $side ) {
                if ( empty( $item['diff'][ $side ] ) || ! is_array( $item['diff'][ $side ] ) ) {
                    continue;
                }

                foreach ( $item['diff'][ $side ] as $line_index => $line ) {
                    if ( ! is_array( $line ) || ! isset( $line['content'] ) || ! is_string( $line['content'] ) ) {
                        continue;
                    }

                    $safe = $this->redact_server_secrets( $line['content'] );

                    if ( $safe !== $line['content'] ) {
                        $results['modified'][ $index ]['diff'][ $side ][ $line_index ]['content'] = $safe;
                        $changed = true;
                    }
                }
            }
        }

        if ( $changed ) {
            update_option( 'vigilante_last_integrity_results', $results );
        }
    }

    /**
     * Clean up what earlier versions stored, wherever they stored it
     *
     * Two jobs, and the second one only exists on a network.
     *
     * The first: versions up to 2.11.1 kept the contents of wp-config.php in
     * the baseline, credentials included, so what is already on disk is
     * redacted in place.
     *
     * The second: up to 2.11.2 that baseline was a per-site option, so on a
     * network every site had its own copy of the same file. This runs per site
     * and removes that copy, because the baseline now lives in a single
     * network option. Doing it here is what makes the cleanup reach a site
     * whose dashboard nobody ever opens: this method is called from the scan
     * as well as from admin_init, and the scan runs on every site through
     * wp-cron with front-end traffic alone.
     *
     * The gate option stays per site on purpose. It records that THIS site has
     * been cleaned, which is exactly the per-site fact being tracked.
     *
     * @since 2.11.2
     */
    public function maybe_redact_stored_baseline() {
        if ( VIGILANTE_VERSION === get_option( self::BASELINE_REDACTION_OPTION ) ) {
            return;
        }

        /*
         * The per-site copy left behind by 2.11.2 and earlier. On a network it
         * holds the database password and the eight keys and salts, so it goes,
         * but never before what it records has been carried over:
         * promote_per_site_baseline() explains why the record has to outlive
         * the copy, and which copy wins when they disagree. Measured on the
         * Multisite install while writing 2.11.3: without that, the first scan
         * after the migration reported zero modified files where it had to
         * report one.
         */
        $pending = false;

        if ( is_multisite() ) {
            $per_site = get_option( self::BASELINE_OPTION, null );

            if ( null !== $per_site ) {
                if ( $this->promote_per_site_baseline( $per_site ) ) {
                    delete_option( self::BASELINE_OPTION );
                } elseif ( is_array( $per_site ) ) {
                    // Something this copy recorded is not on the network record
                    // yet, so it does not go: it is the only evidence of what
                    // was approved. The secrets do go, right now, because that
                    // part cannot wait for the next pass.
                    $this->redact_in_place( $per_site );
                    $pending = true;
                }
            }
        }

        $baseline = $this->read_baseline();

        if ( is_array( $baseline ) ) {
            $changed = false;

            foreach ( $baseline as $filename => $data ) {
                if ( ! is_array( $data ) || ! isset( $data['content'] ) || ! is_string( $data['content'] ) ) {
                    continue;
                }

                $safe = $this->baseline_content( $filename, $data['content'] );

                if ( $safe !== $data['content'] ) {
                    $baseline[ $filename ]['content'] = $safe;
                    $changed = true;
                }
            }

            if ( $changed ) {
                $this->write_baseline( $baseline );
            }
        }

        $this->redact_stored_results();

        /*
         * The gate does not close while a per-site copy is still waiting to be
         * promoted. Closing it would end the retries for a whole version: the
         * copy would sit there unread, the file it records would be missing
         * from the network record, and the next scan would take whatever is on
         * disk as approved. Not closing it is not free, though, and the first
         * wording here said "one option read": measured cold on the Multisite
         * install, it is 6 SQL queries per admin request against 0 with the gate
         * closed, admin-ajax.php and the heartbeat included, two of them from the
         * cache invalidation in promote_per_site_baseline(). Acceptable only
         * because it converges: the stuck case this guards against resolves on
         * the next pass that gets its write through.
         */
        if ( ! $pending ) {
            update_option( self::BASELINE_REDACTION_OPTION, VIGILANTE_VERSION, false );
        }
    }

    /**
     * Sweep the whole network once, so it does not wait for each site's cron
     *
     * The per-site cleanup above reaches a site when that site runs a scan or
     * someone opens its dashboard, which on a quiet subsite can take a while.
     * This walks every site once and gets it over with, and its marker is a
     * network option so it does not repeat per site.
     *
     * Runs only on the main site of the network, where a network administrator
     * works, and only there does it cost anything.
     *
     * @since 2.11.3
     */
    public function maybe_sweep_network_baselines() {
        if ( ! is_multisite() || ! is_main_site() ) {
            return;
        }

        /*
         * A network administrator, and nobody else. admin_init fires for any
         * logged-in visitor, a subscriber opening their own profile included,
         * and this walks every site of the network writing to each one. What it
         * removes is stale data that rebuilds itself, so the harm is small, but
         * an action over the whole network belongs to whoever administers the
         * network. The surface inventory cannot see this: it reads wp_ajax_*,
         * admin_post_* and REST routes, and a hook on admin_init is outside its
         * coverage by construction, which is exactly the blind spot written
         * down as rule 23.
         *
         * The per-site cleanup is deliberately not gated the same way: it also
         * runs from the scan, under wp-cron with no user at all, and it only
         * touches the site it runs on.
         */
        if ( ! current_user_can( 'manage_network_options' ) ) {
            return;
        }

        $this->maybe_sweep_network_results();

        $marker = get_site_option( self::BASELINE_SWEEP_OPTION );

        /*
         * Two markers, because there are two different things to remember and
         * 2.11.3 only remembered one of them.
         *
         * The walk is marked BEFORE it starts, on purpose: on a very large
         * network it may not finish inside one request, and repeating it on
         * every admin page load would be worse than leaving the rest to each
         * site's own scan. But 2.11.3 wrote VIGILANTE_VERSION there, so an
         * interrupted walk was retried by the next release, which was the only
         * thing that ever finished it. Writing a fixed literal instead, as the
         * first draft of 2.11.4 did, stopped the pointless rearming and took
         * that retry away with it: a walk cut short would never be resumed by
         * any version. And "each site's own scan cleans the rest" only holds
         * where the module is on; with it off, the cleanup is registered under
         * is_admin() alone, so a subsite nobody opens is exactly what the sweep
         * exists for. Found by a cross review on 10 sep 2026.
         *
         * So: the running version means "started here and did not finish", and
         * the migration literal means "finished, never again".
         */
        if ( self::BASELINE_SWEEP_MIGRATION === $marker ) {
            return;
        }

        if ( VIGILANTE_VERSION === $marker ) {
            return;
        }

        update_site_option( self::BASELINE_SWEEP_OPTION, VIGILANTE_VERSION );

        // Only this network. WP_Site_Query filters by network solely when
        // network_id is given, so on a multi-network install the walk would
        // otherwise reach the sites of other networks and promote their copies
        // into this network's record (get_current_network_id() below does not
        // change with switch_to_blog()).
        $site_ids = get_sites(
            array(
                'fields'                 => 'ids',
                'number'                 => 0,
                'network_id'             => get_current_network_id(),
                'update_site_meta_cache' => false,
            )
        );

        $pending = 0;

        foreach ( $site_ids as $site_id ) {
            switch_to_blog( $site_id );

            $per_site = get_option( self::BASELINE_OPTION, null );

            if ( null !== $per_site ) {
                // Same care as the per-site cleanup, and the same helper, so
                // the two paths cannot drift apart the way they nearly did.
                if ( $this->promote_per_site_baseline( $per_site ) ) {
                    delete_option( self::BASELINE_OPTION );
                } elseif ( is_array( $per_site ) ) {
                    $this->redact_in_place( $per_site );
                    $pending++;
                }
            }

            restore_current_blog();
        }

        // Finished, and with nothing left behind, so it never has to run again
        // in any version. A site whose copy could not be promoted keeps the
        // marker on the running version instead, which is what gets the walk
        // retried by the next release.
        if ( ! $pending ) {
            update_site_option( self::BASELINE_SWEEP_OPTION, self::BASELINE_SWEEP_MIGRATION );
        }
    }

    /**
     * Critical root files to monitor against a stored baseline.
     * These files have no official WordPress.org checksum because their
     * content is unique per installation.
     *
     * @var array
     */
    private $critical_root_files = array(
        'wp-config.php',
        '.htaccess',
    );

    /**
     * Vigilante markers used in wp-config.php (constants block).
     *
     * @var array
     */
    private $wpconfig_markers = array(
        array( '/* BEGIN Vigilante Security Constants */', '/* END Vigilante Security Constants */' ),
        array( '/* BEGIN AyudaWP Security Constants */', '/* END AyudaWP Security Constants */' ),
    );

    /**
     * Vigilante marker for commented-out original constants in wp-config.php.
     *
     * @var string
     */
    private $wpconfig_original_marker = '// [VIGILANTE_ORIGINAL] ';

    /**
     * Vigilante markers used in .htaccess (firewall, security headers and Under Attack).
     *
     * Under Attack writes its cache block at the top of .htaccess while the
     * mode is on. Until 3.0.6 it was missing here, so switching the mode on or
     * off read as a change to .htaccess in the next scan (A6 of the list of
     * 3 Oct 2026). Its block is left out of the hash like the others: only
     * while its fingerprint is the one the htaccess manager recorded when it
     * wrote it.
     *
     * @var array
     */
    private $htaccess_markers = array(
        array( '# BEGIN Vigilante Protection', '# END Vigilante Protection' ),
        array( '# BEGIN Vigilante Security Headers', '# END Vigilante Security Headers' ),
        array( '# BEGIN Vigilante Under Attack', '# END Vigilante Under Attack' ),
    );

    /**
     * Whether the core is being compared with the English checksums because
     * WordPress.org has none for the language of the site. Set by
     * get_core_checksums().
     *
     * @var bool
     */
    private $core_checksums_are_english = false;

    /**
     * Core files known to produce false positives in checksum comparison.
     * These are skipped during core scanning: the readme and the license vary
     * by locale and are not code. version.php used to be here too, and is now
     * compared (see matches_core_of_other_locale()).
     *
     * @var array
     */
    private $core_known_false_positives = array(
        'readme.html',
        'license.txt',
        'licencia.txt',
    );

    /**
     * Plugin files known to produce false positives in checksum comparison.
     * Readme files frequently differ between WordPress.org API checksums and
     * the actual installed version due to encoding, line endings, or locale.
     *
     * @var array
     */
    private $plugin_known_false_positives = array(
        'readme.txt',
        'readme.md',
    );

    /**
     * Legitimate non-PHP files commonly found in WordPress root.
     * These are reported as 'additional' (informational), not suspicious.
     * Dotfiles (e.g. .htaccess) are skipped entirely by the root scanner.
     *
     * @var array
     */
    private $known_safe_root_files = array(
        'robots.txt',
        'security.txt',
        'humans.txt',
        'llms.txt',
        'llms-full.txt',
        'ads.txt',
        'app-ads.txt',
        'favicon.ico',
        'favicon.png',
        'favicon.svg',
        'apple-touch-icon.png',
        'apple-touch-icon-precomposed.png',
        'sitemap.xml',
        'sitemap_index.xml',
        'bingsiteauth.xml',
        'livesearchsiteauth.xml',
        'google-site-verification.html',
        'php.ini',
        // PHP error logs commonly created by managed hosting (SiteGround, Hostinger, cPanel).
        // Not executable; reported as "additional" instead of "suspicious".
        'php_errorlog',
        'error_log',
    );

    /**
     * Legacy WordPress core files removed from newer versions but kept on
     * existing installs to prevent breakage. These are dead code, not malware.
     * Marked as 'extra' (additional) instead of 'suspicious' with advice to delete.
     *
     * @see https://core.trac.wordpress.org/ticket/48540
     * @see https://core.trac.wordpress.org/ticket/18384
     * @var array
     */
    private $legacy_core_root_files = array(
        'wp-feed.php',
        'wp-rss.php',
        'wp-rss2.php',
        'wp-rdf.php',
        'wp-atom.php',
        'wp-commentsrss2.php',
        'wp-pass.php',
        'wp-register.php',
    );

    /**
     * Constructor
     *
     * @param Vigilante_Settings          $settings     Settings instance.
     * @param Vigilante_Database|null     $database     Database instance.
     * @param Vigilante_Activity_Log|null $activity_log Activity log instance.
     */
    public function __construct( $settings, $database = null, $activity_log = null ) {
        $this->settings      = $settings;
        $this->database      = $database;
        $this->activity_log  = $activity_log;
        $this->options       = $settings ? $settings->get_section( 'file_integrity' ) : array();
        $this->wp_version    = get_bloginfo( 'version' );
        $this->ignored_files = get_option( 'vigilante_ignored_files', array() );
    }

    /**
     * Register the hooks of the scanner itself
     *
     * Until 2.11.4 all of this lived in the constructor, and the constructor is
     * called from a dozen places: the module gate, the activator, the hook that
     * runs after Vigilant writes a watched file, and the admin handlers that
     * only want the class as a tool. Every
     * one of them registered these hooks again, and one runs during admin_init
     * itself. Registering apart from constructing means a `new` is only a
     * `new`, and it is what lets the cleanup below stand on its own.
     *
     * @since 2.11.4
     */
    public function init_hooks() {
        // Schedule automated scans only if options available
        if ( ! empty( $this->options['auto_scan'] ) ) {
            add_action( 'vigilante_file_integrity_scan', array( $this, 'run_scheduled_scan' ) );
            $this->schedule_scan();
        }

        // Post-update verification: verify any just-updated plugin/theme against
        // WordPress.org immediately, and open a short grace window so the
        // scheduled scan does not raise false positives while wp.org is still
        // publishing the new version's checksums. Registered regardless of
        // auto_scan because it reacts to update events, not to the schedule.
        add_action( 'upgrader_process_complete', array( $this, 'on_upgrade_complete' ), 20, 2 );
        add_action( 'vigilante_fi_postupdate_verify', array( $this, 'run_postupdate_verify' ) );
    }

    /**
     * Register the cleanup of what earlier versions stored, module on or off
     *
     * These two are not integrity monitoring. They take out of the database
     * something the plugin stored and should not have, which is the copy of
     * wp-config.php carrying the database password and the eight keys and
     * salts. Whoever switched the module off did not decide to keep that, and
     * for that person the cleanup matters more, not less: they are not going
     * to pass through the scanner again.
     *
     * Until 2.11.4 these were registered in the constructor, so they only ran
     * where the module was on. A site with the module off kept the credentials
     * with 2.11.3 installed, and a network whose main site had it off lost the
     * sweep too, which was the one path that reached the sites nobody visits.
     * Reported by @calzbert after reading the 2.11.3 diff.
     *
     * On admin_init because that is where the baseline is looked at, and it
     * does one option read per admin request until it has run once.
     *
     * @since 2.11.4
     */
    public function init_cleanup_hooks() {
        add_action( 'admin_init', array( $this, 'maybe_redact_stored_baseline' ) );
        add_action( 'admin_init', array( $this, 'maybe_sweep_network_baselines' ) );
        add_action( 'admin_init', array( $this, 'maybe_claim_owned_blocks_on_admin' ) );
    }

    /**
     * Check if scan time limit has been exceeded
     *
     * @return bool True if time exceeded.
     */
    private function is_time_exceeded() {
        if ( 0 === $this->scan_start_time ) {
            return false;
        }
        if ( ( microtime( true ) - $this->scan_start_time ) > $this->max_scan_time ) {
            // The clock budget was the one cut to the limit of PHP.
            if ( $this->php_limit > 0 && $this->cpu_budget <= 0 ) {
                $this->cut_by_php_limit = true;
            }
            return true;
        }
        if ( $this->cpu_budget > 0 && null !== $this->cpu_at_start ) {
            $cpu = self::cpu_seconds();
            if ( null !== $cpu && ( $cpu - $this->cpu_at_start ) > $this->cpu_budget ) {
                $this->cut_by_php_limit = true;
                return true;
            }
        }
        return false;
    }

    /**
     * Schedule automated scans
     */
    private function schedule_scan() {
        $frequency = $this->options['scan_frequency'] ?? 'daily';

        if ( ! wp_next_scheduled( 'vigilante_file_integrity_scan' ) ) {
            wp_schedule_event( time(), $frequency, 'vigilante_file_integrity_scan' );
        }
    }

    /**
     * Run a scheduled scan
     */
    public function run_scheduled_scan() {
        $results = $this->run_scan();

        // Store last scan time
        update_option( 'vigilante_last_integrity_scan', time() );
        update_option( 'vigilante_last_integrity_results', $results );
    }

    /**
     * React to a completed plugin/theme update (upgrader_process_complete).
     *
     * Opens a short grace window for each updated slug (so the scheduled scan
     * skips it and the checksum cache is bypassed) and schedules an immediate
     * verification against WordPress.org. This stops the post-update "files
     * don't match WordPress.org" false positives and, when WP-Cron is healthy,
     * verifies the update against WordPress.org right away instead of waiting
     * for the next scheduled scan. The grace window is intentionally short (30
     * minutes) so that if WP-Cron never fires the verification, the normal scan
     * resumes for the slug rather than leaving it unscanned.
     *
     * Runs as the old plugin code with the new files already on disk, so slugs
     * are read from $hook_extra, not from in-memory version constants.
     *
     * @param WP_Upgrader|mixed $upgrader   Upgrader instance (unused).
     * @param array             $hook_extra Update context.
     */
    public function on_upgrade_complete( $upgrader, $hook_extra ) {
        unset( $upgrader );
        if ( ! is_array( $hook_extra ) || 'update' !== ( $hook_extra['action'] ?? '' ) ) {
            return;
        }

        $type    = $hook_extra['type'] ?? '';
        $targets = array(); // type => list of slugs.

        if ( 'plugin' === $type ) {
            $files = array();
            if ( ! empty( $hook_extra['plugins'] ) && is_array( $hook_extra['plugins'] ) ) {
                $files = $hook_extra['plugins'];
            } elseif ( ! empty( $hook_extra['plugin'] ) ) {
                $files = array( $hook_extra['plugin'] );
            }
            foreach ( $files as $file ) {
                $slug = dirname( (string) $file );
                // Vigilant itself is verified immediately (not after 90 s) by
                // Vigilante_Self_Integrity::handle_upgrader() when the
                // self-check is on; do not also open a grace window for it.
                // Compared with the folder it really lives in, not the literal
                // slug, so a renamed folder is skipped the same way.
                if ( dirname( VIGILANTE_PLUGIN_BASENAME ) === $slug && Vigilante_Self_Integrity::is_on() ) {
                    continue;
                }
                if ( '.' !== $slug && '' !== $slug ) {
                    $targets['plugin'][] = $slug;
                }
            }
        } elseif ( 'theme' === $type && ! empty( $hook_extra['themes'] ) && is_array( $hook_extra['themes'] ) ) {
            foreach ( $hook_extra['themes'] as $slug ) {
                $slug = (string) $slug;
                if ( '' !== $slug ) {
                    $targets['theme'][] = $slug;
                }
            }
        }

        if ( empty( $targets ) ) {
            return;
        }

        // Open a short grace window per slug (30 minutes; closed earlier once the
        // verifier runs). Kept short on purpose: with WP-Cron disabled the
        // verifier never fires, so a longer window would leave a just-updated
        // slug unscanned. After it expires the normal scan resumes.
        foreach ( $targets as $t => $slugs ) {
            foreach ( array_unique( $slugs ) as $slug ) {
                set_transient( 'vigilante_fi_grace_' . $t . '_' . md5( $slug ), 1, 30 * MINUTE_IN_SECONDS );
            }
        }

        // Verify shortly after the update settles. A single delayed event keeps
        // the heavy work out of the update request itself.
        if ( ! wp_next_scheduled( 'vigilante_fi_postupdate_verify', array( $targets ) ) ) {
            wp_schedule_single_event( time() + 90, 'vigilante_fi_postupdate_verify', array( $targets ) );
        }
    }

    /**
     * Immediate post-update verification callback (vigilante_fi_postupdate_verify).
     *
     * @param array $targets type => list of slugs.
     */
    public function run_postupdate_verify( $targets ) {
        if ( ! is_array( $targets ) ) {
            return;
        }
        foreach ( $targets as $type => $slugs ) {
            if ( 'plugin' !== $type && 'theme' !== $type ) {
                continue;
            }
            foreach ( array_unique( (array) $slugs ) as $slug ) {
                $this->verify_updated_slug( $type, (string) $slug );
            }
        }
    }

    /**
     * Verify a single just-updated plugin/theme against fresh wp.org checksums.
     *
     * The grace window forces get_*_checksums() to fetch a live manifest, so this
     * never compares against a manifest cached during wp.org's propagation lag.
     * Outcomes: checksums not published yet => leave the window to expire and let
     * the next scan re-check; all files match => close the window early; a file
     * matches no published hash => a genuine mismatch (right after a legit update
     * that points at a tampered package), logged as a warning, and the window is
     * closed so the finding also surfaces in the normal scan.
     *
     * @param string $type 'plugin' or 'theme'.
     * @param string $slug Slug.
     */
    private function verify_updated_slug( $type, $slug ) {
        $grace_key = 'vigilante_fi_grace_' . $type . '_' . md5( $slug );

        // Defensive skip for the first 2.11.x -> 3.0.x update: the OLD code in
        // memory scheduled this event including Vigilant's own slug, and by the
        // time it fires the NEW code (this one) is running with the self-check
        // handling Vigilant on its own.
        if ( 'plugin' === $type && dirname( VIGILANTE_PLUGIN_BASENAME ) === $slug && Vigilante_Self_Integrity::is_on() ) {
            delete_transient( $grace_key );
            return;
        }

        if ( 'plugin' === $type ) {
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $version = '';
            $name    = $slug;
            foreach ( get_plugins() as $file => $data ) {
                if ( dirname( $file ) === $slug ) {
                    $version = $data['Version'] ?? '';
                    $name    = $data['Name'] ?? $slug;
                    break;
                }
            }
            $checksums = $this->get_plugin_checksums( $slug, $version );
            $base_dir  = WP_PLUGIN_DIR . '/' . $slug;
        } else {
            $theme = wp_get_theme( $slug );
            if ( ! $theme->exists() ) {
                delete_transient( $grace_key );
                return;
            }
            $version   = $theme->get( 'Version' );
            $name      = $theme->get( 'Name' );
            $checksums = $this->get_theme_checksums( $slug, $version );
            $base_dir  = $theme->get_stylesheet_directory();
        }

        // Checksums not available yet (propagation lag): leave the grace window
        // to expire; the next scheduled scan re-verifies once wp.org publishes.
        if ( is_wp_error( $checksums ) || 'not_found' === $checksums || ! is_array( $checksums ) ) {
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'file',
                    'postupdate_pending',
                    sprintf(
                        /* translators: 1: Plugin or theme name. */
                        __( 'Post-update verification pending for %1$s: WordPress.org has not published the new version checksums yet. It will be re-verified automatically.', 'vigilante' ),
                        $name
                    ),
                    array(
                        'type'    => $type,
                        'slug'    => $slug,
                        'version' => $version,
                    ),
                    'info'
                );
            }
            return;
        }

        // Compare every shipped file against the fresh manifest.
        $mismatched = array();
        foreach ( $checksums as $file => $expected ) {
            if ( in_array( $file, $this->plugin_known_false_positives, true ) ) {
                continue;
            }
            $path = $base_dir . '/' . $file;
            if ( $this->is_path_excluded( $path ) || $this->is_extension_excluded( $path ) ) {
                continue;
            }
            // Honor the user ignore list, exactly as run_scan()'s filter_ignored()
            // does, so the verifier never warns about a file the user silenced.
            $rel = $type . 's/' . $slug . '/' . $file;
            if ( in_array( $rel, (array) $this->ignored_files, true ) ) {
                continue;
            }
            if ( ! file_exists( $path ) ) {
                continue;
            }
            if ( ! $this->hash_matches_published( $path, $expected ) ) {
                $mismatched[] = $rel;
            }
        }

        // Verified clean: close the grace window so normal scanning resumes.
        if ( empty( $mismatched ) ) {
            delete_transient( $grace_key );
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'file',
                    'postupdate_verified',
                    sprintf(
                        /* translators: 1: Plugin or theme name. */
                        __( 'Post-update verification passed: %1$s matches the WordPress.org distribution.', 'vigilante' ),
                        $name
                    ),
                    array(
                        'type'    => $type,
                        'slug'    => $slug,
                        'version' => $version,
                    ),
                    'info'
                );
            }
            return;
        }

        // Genuine mismatch right after a legitimate update: likely a tampered
        // package. Close the window so the normal scan also surfaces it, and log
        // a warning (Audit Alerts escalates warnings if configured).
        delete_transient( $grace_key );
        if ( $this->activity_log ) {
            $this->activity_log->log(
                'file',
                'postupdate_mismatch',
                sprintf(
                    /* translators: 1: Number of files, 2: Plugin or theme name. */
                    _n(
                        'Post-update integrity check failed: %1$d file in %2$s does not match the WordPress.org distribution.',
                        'Post-update integrity check failed: %1$d files in %2$s do not match the WordPress.org distribution.',
                        count( $mismatched ),
                        'vigilante'
                    ),
                    count( $mismatched ),
                    $name
                ),
                array(
                    'type'    => $type,
                    'slug'    => $slug,
                    'version' => $version,
                    'files'   => array_slice( $mismatched, 0, 50 ),
                ),
                'warning'
            );
        }
    }

    /**
     * Run a full integrity scan
     *
     * @return array Scan results.
     */
    public function run_scan() {
        // Initialize scan timer
        $this->scan_start_time = microtime( true );

        $results = array(
            'scanned'    => 0,
            'ok'         => 0,
            'modified'   => array(),
            'missing'    => array(),
            'suspicious' => array(),
            'extra'      => array(),
            'new'        => array(),
            'errors'     => array(),
            'scan_time'  => 0,
            'incomplete' => false,
        );

        // Fit the scan into the time PHP gives this request, and leave a mark
        // that says it started, so that one the server stops is not silent.
        $this->fit_to_time_limit();
        $this->mark_scan_started();

        // Use settings from options page
        $options = is_array( $this->options ) ? $this->options : array();

        // Vigilant self-check runs FIRST and exempt from the time budget:
        // ~60 small-file hashes cost < 50 ms and the guardian must never be
        // dropped by the budget on plugin-heavy sites. User exclusions do not
        // apply to it (see Vigilante_Self_Integrity::run_check()).
        if ( ! class_exists( 'Vigilante_Self_Integrity' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-self-integrity.php';
        }
        if ( Vigilante_Self_Integrity::is_on() ) {
            if ( ! class_exists( 'Vigilante_Self_Integrity' ) ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-self-integrity.php';
            }
            $self        = new Vigilante_Self_Integrity( $this->settings, $this->activity_log );
            $self_result = $self->run_check( 'scan' );
            // run_check() above updates this site's own state (status line and
            // the analyzer check keep working everywhere). The plugin files are
            // shared by the whole installation, so the self findings are folded
            // Self-protection has its own alert, and it does not travel in the
            // scan digest any more. That digest is governed by a notification
            // setting that can be switched off, and switching off "tell me about
            // changed files" was also switching off the alarm of the plugin
            // itself. So the findings stay out of the scan results (they have
            // their own block in File Integrity, with what each one means and how
            // to repair it) and a critical one sends its own email from here,
            // wherever the scan runs. maybe_send_self_alert() keeps it to the
            // site that owns the shared files and dedupes by set of findings.
            foreach ( (array) $self_result['findings'] as $self_finding ) {
                if ( 'critical' === ( $self_finding['severity'] ?? '' ) ) {
                    $self->maybe_send_self_alert( $self_result['findings'], 'scan' );
                    break;
                }
            }
        }

        // What the time does not reach. A scan that runs out of time used to
        // say only that it was partial, and it starts from the beginning
        // every time, so on a large site the same plugins and themes were
        // left out on every scan with nobody told which. They are named.
        $not_checked = array(
            'areas'   => array(),
            'plugins' => array(),
            'themes'  => array(),
        );

        // And the folders of the plugins and themes it did check, which is
        // what the tab offers to exclude so that a scan by hand reaches the
        // rest (see folders_to_exclude()).
        $checked_folders = array();

        // Scan uploads for suspicious files FIRST (highest security priority)
        // PHP files in uploads are almost always malware
        if ( ! empty( $options['scan_uploads'] ) && ! $this->is_time_exceeded() ) {
            $upload_results = $this->scan_uploads();
            $results['suspicious'] = array_merge( $results['suspicious'], $upload_results['suspicious'] );
            $results['extra'] = array_merge( $results['extra'], $upload_results['extra'] );
            $results['errors'] = array_merge( $results['errors'], $upload_results['errors'] ?? array() );
        } elseif ( ! empty( $options['scan_uploads'] ) ) {
            $not_checked['areas'][] = 'uploads';
        }

        // Scan core files
        if ( ! empty( $options['scan_core'] ) && ! $this->is_time_exceeded() ) {
            $core_results = $this->scan_core_files();
            $results = $this->merge_results( $results, $core_results );
        } elseif ( ! empty( $options['scan_core'] ) ) {
            $not_checked['areas'][] = 'core';
        }

        // Scan root directory for non-core files (PHP = suspicious, others = additional)
        // Runs after core scan so checksums are already cached
        if ( ! empty( $options['scan_core'] ) && ! $this->is_time_exceeded() ) {
            $root_results = $this->scan_root_files();
            $results['suspicious'] = array_merge( $results['suspicious'], $root_results['suspicious'] );
            $results['extra'] = array_merge( $results['extra'], $root_results['extra'] );
        } elseif ( ! empty( $options['scan_core'] ) ) {
            $not_checked['areas'][] = 'core';
        }

        // Files added to wp-admin or wp-includes, which the comparison with
        // the checksums never visits because the checksums do not name them.
        if ( ! empty( $options['scan_core'] ) && ! $this->is_time_exceeded() ) {
            $folder_results = $this->scan_core_folders();
            $results['suspicious'] = array_merge( $results['suspicious'], $folder_results['suspicious'] );
            $results['extra'] = array_merge( $results['extra'], $folder_results['extra'] );
            $results['errors'] = array_merge( $results['errors'], $folder_results['errors'] );
        } elseif ( ! empty( $options['scan_core'] ) ) {
            $not_checked['areas'][] = 'core';
        }

        // Scan critical config files (wp-config.php, .htaccess) against stored baseline
        if ( ! empty( $options['scan_critical_config'] ) && ! $this->is_time_exceeded() ) {
            $critical_results = $this->scan_critical_root_files();
            $results['modified'] = array_merge( $results['modified'], $critical_results );
        } elseif ( ! empty( $options['scan_critical_config'] ) ) {
            $not_checked['areas'][] = 'config';
        }

        // The other folders of wp-content (cache, languages, upgrade and
        // whatever else is there), which belong to no plugin and no theme and
        // had no turn. Before the plugins and the themes, which on a large
        // site can use up the whole scan, and with a share of the time of
        // their own, so a cache of a hundred thousand files cannot do the
        // same to them.
        $content_results = null;
        if ( ! empty( $options['scan_plugins'] ) && ! $this->is_time_exceeded() ) {
            $content_results       = $this->scan_content_folders();
            $results['suspicious'] = array_merge( $results['suspicious'], $content_results['suspicious'] );
            $results['extra']      = array_merge( $results['extra'], $content_results['extra'] );
            $results['errors']     = array_merge( $results['errors'], $content_results['errors'] );
        } elseif ( ! empty( $options['scan_plugins'] ) ) {
            $not_checked['areas'][] = 'content';
        }

        // Scan plugins
        if ( ! empty( $options['scan_plugins'] ) && ! $this->is_time_exceeded() ) {
            $plugin_results = $this->scan_plugins();
            $results = $this->merge_results( $results, $plugin_results );

            $not_checked['plugins'] = $plugin_results['not_checked'] ?? array();
            $checked_folders        = $plugin_results['checked'] ?? array();

            if ( empty( $plugin_results['unlisted_checked'] ) ) {
                $not_checked['areas'][] = 'unlisted';
            }
        } elseif ( ! empty( $options['scan_plugins'] ) ) {
            $not_checked['areas'][] = 'plugins';
            $not_checked['areas'][] = 'unlisted';
        }

        // Scan themes
        if ( ! empty( $options['scan_themes'] ) && ! $this->is_time_exceeded() ) {
            $theme_results = $this->scan_themes();
            $results = $this->merge_results( $results, $theme_results );

            $not_checked['themes'] = $theme_results['not_checked'] ?? array();
            $checked_folders       = array_merge( $checked_folders, $theme_results['checked'] ?? array() );
        } elseif ( ! empty( $options['scan_themes'] ) ) {
            $not_checked['areas'][] = 'themes';
        }

        // What could only be searched for hidden code: plugins and themes
        // first, as they are found, and the folders of wp-content after them.
        if ( null !== $content_results ) {
            $results['unverified'] = array_values( array_unique( array_merge( $results['unverified'] ?? array(), $content_results['unverified'] ) ) );
        }

        // Mark as incomplete if time was exceeded
        if ( $this->is_time_exceeded() ) {
            $results['incomplete'] = true;
            $results['errors'][] = __( 'Scan was incomplete due to time limit. Results may be partial.', 'vigilante' );
        }

        // Stored after the last merge: merge_results() keeps only the keys it
        // knows. So is why the scan had less time than usual (until the first
        // blind review of 3.0.8 it was written at the start and was lost).
        $this->note_php_limit( $results );
        $not_checked['areas']   = array_values( array_unique( $not_checked['areas'] ) );
        $results['not_checked'] = $not_checked;

        // Only with plugins or themes left out: a scan that reached them all
        // has nothing to make room for.
        if ( ! empty( $not_checked['plugins'] ) || ! empty( $not_checked['themes'] ) || array_intersect( array( 'plugins', 'themes' ), $not_checked['areas'] ) ) {
            $results['checked_folders'] = array_values( array_unique( $checked_folders ) );
        }

        // Filter out ignored files from all result categories
        $results['modified']   = $this->filter_ignored( $results['modified'] );
        $results['suspicious'] = $this->filter_ignored( $results['suspicious'] );
        $results['extra']      = $this->filter_ignored( $results['extra'] );

        $results['scan_time'] = round( microtime( true ) - $this->scan_start_time, 2 );

        // Log the scan only if activity_log is available
        if ( $this->activity_log ) {
            $has_issues = ! empty( $results['modified'] ) || ! empty( $results['suspicious'] ) || ! empty( $results['extra'] );
            $severity   = $has_issues ? 'warning' : 'info';
            
            /* translators: 1: Scanned count, 2: Modified count, 3: Suspicious count, 4: Extra files count */
            $log_text = __( 'File integrity scan completed: %1$d files scanned, %2$d modified, %3$d suspicious, %4$d extra', 'vigilante' );

            if ( $results['incomplete'] ) {
                /* translators: 1: Scanned count, 2: Modified count, 3: Suspicious count, 4: Extra files count */
                $log_text = __( 'File integrity scan ran out of time, so its result is partial: %1$d files scanned, %2$d modified, %3$d suspicious, %4$d extra', 'vigilante' );
            }

            $this->activity_log->log(
                'file',
                'integrity_scan',
                sprintf(
                    $log_text,
                    $results['scanned'],
                    count( $results['modified'] ),
                    count( $results['suspicious'] ),
                    count( $results['extra'] )
                ),
                array(
                    'scanned'    => $results['scanned'],
                    'modified'   => count( $results['modified'] ),
                    'suspicious' => count( $results['suspicious'] ),
                    'extra'      => count( $results['extra'] ),
                    'scan_time'  => $results['scan_time'],
                    'incomplete' => $results['incomplete'],
                ),
                $severity
            );
        }

        // Saved here, as soon as the files are done, and not only by whoever
        // called: what comes next asks WordPress.org about every plugin and
        // sends the email, outside the scan clock, and a server that stopped
        // the request in that stretch took with it a scan that had finished
        // (27.6 s for 57 plugins in Testing, 4 Oct 2026). The callers save the
        // same again when it returns.
        $this->store_results( $results );

        // Closed plugins check: queries the wp.org repository for the closure status
        // of every installed plugin slug. Independent of the file-level scan_* toggles
        // (gated by its own `check_closed_plugins` toggle in Scan Scope). Runs BEFORE
        // the notification call so closed plugins are folded into the scan email
        // (instead of triggering a separate one-shot).
        //
        // suppress_email=true: this entry point is the file integrity scan; the
        // daily plugin-status cron passes suppress_email=false so urgent closures
        // still produce an immediate alert when the file scan is on a weekly schedule.
        // That daily check is also why it is left out here when the request has
        // too little time left for it: the email would be the next thing lost.
        if ( ! empty( $options['check_closed_plugins'] ) && $this->seconds_left_in_request() >= self::CLOSED_PLUGINS_SECONDS ) {
            if ( ! class_exists( 'Vigilante_Plugin_Status' ) ) {
                require_once VIGILANTE_INCLUDES_DIR . 'class-plugin-status.php';
            }
            $closed_checker = new Vigilante_Plugin_Status( $this->settings, $this->activity_log );
            $closed_checker->check_all_plugins( true, true );
        }

        // Send email notification based on notify_level (now also includes closed
        // plugins picked up just above).
        $this->maybe_send_notification( $results );

        return $results;
    }

    /**
     * Fit the scan into the time PHP gives this request
     *
     * The scan runs for MAX_SCAN_SECONDS, and until 3.0.8 nothing looked at
     * max_execution_time: on a hosting that gives a request 30 seconds, PHP
     * could stop the scan halfway, and a scan stopped there saves nothing.
     * More time is asked for; when the server does not allow it, the scan
     * stops in time to save its result, and the result says so.
     *
     * What PHP counts depends on the platform. On Linux it is processor time
     * (ITIMER_PROF): waiting for WordPress.org or for the disk does not count,
     * so a scan of 60 seconds of clock can fit in 30 of PHP. There the budget
     * is measured with getrusage(), and the 60 seconds of clock stay. On
     * Windows, and on macOS with a recent PHP, it is clock time, and the clock
     * budget is cut. Measured on 19 Oct 2026 with the PHP of Local on Apple
     * Silicon: 7.4 lives through a sleep(4) with a limit of 2 seconds, and
     * 8.5 does not. Cutting the clock on Linux, as the first version of this
     * did, left partial a scan that 3.0.7 finished (first blind review).
     *
     * @since 3.0.8
     */
    private function fit_to_time_limit() {
        $this->php_limit        = 0;
        $this->cpu_budget       = 0;
        $this->cut_by_php_limit = false;
        $this->cpu_at_start     = self::cpu_seconds();

        $needed = self::MAX_SCAN_SECONDS + 30;
        $limit  = (int) ini_get( 'max_execution_time' );

        if ( $limit <= 0 || $limit >= $needed ) {
            return;
        }

        // set_time_limit() counts from now, and does nothing where the
        // hosting has disabled it: what counts is the limit read afterwards.
        if ( function_exists( 'set_time_limit' ) ) {
            set_time_limit( $needed ); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- Asked only when the limit of PHP is below what one scan needs; where the hosting refuses, the scan budget adapts to it below.
        }
        $limit = (int) ini_get( 'max_execution_time' );
        if ( $limit <= 0 || $limit >= $needed ) {
            return;
        }

        // PHP counts that limit from the start of the request, and in a cron
        // run other tasks may have used part of it before the scan: what was
        // spent is taken off, measured as PHP measures it (second blind
        // review of 3.0.8). In processor time, since the plugin loaded: the
        // first version took off the clock there too, and a cron run that had
        // waited 22 seconds for the network left the scan one second of a
        // limit PHP was not going to enforce (third blind review). The margin
        // is for saving the result: a third of the limit, 15 seconds at most,
        // in processor time; in clock time, also a download of checksums that
        // starts just before the budget runs out and waits its whole timeout.
        $this->php_limit = $limit;
        if ( 'cpu' === self::php_limit_clock() && null !== $this->cpu_at_start ) {
            $spent            = null !== self::$cpu_at_load ? max( 0, $this->cpu_at_start - self::$cpu_at_load ) : 0;
            $this->cpu_budget = max( 1, $limit - min( 15, $limit / 3 ) - $spent );
        } else {
            $spent               = isset( $_SERVER['REQUEST_TIME_FLOAT'] ) ? max( 0, microtime( true ) - (float) $_SERVER['REQUEST_TIME_FLOAT'] ) : 0;
            $this->max_scan_time = max( 1, $limit - min( $limit / 2, self::CHECKSUM_TIMEOUT + 5 ) - $spent );
        }
    }

    /**
     * What max_execution_time counts on this platform
     *
     * @since 3.0.8
     *
     * @return string cpu or wall.
     */
    private static function php_limit_clock() {
        if ( '' !== self::$limit_clock ) {
            return self::$limit_clock;
        }
        // A thread safe PHP on Linux counts with its own timers, in clock time
        // (zend max execution timers, the default there; FrankenPHP, for one).
        if ( PHP_ZTS ) {
            return 'wall';
        }
        return in_array( PHP_OS_FAMILY, array( 'Windows', 'Darwin' ), true ) ? 'wall' : 'cpu';
    }

    /**
     * Note the processor time of the process when the plugin loads
     *
     * @since 3.0.8
     *
     * @internal Called once, at the end of this file.
     */
    public static function note_load_cpu() {
        if ( null === self::$cpu_at_load ) {
            self::$cpu_at_load = self::cpu_seconds();
        }
    }

    /**
     * Processor time used by this process, user and system, in seconds
     *
     * @since 3.0.8
     *
     * @return float|null Null when getrusage() is not available.
     */
    private static function cpu_seconds() {
        if ( ! function_exists( 'getrusage' ) ) {
            return null;
        }
        $use = getrusage();
        if ( ! is_array( $use ) || ! isset( $use['ru_utime.tv_sec'], $use['ru_utime.tv_usec'], $use['ru_stime.tv_sec'], $use['ru_stime.tv_usec'] ) ) {
            return null;
        }
        return $use['ru_utime.tv_sec'] + $use['ru_utime.tv_usec'] / 1000000 + $use['ru_stime.tv_sec'] + $use['ru_stime.tv_usec'] / 1000000;
    }

    /**
     * Note in the results why the scan had less time than usual, when the
     * short limit of PHP is what stopped it
     *
     * @since 3.0.8
     *
     * @param array $results Scan results, by reference.
     */
    private function note_php_limit( &$results ) {
        if ( ! $this->cut_by_php_limit ) {
            return;
        }
        $results['time_limit']   = $this->php_limit;
        $results['scan_budget']  = (int) ( $this->cpu_budget > 0 ? $this->cpu_budget : $this->max_scan_time );
        $results['budget_clock'] = $this->cpu_budget > 0 ? 'cpu' : 'wall';
    }

    /**
     * Seconds left before PHP stops this request, or a large number when it
     * has no limit
     *
     * With the clock PHP uses here (see fit_to_time_limit()): processor time
     * since the plugin loaded where PHP counts that, and the clock since the
     * start of the request otherwise, both on the side of too little time.
     * Until 3.0.9 the processor time counted from the start of the scan, so
     * other tasks of the same cron run were left out and the closed plugins
     * check could start with less time ahead than this said (fourth blind
     * review of 3.0.8).
     *
     * @since 3.0.8
     *
     * @return float
     */
    private function seconds_left_in_request() {
        $limit = (int) ini_get( 'max_execution_time' );
        if ( $limit <= 0 ) {
            return PHP_INT_MAX;
        }
        if ( 'cpu' === self::php_limit_clock() && null !== $this->cpu_at_start ) {
            $cpu  = self::cpu_seconds();
            $from = null !== self::$cpu_at_load ? self::$cpu_at_load : $this->cpu_at_start;
            if ( null !== $cpu ) {
                return $limit - ( $cpu - $from );
            }
        }
        $start = isset( $_SERVER['REQUEST_TIME_FLOAT'] ) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : (float) $this->scan_start_time;
        return $limit - ( microtime( true ) - $start );
    }

    /**
     * Seconds the next request for checksums may wait
     *
     * CHECKSUM_TIMEOUT, or less when the scan was fitted to a short limit of
     * PHP that counts clock time and less is left. With a limit of 20 seconds
     * or less the margin of fit_to_time_limit() does not cover a whole
     * download, and the first request for the checksums of WordPress did not
     * look at the time left at all (fourth blind review of 3.0.8). Where PHP
     * counts processor time, waiting for the answer costs none of it. A
     * download cut short fails like one with no answer, which the scan
     * already reports as an error.
     *
     * @since 3.0.9
     *
     * @return int
     */
    private function checksum_timeout() {
        if ( $this->php_limit <= 0 || $this->cpu_budget > 0 ) {
            return self::CHECKSUM_TIMEOUT;
        }
        return (int) max( 1, min( self::CHECKSUM_TIMEOUT, floor( $this->seconds_left_in_request() - 3 ) ) );
    }

    /**
     * Mark that a scan started, and record the previous one if it never ended
     *
     * @since 3.0.8
     */
    private function mark_scan_started() {
        $previous = get_option( self::RUNNING_OPTION );

        // A marker that is still within its time belongs to a scan that may be
        // running right now in another request: it is left to that one, unless
        // its PHP already said that it died.
        if ( is_array( $previous ) && ! empty( $previous['started'] ) && ( ! empty( $previous['cause'] ) || self::marker_is_stale( $previous ) ) ) {
            update_option( self::UNFINISHED_OPTION, $previous, false );
            if ( $this->activity_log ) {
                $this->activity_log->log(
                    'file',
                    'integrity_scan_unfinished',
                    self::unfinished_scan_text( $previous ),
                    array(
                        'started'      => (int) $previous['started'],
                        'via'          => isset( $previous['via'] ) ? (string) $previous['via'] : '',
                        'cause'        => isset( $previous['cause'] ) ? (string) $previous['cause'] : '',
                        'time_limit'   => isset( $previous['time_limit'] ) ? (int) $previous['time_limit'] : 0,
                        'memory_limit' => isset( $previous['memory_limit'] ) ? (string) $previous['memory_limit'] : '',
                    ),
                    'warning'
                );
            }
        }

        $this->scan_token = wp_generate_password( 12, false );
        $via              = 'other';
        if ( wp_doing_ajax() ) {
            $via = 'button';
        } elseif ( wp_doing_cron() ) {
            $via = 'scheduled';
        }

        update_option(
            self::RUNNING_OPTION,
            array(
                'started'      => time(),
                'via'          => $via,
                'token'        => $this->scan_token,
                'time_limit'   => (int) ini_get( 'max_execution_time' ),
                'memory_limit' => (string) ini_get( 'memory_limit' ),
                'budget'       => (int) $this->max_scan_time,
            ),
            false
        );

        register_shutdown_function( array( $this, 'note_scan_stopped' ) );
    }

    /**
     * At the end of the request: say why the scan stopped, when PHP says it
     *
     * Runs on shutdown, also after a fatal error. When PHP ran out of memory
     * or time, the marker keeps it, and the notice can name the cause. When
     * the web server killed the process, nothing runs and only the marker is
     * left, so the notice says "most likely".
     *
     * @since 3.0.8
     *
     * @internal Hooked by mark_scan_started(); public because PHP calls it.
     */
    public function note_scan_stopped() {
        try {
            $running = get_option( self::RUNNING_OPTION );
            if ( ! is_array( $running ) || ! isset( $running['token'] ) || $this->scan_token !== (string) $running['token'] ) {
                return;
            }
            $cause = self::stop_cause( error_get_last() );
            if ( '' === $cause ) {
                return;
            }
            $running['cause'] = $cause;
            update_option( self::RUNNING_OPTION, $running, false );
        } catch ( Throwable $e ) {
            unset( $e );
        }
    }

    /**
     * Why PHP stopped a request, from error_get_last()
     *
     * @since 3.0.8
     *
     * @param mixed $error What error_get_last() returned.
     * @return string memory, time, error, or '' when it was not a fatal error.
     */
    public static function stop_cause( $error ) {
        if ( ! is_array( $error ) || ! isset( $error['type'], $error['message'] ) || ! in_array( (int) $error['type'], array( E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR ), true ) ) {
            return '';
        }
        $message = (string) $error['message'];
        if ( false !== stripos( $message, 'Allowed memory size' ) ) {
            return 'memory';
        }
        if ( false !== stripos( $message, 'Maximum execution time' ) ) {
            return 'time';
        }
        return 'error';
    }

    /**
     * Save the result of a scan and close its marker
     *
     * @since 3.0.8
     *
     * @param array $results Scan results.
     */
    private function store_results( $results ) {
        update_option( 'vigilante_last_integrity_scan', time() );
        update_option( 'vigilante_last_integrity_results', $results );
        delete_option( self::RUNNING_OPTION );
        delete_option( self::UNFINISHED_OPTION );
    }

    /**
     * Whether a marker is older than any scan can last
     *
     * @since 3.0.8
     *
     * @param array    $marker Marker of RUNNING_OPTION.
     * @param int|null $now    Current time.
     * @return bool
     */
    private static function marker_is_stale( $marker, $now = null ) {
        $limit  = isset( $marker['time_limit'] ) ? (int) $marker['time_limit'] : 0;
        $budget = isset( $marker['budget'] ) ? (int) $marker['budget'] : self::MAX_SCAN_SECONDS;
        $now    = null === $now ? time() : (int) $now;
        return ( $now - (int) $marker['started'] ) > ( max( $limit, $budget ) + 120 );
    }

    /**
     * Whether the marker of a scan in progress belongs to one that is over:
     * its PHP said that it died, or it is older than any scan can last
     *
     * @since 3.0.8
     *
     * @return bool False when there is no marker, or when it may be a scan
     *              running right now.
     */
    public static function running_marker_is_over() {
        $running = get_option( self::RUNNING_OPTION );
        return is_array( $running ) && ! empty( $running['started'] ) && ( ! empty( $running['cause'] ) || self::marker_is_stale( $running ) );
    }

    /**
     * The scan that started and did not finish, or null
     *
     * The one the next scan found, or the marker of one that is older than
     * any scan can last. The only source of that fact for the tab and for
     * Security Check.
     *
     * @since 3.0.8
     *
     * @return array|null { int started, string via, string cause, int time_limit, string memory_limit }
     */
    public static function unfinished_scan() {
        $unfinished = get_option( self::UNFINISHED_OPTION );
        if ( is_array( $unfinished ) && ! empty( $unfinished['started'] ) ) {
            return $unfinished;
        }
        $running = get_option( self::RUNNING_OPTION );
        // A marker with a cause is one whose PHP said, as it died, that it
        // ran out of memory or time: it is not running, and there is no need
        // to wait until it is old to say so.
        if ( is_array( $running ) && ! empty( $running['started'] ) && ( ! empty( $running['cause'] ) || self::marker_is_stale( $running ) ) ) {
            return $running;
        }
        return null;
    }

    /**
     * What a scan that did not finish says
     *
     * @since 3.0.8
     *
     * @param array $marker What unfinished_scan() returned.
     * @return string
     */
    public static function unfinished_scan_text( $marker ) {
        $text = sprintf(
            /* translators: %s: date and time the scan started */
            __( 'The scan started on %s did not finish: it was stopped before it could save its result.', 'vigilante' ),
            wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $marker['started'] )
        );
        // A scan that finishes deletes the marker, so the last one that did
        // is always older than this.
        $text .= ' ' . ( (int) get_option( 'vigilante_last_integrity_scan', 0 ) > 0
            ? __( 'What is shown is the last scan that finished.', 'vigilante' )
            : __( 'No scan has finished on this site yet.', 'vigilante' ) );

        $cause = isset( $marker['cause'] ) ? (string) $marker['cause'] : '';
        if ( 'memory' === $cause ) {
            $text .= ' ' . sprintf(
                /* translators: %s: PHP memory limit, such as 128M */
                __( 'PHP ran out of memory (memory_limit is %s).', 'vigilante' ),
                isset( $marker['memory_limit'] ) ? (string) $marker['memory_limit'] : '?'
            );
        } elseif ( 'time' === $cause ) {
            $text .= ' ' . sprintf(
                /* translators: %d: seconds */
                __( 'PHP ran out of time (max_execution_time is %d seconds).', 'vigilante' ),
                isset( $marker['time_limit'] ) ? (int) $marker['time_limit'] : 0
            );
        } elseif ( 'error' === $cause ) {
            $text .= ' ' . __( 'PHP stopped it with an error: the error log of the server has it.', 'vigilante' );
        } else {
            $text .= ' ' . __( 'The most likely cause is the time or the memory the server gives to one request.', 'vigilante' );
        }

        return $text . ' ' . __( 'If it happens again, ask your hosting for more time or memory for PHP.', 'vigilante' );
    }

    /**
     * Scan WordPress core files
     *
     * @return array Scan results.
     */
    private function scan_core_files() {
        $results = array(
            'scanned'  => 0,
            'ok'       => 0,
            'modified' => array(),
            'missing'  => array(),
            'errors'   => array(),
        );

        // Get official checksums from WordPress.org
        $this->core_checksums_are_english = false;
        $checksums                        = $this->get_core_checksums();

        if ( is_wp_error( $checksums ) ) {
            $results['errors'][] = $checksums->get_error_message();
            return $results;
        }

        // The plugins and themes that get a turn of their own in this scan.
        $own_turn = array(
            'plugins' => array(),
            'themes'  => array(),
        );

        if ( ! empty( $this->options['scan_plugins'] ) ) {
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }

            foreach ( array_keys( get_plugins() ) as $plugin_file ) {
                $slash = strpos( $plugin_file, '/' );

                if ( false !== $slash ) {
                    $own_turn['plugins'][ substr( $plugin_file, 0, $slash ) ] = true;
                }
            }
        }

        if ( ! empty( $this->options['scan_themes'] ) ) {
            foreach ( array_keys( wp_get_themes() ) as $stylesheet ) {
                $stylesheet = (string) $stylesheet;
                $slash      = strpos( $stylesheet, '/' );

                $own_turn['themes'][ false === $slash ? $stylesheet : substr( $stylesheet, 0, $slash ) ] = true;
            }
        }

        foreach ( $checksums as $file => $expected_hash ) {
            // Check time limit
            if ( $this->is_time_exceeded() ) {
                break;
            }

            $file_path = ABSPATH . $file;

            // Skip excluded paths
            if ( $this->is_path_excluded( $file_path ) ) {
                continue;
            }

            // Skip excluded extensions
            if ( $this->is_extension_excluded( $file_path ) ) {
                continue;
            }

            // Skip known false positives (e.g. readme.html, license.txt)
            if ( in_array( $file, $this->core_known_false_positives, true ) ) {
                continue;
            }

            // Skip translations that travel inside the localized core ZIP but do
            // not belong to core. WordPress.org's localized checksum manifest
            // lists Akismet and the default themes' language files (8 entries on
            // every non-en_US locale, none on en_US), yet they are updated on the
            // plugin and theme cycle and are absent from the core language pack.
            // Deleting an unused plugin or theme, which this plugin's own audit
            // recommends, otherwise left permanent "missing core file" findings.
            if ( 0 === strpos( $file, 'wp-content/languages/plugins/' )
                || 0 === strpos( $file, 'wp-content/languages/themes/' ) ) {
                continue;
            }

            // The bundled themes and plugins have their own turn. Akismet and
            // the default themes are in this list at the version WordPress
            // shipped, and they update on their own cycle: every one of those
            // updates showed as a modified core file, and deleting one that is
            // not in use as missing core files. The plugin and theme scans
            // compare them with their own published copy, so they are left to
            // those whenever those are on and have them in their list.
            if ( preg_match( '#^wp-content/(plugins|themes)/([^/]+)/#', $file, $bundled ) ) {
                // Deleted on purpose: nothing to compare and nothing missing.
                if ( ! is_dir( ABSPATH . 'wp-content/' . $bundled[1] . '/' . $bundled[2] ) ) {
                    continue;
                }

                // Its own scan compares it, but only what WordPress lists as a
                // plugin or as a theme gets that turn. A folder that is there
                // and is not listed (a plugin without its header, a theme
                // without its style.css) stays with the core.
                if ( isset( $own_turn[ $bundled[1] ][ $bundled[2] ] ) ) {
                    continue;
                }
            }

            $results['scanned']++;

            if ( ! file_exists( $file_path ) ) {
                $results['missing'][] = array(
                    'file' => $file,
                    'type' => 'core',
                );
                continue;
            }

            $actual_hash = md5_file( $file_path );

            if ( $actual_hash !== $expected_hash && ! $this->matches_core_of_other_locale( $file, $actual_hash ) ) {
                // The two files a translated package changes cannot be told
                // from a modified one while only the English list exists. Said
                // as what it is, a file that could not be verified, instead of
                // as a modified core file.
                if ( $this->core_checksums_are_english && in_array( $file, array( 'wp-includes/version.php', 'wp-config-sample.php' ), true ) ) {
                    $results['errors'][] = sprintf(
                        /* translators: %s: File name */
                        __( '%s differs from the English package of WordPress, and WordPress.org has not published the checksums for the language of this site yet, so it could not be verified.', 'vigilante' ),
                        $file
                    );
                    continue;
                }

                $results['modified'][] = array(
                    'file'          => $file,
                    'type'          => 'core',
                    'expected_hash' => $expected_hash,
                    'actual_hash'   => $actual_hash,
                );
            } else {
                $results['ok']++;
            }
        }

        $results['modified'] = $this->drop_stale_language_mismatches( $results['modified'], $results );

        return $results;
    }

    /**
     * Drop language files that only mismatch because the manifest was stale
     *
     * wp.org rebuilds the checksum manifest every time GlotPress rebuilds a
     * language pack, and that happens without the WordPress version moving. The
     * cache key here is version plus locale, so it does not expire when that
     * happens, and the site spends up to a day comparing today's translation
     * files against yesterday's manifest. That is where the bursts of "modified
     * core files" under wp-content/languages/ come from, and they are not
     * modifications at all.
     *
     * So before reporting one, the manifest is fetched again bypassing the
     * cache, once per scan, and whatever matches the fresh copy is dropped.
     * Anything still mismatching is reported as before.
     *
     * @since 2.9.9
     *
     * @param array $modified Entries flagged as modified.
     * @param array $results  Scan results, to move the recovered files to 'ok'.
     * @return array Entries that are still modified.
     */
    private function drop_stale_language_mismatches( $modified, &$results ) {
        if ( empty( $modified ) ) {
            return $modified;
        }

        $suspects = array();
        foreach ( $modified as $entry ) {
            if ( 0 === strpos( $entry['file'], 'wp-content/languages/' ) ) {
                $suspects[ $entry['file'] ] = true;
            }
        }

        if ( empty( $suspects ) ) {
            return $modified;
        }

        $fresh = $this->get_core_checksums( true );

        if ( is_wp_error( $fresh ) || empty( $fresh ) ) {
            return $modified;
        }

        $kept = array();

        foreach ( $modified as $entry ) {
            $file = $entry['file'];

            if ( ! isset( $suspects[ $file ] ) || ! isset( $fresh[ $file ] ) ) {
                $kept[] = $entry;
                continue;
            }

            if ( $this->hash_matches_published( ABSPATH . $file, $fresh[ $file ] ) ) {
                $results['ok']++;
                continue;
            }

            $kept[] = $entry;
        }

        return $kept;
    }

    /**
     * Scan WordPress root directory for non-core files
     *
     * Compares files in ABSPATH (non-recursive) against the official core
     * checksums list. PHP files not in the core distribution are flagged as
     * suspicious (common attack vector: info.php, shell.php, backdoors).
     * Non-PHP files not in the known safe list are flagged as extra/additional.
     * Dotfiles and known safe files (robots.txt, etc.) are skipped.
     *
     * @return array Array with 'suspicious' and 'extra' sub-arrays.
     */
    private function scan_root_files() {
        $found = array(
            'suspicious' => array(),
            'extra'      => array(),
        );

        // Get core checksums to know which root files are legitimate
        $checksums = $this->get_core_checksums();
        if ( is_wp_error( $checksums ) ) {
            return $found;
        }

        // Build list of known core root files from checksums (only root-level, no directory prefix)
        $core_root_files = array();
        foreach ( array_keys( $checksums ) as $file ) {
            // Only root-level files (no directory separator)
            if ( false === strpos( $file, '/' ) ) {
                $core_root_files[] = $file;
            }
        }

        // Also add wp-config.php which is not in checksums but is core
        $core_root_files[] = 'wp-config.php';

        $php_extensions = self::php_extensions();

        // Scan only direct children of ABSPATH (not recursive)
        $root_path = untrailingslashit( ABSPATH );
        $handle = opendir( $root_path );

        if ( ! $handle ) {
            return $found;
        }

        while ( false !== ( $entry = readdir( $handle ) ) ) {
            if ( $this->is_time_exceeded() ) {
                break;
            }

            // Skip . and ..
            if ( '.' === $entry || '..' === $entry ) {
                continue;
            }

            // PHP reads .user.ini and php.ini from the folder of the script, and
            // either can make it load a file before every request: the same
            // door as .htaccess, for servers that run PHP outside Apache.
            if ( in_array( strtolower( $entry ), array( '.user.ini', 'php.ini' ), true ) ) {
                $config = $this->is_path_excluded( $root_path . '/' . $entry ) ? null : self::server_config_finding( $root_path . '/' . $entry, $entry );

                if ( $config ) {
                    $config['item']['type'] = 'php_config_in_root';
                    $found['extra'][]       = $config['item'];
                }
                continue;
            }

            // Skip dotfiles (.htaccess, .env, etc.): handled by firewall protection
            if ( 0 === strpos( $entry, '.' ) ) {
                continue;
            }

            $full_path = $root_path . '/' . $entry;

            // Skip directories — we only care about files in root
            if ( is_dir( $full_path ) ) {
                continue;
            }

            // Skip if this is a known core file
            if ( in_array( $entry, $core_root_files, true ) ) {
                continue;
            }

            // Skip excluded paths
            if ( $this->is_path_excluded( $full_path ) ) {
                continue;
            }

            // Skip known safe non-PHP root files
            if ( in_array( strtolower( $entry ), $this->known_safe_root_files, true ) ) {
                continue;
            }

            // Site verification files and sitemaps that are what their name says.
            if ( self::is_harmless_root_file( $entry, $full_path ) ) {
                continue;
            }

            $extension = strtolower( pathinfo( $entry, PATHINFO_EXTENSION ) );

            if ( in_array( $extension, $php_extensions, true ) ) {
                // Check if this is a legacy WordPress core file (removed from newer versions)
                if ( in_array( $entry, $this->legacy_core_root_files, true ) ) {
                    $found['extra'][] = array(
                        'file'   => $entry,
                        'type'   => 'legacy_core',
                        'reason' => __( 'Legacy WordPress core file, removed in newer versions. Safe to delete.', 'vigilante' ),
                    );
                    continue;
                }

                // Silence-is-golden placeholders dropped here by some setups
                // (e.g. WordPress installed in a subdirectory, or third-party tooling).
                if ( $this->is_silence_golden_file( $full_path ) ) {
                    continue;
                }

                // PHP file not in core = suspicious
                $reason = __( 'Non-core PHP file in WordPress root directory', 'vigilante' );

                // Scan content for specific patterns
                $pattern = $this->search_file( $full_path );
                if ( $pattern ) {
                    /* translators: %s: Suspicious pattern found */
                    $reason = sprintf( __( 'Non-core PHP in root with suspicious code: %s', 'vigilante' ), $pattern );
                }

                $found['suspicious'][] = array(
                    'file'   => $entry,
                    'type'   => 'php_in_root',
                    'reason' => $reason,
                );
            } else {
                // A copy of the configuration, a database dump or an archive
                // is not one more loose file: whoever guesses its name can
                // download it.
                if ( false !== stripos( $entry, 'wp-config' ) || preg_match( '/\.(?:sql|bak|old|orig|save|swp|dump|zip|gz|tgz|tar|7z|rar)$/i', $entry ) ) {
                    $found['extra'][] = array(
                        'file'   => $entry,
                        'type'   => 'backup_in_root',
                        'reason' => __( 'Backup or copy of a sensitive file in the site root, where it can be downloaded', 'vigilante' ),
                    );
                    continue;
                }

                // Non-PHP, non-known-safe file = additional (informational)
                $found['extra'][] = array(
                    'file'   => $entry,
                    'type'   => 'extra_root',
                    'reason' => __( 'Non-core file in WordPress root directory', 'vigilante' ),
                );
            }
        }

        closedir( $handle );

        return $found;
    }

    /**
     * The line of a .user.ini or php.ini that makes PHP load a file by itself
     *
     * @param string $path Absolute path of the file.
     * @return string|null The line, an empty string when there is none, or
     *                     null when the file is too large to be read, which
     *                     the caller reports instead of taking for clean.
     */
    private static function php_ini_loads( $path ) {
        // PHP runs as the same user: what it cannot read here it cannot apply.
        if ( ! is_readable( $path ) ) {
            return '';
        }

        if ( filesize( $path ) > MB_IN_BYTES ) {
            return null;
        }

        $content = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a local file to look at its directives; nothing is written.

        foreach ( preg_split( '/\r\n|\r|\n/', (string) $content ) as $line ) {
            $line = trim( $line );

            if ( '' === $line || ';' === $line[0] || '#' === $line[0] ) {
                continue;
            }

            if ( preg_match( '/^(auto_prepend_file|auto_append_file)\s*=\s*(.*)$/i', $line, $parts ) ) {
                $value = trim( $parts[2], " \t\"'" );

                if ( '' !== $value && 'none' !== strtolower( $value ) ) {
                    return strtolower( $parts[1] ) . ' = ' . substr( $value, 0, 200 );
                }
            }
        }

        return '';
    }

    /**
     * What a .htaccess, .user.ini or php.ini outside uploads makes the server do
     *
     * Inside a plugin, a theme, wp-content or a WordPress folder, one of these
     * files is a finding only when it makes the server run code or load a file.
     * One that denies access, or does nothing of the kind, is left alone.
     *
     * @param string $file_path Absolute path.
     * @param string $relative  Path for display.
     * @return array|null Array with 'category' and 'item', or null.
     */
    private static function server_config_finding( $file_path, $relative ) {
        $item = array(
            'file' => $relative,
            'type' => 'server_config',
        );

        if ( '.htaccess' === strtolower( basename( $file_path ) ) ) {
            if ( ! is_readable( $file_path ) ) {
                return null;
            }

            if ( filesize( $file_path ) >= 65536 ) {
                $item['reason'] = __( '.htaccess file that is too large to be read', 'vigilante' );

                return array(
                    'category' => 'extra',
                    'item'     => $item,
                );
            }

            $facts = self::read_htaccess_rules( file_get_contents( $file_path ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a local file to look at its directives; nothing is written.

            if ( empty( $facts['runs'] ) ) {
                return null;
            }

            $item['reason'] = self::htaccess_run_reason( $facts );

            return array(
                'category' => 'suspicious',
                'item'     => $item,
            );
        }

        $loads = self::php_ini_loads( $file_path );

        if ( '' === $loads ) {
            return null;
        }

        $item['reason'] = null === $loads
            ? __( 'PHP configuration file that is too large to be read', 'vigilante' )
            /* translators: %s: The line of the file that does it */
            : sprintf( __( 'PHP configuration file that loads a file on every request: %s', 'vigilante' ), $loads );

        return array(
            'category' => 'extra',
            'item'     => $item,
        );
    }

    /**
     * Whether a loose file in the site root is a verification file or a sitemap
     *
     * By what it contains or by its kind, never by its name alone: a Google
     * verification file is one line that repeats its own name, and a sitemap
     * is XML, which no server runs.
     *
     * @param string $entry     File name.
     * @param string $full_path Absolute path.
     * @return bool
     */
    private static function is_harmless_root_file( $entry, $full_path ) {
        if ( preg_match( '/^[a-z0-9_-]*sitemap[a-z0-9_-]*\.xml(?:\.gz)?$/i', $entry ) ) {
            return true;
        }

        if ( preg_match( '/^google[0-9a-f]{16}\.html$/', $entry ) && is_readable( $full_path ) && filesize( $full_path ) < 200 ) {
            $content = file_get_contents( $full_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a local file to compare it with its own name; nothing is written.

            return 'google-site-verification: ' . $entry === trim( (string) $content );
        }

        return false;
    }

    /**
     * Walk a folder and everything under it without stopping at what cannot be read
     *
     * A folder PHP cannot open used to end the whole walk in silence, which is
     * all it took to blind a scan: one unreadable folder early in the order,
     * and nothing after it was looked at. Now the walk goes past it, and the
     * caller reports it (see unreadable_folder_error()).
     *
     * @param string        $directory Folder to walk.
     * @param callable|null $skip      Given the path of a folder, whether to leave
     *                                 it and everything under it out of the walk.
     * @return RecursiveIteratorIterator Folders included: the caller skips them.
     */
    private static function walk_folder( $directory, $skip = null ) {
        $folder = new RecursiveDirectoryIterator( $directory, RecursiveDirectoryIterator::SKIP_DOTS );

        if ( null !== $skip ) {
            $folder = new RecursiveCallbackFilterIterator(
                $folder,
                static function ( $current ) use ( $skip ) {
                    return ! ( $current->isDir() && call_user_func( $skip, $current->getPathname() ) );
                }
            );
        }

        return new RecursiveIteratorIterator(
            $folder,
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD
        );
    }

    /**
     * What the scan says about a folder it could not read
     *
     * @param string $path Absolute path of the folder.
     * @return string
     */
    private static function unreadable_folder_error( $path ) {
        return sprintf(
            /* translators: %s: Folder path */
            __( 'The folder %s could not be read, so what is inside it was not checked.', 'vigilante' ),
            str_replace( ABSPATH, '', $path )
        );
    }

    /**
     * Extensions a server may be set up to run as PHP
     *
     * One list for uploads, the site root, the core folders and the plugin and
     * theme folders. Each had its own until now, and none had them all.
     *
     * @return array
     */
    private static function php_extensions() {
        return array( 'php', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps', 'inc' );
    }

    /**
     * Look in wp-admin and wp-includes for files WordPress does not ship
     *
     * The comparison with the official checksums only visits the files the
     * checksums name, so a file added to either folder was never looked at. A
     * PHP file there that is not part of the installed version is reported as
     * suspicious. A file that changes how the server runs code (.htaccess,
     * .user.ini, php.ini) is reported as extra, or as suspicious when it
     * makes the server run code. Anything else that is not code, such as an
     * error log the host writes there, is left alone.
     *
     * @return array Array with 'suspicious', 'extra' and 'errors' sub-arrays.
     */
    private function scan_core_folders() {
        $found = array(
            'suspicious' => array(),
            'extra'      => array(),
            'errors'     => array(),
        );

        $checksums = $this->get_core_checksums();
        if ( is_wp_error( $checksums ) ) {
            return $found;
        }

        $php_extensions = self::php_extensions();
        $config_files   = array( '.htaccess', '.user.ini', 'php.ini' );

        foreach ( array( 'wp-admin', 'wp-includes' ) as $folder ) {
            $directory = ABSPATH . $folder;

            if ( ! is_dir( $directory ) ) {
                continue;
            }

            try {
                foreach ( self::walk_folder( $directory ) as $file ) {
                    if ( $this->is_time_exceeded() ) {
                        break 2;
                    }

                    $file_path = $file->getPathname();

                    if ( $file->isDir() ) {
                        if ( ! $file->isReadable() ) {
                            $found['errors'][] = self::unreadable_folder_error( $file_path );
                        }
                        continue;
                    }

                    $relative = $this->normalize_rel_path( str_replace( '\\', '/', str_replace( ABSPATH, '', $file_path ) ) );

                    if ( isset( $checksums[ $relative ] ) || $this->is_path_excluded( $file_path ) ) {
                        continue;
                    }

                    $extension = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );

                    if ( in_array( $extension, $php_extensions, true ) ) {
                        // The placeholder some hosts and tools drop in every folder.
                        if ( $this->is_silence_golden_file( $file_path ) ) {
                            continue;
                        }

                        // Translation files, on the installations old enough
                        // to keep them in wp-includes/languages: text and
                        // nothing else, which is checked and not assumed.
                        if ( self::is_inside_languages( $file_path ) && true === $this->is_literal_data( $file_path ) ) {
                            continue;
                        }

                        /* translators: %s: Folder name, wp-admin or wp-includes */
                        $reason = sprintf( __( 'File in %s that is not part of the installed WordPress version', 'vigilante' ), $folder );

                        $pattern = $this->search_file( $file_path );
                        if ( $pattern ) {
                            /* translators: 1: Folder name, wp-admin or wp-includes, 2: Suspicious pattern found */
                            $reason = sprintf( __( 'File in %1$s that is not part of WordPress, with suspicious code: %2$s', 'vigilante' ), $folder, $pattern );
                        }

                        $found['suspicious'][] = array(
                            'file'   => $relative,
                            'type'   => 'php_in_core',
                            'reason' => $reason,
                        );
                    } elseif ( in_array( strtolower( basename( $file_path ) ), $config_files, true ) ) {
                        $config = self::server_config_finding( $file_path, $relative );

                        if ( $config && 'suspicious' === $config['category'] ) {
                            $found['suspicious'][] = $config['item'];
                            continue;
                        }

                        $found['extra'][] = array(
                            'file'   => $relative,
                            'type'   => 'config_in_core',
                            /* translators: %s: Folder name, wp-admin or wp-includes */
                            'reason' => $config ? $config['item']['reason'] : sprintf( __( 'Server configuration file in %s', 'vigilante' ), $folder ),
                        );
                    }
                }
            } catch ( Exception $e ) {
                $found['errors'][] = self::unreadable_folder_error( $directory );
            }
        }

        return $found;
    }

    /**
     * Look for code where there is no official copy to compare with
     *
     * Must-use plugins, drop-ins, the loose PHP files of wp-content, of the
     * plugins folder and of the themes folder, and the folders in those two
     * that WordPress does not list as a plugin or as a theme, were not opened
     * by any part of the scan, although WordPress loads some of them on every
     * request and the rest can be reached by their address. They are searched
     * the way a plugin from outside WordPress.org is, for code written the way
     * malware hides itself. A loose PHP file or a folder with PHP that is
     * neither a plugin, a theme nor a drop-in is listed as extra, and so is a
     * .htaccess, .user.ini or php.ini there that makes the server run code or
     * load a file.
     *
     * @return array Array with 'suspicious', 'extra', 'unverified' and 'errors' sub-arrays.
     */
    private function scan_unlisted_code() {
        $found = array(
            'suspicious' => array(),
            'extra'      => array(),
            'unverified' => array(),
            'errors'     => array(),
        );

        // Must-use plugins: the whole folder.
        if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
            $mu = $this->detect_extra_files( WPMU_PLUGIN_DIR, array(), 'plugin', __( 'Must-use plugins', 'vigilante' ), true );

            $found['suspicious'] = array_merge( $found['suspicious'], $mu['suspicious'] );
            $found['extra']      = array_merge( $found['extra'], $mu['extra'] );
            $found['errors']     = array_merge( $found['errors'], $mu['errors'] );

            if ( $mu['php_files'] > 0 ) {
                $found['unverified'][] = __( 'Must-use plugins', 'vigilante' );
            }
        }

        if ( ! function_exists( '_get_dropins' ) || ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $php_extensions = self::php_extensions();
        $config_files   = array( '.htaccess', '.user.ini', 'php.ini' );
        $dropins        = array_keys( _get_dropins() );

        // What WordPress lists as a plugin or as a theme, by the file or the
        // folder it lives in.
        $single_plugins = array();
        $plugin_folders = array();
        foreach ( get_plugins() as $plugin_file => $plugin_data ) {
            if ( false === strpos( $plugin_file, '/' ) ) {
                $single_plugins[ $plugin_file ] = $plugin_data['Name'] ?? $plugin_file;
            } else {
                $plugin_folders[ substr( $plugin_file, 0, strpos( $plugin_file, '/' ) ) ] = true;
            }
        }

        // The themes by where they really are, because there can be more
        // than one folder of themes and the same name in two of them.
        $theme_folders = array();
        foreach ( wp_get_themes() as $stylesheet => $theme ) {
            $stylesheet = (string) $stylesheet;
            $slash      = strpos( $stylesheet, '/' );
            $real       = realpath( untrailingslashit( $theme->get_theme_root() ) . '/' . ( false === $slash ? $stylesheet : substr( $stylesheet, 0, $slash ) ) );

            if ( false !== $real ) {
                $theme_folders[ wp_normalize_path( $real ) ] = true;
            }
        }

        $roots = array(
            array( 'content', WP_CONTENT_DIR ),
            array( 'plugins', WP_PLUGIN_DIR ),
        );

        // Every folder themes are registered in, not only the usual one. One
        // that is inside a plugin belongs to that plugin, and has its turn
        // with it.
        global $wp_theme_directories;

        $plugin_roots = array();
        foreach ( array( WP_PLUGIN_DIR, defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : '' ) as $plugin_root ) {
            $real = '' === (string) $plugin_root ? false : realpath( $plugin_root );

            if ( false !== $real ) {
                $plugin_roots[ wp_normalize_path( $real ) ] = true;
            }
        }

        $theme_roots = array();
        foreach ( array_merge( array( get_theme_root() ), is_array( $wp_theme_directories ) ? $wp_theme_directories : array() ) as $theme_root ) {
            $real = '' === (string) $theme_root ? false : realpath( $theme_root );
            $real = false === $real ? '' : wp_normalize_path( $real );

            if ( '' === $real || isset( $theme_roots[ $real ] ) || self::is_inside_any( $real, $plugin_roots ) ) {
                continue;
            }

            $theme_roots[ $real ] = true;
            $roots[]              = array( 'themes', untrailingslashit( $theme_root ) );
        }

        foreach ( $roots as $root ) {
            list( $kind, $directory ) = $root;

            $entries = is_dir( $directory ) ? scandir( $directory ) : false;

            if ( ! is_array( $entries ) ) {
                continue;
            }

            foreach ( $entries as $entry ) {
                if ( '.' === $entry || '..' === $entry ) {
                    continue;
                }

                if ( $this->is_time_exceeded() ) {
                    break 2;
                }

                $path = $directory . '/' . $entry;

                if ( $this->is_path_excluded( $path ) ) {
                    continue;
                }

                $relative = str_replace( ABSPATH, '', $path );

                // A folder among the plugins or the themes that WordPress does
                // not list as one: no scan had a turn for it.
                if ( is_dir( $path ) ) {
                    $real   = realpath( $path );
                    $listed = 'plugins' === $kind ? isset( $plugin_folders[ $entry ] ) : ( 'themes' === $kind ? ( false !== $real && isset( $theme_folders[ wp_normalize_path( $real ) ] ) ) : true );

                    // A link is followed like any other folder, because what
                    // is behind it is reached by its address just the same,
                    // unless it leads back to wp-content or above it, which
                    // would be walking the site a second time.
                    if ( $listed || ( is_link( $path ) && self::leads_back( $path ) ) ) {
                        continue;
                    }

                    $inside = $this->detect_extra_files( $path, array(), 'themes' === $kind ? 'theme' : 'plugin', $entry, true );

                    $found['suspicious'] = array_merge( $found['suspicious'], $inside['suspicious'] );
                    $found['extra']      = array_merge( $found['extra'], $inside['extra'] );
                    $found['errors']     = array_merge( $found['errors'], $inside['errors'] );

                    if ( $inside['php_files'] > 0 ) {
                        $found['extra'][] = array(
                            'file'   => $relative,
                            'type'   => 'php_in_content',
                            'reason' => 'themes' === $kind
                                ? __( 'Folder with PHP files that WordPress does not list as a theme', 'vigilante' )
                                : __( 'Folder with PHP files that WordPress does not list as a plugin', 'vigilante' ),
                        );
                    }
                    continue;
                }

                if ( in_array( strtolower( $entry ), $config_files, true ) ) {
                    $config = self::server_config_finding( $path, $relative );

                    if ( $config ) {
                        $found[ $config['category'] ][] = $config['item'];
                    }
                    continue;
                }

                $extension = strtolower( pathinfo( $entry, PATHINFO_EXTENSION ) );

                if ( ! in_array( $extension, $php_extensions, true ) || $this->is_silence_golden_file( $path ) ) {
                    continue;
                }

                // hello.php comes with WordPress and is compared with it.
                if ( 'plugins' === $kind && 'hello.php' === $entry ) {
                    continue;
                }

                $pattern = $this->search_file( $path, true );

                $known = ( 'plugins' === $kind && isset( $single_plugins[ $entry ] ) ) || ( 'content' === $kind && in_array( $entry, $dropins, true ) );

                if ( $known ) {
                    $found['unverified'][] = 'plugins' === $kind ? $single_plugins[ $entry ] : __( 'Drop-ins', 'vigilante' );
                }

                if ( $pattern ) {
                    $found['suspicious'][] = array(
                        'file'   => $relative,
                        'type'   => 'suspicious_plugin',
                        /* translators: 1: Plugin or theme name, or the folder the file is in, 2: Suspicious pattern found */
                        'reason' => sprintf( __( 'File in %1$s with suspicious code: %2$s', 'vigilante' ), dirname( $relative ), $pattern ),
                    );
                } elseif ( ! $known ) {
                    $found['extra'][] = array(
                        'file'   => $relative,
                        'type'   => 'php_in_content',
                        'reason' => __( 'PHP file that is not a plugin, a theme or a WordPress drop-in', 'vigilante' ),
                    );
                } elseif ( null === $pattern ) {
                    $found['extra'][] = $this->not_searched_item( $path, $relative );
                }
            }
        }

        $found['unverified'] = array_values( array_unique( $found['unverified'] ) );

        return $found;
    }

    /**
     * Look in the folders of wp-content that belong to no plugin and no theme
     *
     * cache, languages, upgrade and whatever else is there were not opened by
     * any part of the scan, and a PHP file in any of them can be reached by
     * its address like one anywhere else. Every PHP file in them is searched
     * for hidden code, the way a plugin from outside WordPress.org is, and a
     * .htaccess, .user.ini or php.ini is reported when it makes the server run
     * code or load a file. A folder with PHP files that could only be
     * searched is named among what has no official copy.
     *
     * Translation files are the exception, because what they must hold is
     * known: text. WordPress loads the .l10n.php files of the site language
     * with include on every request
     * (wp-includes/l10n/class-wp-translation-file-php.php:24), so one that
     * holds anything else is reported whatever the code looks like, and any
     * other PHP file among the translations is listed. A PHP file that holds
     * literal data and nothing else cannot run anything, and is left alone
     * wherever it is (see is_literal_data()).
     *
     * Plugins, themes, must-use plugins and uploads have their own scans and
     * are skipped here. The folders whose name says cache go last, and the
     * whole walk has a share of the scan time of its own, so a cache with a
     * hundred thousand files costs that share and no more.
     *
     * @return array Array with 'suspicious', 'extra', 'unverified' and 'errors' sub-arrays.
     */
    private function scan_content_folders() {
        $found = array(
            'suspicious' => array(),
            'extra'      => array(),
            'unverified' => array(),
            'errors'     => array(),
        );

        $entries = is_dir( WP_CONTENT_DIR ) ? scandir( WP_CONTENT_DIR ) : false;

        if ( ! is_array( $entries ) ) {
            return $found;
        }

        // The folders with a scan of their own, by where they really are.
        global $wp_theme_directories;

        $uploads      = wp_get_upload_dir();
        $uploads_real = empty( $uploads['basedir'] ) ? false : realpath( $uploads['basedir'] );
        $uploads_real = false === $uploads_real ? '' : wp_normalize_path( $uploads_real );
        $own          = array();
        $roots        = array_merge(
            array( WP_PLUGIN_DIR, defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : '', get_theme_root() ),
            is_array( $wp_theme_directories ) ? $wp_theme_directories : array()
        );

        foreach ( $roots as $root ) {
            $real = '' === (string) $root ? false : realpath( $root );

            if ( false !== $real ) {
                $own[ wp_normalize_path( $real ) ] = true;
            }
        }

        if ( '' !== $uploads_real ) {
            $own[ $uploads_real ] = true;
        }

        // On a site of a network that is not the main one, the uploads of the
        // site live inside the uploads of the network, which are the main
        // site's turn.
        $network_uploads = is_multisite() && ! is_main_site() ? $uploads_real : '';

        $folders = array();

        foreach ( $entries as $entry ) {
            $path = WP_CONTENT_DIR . '/' . $entry;

            if ( '.' === $entry || '..' === $entry || ! is_dir( $path ) ) {
                continue;
            }

            $real = realpath( $path );
            $real = false === $real ? '' : wp_normalize_path( $real );

            // A folder with a scan of its own, or a link into one. A link to
            // anywhere else is walked like the folder it stands for: deploy
            // tools keep languages or a cache behind one, and what is there
            // is reached by its address all the same.
            if ( '' === $real || self::is_inside_any( $real, $own ) || ( is_link( $path ) && self::leads_back( $path ) ) ) {
                continue;
            }

            if ( '' !== $network_uploads && 0 === strpos( $network_uploads, $real . '/' ) ) {
                continue;
            }

            if ( $this->is_path_excluded( $path . '/.' ) ) {
                continue;
            }

            $folders[] = $entry;
        }

        usort(
            $folders,
            static function ( $a, $b ) {
                $a_cache = false !== stripos( $a, 'cache' );
                $b_cache = false !== stripos( $b, 'cache' );

                return $a_cache === $b_cache ? strcmp( $a, $b ) : ( $a_cache ? 1 : -1 );
            }
        );

        $php_extensions = self::php_extensions();
        $config_files   = array( '.htaccess', '.user.ini', 'php.ini' );
        $deadline       = microtime( true ) + $this->content_folders_time;

        // A folder with a scan of its own nested further down, or one the
        // user left out, is not walked at all.
        $skip = function ( $folder ) use ( $own ) {
            $real = realpath( $folder );

            return ( false !== $real && isset( $own[ wp_normalize_path( $real ) ] ) ) || $this->is_path_excluded( $folder . '/.' );
        };

        foreach ( $folders as $entry ) {
            $path      = WP_CONTENT_DIR . '/' . $entry;
            $php_files = 0;

            try {
                foreach ( self::walk_folder( $path, $skip ) as $file ) {
                    if ( $this->is_time_exceeded() ) {
                        break 2;
                    }

                    if ( microtime( true ) > $deadline ) {
                        $found['errors'][] = sprintf(
                            /* translators: %s: Folder path */
                            __( 'The folders of wp-content outside plugins, themes and uploads were not checked completely: the time for them ran out in %s. If that folder only holds files that change all the time, such as a cache, add it to Excluded Paths.', 'vigilante' ),
                            str_replace( ABSPATH, '', $path )
                        );
                        break 2;
                    }

                    $file_path = $file->getPathname();

                    if ( $file->isDir() ) {
                        if ( ! $file->isReadable() ) {
                            $found['errors'][] = self::unreadable_folder_error( $file_path );
                        }
                        continue;
                    }

                    $basename = strtolower( basename( $file_path ) );

                    if ( in_array( $basename, $config_files, true ) ) {
                        $config = $this->is_path_excluded( $file_path ) ? null : self::server_config_finding( $file_path, str_replace( ABSPATH, '', $file_path ) );

                        if ( $config ) {
                            $found[ $config['category'] ][] = $config['item'];
                        }
                        continue;
                    }

                    if ( ! in_array( strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) ), $php_extensions, true ) ) {
                        continue;
                    }

                    if ( $this->is_path_excluded( $file_path ) || $this->is_silence_golden_file( $file_path ) ) {
                        continue;
                    }

                    $literal = $this->is_literal_data( $file_path );

                    if ( true === $literal ) {
                        continue;
                    }

                    $relative = str_replace( ABSPATH, '', $file_path );

                    if ( false === $literal && '.l10n.php' === substr( $basename, -9 ) ) {
                        // Reported whatever the search finds, like a PHP file
                        // in uploads: WordPress loads it on every request, and
                        // no tool writes anything but the table of texts in
                        // it. What the search finds is said next to it.
                        $pattern = $this->search_file( $file_path, true );
                        $reason  = __( 'Translation file that holds something other than translations', 'vigilante' );

                        if ( $pattern ) {
                            /* translators: %s: Suspicious pattern found */
                            $reason = sprintf( __( 'Translation file with suspicious code: %s', 'vigilante' ), $pattern );
                        }

                        $found['suspicious'][] = array(
                            'file'   => $relative,
                            'type'   => 'translation_with_code',
                            'reason' => $reason,
                        );
                        continue;
                    }

                    $pattern = $this->search_file( $file_path, true );

                    if ( $pattern ) {
                        $found['suspicious'][] = array(
                            'file'   => $relative,
                            'type'   => 'suspicious_content',
                            /* translators: 1: Plugin or theme name, or the folder the file is in, 2: Suspicious pattern found */
                            'reason' => sprintf( __( 'File in %1$s with suspicious code: %2$s', 'vigilante' ), str_replace( ABSPATH, '', $path ), $pattern ),
                        );
                    } elseif ( null === $pattern ) {
                        $found['extra'][] = $this->not_searched_item( $file_path, $relative );
                    } elseif ( self::is_inside_languages( $file_path ) ) {
                        $found['extra'][] = array(
                            'file'   => $relative,
                            'type'   => 'php_in_content',
                            'reason' => __( 'PHP file among the translations that is not a translation file', 'vigilante' ),
                        );
                    } else {
                        $php_files++;
                    }
                }
            } catch ( Exception $e ) {
                $found['errors'][] = self::unreadable_folder_error( $path );
            }

            if ( $php_files > 0 ) {
                $found['unverified'][] = str_replace( ABSPATH, '', $path );
            }
        }

        return $found;
    }

    /**
     * Whether a real path is one of a set of folders or lies inside one of them
     *
     * @param string $real    Real path, with forward slashes.
     * @param array  $folders Real paths with forward slashes, as keys.
     * @return bool
     */
    private static function is_inside_any( $real, $folders ) {
        foreach ( array_keys( $folders ) as $folder ) {
            if ( $real === $folder || 0 === strpos( $real, $folder . '/' ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a link leads to wp-content itself or to a folder above it
     *
     * @param string $path Path of the link.
     * @return bool True also when where it leads cannot be worked out.
     */
    private static function leads_back( $path ) {
        $real    = realpath( $path );
        $content = realpath( WP_CONTENT_DIR );

        if ( false === $real || false === $content ) {
            return true;
        }

        return 0 === strpos( wp_normalize_path( $content ) . '/', wp_normalize_path( $real ) . '/' );
    }

    /**
     * Whether a path is inside the folder WordPress keeps its translations in
     *
     * @param string $path Absolute path.
     * @return bool
     */
    private static function is_inside_languages( $path ) {
        if ( ! defined( 'WP_LANG_DIR' ) ) {
            return false;
        }

        return 0 === strpos( wp_normalize_path( $path ), untrailingslashit( wp_normalize_path( WP_LANG_DIR ) ) . '/' );
    }

    /**
     * Whether a PHP file holds literal data and nothing else
     *
     * A file such as "<?php return [ 'a' => 'b' ];" cannot run anything. It is
     * how WordPress, GlotPress, WP-CLI and Loco Translate write translation
     * files, and how plugins keep small tables. The file is read one piece at
     * a time, and every piece has to be a quoted string with nothing
     * interpolated in it, a number, true, false, null, return, an array
     * bracket, a comma, "=>", a dot or a semicolon. A parenthesis is
     * accepted only as part of "array(" and to close it, so
     * nothing can be called, and with those pieces there is no way to name a
     * variable, a function, a class or a file.
     *
     * Anything else, a comment included, and the answer is no. Saying no to a
     * harmless file only means it is searched like any other; saying yes to
     * a file with code would hide it. So this reads less than PHP does, on
     * purpose. Each piece is also one PHP would cut the same way: a minus
     * sign only in front of a number and a dot never in front of "=", or
     * "-=>" and ".=>" would be read here as an arrow and by PHP as an
     * assignment. What it accepts is checked against PHP's own reading of
     * the same file, at random, in the release checks.
     *
     * @param string $file_path Absolute path.
     * @return bool|null True when it holds only data, false when it holds
     *                   anything else, null when it could not be read whole.
     */
    private function is_literal_data( $file_path ) {
        if ( ! is_file( $file_path ) || ! is_readable( $file_path ) ) {
            return null;
        }

        // With another source encoding set (zend.multibyte), a string does
        // not end for PHP where it ends byte by byte: nothing is vouched for.
        if ( ini_get( 'zend.multibyte' ) ) {
            return null;
        }

        $size = filesize( $file_path );

        if ( false === $size || $size > self::MAX_SEARCHED_BYTES ) {
            return null;
        }

        $content = file_get_contents( $file_path, false, null, 0, self::MAX_SEARCHED_BYTES + 1 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a local file to see whether it holds anything but data; nothing is written.

        if ( false === $content || strlen( $content ) > self::MAX_SEARCHED_BYTES ) {
            return null;
        }

        if ( 1 !== preg_match( '/\A<\?php[ \t\r\n]/', $content ) ) {
            return false;
        }

        $piece  = '/\G(?:[ \t\r\n]++|\'[^\'\\\\]*+(?:\\\\.[^\'\\\\]*+)*+\'|"[^"\\\\$]*+(?:\\\\.[^"\\\\$]*+)*+"|-?+\d++(?:\.\d++)?+(?:e[+-]?+\d++)?+|=>|\.(?!=)|[\[\],;)]|(?:true|false|null|return)(?![a-z0-9_\x80-\xff])|array[ \t\r\n]*+\()/is';
        $length = strlen( $content );
        $offset = 6;

        while ( $offset < $length ) {
            $match  = array();
            $result = preg_match( $piece, $content, $match, 0, $offset );

            if ( 1 !== $result ) {
                return false === $result ? null : false;
            }

            $offset += strlen( $match[0] );
        }

        return true;
    }

    // =========================================================================
    // Critical config file baseline monitoring (wp-config.php, .htaccess)
    // =========================================================================

    /**
     * Scan critical root files against stored baseline hashes
     *
     * Files like wp-config.php and .htaccess have no official WordPress.org
     * checksum because their content is unique per installation. We maintain
     * our own baseline hash and alert when the file changes outside of
     * Vigilante's own modifications.
     *
     * On the first scan (no baseline stored yet) the baseline is created
     * silently — there is nothing to compare against.
     *
     * @return array Array of modified file entries (same format as core modified).
     */
    /**
     * Where a critical root file actually lives
     *
     * WordPress supports wp-config.php one directory above ABSPATH, guarded by
     * wp-settings.php not being there: that is literally what the installed core
     * does in wp-load.php, and it is a common hardening layout. Until 2.11.10
     * this module only looked inside ABSPATH, so on those installations
     * wp-config.php was never added to the baseline, never compared and never
     * mentioned: the module reported the site clean without having opened the
     * one file it most needs to watch. A zero is justified, never assumed. The
     * plugin already resolved both locations elsewhere
     * (Vigilante_Database_Prefix::find_wpconfig_path()), just not here. Found by
     * the file-by-file review of 2.11.10.
     *
     * @since 2.11.10
     *
     * @param string $filename Name of the file, such as wp-config.php.
     * @return string|false Absolute path, or false when it cannot be found.
     */
    private function critical_file_path( $filename ) {
        $root = untrailingslashit( ABSPATH );
        $path = $root . '/' . $filename;

        if ( file_exists( $path ) ) {
            return $path;
        }

        if ( 'wp-config.php' === $filename ) {
            $above = dirname( $root ) . '/wp-config.php';

            // Suppressed like the core does in wp-load.php: the directory above
            // the install is often outside open_basedir on shared hosting, and
            // without the @ every scan emits a warning that can land in front of
            // the JSON of an AJAX scan.
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- The same @ the core uses for this same check in wp-load.php:52, where a wp-config.php one directory up is looked for: open_basedir makes file_exists() warn on a path outside it, and this must not print.
            if ( @file_exists( $above ) && ! @file_exists( dirname( $root ) . '/wp-settings.php' ) ) {
                return $above;
            }
        }

        return false;
    }

    private function scan_critical_root_files() {
        // Before reading anything: the scan is the only thing that reaches
        // every site of a network on its own, through wp-cron and front-end
        // traffic. Hooking the cleanup to admin_init alone left every subsite
        // whose dashboard nobody opens with its old copy of wp-config.php,
        // credentials included, for as long as nobody visited it.
        $this->maybe_redact_stored_baseline();

        // And claim the blocks already on disk before anything is compared,
        // so the first scan after updating uses the rule that will stay.
        $this->maybe_claim_owned_blocks();

        $modified = array();
        $baseline = $this->get_critical_files_baseline();
        $baseline_changed = false;

        foreach ( $this->critical_root_files as $filename ) {
            $full_path = $this->critical_file_path( $filename );

            if ( false === $full_path ) {
                continue;
            }

            $content = file_get_contents( $full_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            if ( false === $content ) {
                continue;
            }

            $normalized = $this->normalize_critical_file( $filename, $content );
            $current_hash = md5( $normalized );

            if ( ! isset( $baseline[ $filename ] ) ) {
                // First time seeing this file — store baseline silently
                $baseline[ $filename ] = array(
                    'hash'    => $current_hash,
                    'size'    => strlen( $content ),
                    'content' => $this->baseline_content( $filename, $normalized ),
                    'updated' => time(),
                );
                $baseline_changed = true;
                continue;
            }

            // Upgrade legacy baseline entries that lack content (pre-diff format)
            if ( ! isset( $baseline[ $filename ]['content'] ) && $baseline[ $filename ]['hash'] === $current_hash ) {
                $baseline[ $filename ]['content'] = $this->baseline_content( $filename, $normalized );
                $baseline_changed = true;
                continue;
            }

            /*
             * The file has not changed, but the copy on record is not the copy
             * that would be stored today: an entry written before 2.11.2 with
             * the credentials in it, or one written before the redaction list
             * grew. Rewrite it.
             *
             * Only when the hash matches, and that condition is the whole
             * point: if the file HAD changed, this entry is the evidence of
             * the change that the administrator still has to review, and
             * rewriting it here would quietly destroy that evidence.
             */
            if ( $baseline[ $filename ]['hash'] === $current_hash ) {
                $expected = $this->baseline_content( $filename, $normalized );

                if ( $expected !== $baseline[ $filename ]['content'] ) {
                    $baseline[ $filename ]['content'] = $expected;
                    $baseline_changed = true;
                }

                continue;
            }

            /*
             * Everything from here down is the changed file, and only that: the
             * branch above returns on every matching hash, so there is no third
             * case and no condition left to test. It used to be wrapped in an
             * `if` repeating the opposite comparison, which read as if some
             * other path could reach this point. It could not. Flagged by
             * @calzbert, and worth the two lines it costs to say so.
             *
             * Both sides go through the same redaction, or every credential
             * line would read as a change nobody made.
             */
            /*
             * Where the shared files do not belong to this site, the lines are
             * not computed at all. The diff is shown to whoever can open this
             * site's screen, the administrator of a subsite included, and it
             * was stored in the options of every subsite with the module on.
             * Found by the audit of the admin surface for 2.11.8. The change is
             * still reported, with both sizes, and the lines are read on the
             * main site, where the change is approved.
             */
            if ( ! Vigilante_Settings::owns_shared_files() ) {
                $diff = self::network_only_diff();
            } else {
                $baseline_content = $baseline[ $filename ]['content'] ?? '';
                $current_content  = $this->baseline_content( $filename, $normalized );
                $diff = ( '' !== $baseline_content && '' !== $current_content )
                    ? $this->compute_simple_diff( $baseline_content, $current_content )
                    : array( 'added' => array(), 'removed' => array(), 'unavailable' => true );

                // Say why there are no lines when today's copy could not be
                // made safe, which approving does not change: the generic
                // message talks about an old baseline. Cross review of 2.11.8.
                if ( '' === $current_content && 'wp-config.php' === $filename ) {
                    $diff['redaction'] = true;
                }
            }

            $modified[] = array(
                'file'          => $filename,
                'type'          => 'critical_config',
                'expected_hash' => $baseline[ $filename ]['hash'],
                'actual_hash'   => $current_hash,
                'baseline_size' => $baseline[ $filename ]['size'],
                'current_size'  => strlen( $content ),
                'diff'          => $diff,
            );
        }

        if ( $baseline_changed ) {
            $this->write_baseline( $baseline );
        }

        return $modified;
    }

    /**
     * Compute a simple line-based diff between two strings
     *
     * Returns added and removed lines with their original line numbers.
     * Order is preserved. Uses a simple "line present in set" approach
     * which works well for config files where most lines are unique.
     *
     * @param string $old Baseline content.
     * @param string $new Current content.
     * @return array Array with 'added' and 'removed' line entries.
     */
    private function compute_simple_diff( $old, $new ) {
        $old_lines = explode( "\n", $old );
        $new_lines = explode( "\n", $new );

        // Use hash sets for O(1) lookup. Use array_flip for cheap existence check.
        $old_set = array_count_values( $old_lines );
        $new_set = array_count_values( $new_lines );

        $removed = array();
        foreach ( $old_lines as $i => $line ) {
            // Line only considered removed if baseline has more occurrences than current
            if ( ! isset( $new_set[ $line ] ) || $new_set[ $line ] < ( $old_set[ $line ] ?? 0 ) ) {
                $removed[] = array(
                    'line'    => $i + 1,
                    'content' => $line,
                );
                // Decrement to handle duplicates correctly
                if ( isset( $old_set[ $line ] ) ) {
                    $old_set[ $line ]--;
                }
            }
        }

        // Reset for added detection
        $old_set = array_count_values( $old_lines );
        $added = array();
        foreach ( $new_lines as $i => $line ) {
            if ( ! isset( $old_set[ $line ] ) || $old_set[ $line ] < ( $new_set[ $line ] ?? 0 ) ) {
                $added[] = array(
                    'line'    => $i + 1,
                    'content' => $line,
                );
                if ( isset( $new_set[ $line ] ) ) {
                    $new_set[ $line ]--;
                }
            }
        }

        return array(
            'added'       => $added,
            'removed'     => $removed,
            'unavailable' => false,
        );
    }

    /**
     * Normalize critical file content by removing Vigilante-managed blocks
     *
     * This ensures that changes made by Vigilante itself (security constants,
     * htaccess rules) do not trigger false-positive modification alerts.
     * Line endings are normalized to LF to prevent false positives from
     * editors that change CRLF/LF.
     *
     * @param string $filename File name (e.g. 'wp-config.php').
     * @param string $content  Raw file content.
     * @return string Normalized content for hashing.
     */
    private function normalize_critical_file( $filename, $content, $drop_all_original = false ) {
        // Normalize line endings first (CRLF and CR to LF)
        $content = str_replace( array( "\r\n", "\r" ), "\n", $content );

        /*
         * Vigilant's own blocks are left out of the hash, so rewriting them is
         * not reported as somebody else's change. Until 2.11.5 that covered
         * everything between the markers, and every line carrying the
         * [VIGILANTE_ORIGINAL] marker, whatever they contained. From 2.11.5 a
         * block is left out only if it is exactly a block Vigilant wrote (see
         * remember_owned_block()), and a marked line only while uncommenting it
         * would still give a harmless define() (see is_vigilant_original_line()).
         *
         * Until the blocks already on disk have been claimed, the old rule
         * applies unchanged. That is what keeps an update from changing the
         * hash of a file nobody touched.
         */
        $claimed = $this->owned_blocks_claimed();

        if ( 'wp-config.php' === $filename ) {
            // Vigilante constants blocks (current and legacy)
            foreach ( $this->wpconfig_markers as $markers ) {
                $content = $this->strip_vigilant_blocks( $filename, $content, $markers, $claimed );
            }

            // Lines commented out by Vigilante (original constants)
            $content = preg_replace_callback(
                '/^.*' . preg_quote( $this->wpconfig_original_marker, '/' ) . '.*$/m',
                function ( $line ) use ( $claimed, $drop_all_original ) {
                    // $drop_all_original reproduce la regla anterior a la 2.11.5 (quitar
                    // toda linea marcada) sobre los bloques de la regla nueva. Solo lo usa
                    // el re-base de la transicion, para decidir si la unica diferencia con
                    // el registro aprobado son estas lineas. Ver rebase_original_line_shift().
                    return ( ! $claimed || $drop_all_original || $this->is_vigilant_original_line( $line[0] ) ) ? '' : $line[0];
                },
                $content
            );
        } elseif ( '.htaccess' === $filename ) {
            // Vigilante htaccess blocks (firewall + security headers)
            foreach ( $this->htaccess_markers as $markers ) {
                $content = $this->strip_vigilant_blocks( $filename, $content, $markers, $claimed );
            }
        }

        // Collapse multiple blank lines into one (blocks removal leaves gaps)
        $content = preg_replace( '/\n{3,}/', "\n\n", $content );

        return trim( $content );
    }

    /**
     * Leave Vigilant's blocks for one pair of markers out of the content
     *
     * Before the claim, every block, as it always was. After it, only the blocks
     * whose fingerprint was recorded when Vigilant wrote them. A block that does
     * not match, edited or planted, stays in the content: it counts in the hash
     * and shows up in the diff.
     *
     * The match runs from marker to marker and the removal also takes the
     * whitespace after the block, exactly as before, so a file whose blocks are
     * all Vigilant's normalizes to the same text under both rules.
     *
     * @since 2.11.5
     *
     * @param string $filename 'wp-config.php' or '.htaccess'.
     * @param string $content  Content with normalized line endings.
     * @param array  $markers  Start and end marker.
     * @param bool   $claimed  Whether the claim has run.
     * @return string
     */
    private function strip_vigilant_blocks( $filename, $content, $markers, $claimed ) {
        $pattern = '/(' . preg_quote( $markers[0], '/' ) . '.*?' . preg_quote( $markers[1], '/' ) . ')\s*/s';

        if ( ! $claimed ) {
            return preg_replace( $pattern, '', $content );
        }

        return preg_replace_callback(
            $pattern,
            function ( $match ) use ( $filename ) {
                return self::is_owned_block( $filename, $match[1] ) ? '' : $match[0];
            },
            $content
        );
    }

    /**
     * Whether a line carrying the original-constant marker is one Vigilant wrote
     *
     * comment_existing_constants() puts the marker in front of a define() of a
     * constant it manages, and uncomment_original_constants() takes it away
     * again whenever the constants are applied or removed, so whatever follows
     * the marker gets to run some day. The line is left out of the hash only
     * when there is nothing but indentation before the marker, nothing after it
     * but a harmless define() and at most a line comment, and no PHP tag
     * anywhere on it. That keeps it a comment today and harmless once
     * uncommented. Anything else counts, and shows up in the diff.
     *
     * @since 2.11.5
     *
     * @param string $line One line of wp-config.php.
     * @return bool
     */
    /**
     * Whether every marked line of a file can run nothing at all
     *
     * The question the re-base has to answer before adopting a file is whether
     * the lines that carry the marker are only comments. Asking a stricter one
     * was wrong in both directions: the first version of the guard used
     * is_vigilant_original_line(), which also requires the commented define to
     * match a known harmless shape, so it refused to re-base a perfectly inert
     * line carrying an unusual define, which is exactly the case the re-base
     * exists for, leaving the function unable to act at all. Found by the cross
     * review of 2.11.10.
     *
     * The second version read one line at a time and reasoned that the marker
     * begins with //, so a line with nothing but whitespace before it is wholly
     * a comment. That is true only where PHP is already reading code, and the
     * second cross review of 2.11.10 built three files where it is not, all of
     * them valid PHP, all of them passing that test and all of them running or
     * printing something:
     *
     *   - the marked line placed BEFORE the opening <?php, so it is inline HTML
     *     that the server prints verbatim to the browser;
     *   - the same after a ?> that the file already had;
     *   - the marked line ending a block comment opened on an earlier line and
     *     opening another one at its end, with a statement in between, which
     *     runs like any other statement.
     *
     * So the file is read the way PHP reads it, not the way the line looks. A
     * marked line is inert when every token touching it is a comment or
     * whitespace, which answers the three at once: inline HTML is not a comment,
     * and neither is a statement. The shape the guard was written for, code
     * BEFORE the marker, is the same question from the other side.
     *
     * The three shapes are in the harness as cells X2, X3 and X4 of
     * matriz-escondite-marcadores.sh, written out in full there. They are not
     * written out here on purpose: a literal payload in a shipped file is
     * signature surface for the scanners this plugin is read by, and a comment
     * is a bad place to pay for it.
     *
     * @since 2.11.10
     *
     * @param string $content Whole file content.
     * @return bool True when no marked line can run or print anything.
     */
    /**
     * The lines of a file that carry the original-value marker
     *
     * @since 2.11.10
     *
     * @param string $content Whole file content, newlines already normalised.
     * @return string[]
     */
    private function marked_lines_of( $content ) {
        $out = array();

        foreach ( explode( "\n", $content ) as $text ) {
            if ( false !== strpos( $text, $this->wpconfig_original_marker ) ) {
                $out[] = $text;
            }
        }

        return $out;
    }

    /**
     * Whether what a marked line carries would still be harmless uncommented
     *
     * Only the part after the marker matters: what comes before it is answered by
     * the token pass, which refuses anything that is not comment or whitespace.
     * Here the question is what comes BACK when uncomment_original_constants()
     * removes the marker, so the body has to be a single define() and nothing
     * else, with at most a trailing line comment. Deliberately says nothing about
     * WHICH constant it is: asking that was the first version of this guard, and
     * it refused every define it did not recognise, which is exactly the case the
     * re-base exists for.
     *
     * @since 2.11.10
     *
     * @param string $line One line carrying the marker.
     * @return bool
     */
    private function marked_line_body_is_harmless( $line ) {
        $at = strpos( $line, $this->wpconfig_original_marker );

        if ( false === $at ) {
            return true;
        }

        $body = trim( substr( $line, $at + strlen( $this->wpconfig_original_marker ) ) );

        if ( '' === $body ) {
            return true;
        }

        // Tokenised as PHP so the trailing comment, the strings and the nesting
        // are read the way PHP reads them and not with a regular expression.
        $tokens = @token_get_all( '<?php ' . $body ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A marked line can carry anything; a warning here must not be printed, and an unreadable body is refused below.

        if ( empty( $tokens ) ) {
            return false;
        }

        $statements = 0;
        $depth      = 0;

        foreach ( $tokens as $token ) {
            $type = is_array( $token ) ? $token[0] : $token;

            if ( in_array( $type, array( T_OPEN_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
                continue;
            }

            if ( '(' === $type ) {
                $depth++;
                continue;
            }

            if ( ')' === $type ) {
                $depth--;
                continue;
            }

            // A semicolon at the top level closes a statement. More than one, or
            // anything after the first, means the line carries something else.
            if ( ';' === $type && 0 === $depth ) {
                $statements++;
                continue;
            }

            if ( $statements > 0 ) {
                return false;
            }
        }

        return ( $statements <= 1 );
    }

    private function marked_lines_are_inert( $content ) {
        $content = str_replace( "\r\n", "\n", (string) $content );
        $marker  = $this->wpconfig_original_marker;

        if ( '' === $content || false === strpos( $content, $marker ) ) {
            return true;
        }

        $marked = array();

        foreach ( explode( "\n", $content ) as $index => $text ) {
            if ( false !== strpos( $text, $marker ) ) {
                $marked[ $index + 1 ] = true;
            }
        }

        // Lenient on purpose (no TOKEN_PARSE): a tampered file still has to be
        // read, and a file that cannot be tokenised is never adopted.
        // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- The file read here may have been tampered with, which is the whole point, and PHP 8 emits a warning when it cannot tokenise: printing it would put a parse error on whatever page ran the scan. An unreadable file is refused four lines below.
        $tokens = @token_get_all( $content );

        if ( empty( $tokens ) ) {
            return false;
        }

        /*
         * And the other half of the question, which the first token version left
         * out: a marked line is a COMMENTED OUT value, and uncommenting it is what
         * the feature exists for, so "runs nothing today" is not enough. Anything
         * sharing the line after the define comes back with it. The shape is real
         * and needs no attacker: comment_existing_constants() takes a define and
         * everything on its line, so
         *   define( 'WP_DEBUG', false ); @ini_set( 'display_errors', 0 );
         * is commented whole, and re-basing it would adopt as approved something
         * that runs the moment the value is restored. The old rule refused this
         * too, but along with every define whose NAME it did not recognise, which
         * is what left the function unable to act at all. Found by the third cross
         * review of 2.11.10.
         */
        foreach ( $this->marked_lines_of( $content ) as $text ) {
            if ( ! $this->marked_line_body_is_harmless( $text ) ) {
                return false;
            }
        }

        $inocuos = array( T_COMMENT, T_DOC_COMMENT, T_WHITESPACE );
        $linea   = 1;

        foreach ( $tokens as $token ) {
            $texto  = is_array( $token ) ? $token[1] : $token;
            $tipo   = is_array( $token ) ? $token[0] : null;
            $saltos = substr_count( $texto, "\n" );
            $desde  = $linea;
            $hasta  = $linea + $saltos;

            /*
             * A token whose text ends in a newline puts nothing on the line that
             * newline opens. Counting it would make the "<?php\n" of every file
             * touch line 2 and refuse the legitimate case, which is what the
             * first version of this did.
             */
            $ultima = ( $saltos > 0 && "\n" === substr( $texto, -1 ) ) ? $hasta - 1 : $hasta;
            $linea  = $hasta;

            if ( null !== $tipo && in_array( $tipo, $inocuos, true ) ) {
                continue;
            }

            for ( $l = $desde; $l <= $ultima; $l++ ) {
                if ( isset( $marked[ $l ] ) ) {
                    return false;
                }
            }
        }

        return true;
    }

    private function is_vigilant_original_line( $line ) {
        if ( false !== strpos( $line, '<?' ) || false !== strpos( $line, '?>' ) ) {
            return false;
        }

        return 1 === preg_match(
            '/^[ \t]*' . preg_quote( $this->wpconfig_original_marker, '/' ) . self::harmless_define_pattern() . '[ \t]*(?:(?:\/\/|#(?!\[)).*)?$/',
            $line
        );
    }

    /**
     * A define() that runs nothing but itself, as a regular expression fragment
     *
     * The name is one of the constants Vigilant has managed in any version. The
     * value is made only of literals (true, false, null, a number, a quoted
     * string with nothing to interpolate) and of ABSPATH, WP_CONTENT_DIR and
     * __DIR__, which is what a debug log path is usually built from, joined
     * with dots. No call, no variable, no backtick, no include.
     *
     * @since 2.11.5
     *
     * @return string Pattern without delimiters.
     */
    private static function harmless_define_pattern() {
        $names = 'DISALLOW_FILE_EDIT|DISALLOW_FILE_MODS|FORCE_SSL_ADMIN|FORCE_SSL_LOGIN|WP_DEBUG|WP_DEBUG_LOG|WP_DEBUG_DISPLAY|SCRIPT_DEBUG|DISABLE_WP_CRON'
            . '|WP_POST_REVISIONS|AUTOSAVE_INTERVAL|EMPTY_TRASH_DAYS|WP_MEMORY_LIMIT|WP_MAX_MEMORY_LIMIT|WP_AUTO_UPDATE_CORE|CONCATENATE_SCRIPTS';

        $value = '(?:(?i:true|false|null)|-?\d+|\'(?:[^\'\\\\]|\\\\.)*\'|"[^"\\\\$]*"|ABSPATH|WP_CONTENT_DIR|__DIR__)';

        return 'define\s*\(\s*[\'"](?:' . $names . ')[\'"]\s*,\s*' . $value . '(?:\s*\.\s*' . $value . ')*\s*\)\s*;';
    }

    /**
     * Whether a wp-config.php constants block can only be one Vigilant wrote
     *
     * Every version of generate_constants() has written the start marker on its
     * own line, then comments, blank lines and define() calls, bare or wrapped
     * in if ( ! defined() ), then the end marker on its own line. A block made
     * only of those lines runs nothing but the defines, whatever version wrote
     * it and whatever settings it was written with. One line of anything else,
     * or a PHP tag on any line, and the block is not taken.
     *
     * @since 2.11.5
     *
     * @param string $block   Block from start marker to end marker, inclusive.
     * @param array  $markers Start and end marker.
     * @return bool
     */
    private static function is_harmless_constants_block( $block, $markers ) {
        $lines = explode( "\n", str_replace( array( "\r\n", "\r" ), "\n", (string) $block ) );

        if ( count( $lines ) < 2
            || rtrim( array_shift( $lines ), " \t" ) !== $markers[0]
            || ltrim( array_pop( $lines ), " \t" ) !== $markers[1]
        ) {
            return false;
        }

        $define  = self::harmless_define_pattern();
        $guarded = '/^if\s*\(\s*!\s*defined\s*\(\s*[\'"][A-Z_]+[\'"]\s*\)\s*\)\s*\{\s*' . $define . '\s*\}$/';

        foreach ( $lines as $line ) {
            $line = trim( $line, " \t" );

            if ( false !== strpos( $line, '<?' ) || false !== strpos( $line, '?>' ) ) {
                return false;
            }

            if ( '' === $line
                || 0 === strpos( $line, '//' )
                || preg_match( '/^' . $define . '$/', $line )
                || preg_match( $guarded, $line )
            ) {
                continue;
            }

            return false;
        }

        return true;
    }

    /**
     * Take ownership of the blocks already on disk, once
     *
     * Fingerprints are recorded when Vigilant writes a block, which leaves every
     * block written before 2.11.5 without one. This records the blocks that can
     * be recognised as Vigilant's without having seen them written:
     *
     * - A .htaccess block, when it is exactly what Vigilant would write today
     *   with the settings it has, the timestamp and the version apart. After an
     *   update, maybe_sync_server_files() rewrites those blocks on the next
     *   request, so the claim waits for it. Unless it has already failed: a
     *   block Vigilant cannot rewrite is not going to start matching, and
     *   waiting for it would keep the old rule for good.
     * - A wp-config.php constants block, when every line in it is a comment, a
     *   blank line or a harmless define(). Nothing rewrites that block on an
     *   update and its format has changed five times, so comparing it with
     *   today's output would report every site that has not saved those
     *   settings since. A line that could run anything is never accepted.
     *
     * A block that is not recognised stays in the hash and is reported as a
     * change, so the owner gets to look at it, and the activity log says why.
     * Nothing in the stored baseline is rewritten.
     *
     * Only where the shared files belong, a single site or the main site of a
     * network, because the expected blocks come from that site's settings. Until
     * it has run, normalize_critical_file() keeps the old rule on every site.
     *
     * @since 2.11.5
     */
    /**
     * The admin_init entry point of the claim, which does ask for an administrator
     *
     * admin-ajax.php fires admin_init before it decides who is asking
     * (wp-admin/admin-ajax.php:45), so without this an anonymous request chose
     * the moment the claim runs. Unlike its two neighbours in
     * init_cleanup_hooks(), which only drop the plugin's own copy out of the
     * database, the claim writes two network options, changes for the whole
     * network the rule normalize_critical_file() applies, and re-bases the
     * approved baseline.
     *
     * The gate lives here and not inside maybe_claim_owned_blocks() because the
     * scan calls that one directly and the scan runs from wp-cron, with no user:
     * putting the capability check inside left the claim unable to complete on
     * any site whose dashboard nobody opens, and until it completes the older,
     * permissive rule is the one in force, which is the hiding place 2.11.5 was
     * written to close. Found by the cross review of 2.11.10.
     *
     * @since 2.11.10
     */
    public function maybe_claim_owned_blocks_on_admin() {
        if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $this->maybe_claim_owned_blocks();
    }

    public function maybe_claim_owned_blocks() {
        if ( $this->owned_blocks_claimed() || ! Vigilante_Settings::owns_shared_files() ) {
            return;
        }

        $sync_due = get_option( 'vigilante_server_files_pending' )
            || VIGILANTE_VERSION !== get_option( 'vigilante_server_files_version' );

        if ( $sync_due && ! get_option( 'vigilante_server_files_retry_after' ) ) {
            return;
        }

        $expected  = null;
        $unclaimed = array();

        foreach ( $this->critical_root_files as $filename ) {
            $full_path = $this->critical_file_path( $filename );

            if ( false === $full_path ) {
                continue;
            }

            $content = file_get_contents( $full_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

            if ( false === $content ) {
                // Unreadable right now: leave the claim open and try again later.
                return;
            }

            $content   = str_replace( array( "\r\n", "\r" ), "\n", $content );
            $is_config = 'wp-config.php' === $filename;

            foreach ( ( $is_config ? $this->wpconfig_markers : $this->htaccess_markers ) as $markers ) {
                $pattern = '/' . preg_quote( $markers[0], '/' ) . '.*?' . preg_quote( $markers[1], '/' ) . '/s';

                if ( ! preg_match_all( $pattern, $content, $found ) ) {
                    continue;
                }

                foreach ( $found[0] as $block ) {
                    if ( $is_config ) {
                        $ours = self::is_harmless_constants_block( $block, $markers );
                    } else {
                        $expected = null === $expected ? $this->expected_htaccess_blocks() : $expected;
                        $ours     = isset( $expected[ $markers[0] ] )
                            && self::comparable_block( $block ) === self::comparable_block( $expected[ $markers[0] ] );
                    }

                    if ( $ours ) {
                        self::remember_owned_block( $filename, $markers[0], $block, false );
                    } else {
                        $unclaimed[ $filename ] = $filename;
                    }
                }
            }

            // The commented-out originals are judged line by line at scan time.
            // Looking at them here only keeps the log entry below complete.
            if ( $is_config && preg_match_all( '/^.*' . preg_quote( $this->wpconfig_original_marker, '/' ) . '.*$/m', $content, $marked ) ) {
                foreach ( $marked[0] as $line ) {
                    if ( ! $this->is_vigilant_original_line( $line ) ) {
                        $unclaimed[ $filename ] = $filename;
                    }
                }
            }
        }

        update_site_option( self::OWNED_BLOCKS_CLAIM_OPTION, self::OWNED_BLOCKS_CLAIMED );

        // With the claim in place normalize uses the new rule, so a file nobody
        // touched whose only difference is an original line the old rule dropped
        // would read as changed. Re-base those, and only those, once.
        $this->rebase_original_line_shift();

        if ( $unclaimed && $this->activity_log ) {
            $this->activity_log->log(
                'file',
                'critical_file_unrecognized_block',
                sprintf(
                    /* translators: %s: comma-separated file names, such as wp-config.php or .htaccess. */
                    __( 'Content marked as written by Vigilant in %s does not match what Vigilant writes. From now on it is checked like the rest of the file, so the file integrity scan reports it as a change for you to review.', 'vigilante' ),
                    implode( ', ', $unclaimed )
                ),
                array( 'files' => array_values( $unclaimed ) ),
                'warning'
            );
        }
    }

    /**
     * Re-base the critical files whose only change is a newly kept original line
     *
     * Until 2.11.5 the hash left out every [VIGILANTE_ORIGINAL] line; from 2.11.5
     * it keeps the ones whose value is not a plain constant define, which is the
     * right thing for the hash but moves it on a file nobody edited: the stored
     * baseline was taken under the old rule, and nothing re-bases wp-config.php on
     * an update (maybe_sync_server_files() only rewrites the .htaccess). So the
     * first scan after updating would report wp-config.php as changed.
     *
     * This runs once, in the same pass that claims the blocks. For each file it
     * re-bases to the new hash only when the baseline still matches the file with
     * every original line dropped, which means the blocks are exactly the approved
     * ones and the sole difference is those lines, the user's own commented-out
     * defines. A block that was edited or planted does not match with the lines
     * dropped, so it is left to be reported: this closes the false positive
     * without adopting anything that was hidden before.
     *
     * @since 2.11.5
     */
    private function rebase_original_line_shift() {
        $baseline = $this->get_critical_files_baseline();
        $changed  = false;

        foreach ( $this->critical_root_files as $filename ) {
            $full_path = $this->critical_file_path( $filename );

            if ( false === $full_path || empty( $baseline[ $filename ]['hash'] ) ) {
                continue;
            }

            $content = file_get_contents( $full_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

            if ( false === $content ) {
                continue;
            }

            /*
             * Never re-base a file that carries a marked line which is not
             * wholly a comment. The test below only establishes that the
             * difference lies in lines carrying the marker, and the old rule
             * dropped the WHOLE line, so a line with a statement in front of the
             * marker satisfies it (cell X1 of matriz-escondite-marcadores.sh,
             * where the shape is written out): re-basing would write that line
             * into the approved baseline and rewrite the stored content, so the
             * diff would stop showing it. Adopting as approved what the previous rule
             * hid is the one thing an integrity scanner must never do, and the
             * log entry of maybe_claim_owned_blocks() already promises the
             * opposite ("the scan reports it as a change for you to review").
             * Those files are left to be reported. Found by the file-by-file
             * review of 2.11.10.
             *
             * What counts as "wholly a comment" is decided by reading the file
             * as PHP reads it, not by the shape of the line: see
             * marked_lines_are_inert(). A line that is not recognised is not the
             * same thing as a line that can run something, and the first
             * wording of this guard confused the two.
             */
            if ( ! $this->marked_lines_are_inert( $content ) ) {
                continue;
            }

            $current = md5( $this->normalize_critical_file( $filename, $content ) );

            // Already in step, or a real change to something other than the
            // original lines: nothing to re-base here.
            if ( $baseline[ $filename ]['hash'] === $current
                || $baseline[ $filename ]['hash'] !== md5( $this->normalize_critical_file( $filename, $content, true ) )
            ) {
                continue;
            }

            $normalized                       = $this->normalize_critical_file( $filename, $content );
            $baseline[ $filename ]['hash']    = $current;
            $baseline[ $filename ]['size']    = strlen( $content );
            $baseline[ $filename ]['content'] = $this->baseline_content( $filename, $normalized );
            $baseline[ $filename ]['updated'] = time();
            $changed                          = true;
        }

        if ( $changed ) {
            $this->write_baseline( $baseline );
        }
    }

    /**
     * The .htaccess blocks Vigilant would write today, keyed by start marker
     *
     * @since 2.11.5
     *
     * @return array
     */
    private function expected_htaccess_blocks() {
        $settings = $this->settings ? $this->settings : new Vigilante_Settings();

        $classes = array(
            'Vigilante_Htaccess_Protection' => 'class-htaccess-protection.php',
            'Vigilante_Security_Headers'    => 'class-security-headers.php',
            'Vigilante_Under_Attack'        => 'class-under-attack.php',
        );

        foreach ( $classes as $class => $file ) {
            if ( ! class_exists( $class ) ) {
                require_once VIGILANTE_INCLUDES_DIR . $file;
            }
        }

        $headers = new Vigilante_Security_Headers( $settings );

        return array(
            Vigilante_Htaccess_Protection::MARKER_START => ( new Vigilante_Htaccess_Protection( $settings ) )->generate_rules(),
            Vigilante_Security_Headers::MARKER_START    => Vigilante_Security_Headers::MARKER_START . "\n" . $headers->generate_rules_content() . "\n" . Vigilante_Security_Headers::MARKER_END,
            Vigilante_Under_Attack::HTACCESS_MARKER_START => Vigilante_Under_Attack::get_cache_bypass_block(),
        );
    }

    /**
     * A .htaccess block with the parts that change on every write evened out
     *
     * Two blocks Vigilant wrote with the same settings differ only in the time
     * they were generated and, across an update, in the version the firewall
     * block names. Everything else has to be identical for the claim to take
     * the block.
     *
     * @since 2.11.5
     *
     * @param string $block Block from start marker to end marker, inclusive.
     * @return string
     */
    private static function comparable_block( $block ) {
        $block = str_replace( array( "\r\n", "\r" ), "\n", (string) $block );
        $block = preg_replace( '/^# Generated: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$/m', '# Generated:', $block );
        $block = preg_replace( '/^# Vigilante for WordPress - Firewall v[0-9][0-9A-Za-z.\-]*$/m', '# Vigilante for WordPress - Firewall v', $block );

        return rtrim( $block, "\n" );
    }

    /**
     * Get stored baseline hashes for critical files
     *
     * @return array Associative array keyed by filename.
     */
    public function get_critical_files_baseline() {
        return $this->read_baseline();
    }

    /**
     * Update baseline hash for a single critical file
     *
     * Called by wp-config and htaccess writers after Vigilante modifies
     * the file, so the next scan does not flag the change as suspicious.
     *
     * @param string $filename File name relative to ABSPATH (e.g. 'wp-config.php').
     * @return bool True on success.
     */
    public function update_critical_file_baseline( $filename ) {
        $full_path = $this->critical_file_path( $filename );

        if ( false === $full_path ) {
            return false;
        }

        $content = file_get_contents( $full_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        if ( false === $content ) {
            return false;
        }

        $normalized = $this->normalize_critical_file( $filename, $content );

        $baseline = $this->get_critical_files_baseline();

        /*
         * No guard here, and there was one for a few hours during 2.11.4 that
         * had to come out. It refused to rewrite the record when the stored hash
         * no longer matched the file, meant to stop a write of ours from
         * approving somebody else's pending edit. Two things were wrong with it,
         * both measured on 10 sep 2026 by a third cross review:
         *
         * - This is also the Approve button (Vigilante_Admin_Ajax::
         *   ajax_approve_critical_file). A moved hash is exactly the state in
         *   which Approve is pressed, so the guard made Approve fail every time
         *   and the warning could never be closed.
         * - Its premise, "our own write cannot move the normalized hash", holds
         *   for the block and not for the rest of what the writers do.
         *   comment_existing_constants() turns a define() into a
         *   [VIGILANTE_ORIGINAL] line that normalize_critical_file() leaves as
         *   an empty line, and remove_old_rules() deletes legacy .htaccess blocks
         *   that normalize_critical_file() does not know. Both move the hash, so
         *   the guard would have raised a false "file modified" after Vigilant's
         *   own work, on sites that updated.
         *
         * The real fix is to know what the hash was before WE touched the file:
         * the writers capture it and pass it along vigilante_critical_file_
         * written, and this compares against that instead of against the
         * record. Until then this behaves as it always has, which does mean a
         * write of ours can adopt a third-party edit that was pending review.
         * That is pre-existing, and written down in the roadmap.
         */
        $baseline[ $filename ] = array(
            'hash'    => md5( $normalized ),
            'size'    => strlen( $content ),
            'content' => $this->baseline_content( $filename, $normalized ),
            'updated' => time(),
        );

        return $this->write_baseline( $baseline );
    }

    /**
     * Regenerate baseline for all critical files
     *
     * Used by the admin UI button and the 1.14.0 migration.
     *
     * @return array Updated baseline data.
     */
    public function regenerate_all_baselines() {
        $baseline  = array();

        foreach ( $this->critical_root_files as $filename ) {
            $full_path = $this->critical_file_path( $filename );

            if ( false === $full_path ) {
                continue;
            }

            $content = file_get_contents( $full_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            if ( false === $content ) {
                continue;
            }

            $normalized = $this->normalize_critical_file( $filename, $content );
            $baseline[ $filename ] = array(
                'hash'    => md5( $normalized ),
                'size'    => strlen( $content ),
                'content' => $this->baseline_content( $filename, $normalized ),
                'updated' => time(),
            );
        }

        $this->write_baseline( $baseline );

        return $baseline;
    }

    /**
     * Get core checksums from WordPress.org API
     *
     * @param bool $force_refresh Skip the cached copy and ask wp.org again.
     * @return array|WP_Error Checksums or error.
     */
    private function get_core_checksums( $force_refresh = false, $locale = null, $english_fallback = true ) {
        $locale = null === $locale ? get_locale() : $locale;
        $version = $this->wp_version;
        
        // Check cache first
        $cache_key = 'vigilante_core_checksums_' . md5( $version . $locale );

        if ( $force_refresh ) {
            delete_transient( $cache_key );
        }

        $cached = get_transient( $cache_key );
        if ( false !== $cached ) {
            return $cached;
        }

        // Fetch from WordPress.org
        $url = sprintf(
            'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
            $version,
            $locale
        );

        $response = wp_remote_get( $url, array( 'timeout' => $this->checksum_timeout() ) );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body['checksums'] ) ) {
            /*
             * WordPress.org has no list for this version in this language. That
             * is the normal state of every site that is not in English for the
             * hours or days after a release, until the package of its language
             * is built, and of the languages that never get one. Until now the
             * core was then not compared at all. Those sites run the English
             * files, so the English list is the one to compare with. It is not
             * kept under this language, so the next scan asks again.
             */
            if ( 'en_US' !== $locale && $english_fallback ) {
                $english = $this->get_core_checksums( $force_refresh, 'en_US' );

                if ( is_array( $english ) ) {
                    $this->core_checksums_are_english = true;
                    return $english;
                }
            }

            return new WP_Error( 'no_checksums', __( 'Could not retrieve WordPress core checksums', 'vigilante' ) );
        }

        $checksums = $body['checksums'];

        // Handle nested format: checksums keyed under version string (WP 6.9+)
        if ( isset( $checksums[ $version ] ) && is_array( $checksums[ $version ] ) ) {
            $checksums = $checksums[ $version ];
        }

        // Cache for 24 hours
        set_transient( $cache_key, $checksums, DAY_IN_SECONDS );

        return $checksums;
    }

    /**
     * Whether a core file is the official copy of another language
     *
     * The checksums are asked for in the language of the site, and a site does
     * not always run the package of its language: one installed in English and
     * switched to Spanish afterwards keeps the English files, so its
     * version.php and its wp-config-sample.php do not match the Spanish list.
     * That is why version.php used to be left out of the comparison altogether,
     * which left a file WordPress loads on every request unchecked. A file that
     * matches the official copy of the same version in English, or in the
     * language its own package declares, is an official file. The language
     * only chooses which official list to look at: a file that was tampered
     * with matches none of them.
     *
     * @param string $file        Path relative to the WordPress root.
     * @param string $actual_hash md5 of the file on disk.
     * @return bool
     */
    private function matches_core_of_other_locale( $file, $actual_hash ) {
        $current = get_locale();
        $others  = array( 'en_US' );

        if ( ! empty( $GLOBALS['wp_local_package'] ) && is_string( $GLOBALS['wp_local_package'] ) ) {
            $others[] = $GLOBALS['wp_local_package'];
        }

        foreach ( array_unique( $others ) as $locale ) {
            if ( $locale === $current || ! preg_match( '/^[A-Za-z0-9_]{2,24}$/', $locale ) ) {
                continue;
            }

            // Without the English list in its place: asking about another
            // language must not leave the scan believing that the list of the
            // site itself was missing.
            $checksums = $this->get_core_checksums( false, $locale, false );

            if ( is_array( $checksums ) && isset( $checksums[ $file ] ) && $checksums[ $file ] === $actual_hash ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Scan plugins for modifications
     *
     * @return array Scan results.
     */
    private function scan_plugins() {
        $results = array(
            'scanned'    => 0,
            'ok'         => 0,
            'modified'   => array(),
            'suspicious' => array(),
            'extra'      => array(),
            'errors'     => array(),
        );

        // Get all installed plugins
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugins  = get_plugins();
        $finished = array();

        foreach ( $plugins as $plugin_file => $plugin_data ) {
            // Check time limit
            if ( $this->is_time_exceeded() ) {
                break;
            }

            $plugin_slug = dirname( $plugin_file );

            if ( ! $this->plugin_has_turn( $plugin_slug ) ) {
                continue;
            }

            // Get checksums from WordPress.org
            $version = $plugin_data['Version'] ?? '';
            $checksums = $this->get_plugin_checksums( $plugin_slug, $version );

            $has_checksums = ! is_wp_error( $checksums ) && 'not_found' !== $checksums;

            // Say which plugins could not be compared, and why. A plugin that
            // is not on WordPress.org is named as such; a failed request is an
            // error of this scan, not a plugin without an official copy.
            if ( is_wp_error( $checksums ) ) {
                $results['errors'][] = sprintf(
                    /* translators: 1: Plugin name, 2: What went wrong */
                    __( 'The plugin %1$s could not be compared with its copy on WordPress.org: %2$s', 'vigilante' ),
                    $plugin_data['Name'] ?? $plugin_slug,
                    $checksums->get_error_message()
                );
            } elseif ( ! $has_checksums ) {
                $results['unverified'][] = $plugin_data['Name'] ?? $plugin_slug;
            }

            $plugin_dir = WP_PLUGIN_DIR . '/' . $plugin_slug;

            // Check known files against checksums (only if available)
            if ( $has_checksums ) {
                foreach ( $checksums as $file => $expected_hash ) {
                // Check time limit inside inner loop too
                if ( $this->is_time_exceeded() ) {
                    break 2; // Break both loops
                }

                $file_path = $plugin_dir . '/' . $file;

                // Skip excluded paths
                if ( $this->is_path_excluded( $file_path ) ) {
                    continue;
                }

                // Skip excluded extensions
                if ( $this->is_extension_excluded( $file_path ) ) {
                    continue;
                }

                // Skip known false positives (e.g. readme.txt, readme.md)
                if ( in_array( $file, $this->plugin_known_false_positives, true ) ) {
                    continue;
                }

                $results['scanned']++;

                if ( ! file_exists( $file_path ) ) {
                    // Reported, and not just skipped: a file that is in the
                    // published copy and not on the server is part of what
                    // the scan found.
                    $results['missing'][] = array(
                        'file'   => 'plugins/' . $plugin_slug . '/' . $file,
                        'type'   => 'plugin',
                        'plugin' => $plugin_data['Name'] ?? $plugin_slug,
                    );
                    continue;
                }

                if ( ! $this->hash_matches_published( $file_path, $expected_hash ) ) {
                    $results['modified'][] = array(
                        'file'          => 'plugins/' . $plugin_slug . '/' . $file,
                        'type'          => 'plugin',
                        'plugin'        => $plugin_data['Name'],
                        'expected_hash' => $this->expected_hash_label( $expected_hash ),
                        'actual_hash'   => md5_file( $file_path ),
                    );
                } else {
                    $results['ok']++;
                }
            }
            } // end if $has_checksums

            // Detect extra/suspicious files
            // With checksums: finds files not in the original distribution
            // Without checksums: scans ALL plugin files but only flags suspicious patterns
            if ( ! $this->is_time_exceeded() ) {
                $known_files    = $has_checksums ? $checksums : array();
                $suspicious_only = ! $has_checksums; // Without checksums, only report files with suspicious code
                $extra_results  = $this->detect_extra_files( $plugin_dir, $known_files, 'plugin', $plugin_data['Name'], $suspicious_only );
                $results['extra'] = array_merge( $results['extra'] ?? array(), $extra_results['extra'] );
                $results['suspicious'] = array_merge( $results['suspicious'] ?? array(), $extra_results['suspicious'] );
                $results['errors'] = array_merge( $results['errors'] ?? array(), $extra_results['errors'] ?? array() );
            }

            // The plugin had its whole turn. The one the time runs out on
            // does not get here with time left, and is named with the ones
            // behind it.
            if ( ! $this->is_time_exceeded() ) {
                $finished[ $plugin_file ] = true;

                // Its folder, as a line for Excluded Paths: what a partial
                // scan offers so that the next one spends its time on the
                // rest. One that is already excluded was not looked at.
                if ( ! $this->is_path_excluded( $plugin_dir . '/.' ) ) {
                    $results['checked'][] = $this->relative_path( $plugin_dir );
                }
            }
        }

        // The plugins the time did not reach, by name.
        $results['not_checked'] = array();

        foreach ( $plugins as $plugin_file => $plugin_data ) {
            if ( isset( $finished[ $plugin_file ] ) || ! $this->plugin_has_turn( dirname( $plugin_file ) ) ) {
                continue;
            }

            $results['not_checked'][] = (string) ( $plugin_data['Name'] ?? dirname( $plugin_file ) );
        }

        // Must-use plugins, drop-ins and loose PHP files, which have no
        // official copy and no entry in the list above.
        $results['unlisted_checked'] = false;

        if ( ! $this->is_time_exceeded() ) {
            $unlisted = $this->scan_unlisted_code();

            $results['extra']      = array_merge( $results['extra'] ?? array(), $unlisted['extra'] );
            $results['suspicious'] = array_merge( $results['suspicious'] ?? array(), $unlisted['suspicious'] );
            $results['unverified'] = array_merge( $results['unverified'] ?? array(), $unlisted['unverified'] );
            $results['errors']     = array_merge( $results['errors'] ?? array(), $unlisted['errors'] );

            $results['unlisted_checked'] = ! $this->is_time_exceeded();
        }

        return $results;
    }

    /**
     * Whether a plugin gets a turn of its own in scan_plugins()
     *
     * @param string $plugin_slug Folder of the plugin, or "." for a single file.
     * @return bool
     */
    private function plugin_has_turn( $plugin_slug ) {
        // Single-file plugins are loose PHP files: scan_unlisted_code().
        if ( '.' === $plugin_slug ) {
            return false;
        }

        // With the self-check on, Vigilant itself is verified by the
        // sha256 triple-anchor block at the start of run_scan(): scanning
        // it here again would duplicate findings and the md5 fetch. With
        // the check off by filter, Vigilant is a regular plugin (legacy
        // behaviour).
        if ( dirname( VIGILANTE_PLUGIN_BASENAME ) === $plugin_slug && Vigilante_Self_Integrity::is_on() ) {
            return false;
        }

        // Skip slugs in their post-update grace window: wp.org may still be
        // publishing the new version's checksums, so a scheduled scan here
        // would raise benign "modified/extra" noise. The dedicated post-update
        // verifier (vigilante_fi_postupdate_verify) handles these instead.
        return ! $this->in_post_update_grace( 'plugin', $plugin_slug );
    }

    /**
     * Whether a file on disk matches a hash WordPress.org publishes for it.
     *
     * The wp.org checksums JSON gives, per file, an md5 (and usually a sha256)
     * that may be a single string OR an array of strings: a file whose content
     * differs across the re-tagged zips that one checksums file covers (e.g. a
     * release that shares its checksums file with a beta) gets every valid hash
     * listed as an array. The old `$actual !== $expected` comparison evaluated a
     * 32-char string against an array as unequal unconditionally, so those files
     * were always reported as "modified" even when the on-disk hash was one of
     * the published ones. Match against membership, and accept either md5 or
     * sha256, so the comparison is correct and strictly stronger than md5-only.
     *
     * Robust to both shapes: the new record array( 'md5' => ..., 'sha256' => ... )
     * and a legacy cached value (a bare md5 string or array), so a transient
     * cached by an older version still compares correctly until it expires.
     *
     * @param string       $file_path Absolute path to the file on disk.
     * @param array|string $expected  Record array, or a legacy md5 string|array.
     * @return bool True when the file matches a published hash.
     */
    private function hash_matches_published( $file_path, $expected ) {
        $md5 = $expected;
        $sha = null;
        if ( is_array( $expected ) && ( array_key_exists( 'md5', $expected ) || array_key_exists( 'sha256', $expected ) ) ) {
            $md5 = isset( $expected['md5'] ) ? $expected['md5'] : null;
            $sha = isset( $expected['sha256'] ) ? $expected['sha256'] : null;
        }

        if ( null !== $md5 && in_array( md5_file( $file_path ), (array) $md5, true ) ) {
            return true;
        }
        if ( ! empty( $sha ) && in_array( hash_file( 'sha256', $file_path ), (array) $sha, true ) ) {
            return true;
        }

        // Fallback: some hosts and deploy pipelines rewrite text files on disk
        // (prepend a UTF-8 BOM, or convert LF line endings to CRLF) without
        // changing a single line of code. That alters the raw bytes, so the
        // md5/sha256 stops matching WordPress.org even though the file is
        // intact, which surfaced as false "modified file" alerts. Retry the
        // comparison against a normalized copy (BOM stripped, CRLF/CR collapsed
        // to LF) for text files only, so a genuine code change is still caught.
        if ( is_string( $file_path ) && '' !== $file_path && $this->is_text_file( $file_path ) && is_readable( $file_path ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file read for hashing, not remote.
            $content = file_get_contents( $file_path );
            if ( false !== $content ) {
                if ( "\xEF\xBB\xBF" === substr( $content, 0, 3 ) ) {
                    $content = substr( $content, 3 );
                }
                $content = str_replace( array( "\r\n", "\r" ), "\n", $content );
                if ( null !== $md5 && in_array( md5( $content ), (array) $md5, true ) ) {
                    return true;
                }
                if ( ! empty( $sha ) && in_array( hash( 'sha256', $content ), (array) $sha, true ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Human-readable expected-hash value for a modified-file result record.
     *
     * The published md5 may be a string or an array; flatten it for storage.
     *
     * @param array|string $expected Record array or legacy md5 string|array.
     * @return string
     */
    private function expected_hash_label( $expected ) {
        $md5 = ( is_array( $expected ) && array_key_exists( 'md5', $expected ) ) ? $expected['md5'] : $expected;
        if ( is_array( $md5 ) ) {
            return implode( ', ', array_map( 'strval', $md5 ) );
        }
        return (string) $md5;
    }

    /**
     * Whether a plugin/theme slug is inside its post-update grace window.
     *
     * Set by on_upgrade_complete() right after WordPress finishes updating a
     * plugin or theme. During the window the checksum cache is bypassed (so a
     * stale manifest cached during wp.org's propagation lag is never reused) and
     * the scheduled scan skips the slug (the dedicated post-update verifier
     * handles it instead), which is what stops the "files don't match
     * WordPress.org" false positives right after an update.
     *
     * @param string $type 'plugin' or 'theme'.
     * @param string $slug Slug.
     * @return bool
     */
    private function in_post_update_grace( $type, $slug ) {
        return (bool) get_transient( 'vigilante_fi_grace_' . $type . '_' . md5( $slug ) );
    }

    /**
     * Get plugin checksums from WordPress.org
     *
     * @param string $slug    Plugin slug.
     * @param string $version Plugin version.
     * @return array|WP_Error|string
     */
    private function get_plugin_checksums( $slug, $version ) {
        $cache_key = 'vigilante_plugin_checksums_' . md5( $slug . $version );

        // During the post-update grace window, bypass the cache entirely so a
        // manifest cached while wp.org was still propagating the new version's
        // checksums can never be reused. Fetch fresh and do not write it back.
        $grace = $this->in_post_update_grace( 'plugin', $slug );

        if ( ! $grace ) {
            $cached = get_transient( $cache_key );
            if ( false !== $cached ) {
                return $cached;
            }
        }

        $url = sprintf(
            'https://downloads.wordpress.org/plugin-checksums/%s/%s.json',
            $slug,
            $version
        );

        $response = wp_remote_get( $url, array( 'timeout' => $this->checksum_timeout() ) );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $status = wp_remote_retrieve_response_code( $response );
        if ( 404 === (int) $status ) {
            // Cache "not found" to avoid repeated requests (never during grace).
            if ( ! $grace ) {
                set_transient( $cache_key, 'not_found', HOUR_IN_SECONDS );
            }
            return 'not_found';
        }

        if ( 200 !== (int) $status ) {
            // WordPress.org answered, but not with the checksums. An outage is
            // not a plugin with no published copy, and until now it passed
            // for one: the plugin was quietly left uncompared.
            return new WP_Error(
                'http_error',
                /* translators: %d: HTTP status code */
                sprintf( __( 'WordPress.org answered with status %d', 'vigilante' ), (int) $status )
            );
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body['files'] ) ) {
            return new WP_Error( 'no_checksums', __( 'No checksums found', 'vigilante' ) );
        }

        // Store the full per-file record (md5 + sha256). Either value can be a
        // string or an array of strings; hash_matches_published() handles both.
        $checksums = array();
        foreach ( $body['files'] as $file => $data ) {
            $checksums[ $file ] = array(
                'md5'    => isset( $data['md5'] ) ? $data['md5'] : null,
                'sha256' => isset( $data['sha256'] ) ? $data['sha256'] : null,
            );
        }

        // Cache for 24 hours (never during grace, to avoid persisting a manifest
        // wp.org may still be regenerating).
        if ( ! $grace ) {
            set_transient( $cache_key, $checksums, DAY_IN_SECONDS );
        }

        return $checksums;
    }

    /**
     * Scan themes for modifications
     *
     * @return array Scan results.
     */
    private function scan_themes() {
        $results = array(
            'scanned'    => 0,
            'ok'         => 0,
            'modified'   => array(),
            'suspicious' => array(),
            'extra'      => array(),
            'errors'     => array(),
        );

        $themes   = wp_get_themes();
        $finished = array();

        foreach ( $themes as $theme_slug => $theme ) {
            // Check time limit
            if ( $this->is_time_exceeded() ) {
                break;
            }

            // Skip slugs in their post-update grace window (see scan_plugins()).
            if ( $this->in_post_update_grace( 'theme', $theme_slug ) ) {
                continue;
            }

            $version = $theme->get( 'Version' );
            $checksums = $this->get_theme_checksums( $theme_slug, $version );

            $has_checksums = ! is_wp_error( $checksums ) && 'not_found' !== $checksums;

            // Same as for plugins: name what could not be compared, and why.
            if ( is_wp_error( $checksums ) && 'not_found' !== $checksums->get_error_code() ) {
                $results['errors'][] = sprintf(
                    /* translators: 1: Theme name, 2: What went wrong */
                    __( 'The theme %1$s could not be compared with its copy on WordPress.org: %2$s', 'vigilante' ),
                    $theme->get( 'Name' ),
                    $checksums->get_error_message()
                );
            } elseif ( ! $has_checksums ) {
                $results['unverified'][] = $theme->get( 'Name' );
            }

            $theme_dir = $theme->get_stylesheet_directory();

            // Check known files against checksums (only if available)
            if ( $has_checksums ) {
            foreach ( $checksums as $file => $expected_hash ) {
                // Check time limit inside inner loop too
                if ( $this->is_time_exceeded() ) {
                    break 2; // Break both loops
                }

                $file_path = $theme_dir . '/' . $file;

                // Skip excluded paths
                if ( $this->is_path_excluded( $file_path ) ) {
                    continue;
                }

                // Skip excluded extensions
                if ( $this->is_extension_excluded( $file_path ) ) {
                    continue;
                }

                // Skip known false positives (e.g. readme.txt, readme.md)
                if ( in_array( $file, $this->plugin_known_false_positives, true ) ) {
                    continue;
                }

                $results['scanned']++;

                if ( ! file_exists( $file_path ) ) {
                    $results['missing'][] = array(
                        'file'  => 'themes/' . $theme_slug . '/' . $file,
                        'type'  => 'theme',
                        'theme' => $theme->get( 'Name' ),
                    );
                    continue;
                }

                if ( ! $this->hash_matches_published( $file_path, $expected_hash ) ) {
                    $results['modified'][] = array(
                        'file'          => 'themes/' . $theme_slug . '/' . $file,
                        'type'          => 'theme',
                        'theme'         => $theme->get( 'Name' ),
                        'expected_hash' => $this->expected_hash_label( $expected_hash ),
                        'actual_hash'   => md5_file( $file_path ),
                    );
                } else {
                    $results['ok']++;
                }
            }
            } // end if $has_checksums

            // Detect extra/suspicious files
            if ( ! $this->is_time_exceeded() ) {
                $known_files    = $has_checksums ? $checksums : array();
                $suspicious_only = ! $has_checksums;
                $extra_results  = $this->detect_extra_files( $theme_dir, $known_files, 'theme', $theme->get( 'Name' ), $suspicious_only );
                $results['extra'] = array_merge( $results['extra'] ?? array(), $extra_results['extra'] );
                $results['suspicious'] = array_merge( $results['suspicious'] ?? array(), $extra_results['suspicious'] );
                $results['errors'] = array_merge( $results['errors'] ?? array(), $extra_results['errors'] ?? array() );
            }

            // Same as for plugins: a whole turn, with time left.
            if ( ! $this->is_time_exceeded() ) {
                $finished[ $theme_slug ] = true;

                if ( ! $this->is_path_excluded( $theme_dir . '/.' ) ) {
                    $results['checked'][] = $this->relative_path( $theme_dir );
                }
            }
        }

        // The themes the time did not reach, by name.
        $results['not_checked'] = array();

        foreach ( $themes as $theme_slug => $theme ) {
            if ( isset( $finished[ $theme_slug ] ) || $this->in_post_update_grace( 'theme', $theme_slug ) ) {
                continue;
            }

            $results['not_checked'][] = (string) $theme->get( 'Name' );
        }

        return $results;
    }

    /**
     * Get theme checksums from WordPress.org
     *
     * @param string $slug    Theme slug.
     * @param string $version Theme version.
     * @return array|WP_Error
     */
    private function get_theme_checksums( $slug, $version ) {
        $cache_key = 'vigilante_theme_package_' . md5( $slug . $version );

        // Bypass the cache during the post-update grace window (see plugin path).
        $grace = $this->in_post_update_grace( 'theme', $slug );

        if ( ! $grace ) {
            $cached = get_transient( $cache_key );
            if ( false !== $cached ) {
                return $cached;
            }
        }

        /*
         * WordPress.org publishes checksums for plugins and for core, and none
         * for themes: the address this method asked until now answers 404 for
         * every theme, so no theme was ever compared with anything and they
         * were all treated as themes from elsewhere. What WordPress.org does
         * publish is the package of each version, so the checksums are taken
         * from there: the package is downloaded once per version, each file in
         * it is hashed straight from the archive, nothing is unpacked to disk,
         * and the result is kept for a month.
         */
        if ( '' === (string) $version || ! preg_match( '/^[A-Za-z0-9._-]+$/', (string) $slug ) ) {
            return new WP_Error( 'not_found', __( 'Checksums not available', 'vigilante' ) );
        }

        if ( ! class_exists( 'ZipArchive' ) ) {
            return new WP_Error( 'no_zip', __( 'the zip extension of PHP is missing on this server', 'vigilante' ) );
        }

        if ( ! function_exists( 'download_url' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        $package = download_url(
            sprintf( 'https://downloads.wordpress.org/theme/%s.%s.zip', rawurlencode( $slug ), rawurlencode( (string) $version ) ),
            30
        );

        if ( is_wp_error( $package ) ) {
            $data = $package->get_error_data();

            // WordPress.org has no such theme or no such version: a theme from
            // somewhere else. Anything other than a 404 is a failed download,
            // and is reported as that instead of passing for a theme with no
            // official copy.
            if ( is_array( $data ) && isset( $data['code'] ) && 404 === (int) $data['code'] ) {
                if ( ! $grace ) {
                    set_transient( $cache_key, 'not_found', 12 * HOUR_IN_SECONDS );
                }
                return new WP_Error( 'not_found', __( 'Checksums not available', 'vigilante' ) );
            }

            return $package;
        }

        $checksums = array();
        $archive   = new ZipArchive();

        if ( true === $archive->open( $package ) ) {
            $prefix    = $slug . '/';
            $max_entry = 16 * MB_IN_BYTES;

            for ( $i = 0; $i < $archive->numFiles; $i++ ) {
                $entry = $archive->statIndex( $i );
                $name  = is_array( $entry ) ? (string) $entry['name'] : '';

                // Everything in the package lives under the folder of the theme.
                // Folders, anything outside it and any path with a ".."
                // segment are not files of the theme.
                if ( '' === $name || '/' === substr( $name, -1 ) || 0 !== strpos( $name, $prefix ) || preg_match( '#(?:^|/)\.\.(?:/|$)#', $name ) ) {
                    continue;
                }

                // Read up to a limit: an entry larger than this is not code,
                // and is left out of the comparison instead of being loaded
                // whole into memory.
                $content = $archive->getFromIndex( $i, $max_entry + 1 );

                if ( false === $content ) {
                    $checksums = array();
                    break;
                }

                if ( strlen( $content ) > $max_entry ) {
                    continue;
                }

                $checksums[ substr( $name, strlen( $prefix ) ) ] = array(
                    'md5'    => md5( $content ),
                    'sha256' => hash( 'sha256', $content ),
                );
            }

            $archive->close();
        }

        wp_delete_file( $package );

        if ( empty( $checksums ) ) {
            return new WP_Error( 'no_checksums', __( 'the package from WordPress.org could not be read', 'vigilante' ) );
        }

        // The package of a published version does not change, so it is kept
        // for a month (never during grace).
        if ( ! $grace ) {
            set_transient( $cache_key, $checksums, MONTH_IN_SECONDS );
        }

        return $checksums;
    }

    /**
     * Scan uploads directory for suspicious files
     *
     * @return array Array with 'suspicious' and 'extra' sub-arrays.
     */
    private function scan_uploads() {
        $found = array(
            'suspicious' => array(),
            'extra'      => array(),
            'errors'     => array(),
        );
        $upload_dir = wp_upload_dir();
        $base_dir = $upload_dir['basedir'];
        $files_checked = 0;

        // The walk used to stop after 10,000 files without saying so, and a
        // media library passes that with a few thousand images. Now it goes on
        // for as long as its share of the scan time lasts, and says so when it
        // is cut short. The share keeps a huge library from leaving the core
        // and the plugins without their turn.
        $deadline = $this->scan_start_time > 0 ? $this->scan_start_time + ( 0.4 * $this->max_scan_time ) : 0;

        // Executable extensions that should never be in uploads
        $dangerous_extensions = self::php_extensions();

        // Files that change how PHP runs in the folder they are in.
        $php_config_files = array( '.user.ini', 'php.ini' );

        // Scripts a server can be told to run through CGI.
        $script_extensions = array( 'cgi', 'pl', 'py', 'sh', 'shtml' );

        if ( ! is_dir( $base_dir ) ) {
            return $found;
        }

        try {
            foreach ( self::walk_folder( $base_dir ) as $file ) {
                // Check global time limit
                if ( $this->is_time_exceeded() ) {
                    break;
                }

                if ( $file->isDir() ) {
                    if ( ! $file->isReadable() ) {
                        $found['errors'][] = self::unreadable_folder_error( $file->getPathname() );
                    }
                    continue;
                }

                // Check the share of the scan time (every 500 files)
                $files_checked++;
                if ( $deadline > 0 && 0 === $files_checked % 500 && microtime( true ) > $deadline ) {
                    $found['errors'][] = sprintf(
                        /* translators: %s: Number of files */
                        __( 'The uploads folder was not checked completely: the time for it ran out after %s files.', 'vigilante' ),
                        number_format_i18n( $files_checked )
                    );
                    break;
                }

                $file_path = $file->getPathname();
                $basename  = basename( $file_path );
                $extension = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
                $relative  = str_replace( ABSPATH, '', $file_path );

                // Skip excluded paths
                if ( $this->is_path_excluded( $file_path ) ) {
                    continue;
                }

                // 1. Check for PHP files in uploads (most important security check)
                if ( in_array( $extension, $dangerous_extensions, true ) ) {
                    // Silence-is-golden placeholders are dropped by WordPress and many
                    // plugins into upload subfolders to block directory listings.
                    // Whitelist by content so an attacker can't bypass the rule with
                    // a payload named index.php.
                    if ( $this->is_silence_golden_file( $file_path ) ) {
                        continue;
                    }

                    $reason = __( 'PHP file found in uploads directory', 'vigilante' );

                    // Scan content for specific suspicious patterns
                    $pattern = $this->search_file( $file_path );
                    if ( $pattern ) {
                        /* translators: %s: Suspicious pattern found */
                        $reason = sprintf( __( 'PHP in uploads with suspicious code: %s', 'vigilante' ), $pattern );
                    }

                    $found['suspicious'][] = array(
                        'file'   => $relative,
                        'type'   => 'php_in_uploads',
                        'reason' => $reason,
                    );
                    continue;
                }

                // 2. Check for double extensions (image.php.jpg, file.phtml.png)
                // The second extension can be anything: a script renamed by a
                // malware cleaner (shell.php.suspected) or numbered (shell.php.1)
                // is as much of a finding as one dressed up as an image.
                if ( preg_match( '/\.(' . implode( '|', $dangerous_extensions ) . ')\.[a-z0-9_~-]{1,16}$/i', $basename ) ) {
                    $found['suspicious'][] = array(
                        'file'   => $relative,
                        'type'   => 'double_extension',
                        'reason' => __( 'Double extension detected (possible disguised executable)', 'vigilante' ),
                    );
                    continue;
                }

                // 2b. Files that change how PHP runs in this folder
                if ( in_array( strtolower( $basename ), $php_config_files, true ) ) {
                    $found['suspicious'][] = array(
                        'file'   => $relative,
                        'type'   => 'php_config_in_uploads',
                        'reason' => __( 'PHP configuration file in uploads', 'vigilante' ),
                    );
                    continue;
                }

                // 2c. Scripts in other languages
                if ( in_array( $extension, $script_extensions, true ) ) {
                    $found['extra'][] = array(
                        'file'   => $relative,
                        'type'   => 'script_in_uploads',
                        'reason' => __( 'Script file in uploads', 'vigilante' ),
                    );
                    continue;
                }

                // 3. Check for .htaccess files in uploads
                // Read content to classify (see classify_htaccess_in_uploads())
                if ( '.htaccess' === $basename ) {
                    $htaccess_result = $this->classify_htaccess_in_uploads( $file_path, $relative );

                    // One that only denies access, or does nothing, is not a finding.
                    if ( 'none' !== $htaccess_result['category'] ) {
                        $found[ $htaccess_result['category'] ][] = $htaccess_result['item'];
                    }
                }
            }
        } catch ( Exception $e ) {
            $found['errors'][] = self::unreadable_folder_error( $base_dir );
        }

        return $found;
    }

    /**
     * Classify a .htaccess file found in uploads directory
     *
     * The file is read the way Apache reads it: continued lines are joined,
     * comments are dropped and each directive is looked at on its own. That
     * replaces a handful of expressions run over the whole text, which took a
     * commented line for a live one and the rule that forbids PHP for one that
     * runs it, and let through the directives that turn CGI on.
     *
     * - Something that makes the server run code: suspicious.
     * - Only directives that deny or switch something off: not reported.
     * - Rewrite rules of its own and nothing that denies PHP: extra, because in
     *   that folder they replace the rules of the site root, the one that
     *   blocks PHP in uploads included (measured on Apache, 3 Oct 2026).
     * - Anything else: extra, with what it contains.
     *
     * @param string $file_path Absolute file path.
     * @param string $relative  Relative file path for display.
     * @return array Array with 'category' ('suspicious', 'extra' or 'none') and 'item' data.
     */
    private function classify_htaccess_in_uploads( $file_path, $relative ) {
        $content = false;

        if ( filesize( $file_path ) < 65536 ) { // Only read files < 64KB
            $content = file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        }

        $item = array(
            'file' => $relative,
            'type' => 'htaccess_in_uploads',
        );

        // A file that cannot be read cannot be vouched for.
        if ( false === $content ) {
            $item['reason'] = __( '.htaccess file in uploads directory that could not be read', 'vigilante' );

            return array(
                'category' => 'suspicious',
                'item'     => $item,
            );
        }

        $facts = self::read_htaccess_rules( $content );

        if ( ! empty( $facts['runs'] ) ) {
            $item['reason'] = self::htaccess_run_reason( $facts );

            return array(
                'category' => 'suspicious',
                'item'     => $item,
            );
        }

        if ( $facts['rewrite'] && ! $facts['denies_php'] ) {
            // Until 3.0.6 this said that the rule against PHP in uploads was
            // replaced with them, everywhere. Since 3.0.7 that rule has a second
            // half that a folder's rewrite rules do not replace on Apache 2.4
            // (see Vigilante_Htaccess_Protection), so the text says where it
            // still holds.
            $item['reason'] = __( '.htaccess in uploads with rewrite rules of its own: in this folder they replace the rewrite rules of the site root, and outside Apache 2.4 that includes the rule that blocks PHP in uploads', 'vigilante' );

            return array(
                'category' => 'extra',
                'item'     => $item,
            );
        }

        // Empty, or nothing in it that does not deny or switch something off:
        // it protects the folder, or does nothing, and is not a finding.
        if ( empty( $facts['other'] ) ) {
            return array(
                'category' => 'none',
                'item'     => null,
            );
        }

        $kinds = array(
            'access'  => __( 'access rules', 'vigilante' ),
            'rewrite' => __( 'rewrite rules', 'vigilante' ),
            'headers' => __( 'cache or header rules', 'vigilante' ),
            'other'   => __( 'other rules', 'vigilante' ),
        );

        /* translators: %s: Summary of rules found in the .htaccess file */
        $item['reason'] = sprintf( __( '.htaccess in uploads (likely from plugin). Contains: %s', 'vigilante' ), implode( ', ', array_intersect_key( $kinds, $facts['other'] ) ) );

        return array(
            'category' => 'extra',
            'item'     => $item,
        );
    }

    /**
     * The reason shown for a .htaccess that makes the server run code
     *
     * @param array $facts What read_htaccess_rules() found.
     * @return string
     */
    private static function htaccess_run_reason( $facts ) {
        $labels = array(
            'run'     => __( 'makes the server run files of this folder as code', 'vigilante' ),
            'load'    => __( 'loads a file on every PHP request', 'vigilante' ),
            'rewrite' => __( 'sends requests to a PHP file', 'vigilante' ),
            'cgi'     => __( 'turns on CGI or server-side includes', 'vigilante' ),
        );

        /* translators: %s: What the rule does */
        return sprintf( __( '.htaccess with a rule that affects how code runs: %s', 'vigilante' ), implode( '; ', array_intersect_key( $labels, $facts['runs'] ) ) );
    }

    /**
     * What a section of a .htaccess says about the directives inside it
     *
     * @param string $name Section name, in lower case.
     * @param string $args What follows the name, as written.
     * @return string '' when it changes nothing (<RequireAll>), 'rewrite' for
     *                <IfModule mod_rewrite.c>, 'maybe' for any other test of
     *                what the server has, 'files-php' for a <Files> or
     *                <FilesMatch> that names PHP files, 'files' for one that
     *                names other files, and 'condition' for the rest (<Limit>,
     *                <If>, <RequireAny>...), which apply to some requests only.
     */
    private static function htaccess_section_kind( $name, $args ) {
        $args = trim( rtrim( trim( $args ), '>' ) );

        if ( 'requireall' === $name ) {
            return '';
        }

        if ( 'ifmodule' === $name ) {
            return in_array( strtolower( trim( $args, '"\' ' ) ), array( 'mod_rewrite.c', 'rewrite_module' ), true ) ? 'rewrite' : 'maybe';
        }

        if ( in_array( $name, array( 'ifdefine', 'ifversion' ), true ) ) {
            return 'maybe';
        }

        if ( 'files' === $name || 'filesmatch' === $name ) {
            $regex = 'filesmatch' === $name;

            if ( ! $regex && '~' === substr( $args, 0, 1 ) ) {
                $regex = true;
                $args  = trim( substr( $args, 1 ) );
            }

            return true === self::extension_pattern_names_php( trim( $args, '"\'' ), $regex, false ) ? 'files-php' : 'files';
        }

        return 'condition';
    }

    /**
     * Whether a pattern that goes only by the extension of a file names the PHP ones
     *
     * "Every PHP file" cannot be asked of a sample name. A sample is public,
     * so a section can be written for it and nothing else, and an expression
     * can name every file but one ("all but shell.php") in more ways than can
     * be tried. So the pattern has to be of a kind that cannot tell one name
     * from another: any name, a dot and a list of extensions, to the end. In
     * that kind there is nothing to make an exception with, and whether .php
     * is on the list is then a fair question for a sample. Anything else is
     * not taken for a denial of PHP, which only means the .htaccess is listed.
     *
     * @param string $pattern Pattern, without its quotes.
     * @param bool   $regex   Whether it is an expression (FilesMatch, "Files ~",
     *                        RewriteRule) or a wildcard (Files).
     * @param bool   $nocase  Whether it ignores case.
     * @return bool|null True when it names every .php file, false when it goes
     *                   by the extension and .php is not one of them, null
     *                   when it is not of that kind.
     */
    private static function extension_pattern_names_php( $pattern, $regex, $nocase ) {
        if ( ! $regex ) {
            if ( 1 !== preg_match( '/^\*\.[a-z0-9*?]+$/i', $pattern ) ) {
                return null;
            }

            return function_exists( 'fnmatch' ) ? fnmatch( $pattern, 'x.php' ) : '*.php' === $pattern;
        }

        $rest = $pattern;

        if ( 0 === stripos( $rest, '(?i)' ) ) {
            $rest   = substr( $rest, 4 );
            $nocase = true;
        }

        // "Any name" in front, written out or left out, and then a dot, the
        // extensions and the end, written out or left out too. The extensions
        // are letters, digits, groups, alternatives and classes of letters and
        // digits: no dot, no "any character", nothing negated and nothing
        // that looks around.
        $rest = preg_replace( '/^\^?\.[*+]/', '', $rest, 1 );

        if ( 1 !== preg_match( '/^\\\\\.(?:[a-z0-9|?*+)]|\\\\d|\[[a-z0-9-]+\]|\((?:\?i?:)?)+\$?$/i', (string) $rest ) ) {
            return null;
        }

        // The dot has to be there: with "?" or "*" after it, what follows
        // would be looked for anywhere in the name. And an alternative
        // outside a group is a second pattern with no dot in front of it,
        // which goes by the name again.
        if ( 1 === preg_match( '/^\\\\\.[?*+]/', $rest ) ) {
            return null;
        }

        $depth = 0;

        for ( $i = 0, $length = strlen( $rest ); $i < $length; $i++ ) {
            if ( '(' === $rest[ $i ] ) {
                $depth++;
            } elseif ( ')' === $rest[ $i ] ) {
                $depth--;
            }

            if ( $depth < 0 || ( 0 === $depth && '|' === $rest[ $i ] ) ) {
                return null;
            }
        }

        if ( 0 !== $depth ) {
            return null;
        }

        $expression = '~' . str_replace( '~', '\\~', $pattern ) . '~' . ( $nocase ? 'i' : '' );

        foreach ( array( 'x.php', 'a/b/x.php' ) as $sample ) {
            $matched = @preg_match( $expression, $sample ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A pattern Apache would refuse names nothing.

            if ( false === $matched ) {
                return null;
            }

            if ( 0 === $matched ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether a RewriteRule that refuses requests refuses every PHP file
     *
     * A pattern with a "!" in front refuses what it does not match, so it
     * refuses PHP when it goes by the extension and .php is not one of them
     * ("!\.(jpe?g|png)$": everything but the images).
     *
     * @param string $pattern Pattern of the rule.
     * @param string $flags   Flags of the rule, in lower case.
     * @return bool
     */
    private static function rewrite_rule_refuses_php( $pattern, $flags ) {
        $pattern = trim( $pattern, '"\'' );
        $negated = '' !== $pattern && '!' === $pattern[0];

        if ( $negated ) {
            $pattern = substr( $pattern, 1 );
        }

        if ( '' === $pattern ) {
            return false;
        }

        $names = self::extension_pattern_names_php( $pattern, true, (bool) preg_match( '/[\[,]\s*(?:nc|nocase)\s*[,\]]/', $flags ) );

        return $negated ? false === $names : true === $names;
    }

    /**
     * What the directives of a .htaccess do, as far as running code goes
     *
     * @param string $content Content of the file.
     * @return array {
     *     @type array $runs       Ways it makes the server run code, as keys:
     *                             'run', 'load', 'rewrite', 'cgi'.
     *     @type array $other      Kinds of directive that neither run code nor
     *                             only deny, as keys: 'access', 'rewrite',
     *                             'headers', 'other'.
     *     @type bool  $rewrite    Whether it has rewrite directives of its own.
     *     @type bool  $denies_php Whether it denies access to every PHP file
     *                             itself, for every request and whatever the
     *                             server has loaded.
     * }
     */
    private static function read_htaccess_rules( $content ) {
        $facts = array(
            'runs'       => array(),
            'other'      => array(),
            'rewrite'    => false,
            'denies_php' => false,
        );

        // A line that ends in a backslash goes on in the next one, and Apache
        // joins the two before it looks at anything else, comments included.
        $content = str_replace( array( "\r\n", "\r" ), "\n", (string) $content );
        $content = preg_replace( '/(?<!\\\\)\\\\\n/', '', $content );

        // "script" as a word of its own: cgi-script and php-script are
        // handlers that run code, application/javascript is a kind of file.
        $scripts     = '/php|cgi|(?<![a-z])script|lsapi|server-parsed|proxy:|python-program/';
        $php_target  = '/\.(?:ph(?:p\d*|tml|t|ar|ps)|inc)(?![a-z0-9])/';
        $containers  = array();
        $cgi_handler = false;
        $execcgi_on  = false;
        $execcgi_off = false;

        foreach ( explode( "\n", (string) $content ) as $line ) {
            $line = trim( $line );

            if ( '' === $line || '#' === $line[0] ) {
                continue;
            }

            // Sections are remembered, to know what a directive inside them
            // applies to (see htaccess_section_kind()).
            if ( '<' === $line[0] ) {
                if ( preg_match( '/^<\s*\//', $line ) ) {
                    array_pop( $containers );
                } elseif ( preg_match( '/^<\s*([A-Za-z]+)\b(.*)$/', $line, $section ) ) {
                    $containers[] = self::htaccess_section_kind( strtolower( $section[1] ), $section[2] );
                }
                continue;
            }

            if ( ! preg_match( '/^([A-Za-z_]+)\s*(.*)$/', $line, $parts ) ) {
                $facts['other']['other'] = true;
                continue;
            }

            $name  = strtolower( $parts[1] );
            $args  = trim( $parts[2] );
            $low   = strtolower( $args );
            $words = preg_split( '/\s+/', $low, -1, PREG_SPLIT_NO_EMPTY );
            $first = isset( $words[0] ) ? trim( $words[0], '"\'' ) : '';

            // The sections around this line that put a condition on it.
            $inside = array_values( array_diff( $containers, array( '' ) ) );

            switch ( $name ) {
                case 'sethandler':
                case 'addhandler':
                case 'addtype':
                case 'forcetype':
                    if ( preg_match( $scripts, $first ) ) {
                        // "AddHandler cgi-script" next to "Options -ExecCGI" is
                        // the old recipe that hands every script to CGI and
                        // forbids CGI. Which of the two it is gets decided
                        // once the whole file has been read.
                        if ( 'addhandler' === $name && false !== strpos( $first, 'cgi' ) ) {
                            $cgi_handler = true;
                        } else {
                            $facts['runs']['run'] = true;
                        }
                    } elseif ( ! in_array( $first, array( 'none', 'default-handler', 'text/plain', 'application/octet-stream' ), true ) ) {
                        $facts['other']['other'] = true;
                    }
                    break;

                case 'php_flag':
                case 'php_admin_flag':
                case 'php_value':
                case 'php_admin_value':
                    $value = isset( $words[1] ) ? trim( $words[1], '"\'' ) : '';

                    if ( 'engine' === $first ) {
                        if ( ! in_array( $value, array( 'off', '0', 'false', 'no' ), true ) ) {
                            $facts['runs']['run'] = true;
                        }
                    } elseif ( in_array( $first, array( 'auto_prepend_file', 'auto_append_file' ), true ) ) {
                        if ( '' !== $value && 'none' !== $value ) {
                            $facts['runs']['load'] = true;
                        }
                    } else {
                        $facts['other']['other'] = true;
                    }
                    break;

                case 'options':
                    foreach ( $words as $option ) {
                        // Only a ban on CGI that holds for everybody counts as one.
                        if ( '-execcgi' === $option && empty( $inside ) ) {
                            $execcgi_off = true;
                        }

                        if ( '-' === $option[0] || 'none' === $option ) {
                            continue;
                        }

                        $option = ltrim( $option, '+' );

                        if ( in_array( $option, array( 'execcgi', 'includes', 'all' ), true ) ) {
                            $facts['runs']['cgi'] = true;
                            $execcgi_on           = true;
                        } else {
                            $facts['other']['other'] = true;
                        }
                    }
                    break;

                case 'addoutputfilter':
                case 'setoutputfilter':
                case 'addoutputfilterbytype':
                    if ( false !== strpos( $low, 'includes' ) ) {
                        $facts['runs']['cgi'] = true;
                    } else {
                        $facts['other']['other'] = true;
                    }
                    break;

                case 'action':
                    $facts['runs']['cgi'] = true;
                    break;

                case 'xbithack':
                    // Server-side includes for every file with the execute bit.
                    if ( 'off' !== $first ) {
                        $facts['runs']['cgi'] = true;
                    }
                    break;

                case 'deny':
                case 'require':
                    $denies = 'deny' === $name ? ( 'from' === $first && isset( $words[1] ) && 'all' === $words[1] ) : ( 'all' === $first && isset( $words[1] ) && 'denied' === $words[1] );

                    if ( ! $denies || in_array( 'condition', $inside, true ) ) {
                        $facts['other']['access'] = true;
                    } elseif ( ! array_diff( $inside, array( 'rewrite', 'files-php' ) ) ) {
                        // For every request, on any server, and for every file
                        // or for the PHP ones. A denial that depends on a
                        // module being there, or that names other files, still
                        // protects, but it does not make up for rewrite rules
                        // that switch off the ones of the site root.
                        $facts['denies_php'] = true;
                    }
                    break;

                case 'order':
                case 'indexignore':
                    break;

                case 'allow':
                case 'satisfy':
                case 'authtype':
                case 'authname':
                case 'authuserfile':
                case 'authgroupfile':
                    $facts['other']['access'] = true;
                    break;

                case 'rewriteengine':
                case 'rewritebase':
                case 'rewriteoptions':
                    $facts['rewrite'] = true;
                    break;

                case 'rewritecond':
                    // A condition makes the rule after it apply to some
                    // requests and not to others, a denial included.
                    $facts['rewrite']          = true;
                    $facts['other']['rewrite'] = true;
                    break;

                case 'rewriterule':
                    $facts['rewrite'] = true;

                    $rule    = preg_split( '/\s+/', $args, 3 );
                    $pattern = isset( $rule[0] ) ? $rule[0] : '';
                    $target  = isset( $rule[1] ) ? strtolower( trim( $rule[1], '"\'' ) ) : '';
                    $flags   = isset( $rule[2] ) ? strtolower( $rule[2] ) : '';

                    if ( preg_match( '/[\[,]\s*h=/', $flags ) || preg_match( '/[\[,]\s*t=[^,\]]*(?:php|cgi|(?<![a-z])script)/', $flags ) ) {
                        // A handler or a type forced from the rule itself.
                        $facts['runs']['run'] = true;
                    } elseif ( '-' === $target && preg_match( '/[\[,]\s*(?:f|forbidden|g|gone)\s*[,\]]/', $flags ) ) {
                        // Rewrites nothing and refuses the request. It stands
                        // for the rule of the site root only when it refuses
                        // every PHP file, for every request.
                        if ( ! array_diff( $inside, array( 'rewrite' ) ) && self::rewrite_rule_refuses_php( $pattern, $flags ) ) {
                            $facts['denies_php'] = true;
                        } else {
                            $facts['other']['rewrite'] = true;
                        }
                    } elseif ( '-' === $target ) {
                        // Rewrites nothing and lets the request through, which
                        // can be the way to keep one file out of the denial
                        // that follows: it is not part of a file that only
                        // protects.
                        $facts['other']['rewrite'] = true;
                    } elseif ( preg_match( $php_target, $target ) && '/index.php' !== $target ) {
                        $facts['runs']['rewrite'] = true;
                    } else {
                        $facts['other']['rewrite'] = true;
                    }
                    break;

                case 'header':
                case 'requestheader':
                case 'expiresactive':
                case 'expiresbytype':
                case 'expiresdefault':
                case 'fileetag':
                    $facts['other']['headers'] = true;
                    break;

                default:
                    $facts['other']['other'] = true;
            }
        }

        if ( $cgi_handler && ( $execcgi_on || ! $execcgi_off ) ) {
            $facts['runs']['cgi'] = true;
        }

        return $facts;
    }

    /**
     * Check content for suspicious patterns
     *
     * @param string $content File content.
     * @return bool
     */
    private function has_suspicious_content( $content ) {
        return (bool) $this->detect_suspicious_pattern( $content );
    }

    /**
     * Detect specific suspicious pattern in file content
     *
     * Two detection levels:
     * - Standard (strict=false): for uploads where ANY PHP is already suspicious.
     *   Single-function matches like dangerous functions, superglobals are enough.
     * - Strict (strict=true): for plugins/themes without checksums where PHP is expected.
     *   Only flags clear obfuscation combos to avoid false positives on legitimate code.
     *
     * Patterns are loaded from an external JSON file (scan-patterns.json)
     * with base64-encoded needles to prevent WAF/antimalware false positives
     * on the scanner file itself.
     *
     * @param string $content File content.
     * @param bool   $strict  Use strict mode (fewer, higher-confidence patterns).
     * @return string|false The pattern found, or false.
     */
    private function detect_suspicious_pattern( $content, $strict = false ) {

        if ( $strict ) {
            return $this->detect_strict_suspicious_pattern( $content );
        }

        $patterns_data = $this->load_scan_patterns();
        if ( empty( $patterns_data['standard_patterns'] ) ) {
            return false;
        }

        // Standard mode: broad detection for uploads and known-extra files
        foreach ( $patterns_data['standard_patterns'] as $encoded_needle => $label ) {
            // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding pattern definitions, not user input.
            $needle = base64_decode( $encoded_needle );
            if ( $this->needle_present( $content, $needle ) ) {
                // The labels live in the pattern file, in English: "$_GET access"
                // becomes "$_GET", which needs no translation.
                return preg_replace( '/ access$/', '', (string) $label );
            }
        }

        return $this->detect_common_pattern( $content );
    }

    /**
     * The three checks both levels of the search share
     *
     * @param string $content File content.
     * @return string|false The pattern found, or false.
     */
    private function detect_common_pattern( $content ) {
        // preg_replace with the /e modifier (arbitrary code execution,
        // deprecated). The modifier is looked for on the same line and within
        // 300 characters of the opening quote. With ".*" every preg_replace of
        // a long line cost a pass over the whole line: 88 seconds for a file
        // of 500 KB made for it, measured without the PCRE compiler.
        if ( $this->found( '/preg_replace\s*+\(\s*+[\'"][^\n]{0,300}?\/e[\'"]/i', $content ) ) {
            return __( 'preg_replace with the /e modifier, which runs code', 'vigilante' );
        }

        // Long hex-encoded strings (obfuscated payloads). Eleven escapes in a
        // row and not "ten or more after the first": asked to take them all,
        // PCRE gave up on a run of some 12,000, and a search that gave up
        // read as "nothing found". The longer the payload, the less it was
        // found.
        if ( $this->found( '/(?:\\\\x[0-9a-f]{2}){11}/i', $content ) ) {
            return __( 'a long string written in hexadecimal', 'vigilante' );
        }

        // Heavily concatenated chr() calls (char-by-char obfuscation)
        if ( $this->found( '/chr\s*+\(\s*+\d++\s*+\)\s*+\.\s*+chr\s*+\(\s*+\d++\s*+\)\s*+\.\s*+chr/i', $content ) ) {
            return __( 'text built character by character with chr()', 'vigilante' );
        }

        return false;
    }

    /**
     * Strict suspicious pattern detection for plugins/themes without checksums
     *
     * Only flags high-confidence obfuscation combos that are almost certainly malware.
     * Individual functions are normal in plugins and are not flagged.
     *
     * @param string $content File content.
     * @return string|false The pattern found, or false.
     */
    private function detect_strict_suspicious_pattern( $content ) {

        $patterns_data = $this->load_scan_patterns();
        if ( empty( $patterns_data['strict_fragments'] ) ) {
            return false;
        }

        // Decode fragment names from JSON
        $fragments = array();
        foreach ( $patterns_data['strict_fragments'] as $key => $encoded ) {
            // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
            $fragments[ $key ] = base64_decode( $encoded );
        }

        $ev = $fragments['ev'] ?? '';
        $b6 = $fragments['b6'] ?? '';
        $gz = $fragments['gz'] ?? '';
        $gu = $fragments['gu'] ?? '';
        $sr = $fragments['sr'] ?? '';
        $hb = $fragments['hb'] ?? '';
        $as = $fragments['as'] ?? '';
        $ss = $fragments['ss'] ?? '';
        $cf = $fragments['cf'] ?? '';

        // Obfuscation combos: dangerous function wrapping decoded content.
        // The labels name the two functions side by side and not one inside
        // the other. Written the way the code is written, a label was itself
        // a match: the results of a scan, kept in a cache that stores options
        // as PHP files under wp-content, would have been the next finding.
        // The possessive quantifiers ("*+") change nothing in what matches,
        // because what follows each run of spaces is never a space. They keep
        // PCRE from walking a long run back one space at a time, which is
        // where it gives up when it runs without its compiler.
        $obfuscation_combos = array(
            '/' . $ev . '\s*+\(\s*+' . $b6 . '\s*+\(/i'  => $ev . '() + ' . $b6 . '()',
            '/' . $ev . '\s*+\(\s*+' . $gz . '\s*+\(/i'  => $ev . '() + ' . $gz . '()',
            '/' . $ev . '\s*+\(\s*+' . $gu . '\s*+\(/i'  => $ev . '() + ' . $gu . '()',
            '/' . $ev . '\s*+\(\s*+' . $sr . '\s*+\(/i'  => $ev . '() + ' . $sr . '()',
            '/' . $ev . '\s*+\(\s*+' . $hb . '\s*+\(/i'  => $ev . '() + ' . $hb . '()',
            '/' . $as . '\s*+\(\s*+' . $b6 . '\s*+\(/i'  => $as . '() + ' . $b6 . '()',
            '/' . $ev . '\s*+\(\s*+\$[a-z_]++\s*+\(/i' => $ev . '() + $variable()',
            '/' . $ev . '\s*+\(\s*+' . $ss . '\s*+\(/i'  => $ev . '() + ' . $ss . '()',
        );

        foreach ( $obfuscation_combos as $regex => $label ) {
            if ( $this->found( $regex, $content ) ) {
                return $label;
            }
        }

        // The plain backdoor, with nothing to hide: data from the request
        // handed straight to code or to the system, a function the request
        // chooses, or a file included from another server. The names come
        // from the list the concatenation check below uses, minus the decoders,
        // so they are not written here either. That list is decoded once, for both.
        $dangerous_names = array();
        if ( ! empty( $patterns_data['dangerous_names'] ) ) {
            foreach ( $patterns_data['dangerous_names'] as $encoded_name ) {
                // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
                $dangerous_names[] = base64_decode( $encoded_name );
            }
        }

        $runners = array_merge( array_filter( array( $ev, $as ) ), array_diff( $dangerous_names, array( $b6, $gz, $gu, $sr, $hb ) ) );

        // These three read as code what PHP reads as code, so they are
        // searched with the comments of the file turned into blank space
        // (blank_comments()). A comment that quotes one of them ("never do
        // this: ...") is then not a finding, and a comment slipped between a
        // name and its parenthesis hides nothing. The first two cannot match
        // without a superglobal of the request, so only the files that name
        // one are prepared that way, about one in twenty. The third is looked
        // for in the file as it is and checked again that way when it matches.
        // The dynamic function constructor, further down, reuses the copy.
        $code = null;

        if ( $this->found( '/\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/', $content ) ) {
            $code = $this->blank_comments( $content );

            // When PHP cannot be asked what is a comment, the file is
            // searched as it is: a comment may then be reported, and nothing
            // that runs is left out.
            $subject = false === $code ? $content : $code;

            if ( ! empty( $runners ) ) {
                $names        = implode( '|', array_map( 'preg_quote', $runners ) );
                // What the visitor sends, when it is not just being asked about
                // with isset() or empty(). The path of an uploaded file is not in
                // the list: handing it to a command is how images get processed.
                $from_request = '(?<!isset\()(?<!isset\( )(?<!empty\()(?<!empty\( )(?:\$_(?:GET|POST|REQUEST|COOKIE)\b|\$_SERVER\s*\[\s*[\'"]HTTP_)';

                // The possessive quantifiers keep a file made of spaces from
                // costing a try per space.
                if ( $this->found( '/(?<![a-z0-9_>:$])(?:' . $names . ')\s*+\(\s*+[^;\n]{0,80}?' . $from_request . '/i', $subject ) ) {
                    return __( 'data from the request is run as code or as a command', 'vigilante' );
                }
            }

            if ( $this->found( '/\$_(?:GET|POST|REQUEST|COOKIE)\s*+\[[^\]\n]{1,60}\]\s*+\(/', $subject ) ) {
                return __( 'a function chosen by the request is called', 'vigilante' );
            }
        }

        if ( $this->found_in_code( '/(?<![a-z0-9_>$])(?:include|require)(?:_once)?\s*+(?:\(\s*+)?[\'"]https?:\/\//i', $content, $code ) ) {
            return __( 'a file from another server is included', 'vigilante' );
        }

        // Deprecated dynamic function constructor, nearly always malicious in
        // modern code. It is a call, so it is looked for in the code and not
        // in the comments, like the three above: an old call left commented
        // out runs nothing, and plugins that are not on WordPress.org keep
        // them. Only the files that name it are prepared that way, and the
        // search goes straight to the copy without comments, so a comment
        // between the name and its parenthesis hides nothing either.
        if ( ! empty( $cf ) && false !== stripos( $content, rtrim( $cf, '(' ) ) ) {
            if ( null === $code ) {
                $code = $this->blank_comments( $content );
            }

            // When PHP cannot be asked what is a comment, the match stands.
            if ( $this->needle_present( false === $code ? $content : $code, $cf ) ) {
                // The name alone, for the same reason as the labels above.
                return rtrim( $cf, '(' );
            }
        }

        // Remote fetch piped into unserialize: a PHP object-injection / supply-chain
        // vector seen in trojanized or nulled plugins (download a payload from a
        // remote URL and unserialize it). Requires a REAL unserialize() call
        // (not maybe_unserialize() / igbinary_unserialize(), which are common and
        // safe) sitting CLOSE TO a remote-fetch call. Earlier releases only
        // checked that both strings appeared somewhere in the file, which
        // false-positived on legitimate code using both in unrelated methods
        // (e.g. a theme reading a transient with maybe_unserialize() while
        // fetching its public IP with wp_remote_get()).
        //
        // The search runs on a copy of the file in lower case, with
        // expressions that tell the case apart, and only when the file names
        // the function at all. PCRE without its compiler looks ahead for the
        // first letter of an expression in both cases before each try, and
        // when one of the two is not in the file that look runs to the end of
        // it. pattern_near() asks once per match, so a file with thousands of
        // them cost thousands of passes (26 seconds for 8 MB, measured). With
        // one case to look for, each look stops at the next candidate.
        $us = self::lower_ascii( $fragments['us'] ?? '' );
        if ( '' !== $us && false !== stripos( $content, $us ) ) {
            $lower           = self::lower_ascii( $content );
            $us_regex        = '/(?<![a-z0-9_])' . preg_quote( $us, '/' ) . '\s*+\(/';
            $remote_fetchers = array(
                $fragments['wr'] ?? '', // wp_remote_get
                $fragments['rb'] ?? '', // wp_remote_retrieve_body
                $fragments['ce'] ?? '', // curl_exec
            );
            foreach ( $remote_fetchers as $rf ) {
                if ( '' === $rf ) {
                    continue;
                }
                $rf_regex = '/(?<![a-z0-9_])' . preg_quote( self::lower_ascii( $rf ), '/' ) . '\s*+\(/';
                if ( $this->pattern_near( $lower, $us_regex, $rf_regex, 600 ) ) {
                    /* translators: 1: Function that downloads, 2: Function that unserializes */
                    return sprintf( __( 'data downloaded from another server is unserialized (%1$s and %2$s)', 'vigilante' ), $rf, $us );
                }
            }

            // file_get_contents() is treated separately from the fetchers
            // above: those are unambiguously remote, while file_get_contents
            // is PHP's most common LOCAL file reader, and reading a local
            // path right next to unserialize() is a legitimate pattern
            // (settings import/export, PSR-6 file caches shipped in premium
            // plugins, which have no wp.org checksums so this heuristic is
            // their only filter). It only acts as a remote fetcher when its
            // argument is a URL, so the combo additionally requires a
            // remote-scheme literal near the call before it fires.
            $fg = $fragments['fg'] ?? '';
            if ( '' !== $fg ) {
                $fg_regex     = '/(?<![a-z0-9_])' . preg_quote( self::lower_ascii( $fg ), '/' ) . '\s*+\(/';
                $scheme_regex = '/(?:https?|ftps?):\/\/|php:\/\/input/';

                if ( $this->pattern_near( $lower, $us_regex, $fg_regex, 600 )
                    && $this->pattern_near( $lower, $fg_regex, $scheme_regex, 600 ) ) {
                    /* translators: 1: Function that downloads, 2: Function that unserializes */
                    return sprintf( __( 'data downloaded from another server is unserialized (%1$s and %2$s)', 'vigilante' ), $fg, $us );
                }
            }
        }

        $common = $this->detect_common_pattern( $content );
        if ( $common ) {
            return $common;
        }

        // Dangerous function names built from string concatenation: a variable
        // given a name in pieces and then called. The assignments are taken
        // one at a time and the calls are looked up in one pass. Collecting
        // every assignment of the file first, and then searching the whole
        // file again for each one, took memory and time that grew with the
        // square of the file.
        $split  = array();
        $capped = false;
        $offset = 0;

        while ( true ) {
            // A variable, "=" and a quoted piece followed by a dot: where a
            // string put together from pieces starts.
            $start = $this->next_match( '/\$([a-z_]\w*)\s*+=\s*+(?=["\'][a-z0-9_]*+["\']\s*+\.)/i', $content, $offset );

            if ( null === $start ) {
                break;
            }

            // The pieces are taken one by one, however many there are: a name
            // can be padded with as many empty ones as its author likes, and
            // asking PCRE for the whole chain at once is what made it give up.
            $position = $start[0][1] + strlen( $start[0][0] );
            $combined = '';
            $closed   = false;

            while ( true ) {
                $piece = $this->next_match( '/\G["\']([a-z0-9_]*+)["\']\s*+(\.\s*+|;)?+/i', $content, $position );

                if ( null === $piece ) {
                    break;
                }

                // No name on the list is this long: past it, the letters are
                // not kept, and the chain is still walked to its end.
                if ( strlen( $combined ) <= 64 ) {
                    $combined .= self::lower_ascii( $piece[1][0] );
                }

                $position = $piece[0][1] + strlen( $piece[0][0] );
                $after    = isset( $piece[2] ) && $piece[2][1] >= 0 ? $piece[2][0] : '';

                if ( '' === $after || ';' === $after ) {
                    $closed = ';' === $after;
                    break;
                }
            }

            $offset = max( $position, $start[0][1] + 1 );

            if ( $closed && in_array( $combined, $dangerous_names, true ) && ! isset( $split[ $start[1][0] ] ) ) {
                $split[ $start[1][0] ] = $combined;

                if ( count( $split ) >= 500 ) {
                    $capped = true;
                    break;
                }
            }
        }

        if ( ! empty( $split ) ) {
            $offset = 0;

            while ( true ) {
                $call = $this->next_match( '/\$([a-z_]\w*)\s*+\(/i', $content, $offset );

                if ( null === $call ) {
                    break;
                }

                if ( isset( $split[ $call[1][0] ] ) ) {
                    /* translators: %s: Function name */
                    return sprintf( __( 'call to %s() with its name split in pieces', 'vigilante' ), $split[ $call[1][0] ] );
                }

                $offset = $call[0][1] + strlen( $call[0][0] );
            }

            // More names in pieces than a file has any reason to hold, and
            // not every one was followed: not searched, rather than clean.
            if ( $capped ) {
                $this->search_failed = true;
            }
        }

        return false;
    }

    /**
     * Whether a scan needle is present as a real token rather than glued inside
     * a longer identifier.
     *
     * Function-call needles (an identifier followed by "(") are matched with a
     * left word boundary, so "file_get_contents(" no longer matches
     * "wpcom_vip_file_get_contents(", "unserialize(" no longer matches
     * "maybe_unserialize(", and "eval(" no longer matches "retrieval(". Needles
     * that are not plain identifiers (such as the "$_GET[" superglobal probes)
     * keep a plain case-insensitive substring search.
     *
     * @param string $content File content.
     * @param string $needle  Decoded needle (e.g. "eval(", "$_GET[").
     * @return bool
     */
    private function needle_present( $content, $needle ) {
        if ( '' === $needle ) {
            return false;
        }
        if ( preg_match( '/^[a-z_][a-z0-9_]*\($/i', $needle ) ) {
            $fn = rtrim( $needle, '(' );
            return $this->found( '/(?<![a-z0-9_])' . preg_quote( $fn, '/' ) . '\s*+\(/i', $content );
        }
        return stripos( $content, $needle ) !== false;
    }

    /**
     * Whether two patterns both occur within $window bytes of each other.
     *
     * Used to require that correlated malware signals (for example a remote
     * fetch and an unserialize call) sit in the same code path instead of
     * merely coexisting somewhere in the file, which was a false-positive
     * source when only their presence was checked.
     *
     * @param string $content File content.
     * @param string $regex_a First anchored pattern (with delimiters and flags).
     * @param string $regex_b Second anchored pattern (with delimiters and flags).
     * @param int    $window  Maximum byte distance between a match of each.
     * @return bool
     */
    private function pattern_near( $content, $regex_a, $regex_b, $window ) {
        // Both lists come in order, so they are walked together: the match
        // that is behind moves on, and no pair is compared twice. Every match
        // of one used to be compared with every match of the other.
        $a = $this->next_match( $regex_a, $content, 0 );
        $b = $this->next_match( $regex_b, $content, 0 );

        while ( null !== $a && null !== $b ) {
            if ( abs( $a[0][1] - $b[0][1] ) <= $window ) {
                return true;
            }

            if ( $a[0][1] < $b[0][1] ) {
                $a = $this->next_match( $regex_a, $content, $a[0][1] + 1 );
            } else {
                $b = $this->next_match( $regex_b, $content, $b[0][1] + 1 );
            }
        }

        return false;
    }

    /**
     * A text with its capital letters from A to Z in lower case, and nothing else
     *
     * strtolower() follows the language of the server until PHP 8.2, and in
     * Turkish a capital I does not become an i: a function name written in
     * capitals would not be found there.
     *
     * @param string $text Text.
     * @return string
     */
    private static function lower_ascii( $text ) {
        return strtr( (string) $text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz' );
    }

    /**
     * Whether an expression matches, without taking a search that gave up for a "no"
     *
     * preg_match() answers false, and not 0, when PCRE stops before the end
     * because a long run used up the stack of its compiler or its
     * backtracking limit. Read as "nothing found", that is a file that passes
     * as clean without having been searched. Measured on what was published
     * until now: a hexadecimal string of some 12,000 characters made the
     * expression that looks for hexadecimal strings give up. Every expression
     * of the search goes through here or through next_match(), and a file on
     * which one of them gave up is reported as not searched (search_file()).
     *
     * @param string $regex   Expression, with delimiters and flags.
     * @param string $content Text to search.
     * @return bool
     */
    private function found( $regex, $content ) {
        $result = preg_match( $regex, $content );

        if ( false === $result ) {
            $this->search_failed = true;
        }

        return 1 === $result;
    }

    /**
     * The next match of an expression from a position on
     *
     * For the checks that walk every match. Asked for one at a time they take
     * no memory to speak of, where preg_match_all() held every match of the
     * file at once.
     *
     * @param string $regex   Expression, with delimiters and flags.
     * @param string $content Text to search.
     * @param int    $offset  Where to start.
     * @return array|null The match as PREG_OFFSET_CAPTURE gives it, or null.
     */
    private function next_match( $regex, $content, $offset ) {
        $match  = array();
        $result = preg_match( $regex, $content, $match, PREG_OFFSET_CAPTURE, $offset );

        if ( false === $result ) {
            $this->search_failed = true;
        }

        return 1 === $result ? $match : null;
    }

    /**
     * Whether an expression matches in the code of a file and not only in its comments
     *
     * @param string            $regex   Expression, with delimiters and flags.
     * @param string            $content File content.
     * @param string|false|null $code    The content with its comments blanked. Worked
     *                                   out here the first time it is needed and kept
     *                                   by the caller; false when it cannot be.
     * @return bool
     */
    private function found_in_code( $regex, $content, &$code ) {
        if ( ! $this->found( $regex, $content ) ) {
            return false;
        }

        if ( null === $code ) {
            $code = $this->blank_comments( $content );
        }

        // When PHP cannot be asked what is a comment, the match stands.
        return false === $code || $this->found( $regex, $code );
    }

    /**
     * The content of a PHP file with its comments turned into blank space
     *
     * PHP itself says what is a comment (token_get_all()), so nothing that
     * runs can be taken for one: a "//" comment ends at "?>", a string that
     * holds "/*" opens nothing, and so on, without a second reader of the
     * language here to get any of it wrong. Each comment is replaced by as
     * many spaces as it had characters, line breaks kept, so the result is as
     * long as the original and what was on one line stays on one line.
     *
     * Three cases are left as they are, and then the match stands:
     *
     * - A file with a "<?" that is not "<?php" or "<?=". Whether PHP reads
     *   that as an opening tag depends on short_open_tag, which may not be
     *   set the same for the PHP that runs this scan as for the one that
     *   serves the site, and with it changes where the code starts and so
     *   what is a comment.
     * - A comment that starts with "#[". PHP 8 reads that as an attribute and
     *   runs what follows it on the line; PHP 7 reads the whole line as a
     *   comment.
     * - A file whose tokens would not fit in the memory that is left, or
     *   would take more than 64 MB. PHP returns one array per token, up to
     *   450 bytes each, and a file can be written so that every byte is one:
     *   400 KB of that took 180 MB with PHP 7.4 (measured). How many tokens
     *   there can be is counted first, without making them.
     * - Any file, when PHP is set to read its source in another encoding
     *   (zend.multibyte). In Shift JIS, Big5 or GBK the second byte of a
     *   character can be a backslash, so where a string ends is not where
     *   it ends for a reader that goes byte by byte.
     *
     * @param string $content File content.
     * @return string|false The content without its comments, or false when it
     *                      cannot be told what is a comment.
     */
    private function blank_comments( $content ) {
        if ( ! function_exists( 'token_get_all' ) || ini_get( 'zend.multibyte' ) || preg_match( '/<\?(?!php[ \t\r\n]|=)/i', $content ) ) {
            return false;
        }

        // No more tokens than this: each character that is not part of a
        // word can be one, and so can each run of digits and each word.
        $words  = 0;
        $others = preg_replace( '/[a-z_\x80-\xff][a-z0-9_\x80-\xff]*+|[0-9]++/i', '', $content, -1, $words );

        if ( null === $others ) {
            return false;
        }

        $needed = 450 * ( strlen( $others ) + $words + 2 ) + strlen( $content );
        $limit  = wp_convert_hr_to_bytes( ini_get( 'memory_limit' ) );
        unset( $others );

        if ( $needed > 64 * MB_IN_BYTES || ( $limit > 0 && ( $limit - memory_get_usage() ) < $needed ) ) {
            return false;
        }

        $tokens = @token_get_all( $content ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- PHP 7 warns about what it cannot read in the file being scanned, such as a comment left open; the warning says nothing about this code.
        $code   = '';
        $length = 0;

        foreach ( $tokens as $token ) {
            $text    = is_array( $token ) ? $token[1] : $token;
            $length += strlen( $text );

            if ( is_array( $token ) && ( T_COMMENT === $token[0] || T_DOC_COMMENT === $token[0] ) && 0 !== strpos( $text, '#[' ) ) {
                $text = preg_replace( '/[^\n]/', ' ', $text );
            }

            $code .= $text;
        }

        // The pieces have to add up to the file. If they do not, the
        // positions cannot be trusted and neither can the result.
        if ( strlen( $content ) !== $length || strlen( $code ) !== $length ) {
            return false;
        }

        return $code;
    }

    /**
     * Search one file for hidden code
     *
     * The one place where a file is read for that. Each scan used to read it
     * by itself, and only when it was under 512,000 bytes: a larger file was
     * not opened, and where the file was not going to be listed anyway (a
     * plugin or a theme with no official copy) that was the same as calling
     * it clean. Padding a file was enough to keep it out of the results.
     *
     * @param string $file_path Absolute path.
     * @param bool   $strict    Use strict mode (see detect_suspicious_pattern()).
     * @return string|false|null The pattern found, false when the file was
     *                           searched and has none, or null when it could
     *                           not be searched: it is larger than
     *                           MAX_SEARCHED_BYTES, it cannot be read, or an
     *                           expression gave up on it. The caller reports
     *                           that instead of taking it for clean.
     */
    private function search_file( $file_path, $strict = false ) {
        if ( ! is_file( $file_path ) || ! is_readable( $file_path ) ) {
            return null;
        }

        $size = filesize( $file_path );

        if ( false === $size || $size > self::MAX_SEARCHED_BYTES ) {
            return null;
        }

        // One byte past the cap and no more, whatever the size said: a file
        // that grew since it was measured is not read whole.
        $content = file_get_contents( $file_path, false, null, 0, self::MAX_SEARCHED_BYTES + 1 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a local file to look for hidden code; nothing is written.

        if ( false === $content || strlen( $content ) > self::MAX_SEARCHED_BYTES ) {
            return null;
        }

        $this->search_failed = false;
        $pattern             = $this->detect_suspicious_pattern( $content, $strict );

        if ( $pattern ) {
            return $pattern;
        }

        return $this->search_failed ? null : false;
    }

    /**
     * The finding for a PHP file with no official copy that could not be searched
     *
     * @param string $file_path Absolute path.
     * @param string $relative  Path for display.
     * @return array
     */
    private function not_searched_item( $file_path, $relative ) {
        $size   = is_file( $file_path ) ? filesize( $file_path ) : false;
        $reason = __( 'PHP file that could not be searched for hidden code', 'vigilante' );

        if ( false !== $size && $size > self::MAX_SEARCHED_BYTES ) {
            /* translators: %s: File size, such as 12 MB */
            $reason = sprintf( __( 'PHP file of %s, too large to be searched for hidden code', 'vigilante' ), size_format( $size ) );
        }

        return array(
            'file'   => $relative,
            'type'   => 'not_searched',
            'reason' => $reason,
        );
    }

    /**
     * Whether a file is a text file worth normalizing before the fallback hash
     * comparison in hash_matches_published().
     *
     * @param string $file_path Absolute path.
     * @return bool
     */
    private function is_text_file( $file_path ) {
        $text_ext = array(
            'php', 'php3', 'php4', 'php5', 'php7', 'phtml',
            'js', 'css', 'html', 'htm', 'xml', 'svg',
            'txt', 'md', 'json', 'po', 'pot', 'yml', 'yaml', 'ini', 'csv',
        );
        return in_array( strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) ), $text_ext, true );
    }

    /**
     * Normalize a relative path for checksum-key comparison: forward slashes,
     * no doubled slashes, no leading "./" or "/". Case is preserved because
     * plugin and theme file systems are case-sensitive on most hosts.
     *
     * @param string $path Relative path.
     * @return string
     */
    private function normalize_rel_path( $path ) {
        $path = str_replace( '\\', '/', $path );
        $path = preg_replace( '#/+#', '/', $path );
        if ( 0 === strpos( $path, './' ) ) {
            $path = substr( $path, 2 );
        }
        return ltrim( $path, '/' );
    }

    /**
     * Load scan patterns from external JSON file
     *
     * Patterns are stored in a JSON file with base64-encoded values
     * to prevent hosting WAF/antimalware from flagging the scanner
     * PHP file as suspicious.
     *
     * @return array Patterns data.
     */
    private function load_scan_patterns() {
        static $cached = null;

        if ( null !== $cached ) {
            return $cached;
        }

        $file = VIGILANTE_INCLUDES_DIR . 'scan-patterns.json';

        if ( ! file_exists( $file ) ) {
            $cached = array();
            return $cached;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file read, not remote.
        $json = file_get_contents( $file );
        $cached = json_decode( $json, true );

        if ( ! is_array( $cached ) ) {
            $cached = array();
        }

        return $cached;
    }

    /**
     * Detect extra files in a directory that are not in checksums
     * (potential backdoors injected into plugins/themes)
     *
     * When $suspicious_only is true (no checksums available), only files
     * with suspicious code patterns are reported. This avoids flooding
     * results with every PHP file from plugins/themes not on WordPress.org.
     *
     * @param string $directory       Directory to scan.
     * @param array  $checksums       Known checksums from WordPress.org (empty if unavailable).
     * @param string $type            'plugin' or 'theme'.
     * @param string $name            Plugin or theme name.
     * @param bool   $suspicious_only Only report files with suspicious patterns.
     * @return array Array with 'suspicious' and 'extra' sub-arrays.
     */
    private function detect_extra_files( $directory, $checksums, $type, $name, $suspicious_only = false ) {
        $found = array(
            'suspicious' => array(),
            'extra'      => array(),
            'errors'     => array(),
            'php_files'  => 0,
        );
        // Every PHP file is examined. Until now the walk stopped after 50, which
        // in a plugin or theme with no official copy meant the first 50 files
        // of the folder and nothing else. Only the list of plain extra files is
        // bounded, so a folder full of generated PHP cannot fill the results;
        // hidden code is reported wherever it is.
        $max_listed = 500;
        $listed     = 0;
        $truncated  = false;

        // Only check PHP files for performance
        $php_extensions = self::php_extensions();

        // Pre-normalize the checksum keys once so path-shape differences
        // (Windows backslashes, a leading "./", doubled slashes) don't make a
        // known file look "extra" and get scanned or flagged. Case is preserved.
        $known_normalized = array();
        foreach ( array_keys( $checksums ) as $known_file ) {
            $known_normalized[ $this->normalize_rel_path( $known_file ) ] = true;
        }

        try {
            foreach ( self::walk_folder( $directory ) as $file ) {
                if ( $this->is_time_exceeded() ) {
                    break;
                }

                $file_path = $file->getPathname();

                if ( $file->isDir() ) {
                    if ( ! $file->isReadable() ) {
                        $found['errors'][] = self::unreadable_folder_error( $file_path );
                    }
                    continue;
                }

                $extension = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );

                // A .htaccess, .user.ini or php.ini that is not part of the
                // published copy is looked at for what it makes the server do.
                if ( in_array( strtolower( basename( $file_path ) ), array( '.htaccess', '.user.ini', 'php.ini' ), true ) ) {
                    $config_path = $this->normalize_rel_path( str_replace( str_replace( '\\', '/', $directory ) . '/', '', str_replace( '\\', '/', $file_path ) ) );

                    if ( ! isset( $known_normalized[ $config_path ] ) && ! $this->is_path_excluded( $file_path ) ) {
                        $config = self::server_config_finding( $file_path, str_replace( ABSPATH, '', $file_path ) );

                        if ( $config ) {
                            $found[ $config['category'] ][] = $config['item'];
                        }
                    }
                    continue;
                }

                // Only check PHP files
                if ( ! in_array( $extension, $php_extensions, true ) ) {
                    continue;
                }

                // Get relative path within plugin/theme directory, normalized so
                // path-shape quirks don't misclassify a known file as "extra".
                $norm_path       = str_replace( '\\', '/', $file_path );
                $norm_dir        = str_replace( '\\', '/', $directory );
                $relative_to_dir = $this->normalize_rel_path( str_replace( $norm_dir . '/', '', $norm_path ) );

                // Skip if file is in the checksums (it's known)
                if ( isset( $known_normalized[ $relative_to_dir ] ) ) {
                    continue;
                }

                // Skip excluded paths
                if ( $this->is_path_excluded( $file_path ) ) {
                    continue;
                }

                // Skip "Silence is golden" placeholder index.php files used by
                // WordPress core and many plugins to prevent directory listings.
                // The check is content-based — an attacker cannot bypass it by
                // simply naming a payload file index.php.
                if ( $this->is_silence_golden_file( $file_path ) ) {
                    continue;
                }

                $found['php_files']++;

                $relative = str_replace( ABSPATH, '', $file_path );

                // Check for suspicious content in extra files
                // Use strict mode for plugins without checksums to avoid false positives
                $pattern = $this->search_file( $file_path, $suspicious_only );

                $item = array(
                    'file' => $relative,
                    $type  => $name,
                );

                if ( $pattern ) {
                    // Suspicious content: promote to suspicious category
                    $item['type']   = 'suspicious_' . $type;

                    // With an official copy to compare with, the file is known
                    // not to belong to it. Without one it may well be the
                    // plugin's own, so it is not called injected.
                    if ( $suspicious_only ) {
                        /* translators: 1: Plugin or theme name, or the folder the file is in, 2: Suspicious pattern found */
                        $item['reason'] = sprintf( __( 'File in %1$s with suspicious code: %2$s', 'vigilante' ), $name, $pattern );
                    } else {
                        /* translators: 1: Plugin or theme name, 2: Suspicious pattern found */
                        $item['reason'] = sprintf( __( 'File that is not part of %1$s, with suspicious code: %2$s', 'vigilante' ), $name, $pattern );
                    }

                    $found['suspicious'][] = $item;
                } elseif ( ! $suspicious_only ) {
                    // No suspicious patterns and checksums available: report as extra
                    // Skipped in suspicious_only mode (no checksums) to avoid noise
                    if ( $listed >= $max_listed ) {
                        if ( ! $truncated ) {
                            $truncated         = true;
                            $found['errors'][] = sprintf(
                                /* translators: 1: Plugin or theme name, 2: Number of files */
                                __( '%1$s has more extra files than can be listed: only the first %2$d are shown.', 'vigilante' ),
                                $name,
                                $max_listed
                            );
                        }
                        continue;
                    }

                    $listed++;
                    $item['type']   = 'extra_' . $type;
                    $item['reason'] = __( 'PHP file not present in original distribution', 'vigilante' );
                    $found['extra'][] = $item;
                } elseif ( null === $pattern ) {
                    // No official copy to compare with, and the search could
                    // not look inside either: said, not passed over.
                    $found['extra'][] = $this->not_searched_item( $file_path, $relative );
                }
            }
        } catch ( Exception $e ) {
            $found['errors'][] = self::unreadable_folder_error( $directory );
        }

        return $found;
    }

    /**
     * Whether the given file is a trivial "Silence is golden" placeholder.
     *
     * WordPress core and most plugins drop an empty or near-empty index.php
     * inside their directories to block directory listings on misconfigured
     * servers. Those files trip the extra/suspicious detector even though
     * they're harmless. We whitelist them by content (not by name) so an
     * attacker cannot bypass the rule simply by calling a payload index.php.
     *
     * @param string $file_path Absolute path to the file being scanned.
     * @return bool True when the file is a known harmless placeholder.
     */
    private function is_silence_golden_file( $file_path ) {
        if ( 'index.php' !== basename( $file_path ) ) {
            return false;
        }

        // Cap to avoid reading large files just to check this. Real placeholders
        // are always tiny (< 100 bytes); anything bigger isn't one.
        $size = @filesize( $file_path );
        if ( false === $size || $size > 256 ) {
            return false;
        }

        $content = @file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        if ( false === $content ) {
            return false;
        }

        // Every run of whitespace counts as one space, so the placeholder
        // WordPress itself ships (the opening tag, a line break and the comment)
        // matches the same entries as the one-line form. The comparison is
        // still against the whole file: nothing can follow these few words, and
        // no arrangement of them on several lines is code that runs.
        $normalized = strtolower( trim( preg_replace( '/\s+/', ' ', $content ) ) );

        $known = array(
            '',
            '<?php',
            '<?php //silence is golden.',
            '<?php // silence is golden.',
            '<?php //silence is golden',
            '<?php // silence is golden',
        );

        return in_array( $normalized, $known, true );
    }

    /**
     * Folders of the installation that hold plugins or themes
     *
     * @return array Relative path => true, for the plugins folder and every
     *               theme root that lies inside the WordPress directory.
     */
    private function code_roots() {
        global $wp_theme_directories;

        $roots = array();

        foreach ( array_merge( array( WP_PLUGIN_DIR, get_theme_root() ), is_array( $wp_theme_directories ) ? $wp_theme_directories : array() ) as $root ) {
            $root = untrailingslashit( str_replace( '\\', '/', (string) $root ) );

            if ( '' !== $root && 0 === strpos( $root . '/', str_replace( '\\', '/', ABSPATH ) ) ) {
                $roots[ $this->relative_path( $root ) ] = true;
            }
        }

        return $roots;
    }

    /**
     * What a partial scan offers to exclude, so that the next one reaches the rest
     *
     * The folders of the plugins and themes the scan did check, as lines for
     * Excluded Paths, less the ones that are excluded by now. A scan starts
     * from the beginning every time, so with these out of the way a scan
     * run by hand spends its time on what the last one never got to. They
     * have to come out of the list afterwards, and the tab says so for as
     * long as they are there (see excluded_code_folders()).
     *
     * The list comes from stored results, and whoever reads it is told to
     * paste it into the exclusions, so only what can be the folder of a
     * plugin or of a theme is let through: one line with anything else in it
     * would exclude far more than it says.
     *
     * @param mixed $results Scan results, as run_scan() returns them.
     * @return array Relative paths, one per folder.
     */
    public function folders_to_exclude( $results ) {
        $stored = is_array( $results ) && isset( $results['checked_folders'] ) && is_array( $results['checked_folders'] ) ? $results['checked_folders'] : array();
        $roots  = $this->code_roots();
        $lines  = array();

        foreach ( $stored as $folder ) {
            if ( ! is_string( $folder ) || 1 === preg_match( '/[\\x00-\\x1f\\x7f]/', $folder ) ) {
                continue;
            }

            $folder = trim( str_replace( '\\', '/', $folder ), '/' );
            $name   = basename( $folder );

            if ( '' === $name || '.' === $name || '..' === $name || ! isset( $roots[ dirname( $folder ) ] ) ) {
                continue;
            }

            if ( ! is_dir( ABSPATH . $folder ) || $this->is_path_excluded( ABSPATH . $folder . '/.' ) ) {
                continue;
            }

            $lines[ $folder ] = true;
        }

        return array_keys( $lines );
    }

    /**
     * Whole folders of code, or the uploads folder, that Excluded Paths keeps out of every scan
     *
     * A subfolder of uploads or of a plugin is an ordinary exclusion (a cache
     * of compiled templates, say). A whole plugin, a whole theme, the
     * must-use plugins or all of uploads is something else: the scan comes
     * out complete and clean without having looked there. The tab and
     * Security Check go by this list, so that nobody is left thinking those
     * folders are being watched.
     *
     * @return array Relative paths. A folder that holds others (the plugins
     *               folder, a theme root) stands for all of them.
     */
    public function excluded_code_folders() {
        if ( empty( $this->options['excluded_paths'] ) || ! is_array( $this->options['excluded_paths'] ) ) {
            return array();
        }

        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $found = array();
        $roots = array_keys( $this->code_roots() );

        foreach ( $roots as $root ) {
            if ( $this->is_path_excluded( ABSPATH . $root . '/.' ) ) {
                $found[ $root ] = true;
            }
        }

        $plugins_root = $this->relative_path( WP_PLUGIN_DIR );

        if ( ! isset( $found[ $plugins_root ] ) ) {
            foreach ( array_keys( get_plugins() ) as $plugin_file ) {
                $slug = dirname( $plugin_file );

                if ( '.' !== $slug && $this->is_path_excluded( WP_PLUGIN_DIR . '/' . $slug . '/.' ) ) {
                    $found[ $this->relative_path( WP_PLUGIN_DIR . '/' . $slug ) ] = true;
                }
            }
        }

        foreach ( wp_get_themes() as $theme ) {
            $dir = $theme->get_stylesheet_directory();

            if ( ! isset( $found[ $this->relative_path( dirname( $dir ) ) ] ) && $this->is_path_excluded( $dir . '/.' ) ) {
                $found[ $this->relative_path( $dir ) ] = true;
            }
        }

        if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) && $this->is_path_excluded( WPMU_PLUGIN_DIR . '/.' ) ) {
            $found[ $this->relative_path( WPMU_PLUGIN_DIR ) ] = true;
        }

        $uploads = wp_get_upload_dir();

        if ( ! empty( $uploads['basedir'] ) && $this->is_path_excluded( $uploads['basedir'] . '/.' ) ) {
            $found[ $this->relative_path( $uploads['basedir'] ) ] = true;
        }

        return array_keys( $found );
    }

    /**
     * Whether a scan checked less than it was asked to
     *
     * Either it ran out of time, or something could not be read or compared
     * (a folder, a plugin whose copy on WordPress.org could not be fetched).
     * The tab, the scan email and Security Check go by this, so none of them
     * calls clean a result that covers only part of the site.
     *
     * @param mixed $results Scan results, as run_scan() returns them.
     * @return bool
     */
    public static function is_partial( $results ) {
        return is_array( $results ) && ( ! empty( $results['incomplete'] ) || ! empty( $results['errors'] ) );
    }

    /**
     * What a scan did not get to, one line per thing
     *
     * The one source of that text, for the tab, the scan email and anything
     * else that shows the result of a scan. In the order of the scan.
     *
     * @param mixed $results Scan results, as run_scan() returns them.
     * @return array Lines ready to show, not escaped. Empty when nothing was
     *               left out.
     */
    public static function not_checked_lines( $results ) {
        $left = is_array( $results ) && isset( $results['not_checked'] ) && is_array( $results['not_checked'] ) ? $results['not_checked'] : array();

        $areas   = isset( $left['areas'] ) && is_array( $left['areas'] ) ? $left['areas'] : array();
        $plugins = isset( $left['plugins'] ) && is_array( $left['plugins'] ) ? array_filter( array_map( 'strval', $left['plugins'] ), 'strlen' ) : array();
        $themes  = isset( $left['themes'] ) && is_array( $left['themes'] ) ? array_filter( array_map( 'strval', $left['themes'] ), 'strlen' ) : array();
        $lines   = array();

        if ( in_array( 'uploads', $areas, true ) ) {
            $lines[] = __( 'The uploads folder was not checked.', 'vigilante' );
        }

        if ( in_array( 'core', $areas, true ) ) {
            $lines[] = __( 'The WordPress files were not checked completely.', 'vigilante' );
        }

        if ( in_array( 'config', $areas, true ) ) {
            $lines[] = __( 'wp-config.php and .htaccess were not compared.', 'vigilante' );
        }

        if ( in_array( 'content', $areas, true ) ) {
            $lines[] = __( 'The other folders of wp-content were not checked.', 'vigilante' );
        }

        if ( in_array( 'plugins', $areas, true ) ) {
            $lines[] = __( 'No plugin was checked.', 'vigilante' );
        } elseif ( ! empty( $plugins ) ) {
            /* translators: %s: Comma separated list of plugin names */
            $lines[] = sprintf( __( 'Plugins not checked: %s.', 'vigilante' ), implode( ', ', $plugins ) );
        }

        if ( in_array( 'unlisted', $areas, true ) ) {
            $lines[] = __( 'Must-use plugins, drop-ins and loose PHP files were not checked.', 'vigilante' );
        }

        if ( in_array( 'themes', $areas, true ) ) {
            $lines[] = __( 'No theme was checked.', 'vigilante' );
        } elseif ( ! empty( $themes ) ) {
            /* translators: %s: Comma separated list of theme names */
            $lines[] = sprintf( __( 'Themes not checked: %s.', 'vigilante' ), implode( ', ', $themes ) );
        }

        // Why it had less time than usual: the server gives a request less
        // than a scan needs, and does not let it ask for more (since 3.0.8;
        // see fit_to_time_limit()).
        if ( ! empty( $lines ) && ! empty( $results['time_limit'] ) && ! empty( $results['scan_budget'] ) ) {
            if ( 'cpu' === ( $results['budget_clock'] ?? '' ) ) {
                $lines[] = sprintf(
                    /* translators: 1: seconds of processor time the server gives a request, 2: seconds the scan used */
                    __( 'This server gives a request %1$d seconds of PHP processing time and does not let the scan ask for more, so the scan stopped after %2$d of them, to be able to save its result. More time for PHP, from your hosting, lets it check more.', 'vigilante' ),
                    (int) $results['time_limit'],
                    (int) $results['scan_budget']
                );
            } else {
                $lines[] = sprintf(
                    /* translators: 1: seconds the server gives a request, 2: seconds the scan had */
                    __( 'This server gives a request %1$d seconds and does not let the scan ask for more, so the scan had %2$d seconds, to be able to save its result. More time for PHP, from your hosting, lets it check more.', 'vigilante' ),
                    (int) $results['time_limit'],
                    (int) $results['scan_budget']
                );
            }
        }

        return $lines;
    }

    /**
     * Whether the scheduled scan has not finished for longer than it should
     *
     * A scan that PHP or the server stops halfway stores nothing, so the date
     * of the last one that finished is the only sign left. Twice the interval
     * and one day more, because WP-Cron only runs when the site has a visit.
     *
     * @param int    $last_scan Time of the last stored scan, 0 for none.
     * @param string $frequency 'daily' or 'weekly'.
     * @return bool
     */
    public static function is_scan_overdue( $last_scan, $frequency ) {
        $last_scan = (int) $last_scan;

        if ( $last_scan <= 0 ) {
            return false;
        }

        $every = 'weekly' === $frequency ? WEEK_IN_SECONDS : DAY_IN_SECONDS;

        return ( time() - $last_scan ) > ( 2 * $every + DAY_IN_SECONDS );
    }

    /**
     * What a kind of finding usually is, and what to do about it
     *
     * The one source of the text shown next to the findings of a scan, so the
     * File Integrity tab and anything else that explains them say the same.
     * Vigilant's own files have their own source,
     * Vigilante_Self_Integrity_Guidance.
     *
     * @param string $type Finding type as stored in the scan results.
     * @return array {
     *     @type string $label  Name of the kind of finding, for a table cell.
     *     @type string $advice What it usually is and what to do. Empty for a
     *                          type this method does not know.
     * }
     */
    public static function finding_guidance( $type ) {
        switch ( $type ) {
            case 'php_in_uploads':
                return array(
                    'label'  => __( 'PHP in uploads', 'vigilante' ),
                    'advice' => __( 'Uploads is meant for media, not for code. It is normal only when a plugin you use writes PHP there, such as compiled templates or cache files: ignore the file, or add its folder to Excluded Paths if new ones keep appearing. If nothing you use explains it, treat it as malware.', 'vigilante' ),
                );

            case 'double_extension':
                return array(
                    'label'  => __( 'Double extension', 'vigilante' ),
                    'advice' => __( 'A name such as photo.php.jpg is a common way to pass a script off as an image. Delete it unless you know who or what uploaded it.', 'vigilante' ),
                );

            case 'htaccess_in_uploads':
                return array(
                    'label'  => __( '.htaccess in uploads', 'vigilante' ),
                    'advice' => __( 'A .htaccess here changes how the server treats this folder. One that only denies access is not listed. If it makes files run as code (AddHandler, SetHandler, php_value, Options ExecCGI) and you did not put it there, it is a sign of infection. If it only has rewrite rules, it usually belongs to an image or cache plugin, and it switches off for this folder the rule that blocks PHP in uploads.', 'vigilante' ),
                );

            case 'php_in_root':
                return array(
                    'label'  => __( 'PHP in the site root', 'vigilante' ),
                    'advice' => __( 'A PHP file next to wp-config.php that WordPress does not ship. Hosting tools, firewalls and verification scripts put files here, and so do attackers. Ignore it if you know where it comes from; if you do not, look at what it contains before anything else.', 'vigilante' ),
                );

            case 'extra_root':
                return array(
                    'label'  => __( 'Extra file in the site root', 'vigilante' ),
                    'advice' => __( 'WordPress does not ship this file. Verification files and the like are harmless. A copy of wp-config.php, a database dump or a backup archive here can be downloaded by anyone who guesses its name: move it out of the web root.', 'vigilante' ),
                );

            case 'legacy_core':
                return array(
                    'label'  => __( 'Old core file', 'vigilante' ),
                    'advice' => __( 'Left behind by an earlier version of WordPress. Nothing uses it any more and it can be deleted.', 'vigilante' ),
                );

            case 'suspicious_plugin':
            case 'suspicious_theme':
                return array(
                    'label'  => 'suspicious_theme' === $type ? __( 'Hidden code in a theme', 'vigilante' ) : __( 'Hidden code in a plugin', 'vigilante' ),
                    'advice' => __( 'The file contains code written the way malware hides itself, and it is not part of the published copy, or there is no published copy to compare with. Some commercial plugins and themes obfuscate their own code and end up here. If you cannot tell, replace the plugin or theme with a clean copy from its author.', 'vigilante' ),
                );

            case 'extra_plugin':
            case 'extra_theme':
                return array(
                    'label'  => 'extra_theme' === $type ? __( 'Extra file in a theme', 'vigilante' ) : __( 'Extra file in a plugin', 'vigilante' ),
                    'advice' => __( 'A PHP file that is not in the copy WordPress.org publishes for the installed version. Some plugins and themes create files after they are installed, and a manual fix adds them too. If you cannot explain it, reinstall the plugin or theme: that removes everything that does not belong to it.', 'vigilante' ),
                );

            case 'php_in_core':
                return array(
                    'label'  => __( 'PHP in a WordPress folder', 'vigilante' ),
                    'advice' => __( 'A PHP file in wp-admin or wp-includes that the installed version of WordPress does not ship. It is either left over from an older version or put there by someone: compare it with a clean copy of WordPress and delete it if it is not in it.', 'vigilante' ),
                );

            case 'config_in_core':
                return array(
                    'label'  => __( 'Configuration file in a WordPress folder', 'vigilante' ),
                    'advice' => __( 'A .htaccess, .user.ini or php.ini in wp-admin or wp-includes. A .htaccess that asks for a password in wp-admin is a common protection, and some hosts leave a php.ini there. A line with auto_prepend_file or auto_append_file loads a file on every request: make sure you know which one.', 'vigilante' ),
                );

            case 'php_config_in_uploads':
                return array(
                    'label'  => __( 'PHP configuration in uploads', 'vigilante' ),
                    'advice' => __( 'A .user.ini or php.ini here changes how PHP runs for this folder, and can make it load another file on every request. Nothing in uploads needs one: delete it unless you put it there.', 'vigilante' ),
                );

            case 'script_in_uploads':
                return array(
                    'label'  => __( 'Script in uploads', 'vigilante' ),
                    'advice' => __( 'A script in another language (shell, Perl, Python, CGI). It only runs if the server is told to run it, which a .htaccess in the same folder can do. Delete it unless you know why it is there.', 'vigilante' ),
                );

            case 'php_config_in_root':
                return array(
                    'label'  => __( 'PHP configuration in the site root', 'vigilante' ),
                    'advice' => __( 'This file makes PHP load another file before every request. Firewalls such as Wordfence set it up for themselves, and so do some hosts: check that the file it names is theirs. If nothing you installed needs it, that file runs before WordPress on every visit: treat it as a backdoor.', 'vigilante' ),
                );

            case 'backup_in_root':
                return array(
                    'label'  => __( 'Backup in the site root', 'vigilante' ),
                    'advice' => __( 'A copy of wp-config.php, a database dump or an archive next to WordPress can be downloaded by anyone who guesses its name, and it holds passwords or the whole site. Move it out of the web root or delete it.', 'vigilante' ),
                );

            case 'php_in_content':
                return array(
                    'label'  => __( 'Loose PHP in wp-content', 'vigilante' ),
                    'advice' => __( 'A PHP file, or a folder with PHP files, in wp-content or among the plugins or the themes, that WordPress does not list as a plugin, a theme or a drop-in. It does not show on the Plugins screen, and it can still be reached by its address. Some plugins keep a settings file there, WP Super Cache for one. If nothing you use explains it, look at what it contains.', 'vigilante' ),
                );

            case 'suspicious_content':
                return array(
                    'label'  => __( 'Hidden code in wp-content', 'vigilante' ),
                    'advice' => __( 'The file contains code written the way malware hides itself, in a folder of wp-content that belongs to no plugin and no theme. Cache, backup and security plugins keep files in folders like these, and what they store can look like this. Find out which one the folder belongs to. If nothing you use explains the file, treat it as malware.', 'vigilante' ),
                );

            case 'translation_with_code':
                return array(
                    'label'  => __( 'Translation file with code', 'vigilante' ),
                    'advice' => __( 'WordPress loads the translation files of the site language on every request, and a translation file holds text and nothing else. This one holds something more. Delete it and get the translations again from Dashboard > Updates. If it comes back, something on the site is writing it.', 'vigilante' ),
                );

            case 'not_searched':
                return array(
                    'label'  => __( 'File not searched', 'vigilante' ),
                    'advice' => __( 'The search for hidden code could not look inside this file, nearly always because it is very large, and there is no official copy to compare it with. A PHP file of that size is unusual. Check that it belongs to the plugin, the theme or the folder it is in, and ignore it if it does.', 'vigilante' ),
                );

            case 'server_config':
                return array(
                    'label'  => __( 'Server configuration file', 'vigilante' ),
                    'advice' => __( 'A .htaccess, .user.ini or php.ini outside uploads that makes the server run files as code or load a file on every request. Plugins rarely need one. If you cannot tell which one put it there, treat it as a sign of infection.', 'vigilante' ),
                );

            case 'core':
                return array(
                    'label'  => __( 'WordPress core', 'vigilante' ),
                    'advice' => __( 'Does not match the copy WordPress.org publishes for your version and language. For a file in wp-admin, wp-includes or the site root, reinstall WordPress from Dashboard > Updates and scan again. A file of a bundled theme or of Akismet, under wp-content, appears here after that theme or plugin updates on its own, which is normal.', 'vigilante' ),
                );

            case 'plugin':
            case 'theme':
                return array(
                    'label'  => 'theme' === $type ? __( 'Theme', 'vigilante' ) : __( 'Plugin', 'vigilante' ),
                    'advice' => __( 'Does not match the copy WordPress.org publishes for the installed version. The usual causes are an update that did not finish, a release replaced on WordPress.org without a new version number, or a manual edit. Reinstall it; if the file changes again by itself, investigate.', 'vigilante' ),
                );

            case 'critical_config':
                return array(
                    'label'  => __( 'Configuration file', 'vigilante' ),
                    'advice' => __( 'Changed since you last approved it. Cache, security and redirection plugins rewrite their own blocks in these files, often on every update, and that shows up here too. Review the changes and approve them if they belong to something you use. Lines you cannot explain, above all the ones that load a file or send requests to one, need a closer look.', 'vigilante' ),
                );
        }

        return array(
            'label'  => (string) $type,
            'advice' => '',
        );
    }

    /**
     * Check if a path is excluded from scanning
     *
     * @param string $path File path.
     * @return bool
     */
    private function is_path_excluded( $path ) {
        $excluded = $this->options['excluded_paths'] ?? array();

        if ( empty( $excluded ) ) {
            return false;
        }

        $relative = $this->relative_path( $path );

        foreach ( $excluded as $exclude ) {
            $exclude = trim( trim( str_replace( '\\', '/', (string) $exclude ) ), '/' );

            if ( '' === $exclude ) {
                continue;
            }

            /*
             * Two forms, both with real boundaries. Until 2.9.9 this was a plain
             * strpos() over the relative path, so an exclusion matched anywhere
             * inside it: "cache" also silenced a plugin folder named mycache,
             * "logs" silenced catalogs, and nothing told the user how much had
             * stopped being watched.
             *
             * Anything with a slash is a path: it excludes exactly that file, or
             * everything under it, anchored at the root of the installation.
             */
            if ( false !== strpos( $exclude, '/' ) ) {
                if ( $relative === $exclude || 0 === strpos( $relative, $exclude . '/' ) ) {
                    return true;
                }

                continue;
            }

            /*
             * A bare name excludes any folder called exactly that, at any depth,
             * which is what someone typing "languages" means. It has to be the
             * whole segment, not a fragment of one.
             */
            if ( $relative === $exclude
                || 0 === strpos( $relative, $exclude . '/' )
                || false !== strpos( $relative, '/' . $exclude . '/' ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Path relative to the WordPress directory, with forward slashes
     *
     * @since 2.9.9
     *
     * @param string $path Absolute path.
     * @return string
     */
    private function relative_path( $path ) {
        $path = str_replace( '\\', '/', (string) $path );
        $root = str_replace( '\\', '/', ABSPATH );

        if ( 0 === strpos( $path, $root ) ) {
            $path = substr( $path, strlen( $root ) );
        }

        return ltrim( $path, '/' );
    }

    /**
     * Check if a file extension is excluded from scanning
     *
     * @param string $path File path.
     * @return bool
     */
    private function is_extension_excluded( $path ) {
        $excluded = $this->options['excluded_extensions'] ?? array();

        if ( empty( $excluded ) ) {
            return false;
        }

        $extension = '.' . strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
        $relative  = strtolower( $this->relative_path( $path ) );

        foreach ( $excluded as $exclude ) {
            $exclude = strtolower( trim( (string) $exclude ) );

            if ( '' === $exclude ) {
                continue;
            }

            /*
             * An extension on its own is global, as it has always been. Since
             * 2.9.9 it can also be scoped to a folder, written as
             * wp-content/languages/*.json, because the global form is a blunt
             * instrument: excluding .json to quiet the translation files also
             * stopped watching the 173 block.json files of core.
             */
            $scope = '';

            if ( false !== strpos( $exclude, '*' ) ) {
                $parts   = explode( '*', $exclude, 2 );
                $scope   = trim( $parts[0], '/' );
                $exclude = $parts[1];
            }

            if ( '' === $exclude ) {
                continue;
            }

            // Support both ".log" and "log" formats
            if ( 0 !== strpos( $exclude, '.' ) ) {
                $exclude = '.' . $exclude;
            }

            if ( $exclude !== $extension ) {
                continue;
            }

            if ( '' === $scope ) {
                return true;
            }

            if ( $relative === $scope || 0 === strpos( $relative, $scope . '/' ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Filter out ignored files from results
     *
     * @param array $items Array of scan result items.
     * @return array Filtered items.
     */
    private function filter_ignored( $items ) {
        if ( empty( $this->ignored_files ) || empty( $items ) ) {
            return $items;
        }

        return array_values(
            array_filter(
                $items,
                function ( $item ) {
                    /*
                     * On a network, wp-config.php and the root .htaccess are not a
                     * site's to silence: a change to them is closed by approving it,
                     * and approving takes a network administrator since 2.11.3. The
                     * ignore list is an option of each site, so until 2.11.8 the
                     * administrator of the main site without network rights hid a
                     * pending change from the network administrator's own screen by
                     * posting the file name to the ignore handler.
                     */
                    if ( is_multisite() && is_array( $item ) && 'critical_config' === ( $item['type'] ?? '' ) ) {
                        return true;
                    }

                    // Findings about the manifest and the version of Vigilant
                    // itself are not about one file, so no entry of the list may
                    // hide them, on a single site either: ignoring the row of
                    // MANIFEST.sha256 took a replaced manifest out of the email.
                    // Vigilante_Self_Integrity::filter_ignored_findings() keeps
                    // them the same way.
                    if ( is_array( $item ) && 'vigilante_self' === ( $item['type'] ?? '' ) && in_array( $item['self_finding'] ?? '', array( 'manifest_replaced', 'manifest_unverified', 'manifest_missing', 'manifest_invalid', 'self_downgraded' ), true ) ) {
                        return true;
                    }
                    // Nor the findings of the walk of Vigilant's folder (a folder
                    // that cannot be listed, the folder that could not be walked):
                    // their path ends in a slash, and ignoring that row left the
                    // scan with no row and no email while the self-protection
                    // status stayed critical.
                    if ( is_array( $item ) && 'vigilante_self' === ( $item['type'] ?? '' ) && '/' === substr( (string) ( $item['file'] ?? '' ), -1 ) ) {
                        return true;
                    }

                    $file = is_array( $item ) && isset( $item['file'] ) ? $item['file'] : '';
                    return ! in_array( $file, $this->ignored_files, true );
                }
            )
        );
    }

    /**
     * Send email notification based on notify_level setting
     *
     * Supports three levels:
     * - 'all': notify on any issues (modified + suspicious + extra)
     * - 'suspicious_only': notify only when suspicious or extra files found
     * - 'disabled': never send
     *
     * Backward compatible with old notify_on_changes boolean.
     *
     * @param array $results Scan results.
     */
    private function maybe_send_notification( $results ) {
        $options = is_array( $this->options ) ? $this->options : array();

        // Closed/removed plugins (excluding ignored slugs) travel in this
        // email, in the same tier as a suspicious file.
        $closed_plugins = $this->collect_closed_plugins_for_email();

        /*
         * Self-protection is not part of this decision. Its alert is its own
         * and no setting switches it off, so this email is about the files of
         * the site: core, plugins, themes, uploads and the two shared
         * configuration files. Missing files do not send it on their own: it
         * has no section to list them in.
         */

        // Instant alert: every finding travels, modified files included,
        // whatever the level below says. A scan with nothing to report goes
        // through as well, so that what was reported is forgotten.
        if ( ! empty( $options['instant_alert'] ) ) {
            $this->send_new_findings( $results, 'all', $closed_plugins );
            return;
        }

        // Determine notify level with backward compatibility
        $notify_level = $options['notify_level'] ?? '';

        // Backward compat: if notify_level not set, check old boolean
        if ( empty( $notify_level ) ) {
            if ( ! empty( $options['notify_on_changes'] ) ) {
                $notify_level = 'all';
            } else {
                $notify_level = 'disabled';
            }
        }

        if ( 'disabled' === $notify_level ) {
            // Nothing is sent, and nothing stays on record as reported:
            // whoever switches the email back on is told about everything
            // that is pending then.
            delete_option( self::NOTIFIED_OPTION );
            return;
        }

        // 'suspicious_only' treats suspicious/extra, critical_config AND closed
        // plugins as serious. A scan with nothing to send at this level still
        // goes through send_new_findings(), which then forgets what it had
        // reported, so a finding that goes away and comes back is new again.
        $this->send_new_findings( $results, $notify_level, $closed_plugins );
    }

    /**
     * What the scan email has already reported to the recipients
     */
    const NOTIFIED_OPTION = 'vigilante_integrity_notified';

    /**
     * Send the scan email only when the scan found something new
     *
     * Until now the email went out after every scan for as long as a finding
     * was still listed, so a plugin that rewrote its block in .htaccess meant
     * the same alert every day until somebody approved the change. Now every
     * finding is reported once: the email goes out when a scan finds something
     * the recipients have not been told about, and it lists everything that is
     * pending, old and new.
     *
     * A finding is the file, its kind and its content (by its hash), so a
     * file that changes again under the same name is new, also when the
     * change keeps its size and its date. What goes away is forgotten, so it
     * is new again if it comes back. Nothing is recorded when the email could
     * not be sent, and the next scan tries again.
     *
     * @param array  $results        Scan results.
     * @param string $notify_level   'all' or 'suspicious_only'.
     * @param array  $closed_plugins Closed plugins, keyed by slug.
     */
    private function send_new_findings( $results, $notify_level, $closed_plugins ) {
        $keys = $this->notification_keys( $results, $closed_plugins, 'all' === $notify_level );
        $told = get_option( self::NOTIFIED_OPTION, array() );
        $told = is_array( $told ) ? $told : array();

        // A partial scan cannot tell whether what it did not reach is still
        // there, so it forgets nothing: with the findings of an unchecked
        // plugin forgotten, the next scan that reached it would report them
        // again as new, and on a site whose scans are always partial that
        // is the same email over and over.
        $known = self::is_partial( $results ) ? array_values( array_unique( array_merge( $keys, $told ) ) ) : $keys;

        // The record is bounded, and the comparison is not: what does not fit
        // in the record is reported again, never left out. The keys come in
        // order of importance, so what does not fit is the least of it.
        $record = array_slice( $known, 0, 5000 );

        if ( empty( array_diff( $keys, $told ) ) ) {
            if ( count( $record ) !== count( $told ) ) {
                update_option( self::NOTIFIED_OPTION, $record, false );
            }
            return;
        }

        if ( $this->send_notification( $results, $notify_level, $closed_plugins ) ) {
            update_option( self::NOTIFIED_OPTION, $record, false );
        }
    }

    /**
     * One key per finding the scan email would carry at this level
     *
     * @param array $results        Scan results.
     * @param array $closed_plugins Closed plugins, keyed by slug.
     * @param bool  $with_modified  Whether files that are only modified travel
     *                              in the email at this level.
     * @return array
     */
    private function notification_keys( $results, $closed_plugins, $with_modified ) {
        $keys = array(
            'config'     => array(),
            'closed'     => array(),
            'suspicious' => array(),
            'modified'   => array(),
            'extra'      => array(),
        );

        foreach ( (array) ( $results['modified'] ?? array() ) as $item ) {
            if ( ! is_array( $item ) ) {
                continue;
            }

            $type   = (string) ( $item['type'] ?? '' );
            $config = 'critical_config' === $type;

            // Vigilant's own files have their own alert.
            if ( 'vigilante_self' === $type || ( ! $config && ! $with_modified ) ) {
                continue;
            }

            $keys[ $config ? 'config' : 'modified' ][] = md5( 'modified|' . $type . '|' . (string) ( $item['file'] ?? '' ) . '|' . (string) ( $item['actual_hash'] ?? '' ) );
        }

        foreach ( (array) $closed_plugins as $slug => $info ) {
            $keys['closed'][] = md5( 'closed|' . $slug . '|' . ( is_array( $info ) ? (string) ( $info['state'] ?? '' ) : '' ) );
        }

        foreach ( array( 'suspicious', 'extra' ) as $bucket ) {
            foreach ( (array) ( $results[ $bucket ] ?? array() ) as $item ) {
                $type = is_array( $item ) ? (string) ( $item['type'] ?? '' ) : '';

                if ( 'vigilante_self' === $type ) {
                    continue;
                }

                $file  = is_array( $item ) ? (string) ( $item['file'] ?? '' ) : (string) $item;
                $state = '';
                $path  = ABSPATH . ltrim( $file, '/' );

                // By content, so a file rewritten with the same size and the
                // same date is still a different file. The ones too large to
                // hash on every scan go by size, date and the time of their
                // last change of any kind, which writing to a file moves and
                // which cannot be set back the way the date can.
                if ( '' !== $file && is_file( $path ) ) {
                    $state = filesize( $path ) <= MB_IN_BYTES ? (string) md5_file( $path ) : filesize( $path ) . ':' . filemtime( $path ) . ':' . filectime( $path );
                }

                $keys[ $bucket ][] = md5( $bucket . '|' . $type . '|' . $file . '|' . $state );
            }
        }

        // In order of importance: only the first 5,000 are remembered, and
        // what is not remembered is reported again.
        return array_values( array_unique( array_merge( $keys['config'], $keys['closed'], $keys['suspicious'], $keys['modified'], $keys['extra'] ) ) );
    }

    /**
     * Collect the closed/removed plugins (excluding ignored slugs) so they can
     * be folded into the scan email digest. Returns an array keyed by slug.
     *
     * @return array
     */
    private function collect_closed_plugins_for_email() {
        if ( empty( $this->options['check_closed_plugins'] ) ) {
            return array();
        }
        if ( ! class_exists( 'Vigilante_Plugin_Status' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-plugin-status.php';
        }
        $checker = new Vigilante_Plugin_Status( $this->settings, $this->activity_log );
        return $checker->get_closed_plugins();
    }

    /**
     * Merge scan results
     *
     * @param array $results1 First results.
     * @param array $results2 Second results.
     * @return array Merged results.
     */
    private function merge_results( $results1, $results2 ) {
        return array(
            'scanned'    => $results1['scanned'] + ( $results2['scanned'] ?? 0 ),
            'ok'         => $results1['ok'] + ( $results2['ok'] ?? 0 ),
            'modified'   => array_merge( $results1['modified'], $results2['modified'] ?? array() ),
            'missing'    => array_merge( $results1['missing'] ?? array(), $results2['missing'] ?? array() ),
            'suspicious' => array_merge( $results1['suspicious'] ?? array(), $results2['suspicious'] ?? array() ),
            'extra'      => array_merge( $results1['extra'] ?? array(), $results2['extra'] ?? array() ),
            'new'        => $results1['new'] ?? array(),
            'errors'     => array_merge( $results1['errors'] ?? array(), $results2['errors'] ?? array() ),
            // Plugins and themes with no official copy to compare with.
            'unverified' => array_merge( $results1['unverified'] ?? array(), $results2['unverified'] ?? array() ),
            'scan_time'  => $results1['scan_time'] ?? 0,
            'incomplete' => $results1['incomplete'] ?? false,
        );
    }

    /**
     * Send notification email about scan results
     *
     * @param array  $results        Scan results.
     * @param string $notify_level   Notification level ('all' or 'suspicious_only').
     * @param array  $closed_plugins Optional map of slug=>state-entry for closed/removed
     *                                plugins to include as a dedicated section.
     */
    private function send_notification( $results, $notify_level = 'all', $closed_plugins = array() ) {
        $to = Vigilante_Email_Template::get_admin_recipients();
        $site_name = get_bloginfo( 'name' );

        // Split critical_config files from regular modified so they get their own
        // prominent section in the email, next to suspicious/extra.
        $critical_config = array();
        $regular_modified = array();
        foreach ( $results['modified'] ?? array() as $item ) {
            if ( is_array( $item ) && isset( $item['type'] ) && 'critical_config' === $item['type'] ) {
                // Synthesize a reason string with size + line-diff info so get_section_html shows it
                $baseline_size = $item['baseline_size'] ?? 0;
                $current_size  = $item['current_size'] ?? 0;
                $added_count   = is_array( $item['diff'] ?? null ) ? count( $item['diff']['added'] ?? array() ) : 0;
                $removed_count = is_array( $item['diff'] ?? null ) ? count( $item['diff']['removed'] ?? array() ) : 0;
                $diff_unavail  = is_array( $item['diff'] ?? null ) && ! empty( $item['diff']['unavailable'] );

                $reason = sprintf(
                    /* translators: 1: baseline size, 2: current size */
                    __( '%1$s → %2$s bytes', 'vigilante' ),
                    number_format_i18n( $baseline_size ),
                    number_format_i18n( $current_size )
                );
                if ( ! $diff_unavail ) {
                    $reason .= sprintf( ' (+%d / -%d %s)', $added_count, $removed_count, __( 'lines', 'vigilante' ) );
                }

                $item['reason'] = $reason;
                $critical_config[] = $item;
            } else {
                $regular_modified[] = $item;
            }
        }

        /*
         * Self-protection does not travel in this email any more: it has its own
         * alert, which no setting switches off (Vigilante_Self_Integrity::
         * maybe_send_self_alert()). Older stored results can still carry its
         * rows, so they are dropped here instead of being listed as ordinary
         * files.
         */
        foreach ( array( 'suspicious', 'extra', 'missing' ) as $self_bucket ) {
            if ( empty( $results[ $self_bucket ] ) || ! is_array( $results[ $self_bucket ] ) ) {
                continue;
            }
            $results[ $self_bucket ] = array_values(
                array_filter(
                    $results[ $self_bucket ],
                    function ( $item ) {
                        return ! ( is_array( $item ) && 'vigilante_self' === ( $item['type'] ?? '' ) );
                    }
                )
            );
        }
        $regular_modified = array_values(
            array_filter(
                $regular_modified,
                function ( $item ) {
                    return ! ( is_array( $item ) && 'vigilante_self' === ( $item['type'] ?? '' ) );
                }
            )
        );

        $suspicious_count      = count( $results['suspicious'] ?? array() );
        $extra_count           = count( $results['extra'] ?? array() );
        $critical_config_count = count( $critical_config );
        $modified_count        = count( $regular_modified );
        $closed_count          = count( $closed_plugins );

        // The subject says what was found. Suspicious files and closed plugins
        // keep the alert wording. A change in wp-config.php or .htaccess with
        // nothing else next to it names the files instead: most of the time it
        // is a plugin rewriting its own block, and "SECURITY ALERT" on every
        // one of those taught people to read the subject as "I was hacked".
        if ( $suspicious_count > 0 || $closed_count > 0 ) {
            $subject = sprintf(
                /* translators: %s: Site name */
                __( '[%s] SECURITY ALERT: File integrity issues detected', 'vigilante' ),
                $site_name
            );
        } elseif ( $critical_config_count > 0 ) {
            $changed = array();
            foreach ( $critical_config as $item ) {
                $changed[] = (string) ( $item['file'] ?? '' );
            }

            $subject = sprintf(
                /* translators: 1: Site name, 2: The file that changed, or both of them, such as "wp-config.php, .htaccess" */
                __( '[%1$s] %2$s changed: review needed', 'vigilante' ),
                $site_name,
                implode( ', ', array_unique( array_filter( $changed ) ) )
            );
        } else {
            $subject = sprintf(
                /* translators: %s: Site name */
                __( '[%s] File integrity issues detected', 'vigilante' ),
                $site_name
            );
        }

        // Build HTML email using template wrapper
        $inner = '';

        // Summary counts
        $inner .= '<table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:20px;">';
        $inner .= '<tr>';
        if ( $suspicious_count > 0 ) {
            $inner .= $this->get_stat_cell( $suspicious_count, __( 'Suspicious', 'vigilante' ), '#d63638' );
        }
        if ( $extra_count > 0 ) {
            $inner .= $this->get_stat_cell( $extra_count, __( 'Extra', 'vigilante' ), '#b32d2e' );
        }
        if ( $critical_config_count > 0 ) {
            $inner .= $this->get_stat_cell( $critical_config_count, __( 'Critical', 'vigilante' ), '#e36210' );
        }
        if ( $closed_count > 0 ) {
            $inner .= $this->get_stat_cell( $closed_count, __( 'Closed', 'vigilante' ), '#d63638' );
        }
        if ( 'all' === $notify_level && $modified_count > 0 ) {
            $inner .= $this->get_stat_cell( $modified_count, __( 'Modified', 'vigilante' ), '#dba617' );
        }
        $inner .= $this->get_stat_cell( $results['scanned'] ?? 0, __( 'Scanned', 'vigilante' ), '#50575e' );
        $inner .= '</tr></table>';

        // Suspicious files section
        if ( ! empty( $results['suspicious'] ) ) {
            $inner .= $this->get_section_html(
                __( 'Suspicious files', 'vigilante' ),
                __( 'Files that can run code where none is expected, or that contain code written the way malware hides itself. Some are harmless, such as cache files a plugin generates or a .htaccess that protects a folder: check the path and the reason before acting.', 'vigilante' ),
                $results['suspicious'],
                '#d63638',
                '#fef1f1',
                20,
                true
            );
        }

        // Extra files section
        if ( ! empty( $results['extra'] ) ) {
            $inner .= $this->get_section_html(
                __( 'Extra files', 'vigilante' ),
                __( 'Files that are not part of WordPress, or of the plugin or theme they sit in. Many are legitimate. A copy of wp-config.php or a database dump in the site root should be moved out of it.', 'vigilante' ),
                $results['extra'],
                '#b32d2e',
                '#fdf6f4',
                20,
                true
            );
        }

        // Critical config files section (wp-config.php, .htaccess modified outside Vigilante)
        if ( ! empty( $critical_config ) ) {
            $inner .= $this->get_section_html(
                __( 'Critical config files modified', 'vigilante' ),
                __( 'Changed since you last approved them. Cache, security and redirection plugins rewrite their own blocks in these files, often on every update, and attackers write to them too. Review the changes and approve them if they belong to something you use.', 'vigilante' ),
                $critical_config,
                '#e36210',
                '#fdf2e6',
                10,
                true
            );
        }

        // Modified files section (only if notify_level is 'all')
        if ( 'all' === $notify_level && ! empty( $regular_modified ) ) {
            $inner .= $this->get_section_html(
                __( 'Modified files', 'vigilante' ),
                __( 'These files do not match the copy WordPress.org publishes for the installed version. Reinstalling the plugin, the theme or WordPress brings the original back.', 'vigilante' ),
                $regular_modified,
                '#dba617',
                '#fdf8e8',
                15,
                false
            );
        }

        // Closed + Removed plugins section.
        // Same tier as suspicious files: WordPress.org has flagged the plugin as
        // closed or removed, the site keeps running its code, and ignoring the
        // finding is an explicit per-slug action by the admin.
        if ( $closed_count > 0 ) {
            $inner .= $this->build_closed_plugins_email_section( $closed_plugins );
        }

        // A partial scan says so and names what it did not get to. With no
        // finding in a plugin that was never looked at, silence here read as
        // "that plugin is fine".
        if ( self::is_partial( $results ) ) {
            $partial_lines = array_merge(
                array_slice( array_map( 'strval', (array) ( $results['errors'] ?? array() ) ), 0, 10 ),
                self::not_checked_lines( $results )
            );

            $inner .= '<p style="margin:0 0 8px;font-size:13px;color:#1d2327;"><strong>' . esc_html__( 'The last scan could not check everything, so its result is partial.', 'vigilante' ) . '</strong></p>';
            $inner .= '<ul style="margin:0 0 16px 18px;padding:0;font-size:13px;color:#50575e;">';

            foreach ( $partial_lines as $partial_line ) {
                $inner .= '<li>' . esc_html( $partial_line ) . '</li>';
            }

            $inner .= '</ul>';
        }

        // Where the explanation is. The email stays a list; what each kind of
        // finding usually is and what to do about it lives next to the results.
        $inner .= '<p style="margin:0 0 16px;font-size:12px;color:#50575e;">' . esc_html__( 'File Integrity explains what each kind of finding usually is and what to do about it. A finding stays listed until you approve it, ignore it or fix it.', 'vigilante' ) . '</p>';

        // CTA button
        $inner .= Vigilante_Email_Template::button(
            admin_url( 'admin.php?page=vigilante&tab=file-integrity#vigilante-section-fi-last-scan' ),
            __( 'Review in Vigilant', 'vigilante' )
        );

        $is_alert = ( $suspicious_count > 0 || $critical_config_count > 0 || $closed_count > 0 );

        // Same three cases as the subject.
        if ( $suspicious_count > 0 || $closed_count > 0 ) {
            $title = __( 'Security alert', 'vigilante' );
        } elseif ( $critical_config_count > 0 ) {
            $title = __( 'Configuration file changed', 'vigilante' );
        } else {
            $title = __( 'File integrity report', 'vigilante' );
        }

        // The caller records what was reported only when the email went out.
        return (bool) Vigilante_Email_Template::send( $to, $subject, $title, $inner, $is_alert );
    }

    /**
     * Build the closed + removed plugins block for the scan email.
     *
     * Reuses the same visual treatment as the suspicious files section
     * (red accent, danger description) because the security tier is the
     * same: WordPress.org has marked the plugin as compromised or removed.
     *
     * @param array $closed_plugins Map of slug=>state entry.
     * @return string HTML block.
     */
    private function build_closed_plugins_email_section( $closed_plugins ) {
        $color    = '#d63638';
        $bg_color = '#fef1f1';
        $title    = __( 'Closed + Removed plugins', 'vigilante' );
        $desc     = __( 'These plugins have been closed in the WordPress.org repository. Closures usually indicate malware, security issues, guideline violations, or supply chain attacks. Uninstall and replace as soon as possible.', 'vigilante' );

        $html  = '<div style="background:' . $bg_color . ';border-left:4px solid ' . $color . ';border-radius:4px;padding:14px 16px;margin-bottom:16px;">';
        $html .= '<h2 style="margin:0 0 4px;font-size:14px;color:' . $color . ';">' . esc_html( $title ) . '</h2>';
        $html .= '<p style="margin:0 0 12px;font-size:12px;color:#50575e;">' . esc_html( $desc ) . '</p>';

        $html .= '<table cellpadding="0" cellspacing="0" border="0" width="100%" style="font-size:12px;">';
        foreach ( $closed_plugins as $slug => $entry ) {
            $name        = isset( $entry['name'] ) ? $entry['name'] : $slug;
            $version     = isset( $entry['version'] ) ? $entry['version'] : '';
            $state       = isset( $entry['state'] ) ? $entry['state'] : '';
            $state_label = 'closed' === $state ? __( 'Closed', 'vigilante' ) : __( 'Removed', 'vigilante' );
            $closed_date = isset( $entry['closed_date'] ) ? $entry['closed_date'] : '';
            $reason      = isset( $entry['closed_reason_text'] ) && '' !== $entry['closed_reason_text']
                ? $entry['closed_reason_text']
                : '';

            $detail_bits = array();
            $detail_bits[] = $state_label;
            if ( '' !== $closed_date ) {
                $detail_bits[] = esc_html( $closed_date );
            }
            if ( '' !== $version ) {
                $detail_bits[] = 'v' . esc_html( $version );
            }

            $html .= '<tr>';
            $html .= '<td style="padding:4px 0;color:#1d2327;font-family:Consolas,Monaco,monospace;font-size:11px;word-break:break-all;">';
            $html .= '<strong>' . esc_html( $name ) . '</strong> &middot; <a href="' . esc_url( 'https://wordpress.org/plugins/' . $slug . '/' ) . '" style="color:#2271b1;text-decoration:none;"><code>' . esc_html( $slug ) . '</code></a>';
            $html .= '</td></tr>';
            $html .= '<tr><td style="padding:0 0 4px 12px;color:#787c82;font-size:11px;">' . esc_html( implode( ' &middot; ', array_map( 'wp_strip_all_tags', $detail_bits ) ) ) . '</td></tr>';
            if ( '' !== $reason ) {
                $html .= '<tr><td style="padding:0 0 8px 12px;color:#787c82;font-size:11px;font-style:italic;">' . esc_html( $reason ) . '</td></tr>';
            }
        }
        $html .= '</table>';
        $html .= '</div>';

        return $html;
    }

    /**
     * Get a summary stat cell for email
     *
     * @param int    $count Stat count.
     * @param string $label Stat label.
     * @param string $color Color hex.
     * @return string HTML table cell.
     */
    private function get_stat_cell( $count, $label, $color ) {
        $html  = '<td style="text-align:center;padding:12px 8px;">';
        $html .= '<div style="font-size:24px;font-weight:700;color:' . $color . ';line-height:1.2;">' . (int) $count . '</div>';
        $html .= '<div style="font-size:11px;color:#50575e;text-transform:uppercase;letter-spacing:0.5px;">' . esc_html( $label ) . '</div>';
        $html .= '</td>';

        return $html;
    }

    /**
     * Get an HTML section for file list in email
     *
     * @param string $title       Section title.
     * @param string $description Section description.
     * @param array  $files       Array of file items.
     * @param string $color       Accent color.
     * @param string $bg_color    Background color.
     * @param int    $max         Max files to show.
     * @param bool   $show_reason Whether to show reason column.
     * @return string HTML.
     */
    private function get_section_html( $title, $description, $files, $color, $bg_color, $max, $show_reason ) {
        $total = count( $files );
        $shown = array_slice( $files, 0, $max );

        $html  = '<div style="background:' . $bg_color . ';border-left:4px solid ' . $color . ';border-radius:4px;padding:14px 16px;margin-bottom:16px;">';
        $html .= '<h2 style="margin:0 0 4px;font-size:14px;color:' . $color . ';">' . esc_html( $title ) . '</h2>';
        $html .= '<p style="margin:0 0 12px;font-size:12px;color:#50575e;">' . esc_html( $description ) . '</p>';

        $html .= '<table cellpadding="0" cellspacing="0" border="0" width="100%" style="font-size:12px;">';
        foreach ( $shown as $file ) {
            $file_path = is_array( $file ) ? ( $file['file'] ?? '' ) : (string) $file;
            $reason    = is_array( $file ) ? ( $file['reason'] ?? '' ) : '';

            $html .= '<tr>';
            $html .= '<td style="padding:4px 0;color:#1d2327;font-family:Consolas,Monaco,monospace;font-size:11px;word-break:break-all;">' . esc_html( $file_path ) . '</td>';
            $html .= '</tr>';

            if ( $show_reason && ! empty( $reason ) ) {
                $html .= '<tr>';
                $html .= '<td style="padding:0 0 8px 12px;color:#787c82;font-size:11px;font-style:italic;">' . esc_html( $reason ) . '</td>';
                $html .= '</tr>';
            }
        }
        $html .= '</table>';

        if ( $total > $max ) {
            $html .= '<p style="margin:8px 0 0;font-size:12px;color:#787c82;">';
            /* translators: %d: Number of additional files */
            $html .= sprintf( esc_html__( '... and %d more', 'vigilante' ), $total - $max );
            $html .= '</p>';
        }

        $html .= '</div>';

        return $html;
    }

    /**
     * Add a file to the ignored list
     *
     * The path is stored exactly as it comes: the callers are the AJAX
     * handlers, which have already read it and checked it against the shared
     * files and Vigilant's own, and the scan compares the stored strings with
     * the paths it finds one by one (in_array(), strict). This used to run
     * sanitize_text_field() over it, which deletes every %XX octet and collapses
     * repeated spaces, so the entry never matched the file it was made for
     * (measured on 1 oct 2026 against 3.0.1). Anything that is not a plain
     * string, is empty or carries tags is not a path and is refused. That guards
     * a direct caller: the AJAX handlers read the path with wp_strip_all_tags()
     * first, which shortens a name with a stray < instead of handing it over
     * intact (see ajax_ignore_file()).
     *
     * @param string $file_path Relative file path to ignore.
     * @return bool
     */
    public function ignore_file( $file_path ) {
        if ( ! is_string( $file_path ) || '' === $file_path || wp_strip_all_tags( $file_path ) !== $file_path ) {
            return false;
        }

        $ignored = get_option( 'vigilante_ignored_files', array() );

        if ( ! in_array( $file_path, $ignored, true ) ) {
            $ignored[] = $file_path;
            return update_option( 'vigilante_ignored_files', $ignored );
        }

        return true;
    }

    /**
     * Remove a file from the ignored list
     *
     * @param string $file_path Relative file path to stop ignoring.
     * @return bool
     */
    public function unignore_file( $file_path ) {
        $ignored = get_option( 'vigilante_ignored_files', array() );
        $ignored = array_values( array_diff( $ignored, array( $file_path ) ) );

        return update_option( 'vigilante_ignored_files', $ignored );
    }

    /**
     * Get the list of ignored files
     *
     * @return array
     */
    public function get_ignored_files() {
        return get_option( 'vigilante_ignored_files', array() );
    }

    /**
     * Clear all ignored files
     *
     * @return bool
     */
    public function clear_ignored_files() {
        return delete_option( 'vigilante_ignored_files' );
    }

    /**
     * Get last scan results
     *
     * @return array|false
     */
    public function get_last_scan_results() {
        return get_option( 'vigilante_last_integrity_results', false );
    }

    /**
     * Get last scan time
     *
     * @return int|false
     */
    public function get_last_scan_time() {
        return get_option( 'vigilante_last_integrity_scan', false );
    }

    /**
     * Clear stored hashes
     *
     * @return bool
     */
    public function clear_hashes() {
        return $this->database->clear_file_hashes();
    }
}

// The processor time when the plugin loads, the start of the budget of a scan
// where PHP counts processor time (see fit_to_time_limit()).
Vigilante_File_Integrity::note_load_cpu();
