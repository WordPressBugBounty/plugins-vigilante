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
     * Maximum scan time in seconds (default 60s for thorough scanning)
     *
     * @var int
     */
    private $max_scan_time = 60;

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
     * Vigilante markers used in .htaccess (firewall + security headers).
     *
     * @var array
     */
    private $htaccess_markers = array(
        array( '# BEGIN Vigilante Protection', '# END Vigilante Protection' ),
        array( '# BEGIN Vigilante Security Headers', '# END Vigilante Security Headers' ),
    );

    /**
     * Core files known to produce false positives in checksum comparison.
     * These are skipped during core scanning (e.g. version.php is rewritten
     * during auto-updates and localized installs, readme files vary by locale).
     *
     * @var array
     */
    private $core_known_false_positives = array(
        'wp-includes/version.php',
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
        return ( microtime( true ) - $this->scan_start_time ) > $this->max_scan_time;
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

        // Use settings from options page
        $options = is_array( $this->options ) ? $this->options : array();

        // Scan uploads for suspicious files FIRST (highest security priority)
        // PHP files in uploads are almost always malware
        if ( ! empty( $options['scan_uploads'] ) && ! $this->is_time_exceeded() ) {
            $upload_results = $this->scan_uploads();
            $results['suspicious'] = array_merge( $results['suspicious'], $upload_results['suspicious'] );
            $results['extra'] = array_merge( $results['extra'], $upload_results['extra'] );
        }

        // Scan core files
        if ( ! empty( $options['scan_core'] ) && ! $this->is_time_exceeded() ) {
            $core_results = $this->scan_core_files();
            $results = $this->merge_results( $results, $core_results );
        }

        // Scan root directory for non-core files (PHP = suspicious, others = additional)
        // Runs after core scan so checksums are already cached
        if ( ! empty( $options['scan_core'] ) && ! $this->is_time_exceeded() ) {
            $root_results = $this->scan_root_files();
            $results['suspicious'] = array_merge( $results['suspicious'], $root_results['suspicious'] );
            $results['extra'] = array_merge( $results['extra'], $root_results['extra'] );
        }

        // Scan critical config files (wp-config.php, .htaccess) against stored baseline
        if ( ! empty( $options['scan_critical_config'] ) && ! $this->is_time_exceeded() ) {
            $critical_results = $this->scan_critical_root_files();
            $results['modified'] = array_merge( $results['modified'], $critical_results );
        }

        // Scan plugins
        if ( ! empty( $options['scan_plugins'] ) && ! $this->is_time_exceeded() ) {
            $plugin_results = $this->scan_plugins();
            $results = $this->merge_results( $results, $plugin_results );
        }

        // Scan themes
        if ( ! empty( $options['scan_themes'] ) && ! $this->is_time_exceeded() ) {
            $theme_results = $this->scan_themes();
            $results = $this->merge_results( $results, $theme_results );
        }

        // Mark as incomplete if time was exceeded
        if ( $this->is_time_exceeded() ) {
            $results['incomplete'] = true;
            $results['errors'][] = __( 'Scan was incomplete due to time limit. Results may be partial.', 'vigilante' );
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
            
            $this->activity_log->log(
                'file',
                'integrity_scan',
                sprintf(
                    /* translators: 1: Scanned count, 2: Modified count, 3: Suspicious count, 4: Extra files count */
                    __( 'File integrity scan completed: %1$d files scanned, %2$d modified, %3$d suspicious, %4$d extra', 'vigilante' ),
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

        // Closed plugins check: queries the wp.org repository for the closure status
        // of every installed plugin slug. Independent of the file-level scan_* toggles
        // (gated by its own `check_closed_plugins` toggle in Scan Scope). Runs BEFORE
        // the notification call so closed plugins are folded into the scan email
        // (instead of triggering a separate one-shot). Quick (~10 s for 50 plugins).
        //
        // suppress_email=true: this entry point is the file integrity scan; the
        // daily plugin-status cron passes suppress_email=false so urgent closures
        // still produce an immediate alert when the file scan is on a weekly schedule.
        if ( ! empty( $options['check_closed_plugins'] ) ) {
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
        $checksums = $this->get_core_checksums();

        if ( is_wp_error( $checksums ) ) {
            $results['errors'][] = $checksums->get_error_message();
            return $results;
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

            // Skip known false positives (e.g. version.php, readme.html)
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

            $results['scanned']++;

            if ( ! file_exists( $file_path ) ) {
                $results['missing'][] = array(
                    'file' => $file,
                    'type' => 'core',
                );
                continue;
            }

            $actual_hash = md5_file( $file_path );

            if ( $actual_hash !== $expected_hash ) {
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

        $php_extensions = array( 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'phps' );

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

            // Skip dotfiles (.htaccess, .user.ini, .env, etc.) — handled by firewall protection
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
                if ( filesize( $full_path ) < 512000 ) {
                    $content = file_get_contents( $full_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
                    $pattern = $this->detect_suspicious_pattern( $content );
                    if ( $pattern ) {
                        /* translators: %s: Suspicious pattern found */
                        $reason = sprintf( __( 'Non-core PHP in root with suspicious code: %s', 'vigilante' ), $pattern );
                    }
                }

                $found['suspicious'][] = array(
                    'file'   => $entry,
                    'type'   => 'php_in_root',
                    'reason' => $reason,
                );
            } else {
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
    private function get_core_checksums( $force_refresh = false ) {
        $locale = get_locale();
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

        $response = wp_remote_get( $url, array( 'timeout' => 10 ) );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body['checksums'] ) ) {
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

        $plugins = get_plugins();

        foreach ( $plugins as $plugin_file => $plugin_data ) {
            // Check time limit
            if ( $this->is_time_exceeded() ) {
                break;
            }

            $plugin_slug = dirname( $plugin_file );

            // Skip single-file plugins
            if ( '.' === $plugin_slug ) {
                continue;
            }

            // Skip slugs in their post-update grace window: wp.org may still be
            // publishing the new version's checksums, so a scheduled scan here
            // would raise benign "modified/extra" noise. The dedicated post-update
            // verifier (vigilante_fi_postupdate_verify) handles these instead.
            if ( $this->in_post_update_grace( 'plugin', $plugin_slug ) ) {
                continue;
            }

            // Get checksums from WordPress.org
            $version = $plugin_data['Version'] ?? '';
            $checksums = $this->get_plugin_checksums( $plugin_slug, $version );

            $has_checksums = ! is_wp_error( $checksums ) && 'not_found' !== $checksums;

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
                    continue; // Some files might not be installed
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
            }
        }

        return $results;
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

        $response = wp_remote_get( $url, array( 'timeout' => 10 ) );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $status = wp_remote_retrieve_response_code( $response );
        if ( 200 !== $status ) {
            // Cache "not found" to avoid repeated requests (never during grace).
            if ( ! $grace ) {
                set_transient( $cache_key, 'not_found', HOUR_IN_SECONDS );
            }
            return 'not_found';
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

        $themes = wp_get_themes();

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
            }
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
        $cache_key = 'vigilante_theme_checksums_' . md5( $slug . $version );

        // Bypass the cache during the post-update grace window (see plugin path).
        $grace = $this->in_post_update_grace( 'theme', $slug );

        if ( ! $grace ) {
            $cached = get_transient( $cache_key );
            if ( false !== $cached ) {
                return $cached;
            }
        }

        $url = sprintf(
            'https://downloads.wordpress.org/theme-checksums/%s/%s.json',
            $slug,
            $version
        );

        $response = wp_remote_get( $url, array( 'timeout' => 10 ) );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $status = wp_remote_retrieve_response_code( $response );
        if ( 200 !== $status ) {
            // Cache "not found" to avoid repeated requests (never during grace).
            if ( ! $grace ) {
                set_transient( $cache_key, 'not_found', HOUR_IN_SECONDS );
            }
            return new WP_Error( 'not_found', __( 'Checksums not available', 'vigilante' ) );
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body['files'] ) ) {
            return new WP_Error( 'no_checksums', __( 'No checksums found', 'vigilante' ) );
        }

        // Store the full per-file record (md5 + sha256), either of which may be a
        // string or an array; hash_matches_published() handles both shapes.
        $checksums = array();
        foreach ( $body['files'] as $file => $data ) {
            $checksums[ $file ] = array(
                'md5'    => isset( $data['md5'] ) ? $data['md5'] : null,
                'sha256' => isset( $data['sha256'] ) ? $data['sha256'] : null,
            );
        }

        // Cache for 24 hours (never during grace).
        if ( ! $grace ) {
            set_transient( $cache_key, $checksums, DAY_IN_SECONDS );
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
        );
        $upload_dir = wp_upload_dir();
        $base_dir = $upload_dir['basedir'];
        $max_files = 10000; // Increased limit for thorough scanning
        $files_checked = 0;

        // Executable extensions that should never be in uploads
        $dangerous_extensions = array( 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'phps' );

        if ( ! is_dir( $base_dir ) ) {
            return $found;
        }

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator( $base_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ( $iterator as $file ) {
                // Check global time limit
                if ( $this->is_time_exceeded() ) {
                    break;
                }

                // Check file limit
                $files_checked++;
                if ( $files_checked > $max_files ) {
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
                    if ( $file->getSize() < 512000 ) { // Only scan files < 500KB
                        $content = file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
                        $pattern = $this->detect_suspicious_pattern( $content );
                        if ( $pattern ) {
                            /* translators: %s: Suspicious pattern found */
                            $reason = sprintf( __( 'PHP in uploads with suspicious code: %s', 'vigilante' ), $pattern );
                        }
                    }

                    $found['suspicious'][] = array(
                        'file'   => $relative,
                        'type'   => 'php_in_uploads',
                        'reason' => $reason,
                    );
                    continue;
                }

                // 2. Check for double extensions (image.php.jpg, file.phtml.png)
                if ( preg_match( '/\.(' . implode( '|', $dangerous_extensions ) . ')\.[a-z]{2,4}$/i', $basename ) ) {
                    $found['suspicious'][] = array(
                        'file'   => $relative,
                        'type'   => 'double_extension',
                        'reason' => __( 'Double extension detected (possible disguised executable)', 'vigilante' ),
                    );
                    continue;
                }

                // 3. Check for .htaccess files in uploads
                // Read content to classify: dangerous rules = suspicious, protective rules = extra
                if ( '.htaccess' === $basename ) {
                    $htaccess_result = $this->classify_htaccess_in_uploads( $file_path, $relative );
                    $found[ $htaccess_result['category'] ][] = $htaccess_result['item'];
                }
            }
        } catch ( Exception $e ) {
            // Ignore iterator errors
        }

        return $found;
    }

    /**
     * Classify a .htaccess file found in uploads directory
     *
     * Reads the file content to determine if it contains dangerous rules
     * (enabling PHP execution, rewriting to executables) or protective rules
     * (deny access, disable indexes). Dangerous = suspicious, protective = extra.
     *
     * @param string $file_path Absolute file path.
     * @param string $relative  Relative file path for display.
     * @return array Array with 'category' ('suspicious' or 'extra') and 'item' data.
     */
    private function classify_htaccess_in_uploads( $file_path, $relative ) {
        $content = '';

        if ( filesize( $file_path ) < 65536 ) { // Only read files < 64KB
            $content = file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        }

        // If we can't read it or it's empty, treat as suspicious (unknown)
        if ( empty( trim( $content ) ) ) {
            return array(
                'category' => 'suspicious',
                'item'     => array(
                    'file'   => $relative,
                    'type'   => 'htaccess_in_uploads',
                    'reason' => __( '.htaccess file in uploads directory (empty or unreadable)', 'vigilante' ),
                ),
            );
        }

        // Dangerous patterns: rules that enable code execution or rewrite to executables
        $dangerous_patterns = array(
            '/AddHandler\s+.*(php|cgi|pl|py)/i'          => 'AddHandler enabling script execution',
            '/AddType\s+application\/x-httpd-php/i'       => 'AddType enabling PHP execution',
            '/SetHandler\s+.*(php|cgi)/i'                 => 'SetHandler enabling script execution',
            '/php_flag\s+engine\s+on/i'                   => 'PHP engine enabled',
            '/php_admin_flag\s+engine\s+on/i'             => 'PHP admin engine enabled',
            '/RewriteRule\s+.*\.(php|phtml|phar)/i'       => 'Rewrite rule targeting PHP files',
            '/auto_prepend_file/i'                        => 'auto_prepend_file directive',
            '/auto_append_file/i'                         => 'auto_append_file directive',
        );

        foreach ( $dangerous_patterns as $pattern => $label ) {
            if ( preg_match( $pattern, $content ) ) {
                return array(
                    'category' => 'suspicious',
                    'item'     => array(
                        'file'   => $relative,
                        'type'   => 'htaccess_in_uploads',
                        /* translators: %s: Dangerous rule description */
                        'reason' => sprintf( __( '.htaccess with dangerous rule: %s', 'vigilante' ), $label ),
                    ),
                );
            }
        }

        // Identify what protective/benign rules it contains for informational display
        $found_rules = array();

        $benign_patterns = array(
            '/Deny\s+from\s+all/i'             => 'Deny from all',
            '/Require\s+all\s+denied/i'        => 'Require all denied',
            '/Options\s+.*-Indexes/i'          => 'Options -Indexes',
            '/Header\s+set/i'                  => 'Header rules',
            '/ExpiresActive/i'                 => 'Expires/cache rules',
            '/RewriteEngine/i'                 => 'Rewrite rules',
            '/FilesMatch/i'                    => 'FilesMatch rules',
            '/ForceType\s+application\/octet/i' => 'ForceType (force download)',
        );

        foreach ( $benign_patterns as $pattern => $label ) {
            if ( preg_match( $pattern, $content ) ) {
                $found_rules[] = $label;
            }
        }

        $rules_summary = ! empty( $found_rules )
            ? implode( ', ', $found_rules )
            : __( 'Custom rules', 'vigilante' );

        return array(
            'category' => 'extra',
            'item'     => array(
                'file'   => $relative,
                'type'   => 'htaccess_in_uploads',
                /* translators: %s: Summary of rules found in the .htaccess file */
                'reason' => sprintf( __( '.htaccess in uploads (likely from plugin). Contains: %s', 'vigilante' ), $rules_summary ),
            ),
        );
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
                return $label;
            }
        }

        // Check for preg_replace with /e modifier (code execution)
        if ( preg_match( '/preg_replace\s*\(\s*[\'"].*\/e[\'"]/i', $content ) ) {
            return 'preg_replace /e modifier';
        }

        // Check for long hex-encoded strings (obfuscated payloads)
        if ( preg_match( '/\\\\x[0-9a-f]{2}(\\\\x[0-9a-f]{2}){10,}/i', $content ) ) {
            return 'hex-encoded string';
        }

        // Check for heavily concatenated chr() calls (char-by-char obfuscation)
        if ( preg_match( '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr/i', $content ) ) {
            return 'chr() concatenation obfuscation';
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

        // Obfuscation combos: dangerous function wrapping decoded content
        $obfuscation_combos = array(
            '/' . $ev . '\s*\(\s*' . $b6 . '\s*\(/i'  => $ev . '(' . $b6 . '())',
            '/' . $ev . '\s*\(\s*' . $gz . '\s*\(/i'   => $ev . '(' . $gz . '())',
            '/' . $ev . '\s*\(\s*' . $gu . '\s*\(/i'   => $ev . '(' . $gu . '())',
            '/' . $ev . '\s*\(\s*' . $sr . '\s*\(/i'   => $ev . '(' . $sr . '())',
            '/' . $ev . '\s*\(\s*' . $hb . '\s*\(/i'   => $ev . '(' . $hb . '())',
            '/' . $as . '\s*\(\s*' . $b6 . '\s*\(/i'   => $as . '(' . $b6 . '())',
            '/' . $ev . '\s*\(\s*\$[a-z_]+\s*\(/i'     => $ev . '($variable())',
            '/' . $ev . '\s*\(\s*' . $ss . '\s*\(/i'   => $ev . '(' . $ss . '())',
        );

        foreach ( $obfuscation_combos as $regex => $label ) {
            if ( preg_match( $regex, $content ) ) {
                return $label;
            }
        }

        // Deprecated dynamic function constructor, nearly always malicious in modern code
        if ( ! empty( $cf ) && $this->needle_present( $content, $cf ) ) {
            return $cf . ')';
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
        $us = $fragments['us'] ?? '';
        if ( '' !== $us ) {
            $us_regex        = '/(?<![a-z0-9_])' . preg_quote( $us, '/' ) . '\s*\(/i';
            $remote_fetchers = array(
                $fragments['wr'] ?? '', // wp_remote_get
                $fragments['rb'] ?? '', // wp_remote_retrieve_body
                $fragments['ce'] ?? '', // curl_exec
            );
            foreach ( $remote_fetchers as $rf ) {
                if ( '' === $rf ) {
                    continue;
                }
                $rf_regex = '/(?<![a-z0-9_])' . preg_quote( $rf, '/' ) . '\s*\(/i';
                if ( $this->pattern_near( $content, $us_regex, $rf_regex, 600 ) ) {
                    return $rf . '() + ' . $us . '() remote deserialization';
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
                $fg_regex     = '/(?<![a-z0-9_])' . preg_quote( $fg, '/' ) . '\s*\(/i';
                $scheme_regex = '/(?:https?|ftps?):\/\/|php:\/\/input/i';

                if ( $this->pattern_near( $content, $us_regex, $fg_regex, 600 )
                    && $this->pattern_near( $content, $fg_regex, $scheme_regex, 600 ) ) {
                    return $fg . '() + ' . $us . '() remote deserialization';
                }
            }
        }

        // preg_replace with /e modifier (arbitrary code execution, deprecated)
        if ( preg_match( '/preg_replace\s*\(\s*[\'"].*\/e[\'"]/i', $content ) ) {
            return 'preg_replace /e modifier';
        }

        // Long hex-encoded strings (obfuscated payloads)
        if ( preg_match( '/\\\\x[0-9a-f]{2}(\\\\x[0-9a-f]{2}){10,}/i', $content ) ) {
            return 'hex-encoded string';
        }

        // Heavily concatenated chr() calls (char-by-char obfuscation)
        if ( preg_match( '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr/i', $content ) ) {
            return 'chr() concatenation obfuscation';
        }

        // Detect dangerous function names built from string concatenation
        if ( preg_match_all( '/\$([a-z_]\w*)\s*=\s*((?:["\'][a-z0-9_]*["\']\s*\.\s*)+["\'][a-z0-9_]*["\'])\s*;/i', $content, $matches, PREG_SET_ORDER ) ) {
            $dangerous_names = array();
            if ( ! empty( $patterns_data['dangerous_names'] ) ) {
                foreach ( $patterns_data['dangerous_names'] as $encoded_name ) {
                    // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
                    $dangerous_names[] = base64_decode( $encoded_name );
                }
            }

            foreach ( $matches as $match ) {
                $combined = strtolower( preg_replace( '/["\'\s\.]/', '', $match[2] ) );
                if ( in_array( $combined, $dangerous_names, true ) ) {
                    $var_pattern = '/\$' . preg_quote( $match[1], '/' ) . '\s*\(/';
                    if ( preg_match( $var_pattern, $content ) ) {
                        return 'obfuscated ' . $combined . '() call';
                    }
                }
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
            return (bool) preg_match( '/(?<![a-z0-9_])' . preg_quote( $fn, '/' ) . '\s*\(/i', $content );
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
        if ( ! preg_match_all( $regex_a, $content, $m_a, PREG_OFFSET_CAPTURE ) ) {
            return false;
        }
        if ( ! preg_match_all( $regex_b, $content, $m_b, PREG_OFFSET_CAPTURE ) ) {
            return false;
        }
        foreach ( $m_a[0] as $a ) {
            foreach ( $m_b[0] as $b ) {
                if ( abs( $a[1] - $b[1] ) <= $window ) {
                    return true;
                }
            }
        }
        return false;
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
        );
        $max_extra = 50; // Limit to prevent timeout on large plugins
        $count = 0;

        // Only check PHP files for performance
        $php_extensions = array( 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar' );

        // Pre-normalize the checksum keys once so path-shape differences
        // (Windows backslashes, a leading "./", doubled slashes) don't make a
        // known file look "extra" and get scanned or flagged. Case is preserved.
        $known_normalized = array();
        foreach ( array_keys( $checksums ) as $known_file ) {
            $known_normalized[ $this->normalize_rel_path( $known_file ) ] = true;
        }

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator( $directory, RecursiveDirectoryIterator::SKIP_DOTS ),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ( $iterator as $file ) {
                if ( $this->is_time_exceeded() || $count >= $max_extra ) {
                    break;
                }

                $file_path = $file->getPathname();
                $extension = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );

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

                $count++;
                $relative = str_replace( ABSPATH, '', $file_path );
                $pattern  = false;

                // Check for suspicious content in extra files
                // Use strict mode for plugins without checksums to avoid false positives
                if ( $file->getSize() < 512000 ) { // Only scan files < 500KB
                    $content = file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
                    $pattern = $this->detect_suspicious_pattern( $content, $suspicious_only );
                }

                $item = array(
                    'file' => $relative,
                    $type  => $name,
                );

                if ( $pattern ) {
                    // Suspicious content: promote to suspicious category
                    $item['type']   = 'suspicious_' . $type;
                    /* translators: 1: Plugin or theme name, 2: Suspicious pattern found */
                    $item['reason'] = sprintf( __( 'Injected file in %1$s with suspicious code: %2$s', 'vigilante' ), $name, $pattern );
                    $found['suspicious'][] = $item;
                } elseif ( ! $suspicious_only ) {
                    // No suspicious patterns and checksums available: report as extra
                    // Skipped in suspicious_only mode (no checksums) to avoid noise
                    $item['type']   = 'extra_' . $type;
                    $item['reason'] = __( 'PHP file not present in original distribution', 'vigilante' );
                    $found['extra'][] = $item;
                }
            }
        } catch ( Exception $e ) {
            // Ignore iterator errors
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

        $normalized = strtolower( trim( str_replace( array( "\r\n", "\r" ), "\n", $content ) ) );

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

        // Count critical_config separately from regular modified so we can treat it
        // as "serious" for notification level purposes (same tier as suspicious/extra).
        $has_critical_config = false;
        foreach ( $results['modified'] ?? array() as $item ) {
            if ( is_array( $item ) && isset( $item['type'] ) && 'critical_config' === $item['type'] ) {
                $has_critical_config = true;
                break;
            }
        }

        // Collect closed/removed plugins (excluding ignored slugs). These count
        // as "serious" for notification purposes: a closed plugin in wp.org is
        // a security-critical finding, same tier as a suspicious file.
        $closed_plugins = $this->collect_closed_plugins_for_email();
        $has_closed     = ! empty( $closed_plugins );

        $has_suspicious = ! empty( $results['suspicious'] ) || ! empty( $results['extra'] ) || $has_critical_config || $has_closed;
        $has_modified   = ! empty( $results['modified'] );

        // Instant alert: send for suspicious, extra, critical_config, modified
        // files, or closed plugins.
        $instant_alert = ! empty( $options['instant_alert'] );
        if ( $instant_alert && ( $has_suspicious || $has_modified ) ) {
            $this->send_notification( $results, 'all', $closed_plugins );
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
            return;
        }

        // 'suspicious_only' treats suspicious/extra, critical_config AND closed
        // plugins as serious.
        if ( 'suspicious_only' === $notify_level && ! $has_suspicious ) {
            return;
        }

        if ( ! $has_suspicious && ! $has_modified ) {
            return;
        }

        $this->send_notification( $results, $notify_level, $closed_plugins );
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

        $suspicious_count      = count( $results['suspicious'] ?? array() );
        $extra_count           = count( $results['extra'] ?? array() );
        $critical_config_count = count( $critical_config );
        $modified_count        = count( $regular_modified );
        $closed_count          = count( $closed_plugins );

        // Use more urgent subject when suspicious files, critical config changes
        // or closed plugins are found (all three are security-critical).
        if ( $suspicious_count > 0 || $critical_config_count > 0 || $closed_count > 0 ) {
            $subject = sprintf(
                /* translators: %s: Site name */
                __( '[%s] SECURITY ALERT: File integrity issues detected', 'vigilante' ),
                $site_name
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
                __( 'These files may contain malicious code. Review immediately.', 'vigilante' ),
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
                __( 'PHP files not in the original WordPress.org distribution.', 'vigilante' ),
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
                __( 'These files are common targets for code injection. Review the changes and approve if they are legitimate.', 'vigilante' ),
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
                __( 'Checksum mismatch with WordPress.org originals.', 'vigilante' ),
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

        // CTA button
        $inner .= Vigilante_Email_Template::button(
            admin_url( 'admin.php?page=vigilante&tab=file-integrity#vigilante-section-fi-last-scan' ),
            __( 'Review in Vigilant', 'vigilante' )
        );

        $is_alert = ( $suspicious_count > 0 || $critical_config_count > 0 || $closed_count > 0 );
        $title    = $is_alert
            ? __( 'Security alert', 'vigilante' )
            : __( 'File integrity report', 'vigilante' );

        Vigilante_Email_Template::send( $to, $subject, $title, $inner, $is_alert );
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
     * @param string $file_path Relative file path to ignore.
     * @return bool
     */
    public function ignore_file( $file_path ) {
        $ignored = get_option( 'vigilante_ignored_files', array() );

        if ( ! in_array( $file_path, $ignored, true ) ) {
            $ignored[] = sanitize_text_field( $file_path );
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