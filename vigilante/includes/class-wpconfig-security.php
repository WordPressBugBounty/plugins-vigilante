<?php
/**
 * WP-Config Security Class
 *
 * Manages wp-config.php security constants with MULTIPLE safety checks
 * Uses comment/uncomment strategy to handle existing constants
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Wpconfig_Security
 *
 * Applies security constants to wp-config.php
 */
class Vigilante_Wpconfig_Security {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Security options
     *
     * @var array
     */
    private $options;

    /**
     * Path to wp-config.php
     *
     * @var string
     */
    private $wpconfig_path;

    /**
     * Marker for our constants
     */
    const MARKER_START = '/* BEGIN Vigilante Security Constants */';
    const MARKER_END   = '/* END Vigilante Security Constants */';

    /**
     * Marker for commented original lines
     */
    const ORIGINAL_MARKER = '// [VIGILANTE_ORIGINAL] ';

    /**
     * Old plugin markers to clean
     */
    const OLD_MARKER_START = '/* BEGIN AyudaWP Security Constants */';
    const OLD_MARKER_END   = '/* END AyudaWP Security Constants */';

    /**
     * Minimum valid wp-config.php size in bytes
     */
    const MIN_CONFIG_SIZE = 1000;

    /**
     * Constants managed by this plugin
     *
     * @var array
     */
    private $managed_constants = array(
        'DISALLOW_FILE_EDIT',
        'DISALLOW_FILE_MODS',
        'FORCE_SSL_ADMIN',
        'FORCE_SSL_LOGIN',
        'WP_DEBUG',
        'WP_DEBUG_LOG',
        'WP_DEBUG_DISPLAY',
        'SCRIPT_DEBUG',
        'DISABLE_WP_CRON',
    );

    /**
     * Constructor
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    public function __construct( $settings ) {
        $this->settings      = $settings;
        $this->options       = $settings->get_section( 'wp_hardening' );
        $this->wpconfig_path = ABSPATH . 'wp-config.php';
    }

    /**
     * Option that holds the lock of the writers of wp-config.php
     *
     * @since 3.0.7
     */
    const LOCK_OPTION  = 'vigilante_wpconfig_write_lock';
    const LOCK_TIMEOUT = 30;

    /**
     * Apply security constants to wp-config.php
     *
     * Every step works on the content in memory and the file is written once,
     * at the end, after checking that the result is still valid PHP, and read
     * back afterwards. Until 3.0.6 it was up to four writes in a row (old block
     * out, originals uncommented, originals commented, block in), each with
     * file_put_contents() and none read back, so a failure or a second request
     * in the middle left the file halfway (A3 of the list of 3 Oct 2026).
     *
     * @return bool|WP_Error
     */
    public function apply_security_constants() {
        // Safety check 0: on a network this file belongs to the main site
        if ( ! Vigilante_Settings::can_write_shared_files() ) {
            return new WP_Error( 'network_not_owner', Vigilante_Settings::get_shared_files_notice() );
        }

        // Safety check 1: File must exist and be writable
        if ( ! $this->is_wpconfig_writable() ) {
            return new WP_Error( 'not_writable', __( 'wp-config.php is not writable', 'vigilante' ) );
        }

        // One writer at a time: the htaccess manager takes the same kind of lock.
        if ( ! Vigilante_Settings::acquire_option_lock( self::LOCK_OPTION, self::LOCK_TIMEOUT ) ) {
            return new WP_Error( 'locked', __( 'Another process is writing wp-config.php right now', 'vigilante' ) );
        }

        try {
            $original = $this->read_file_directly( $this->wpconfig_path );

            // Safety check 2: the file must look whole BEFORE any modification
            $check_result = $this->check_content( $original );
            if ( is_wp_error( $check_result ) ) {
                return $check_result;
            }

            $constants = $this->generate_constants();

            // Old plugin block out, then the originals commented by an earlier
            // write back in (clean slate), then commented again only those the
            // new block defines, then the block in.
            $content = $this->strip_old_block( $original );
            $content = $this->uncomment_original_constants( $content );
            $content = $this->comment_existing_constants( $content, self::constants_defined_in( $constants ) );
            $content = $this->place_block( $content, $constants );

            if ( is_wp_error( $content ) ) {
                return $content;
            }

            $result = $this->write_checked( $original, $content );
        } finally {
            Vigilante_Settings::release_option_lock( self::LOCK_OPTION );
        }

        // Regenerate critical file baseline so the integrity scan does not
        // flag our own modifications as unauthorized changes.
        if ( true === $result ) {
            // Record the block as Vigilant's own first: the baseline refreshed
            // below leaves out of its hash only the blocks recorded this way.
            if ( class_exists( 'Vigilante_File_Integrity' ) ) {
                Vigilante_File_Integrity::remember_owned_block( 'wp-config.php', self::MARKER_START, rtrim( $constants, "\n" ) );
            }

            /**
             * Fires after Vigilante successfully writes to wp-config.php.
             * Used by the file integrity module to update the baseline hash.
             */
            do_action( 'vigilante_critical_file_written', 'wp-config.php' );
        }

        return $result;
    }

    /**
     * Check wp-config.php as read, before modifying it
     *
     * Until 2.11.6 this also stored the whole file in vigilante_wpconfig_backup,
     * and with it the database password and the authentication keys and salts.
     * Nothing ever read that copy back to restore anything: the checks are what
     * protected the file, and the copy only put its secrets in the options table.
     *
     * @param string|false $content The file as read, or false.
     * @return bool|WP_Error
     */
    private function check_content( $content ) {
        if ( ! file_exists( $this->wpconfig_path ) ) {
            return new WP_Error( 'no_config', __( 'wp-config.php does not exist', 'vigilante' ) );
        }

        if ( false === $content || strlen( $content ) < self::MIN_CONFIG_SIZE ) {
            return new WP_Error( 'invalid_config', __( 'wp-config.php appears invalid or too small', 'vigilante' ) );
        }

        // Validate it looks like a real wp-config.php
        if ( ! $this->validate_wpconfig_content( $content ) ) {
            return new WP_Error( 'invalid_config', __( 'wp-config.php does not appear to be a valid WordPress configuration file', 'vigilante' ) );
        }

        if ( ! self::constants_blocks_are_whole( $content ) ) {
            return new WP_Error( 'block_incomplete', __( 'A Vigilant block in wp-config.php is missing one of its markers, so the file was left as it is.', 'vigilante' ) );
        }

        // What cannot be read as PHP now cannot be checked after the change.
        if ( ! self::parses( $content ) ) {
            return new WP_Error( 'parse_failed', __( 'wp-config.php could not be read as PHP code, so it was left as it is.', 'vigilante' ) );
        }

        return true;
    }

    /**
     * Whether a piece of PHP code parses
     *
     * The last check before writing wp-config.php: a file that does not parse
     * takes the whole site down. Until 3.0.6 nothing asked, and a define()
     * split over several lines was left with only its first line commented,
     * which is a syntax error (A2 of the list of 3 Oct 2026).
     *
     * @since 3.0.7
     *
     * @param string $content PHP file content.
     * @return bool
     */
    private static function parses( $content ) {
        // Without the tokenizer extension there is nothing to ask, and
        // comment_existing_constants() comments nothing either, which is what
        // could break the file. Until the fourth cross review of 3.0.7 this
        // called token_get_all() unguarded and every write ended in a fatal
        // error there (the File Integrity scan already asked).
        if ( ! function_exists( 'token_get_all' ) ) {
            return true;
        }

        try {
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a deprecation raised while parsing (an (integer) cast on PHP 8.5) must not be printed; only whether it parses matters.
            @token_get_all( (string) $content, TOKEN_PARSE );
        } catch ( CompileError $e ) {
            // ParseError is a CompileError since PHP 7.3.
            return false;
        }

        return true;
    }

    /**
     * Whether no constants block in wp-config.php is left without its END
     *
     * A BEGIN with no END after it, or a second BEGIN before the END, means the
     * block cannot be found whole. Removing it would still rewrite the file and
     * uncomment the original constants around it while the block keeps defining
     * them, and writing a new one would leave the broken block in place for the
     * next removal to pair with the new END, taking everything in between. So
     * the file is left as it is, and the block keeps working until someone
     * removes it by hand. An END with no BEGIN before it is left out of the
     * question: each BEGIN is paired with the next END and a stray END is left
     * alone.
     *
     * Until 2.11.6 only deactivation asked this, from its own copy of the check.
     *
     * @since 2.11.6
     *
     * @param string $content wp-config.php content.
     * @return bool
     */
    private static function constants_blocks_are_whole( $content ) {
        preg_match_all( '/' . preg_quote( self::MARKER_START, '/' ) . '|' . preg_quote( self::MARKER_END, '/' ) . '/', $content, $markers );

        $inside = false;
        foreach ( $markers[0] as $marker ) {
            if ( self::MARKER_START === $marker ) {
                if ( $inside ) {
                    return false;
                }
                $inside = true;
            } else {
                $inside = false;
            }
        }

        return ! $inside;
    }

    /**
     * Read file directly without WP_Filesystem (more reliable)
     *
     * @param string $path File path.
     * @return string|false
     */
    private function read_file_directly( $path ) {
        if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
            return false;
        }
        return file_get_contents( $path ); // phpcs:ignore
    }

    /**
     * Validate that content looks like a real wp-config.php
     *
     * @param string $content File content.
     * @return bool
     */
    private function validate_wpconfig_content( $content ) {
        // Must contain PHP opening tag
        if ( strpos( $content, '<?php' ) === false ) {
            return false;
        }

        // Must contain database configuration
        if ( strpos( $content, 'DB_NAME' ) === false ) {
            return false;
        }

        if ( strpos( $content, 'DB_USER' ) === false ) {
            return false;
        }

        if ( strpos( $content, 'DB_PASSWORD' ) === false ) {
            return false;
        }

        // Must contain table prefix
        if ( strpos( $content, '$table_prefix' ) === false ) {
            return false;
        }

        return true;
    }

    /**
     * The names of the constants a generated block defines
     *
     * @since 3.0.7
     *
     * @param string $block Block from generate_constants().
     * @return string[]
     */
    private static function constants_defined_in( $block ) {
        preg_match_all( "/define\(\s*'([A-Z_]+)'/", (string) $block, $found );

        return array_values( array_unique( $found[1] ) );
    }

    /**
     * Comment out the define() of the given managed constants
     *
     * Only the constants the new block defines. Until 3.0.6 every managed
     * constant the file defined was commented out, also when its setting was
     * off and the block did not define it, so a DISALLOW_FILE_MODS, a
     * DISABLE_WP_CRON or a FORCE_SSL_ADMIN of the owner disappeared without
     * anything taking its place (A1 of the list of 3 Oct 2026).
     *
     * The statements are found with the PHP tokenizer and not with a regular
     * expression, and every line of a statement gets the marker: the
     * expression stopped at the first closing parenthesis and the marker went
     * on the first line only, so a define() split over several lines was left
     * with its other lines loose, a syntax error that took the site down (A2).
     * A statement is only touched when it starts its line and nothing but a
     * line comment follows it on its last one: commenting a line out also
     * comments out whatever else is on it.
     *
     * @param string   $content File content.
     * @param string[] $names   Constants to comment out.
     * @return string
     */
    private function comment_existing_constants( $content, $names ) {
        $names = array_intersect( $this->managed_constants, (array) $names );

        if ( empty( $names ) || ! function_exists( 'token_get_all' ) ) {
            return $content;
        }

        // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- the content was checked to parse; a warning must not reach the page.
        $tokens = @token_get_all( $content );

        if ( empty( $tokens ) ) {
            return $content;
        }

        // A define() inside our own block is never touched.
        $block_from = strpos( $content, self::MARKER_START );
        $block_to   = false === $block_from ? false : strpos( $content, self::MARKER_END, $block_from );

        $skip  = array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT );
        $marks = array();
        $count = count( $tokens );
        $where = array();
        $at    = 0;

        foreach ( $tokens as $i => $token ) {
            $where[ $i ] = $at;
            $at         += strlen( is_array( $token ) ? $token[1] : $token );
        }

        $next = function ( $i ) use ( $tokens, $count, $skip ) {
            for ( $i++; $i < $count; $i++ ) {
                if ( ! is_array( $tokens[ $i ] ) || ! in_array( $tokens[ $i ][0], $skip, true ) ) {
                    return $i;
                }
            }
            return $count;
        };

        $prev = function ( $i ) use ( $tokens, $skip ) {
            for ( $i--; $i >= 0; $i-- ) {
                if ( ! is_array( $tokens[ $i ] ) || ! in_array( $tokens[ $i ][0], $skip, true ) ) {
                    return $tokens[ $i ];
                }
            }
            return null;
        };

        foreach ( $tokens as $i => $token ) {
            if ( ! is_array( $token ) || T_STRING !== $token[0] || 0 !== strcasecmp( $token[1], 'define' ) ) {
                continue;
            }

            // Only a define() that is a statement of its own: after the end of
            // another statement, a brace, a colon or the opening tag. One that is
            // the body of an if, else or while without braces would hand its
            // place to whatever statement follows once commented out. And a
            // method or a function of that name is not the define() of PHP.
            $before = $prev( $i );
            if ( ! ( null === $before
                || in_array( $before, array( ';', '{', '}', ':' ), true )
                || ( is_array( $before ) && in_array( $before[0], array( T_OPEN_TAG, T_CLOSE_TAG, T_INLINE_HTML ), true ) ) ) ) {
                continue;
            }

            $start = $where[ $i ];

            if ( false !== $block_from && false !== $block_to && $start > $block_from && $start < $block_to ) {
                continue;
            }

            // Only whitespace between the start of the line and define.
            $line_start = strrpos( substr( $content, 0, $start ), "\n" );
            $line_start = false === $line_start ? 0 : $line_start + 1;

            if ( '' !== trim( substr( $content, $line_start, $start - $line_start ) ) ) {
                continue;
            }

            $j = $next( $i );
            if ( $j >= $count || '(' !== $tokens[ $j ] ) {
                continue;
            }

            $k = $next( $j );
            if ( $k >= $count || ! is_array( $tokens[ $k ] ) || T_CONSTANT_ENCAPSED_STRING !== $tokens[ $k ][0] ) {
                continue;
            }

            if ( ! in_array( substr( $tokens[ $k ][1], 1, -1 ), $names, true ) ) {
                continue;
            }

            // The parenthesis that closes define(, wherever it is.
            $depth = 0;
            $close = $count;
            for ( $m = $j; $m < $count; $m++ ) {
                if ( '(' === $tokens[ $m ] ) {
                    $depth++;
                } elseif ( ')' === $tokens[ $m ] ) {
                    $depth--;
                    if ( 0 === $depth ) {
                        $close = $m;
                        break;
                    }
                }
            }

            $semi = $close < $count ? $next( $close ) : $count;
            if ( $semi >= $count || ';' !== $tokens[ $semi ] ) {
                continue;
            }

            // Nothing after the semicolon on its line but a line comment.
            $after    = $where[ $semi ] + 1;
            $line_end = strpos( $content, "\n", $after );
            $rest     = trim( false === $line_end ? substr( $content, $after ) : substr( $content, $after, $line_end - $after ) );

            // A block comment that closes on the same line counts as a comment.
            $comment = 0 === strpos( $rest, '//' )
                || ( 0 === strpos( $rest, '#' ) && 0 !== strpos( $rest, '#[' ) )
                || ( 0 === strpos( $rest, '/*' ) && '*/' === substr( $rest, -2 ) && false === strpos( substr( $rest, 2, -2 ), '*/' ) );

            if ( '' !== $rest && ( ! $comment || false !== strpos( $rest, '?>' ) ) ) {
                continue;
            }

            // Inside a line comment the closing tag of PHP still ends PHP mode:
            // one anywhere in the statement, even within a string, would turn
            // what follows into output once the lines are commented out.
            if ( false !== strpos( substr( $content, $start, $after - $start ), '?>' ) ) {
                continue;
            }

            $first = substr_count( $content, "\n", 0, $start );
            $last  = substr_count( $content, "\n", 0, $after );
            for ( $line = $first; $line <= $last; $line++ ) {
                $marks[ $line ] = true;
            }
        }

        if ( empty( $marks ) ) {
            return $content;
        }

        $lines = explode( "\n", $content );

        foreach ( array_keys( $marks ) as $line ) {
            if ( ! isset( $lines[ $line ] ) || '' === trim( $lines[ $line ] ) ) {
                continue;
            }

            preg_match( '/^(\s*)(.*)$/s', $lines[ $line ], $parts );
            $lines[ $line ] = $parts[1] . self::ORIGINAL_MARKER . $parts[2];
        }

        return implode( "\n", $lines );
    }

    /**
     * Uncomment the original constants commented by us
     *
     * @param string $content File content.
     * @return string
     */
    private function uncomment_original_constants( $content ) {
        $pattern = '/^(\s*)' . preg_quote( self::ORIGINAL_MARKER, '/' ) . '(.+)$/m';

        return (string) preg_replace( $pattern, '$1$2', $content );
    }

    /**
     * Take out the block of the plugin's former name
     *
     * @param string $content File content.
     * @return string
     */
    private function strip_old_block( $content ) {
        $pattern = '/' . preg_quote( self::OLD_MARKER_START, '/' ) . '.*?' . preg_quote( self::OLD_MARKER_END, '/' ) . '\s*/s';

        return (string) preg_replace( $pattern, '', $content );
    }

    /**
     * Remove old Easy Vigilante constants from wp-config.php
     *
     * @return bool|WP_Error
     */
    public function remove_old_constants() {
        if ( ! Vigilante_Settings::acquire_option_lock( self::LOCK_OPTION, self::LOCK_TIMEOUT ) ) {
            return new WP_Error( 'locked', __( 'Another process is writing wp-config.php right now', 'vigilante' ) );
        }

        try {
            $original = $this->read_file_directly( $this->wpconfig_path );

            if ( false === $original || ! $this->validate_wpconfig_content( $original ) ) {
                return false;
            }

            return $this->write_checked( $original, $this->strip_old_block( $original ) );
        } finally {
            Vigilante_Settings::release_option_lock( self::LOCK_OPTION );
        }
    }

    /**
     * Drop the integrity scan's record of the constants block once it is gone
     *
     * @since 2.11.5
     */
    private function forget_owned_block() {
        if ( class_exists( 'Vigilante_File_Integrity' ) ) {
            Vigilante_File_Integrity::forget_owned_blocks( 'wp-config.php', self::MARKER_START );
        }
    }

    /**
     * Remove our security constants from wp-config.php and restore originals
     *
     * One write, like apply_security_constants(): until 3.0.6 the block went
     * out in one write and the originals came back in another (A3).
     *
     * @return bool|WP_Error
     */
    public function remove_constants() {
        // On a network, a subsite deactivating the plugin must not strip the
        // constants the main site put there for everyone.
        if ( ! Vigilante_Settings::can_write_shared_files() ) {
            return new WP_Error( 'network_not_owner', Vigilante_Settings::get_shared_files_notice() );
        }

        if ( ! file_exists( $this->wpconfig_path ) ) {
            return true;
        }

        if ( ! Vigilante_Settings::acquire_option_lock( self::LOCK_OPTION, self::LOCK_TIMEOUT ) ) {
            return new WP_Error( 'locked', __( 'Another process is writing wp-config.php right now', 'vigilante' ) );
        }

        try {
            $original = $this->read_file_directly( $this->wpconfig_path );

            if ( false === $original ) {
                return false;
            }

            // A block that lost a marker cannot come out without cutting or
            // duplicating what surrounds it, so the file is left as it is.
            if ( ! self::constants_blocks_are_whole( $original ) ) {
                return new WP_Error( 'block_incomplete', __( 'A Vigilant block in wp-config.php is missing one of its markers, so the file was left as it is.', 'vigilante' ) );
            }

            $content = $original;

            if ( false !== strpos( $original, self::MARKER_START ) ) {
                // Validate before modification
                if ( ! $this->validate_wpconfig_content( $original ) ) {
                    return false;
                }

                // Remove our section
                $pattern = '/' . preg_quote( self::MARKER_START, '/' ) . '.*?' . preg_quote( self::MARKER_END, '/' ) . '\s*/s';
                $content = (string) preg_replace( $pattern, '', $original );

                // Clean up multiple empty lines
                $content = (string) preg_replace( '/\n{3,}/', "\n\n", $content );
            }

            // Now uncomment the original constants
            $result = $this->write_checked( $original, $this->uncomment_original_constants( $content ) );
        } finally {
            Vigilante_Settings::release_option_lock( self::LOCK_OPTION );
        }

        if ( true === $result ) {
            $this->forget_owned_block();
        }

        return $result;
    }

    /**
     * Generate security constants block (without conditional checks)
     *
     * @return string
     */
    public function generate_constants() {
        $constants = array();
        
        $constants[] = self::MARKER_START;
        $constants[] = '// Vigilante for WordPress - v' . VIGILANTE_VERSION;
        $constants[] = '// Generated: ' . gmdate( 'Y-m-d H:i:s' ) . ' UTC';
        $constants[] = '// Note: Original constants (if any) are commented with [VIGILANTE_ORIGINAL] marker';
        $constants[] = '// Each define() is wrapped in "if ( ! defined() )" so the block is safe on';
        $constants[] = '// non-standard setups that pre-define WordPress constants before wp-config.php';
        $constants[] = '// is parsed (would otherwise trigger a "Constant already defined" fatal).';
        $constants[] = '';

        // File editing/modification
        if ( ! empty( $this->options['disallow_file_edit'] ) ) {
            $constants[] = "// Disable file editing in admin";
            $constants[] = "if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) { define( 'DISALLOW_FILE_EDIT', true ); }";
            $constants[] = '';
        }

        if ( ! empty( $this->options['disallow_file_mods'] ) ) {
            $constants[] = "// Disable file modifications (plugins/themes install/update)";
            $constants[] = "if ( ! defined( 'DISALLOW_FILE_MODS' ) ) { define( 'DISALLOW_FILE_MODS', true ); }";
            $constants[] = '';
        }

        // SSL settings
        if ( ! empty( $this->options['force_ssl_admin'] ) ) {
            $constants[] = "// Force SSL for admin";
            $constants[] = "if ( ! defined( 'FORCE_SSL_ADMIN' ) ) { define( 'FORCE_SSL_ADMIN', true ); }";
            $constants[] = '';
        }

        if ( ! empty( $this->options['force_ssl_login'] ) ) {
            $constants[] = "// Force SSL for login";
            $constants[] = "if ( ! defined( 'FORCE_SSL_LOGIN' ) ) { define( 'FORCE_SSL_LOGIN', true ); }";
            $constants[] = '';
        }

        // Debug settings - generate when "Hide PHP errors from visitors" is unchecked (development mode)
        if ( empty( $this->options['wp_debug'] ) ) {
            $constants[] = "// Debug settings (enabled for development)";
            $constants[] = "if ( ! defined( 'WP_DEBUG' ) ) { define( 'WP_DEBUG', true ); }";
            $constants[] = "if ( ! defined( 'WP_DEBUG_LOG' ) ) { define( 'WP_DEBUG_LOG', true ); }";
            $constants[] = "if ( ! defined( 'WP_DEBUG_DISPLAY' ) ) { define( 'WP_DEBUG_DISPLAY', false ); }";
            $constants[] = "if ( ! defined( 'SCRIPT_DEBUG' ) ) { define( 'SCRIPT_DEBUG', false ); }";
            $constants[] = '';
        } else {
            $constants[] = "// Debug disabled (production)";
            $constants[] = "if ( ! defined( 'WP_DEBUG' ) ) { define( 'WP_DEBUG', false ); }";
            $constants[] = '';
        }

        // Disable WordPress's built-in pseudo-cron (page-view trigger). It only stops
        // the visits from starting the scheduled tasks, so the server needs a real
        // cron job for wp-cron.php, by its address or with PHP. Until 3.0.6 this
        // comment paired it with firewall.protect_wp_cron, retired in 3.0.7.
        if ( ! empty( $this->options['disable_wp_cron'] ) ) {
            $constants[] = "// Disable WordPress pseudo-cron (use real server-side cron instead)";
            $constants[] = "if ( ! defined( 'DISABLE_WP_CRON' ) ) { define( 'DISABLE_WP_CRON', true ); }";
            $constants[] = '';
        }

        $constants[] = self::MARKER_END;
        $constants[] = '';

        return implode( "\n", $constants );
    }

    /**
     * The content with the constants block in its place
     *
     * Works on the content in memory; write_checked() writes it.
     *
     * @param string $content   File content.
     * @param string $constants Block from generate_constants().
     * @return string|WP_Error
     */
    private function place_block( $content, $constants ) {
        // Remove existing Vigilante constants block
        $pattern = '/' . preg_quote( self::MARKER_START, '/' ) . '.*?' . preg_quote( self::MARKER_END, '/' ) . '\s*/s';
        $content = (string) preg_replace( $pattern, '', $content );

        // Remove old plugin constants block
        $content = $this->strip_old_block( $content );

        // Clean up multiple empty lines
        $content = (string) preg_replace( '/\n{3,}/', "\n\n", $content );

        // Content should still be valid after removal
        if ( ! $this->validate_wpconfig_content( $content ) ) {
            return new WP_Error( 'invalid_after_clean', __( 'wp-config.php became invalid after cleanup', 'vigilante' ) );
        }

        // Find the best place to insert constants
        $inserted = false;

        // Method 1: Before "That's all, stop editing" comment
        // This comment may be translated in localized wp-config files, so we use a broad pattern
        // that matches the block comment immediately before the ABSPATH section.
        // Known variants: "That's all, stop editing!", "C'est tout, ne touchez plus à ce qui suit",
        // "Das war's, Schluss mit dem Editieren!", "Ya está. ¡Deja de editar!", etc.
        $stop_editing_patterns = array(
            // English (default)
            "/(\/\*[^*]*That's all,?\s*stop editing[^*]*\*\/)/i",
            // Broad match: any block comment on its own line(s) immediately before "Absolute path"
            // This catches translated versions without needing every language
            '/(\n\/\*[^\n*]{5,80}\*\/)\s*\n+\s*\/\*\*\s*Absolute path/i',
        );

        foreach ( $stop_editing_patterns as $pattern ) {
            if ( preg_match( $pattern, $content, $matches ) ) {
                $content = str_replace(
                    $matches[1],
                    $constants . "\n\n" . $matches[1],
                    $content
                );
                $inserted = true;
                break;
            }
        }

        // Method 2: Before "/** Absolute path to the WordPress directory" PHPDoc comment
        // This is a code comment in wp-config-sample.php and is NOT translatable
        if ( ! $inserted && preg_match( '/(\/\*\*\s*Absolute path to the WordPress directory)/i', $content, $matches ) ) {
            $content = str_replace(
                $matches[1],
                $constants . "\n\n" . $matches[1],
                $content
            );
            $inserted = true;
        }

        // Method 3: Before ABSPATH definition (language-independent)
        if ( ! $inserted && preg_match( '/(if\s*\(\s*!\s*defined\s*\(\s*[\'"]ABSPATH[\'"]\s*\)\s*\))/i', $content, $matches ) ) {
            $content = str_replace(
                $matches[1],
                $constants . "\n\n" . $matches[1],
                $content
            );
            $inserted = true;
        }

        // Method 4: Before require_once wp-settings.php (language-independent)
        if ( ! $inserted && preg_match( '/(require[_once\s\(]+[\'"]?.*wp-settings\.php[\'"]?\s*\)?;)/i', $content, $matches ) ) {
            $content = str_replace(
                $matches[1],
                $constants . "\n\n" . $matches[1],
                $content
            );
            $inserted = true;
        }

        // Method 5: After $table_prefix (safest fallback)
        if ( ! $inserted && preg_match( '/(\$table_prefix\s*=\s*[\'"][^\'"]+[\'"]\s*;)/i', $content, $matches ) ) {
            $content = str_replace(
                $matches[1],
                $matches[1] . "\n\n" . $constants,
                $content
            );
            $inserted = true;
        }

        if ( ! $inserted ) {
            return new WP_Error( 'insert_failed', __( 'Could not find a safe place to insert constants', 'vigilante' ) );
        }

        return $content;
    }

    /**
     * Write wp-config.php once, after checking the result, and read it back
     *
     * The result must still look like a wp-config.php, keep its blocks whole,
     * not shrink to less than half and parse as PHP: a wp-config.php that does
     * not parse takes the site down. It is written with an exclusive lock and
     * read back. When what reads back is not what was written and does not
     * parse, the previous content is put back.
     *
     * @since 3.0.7
     *
     * @param string $original The file as it was read.
     * @param string $content  What to write.
     * @return bool|WP_Error
     */
    private function write_checked( $original, $content ) {
        if ( $content === $original ) {
            return true;
        }

        if ( ! $this->validate_wpconfig_content( $content ) || ! self::constants_blocks_are_whole( $content ) ) {
            return new WP_Error( 'invalid_final', __( 'Final wp-config.php would be invalid, aborting', 'vigilante' ) );
        }

        // Measured against the file without the blocks of Vigilant: removing
        // the constants block from a small wp-config.php legitimately takes it
        // below half (the second cross review of 3.0.7 measured 1139 bytes plus
        // a block of 1413).
        $pattern = '/' . preg_quote( self::MARKER_START, '/' ) . '.*?' . preg_quote( self::MARKER_END, '/' ) . '\s*/s';
        $base    = $this->strip_old_block( (string) preg_replace( $pattern, '', $original ) );
        if ( strlen( $content ) < strlen( $base ) * 0.5 ) {
            return new WP_Error( 'size_check_failed', __( 'Final wp-config.php would be too small, aborting', 'vigilante' ) );
        }

        if ( ! self::parses( $content ) ) {
            return new WP_Error( 'parse_failed', __( 'The change would have left wp-config.php with a PHP syntax error, so the file was left as it is.', 'vigilante' ) );
        }

        // What is overwritten is what was read at the start: a change made since,
        // by hand or by another plugin, is not lost (the third and fourth cross
        // reviews of 3.0.7). The writers of Vigilant already wait for each other.
        clearstatcache( true, $this->wpconfig_path );
        if ( $this->read_file_directly( $this->wpconfig_path ) !== $original ) {
            return new WP_Error( 'changed_meanwhile', __( 'wp-config.php changed while Vigilant was preparing its change, so it was left as it is. Save the tab again.', 'vigilante' ) );
        }

        $wrote = $this->write_file_directly( $this->wpconfig_path, $content, $original );

        clearstatcache( true, $this->wpconfig_path );
        $written = $this->read_file_directly( $this->wpconfig_path );

        if ( $wrote && $written === $content ) {
            return true;
        }

        // The write failed or was cut short (a full disk, a quota), or something
        // else wrote the file in between. What is on disk now stays only when it
        // is the file as it was, or somebody's whole wp-config.php: a piece of
        // what was being written goes, also when it parses, because a cut that
        // falls between two statements parses and lacks wp-settings.php (the
        // second cross review of 3.0.7 reproduced it with a file size limit).
        $is_piece = false === $written
            || ( '' !== $written && strlen( $written ) < strlen( $content ) && 0 === strpos( $content, $written ) )
            || ! $this->validate_wpconfig_content( $written )
            || ! self::parses( $written );

        if ( $written !== $original && $is_piece ) {
            $restored = $this->write_file_directly( $this->wpconfig_path, $original, $written );
            clearstatcache( true, $this->wpconfig_path );

            if ( ! $restored || $this->read_file_directly( $this->wpconfig_path ) !== $original ) {
                return new WP_Error( 'restore_failed', __( 'wp-config.php was not written completely and its previous content could not be put back. Check the free disk space and restore the file from a backup.', 'vigilante' ) );
            }
        }

        if ( ! $wrote ) {
            return new WP_Error( 'write_failed', __( 'Failed to write wp-config.php', 'vigilante' ) );
        }

        return new WP_Error( 'verify_failed', __( 'wp-config.php did not read back as written, so it was checked and left in a working state', 'vigilante' ) );
    }

    /**
     * Write file directly (more reliable than WP_Filesystem)
     *
     * @param string $path File path.
     * @param string $content Content to write.
     * @return bool
     */
    private function write_file_directly( $path, $content, $before = null ) {
        // An exclusive lock, so a writer that also locks never reads it half
        // written. A file system without locks (some network mounts) refuses the
        // call before writing anything, and then it is written as until 3.0.6:
        // the writers of Vigilant already wait for each other on their own lock.
        // Only then: after a write that was cut short (a full disk) the file has
        // changed, and writing again would only cut it again. The warnings are
        // silenced because a refused write is reported by the caller, and one
        // printed in the middle of an AJAX answer breaks it.
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents,WordPress.PHP.NoSilencedErrors.Discouraged -- wp-config.php is written directly on purpose (see read_file_directly()); a refused write is reported by the caller.
        $bytes = @file_put_contents( $path, $content, LOCK_EX );

        if ( false === $bytes && null !== $before ) {
            clearstatcache( true, $path );

            if ( $this->read_file_directly( $path ) === $before ) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents,WordPress.PHP.NoSilencedErrors.Discouraged -- same as above, without the lock the file system refused.
                $bytes = @file_put_contents( $path, $content );
            }
        }

        return strlen( $content ) === $bytes;
    }

    /**
     * Check if wp-config.php is writable
     *
     * @return bool
     */
    public function is_wpconfig_writable() {
        if ( ! file_exists( $this->wpconfig_path ) ) {
            return false;
        }

        // Initialize WP_Filesystem
        global $wp_filesystem;
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        if ( ! $wp_filesystem ) {
            return false;
        }

        return $wp_filesystem->is_writable( $this->wpconfig_path );
    }

    /**
     * Verify if our constants are currently active
     *
     * @return bool
     */
    public function are_constants_active() {
        $content = $this->read_file_directly( $this->wpconfig_path );
        if ( false === $content ) {
            return false;
        }
        return strpos( $content, self::MARKER_START ) !== false;
    }

    /**
     * Get current defined constants status
     *
     * @return array
     */
    public function get_constants_status() {
        return array(
            'DISALLOW_FILE_EDIT'    => defined( 'DISALLOW_FILE_EDIT' ) ? DISALLOW_FILE_EDIT : null,
            'DISALLOW_FILE_MODS'    => defined( 'DISALLOW_FILE_MODS' ) ? DISALLOW_FILE_MODS : null,
            'FORCE_SSL_ADMIN'       => defined( 'FORCE_SSL_ADMIN' ) ? FORCE_SSL_ADMIN : null,
            'FORCE_SSL_LOGIN'       => defined( 'FORCE_SSL_LOGIN' ) ? FORCE_SSL_LOGIN : null,
            'WP_DEBUG'              => defined( 'WP_DEBUG' ) ? WP_DEBUG : null,
            'WP_DEBUG_LOG'          => defined( 'WP_DEBUG_LOG' ) ? WP_DEBUG_LOG : null,
            'WP_DEBUG_DISPLAY'      => defined( 'WP_DEBUG_DISPLAY' ) ? WP_DEBUG_DISPLAY : null,
        );
    }

    /**
     * Check if there are commented original constants
     *
     * @return bool
     */
    public function has_commented_originals() {
        $content = $this->read_file_directly( $this->wpconfig_path );
        if ( false === $content ) {
            return false;
        }
        return strpos( $content, self::ORIGINAL_MARKER ) !== false;
    }

    /**
     * Get list of commented original constants
     *
     * @return array
     */
    public function get_commented_originals() {
        $content = $this->read_file_directly( $this->wpconfig_path );
        if ( false === $content ) {
            return array();
        }

        $originals = array();
        $pattern = '/' . preg_quote( self::ORIGINAL_MARKER, '/' ) . '(.+)$/m';
        
        if ( preg_match_all( $pattern, $content, $matches ) ) {
            $originals = $matches[1];
        }

        return $originals;
    }
}