<?php
/**
 * HTAccess Manager Class
 *
 * Centralized, safe management of .htaccess modifications
 * Used by both Firewall and Security Headers modules
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Htaccess_Manager
 *
 * Provides atomic, safe operations on .htaccess file
 */
class Vigilante_Htaccess_Manager {

    /**
     * Singleton instance
     *
     * @var Vigilante_Htaccess_Manager
     */
    private static $instance = null;

    /**
     * Option where the server software seen in a web request is remembered
     *
     * WP-CLI has no request to look at, so the detection made from the web is
     * kept here and used as the fallback. See is_apache().
     *
     * @since 2.9.9
     *
     * @var string
     */
    const SERVER_OPTION = 'vigilante_server_software';

    /**
     * Path to .htaccess file
     *
     * @var string
     */
    private $htaccess_path;

    /**
     * Known block markers (start => end)
     *
     * @var array
     */
    /**
     * Option holding the write lock, and how long a held lock is believed.
     *
     * @since 2.10.0
     */
    const LOCK_OPTION  = 'vigilante_htaccess_write_lock';
    const LOCK_TIMEOUT = 30;

    /**
     * Rolling history of replaced .htaccess versions, and the one-off snapshot
     * taken from a site the 2.9.8 migration had already wiped.
     *
     * @since 2.10.0
     */
    const HISTORY_OPTION       = 'vigilante_htaccess_history';
    const HISTORY_ENTRIES      = 5;
    const HISTORY_MAX_BYTES    = 262144;

    private $known_blocks = array(
        '# BEGIN Vigilante Protection'        => '# END Vigilante Protection',
        '# BEGIN Vigilante Security Headers'  => '# END Vigilante Security Headers',
        '# BEGIN WordPress'             => '# END WordPress',
    );

    /**
     * Get singleton instance
     *
     * @return Vigilante_Htaccess_Manager
     */
    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct() {
        $this->htaccess_path = ABSPATH . '.htaccess';
    }

    /**
     * Add or update a block in .htaccess
     *
     * @param string $marker_start Start marker (e.g. "# BEGIN Vigilante Protection").
     * @param string $marker_end   End marker (e.g. "# END Vigilante Protection").
     * @param string $rules        Rules content (without markers).
     * @param string $position     Where to add: 'top' or 'before_wordpress'.
     * @return bool|WP_Error
     */
    public function add_block( $marker_start, $marker_end, $rules, $position = 'top' ) {
        // On a network the root .htaccess is shared by every site, so only the
        // main site writes it. See Vigilante_Settings::can_write_shared_files().
        if ( ! Vigilante_Settings::can_write_shared_files() ) {
            return new WP_Error( 'network_not_owner', Vigilante_Settings::get_shared_files_notice() );
        }

        /*
         * One writer at a time. maybe_sync_server_files() runs on init, on every
         * request, so the first visitors after an update can enter this
         * read-modify-write at the same moment. Two concurrent writers of
         * *different* blocks is the case that bites: the second one read the file
         * before the first one wrote, so its write drops the block the first one
         * had just added.
         */
        if ( ! $this->acquire_lock() ) {
            return new WP_Error( 'locked', __( 'Another process is writing .htaccess right now', 'vigilante' ) );
        }

        try {
            // Read current content
            $original = $this->read_file();
            if ( false === $original ) {
                $original = '';
            }

            // Create backup before modification
            if ( ! empty( $original ) ) {
                $this->create_backup( $original );
            }

            // Remove existing block if present
            $content = $this->remove_block_from_content( $original, $marker_start, $marker_end );

            // Build new block
            $block = $marker_start . "\n" . $rules . "\n" . $marker_end;

            // Insert at correct position
            $new_content = $this->insert_block( $content, $block, $position );

            // Validate result
            if ( ! $this->validate_content( $new_content ) ) {
                return new WP_Error( 'invalid_result', __( 'Resulting .htaccess would be invalid', 'vigilante' ) );
            }

            // Write file
            if ( ! $this->write_file( $new_content ) ) {
                return new WP_Error( 'write_failed', __( 'Failed to write .htaccess', 'vigilante' ) );
            }

            /*
             * Read back what actually landed. Writing is not the same as having
             * written: a truncated write, a full disk or a filesystem layer that
             * quietly mangles the content would otherwise leave the site serving a
             * broken .htaccess with nobody the wiser, which on this file means a
             * 500 on every page. If the file on disk does not validate, or does
             * not contain the block that was just added, put back exactly what was
             * there before and report the failure instead of walking away.
             */
            $written = $this->read_file();

            if ( false === $written
                || ! $this->validate_content( $written )
                || false === strpos( $written, $marker_start )
            ) {
                if ( '' !== $original ) {
                    $this->write_file( $original );
                }

                return new WP_Error( 'verify_failed', __( 'The .htaccess was written but did not read back as expected, so the previous content was restored', 'vigilante' ) );
            }

            return true;
        } finally {
            $this->release_lock();
        }
    }

    /**
     * Take the write lock, or fail if another process holds it.
     *
     * add_option() is the atomic part: option_name carries a unique index, so
     * exactly one caller can create the row. A lock older than the timeout is
     * treated as abandoned (a fatal between acquire and release) and taken over,
     * otherwise a single crash would freeze every future write.
     *
     * @since 2.10.0
     * @return bool
     */
    private function acquire_lock() {
        $now  = time();
        $held = get_option( self::LOCK_OPTION );

        if ( false !== $held && is_numeric( $held ) && ( $now - (int) $held ) < self::LOCK_TIMEOUT ) {
            return false;
        }

        if ( false !== $held ) {
            // Abandoned lock: take it over.
            update_option( self::LOCK_OPTION, $now, false );
            return true;
        }

        return (bool) add_option( self::LOCK_OPTION, $now, '', false );
    }

    /**
     * Release the write lock.
     *
     * @since 2.10.0
     */
    private function release_lock() {
        delete_option( self::LOCK_OPTION );
    }

    /**
     * Remove a block from .htaccess
     *
     * @param string $marker_start Start marker.
     * @param string $marker_end   End marker.
     * @return bool|WP_Error
     */
    public function remove_block( $marker_start, $marker_end ) {
        if ( ! Vigilante_Settings::can_write_shared_files() ) {
            return new WP_Error( 'network_not_owner', Vigilante_Settings::get_shared_files_notice() );
        }

        // Read current content
        $content = $this->read_file();
        
        if ( false === $content || empty( $content ) ) {
            return true; // Nothing to remove
        }

        // Check if block exists
        if ( strpos( $content, $marker_start ) === false ) {
            return true; // Block doesn't exist, nothing to do
        }

        // Create backup before modification
        $this->create_backup( $content );

        // Remove the block
        $new_content = $this->remove_block_from_content( $content, $marker_start, $marker_end );

        // Validate result - WordPress rules should still be there if they were before
        if ( strpos( $content, '# BEGIN WordPress' ) !== false && 
             strpos( $new_content, '# BEGIN WordPress' ) === false ) {
            // WordPress rules were removed - this is wrong, restore backup
            $this->restore_backup();
            return new WP_Error( 'wordpress_rules_lost', __( 'Operation would remove WordPress rules, aborted', 'vigilante' ) );
        }

        // Write file
        if ( $this->write_file( $new_content ) ) {
            return true;
        }

        // Write failed, restore backup
        $this->restore_backup();
        return new WP_Error( 'write_failed', __( 'Failed to write .htaccess', 'vigilante' ) );
    }

    /**
     * Check if a block exists in .htaccess
     *
     * @param string $marker_start Start marker.
     * @return bool
     */
    public function block_exists( $marker_start ) {
        $content = $this->read_file();
        if ( false === $content ) {
            return false;
        }
        return strpos( $content, $marker_start ) !== false;
    }

    /**
     * Remove a specific block from content string
     *
     * @param string $content      Content to modify.
     * @param string $marker_start Start marker.
     * @param string $marker_end   End marker.
     * @return string Modified content.
     */
    private function remove_block_from_content( $content, $marker_start, $marker_end ) {
        if ( strpos( $content, $marker_start ) === false ) {
            return $content;
        }

        // Use line-by-line approach for safety (regex can be unpredictable)
        $lines = explode( "\n", $content );
        $new_lines = array();
        $inside_block = false;

        foreach ( $lines as $line ) {
            // Check for start marker
            if ( trim( $line ) === $marker_start ) {
                $inside_block = true;
                continue;
            }

            // Check for end marker
            if ( trim( $line ) === $marker_end ) {
                $inside_block = false;
                continue;
            }

            // Add line if not inside our block
            if ( ! $inside_block ) {
                $new_lines[] = $line;
            }
        }

        // Join and clean up multiple empty lines
        $result = implode( "\n", $new_lines );
        $result = preg_replace( '/\n{3,}/', "\n\n", $result );
        $result = trim( $result );

        return $result;
    }

    /**
     * Insert a block at the specified position
     *
     * @param string $content  Current content.
     * @param string $block    Block to insert.
     * @param string $position Position: 'top' or 'before_wordpress'.
     * @return string Modified content.
     */
    private function insert_block( $content, $block, $position ) {
        $content = trim( $content );

        if ( empty( $content ) ) {
            return $block . "\n";
        }

        if ( 'before_wordpress' === $position ) {
            $pos = stripos( $content, '# BEGIN WordPress' );

            /*
             * Spliced by offset, never with preg_replace().
             *
             * The block used to be passed as the replacement argument, where
             * "$1" and "\\1" are backreference syntax and a trailing backslash
             * escapes whatever follows it. That silently ate the escaping that
             * generate_whitelist_exceptions() had just applied: a User-Agent
             * whitelist entry ending in a backslash reached the file as
             * `"!Bot\\" [NC]`, the backslash escaped the closing quote, and
             * Apache answered 500 for the whole site. Reproduced from the
             * settings screen on 25 aug 2026. substr() copies the block
             * verbatim, which is the only correct thing to do here.
             */
            if ( false !== $pos ) {
                return substr( $content, 0, $pos ) . $block . "\n\n" . substr( $content, $pos );
            }
        }

        // Default: insert at top
        return $block . "\n\n" . $content;
    }

    /**
     * Validate .htaccess content
     *
     * @param string $content Content to validate.
     * @return bool
     */
    private function validate_content( $content ) {
        // Empty content is valid (but unusual)
        if ( empty( trim( $content ) ) ) {
            return true;
        }

        // Check for unmatched block markers
        foreach ( $this->known_blocks as $start => $end ) {
            $has_start = strpos( $content, $start ) !== false;
            $has_end = strpos( $content, $end ) !== false;

            // If has start, must have end (and vice versa)
            if ( $has_start !== $has_end ) {
                return false;
            }

            // Start must come before end
            if ( $has_start && $has_end ) {
                if ( strpos( $content, $start ) > strpos( $content, $end ) ) {
                    return false;
                }
            }
        }

        // Basic check: if it starts with PHP code, it's wrong
        if ( preg_match( '/^<\?php/i', trim( $content ) ) ) {
            return false;
        }

        /*
         * Every directive argument has to close the quotes it opens. A stray
         * backslash right before the closing quote escapes it, the directive
         * runs on into the rest of the line and Apache answers 500 for the
         * whole site. That is not hypothetical: until 2.10.0 a User-Agent
         * whitelist entry ending in a backslash did exactly that, and this
         * function waved it through because the only syntax check it had was
         * an unused array of patterns.
         *
         * Escaped pairs are removed first, so a legitimate \\" or \\\\ inside an
         * argument is not miscounted.
         */
        foreach ( preg_split( '/\r\n|\r|\n/', $content ) as $line ) {
            $unescaped = str_replace( array( '\\\\', '\\"' ), '', $line );

            if ( 0 !== ( substr_count( $unescaped, '"' ) % 2 ) ) {
                return false;
            }
        }

        /*
         * Container tags have to balance. An unclosed <IfModule> swallows every
         * directive below it, including the ones WordPress itself wrote.
         */
        if ( preg_match_all( '/^\s*<IfModule\b/im', $content ) !== preg_match_all( '/^\s*<\/IfModule\s*>/im', $content ) ) {
            return false;
        }

        return true;
    }

    /**
     * Read .htaccess file
     *
     * @return string|false
     */
    private function read_file() {
        if ( ! file_exists( $this->htaccess_path ) ) {
            return '';
        }

        if ( ! is_readable( $this->htaccess_path ) ) {
            return false;
        }

        $content = file_get_contents( $this->htaccess_path ); // phpcs:ignore

        return ( false !== $content ) ? $content : false;
    }

    /**
     * Write .htaccess file
     *
     * @param string $content Content to write.
     * @return bool
     */
    private function write_file( $content ) {
        // Ensure content ends with newline
        $content = rtrim( $content ) . "\n";

        // Initialize WP_Filesystem
        global $wp_filesystem;
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        if ( ! $wp_filesystem ) {
            return false;
        }

        // Check writability
        if ( file_exists( $this->htaccess_path ) ) {
            if ( ! $wp_filesystem->is_writable( $this->htaccess_path ) ) {
                return false;
            }
        } else {
            if ( ! $wp_filesystem->is_writable( dirname( $this->htaccess_path ) ) ) {
                return false;
            }
        }

        // Write with WP_Filesystem
        return $wp_filesystem->put_contents( $this->htaccess_path, $content, FS_CHMOD_FILE );
    }

    /**
     * Create backup of current .htaccess
     *
     * @param string $content Content to backup.
     * @return bool
     */
    private function create_backup( $content ) {
        $this->push_history( (string) $content );

        // Store the backup in a private database option instead of a file under
        // the web root, so it can never be served over HTTP.
        $stored = update_option(
            'vigilante_htaccess_backup',
            array(
                'content' => (string) $content,
                'time'    => time(),
            ),
            false
        );

        // update_option() also returns false when the value is unchanged.
        return ( false !== $stored ) || ( (string) $content === $this->get_backup_content() );
    }

    /**
     * Keep the last few .htaccess versions, newest first.
     *
     * The single-slot backup above is the rollback buffer: it is overwritten by
     * the very next write, which is right for its job and useless for anything
     * else. Something that only becomes visible days later, such as a header
     * that quietly stopped being sent, needs more than one step of history.
     *
     * Kept in the database with autoload off, never in a file under the web
     * root. Bounded on both axes so a large .htaccess cannot inflate the
     * options table: oversized files are not stored at all, rather than stored
     * truncated, because half an .htaccess is worse than none.
     *
     * @since 2.10.0
     * @param string $content Content being replaced.
     */
    private function push_history( $content ) {
        if ( '' === $content || strlen( $content ) > self::HISTORY_MAX_BYTES ) {
            return;
        }

        $history = get_option( self::HISTORY_OPTION );
        $history = is_array( $history ) ? $history : array();

        // Nothing changed, nothing to record.
        if ( isset( $history[0]['content'] ) && $history[0]['content'] === $content ) {
            return;
        }

        array_unshift(
            $history,
            array(
                'content' => $content,
                'time'    => time(),
                'version' => VIGILANTE_VERSION,
            )
        );

        update_option( self::HISTORY_OPTION, array_slice( $history, 0, self::HISTORY_ENTRIES ), false );
    }

    /**
     * Get the stored .htaccess backup content, or '' if none.
     *
     * @return string
     */
    private function get_backup_content() {
        $backup = get_option( 'vigilante_htaccess_backup' );
        return ( is_array( $backup ) && isset( $backup['content'] ) ) ? (string) $backup['content'] : '';
    }

    /**
     * Restore .htaccess from backup
     *
     * @return bool
     */
    public function restore_backup() {
        $content = $this->get_backup_content();

        if ( '' === $content ) {
            return false;
        }

        return $this->write_file( $content );
    }

    /**
     * Check if server is Apache/LiteSpeed
     *
     * @return bool
     */
    public function is_apache() {
        $detected = null;

        if ( function_exists( 'apache_get_modules' ) ) {
            $detected = true;
        } else {
            $server = isset( $_SERVER['SERVER_SOFTWARE'] )
                ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) )
                : '';

            if ( '' !== $server ) {
                $detected = self::looks_like_apache( $server );

                // Remember it, because a WP-CLI run has no request to look at.
                if ( get_option( self::SERVER_OPTION ) !== $server ) {
                    update_option( self::SERVER_OPTION, $server, false );
                }
            }
        }

        /*
         * Nothing in this request to go on, which is exactly what happens under
         * WP-CLI: apache_get_modules() only exists under mod_php and
         * SERVER_SOFTWARE is not defined on the command line. Until 2.9.9 that
         * answered "not Apache" and every .htaccess write was refused, so a site
         * activated with `wp plugin activate` silently got no server layer at
         * all while the switches showed as on. So fall back to what a web
         * request taught us earlier.
         */
        if ( null === $detected ) {
            $remembered = (string) get_option( self::SERVER_OPTION, '' );

            if ( '' !== $remembered ) {
                $detected = self::looks_like_apache( $remembered );
            }
        }

        /**
         * Filter the Apache/LiteSpeed detection.
         *
         * The escape hatch for a site deployed entirely from the command line,
         * where there has never been a web request to learn from.
         *
         * @since 2.9.9
         *
         * @param bool|null $detected True, false, or null when it could not be told.
         */
        $detected = apply_filters( 'vigilante_is_apache', $detected );

        return ( true === $detected );
    }

    /**
     * Vigilant blocks sitting in .htaccess files above the WordPress directory
     *
     * Apache applies the .htaccess of every directory above the one being
     * served, and this class only ever writes and reads the one in ABSPATH. So
     * a WordPress in a subfolder can be receiving rules from the block that the
     * Vigilant of the parent installation left in the document root: the
     * settings screen says the header is off, headers_list() does not show it,
     * and the browser receives it all the same. Costed two rounds of diagnosis
     * on a real site before it was understood, so it is worth naming the file.
     *
     * @since 2.9.9
     *
     * @return array<string,string[]> Absolute file path => markers found inside.
     */
    public function find_blocks_above() {
        global $wp_filesystem;

        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        if ( ! $wp_filesystem ) {
            return array();
        }

        $found   = array();
        $markers = array_keys( $this->known_blocks );
        $dir     = dirname( $this->htaccess_path );

        // Bounded walk up to the filesystem root. Eight levels is well past any
        // real docroot and keeps this cheap on a deep path.
        for ( $level = 0; $level < 8; $level++ ) {
            $parent = dirname( $dir );

            if ( $parent === $dir || '' === $parent || '.' === $parent ) {
                break;
            }

            $dir  = $parent;
            $file = $dir . '/.htaccess';

            if ( ! $wp_filesystem->exists( $file ) || ! $wp_filesystem->is_readable( $file ) ) {
                continue;
            }

            $content = $wp_filesystem->get_contents( $file );

            if ( ! is_string( $content ) || '' === $content ) {
                continue;
            }

            $hits = array();
            foreach ( $markers as $marker ) {
                // The WordPress block is not ours, only the Vigilant ones count.
                if ( false === strpos( $marker, 'Vigilante' ) ) {
                    continue;
                }
                if ( false !== strpos( $content, $marker ) ) {
                    $hits[] = $marker;
                }
            }

            if ( ! empty( $hits ) ) {
                $found[ $file ] = $hits;
            }
        }

        return $found;
    }

    /**
     * Whether a SERVER_SOFTWARE string is Apache or LiteSpeed
     *
     * @since 2.9.9
     *
     * @param string $server Server software string.
     * @return bool
     */
    private static function looks_like_apache( $server ) {
        return ( false !== stripos( $server, 'apache' ) || false !== stripos( $server, 'litespeed' ) );
    }

    /**
     * Whether the server could not be identified in this request
     *
     * Tells "we know it is not Apache" apart from "we cannot tell from here",
     * which is what a WP-CLI run gets. The caller uses it to leave the work
     * pending for the first web request instead of dropping it.
     *
     * @since 2.9.9
     *
     * @return bool
     */
    public function server_is_unknown() {
        if ( function_exists( 'apache_get_modules' ) ) {
            return false;
        }

        if ( ! empty( $_SERVER['SERVER_SOFTWARE'] ) ) {
            return false;
        }

        return ( '' === (string) get_option( self::SERVER_OPTION, '' ) );
    }

    /**
     * Check if .htaccess is writable
     *
     * @return bool
     */
    public function is_writable() {
        // Initialize WP_Filesystem
        global $wp_filesystem;
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        if ( ! $wp_filesystem ) {
            return false;
        }

        if ( file_exists( $this->htaccess_path ) ) {
            return $wp_filesystem->is_writable( $this->htaccess_path );
        }
        return $wp_filesystem->is_writable( ABSPATH );
    }

    /**
     * Get current .htaccess content (for debugging)
     *
     * @return string
     */
    public function get_content() {
        $content = $this->read_file();
        return ( false !== $content ) ? $content : '';
    }
}