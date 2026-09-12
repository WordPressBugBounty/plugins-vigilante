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
     * The single-slot rollback buffer, cleared at the end of every operation.
     *
     * @since 2.10.0
     */
    const BACKUP_OPTION = 'vigilante_htaccess_backup';

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
    public function add_block( $marker_start, $marker_end, $rules, $position = 'top', $automatic = false ) {
        /*
         * On a network the root .htaccess is shared by every site, so only the
         * main site writes it.
         *
         * Which question to ask depends on who is asking. A write a person
         * started from a settings screen has to clear the capability too, so one
         * site's administrator cannot overwrite what the network decided. A write
         * Vigilant performs by itself only has to come from the right site: it
         * makes no decision, and demanding a capability of it means demanding one
         * of whichever visitor happened to trigger the request, which nobody has.
         *
         * Getting that distinction wrong is what shipped in 2.10.0, and it is why
         * no network ever had its .htaccess refreshed after an update.
         */
        $allowed = $automatic
            ? Vigilante_Settings::owns_shared_files()
            : Vigilante_Settings::can_write_shared_files();

        if ( ! $allowed ) {
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

            /*
             * read_file() answers '' when there is no file and false when there
             * is one PHP cannot read. Until 2.11.8 both became an empty string
             * here, so a .htaccess that PHP could write but not read was replaced
             * whole by the Vigilant block, and every other rule in it was lost.
             */
            if ( false === $original ) {
                return new WP_Error( 'read_failed', __( '.htaccess could not be read, so it was left as it is.', 'vigilante' ) );
            }

            /*
             * A block that has lost a marker would take the rest of the file with
             * it. The other known blocks are asked too: validate_content() below
             * refuses any result where one of them is unmatched, and saying why
             * here keeps that refusal from reading as a write failure worth
             * retrying every hour.
             */
            $whole = $this->blocks_are_whole( $original, $marker_start, $marker_end );
            foreach ( $this->known_blocks as $known_start => $known_end ) {
                $whole = $whole && $this->blocks_are_whole( $original, $known_start, $known_end );
            }
            if ( ! $whole ) {
                return new WP_Error( 'block_incomplete', __( 'A Vigilant block in .htaccess is missing one of its markers, so the file was left as it is.', 'vigilante' ) );
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

            // Record the block as Vigilant's own. The integrity scan leaves
            // out of its hash only the blocks whose fingerprint is recorded,
            // so anything else carrying these markers is still checked.
            if ( class_exists( 'Vigilante_File_Integrity' ) ) {
                Vigilante_File_Integrity::remember_owned_block( '.htaccess', $marker_start, $block );
            }

            return true;
        } finally {
            // No .htaccess content, which may hold secrets, is left in the
            // options table after the operation. Since 2.11.9.
            $this->clear_backup();
            $this->release_lock();
        }
    }

    /**
     * Take the write lock, or fail if another process holds it.
     *
     * Until 2.11.8 this relied on add_option() being atomic, and it is not: it
     * runs INSERT ... ON DUPLICATE KEY UPDATE, so two writers arriving together
     * both believed they held the lock. See Vigilante_Settings::acquire_option_lock().
     * A lock older than the timeout still counts as abandoned and is taken over.
     *
     * @since 2.10.0
     * @return bool
     */
    private function acquire_lock() {
        return Vigilante_Settings::acquire_option_lock( self::LOCK_OPTION, self::LOCK_TIMEOUT );
    }

    /**
     * Release the write lock.
     *
     * @since 2.10.0
     */
    private function release_lock() {
        Vigilante_Settings::release_option_lock( self::LOCK_OPTION );
    }

    /**
     * Drop the integrity scan's record of a block Vigilant no longer has in the file
     *
     * @since 2.11.5
     *
     * @param string $marker_start Start marker of the block.
     */
    private function forget_owned_block( $marker_start ) {
        if ( class_exists( 'Vigilante_File_Integrity' ) ) {
            Vigilante_File_Integrity::forget_owned_blocks( '.htaccess', $marker_start );
        }
    }

    /**
     * Remove a block from .htaccess
     *
     * Takes the same write lock as add_block(): until 2.11.0 this
     * read-modify-write ran unlocked, so a removal racing an addition of a
     * different block could drop the block that had just been written (S5).
     *
     * @param string $marker_start Start marker.
     * @param string $marker_end   End marker.
     * @param bool   $automatic    True when Vigilant removes the block by itself
     *                             (a mode expiring on cron), false when a person
     *                             asked for it. Same distinction as add_block().
     * @return bool|WP_Error
     */
    public function remove_block( $marker_start, $marker_end, $automatic = false ) {
        $allowed = $automatic
            ? Vigilante_Settings::owns_shared_files()
            : Vigilante_Settings::can_write_shared_files();

        if ( ! $allowed ) {
            return new WP_Error( 'network_not_owner', Vigilante_Settings::get_shared_files_notice() );
        }

        if ( ! $this->acquire_lock() ) {
            return new WP_Error( 'locked', __( 'Another process is writing .htaccess right now', 'vigilante' ) );
        }

        try {
            // Read current content
            $content = $this->read_file();

            if ( false === $content || empty( $content ) ) {
                // An unreadable file proves nothing about the block, so its
                // record stays. A missing or empty one has no block left.
                if ( false !== $content ) {
                    $this->forget_owned_block( $marker_start );
                }
                return true; // Nothing to remove
            }

            // Check if block exists
            if ( strpos( $content, $marker_start ) === false ) {
                $this->forget_owned_block( $marker_start );
                return true; // Block doesn't exist, nothing to do
            }

            // A block that has lost a marker would take the rest of the file with it.
            if ( ! $this->blocks_are_whole( $content, $marker_start, $marker_end ) ) {
                return new WP_Error( 'block_incomplete', __( 'A Vigilant block in .htaccess is missing one of its markers, so the file was left as it is.', 'vigilante' ) );
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
                $this->forget_owned_block( $marker_start );
                return true;
            }

            // Write failed, restore backup
            $this->restore_backup();
            return new WP_Error( 'write_failed', __( 'Failed to write .htaccess', 'vigilante' ) );
        } finally {
            // No .htaccess content, which may hold secrets, is left in the
            // options table after the operation. Since 2.11.9.
            $this->clear_backup();
            $this->release_lock();
        }
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
     * Whether no start marker of a block is left without its end
     *
     * The removal below works line by line and keeps dropping lines from a start
     * marker until it meets an end marker, so a start whose end is missing, or a
     * second start before the end, takes everything after it. Neither existing
     * check catches that: remove_block() only looks for "# BEGIN WordPress",
     * which the rules Network Setup hands out do not carry, and the
     * validate_content() of add_block() only compares marker pairs, which still
     * match once both WordPress markers have been cut away. An end marker with
     * no start before it is harmless to the removal, which just drops that
     * line, so it does not count against the content.
     *
     * @since 2.11.6
     *
     * @param string $content      Content to check.
     * @param string $marker_start Start marker.
     * @param string $marker_end   End marker.
     * @return bool
     */
    private function blocks_are_whole( $content, $marker_start, $marker_end ) {
        $inside = false;

        foreach ( explode( "\n", $content ) as $line ) {
            $line = trim( $line );

            if ( $line === $marker_start ) {
                if ( $inside ) {
                    return false;
                }
                $inside = true;
            } elseif ( $line === $marker_end ) {
                $inside = false;
            }
        }

        return ! $inside;
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

        /*
         * Keep the permissions the file already has. put_contents() always sets
         * a mode, and FS_CHMOD_FILE is "permissions of index.php | 0644", so
         * until 2.11.6 every write left a .htaccess kept at 0640 at 0644 or
         * wider. A mode that cannot be read falls back to the old one rather
         * than to 0, which would lock the server out of the file.
         */
        $perms = file_exists( $this->htaccess_path ) ? fileperms( $this->htaccess_path ) : false;
        $mode  = ( false !== $perms && ( $perms & 0777 ) ) ? ( $perms & 0777 ) : FS_CHMOD_FILE;

        // Write with WP_Filesystem
        return $wp_filesystem->put_contents( $this->htaccess_path, $content, $mode );
    }

    /**
     * Create backup of current .htaccess, for rollback within this operation only
     *
     * A .htaccess can carry secrets (SetEnv credentials, an Authorization
     * header, a php_value with a key), so this rollback buffer is a live copy of
     * the file and is cleared at the end of every add_block/remove_block, in the
     * finally, rather than left sitting in the options table. Until 2.11.9 it
     * persisted between operations and a rolling five-version history kept the
     * raw content indefinitely, so anyone who read the database or a backup of
     * it recovered those secrets without filesystem access. Reported by the
     * wp.org automated review of 2.11.8. The history is gone; the buffer holds
     * the real content because restoring a redacted one would write the marker
     * into the live file, and lives only for the length of the write.
     *
     * @param string $content Content to backup.
     * @return bool
     */
    private function create_backup( $content ) {
        // A private option, never a file under the web root, and dropped again
        // by clear_backup() in the finally of the operation that created it.
        $stored = update_option(
            self::BACKUP_OPTION,
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
     * Drop the rollback buffer, so no .htaccess content lingers in the options table
     *
     * @since 2.11.9
     */
    private function clear_backup() {
        delete_option( self::BACKUP_OPTION );
    }

    /**
     * Get the stored .htaccess backup content, or '' if none.
     *
     * @return string
     */
    private function get_backup_content() {
        $backup = get_option( self::BACKUP_OPTION );
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