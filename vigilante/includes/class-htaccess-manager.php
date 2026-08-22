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

        // Read current content
        $content = $this->read_file();
        if ( false === $content ) {
            $content = '';
        }

        // Create backup before modification
        if ( ! empty( $content ) ) {
            $this->create_backup( $content );
        }

        // Remove existing block if present
        $content = $this->remove_block_from_content( $content, $marker_start, $marker_end );

        // Build new block
        $block = $marker_start . "\n" . $rules . "\n" . $marker_end;

        // Insert at correct position
        $new_content = $this->insert_block( $content, $block, $position );

        // Validate result
        if ( ! $this->validate_content( $new_content ) ) {
            return new WP_Error( 'invalid_result', __( 'Resulting .htaccess would be invalid', 'vigilante' ) );
        }

        // Write file
        if ( $this->write_file( $new_content ) ) {
            return true;
        }

        return new WP_Error( 'write_failed', __( 'Failed to write .htaccess', 'vigilante' ) );
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

        if ( 'before_wordpress' === $position && strpos( $content, '# BEGIN WordPress' ) !== false ) {
            // Insert before WordPress block
            return preg_replace(
                '/(# BEGIN WordPress)/i',
                $block . "\n\n$1",
                $content
            );
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

        // Check for obvious syntax errors
        $error_patterns = array(
            '/^<(?!IfModule|Directory|Files|FilesMatch|Location|LocationMatch|Limit|LimitExcept|Else|ElseIf|If|VirtualHost|Proxy|ProxyMatch|RequireAll|RequireAny|RequireNone|AuthnProviderAlias|AuthzProviderAlias)[^>]*>/im',
        );

        // Basic check: if it starts with PHP code, it's wrong
        if ( preg_match( '/^<\?php/i', trim( $content ) ) ) {
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