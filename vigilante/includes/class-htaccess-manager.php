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
     * Path to .htaccess file
     *
     * @var string
     */
    private $htaccess_path;

    /**
     * Path to backup file
     *
     * @var string
     */
    private $backup_path;

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
        $this->backup_path = WP_CONTENT_DIR . '/vigilante-backups/.htaccess.safe';
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
        $backup_dir = dirname( $this->backup_path );

        if ( ! is_dir( $backup_dir ) ) {
            wp_mkdir_p( $backup_dir );
            file_put_contents( $backup_dir . '/.htaccess', 'Deny from all' ); // phpcs:ignore
        }

        return ( false !== file_put_contents( $this->backup_path, $content ) ); // phpcs:ignore
    }

    /**
     * Restore .htaccess from backup
     *
     * @return bool
     */
    public function restore_backup() {
        if ( ! file_exists( $this->backup_path ) ) {
            return false;
        }

        $content = file_get_contents( $this->backup_path ); // phpcs:ignore

        if ( false === $content ) {
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
        if ( function_exists( 'apache_get_modules' ) ) {
            return true;
        }

        $server = isset( $_SERVER['SERVER_SOFTWARE'] ) 
            ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) 
            : '';

        return ( stripos( $server, 'apache' ) !== false || stripos( $server, 'litespeed' ) !== false );
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