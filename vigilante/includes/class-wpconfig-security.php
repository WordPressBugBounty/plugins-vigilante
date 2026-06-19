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
     * Apply security constants to wp-config.php
     *
     * @return bool|WP_Error
     */
    public function apply_security_constants() {
        // Safety check 1: File must exist and be writable
        if ( ! $this->is_wpconfig_writable() ) {
            return new WP_Error( 'not_writable', __( 'wp-config.php is not writable', 'vigilante' ) );
        }

        // Safety check 2: Create backup BEFORE any modification
        $backup_result = $this->create_backup();
        if ( is_wp_error( $backup_result ) ) {
            return $backup_result;
        }

        // First clean up old plugin constants
        $this->remove_old_constants();

        // Restore any previously commented constants (clean slate for upgrades)
        // This ensures constants no longer managed by current version get uncommented
        $this->uncomment_original_constants();

        // Comment out existing managed constants
        $comment_result = $this->comment_existing_constants();
        if ( is_wp_error( $comment_result ) ) {
            return $comment_result;
        }

        // Generate and write our constants block
        $constants = $this->generate_constants();
        $result = $this->write_constants( $constants );

        // Regenerate critical file baseline so the integrity scan does not
        // flag our own modifications as unauthorized changes.
        if ( true === $result ) {
            /**
             * Fires after Vigilante successfully writes to wp-config.php.
             * Used by the file integrity module to update the baseline hash.
             */
            do_action( 'vigilante_critical_file_written', 'wp-config.php' );
        }

        return $result;
    }

    /**
     * Create a backup of wp-config.php before modification
     *
     * @return bool|WP_Error
     */
    private function create_backup() {
        if ( ! file_exists( $this->wpconfig_path ) ) {
            return new WP_Error( 'no_config', __( 'wp-config.php does not exist', 'vigilante' ) );
        }

        $content = $this->read_file_directly( $this->wpconfig_path );
        
        if ( false === $content || strlen( $content ) < self::MIN_CONFIG_SIZE ) {
            return new WP_Error( 'invalid_config', __( 'wp-config.php appears invalid or too small', 'vigilante' ) );
        }

        // Validate it looks like a real wp-config.php
        if ( ! $this->validate_wpconfig_content( $content ) ) {
            return new WP_Error( 'invalid_config', __( 'wp-config.php does not appear to be a valid WordPress configuration file', 'vigilante' ) );
        }

        // Store the backup in a private database option, never as a file under
        // the web root. wp-config.php holds DB credentials and salts; a file in
        // wp-content could be served by a misconfigured server. The option is
        // not reachable over HTTP and is not autoloaded.
        $stored = update_option(
            'vigilante_wpconfig_backup',
            array(
                'content' => $content,
                'time'    => time(),
            ),
            false
        );

        // update_option() returns false both on failure and when the value is
        // unchanged; only treat it as an error if the content was not stored.
        if ( false === $stored && $content !== $this->get_wpconfig_backup_content() ) {
            return new WP_Error( 'backup_failed', __( 'Could not create wp-config.php backup', 'vigilante' ) );
        }

        return true;
    }

    /**
     * Get the stored wp-config.php backup content, or '' if none.
     *
     * @return string
     */
    private function get_wpconfig_backup_content() {
        $backup = get_option( 'vigilante_wpconfig_backup' );
        return ( is_array( $backup ) && isset( $backup['content'] ) ) ? (string) $backup['content'] : '';
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
     * Comment out existing managed constants in wp-config.php
     *
     * @return bool|WP_Error
     */
    private function comment_existing_constants() {
        $content = $this->read_file_directly( $this->wpconfig_path );
        
        if ( false === $content || ! $this->validate_wpconfig_content( $content ) ) {
            return new WP_Error( 'read_failed', __( 'Could not read wp-config.php', 'vigilante' ) );
        }

        $modified = false;

        foreach ( $this->managed_constants as $constant ) {
            // Pattern to match define statements for this constant
            // Matches: define( 'CONSTANT', value ); or define('CONSTANT', value);
            // Does NOT match already commented lines (commented lines have // prefix before define)
            $pattern = '/^(\s*)(define\s*\(\s*[\'"]' . preg_quote( $constant, '/' ) . '[\'"]\s*,\s*[^)]+\)\s*;)/m';
            
            // Loop to comment ALL occurrences, not just the first
            // wp-config.php files may have duplicate defines (e.g. multiple WP_DEBUG)
            $safety = 0;
            while ( preg_match( $pattern, $content, $matches ) && $safety < 20 ) {
                $safety++;
                $full_line = $matches[0];

                // Already commented by us — no more uncommented matches possible
                if ( strpos( $full_line, self::ORIGINAL_MARKER ) !== false ) {
                    break;
                }
                
                // Check if this line is inside our Vigilante block (skip it)
                $marker_pos = strpos( $content, self::MARKER_START );
                if ( $marker_pos !== false ) {
                    $line_pos = strpos( $content, $full_line );
                    $end_marker_pos = strpos( $content, self::MARKER_END );
                    if ( $line_pos > $marker_pos && $line_pos < $end_marker_pos ) {
                        break; // Inside our block, stop processing this constant
                    }
                }

                // Comment out this occurrence
                $replacement = $matches[1] . self::ORIGINAL_MARKER . $matches[2];
                $content = preg_replace( $pattern, $replacement, $content, 1 );
                $modified = true;
            }
        }

        if ( $modified ) {
            // Validate BEFORE writing
            if ( ! $this->validate_wpconfig_content( $content ) ) {
                return new WP_Error( 'invalid_after_comment', __( 'wp-config.php would be invalid after commenting constants', 'vigilante' ) );
            }
            
            if ( ! $this->write_file_directly( $this->wpconfig_path, $content ) ) {
                return new WP_Error( 'write_failed', __( 'Could not write to wp-config.php', 'vigilante' ) );
            }
        }

        return true;
    }

    /**
     * Uncomment original constants that were commented by us
     *
     * @return bool
     */
    private function uncomment_original_constants() {
        $content = $this->read_file_directly( $this->wpconfig_path );
        
        if ( false === $content ) {
            return false;
        }

        // Find and uncomment lines marked with our original marker
        $pattern = '/^(\s*)' . preg_quote( self::ORIGINAL_MARKER, '/' ) . '(.+)$/m';
        
        if ( preg_match( $pattern, $content ) ) {
            $content = preg_replace( $pattern, '$1$2', $content );
            
            // Validate BEFORE writing
            if ( ! $this->validate_wpconfig_content( $content ) ) {
                return false;
            }
            
            return $this->write_file_directly( $this->wpconfig_path, $content );
        }

        return true;
    }

    /**
     * Remove old Easy Vigilante constants from wp-config.php
     *
     * @return bool
     */
    public function remove_old_constants() {
        $content = $this->read_file_directly( $this->wpconfig_path );
        
        if ( false === $content || ! $this->validate_wpconfig_content( $content ) ) {
            return false;
        }

        $modified = false;
        
        // Remove old AyudaWP Security Constants block
        $pattern = '/' . preg_quote( self::OLD_MARKER_START, '/' ) . '.*?' . preg_quote( self::OLD_MARKER_END, '/' ) . '\s*/s';
        if ( preg_match( $pattern, $content ) ) {
            $content = preg_replace( $pattern, '', $content );
            $modified = true;
        }

        if ( $modified ) {
            // Validate BEFORE writing
            if ( ! $this->validate_wpconfig_content( $content ) ) {
                return false;
            }
            return $this->write_file_directly( $this->wpconfig_path, $content );
        }

        return true;
    }

    /**
     * Remove our security constants from wp-config.php and restore originals
     *
     * @return bool
     */
    public function remove_constants() {
        if ( ! file_exists( $this->wpconfig_path ) ) {
            return true;
        }

        $content = $this->read_file_directly( $this->wpconfig_path );
        
        if ( false === $content ) {
            return false;
        }

        // If our markers don't exist, just try to uncomment originals
        if ( strpos( $content, self::MARKER_START ) === false ) {
            return $this->uncomment_original_constants();
        }

        // Validate before modification
        if ( ! $this->validate_wpconfig_content( $content ) ) {
            return false;
        }
        
        // Remove our section
        $pattern = '/' . preg_quote( self::MARKER_START, '/' ) . '.*?' . preg_quote( self::MARKER_END, '/' ) . '\s*/s';
        $new_content = preg_replace( $pattern, '', $content );

        // CRITICAL: Validate result BEFORE writing
        if ( ! $this->validate_wpconfig_content( $new_content ) ) {
            // Something went wrong, don't write
            return false;
        }

        // Clean up multiple empty lines
        $new_content = preg_replace( '/\n{3,}/', "\n\n", $new_content );

        // Write the file without our block
        if ( ! $this->write_file_directly( $this->wpconfig_path, $new_content ) ) {
            return false;
        }

        // Now uncomment the original constants
        return $this->uncomment_original_constants();
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

        // Disable WordPress's built-in pseudo-cron (page-view trigger). Pairs with the
        // .htaccess block from firewall.protect_wp_cron — this constant alone does NOT
        // block external HTTP access to wp-cron.php, only the auto-spawn from front-end
        // page views. Both pieces are needed for full coverage; both require a real
        // server-side cron job calling wp-cron.php from CLI.
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
     * Write constants to wp-config.php with multiple safety checks
     *
     * @param string $constants Constants block to write.
     * @return bool|WP_Error
     */
    private function write_constants( $constants ) {
        // SAFETY CHECK 1: Read file directly (not via WP_Filesystem which can fail)
        $content = $this->read_file_directly( $this->wpconfig_path );

        // SAFETY CHECK 2: Verify we got valid content
        if ( false === $content || strlen( $content ) < self::MIN_CONFIG_SIZE ) {
            return new WP_Error( 'read_failed', __( 'Could not read wp-config.php or file is too small', 'vigilante' ) );
        }

        // SAFETY CHECK 3: Validate it's a real wp-config.php
        if ( ! $this->validate_wpconfig_content( $content ) ) {
            return new WP_Error( 'invalid_config', __( 'wp-config.php does not appear to be valid', 'vigilante' ) );
        }

        // Store original for comparison
        $original_content = $content;

        // Remove existing Vigilante constants block
        $pattern = '/' . preg_quote( self::MARKER_START, '/' ) . '.*?' . preg_quote( self::MARKER_END, '/' ) . '\s*/s';
        $content = preg_replace( $pattern, '', $content );

        // Remove old plugin constants block
        $old_pattern = '/' . preg_quote( self::OLD_MARKER_START, '/' ) . '.*?' . preg_quote( self::OLD_MARKER_END, '/' ) . '\s*/s';
        $content = preg_replace( $old_pattern, '', $content );

        // Clean up multiple empty lines
        $content = preg_replace( '/\n{3,}/', "\n\n", $content );

        // SAFETY CHECK 4: Content should still be valid after removal
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

        // SAFETY CHECK 5: Final content must still be valid
        if ( ! $this->validate_wpconfig_content( $content ) ) {
            return new WP_Error( 'invalid_final', __( 'Final wp-config.php would be invalid, aborting', 'vigilante' ) );
        }

        // SAFETY CHECK 6: Final content should be at least as big as original (minus our old block)
        if ( strlen( $content ) < strlen( $original_content ) * 0.5 ) {
            return new WP_Error( 'size_check_failed', __( 'Final wp-config.php would be too small, aborting', 'vigilante' ) );
        }

        // All checks passed, write the file
        if ( $this->write_file_directly( $this->wpconfig_path, $content ) ) {
            return true;
        }

        return new WP_Error( 'write_failed', __( 'Failed to write wp-config.php', 'vigilante' ) );
    }

    /**
     * Write file directly (more reliable than WP_Filesystem)
     *
     * @param string $path File path.
     * @param string $content Content to write.
     * @return bool
     */
    private function write_file_directly( $path, $content ) {
        return false !== file_put_contents( $path, $content ); // phpcs:ignore
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