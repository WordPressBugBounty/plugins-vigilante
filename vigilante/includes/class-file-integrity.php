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

        // Schedule automated scans only if options available
        if ( ! empty( $this->options['auto_scan'] ) ) {
            add_action( 'vigilante_file_integrity_scan', array( $this, 'run_scheduled_scan' ) );
            $this->schedule_scan();
        }
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

        return $results;
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
    private function scan_critical_root_files() {
        $modified = array();
        $baseline = $this->get_critical_files_baseline();
        $baseline_changed = false;
        $root_path = untrailingslashit( ABSPATH );

        foreach ( $this->critical_root_files as $filename ) {
            $full_path = $root_path . '/' . $filename;

            if ( ! file_exists( $full_path ) ) {
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
                    'content' => $normalized,
                    'updated' => time(),
                );
                $baseline_changed = true;
                continue;
            }

            // Upgrade legacy baseline entries that lack content (pre-diff format)
            if ( ! isset( $baseline[ $filename ]['content'] ) && $baseline[ $filename ]['hash'] === $current_hash ) {
                $baseline[ $filename ]['content'] = $normalized;
                $baseline_changed = true;
                continue;
            }

            // Compare against stored baseline
            if ( $baseline[ $filename ]['hash'] !== $current_hash ) {
                $baseline_content = $baseline[ $filename ]['content'] ?? '';
                $diff = '' !== $baseline_content
                    ? $this->compute_simple_diff( $baseline_content, $normalized )
                    : array( 'added' => array(), 'removed' => array(), 'unavailable' => true );

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
        }

        if ( $baseline_changed ) {
            update_option( self::BASELINE_OPTION, $baseline, false );
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
    private function normalize_critical_file( $filename, $content ) {
        // Normalize line endings first (CRLF and CR to LF)
        $content = str_replace( array( "\r\n", "\r" ), "\n", $content );

        if ( 'wp-config.php' === $filename ) {
            // Remove Vigilante constants blocks (current and legacy)
            foreach ( $this->wpconfig_markers as $markers ) {
                $pattern = '/' . preg_quote( $markers[0], '/' ) . '.*?' . preg_quote( $markers[1], '/' ) . '\s*/s';
                $content = preg_replace( $pattern, '', $content );
            }

            // Remove lines commented out by Vigilante (original constants)
            $content = preg_replace(
                '/^.*' . preg_quote( $this->wpconfig_original_marker, '/' ) . '.*$/m',
                '',
                $content
            );
        } elseif ( '.htaccess' === $filename ) {
            // Remove Vigilante htaccess blocks (firewall + security headers)
            foreach ( $this->htaccess_markers as $markers ) {
                $pattern = '/' . preg_quote( $markers[0], '/' ) . '.*?' . preg_quote( $markers[1], '/' ) . '\s*/s';
                $content = preg_replace( $pattern, '', $content );
            }
        }

        // Collapse multiple blank lines into one (blocks removal leaves gaps)
        $content = preg_replace( '/\n{3,}/', "\n\n", $content );

        return trim( $content );
    }

    /**
     * Get stored baseline hashes for critical files
     *
     * @return array Associative array keyed by filename.
     */
    public function get_critical_files_baseline() {
        $baseline = get_option( self::BASELINE_OPTION, array() );
        return is_array( $baseline ) ? $baseline : array();
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
        $full_path = untrailingslashit( ABSPATH ) . '/' . $filename;

        if ( ! file_exists( $full_path ) ) {
            return false;
        }

        $content = file_get_contents( $full_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        if ( false === $content ) {
            return false;
        }

        $normalized = $this->normalize_critical_file( $filename, $content );

        $baseline = $this->get_critical_files_baseline();
        $baseline[ $filename ] = array(
            'hash'    => md5( $normalized ),
            'size'    => strlen( $content ),
            'content' => $normalized,
            'updated' => time(),
        );

        return update_option( self::BASELINE_OPTION, $baseline, false );
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
        $root_path = untrailingslashit( ABSPATH );

        foreach ( $this->critical_root_files as $filename ) {
            $full_path = $root_path . '/' . $filename;

            if ( ! file_exists( $full_path ) ) {
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
                'content' => $normalized,
                'updated' => time(),
            );
        }

        update_option( self::BASELINE_OPTION, $baseline, false );

        return $baseline;
    }

    /**
     * Get core checksums from WordPress.org API
     *
     * @return array|WP_Error Checksums or error.
     */
    private function get_core_checksums() {
        $locale = get_locale();
        $version = $this->wp_version;
        
        // Check cache first
        $cache_key = 'vigilante_core_checksums_' . md5( $version . $locale );
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

                $actual_hash = md5_file( $file_path );

                if ( $actual_hash !== $expected_hash ) {
                    $results['modified'][] = array(
                        'file'          => 'plugins/' . $plugin_slug . '/' . $file,
                        'type'          => 'plugin',
                        'plugin'        => $plugin_data['Name'],
                        'expected_hash' => $expected_hash,
                        'actual_hash'   => $actual_hash,
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
     * Get plugin checksums from WordPress.org
     *
     * @param string $slug    Plugin slug.
     * @param string $version Plugin version.
     * @return array|WP_Error|string
     */
    private function get_plugin_checksums( $slug, $version ) {
        // Check cache first
        $cache_key = 'vigilante_plugin_checksums_' . md5( $slug . $version );
        $cached = get_transient( $cache_key );
        if ( false !== $cached ) {
            return $cached;
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
            // Cache "not found" to avoid repeated requests
            set_transient( $cache_key, 'not_found', HOUR_IN_SECONDS );
            return 'not_found';
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body['files'] ) ) {
            return new WP_Error( 'no_checksums', __( 'No checksums found', 'vigilante' ) );
        }

        $checksums = array();
        foreach ( $body['files'] as $file => $data ) {
            $checksums[ $file ] = $data['md5'];
        }

        // Cache for 24 hours
        set_transient( $cache_key, $checksums, DAY_IN_SECONDS );

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

                $actual_hash = md5_file( $file_path );

                if ( $actual_hash !== $expected_hash ) {
                    $results['modified'][] = array(
                        'file'          => 'themes/' . $theme_slug . '/' . $file,
                        'type'          => 'theme',
                        'theme'         => $theme->get( 'Name' ),
                        'expected_hash' => $expected_hash,
                        'actual_hash'   => $actual_hash,
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
        // Check cache first
        $cache_key = 'vigilante_theme_checksums_' . md5( $slug . $version );
        $cached = get_transient( $cache_key );
        if ( false !== $cached ) {
            return $cached;
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
            // Cache "not found" to avoid repeated requests
            set_transient( $cache_key, 'not_found', HOUR_IN_SECONDS );
            return new WP_Error( 'not_found', __( 'Checksums not available', 'vigilante' ) );
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body['files'] ) ) {
            return new WP_Error( 'no_checksums', __( 'No checksums found', 'vigilante' ) );
        }

        $checksums = array();
        foreach ( $body['files'] as $file => $data ) {
            $checksums[ $file ] = $data['md5'];
        }

        // Cache for 24 hours
        set_transient( $cache_key, $checksums, DAY_IN_SECONDS );

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
            if ( stripos( $content, $needle ) !== false ) {
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
        if ( ! empty( $cf ) && stripos( $content, $cf ) !== false ) {
            return $cf . ')';
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

                // Get relative path within plugin/theme directory
                $relative_to_dir = str_replace( $directory . '/', '', $file_path );

                // Skip if file is in the checksums (it's known)
                if ( isset( $checksums[ $relative_to_dir ] ) ) {
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
        $relative = str_replace( ABSPATH, '', $path );

        foreach ( $excluded as $exclude ) {
            if ( strpos( $relative, $exclude ) !== false ) {
                return true;
            }
        }

        return false;
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

        foreach ( $excluded as $exclude ) {
            $exclude = strtolower( trim( $exclude ) );
            // Support both ".log" and "log" formats
            if ( 0 !== strpos( $exclude, '.' ) ) {
                $exclude = '.' . $exclude;
            }
            if ( $exclude === $extension ) {
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
            admin_url( 'admin.php?page=vigilante&tab=file-integrity' ),
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