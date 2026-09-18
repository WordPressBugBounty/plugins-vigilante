<?php
/**
 * Vigilant Self-Integrity (self-protection core)
 *
 * Verifies Vigilant's own files with three anchors:
 *
 *  A1  WordPress.org SHA-256 checksums for the installed version (remote
 *      anchor: a local attacker cannot alter it; unavailable for untagged
 *      builds or in the first hours after a release).
 *  A2  MANIFEST.sha256 distributed inside the plugin (offline anchor in GNU
 *      coreutils format, verifiable by anyone with `sha256sum -c` or
 *      `php bin/verify-manifest.php`; regenerable by whoever can write to the
 *      plugin folder, which is why it never stands alone).
 *  A3  SHA-256 fingerprint of MANIFEST.sha256 stored in the database
 *      (detects a swapped or deleted manifest; forging it needs database
 *      write access).
 *
 * What this deliberately does NOT cover: vulnerabilities in Vigilant's own
 * code (this detects tampering, not bugs), and an attacker with database
 * write access, who can switch the toggle off or blank the fingerprint, as
 * with any security plugin. Both are documented in SECURITY.md.
 *
 * Entry points:
 *  - File Integrity scan (first block of run_scan(), exempt from the time
 *    budget and from user exclusions).
 *  - upgrader_process_complete (immediate verification after each update of
 *    Vigilant itself; see vigilante_on_upgrader_process_complete()).
 *  - admin_init, for a user who can manage options only: version change
 *    detection (priority 20) and the cron watchdog (priority 30).
 *  - daily maintenance (cron): the same two, for sites nobody opens the admin of.
 *
 * Events are logged with type "system", which the Audit Alerts engine
 * ignores, so the standalone alert email here is never duplicated.
 *
 * @package Vigilante
 * @since   3.0.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Self_Integrity
 *
 * The constructor registers nothing: Vigilante_Main creates the one instance
 * that calls init_hooks(), and every other new (activation, migration, scan,
 * upgrader) is a plain object. It is NOT gated by the modules.file_integrity
 * master toggle, and it has no setting of its own: see is_on().
 */
class Vigilante_Self_Integrity {

    /**
     * Option holding the persistent state (autoload off; runtime data never
     * lives inside vigilante_options).
     */
    const STATE_OPTION = 'vigilante_self_integrity_state';

    /**
     * Manifest file name, at the plugin root.
     */
    const MANIFEST_FILE = 'MANIFEST.sha256';

    /**
     * Transient prefix for the wp.org sha256 checksums cache (per version).
     */
    const CHECKSUMS_TRANSIENT_PREFIX = 'vigilante_self_checksums_';

    /**
     * Throttle transient for the watchdog run from admin_init.
     */
    const WATCHDOG_TRANSIENT = 'vigilante_watchdog_ran';

    /**
     * Throttle transient for the version change check. While a version change
     * cannot be vouched for, nothing is rebaselined, so without it every
     * admin page would hash the tree and ask WordPress.org again.
     */
    const VERSION_CHECK_TRANSIENT = 'vigilante_self_version_check';

    /**
     * Seconds between two version change checks while one is unresolved.
     */
    const VERSION_CHECK_THROTTLE = 600;

    /**
     * Per-request HTTP timeout in seconds. Kept low because the check can run
     * in synchronous admin_init contexts.
     */
    const HTTP_TIMEOUT = 5;

    /**
     * A manifest with more lines than this, blank ones included, is not a
     * Vigilant manifest.
     */
    const MAX_MANIFEST_LINES = 2000;

    /**
     * Largest MANIFEST.sha256 that is read at all. MAX_MANIFEST_LINES entries
     * take well under a megabyte, so a bigger file is not a valid manifest,
     * and reading it to find that out could exhaust memory and end the scan
     * with no finding.
     */
    const MAX_MANIFEST_BYTES = 1048576;

    /**
     * Findings kept in the stored state and in log entries (worst first).
     */
    const MAX_STORED_FINDINGS = 200;

    /**
     * Harmless extra files listed at most; links, executables and folders
     * that cannot be listed are always reported (see detect_extra_files()).
     */
    const MAX_EXTRA_WARNINGS = 100;

    /**
     * Largest file whose line endings are normalized before comparing; the
     * biggest distributed file is under 600 KB.
     */
    const MAX_NORMALIZED_BYTES = 5242880;

    /**
     * Entries walked at most in the plugin folder before giving up with a
     * critical finding. A distributed copy holds under a hundred.
     */
    const MAX_TREE_ENTRIES = 50000;

    /**
     * A cron event restored again within this window counts as repeated
     * (30 days).
     */
    const WATCHDOG_REPEAT_WINDOW = 2592000;

    /**
     * A check older than this stops counting as a result. Something that stops
     * the check (a filter, a removed hook, a cron nobody runs, files edited)
     * leaves the last state frozen, and a green from three days ago read as
     * "verified" would be the screen lying by omission.
     */
    const STALE_AFTER = 259200;

    /**
     * How often the same alarm about being switched off, or about a hook that
     * someone removed, is written to the log and emailed.
     */
    const OFF_ALARM_WINDOW = 86400;

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Activity log instance
     *
     * @var Vigilante_Activity_Log|null
     */
    private $activity_log;

    /**
     * Files at the plugin root that are never in the manifest.
     *
     * The same rules live in bin/verify-manifest.php and in the release tool
     * that generates the manifest, and the release checks run the three on the
     * same set of paths and require the same verdicts.
     *
     * - MANIFEST.sha256: the manifest cannot contain its own hash.
     * - readme.txt, changelog.txt: WordPress.org lets a readme be updated on
     *   a released tag without a new version, so hashing them would turn an
     *   ordinary readme fix into a tamper alarm. They are not code; the
     *   WordPress.org checksums still list them.
     *
     * Only at the root: a directory or a file with one of these names deeper
     * in the tree is checked like any other.
     *
     * @var array
     */
    private static $root_excluded_files = array( 'MANIFEST.sha256', 'readme.txt', 'changelog.txt' );

    /**
     * SVN working copy metadata at the plugin root, matched exactly: only the
     * files svn itself writes there. Anything else inside .svn/ is checked
     * like any other file, so the folder cannot hide code (a .htaccess that
     * maps .jpg to PHP next to a .jpg with code in it was enough before).
     *
     * @var string
     */
    private static $svn_metadata_pattern = '#^\.svn/(?:wc\.db|wc\.db-journal|format|entries|pristine/[0-9a-f]{2}/[0-9a-f]{40}\.svn-base)$#';

    /**
     * Operating system junk, skipped by file name anywhere in the tree.
     *
     * @var array
     */
    private static $junk_file_names = array( '.DS_Store', 'Thumbs.db' );

    /**
     * Extensions a web server may run as PHP: an extra file with one of these
     * is critical, and a modified one too.
     *
     * @var array
     */
    private static $executable_extensions = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'pht', 'phar', 'inc' );

    /**
     * File names that change what the server runs in their folder (a handler
     * for another extension, auto_prepend_file): treated as executable.
     *
     * @var array
     */
    private static $executable_names = array( '.htaccess', '.user.ini', 'php.ini' );

    /**
     * Constructor. Registers no hooks, see init_hooks().
     *
     * @param Vigilante_Settings          $settings     Settings instance.
     * @param Vigilante_Activity_Log|null $activity_log Activity log instance.
     */
    public function __construct( $settings, $activity_log = null ) {
        $this->settings     = $settings;
        $this->activity_log = $activity_log;
    }

    /**
     * Register the admin_init entry points. Called once, by Vigilante_Main.
     *
     * Priority 20 runs after Vigilante_Admin::run_migrations() (priority 10),
     * so an anchor captured by the migration is not processed twice.
     */
    public function init_hooks() {
        add_action( 'admin_init', array( $this, 'maybe_detect_version_change' ), 20 );
        add_action( 'admin_init', array( $this, 'maybe_run_watchdog' ), 30 );
        // Last of all, to see whether the two above are still there: code that
        // runs inside WordPress can unhook them, and a plugin that does that
        // leaves every screen showing the last result as if nothing happened.
        add_action( 'admin_init', array( $this, 'verify_hooks' ), PHP_INT_MAX );
    }

    /**
     * Are the two entry points of the self-check still hooked?
     *
     * Runs at the end of admin_init, so anything that unhooked them earlier in
     * the same request is visible here. It cannot say which file called
     * remove_action (WordPress fires nothing when a callback is removed, and by
     * the time this runs it already happened), so it records the short list of
     * suspects: the plugins loaded in this request.
     */
    public function verify_hooks() {
        if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // Switched off by code: the line in the Security Audit is written from
        // here too, not only from the daily task. Waiting for cron to say that
        // the self-check is off is waiting a day to hear the alarm.
        $this->audit_off_state();
        if ( ! self::is_on() ) {
            return;
        }
        $missing = array();
        foreach ( array( 'maybe_detect_version_change', 'maybe_run_watchdog' ) as $method ) {
            if ( false === has_action( 'admin_init', array( $this, $method ) ) ) {
                $missing[] = $method;
            }
        }

        $state = $this->get_state();
        if ( empty( $missing ) ) {
            if ( ! empty( $state['hooks_removed'] ) ) {
                unset( $state['hooks_removed'] );
                $this->save_state( $state );
            }
            return;
        }

        $state['hooks_removed'] = array(
            'methods' => $missing,
            'last'    => time(),
            'plugins' => self::loaded_plugins(),
        );
        $this->save_state( $state );

        $alerted = isset( $state['hooks_alerted'] ) ? (int) $state['hooks_alerted'] : 0;
        if ( ( time() - $alerted ) < self::OFF_ALARM_WINDOW ) {
            return;
        }
        $state['hooks_alerted'] = time();
        $this->save_state( $state );
        $this->log(
            'self_hooks_removed',
            sprintf(
                /* translators: %s: comma-separated list of removed callbacks */
                __( 'Something removed the self-protection hooks of Vigilant in this request: %s', 'vigilante' ),
                implode( ', ', $missing )
            ),
            array(
                'methods' => $missing,
                'plugins' => self::loaded_plugins(),
            ),
            'critical'
        );
        $this->maybe_send_self_alert(
            array(
                $this->finding(
                    'self_hooks_removed',
                    implode( ', ', $missing ),
                    'critical',
                    __( 'Something removed the hooks that run the self-check.', 'vigilante' )
                ),
            ),
            'hooks'
        );
    }

    /**
     * Plugins and must-use plugins loaded in this request: the short list of
     * suspects when something turns the self-check off.
     *
     * @return array
     */
    public static function loaded_plugins() {
        $lista = array();
        if ( function_exists( 'wp_get_active_and_valid_plugins' ) ) {
            foreach ( wp_get_active_and_valid_plugins() as $ruta ) {
                $lista[] = str_replace( WP_PLUGIN_DIR . '/', '', $ruta );
            }
        }
        if ( function_exists( 'wp_get_mu_plugins' ) ) {
            foreach ( wp_get_mu_plugins() as $ruta ) {
                $lista[] = 'mu-plugins/' . basename( $ruta );
            }
        }
        sort( $lista, SORT_STRING );
        return array_slice( $lista, 0, 60 );
    }

    /**
     * Files that hook the filter which switches the self-check off.
     *
     * Named, not guessed: each callback is resolved with Reflection to the file
     * that declares it. Turning the check off is allowed, doing it quietly is
     * not.
     *
     * @return array List of file paths, relative to the WordPress root.
     */
    public static function disabled_by() {
        global $wp_filter;
        $ficheros = array();
        if ( empty( $wp_filter['vigilante_self_integrity_enabled'] ) || ! is_object( $wp_filter['vigilante_self_integrity_enabled'] ) ) {
            return $ficheros;
        }
        foreach ( (array) $wp_filter['vigilante_self_integrity_enabled']->callbacks as $prioridad => $entradas ) {
            foreach ( (array) $entradas as $entrada ) {
                $llamada = isset( $entrada['function'] ) ? $entrada['function'] : null;
                try {
                    if ( is_string( $llamada ) && function_exists( $llamada ) ) {
                        $ref = new ReflectionFunction( $llamada );
                    } elseif ( $llamada instanceof Closure ) {
                        $ref = new ReflectionFunction( $llamada );
                    } elseif ( is_array( $llamada ) && isset( $llamada[0], $llamada[1] ) ) {
                        $ref = new ReflectionMethod( is_object( $llamada[0] ) ? get_class( $llamada[0] ) : (string) $llamada[0], (string) $llamada[1] );
                    } else {
                        continue;
                    }
                } catch ( Exception $e ) {
                    unset( $e );
                    continue;
                } catch ( Error $e ) {
                    unset( $e );
                    continue;
                }
                $fichero = $ref->getFileName();
                if ( ! $fichero ) {
                    continue;
                }
                $fichero = str_replace( array( ABSPATH, WP_CONTENT_DIR . '/' ), array( '', 'wp-content/' ), $fichero );
                if ( ! in_array( $fichero, $ficheros, true ) ) {
                    $ficheros[] = $fichero;
                }
            }
        }
        return $ficheros;
    }

    /**
     * Whether the self-check runs. It always does.
     *
     * There is no setting for this, and that is the point: a security plugin
     * that can be told not to check itself has a switch whose only real user is
     * whoever just changed its files. It was a checkbox while this was being
     * built, it never shipped as one, and it was removed before 3.0.0 was
     * tagged. It is not gated by the modules.file_integrity master toggle
     * either: turning off File Integrity does not stop the plugin from
     * checking its own files.
     *
     * The filter is for the one honest case, a site that must not talk to
     * WordPress.org at all, and it is documented in SECURITY.md. It lives in
     * code, so nobody with write access to the database can use it.
     *
     * @return bool
     */
    public static function is_on() {
        return (bool) apply_filters( 'vigilante_self_integrity_enabled', true );
    }

    /**
     * Instance form of is_on(), kept because most callers have the object.
     *
     * @return bool
     */
    public function is_enabled() {
        return self::is_on();
    }

    // -------------------------------------------------------------------
    // Paths
    // -------------------------------------------------------------------

    /**
     * Whether a manifest path is a plain relative path inside the plugin.
     *
     * The manifest can be written by whoever can write to the plugin folder,
     * and every entry is hashed from disk: an absolute path, a ".." segment or
     * a NUL byte would turn the check into a hash oracle for any file on the
     * server. Only letters, digits, dot, underscore, hyphen, plus and at sign,
     * separated by single slashes, are accepted.
     *
     * @param string $path Relative path.
     * @return bool
     */
    public static function is_safe_relative_path( $path ) {
        if ( ! is_string( $path ) || '' === $path || strlen( $path ) > 255 ) {
            return false;
        }
        if ( ! preg_match( '#^[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)*$#', $path ) ) {
            return false;
        }
        foreach ( explode( '/', $path ) as $segment ) {
            if ( '.' === $segment || '..' === $segment ) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether a relative path is left out of the manifest.
     *
     * @param string $relative Relative path with forward slashes.
     * @return bool
     */
    public static function is_excluded_path( $relative ) {
        $relative = (string) $relative;
        $segments = explode( '/', $relative );
        if ( 1 === count( $segments ) && in_array( $segments[0], self::$root_excluded_files, true ) ) {
            return true;
        }
        if ( preg_match( self::$svn_metadata_pattern, $relative ) ) {
            return true;
        }
        return in_array( end( $segments ), self::$junk_file_names, true );
    }

    /**
     * Whether a relative path is something a web server may run, or a file
     * that changes what it runs.
     *
     * @param string $relative Relative path.
     * @return bool
     */
    public static function is_executable_path( $relative ) {
        $name = strtolower( basename( (string) $relative ) );
        if ( in_array( $name, self::$executable_names, true ) ) {
            return true;
        }
        // Every extension counts, not only the last one: with AddHandler,
        // Apache runs x.php.jpg as PHP (mod_mime maps each extension of the
        // name), which is how several cPanel setups configure PHP.
        $parts = explode( '.', $name );
        array_shift( $parts );
        foreach ( $parts as $part ) {
            if ( in_array( $part, self::$executable_extensions, true ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a path is a text file whose line endings a host may rewrite.
     *
     * @param string $relative Relative path.
     * @return bool
     */
    public static function is_text_path( $relative ) {
        return in_array(
            strtolower( pathinfo( (string) $relative, PATHINFO_EXTENSION ) ),
            array( 'php', 'js', 'css', 'json', 'txt', 'md', 'html', 'htm', 'xml', 'svg', 'po', 'pot', 'ini' ),
            true
        );
    }

    /**
     * sha256 of a text file with CRLF or CR line endings turned into LF and,
     * where it changes nothing, a leading UTF-8 BOM removed.
     *
     * Not a copy of Vigilante_File_Integrity::hash_matches_published(), which
     * forgives more because it judges other plugins. Here a BOM is only
     * forgiven in files that do not care about it: in PHP it is output sent
     * before the headers, and json_decode() rejects it, so a BOM in front of
     * includes/scan-patterns.json empties the malware signatures while the
     * file would look intact. Files above MAX_NORMALIZED_BYTES are not read
     * whole: the raw hash has already failed, and the difference stays a
     * finding instead of a fatal error that stops the whole scan.
     *
     * @param string $path     Absolute path.
     * @param string $relative Relative path, for the extension.
     * @return string|null
     */
    private static function normalized_hash( $path, $relative ) {
        $size = filesize( $path );
        if ( false === $size || $size > self::MAX_NORMALIZED_BYTES ) {
            return null;
        }
        // The read stops past the limit too: the size can change between the
        // check above and the read.
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file of the plugin itself, read to hash it.
        $content = file_get_contents( $path, false, null, 0, self::MAX_NORMALIZED_BYTES + 1 );
        if ( false === $content || strlen( $content ) > self::MAX_NORMALIZED_BYTES ) {
            return null;
        }
        $extension = strtolower( pathinfo( (string) $relative, PATHINFO_EXTENSION ) );
        // The last extension is not enough: x.php.svg runs as PHP where a handler
        // matches any extension of the name, so it keeps its BOM.
        if ( "\xEF\xBB\xBF" === substr( $content, 0, 3 ) && in_array( $extension, array( 'js', 'css', 'txt', 'md', 'html', 'htm', 'xml', 'svg', 'po', 'pot' ), true ) && ! self::is_executable_path( (string) $relative ) ) {
            $content = substr( $content, 3 );
        }
        return hash( 'sha256', str_replace( array( "\r\n", "\r" ), "\n", $content ) );
    }

    /**
     * Folder name of the plugin as installed (normally "vigilante").
     *
     * @return string
     */
    private static function plugin_folder() {
        return dirname( VIGILANTE_PLUGIN_BASENAME );
    }

    /**
     * Whether a path from the File Integrity ignore workflow points inside
     * Vigilant's own folder, in either of the two conventions the scan uses
     * (plugins/<folder>/... and the ABSPATH-relative one).
     *
     * Ignoring such a path silences the self-check for that file, so on a
     * network it takes the same network rights as approving a change to
     * wp-config.php or the root .htaccess: Vigilant's files are shared by
     * every site, and the site that owns them reports for all of them.
     *
     * @param string $path Path as stored in vigilante_ignored_files.
     * @return bool
     */
    public static function is_own_file_path( $path ) {
        $path = ltrim( str_replace( '\\', '/', (string) $path ), '/' );
        if ( '' === $path ) {
            return false;
        }
        $plugin_prefix  = 'plugins/' . self::plugin_folder() . '/';
        $abspath_prefix = ltrim( str_replace( '\\', '/', str_replace( ABSPATH, '', VIGILANTE_PLUGIN_DIR ) ), '/' );
        return 0 === strpos( $path, $plugin_prefix ) || ( '' !== $abspath_prefix && 0 === strpos( $path, $abspath_prefix ) );
    }

    // -------------------------------------------------------------------
    // Anchors
    // -------------------------------------------------------------------

    /**
     * Plugin root without trailing slash.
     *
     * @return string
     */
    private function get_plugin_root() {
        return rtrim( VIGILANTE_PLUGIN_DIR, '/\\' );
    }

    /**
     * Version of the code on disk (not the constant in memory: during an
     * update the old code handles the hook while the new files are already
     * on disk).
     *
     * @return string
     */
    private function get_disk_version() {
        $main = $this->get_plugin_root() . '/' . basename( VIGILANTE_PLUGIN_BASENAME );
        if ( is_readable( $main ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading the plugin's own main file header; WP_Filesystem is not warranted here.
            $head = (string) file_get_contents( $main, false, null, 0, 8192 );
            if ( preg_match( '/^\s*\*\s*Version:\s*(\S+)\s*$/m', $head, $m ) ) {
                return $m[1];
            }
        }
        return defined( 'VIGILANTE_VERSION' ) ? VIGILANTE_VERSION : '';
    }

    /**
     * Read and parse MANIFEST.sha256 (anchor A2).
     *
     * A line that is not "<64 hex>  <path>", an unsafe path, a repeated path,
     * more than MAX_MANIFEST_LINES lines or a file larger than
     * MAX_MANIFEST_BYTES make the whole manifest invalid: it is never used
     * partially.
     *
     * @return array|false|null Map relative path => sha256; false when the file
     *                          exists but is not a valid manifest; null when absent.
     */
    private function read_manifest() {
        $raw = $this->read_manifest_raw();
        if ( null === $raw ) {
            return null;
        }
        if ( false === $raw ) {
            return false;
        }
        $manifest = array();
        $lines    = 0;
        $length   = strlen( $raw );
        $offset   = 0;
        // Line by line over the string and not explode(): a manifest made of
        // line breaks built an array of millions of empty strings and exhausted
        // memory before a single line was judged, which ended the whole scan
        // and the daily check with the last status still stored. Blank lines
        // count towards the limit for the same reason.
        while ( $offset < $length ) {
            $end    = strpos( $raw, "\n", $offset );
            $end    = false === $end ? $length : $end;
            $line   = substr( $raw, $offset, $end - $offset );
            $offset = $end + 1;
            $lines++;
            if ( $lines > self::MAX_MANIFEST_LINES ) {
                return false;
            }
            if ( '' === trim( $line ) ) {
                continue;
            }
            if ( ! preg_match( '/^([0-9a-f]{64})  (.+)$/', $line, $m ) ) {
                return false;
            }
            if ( ! self::is_safe_relative_path( $m[2] ) || isset( $manifest[ $m[2] ] ) ) {
                return false;
            }
            if ( self::is_excluded_path( $m[2] ) ) {
                continue;
            }
            $manifest[ $m[2] ] = $m[1];
        }
        return empty( $manifest ) ? false : $manifest;
    }

    /**
     * Manifest content of this installation, line endings normalized.
     *
     * @return string|false|null See read_manifest_file().
     */
    private function read_manifest_raw() {
        return self::read_manifest_file( $this->get_plugin_root() . '/' . self::MANIFEST_FILE );
    }

    /**
     * Normalized fingerprint of the MANIFEST.sha256 in a folder, taken the same
     * way as the one anchored in the database: the sha256 of the normalized
     * content, 'invalid' for a file larger than MAX_MANIFEST_BYTES, null when
     * there is none (absent, unreadable or a link).
     *
     * vigilante_mark_upgrader_wrote() takes it from the folder the WordPress
     * updater has just written, and the check at the end of the request only
     * trusts the updater when the manifest on disk is still that one.
     *
     * @param string $dir Folder, with or without a trailing slash.
     * @return string|null
     */
    public static function manifest_fingerprint_of( $dir ) {
        $raw = self::read_manifest_file( rtrim( (string) $dir, '/\\' ) . '/' . self::MANIFEST_FILE );
        if ( false === $raw ) {
            return 'invalid';
        }
        return is_string( $raw ) ? hash( 'sha256', $raw ) : null;
    }

    /**
     * Read a manifest file, line endings normalized.
     *
     * @param string $path Absolute path of a MANIFEST.sha256.
     * @return string|false|null Null when absent, unreadable or a link; false
     *                           when larger than MAX_MANIFEST_BYTES, which is
     *                           not read.
     */
    private static function read_manifest_file( $path ) {
        if ( is_link( $path ) || ! is_readable( $path ) ) {
            return null;
        }
        $size = filesize( $path );
        if ( false === $size || $size > self::MAX_MANIFEST_BYTES ) {
            return false;
        }
        // The read stops past the limit too: the size can change between the
        // check above and the read.
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading the plugin's own manifest for verification; WP_Filesystem is not warranted here.
        $raw = file_get_contents( $path, false, null, 0, self::MAX_MANIFEST_BYTES + 1 );
        if ( false === $raw ) {
            return null;
        }
        if ( strlen( $raw ) > self::MAX_MANIFEST_BYTES ) {
            return false;
        }
        // A host or a deploy tool that rewrites line endings rewrites the
        // manifest too. That gives an attacker nothing (an LF manifest reads
        // the same), so the parser and the fingerprint read it normalized.
        if ( "\xEF\xBB\xBF" === substr( $raw, 0, 3 ) ) {
            $raw = substr( $raw, 3 );
        }
        return str_replace( array( "\r\n", "\r" ), "\n", $raw );
    }

    /**
     * SHA-256 of the manifest (the value anchored in DB as A3), line endings
     * normalized: for the manifest the generator writes, that is the SHA-256 of
     * the file itself.
     *
     * @return string|null
     */
    private function get_manifest_fingerprint() {
        $raw = $this->read_manifest_raw();
        return is_string( $raw ) ? hash( 'sha256', $raw ) : null;
    }

    /**
     * Fetch the wp.org SHA-256 checksums for a version (anchor A1).
     *
     * @param string $version Plugin version.
     * @return array|string|null Map path => array of accepted sha256 strings,
     *                           'not_found' (cached 1 h) when wp.org has no
     *                           checksums for the version, or null on
     *                           transient network error (not cached).
     */
    public function get_wporg_sha256_checksums( $version ) {
        if ( '' === $version ) {
            return null;
        }
        $transient_key = self::CHECKSUMS_TRANSIENT_PREFIX . md5( $version );
        $cached        = get_transient( $transient_key );
        if ( 'not_found' === $cached ) {
            return 'not_found';
        }
        if ( is_array( $cached ) && ! empty( $cached ) ) {
            return $cached;
        }

        $url      = 'https://downloads.wordpress.org/plugin-checksums/vigilante/' . rawurlencode( $version ) . '.json';
        $response = wp_remote_get(
            $url,
            array(
                'timeout'             => self::HTTP_TIMEOUT,
                'limit_response_size' => 1048576,
            )
        );

        if ( is_wp_error( $response ) ) {
            return null;
        }

        $code = (int) wp_remote_retrieve_response_code( $response );
        if ( 200 !== $code ) {
            // 404 is normal right after a release (checksums not generated yet)
            // and for untagged builds: cache it for an hour so admin pageloads in
            // that window do not hammer the API. Any other answer (429, 5xx) is
            // WordPress.org having a bad moment, and is asked again sooner.
            set_transient( $transient_key, 'not_found', 404 === $code ? HOUR_IN_SECONDS : 5 * MINUTE_IN_SECONDS );
            return 'not_found';
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
            return null;
        }

        $checksums = array();
        foreach ( $data['files'] as $file => $sums ) {
            if ( count( $checksums ) >= self::MAX_MANIFEST_LINES ) {
                break;
            }
            $file = str_replace( '\\', '/', (string) $file );
            if ( ! is_array( $sums ) || ! isset( $sums['sha256'] ) || ! self::is_safe_relative_path( $file ) ) {
                continue;
            }
            // wp.org publishes a string, or an array when the file changed on
            // the same tag (a readme updated after the release).
            $checksums[ $file ] = array_map( 'strval', (array) $sums['sha256'] );
        }

        if ( empty( $checksums ) ) {
            return null;
        }

        set_transient( $transient_key, $checksums, DAY_IN_SECONDS );
        return $checksums;
    }

    /**
     * Drop the cached wp.org checksums for the disk and anchored versions.
     * Called when an update (upgrader or FTP) is detected.
     */
    public function flush_self_transients() {
        $state = $this->get_state();
        delete_transient( self::CHECKSUMS_TRANSIENT_PREFIX . md5( $this->get_disk_version() ) );
        if ( ! empty( $state['version'] ) ) {
            delete_transient( self::CHECKSUMS_TRANSIENT_PREFIX . md5( $state['version'] ) );
        }
    }

    // -------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------

    /**
     * Stored state.
     *
     * @return array
     */
    public function get_state() {
        $state = get_option( self::STATE_OPTION, array() );
        return is_array( $state ) ? $state : array();
    }

    /**
     * Persist state (autoload off: only read on demand).
     *
     * @param array $state State array.
     */
    private function save_state( $state ) {
        if ( false === get_option( self::STATE_OPTION, false ) ) {
            add_option( self::STATE_OPTION, $state, '', false );
        } else {
            update_option( self::STATE_OPTION, $state, false );
        }
    }

    /**
     * Capture the A3 fingerprint of the current manifest.
     *
     * @param string $via Capture origin: activation|upgrader|version_change|migration|first_run|state_resync.
     * @return bool Whether a fingerprint was captured (valid manifest present).
     */
    public function capture_fingerprint( $via ) {
        if ( ! is_array( $this->read_manifest() ) ) {
            return false;
        }
        $fingerprint = $this->get_manifest_fingerprint();
        if ( null === $fingerprint ) {
            return false;
        }
        $state                  = $this->get_state();
        $state['version']       = $this->get_disk_version();
        $state['manifest_hash'] = $fingerprint;
        $state['captured_at']   = time();
        $state['captured_via']  = $via;
        unset( $state['refused_version'] );
        $this->save_state( $state );
        return true;
    }

    // -------------------------------------------------------------------
    // Main check
    // -------------------------------------------------------------------

    /**
     * Run the self-integrity check.
     *
     * Decision matrix per file (with a valid manifest):
     *  - in manifest, missing on disk            -> self_missing (critical)
     *  - symbolic link, or resolves outside      -> self_symlink (critical)
     *  - disk != manifest and != wp.org          -> self_modified (critical for code, warning for assets)
     *  - disk != manifest but == wp.org          -> manifest_stale (critical)
     *  - disk == manifest but != wp.org          -> distribution_mismatch (warning)
     *  - on disk, not in manifest                -> self_extra (critical if PHP or a link)
     * Anchor level:
     *  - manifest hash != A3, same version       -> manifest_replaced (critical)
     *  - manifest hash != A3, version changed    -> rebaseline if the upgrader did it or wp.org confirms;
     *                                               manifest_replaced if wp.org contradicts it;
     *                                               manifest_unverified (sticky warning) otherwise;
     *                                               a downgrade adds self_downgraded (warning)
     *  - anchored manifest gone or invalid       -> manifest_missing / manifest_invalid
     *                                               (critical with the same version, warning otherwise)
     *  - never anchored, manifest absent/invalid -> verify against wp.org + manifest_missing / manifest_invalid (warning)
     *  - never anchored, nothing available       -> no_anchors (info), no alarm
     *
     * User exclusions (excluded_paths / excluded_extensions /
     * plugin_known_false_positives) do NOT apply here: respecting them would
     * create a silencing vector, and the plugin folder has no variable
     * content. The explicit per-file ignore list (vigilante_ignored_files)
     * IS respected: it is a deliberate admin action.
     *
     * @param string $context scan|upgrader|version_change|watchdog|migration|activation.
     * @return array {status, findings, files_checked, anchors, rebaselined, downgraded}
     */
    public function run_check( $context = 'scan' ) {
        $result = array(
            'status'        => 'disabled',
            'findings'      => array(),
            'files_checked' => 0,
            'anchors'       => array(
                'manifest'    => false,
                'wporg'       => false,
                'fingerprint' => false,
            ),
            'rebaselined'   => false,
            'downgraded'    => false,
        );

        if ( ! $this->is_enabled() ) {
            return $result;
        }

        // An update in progress means half-copied files: skip instead of
        // raising a false critical. The next entry point re-checks. The
        // question is the one WordPress asks, not whether the file exists:
        // core treats a .maintenance older than ten minutes as over
        // (wp-includes/load.php, wp_is_maintenance_mode()), so a stale file
        // left in the root, by accident or on purpose, must not silence
        // the check while the site keeps serving pages.
        if ( function_exists( 'wp_is_maintenance_mode' ) ? wp_is_maintenance_mode() : file_exists( ABSPATH . '.maintenance' ) ) {
            $result['status'] = 'skipped';
            return $result;
        }

        $disk_version = $this->get_disk_version();
        $manifest     = $this->read_manifest();
        $manifest_ok  = is_array( $manifest );
        $manifest_fp  = $this->get_manifest_fingerprint();
        $wporg        = $this->get_wporg_sha256_checksums( $disk_version );
        $wporg_ok     = is_array( $wporg );

        $state          = $this->get_state();
        $previous_state = isset( $state['last_status'] ) ? $state['last_status'] : '';
        $stored_fp      = isset( $state['manifest_hash'] ) ? (string) $state['manifest_hash'] : '';
        $stored_version = isset( $state['version'] ) ? (string) $state['version'] : '';

        $findings = array();
        $refused  = '';

        // --- Anchor A3 evaluation -------------------------------------
        if ( $manifest_ok ) {
            if ( '' === $stored_fp ) {
                if ( $wporg_ok && ! $this->manifest_consistent_with_wporg( $manifest, $wporg ) ) {
                    // The first manifest seen becomes the reference for good, so
                    // it is not adopted when WordPress.org, the one reference out
                    // of an attacker's reach, distributes something else for this
                    // version: a manifest regenerated to list an added file would
                    // otherwise read as verified forever.
                    $findings[] = $this->finding(
                        'manifest_replaced',
                        self::MANIFEST_FILE,
                        'critical',
                        __( 'MANIFEST.sha256 does not describe what WordPress.org distributes for this version, so it was not adopted as the reference for this installation.', 'vigilante' )
                    );
                    $refused = (string) $disk_version;
                } elseif ( ! $wporg_ok && '' !== (string) ( $state['refused_version'] ?? '' ) && ( (string) $state['refused_version'] === (string) $disk_version || 'upgrader' !== $context ) ) {
                    // WordPress.org already said the manifest on disk is not what
                    // it distributes. Not answering now (down, blocked, a checksum
                    // file not cached, or a version it does not publish) is no
                    // reason to adopt one: that would anchor the copy the last
                    // check refused, the same copy with its manifest touched,
                    // since a blank line changes the fingerprint and not the files,
                    // or the same copy with its Version: header raised to a number
                    // WordPress.org will never have. A genuine reinstall waits for
                    // WordPress.org to answer; only the WordPress updater writing
                    // another version is trusted, as it is for an anchored copy.
                    $findings[] = $this->finding(
                        'manifest_replaced',
                        self::MANIFEST_FILE,
                        'critical',
                        (string) $state['refused_version'] === (string) $disk_version
                            ? __( 'MANIFEST.sha256 was not adopted as the reference for this installation: when WordPress.org was last asked, it distributed something else for this version, and it could not be asked now.', 'vigilante' )
                            : ( '' === (string) $disk_version
                                ? sprintf(
                                    /* translators: %s: version WordPress.org contradicted */
                                    __( 'MANIFEST.sha256 was not adopted as the reference for this installation: WordPress.org distributed something else for version %s, and the version now on disk could not be read.', 'vigilante' ),
                                    (string) $state['refused_version']
                                )
                                : sprintf(
                                    /* translators: 1: version WordPress.org contradicted, 2: version now on disk */
                                    __( 'MANIFEST.sha256 was not adopted as the reference for this installation: WordPress.org distributed something else for version %1$s, and version %2$s, now on disk, could not be confirmed with it.', 'vigilante' ),
                                    (string) $state['refused_version'],
                                    (string) $disk_version
                                ) )
                    );
                } else {
                    // First run with the feature: capture quietly.
                    $this->capture_fingerprint( 'activation' === $context || 'migration' === $context ? $context : 'first_run' );
                    $stored_fp      = (string) $manifest_fp;
                    $stored_version = $disk_version;
                    $this->log(
                        'self_integrity_captured',
                        __( 'Vigilant self-protection: manifest fingerprint captured', 'vigilante' ),
                        array( 'version' => $disk_version ),
                        'info'
                    );
                }
            } elseif ( $manifest_fp !== $stored_fp ) {
                // Same version, different manifest, whatever the context: the
                // upgrader hook also fires for a plugin that was not written (a
                // bulk update that skipped it, an install that failed before
                // copying), so it is not proof that WordPress replaced the files.
                if ( $stored_version === $disk_version ) {
                    // Same version, different manifest: swapped without an update.
                    $findings[] = $this->finding(
                        'manifest_replaced',
                        self::MANIFEST_FILE,
                        'critical',
                        __( 'MANIFEST.sha256 was replaced without a plugin update. An attacker regenerating the manifest to hide file changes would look exactly like this.', 'vigilante' )
                    );
                } else {
                    // Version changed: the WordPress updater, a manual/FTP
                    // update, or an attacker who bumped the Version: header to
                    // dodge the same-version manifest_replaced check above.
                    $wporg_confirms = $wporg_ok && $this->manifest_consistent_with_wporg( $manifest, $wporg );

                    if ( $wporg_ok && ! $wporg_confirms ) {
                        // wp.org HAS checksums for this version and the new
                        // manifest does not match them: tampered distribution.
                        $findings[] = $this->finding(
                            'manifest_replaced',
                            self::MANIFEST_FILE,
                            'critical',
                            __( 'The new MANIFEST.sha256 does not match what WordPress.org distributes for this version.', 'vigilante' )
                        );
                    } elseif ( 'upgrader' === $context || $wporg_confirms ) {
                        // Trusted: either the WordPress updater performed the
                        // update, or wp.org confirms the new manifest. Adopt the
                        // new baseline.
                        $result['rebaselined'] = true;
                    } else {
                        // Version changed AND the new manifest cannot be
                        // confirmed against WordPress.org, outside the WordPress
                        // updater. This is the signature of an attacker who
                        // edited files, regenerated MANIFEST.sha256 and set the
                        // Version: header to a value wp.org will never publish.
                        // The previous fingerprint is kept (no rebaseline) and a
                        // sticky warning is raised until wp.org can confirm the
                        // version or the WordPress updater installs one. A manual
                        // update in the first hours after a release lands here
                        // too, and resolves on its own once wp.org publishes the
                        // checksums.
                        $findings[] = $this->finding(
                            'manifest_unverified',
                            self::MANIFEST_FILE,
                            'warning',
                            __( 'MANIFEST.sha256 changed after a Vigilant version change but could not be verified against WordPress.org. If you did not just update Vigilant, treat this as possible tampering.', 'vigilante' )
                        );
                    }

                    if ( '' !== $stored_version && version_compare( $disk_version, $stored_version, '<' ) ) {
                        $result['downgraded'] = true;
                        $findings[]           = $this->finding(
                            'self_downgraded',
                            basename( VIGILANTE_PLUGIN_BASENAME ),
                            'warning',
                            sprintf(
                                /* translators: 1: previous version, 2: current (older) version */
                                __( 'Vigilant was downgraded from %1$s to %2$s. Older versions may contain publicly known vulnerabilities.', 'vigilante' ),
                                $stored_version,
                                $disk_version
                            )
                        );
                    }
                }
            } elseif ( '' !== $stored_version && $stored_version !== $disk_version ) {
                // Fingerprint matches but the anchored version does not: the
                // state was restored from an old database backup while the
                // files (and their manifest) are current and still anchored.
                // Not an attack signal; resync quietly so the version change
                // detector converges instead of re-firing.
                $this->capture_fingerprint( 'state_resync' );
                $stored_version = $disk_version;
            }
        } elseif ( '' !== $stored_fp ) {
            // A manifest was anchored and now it is gone or unusable. With the
            // same version nothing legitimate removes it, and deleting it is
            // the cheapest way to hide file changes from this check.
            // Only the WordPress updater installing another version (a
            // downgrade to one without a manifest) makes it a warning; anything
            // else, an FTP upload with a new Version: header included, is how
            // file changes would be hidden, and is critical.
            $version_changed = '' !== $stored_version && $stored_version !== $disk_version;
            $severity        = ( $version_changed && 'upgrader' === $context ) ? 'warning' : 'critical';
            if ( $version_changed && version_compare( $disk_version, $stored_version, '<' ) ) {
                $result['downgraded'] = true;
                $findings[]           = $this->finding(
                    'self_downgraded',
                    basename( VIGILANTE_PLUGIN_BASENAME ),
                    'warning',
                    sprintf(
                        /* translators: 1: previous version, 2: current (older) version */
                        __( 'Vigilant was downgraded from %1$s to %2$s. Older versions may contain publicly known vulnerabilities.', 'vigilante' ),
                        $stored_version,
                        $disk_version
                    )
                );
            }
            if ( false === $manifest ) {
                $findings[] = $this->finding(
                    'manifest_invalid',
                    self::MANIFEST_FILE,
                    $severity,
                    __( 'MANIFEST.sha256 was anchored for this installation and is no longer a valid manifest (an unexpected line, an unsafe path, too many lines or a file too large to be one), so it was not used.', 'vigilante' )
                );
            } else {
                $findings[] = $this->finding(
                    'manifest_missing',
                    self::MANIFEST_FILE,
                    $severity,
                    __( 'MANIFEST.sha256 was anchored for this installation and is now missing from the Vigilant folder. Deleting the manifest is how file changes would be hidden from this check.', 'vigilante' )
                );
            }
        }

        // --- Per-file verification -------------------------------------
        $known = null;
        if ( $manifest_ok ) {
            $result['anchors']['manifest'] = true;
            $tree                          = $this->verify_tree( $manifest, $wporg_ok ? $wporg : null );
            $findings                      = array_merge( $findings, $tree['findings'] );
            $result['files_checked']       = $tree['files_checked'];
            $known                         = $manifest;
        } elseif ( $wporg_ok ) {
            if ( '' === $stored_fp ) {
                $findings[] = false === $manifest
                    ? $this->finding(
                        'manifest_invalid',
                        self::MANIFEST_FILE,
                        'warning',
                        __( 'MANIFEST.sha256 is not a valid manifest. Verification degraded to the WordPress.org checksums only.', 'vigilante' )
                    )
                    : $this->finding(
                        'manifest_missing',
                        self::MANIFEST_FILE,
                        'warning',
                        __( 'MANIFEST.sha256 is missing from the Vigilant folder. Verification degraded to the WordPress.org checksums only.', 'vigilante' )
                    );
            }
            $pseudo = array();
            foreach ( $wporg as $file => $hashes ) {
                if ( self::is_excluded_path( $file ) ) {
                    continue;
                }
                $pseudo[ $file ] = $hashes; // Arrays accepted by verify_tree.
            }
            $tree                    = $this->verify_tree( $pseudo, null );
            $findings                = array_merge( $findings, $tree['findings'] );
            $result['files_checked'] = $tree['files_checked'];
            $known                   = $pseudo;
        } elseif ( '' === $stored_fp ) {
            // Never anchored and no anchor available: degraded, informational,
            // never an alarm (an old install with wp.org unreachable must not
            // scream).
            $findings[] = $this->finding(
                'no_anchors',
                self::MANIFEST_FILE,
                'info',
                __( 'Neither MANIFEST.sha256 nor the WordPress.org checksums are available; the self-check cannot verify files right now.', 'vigilante' )
            );
        }

        // --- Extra files ------------------------------------------------
        if ( null !== $known ) {
            $findings = array_merge( $findings, $this->detect_extra_files( $known ) );
        }

        $result['anchors']['wporg']       = $wporg_ok;
        $result['anchors']['fingerprint'] = '' !== $stored_fp;

        // --- Explicit admin ignore list ---------------------------------
        $findings = $this->filter_ignored_findings( $findings );

        // --- Status aggregation ------------------------------------------
        $status = 'ok';
        $worst  = $this->worst_severity( $findings );
        if ( 'critical' === $worst ) {
            $status = 'critical';
        } elseif ( 'warning' === $worst ) {
            $status = 'warning';
        } elseif ( ! $wporg_ok || ! $manifest_ok ) {
            $status = 'degraded';
        }

        // --- Rebaseline A3 ------------------------------------------------
        if ( $result['rebaselined'] ) {
            $this->capture_fingerprint( 'upgrader' === $context ? 'upgrader' : 'version_change' );
            if ( 'upgrader' !== $context ) {
                $this->log(
                    'self_rebaselined',
                    $result['downgraded']
                        ? sprintf(
                            /* translators: %s: plugin version */
                            __( 'Vigilant self-protection: downgrade to %s detected outside the WordPress updater and confirmed by WordPress.org; baseline refreshed.', 'vigilante' ),
                            $disk_version
                        )
                        : sprintf(
                            /* translators: %s: plugin version */
                            __( 'Vigilant self-protection: version change detected outside the WordPress updater (manual/FTP update to %s); baseline refreshed.', 'vigilante' ),
                            $disk_version
                        ),
                    array(
                        'previous_version' => $stored_version,
                        'new_version'      => $disk_version,
                    ),
                    'info'
                );
            }
        }

        // --- Persist ------------------------------------------------------
        $state = $this->get_state(); // Re-read: capture_fingerprint may have written.
        if ( '' !== $refused ) {
            $state['refused_version'] = $refused;
        }
        if ( empty( $state['manifest_hash'] ) ) {
            // Nothing anchored: remember the version seen, or the version
            // change detector would run the whole check on every call.
            $state['version'] = $disk_version;
        }
        $state['last_check']          = time();
        $state['last_context']        = $context;
        $state['last_status']         = $status;
        $state['last_findings']       = $this->cap_findings( $findings );
        $state['last_findings_total'] = count( $findings );
        $state['files_checked']       = $result['files_checked'];
        $state['anchors']             = $result['anchors'];
        if ( 'ok' === $status || 'degraded' === $status ) {
            $state['alerted_fingerprint'] = '';
        }
        $this->save_state( $state );

        // A downgrade is reported by email wherever it is decided. The
        // updater and the version change paths send their own alert; the scan
        // and the daily check used to refresh the baseline in silence when
        // they got there first.
        if ( $result['downgraded'] && ! in_array( $context, array( 'upgrader', 'version_change' ), true ) ) {
            $this->maybe_send_self_alert( $findings, $context );
        }

        // --- Log ------------------------------------------------------------
        if ( 'critical' === $worst || 'warning' === $worst ) {
            $this->log(
                'self_integrity_fail',
                sprintf(
                    /* translators: %d: number of findings */
                    _n(
                        'Vigilant self-protection detected %d integrity finding in its own files',
                        'Vigilant self-protection detected %d integrity findings in its own files',
                        count( $findings ),
                        'vigilante'
                    ),
                    count( $findings )
                ),
                array(
                    'context'  => $context,
                    'findings' => $this->findings_summary( $findings ),
                ),
                $worst
            );
        } elseif ( in_array( $previous_state, array( 'critical', 'warning' ), true ) && in_array( $status, array( 'ok', 'degraded' ), true ) ) {
            $this->log(
                'self_integrity_restored',
                __( 'Vigilant self-protection: integrity restored, all files verify clean again', 'vigilante' ),
                array( 'context' => $context ),
                'info'
            );
        } elseif ( 'scan' !== $context && in_array( $status, array( 'ok', 'degraded' ), true ) ) {
            $this->log(
                'self_integrity_scan',
                sprintf(
                    /* translators: 1: number of files, 2: check context */
                    __( 'Vigilant self-check verified clean (%1$d files, context: %2$s)', 'vigilante' ),
                    $result['files_checked'],
                    $context
                ),
                array( 'context' => $context ),
                'info'
            );
        }

        $result['status']   = $status;
        $result['findings'] = $findings;
        return $result;
    }

    /**
     * Verify the plugin tree against a hash map.
     *
     * @param array      $manifest Map path => sha256 string (or array of accepted strings).
     * @param array|null $wporg    wp.org checksums for cross-decisions, or null.
     * @return array {findings, files_checked}
     */
    private function verify_tree( $manifest, $wporg ) {
        $root      = $this->get_plugin_root();
        $real_root = realpath( $root );
        $findings  = array();
        $checked   = 0;

        foreach ( $manifest as $relative => $expected ) {
            $expected_set = array_map( 'strval', (array) $expected );
            $path         = $root . '/' . $relative;
            $checked++;

            // A distributed file is never a link, and nothing listed may
            // resolve outside the plugin folder (a linked directory on the way).
            $real = realpath( $path );
            if ( is_link( $path ) || ( false !== $real && false !== $real_root && 0 !== strpos( $real, $real_root . DIRECTORY_SEPARATOR ) ) ) {
                $findings[] = $this->finding(
                    'self_symlink',
                    $relative,
                    'critical',
                    __( 'A Vigilant file is a symbolic link or resolves outside the plugin folder. Distributed files are never links.', 'vigilante' )
                );
                continue;
            }

            // No exception for iCloud placeholders: WordPress does not run from
            // iCloud Drive, and skipping a missing file when a ".<name>.icloud"
            // sits next to it let anyone hide a deleted module that way.
            if ( ! is_file( $path ) ) {
                $findings[] = $this->finding(
                    'self_missing',
                    $relative,
                    'critical',
                    __( 'File listed in the Vigilant manifest is missing from disk. A deleted module silently stops protecting the site.', 'vigilante' )
                );
                continue;
            }

            if ( ! is_readable( $path ) ) {
                $findings[] = $this->finding(
                    'self_modified',
                    $relative,
                    'critical',
                    __( 'A Vigilant file cannot be read, so it cannot be verified. Distributed files are readable; check its permissions.', 'vigilante' ),
                    'unreadable'
                );
                continue;
            }

            $actual = hash_file( 'sha256', $path );
            if ( ! in_array( $actual, $expected_set, true ) && self::is_text_path( $relative ) ) {
                // Some hosts and deploy tools rewrite text files (a UTF-8 BOM in
                // front, CRLF line endings) without changing a line of code. The
                // File Integrity scan has compared a normalized copy since 2.9.1,
                // and the self-check does the same, so an intact file is not
                // reported as tampering. A real change still fails both hashes.
                $normalized = self::normalized_hash( $path, $relative );
                if ( null !== $normalized && ( in_array( $normalized, $expected_set, true ) || ( null !== $wporg && isset( $wporg[ $relative ] ) && in_array( $normalized, $wporg[ $relative ], true ) ) ) ) {
                    $actual = $normalized;
                }
            }
            if ( in_array( $actual, $expected_set, true ) ) {
                // Matches the manifest; cross-check the manifest itself against wp.org.
                if ( null !== $wporg && ! isset( $wporg[ $relative ] ) ) {
                    // Listed in the local manifest, and not distributed by
                    // WordPress.org at all for this version: a manifest
                    // regenerated to include an added file looks like this.
                    $findings[] = $this->finding(
                        'distribution_mismatch',
                        $relative,
                        self::is_executable_path( $relative ) ? 'critical' : 'warning',
                        __( 'File is listed in the local manifest, but WordPress.org does not distribute it for this version.', 'vigilante' )
                    );
                } elseif ( null !== $wporg && empty( array_intersect( $expected_set, $wporg[ $relative ] ) ) ) {
                    $findings[] = $this->finding(
                        'distribution_mismatch',
                        $relative,
                        'warning',
                        __( 'File matches the local manifest but not what WordPress.org distributes for this version. Expected for development builds; on a production install this can indicate a tampered distribution.', 'vigilante' )
                    );
                }
                continue;
            }

            if ( null !== $wporg && isset( $wporg[ $relative ] ) && in_array( $actual, $wporg[ $relative ], true ) ) {
                $findings[] = $this->finding(
                    'manifest_stale',
                    $relative,
                    'critical',
                    __( 'File is the original one from WordPress.org but does not match the local manifest: the manifest was replaced or the release was mis-generated.', 'vigilante' )
                );
            } else {
                // Code (PHP family or JavaScript) modified is a backdoor/XSS
                // risk: critical. A modified non-code asset (CSS, images, data)
                // is far more often an optimisation plugin or a host rewriting
                // it in place than an attack, so it is a warning (still logged
                // and emailed) with wording that says so.
                // The data files in includes/ decide what the plugin does
                // (scan-patterns.json is the malware signature base): emptying
                // one blinds a protection as surely as editing its PHP.
                $extension = strtolower( pathinfo( $relative, PATHINFO_EXTENSION ) );
                $is_code   = self::is_executable_path( $relative ) || 'js' === $extension || ( 'json' === $extension && 0 === strpos( $relative, 'includes/' ) );
                if ( $is_code ) {
                    $findings[] = $this->finding(
                        'self_modified',
                        $relative,
                        'critical',
                        __( 'Vigilant code file modified: its content no longer matches the distributed version.', 'vigilante' )
                    );
                } else {
                    $findings[] = $this->finding(
                        'self_modified',
                        $relative,
                        'warning',
                        __( 'A Vigilant asset (not a code file) no longer matches the distributed version. This is often an optimisation plugin or host rewriting it in place; if you did not expect it, verify the file.', 'vigilante' )
                    );
                }
            }
        }

        return array(
            'findings'      => $findings,
            'files_checked' => $checked,
        );
    }

    /**
     * Files, links and folders on disk that are not part of the known set.
     *
     * Harmless extra files stop being listed after MAX_EXTRA_WARNINGS, but a
     * link, a file a web server can be told to run and a folder that cannot
     * be listed are always reported, wherever they sit in the walk. The first
     * version counted everything against one cap of 100, so a hundred
     * harmless files placed where the walk starts hid a PHP file behind them.
     *
     * A folder the check cannot list (no read or no search permission) hides
     * what is inside it, and a file in it can still be run by its name, so it
     * is critical whether the distribution has that folder or not. The walk
     * goes on past it instead of stopping, which is what the first version
     * did, reporting a clean folder.
     *
     * @param array $known Map path => hash (only keys are used).
     * @return array Findings.
     */
    private function detect_extra_files( $known ) {
        $root     = $this->get_plugin_root();
        $findings = array();
        $warnings = 0;
        $entries  = 0;

        // Folders the distribution has, from the known paths.
        $known_dirs = array();
        foreach ( array_keys( $known ) as $known_path ) {
            $dir = dirname( (string) $known_path );
            while ( '.' !== $dir && '' !== $dir && ! isset( $known_dirs[ $dir ] ) ) {
                $known_dirs[ $dir ] = true;
                $dir                = dirname( $dir );
            }
        }

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator( $root, RecursiveDirectoryIterator::SKIP_DOTS ),
                RecursiveIteratorIterator::SELF_FIRST,
                RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ( $iterator as $file ) {
                $entries++;
                if ( $entries > self::MAX_TREE_ENTRIES ) {
                    $findings[] = $this->finding(
                        'self_extra',
                        '',
                        'critical',
                        __( 'The Vigilant folder holds far more files than the distribution, so the check stopped walking it. A distributed copy holds fewer than a hundred files.', 'vigilante' ),
                        'walk'
                    );
                    break;
                }

                $relative = str_replace( '\\', '/', substr( $file->getPathname(), strlen( $root ) + 1 ) );
                $is_link  = $file->isLink();

                if ( ! $is_link && $file->isDir() ) {
                    // On Windows is_executable() of a folder is always false (PHP asks
                    // whether it is a program), so only readability counts there.
                    if ( ! $file->isReadable() || ( '\\' !== DIRECTORY_SEPARATOR && ! $file->isExecutable() ) ) {
                        $findings[] = $this->finding(
                            'self_extra',
                            $relative . '/',
                            'critical',
                            isset( $known_dirs[ $relative ] )
                                ? __( 'A Vigilant folder cannot be listed, so files added to it cannot be detected, and a web server can still run them by name. Distributed folders are readable: check its permissions.', 'vigilante' )
                                : __( 'Folder inside Vigilant that is not part of the distribution and cannot be listed. Files hidden in it cannot be checked, and a web server can still run them by name.', 'vigilante' ),
                            'dir'
                        );
                    }
                    continue;
                }
                if ( ! $is_link && ! $file->isFile() ) {
                    continue;
                }
                if ( isset( $known[ $relative ] ) ) {
                    continue;
                }
                $executable = self::is_executable_path( $relative );
                // Excluded names are skipped, but never a link or an executable
                // file, whatever name it hides behind.
                if ( self::is_excluded_path( $relative ) && ! $is_link && ! $executable ) {
                    continue;
                }

                if ( $is_link ) {
                    $findings[] = $this->finding(
                        'self_extra',
                        $relative,
                        'critical',
                        __( 'Symbolic link inside the Vigilant folder that is not part of the distribution.', 'vigilante' ),
                        'link'
                    );
                    continue;
                }
                if ( $executable ) {
                    $findings[] = $this->finding(
                        'self_extra',
                        $relative,
                        'critical',
                        __( 'Executable file inside the Vigilant folder that is not part of the distribution. Injected files here run with the plugin\'s own credibility.', 'vigilante' ),
                        'exec'
                    );
                    continue;
                }
                if ( $warnings >= self::MAX_EXTRA_WARNINGS ) {
                    continue;
                }
                $warnings++;
                $findings[] = $this->finding(
                    'self_extra',
                    $relative,
                    'warning',
                    __( 'File inside the Vigilant folder that is not part of the distribution.', 'vigilante' )
                );
            }
        } catch ( Exception $e ) {
            // The folder itself could not be opened: say so instead of
            // reporting a clean folder.
            unset( $e );
            $findings[] = $this->finding(
                'self_extra',
                '',
                'critical',
                __( 'The Vigilant folder could not be walked, so files added to it cannot be detected.', 'vigilante' ),
                'walk'
            );
        }

        return $findings;
    }

    /**
     * Whether the local manifest describes the same tree wp.org distributes.
     *
     * @param array $manifest Map path => sha256.
     * @param array $wporg    Map path => array of sha256.
     * @return bool
     */
    private function manifest_consistent_with_wporg( $manifest, $wporg ) {
        foreach ( $manifest as $file => $hash ) {
            if ( ! isset( $wporg[ $file ] ) || ! in_array( (string) $hash, $wporg[ $file ], true ) ) {
                return false;
            }
        }
        foreach ( $wporg as $file => $hashes ) {
            if ( self::is_excluded_path( $file ) ) {
                continue;
            }
            if ( ! isset( $manifest[ $file ] ) ) {
                return false;
            }
        }
        return true;
    }

    /**
     * Drop findings the admin explicitly ignored via the File Integrity
     * ignore workflow. Only per-file findings can be ignored; anchor-level
     * findings (manifest_replaced, manifest_missing, no_anchors...) always
     * surface.
     *
     * @param array $findings Findings.
     * @return array
     */
    private function filter_ignored_findings( $findings ) {
        $ignored = get_option( 'vigilante_ignored_files', array() );
        if ( empty( $ignored ) || ! is_array( $ignored ) ) {
            return $findings;
        }
        $per_file       = array( 'self_modified', 'self_missing', 'self_extra', 'self_symlink', 'manifest_stale', 'distribution_mismatch' );
        $plugin_prefix  = 'plugins/' . self::plugin_folder() . '/';
        $abspath_prefix = str_replace( ABSPATH, '', VIGILANTE_PLUGIN_DIR );
        return array_values(
            array_filter(
                $findings,
                function ( $finding ) use ( $ignored, $per_file, $plugin_prefix, $abspath_prefix ) {
                    if ( ! in_array( $finding['code'], $per_file, true ) ) {
                        return true;
                    }
                    // The walk findings (a folder that cannot be listed, the whole
                    // folder that could not be walked, too many entries) are not
                    // about one file: no entry of the list hides them.
                    $file = (string) $finding['file'];
                    if ( '' === $file || '/' === substr( $file, -1 ) ) {
                        return true;
                    }
                    // Both path conventions used by the File Integrity UI.
                    return ! in_array( $plugin_prefix . $finding['file'], $ignored, true ) && ! in_array( $abspath_prefix . $finding['file'], $ignored, true );
                }
            )
        );
    }

    // -------------------------------------------------------------------
    // Update paths (#51)
    // -------------------------------------------------------------------

    /**
     * Immediate verification after the WordPress upgrader updated Vigilant.
     * Called (already filtered to this plugin) from
     * vigilante_on_upgrader_process_complete() in vigilante.php. The OLD code
     * runs this handler while the NEW files are on disk, hence everything is
     * read from disk, never from in-memory constants.
     *
     * @param bool $written Whether WordPress wrote the plugin folder in this
     *                      request (see vigilante_mark_upgrader_wrote()).
     */
    public function handle_upgrader( $written = true ) {
        if ( ! $this->is_enabled() ) {
            return;
        }

        $this->flush_self_transients();
        // Only when WordPress wrote the plugin folder in this request is the
        // updater proof of anything: a bulk update fires the hook for plugins it
        // skipped too. Otherwise it is a version change like any other.
        $result = $this->run_check( $written ? 'upgrader' : 'version_change' );

        $worst = $this->worst_severity( $result['findings'] );
        $this->log(
            'self_verified_post_update',
            sprintf(
                /* translators: 1: plugin version, 2: verification status */
                __( 'Vigilant verified its own files right after updating to %1$s: %2$s', 'vigilante' ),
                $this->get_disk_version(),
                $result['status']
            ),
            array(
                'status'   => $result['status'],
                'findings' => $this->findings_summary( $result['findings'] ),
            ),
            'critical' === $worst ? 'critical' : 'info'
        );

        if ( 'critical' === $worst || $result['downgraded'] ) {
            $this->maybe_send_self_alert( $result['findings'], 'upgrader' );
        }
    }

    /**
     * Version change detection from admin_init (priority 20).
     *
     * admin_init also fires on admin-post.php before anybody is identified,
     * and for logged-in users without any capability, so this only runs for
     * a user who can manage options: the check hashes the tree, writes the
     * state and can send an email, none of which an anonymous request may
     * trigger. The same guard as Vigilante_Admin::run_migrations().
     */
    public function maybe_detect_version_change() {
        if ( wp_doing_ajax() || wp_doing_cron() ) {
            return;
        }
        if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) {
            return;
        }
        $this->detect_version_change();
    }

    /**
     * FTP/manual update and downgrade detection: the anchored version in the
     * state differs from the running code. Also called from the daily
     * maintenance cron. Throttled while a change stays unresolved.
     */
    public function detect_version_change() {
        if ( ! $this->is_enabled() ) {
            return;
        }

        $state          = $this->get_state();
        $stored_version = isset( $state['version'] ) ? (string) $state['version'] : '';
        // The version on disk, not the constant in memory: run_check() stores
        // the one on disk, and with an opcode cache still serving the old files
        // the two differ, so comparing with the constant never converged.
        $running        = $this->get_disk_version();

        if ( '' !== $stored_version && $running === $stored_version ) {
            return;
        }

        if ( get_transient( self::VERSION_CHECK_TRANSIENT ) ) {
            return;
        }
        set_transient( self::VERSION_CHECK_TRANSIENT, 1, self::VERSION_CHECK_THROTTLE );

        if ( '' === $stored_version ) {
            // Feature just arrived (fresh install handled by the activator,
            // updates by the 3.0.0 migration); this is the belt-and-braces
            // path. run_check() captures quietly.
            $this->run_check( 'version_change' );
            return;
        }

        // Flush the cached checksums once per detected version, not on every
        // throttled retry, so a version wp.org has not published yet is asked
        // for again only when its not_found cache expires.
        if ( ! isset( $state['pending_version'] ) || $running !== $state['pending_version'] ) {
            $this->flush_self_transients();
            $state['pending_version'] = $running;
            $this->save_state( $state );
        }

        $result = $this->run_check( 'version_change' );

        // Alert on a confirmed tamper (critical), a downgrade, or an
        // unverifiable manifest change (the forged-version bypass signature),
        // so a version change that cannot be vouched for never passes silently.
        $has_unverified = false;
        foreach ( $result['findings'] as $finding ) {
            if ( 'manifest_unverified' === $finding['code'] ) {
                $has_unverified = true;
                break;
            }
        }
        if ( 'critical' === $this->worst_severity( $result['findings'] ) || $result['downgraded'] || $has_unverified ) {
            $this->maybe_send_self_alert( $result['findings'], 'version_change' );
        }
    }

    // -------------------------------------------------------------------
    // Cron watchdog (#52)
    // -------------------------------------------------------------------

    /**
     * Throttled watchdog entry point (admin_init priority 30), for a user who
     * can manage options only (see maybe_detect_version_change()). The second
     * entry point is daily_maintenance() in vigilante.php, for sites where
     * nobody visits wp-admin.
     */
    public function maybe_run_watchdog() {
        if ( wp_doing_ajax() || wp_doing_cron() ) {
            return;
        }
        if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) {
            return;
        }
        if ( ! $this->is_enabled() || get_transient( self::WATCHDOG_TRANSIENT ) ) {
            return;
        }
        set_transient( self::WATCHDOG_TRANSIENT, 1, 6 * HOUR_IN_SECONDS );
        $this->run_watchdog();
    }

    /**
     * Verify that Vigilant's own cron events are still scheduled and restore
     * any that were unscheduled (a malicious wp_clear_scheduled_hook, or an
     * overzealous cleanup plugin, silences the plugin forever otherwise).
     *
     * A hook is only reported once the watchdog has seen it scheduled: the
     * first pass on a site, and a hook whose setting was just switched on,
     * schedule what is missing quietly. After that, a first disappearance is
     * restored with a warning; the SAME hook disappearing again within 30
     * days means something is actively clearing it: critical and a standalone
     * alert. A hook whose setting is off is forgotten, so switching it back on
     * is not reported either.
     *
     * On a network it only watches the site that owns the installation's
     * shared files: the activation schedules these events once, so on the
     * other sites "not scheduled" does not mean "removed". The events of the
     * other sites are left for the multisite release.
     *
     * Runs only while the plugin is active, so legitimate deactivation (which
     * clears these events in Vigilante_Deactivator) makes no noise, and no
     * new cron of its own is ever registered. The password-expiry reminder
     * (vigilante_password_expiry_reminder) is deliberately NOT in this table:
     * User Security schedules it according to its own toggle.
     *
     * As a fallback for sites with the File Integrity module (and therefore
     * the scan) disabled, a daily self-check also runs from here.
     */
    public function run_watchdog() {
        $fi       = $this->settings ? $this->settings->get_section( 'file_integrity' ) : array();
        $modules  = $this->settings ? $this->settings->get_section( 'modules' ) : array();
        $analyzer = $this->settings ? $this->settings->get_section( 'security_analyzer' ) : array();

        if ( Vigilante_Settings::owns_shared_files() ) {
            // hook => array( schedule, first-run offset, required? ).
            // The weekly analyzer scan is required unless it was switched off
            // explicitly: its own toggle unschedules it on purpose, and an
            // unset value means on (Vigilante_Security_Analyzer reads it the same way).
            $expected = array(
                'vigilante_daily_maintenance'    => array( 'daily', 0, true ),
                'vigilante_hourly_checks'        => array( 'hourly', 0, true ),
                'vigilante_analyzer_weekly_scan' => array( 'weekly', DAY_IN_SECONDS, ! isset( $analyzer['weekly_scan_enabled'] ) || ! empty( $analyzer['weekly_scan_enabled'] ) ),
                'vigilante_plugin_status_check'  => array( 'daily', HOUR_IN_SECONDS, ! empty( $fi['check_closed_plugins'] ) ),
                'vigilante_file_integrity_scan'  => array(
                    isset( $fi['scan_frequency'] ) ? $fi['scan_frequency'] : 'daily',
                    0,
                    ! empty( $modules['file_integrity'] ) && ! empty( $fi['auto_scan'] ),
                ),
            );

            // A recurrence nobody registered (an imported or edited setting)
            // cannot be scheduled: use daily instead of failing on every pass.
            $schedules = wp_get_schedules();
            foreach ( $expected as $hook => $spec ) {
                if ( ! isset( $schedules[ $spec[0] ] ) ) {
                    $expected[ $hook ][0] = 'daily';
                }
            }

            $state      = $this->get_state();
            $watchdog   = ( isset( $state['watchdog'] ) && is_array( $state['watchdog'] ) ) ? $state['watchdog'] : array();
            $first_pass = ! isset( $state['watchdog_seen'] ) || ! is_array( $state['watchdog_seen'] );
            $seen       = $first_pass ? array() : $state['watchdog_seen'];
            $baselined  = array();
            $restored   = array();
            $repeated   = array();
            $now        = time();

            foreach ( $expected as $hook => $spec ) {
                list( $schedule, $offset, $required ) = $spec;

                if ( ! $required ) {
                    unset( $seen[ $hook ], $watchdog[ $hook ] );
                    continue;
                }
                if ( wp_next_scheduled( $hook ) ) {
                    $seen[ $hook ] = true;
                    continue;
                }

                $scheduled = wp_schedule_event( $now + $offset, $schedule, $hook );
                if ( false === $scheduled || is_wp_error( $scheduled ) ) {
                    // Not scheduled, so it cannot be counted as restored: the
                    // next pass tries again without reporting a removal.
                    continue;
                }

                if ( empty( $seen[ $hook ] ) ) {
                    $seen[ $hook ] = true;
                    $baselined[]   = $hook;
                    continue;
                }

                $previous = ( isset( $watchdog[ $hook ] ) && is_array( $watchdog[ $hook ] ) ) ? $watchdog[ $hook ] : array();
                $recent   = isset( $previous['last'] ) && ( $now - (int) $previous['last'] ) < self::WATCHDOG_REPEAT_WINDOW;
                $times    = $recent && isset( $previous['count'] ) ? (int) $previous['count'] + 1 : 1;

                $watchdog[ $hook ] = array(
                    'count' => $times,
                    'last'  => $now,
                );
                $restored[] = $hook;
                if ( $times >= 2 ) {
                    $repeated[] = $hook;
                }
            }

            $state['watchdog']      = $watchdog;
            $state['watchdog_seen'] = $seen;
            $this->save_state( $state );

            if ( ! empty( $baselined ) ) {
                $this->log(
                    'cron_scheduled',
                    sprintf(
                        /* translators: %s: comma-separated list of cron hooks */
                        __( 'Vigilant watchdog scheduled cron events that were not scheduled yet: %s', 'vigilante' ),
                        implode( ', ', $baselined )
                    ),
                    array( 'scheduled' => $baselined ),
                    'info'
                );
            }

            if ( ! empty( $restored ) ) {
                $this->log(
                    'cron_restored',
                    sprintf(
                        /* translators: %s: comma-separated list of cron hooks */
                        __( 'Vigilant watchdog re-scheduled missing cron events: %s', 'vigilante' ),
                        implode( ', ', $restored )
                    ),
                    array(
                        'restored'   => $restored,
                        'recurrence' => $watchdog,
                    ),
                    empty( $repeated ) ? 'warning' : 'critical'
                );
            }

            if ( ! empty( $repeated ) ) {
                $findings = array();
                foreach ( $repeated as $hook ) {
                    $findings[] = $this->finding(
                        'cron_cleared_repeatedly',
                        $hook,
                        'critical',
                        sprintf(
                            /* translators: 1: cron hook name, 2: number of restorations */
                            __( 'The cron event "%1$s" keeps being unscheduled (restored %2$d times in 30 days). Something on this site is actively clearing Vigilant\'s scheduled tasks.', 'vigilante' ),
                            $hook,
                            (int) $watchdog[ $hook ]['count']
                        )
                    );
                }
                $this->maybe_send_self_alert( $findings, 'watchdog' );
            }
        }

        // Fallback file self-check whenever nothing checked the files in the
        // last day: the File Integrity module switched off, scheduled scans
        // switched off, or a weekly schedule. Asking only for the module left a
        // site with scheduled scans switched off with no periodic check at all.
        $state      = $this->get_state();
        $last_check = isset( $state['last_check'] ) ? (int) $state['last_check'] : 0;
        if ( time() - $last_check > DAY_IN_SECONDS ) {
            $result = $this->run_check( 'watchdog' );
            if ( 'critical' === $this->worst_severity( $result['findings'] ) ) {
                $this->maybe_send_self_alert( $result['findings'], 'watchdog' );
            }
        }
    }

    // -------------------------------------------------------------------
    // Alerts and integration surface
    // -------------------------------------------------------------------

    /**
     * Standalone alert for the upgrader, version change and watchdog paths.
     *
     * Deliberately NOT gated by the File Integrity instant_alert toggle
     * (unlike Vigilante_Plugin_Status): a tamper of the guardian itself is
     * the product's maximum alarm. There is no setting that silences it; only
     * the filter of is_on(), which SECURITY.md documents. Findings from a
     * File Integrity scan go in the scan email instead, which follows its
     * notification setting.
     *
     * Sent only from the site that owns the installation's shared files: the
     * plugin files are the same for every site and every network of an
     * installation, so one email. Deduped by a fingerprint of the finding
     * set; cleared when back to ok.
     *
     * @param array  $findings Findings to report.
     * @param string $context  Alert context (upgrader|version_change|watchdog).
     */
    public function maybe_send_self_alert( $findings, $context ) {
        if ( empty( $findings ) ) {
            return;
        }

        if ( ! Vigilante_Settings::owns_shared_files() ) {
            return;
        }
        $summary     = $this->findings_summary( $findings );
        $fingerprint = md5( wp_json_encode( $summary ) );
        $state       = $this->get_state();
        if ( isset( $state['alerted_fingerprint'] ) && $fingerprint === $state['alerted_fingerprint'] ) {
            return;
        }

        if ( ! class_exists( 'Vigilante_Email_Template' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-email-template.php';
        }
        $recipients = Vigilante_Email_Template::get_admin_recipients();
        // On a network the notification recipients are settings of the main
        // site, which its administrator can change without network rights, so
        // the network administration email is added to every one of these
        // alerts. One send, one fingerprint: the set of findings is what is
        // deduped, for the site addresses and for the network one alike.
        if ( is_multisite() ) {
            $network_email = get_site_option( 'admin_email' );
            if ( is_email( $network_email ) ) {
                $recipients[] = $network_email;
            }
            $recipients = array_values( array_unique( $recipients ) );
        }
        if ( empty( $recipients ) ) {
            return;
        }

        $worst     = $this->worst_severity( $findings );
        $site_name = get_bloginfo( 'name' );

        if ( 'critical' === $worst ) {
            $subject = sprintf(
                /* translators: %s: Site name */
                __( '[%s] CRITICAL: Vigilant plugin files were modified', 'vigilante' ),
                $site_name
            );
            $title = __( 'Vigilant self-protection alert', 'vigilante' );
            $intro = __( 'Vigilant verified its own files and they no longer match the distributed version. Treat this as a possible compromise of the site: an attacker tampering with the security plugin is trying to blind it.', 'vigilante' );
        } else {
            $subject = sprintf(
                /* translators: %s: Site name */
                __( '[%s] Vigilant self-protection warning', 'vigilante' ),
                $site_name
            );
            $title = __( 'Vigilant self-protection warning', 'vigilante' );
            $intro = __( 'Vigilant detected a change in its own installation that deserves your attention.', 'vigilante' );
        }

        $body  = Vigilante_Email_Template::p( $intro );
        $body .= self::build_self_email_section( $findings );
        $body .= Vigilante_Email_Template::p(
            __( 'How to verify by yourself: run a scan from File Integrity, or check the folder over SSH with "php bin/verify-manifest.php" or "sha256sum -c MANIFEST.sha256". Full instructions live in the SECURITY.md file distributed with the plugin.', 'vigilante' )
        );
        $body .= Vigilante_Email_Template::button(
            admin_url( 'admin.php?page=vigilante&tab=file-integrity#vigilante-section-fi-last-scan' ),
            __( 'Review in Vigilant', 'vigilante' )
        );
        $body .= Vigilante_Email_Template::small(
            sprintf(
                /* translators: %s: where the check ran (upgrader, version_change or watchdog) */
                __( 'This alert is part of Vigilant self-protection and does not depend on the instant alert setting. Context: %s', 'vigilante' ),
                $context
            )
        );

        $delivered = Vigilante_Email_Template::send( $recipients, $subject, $title, $body, true );
        if ( ! $delivered && 1 === count( (array) $recipients ) ) {
            // One address, so false means that address did not get it: nothing
            // is marked, and the next check takes the alert to it again. With
            // several recipients false is not proof of anything (PHPMailer
            // returns it when one of them is refused and the others were sent),
            // so those count as sent, or the alert would be repeated to
            // everybody who did get it.
            return;
        }

        $state['alerted_fingerprint'] = $fingerprint;
        $this->save_state( $state );
    }

    /**
     * Red email sub-section for self findings, mirroring the closed-plugins
     * section style in the File Integrity digest.
     *
     * @param array $findings Findings.
     * @return string HTML.
     */
    public static function build_self_email_section( $findings ) {
        if ( empty( $findings ) ) {
            return '';
        }

        $html  = '<div style="background:#fef1f1;border-left:4px solid #d63638;padding:12px 16px;margin:16px 0;">';
        $html .= '<h2 style="margin:0 0 8px;font-size:16px;color:#d63638;">' . esc_html__( 'Vigilant self-protection', 'vigilante' ) . '</h2>';
        $html .= '<p style="margin:0 0 10px;color:#3c434a;">' . esc_html__( 'Findings about Vigilant\'s own files. If you did not modify them yourself, treat this as a possible compromise.', 'vigilante' ) . '</p>';
        $html .= '<table style="border-collapse:collapse;width:100%;font-size:13px;">';
        $html .= '<tr><th style="text-align:left;padding:4px 8px;border-bottom:1px solid #dcdcde;">' . esc_html__( 'File', 'vigilante' ) . '</th>'
            . '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #dcdcde;">' . esc_html__( 'Finding', 'vigilante' ) . '</th>'
            . '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #dcdcde;">' . esc_html__( 'Severity', 'vigilante' ) . '</th></tr>';

        foreach ( array_slice( $findings, 0, self::MAX_STORED_FINDINGS ) as $finding ) {
            $html .= '<tr>'
                . '<td style="padding:4px 8px;border-bottom:1px solid #f0f0f1;"><code>' . esc_html( $finding['file'] ) . '</code></td>'
                . '<td style="padding:4px 8px;border-bottom:1px solid #f0f0f1;">' . esc_html( self::finding_label( $finding['code'] ) ) . '</td>'
                . '<td style="padding:4px 8px;border-bottom:1px solid #f0f0f1;">' . esc_html( $finding['severity'] ) . '</td>'
                . '</tr>';
        }

        $html .= '</table>';

        /*
         * The same catalogue the screens use: an email that reports tampering
         * in the security plugin and leaves the reader with no next step is
         * half a tool. One block per kind of finding, worst first, up to three.
         */
        $seen  = array();
        $shown = 0;
        foreach ( $findings as $finding ) {
            $guidance = Vigilante_Self_Integrity_Guidance::for_finding( $finding );
            if ( isset( $seen[ $guidance['key'] ] ) || $shown >= 3 ) {
                continue;
            }
            $seen[ $guidance['key'] ] = true;
            ++$shown;

            $html .= '<p style="margin:12px 0 0;color:#3c434a;"><strong>' . esc_html( $guidance['title'] ) . '.</strong> '
                . esc_html( $guidance['meaning'] ) . '</p>';
            if ( ! empty( $guidance['steps'] ) ) {
                $html .= '<p style="margin:6px 0 0;color:#3c434a;"><strong>' . esc_html__( 'What to do:', 'vigilante' ) . '</strong></p>'
                    . '<ol style="margin:4px 0 0;padding-left:20px;color:#3c434a;">';
                foreach ( $guidance['steps'] as $step ) {
                    $html .= '<li style="margin-bottom:4px;">' . esc_html( $step ) . '</li>';
                }
                $html .= '</ol>';
            }
        }

        $html .= '<p style="margin:12px 0 0;"><a href="' . esc_url( admin_url( 'admin.php?page=vigilante&tab=file-integrity#vigilante-section-fi-self' ) ) . '">'
            . esc_html__( 'Open File Integrity in your site', 'vigilante' ) . '</a></p>';
        $html .= '</div>';
        return $html;
    }

    /**
     * State to show on a screen of this site.
     *
     * The files belong to the whole network but the state option is per site,
     * so the most recent of the two checks that can see those files (this site
     * and the main site of the main network) is the one that describes them.
     * Without this, the main site can report tampering while a subsite keeps
     * showing the clean result it wrote days ago.
     *
     * @return array
     */
    public static function display_state() {
        $state = get_option( self::STATE_OPTION, array() );
        $state = is_array( $state ) ? $state : array();
        if ( ! is_multisite() ) {
            return $state;
        }
        $main_id = (int) get_main_site_id( get_main_network_id() );
        if ( (int) get_current_blog_id() === $main_id ) {
            return $state;
        }
        $main  = get_blog_option( $main_id, self::STATE_OPTION, array() );
        $main  = is_array( $main ) ? $main : array();
        $here  = isset( $state['last_check'] ) ? (int) $state['last_check'] : 0;
        $there = isset( $main['last_check'] ) ? (int) $main['last_check'] : 0;
        return ( $there > $here ) ? $main : $state;
    }

    /**
     * Cron events the watchdog had to schedule again more than once inside its
     * window. They are logged and emailed when they happen, but they are not
     * part of last_findings, so the screens read them from the watchdog state.
     *
     * @param array $state State.
     * @return array Findings, in the same shape as last_findings.
     */
    public static function watchdog_findings( $state ) {
        $findings = array();
        $watchdog = ( isset( $state['watchdog'] ) && is_array( $state['watchdog'] ) ) ? $state['watchdog'] : array();
        foreach ( $watchdog as $hook => $entry ) {
            if ( ! is_array( $entry ) ) {
                continue;
            }
            $count = isset( $entry['count'] ) ? (int) $entry['count'] : 0;
            $last  = isset( $entry['last'] ) ? (int) $entry['last'] : 0;
            if ( $count < 2 || ( time() - $last ) >= self::WATCHDOG_REPEAT_WINDOW ) {
                continue;
            }
            $findings[] = array(
                'code'     => 'cron_cleared_repeatedly',
                'file'     => (string) $hook,
                'severity' => 'critical',
                'message'  => '',
            );
        }
        return $findings;
    }

    /**
     * Findings of a state (stored plus watchdog), or none when the check is off.
     *
     * @param array $state   State.
     * @param bool  $enabled Whether the self-check runs (see is_on()).
     * @return array
     */
    public static function state_findings( $state, $enabled = true ) {
        $findings = array();

        /*
         * Being switched off is a finding, and a critical one. It takes code on
         * the site to do it, which is either an administrator who decided it or
         * something that does not want to be checked; either way the screens say
         * so, with the files that hook the filter, instead of a grey line.
         */
        if ( ! $enabled ) {
            $ficheros = self::disabled_by();
            if ( empty( $ficheros ) ) {
                $ficheros = array( '' );
            }
            foreach ( $ficheros as $fichero ) {
                $findings[] = array(
                    'code'     => 'self_disabled',
                    'file'     => $fichero,
                    'severity' => 'critical',
                    'message'  => '',
                );
            }
            return $findings;
        }

        // Hooks that somebody removed in a request: same tier.
        if ( ! empty( $state['hooks_removed']['methods'] ) && is_array( $state['hooks_removed']['methods'] ) ) {
            foreach ( $state['hooks_removed']['methods'] as $metodo ) {
                $findings[] = array(
                    'code'     => 'self_hooks_removed',
                    'file'     => (string) $metodo,
                    'severity' => 'critical',
                    'message'  => '',
                );
            }
        }

        $stored = ( isset( $state['last_findings'] ) && is_array( $state['last_findings'] ) ) ? $state['last_findings'] : array();

        // A result older than STALE_AFTER is not a result: say so instead of
        // repeating the green of the last check that did run.
        if ( ! empty( $state['last_check'] ) && ( time() - (int) $state['last_check'] ) > self::STALE_AFTER ) {
            $findings[] = array(
                'code'     => 'self_stale',
                'file'     => '',
                'severity' => 'warning',
                'message'  => '',
            );
        }

        return array_merge( $findings, $stored, self::watchdog_findings( $state ) );
    }

    /**
     * Tone of the state: what colours the File Integrity box, the Security
     * Check result, the menu counter and the notices. One function, so the four
     * never disagree.
     *
     * @param array $state   State.
     * @param bool  $enabled Whether the self-check runs (see is_on()).
     * @return string critical|warning|info|ok|off|none
     */
    public static function tone( $state, $enabled = true ) {
        if ( ! $enabled ) {
            // Switched off by code is an alarm, not a neutral state: see
            // state_findings().
            return 'off';
        }
        if ( ! empty( $state['hooks_removed']['methods'] ) ) {
            return 'critical';
        }
        if ( empty( $state['last_check'] ) ) {
            return 'none';
        }
        $findings = self::state_findings( $state, true );
        $worst    = 'none';
        foreach ( $findings as $finding ) {
            $severity = isset( $finding['severity'] ) ? (string) $finding['severity'] : '';
            if ( 'critical' === $severity ) {
                $worst = 'critical';
                break;
            }
            if ( 'warning' === $severity ) {
                $worst = 'warning';
            }
        }
        $status = isset( $state['last_status'] ) ? (string) $state['last_status'] : '';
        if ( 'critical' === $worst || 'critical' === $status ) {
            return 'critical';
        }
        $files = isset( $state['files_checked'] ) ? (int) $state['files_checked'] : 0;
        if ( 'warning' === $worst || 'warning' === $status || $files < 1 ) {
            return 'warning';
        }
        $anchors = ( isset( $state['anchors'] ) && is_array( $state['anchors'] ) ) ? $state['anchors'] : array();
        return ( count( array_filter( $anchors ) ) >= 3 ) ? 'ok' : 'info';
    }

    /**
     * Says out loud, once a day, that the self-check is switched off.
     *
     * Runs from the daily maintenance, which is not gated by is_on(): with the
     * check off nothing else would write a line, and an installation that
     * stopped checking itself in silence is exactly what this release is about.
     */
    public function audit_off_state() {
        if ( self::is_on() ) {
            return;
        }
        $state   = $this->get_state();
        $alerted = isset( $state['off_alerted'] ) ? (int) $state['off_alerted'] : 0;
        if ( ( time() - $alerted ) < self::OFF_ALARM_WINDOW ) {
            return;
        }
        $state['off_alerted'] = time();
        $this->save_state( $state );

        $ficheros = self::disabled_by();
        $this->maybe_send_self_alert(
            array(
                $this->finding(
                    'self_disabled',
                    $ficheros ? implode( ', ', $ficheros ) : '',
                    'critical',
                    __( 'Vigilant self-protection is switched off by code on this site.', 'vigilante' )
                ),
            ),
            'disabled'
        );
        $this->log(
            'self_disabled',
            $ficheros
                ? sprintf(
                    /* translators: %s: comma-separated list of files */
                    __( 'Vigilant self-protection is switched off by code in: %s', 'vigilante' ),
                    implode( ', ', $ficheros )
                )
                : __( 'Vigilant self-protection is switched off by code on this site', 'vigilante' ),
            array( 'files' => $ficheros ),
            'critical'
        );
    }

    /**
     * Human label for a finding code.
     *
     * @param string $code Finding code.
     * @return string
     */
    public static function finding_label( $code ) {
        $labels = array(
            'self_modified'           => __( 'Modified file', 'vigilante' ),
            'self_missing'            => __( 'Missing file', 'vigilante' ),
            'self_extra'              => __( 'Extra file', 'vigilante' ),
            'self_symlink'            => __( 'Symbolic link', 'vigilante' ),
            'manifest_stale'          => __( 'Manifest replaced (file is original)', 'vigilante' ),
            'manifest_replaced'       => __( 'Manifest replaced', 'vigilante' ),
            'distribution_mismatch'   => __( 'Differs from wp.org distribution', 'vigilante' ),
            'self_downgraded'         => __( 'Version downgraded', 'vigilante' ),
            'manifest_missing'        => __( 'Manifest missing', 'vigilante' ),
            'manifest_invalid'        => __( 'Manifest not valid', 'vigilante' ),
            'manifest_unverified'     => __( 'Manifest changed, unverifiable against wp.org', 'vigilante' ),
            'no_anchors'              => __( 'No verification anchors available', 'vigilante' ),
            'cron_cleared_repeatedly' => __( 'Cron event repeatedly cleared', 'vigilante' ),
            'self_disabled'           => __( 'Self-protection switched off by code', 'vigilante' ),
            'self_hooks_removed'      => __( 'Self-protection hooks removed', 'vigilante' ),
            'self_stale'              => __( 'Not checked recently', 'vigilante' ),
        );
        return isset( $labels[ $code ] ) ? $labels[ $code ] : $code;
    }

    // -------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------

    /**
     * Build a finding entry.
     *
     * @param string $code     Finding code (matrix row).
     * @param string $file     Path relative to the plugin root (or hook name).
     * @param string $severity info|warning|critical.
     * @param string $message  Human explanation.
     * @param string $variant  Optional variant of the same code, so the guidance
     *                         catalogue can tell apart cases that share it (an
     *                         unreadable file from a modified one, an injected
     *                         executable from a stray log file). Stored only when
     *                         set, and never part of the dedupe fingerprint.
     * @return array
     */
    private function finding( $code, $file, $severity, $message, $variant = '' ) {
        $finding = array(
            'code'     => $code,
            'file'     => $file,
            'severity' => $severity,
            'message'  => $message,
        );
        if ( '' !== $variant ) {
            $finding['variant'] = $variant;
        }
        return $finding;
    }

    /**
     * Worst severity present in a finding set.
     *
     * @param array $findings Findings.
     * @return string critical|warning|info|none
     */
    private function worst_severity( $findings ) {
        $worst = 'none';
        foreach ( $findings as $finding ) {
            if ( 'critical' === $finding['severity'] ) {
                return 'critical';
            }
            if ( 'warning' === $finding['severity'] ) {
                $worst = 'warning';
            } elseif ( 'info' === $finding['severity'] && 'none' === $worst ) {
                $worst = 'info';
            }
        }
        return $worst;
    }

    /**
     * Findings sorted worst first and cut to MAX_STORED_FINDINGS, so a
     * manifest crafted with thousands of entries cannot bloat the state.
     *
     * @param array $findings Findings.
     * @return array
     */
    private function cap_findings( $findings ) {
        if ( count( $findings ) <= self::MAX_STORED_FINDINGS ) {
            return $findings;
        }
        $rank = array(
            'critical' => 0,
            'warning'  => 1,
            'info'     => 2,
        );
        $keyed = array();
        foreach ( array_values( $findings ) as $index => $finding ) {
            $keyed[] = array( isset( $rank[ $finding['severity'] ] ) ? $rank[ $finding['severity'] ] : 3, $index, $finding );
        }
        usort(
            $keyed,
            function ( $a, $b ) {
                return ( $a[0] === $b[0] ) ? $a[1] - $b[1] : $a[0] - $b[0];
            }
        );
        return array_map(
            function ( $entry ) {
                return $entry[2];
            },
            array_slice( $keyed, 0, self::MAX_STORED_FINDINGS )
        );
    }

    /**
     * Compact, stable summary of findings for logs and dedupe fingerprints.
     *
     * @param array $findings Findings.
     * @return array
     */
    private function findings_summary( $findings ) {
        $summary = array();
        foreach ( $this->cap_findings( $findings ) as $finding ) {
            $summary[] = $finding['code'] . ':' . $finding['file'];
        }
        sort( $summary, SORT_STRING );
        return $summary;
    }

    /**
     * Log through the Activity Log when available.
     *
     * @param string $action   Event action.
     * @param string $message  Message.
     * @param array  $data     Extra data.
     * @param string $severity Severity.
     */
    private function log( $action, $message, $data = array(), $severity = 'info' ) {
        if ( ! $this->activity_log ) {
            return;
        }
        $this->activity_log->log( 'system', $action, $message, $data, $severity );
    }
}
