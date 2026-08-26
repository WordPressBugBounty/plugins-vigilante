<?php
/**
 * Header settings recovery
 *
 * Offers back the Security Headers configuration that the 2.9.8 migration
 * wiped, reading it from the .htaccess snapshot Vigilante_Htaccess_Manager
 * preserved before the first rewrite that would have overwritten it.
 *
 * Deliberately recovers SETTINGS, never the file. Restoring a stored .htaccess
 * wholesale would also put back the WordPress block and every rule the host,
 * the cache plugin or the CDN had added since, undoing work that has nothing to
 * do with Vigilant, and on a site that has changed permalinks or moved to a
 * different folder it would break routing outright. Reading our own block and
 * writing the settings back leaves the file to be regenerated the normal way,
 * through the validated write path, and fixes the settings screen too: a file
 * restore would have left the screen showing factory values, so the next save
 * would have wiped everything again.
 *
 * @package Vigilante
 * @since 2.10.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Htaccess_Recovery
 */
class Vigilante_Htaccess_Recovery {

    /**
     * Set once the owner has restored or dismissed the offer.
     */
    const DISMISSED_OPTION = 'vigilante_htaccess_recovery_done';

    /**
     * The security_headers section as it was just before restoring, so the
     * restore itself can be undone.
     */
    const UNDO_OPTION = 'vigilante_htaccess_recovery_undo';

    /**
     * Markers of the block that is read. Nothing outside them is ever parsed.
     */
    /**
     * The one-off snapshot of the .htaccess taken before the first rewrite that
     * would have overwritten the owner's real header configuration.
     */
    const SNAPSHOT_OPTION = 'vigilante_htaccess_pre_migration';

    const BLOCK_START = '# BEGIN Vigilante Security Headers';
    const BLOCK_END   = '# END Vigilante Security Headers';

    /**
     * Values each header is allowed to carry back into the settings.
     *
     * The snapshot is a file on disk that anything could have edited, so it is
     * treated as untrusted input: a value that is not on these lists is dropped
     * rather than written into the options. Same lists the generator enforces.
     *
     * @return array
     */
    private static function allowed() {
        return array(
            'x_frame_options' => array( 'SAMEORIGIN', 'DENY' ),
            'referrer_policy' => array(
                'no-referrer',
                'no-referrer-when-downgrade',
                'origin',
                'origin-when-cross-origin',
                'same-origin',
                'strict-origin',
                'strict-origin-when-cross-origin',
                'unsafe-url',
            ),
            'opener_policy'   => array( 'unsafe-none', 'same-origin-allow-popups', 'same-origin' ),
            'embedder_policy' => array( 'unsafe-none', 'require-corp', 'credentialless' ),
            'resource_policy' => array( 'same-site', 'same-origin', 'cross-origin' ),
        );
    }

    /**
     * Whether there is a recovery to offer.
     *
     * @return bool
     */
    public static function is_available() {
        if ( get_option( self::DISMISSED_OPTION ) ) {
            return false;
        }

        $recovered = self::get_recovered_settings();

        return ! empty( $recovered );
    }

    /**
     * Whether a restore can still be taken back.
     *
     * @since 2.10.0
     * @return bool
     */
    public static function has_undo() {
        $previous = get_option( self::UNDO_OPTION );

        return is_array( $previous ) && ! empty( $previous );
    }

    /**
     * Preserve the .htaccess once, when the file and the settings disagree.
     *
     * Detecting the damage by the shape of the stored section does not work, and
     * finding that out cost a day: register_setting() hangs
     * Vigilante_Settings::validate_options() on this option as a sanitize
     * callback, and validate_section() fills in a default for every key the input
     * is missing. So the broken 2.9.8 migration, which passed two keys, did not
     * leave a two-key section behind: it left a complete one with factory values
     * in the twelve keys it dropped, which is indistinguishable from a site that
     * simply never customised its headers.
     *
     * What is distinguishable is the desync that Albert reported: the file still
     * describes what the owner chose while the options already say factory. So
     * that is what is looked at here. The file is the older truth, and this is
     * the last moment it exists.
     *
     * Called only when the installed version has changed, never on an ordinary
     * save: a save legitimately leaves the file describing the previous values
     * for the instant before it is rewritten, and capturing there would burn the
     * single slot on a difference the owner made on purpose.
     *
     * @since 2.10.0
     * @param string             $content  The .htaccess about to be rewritten.
     * @param Vigilante_Settings $settings Settings instance.
     */
    public static function maybe_capture( $content, $settings ) {
        if ( '' === (string) $content || false !== get_option( self::SNAPSHOT_OPTION, false ) ) {
            return;
        }

        if ( '' === self::extract_block( $content ) ) {
            return;
        }

        /*
         * Compared as emitted directives, never as settings arrays. The two do
         * not have the same shape and never will: an unsafe-none COEP is not
         * written at all, the CSP carries a report_uri the header does not, and a
         * boolean directive comes back from the file as a flag. Comparing the
         * arrays reported a difference on a perfectly healthy site.
         *
         * What is comparable is what the server is being told. So the block on
         * disk is measured against the block this configuration would write right
         * now: if they say different things, the file is describing a
         * configuration that is no longer stored anywhere.
         */
        require_once VIGILANTE_INCLUDES_DIR . 'class-security-headers.php';

        // Solo nuestro bloque de cabeceras: el fichero entero trae también las
        // directivas del bloque de Protección (unset X-Powered-By, unset Server),
        // que el generador de cabeceras no produce y que harían diferir a
        // cualquier sitio sano que tenga el cortafuegos activo.
        $on_disk = self::directives( self::extract_block( $content ) );
        $would   = self::directives( ( new Vigilante_Security_Headers( $settings ) )->generate_rules_content() );

        if ( empty( $on_disk ) || $on_disk === $would ) {
            return;
        }

        update_option(
            self::SNAPSHOT_OPTION,
            array(
                'content' => (string) $content,
                'time'    => time(),
                'version' => VIGILANTE_VERSION,
            ),
            false
        );
    }

    /**
     * Every header directive a chunk of .htaccess sets, normalised for comparison.
     *
     * Comments, blank lines, indentation and order are all dropped: two blocks
     * that tell the server the same things compare equal even if one was written
     * by an older version with a different timestamp in its header comment.
     *
     * @since 2.10.0
     * @param string $text Block or full file.
     * @return array
     */
    private static function directives( $text ) {
        $lines = array();

        if ( preg_match_all( '/^\s*Header\s+always\s+(set|unset)\s+([A-Za-z0-9-]+)(?:\s+"([^"]*)")?/mi', (string) $text, $matches, PREG_SET_ORDER ) ) {
            foreach ( $matches as $match ) {
                $lines[] = strtolower( $match[1] ) . ' ' . strtolower( $match[2] ) . ' ' . ( isset( $match[3] ) ? trim( $match[3] ) : '' );
            }
        }

        sort( $lines );

        return $lines;
    }

    /**
     * The stored snapshot, or an empty array.
     *
     * @return array
     */
    public static function get_snapshot() {
        $snapshot = get_option( self::SNAPSHOT_OPTION );

        return ( is_array( $snapshot ) && ! empty( $snapshot['content'] ) ) ? $snapshot : array();
    }

    /**
     * The raw Vigilant header block from the snapshot, for the owner to read.
     *
     * @return string
     */
    public static function get_raw_block() {
        $snapshot = self::get_snapshot();

        if ( empty( $snapshot ) ) {
            return '';
        }

        return self::extract_block( $snapshot['content'] );
    }

    /**
     * Cut out our own block. Everything outside the markers is ignored.
     *
     * @param string $content Full .htaccess content.
     * @return string
     */
    private static function extract_block( $content ) {
        $start = strpos( $content, self::BLOCK_START );

        if ( false === $start ) {
            return '';
        }

        $end = strpos( $content, self::BLOCK_END, $start );

        if ( false === $end ) {
            return '';
        }

        return substr( $content, $start, ( $end - $start ) + strlen( self::BLOCK_END ) );
    }

    /**
     * Read every "Header always set" line of the block into name => value.
     *
     * @param string $block Block content.
     * @return array
     */
    private static function read_headers( $block ) {
        $headers = array();

        if ( ! preg_match_all( '/^\s*Header\s+always\s+set\s+([A-Za-z0-9-]+)\s+"([^"]*)"/mi', $block, $matches, PREG_SET_ORDER ) ) {
            return $headers;
        }

        foreach ( $matches as $match ) {
            $headers[ strtolower( $match[1] ) ] = trim( $match[2] );
        }

        return $headers;
    }

    /**
     * The settings the snapshot describes, ready to be compared or written.
     *
     * @return array Section-shaped array, empty when there is nothing to offer.
     */
    public static function get_recovered_settings() {
        return self::settings_from_block( self::get_raw_block() );
    }

    /**
     * The settings a given .htaccess content describes, reading only our block.
     *
     * @since 2.10.0
     * @param string $content Full .htaccess content.
     * @return array
     */
    public static function settings_from_content( $content ) {
        return self::settings_from_block( self::extract_block( (string) $content ) );
    }

    /**
     * Turn one Vigilant header block into a settings array.
     *
     * @param string $block Block content.
     * @return array
     */
    private static function settings_from_block( $block ) {
        if ( '' === $block ) {
            return array();
        }

        $headers = self::read_headers( $block );

        if ( empty( $headers ) ) {
            return array();
        }

        $allowed   = self::allowed();
        $recovered = array();

        if ( isset( $headers['x-frame-options'] )
            && in_array( strtoupper( $headers['x-frame-options'] ), $allowed['x_frame_options'], true )
        ) {
            $recovered['x_frame_options'] = strtoupper( $headers['x-frame-options'] );
        }

        if ( isset( $headers['referrer-policy'] )
            && in_array( strtolower( $headers['referrer-policy'] ), $allowed['referrer_policy'], true )
        ) {
            $recovered['referrer_policy'] = strtolower( $headers['referrer-policy'] );
        }

        $hsts = self::read_hsts( $headers );

        if ( ! empty( $hsts ) ) {
            $recovered['hsts'] = $hsts;
        }

        $csp = self::read_csp( $headers );

        if ( ! empty( $csp ) ) {
            $recovered['csp'] = $csp;
        }

        $cross_origin = self::read_cross_origin( $headers, $allowed );

        if ( ! empty( $cross_origin ) ) {
            $recovered['cross_origin_policies'] = $cross_origin;
        }

        return $recovered;
    }

    /**
     * Strict-Transport-Security back into the hsts sub-array.
     *
     * @param array $headers Parsed headers.
     * @return array
     */
    private static function read_hsts( $headers ) {
        if ( ! isset( $headers['strict-transport-security'] ) ) {
            return array();
        }

        $value = strtolower( $headers['strict-transport-security'] );

        if ( ! preg_match( '/max-age\s*=\s*(\d+)/', $value, $match ) ) {
            return array();
        }

        return array(
            'enabled'            => true,
            'max_age'            => min( absint( $match[1] ), YEAR_IN_SECONDS * 2 ),
            'include_subdomains' => ( false !== strpos( $value, 'includesubdomains' ) ),
            'preload'            => ( false !== strpos( $value, 'preload' ) ),
        );
    }

    /**
     * Content-Security-Policy back into the csp sub-array.
     *
     * @param array $headers Parsed headers.
     * @return array
     */
    private static function read_csp( $headers ) {
        $report_only = isset( $headers['content-security-policy-report-only'] );
        $key         = $report_only ? 'content-security-policy-report-only' : 'content-security-policy';

        if ( ! isset( $headers[ $key ] ) || '' === $headers[ $key ] ) {
            return array();
        }

        $directives = array();

        foreach ( explode( ';', $headers[ $key ] ) as $chunk ) {
            $chunk = trim( $chunk );

            if ( '' === $chunk ) {
                continue;
            }

            $parts = preg_split( '/\s+/', $chunk, 2 );
            $name  = strtolower( trim( $parts[0] ) );

            // Directive names are a fixed vocabulary; anything else is noise.
            if ( ! preg_match( '/^[a-z0-9-]+$/', $name ) ) {
                continue;
            }

            // A valueless directive (upgrade-insecure-requests) is a flag.
            $directives[ $name ] = isset( $parts[1] ) ? trim( $parts[1] ) : true;
        }

        if ( empty( $directives ) ) {
            return array();
        }

        return array(
            'enabled'     => true,
            'report_only' => $report_only,
            'directives'  => $directives,
        );
    }

    /**
     * The three cross-origin policies.
     *
     * @param array $headers Parsed headers.
     * @param array $allowed Allowed values.
     * @return array
     */
    private static function read_cross_origin( $headers, $allowed ) {
        $map = array(
            'cross-origin-opener-policy'   => 'opener_policy',
            'cross-origin-embedder-policy' => 'embedder_policy',
            'cross-origin-resource-policy' => 'resource_policy',
        );

        $out = array();

        foreach ( $map as $header => $key ) {
            if ( ! isset( $headers[ $header ] ) ) {
                continue;
            }

            $value = strtolower( $headers[ $header ] );

            if ( in_array( $value, $allowed[ $key ], true ) ) {
                $out[ $key ] = $value;
            }
        }

        return $out;
    }

    /**
     * What the owner is shown before deciding: setting, value now, value found.
     *
     * Only rows that would actually change are returned, so the list is the
     * change itself rather than a dump of the whole section.
     *
     * @param Vigilante_Settings $settings Settings instance.
     * @return array List of array( label, current, recovered ).
     */
    public static function get_diff( $settings ) {
        $recovered = self::get_recovered_settings();

        if ( empty( $recovered ) ) {
            return array();
        }

        $current = $settings->get_section( 'security_headers' );
        $rows    = array();

        $labels = array(
            'x_frame_options'       => __( 'X-Frame-Options', 'vigilante' ),
            'referrer_policy'       => __( 'Referrer-Policy', 'vigilante' ),
            'hsts'                  => __( 'HSTS', 'vigilante' ),
            'csp'                   => __( 'Content Security Policy', 'vigilante' ),
            'cross_origin_policies' => __( 'Cross-Origin Policies', 'vigilante' ),
        );

        foreach ( $recovered as $key => $value ) {
            $now = isset( $current[ $key ] ) ? $current[ $key ] : null;

            /*
             * Shown as what restoring would actually leave behind, which is the
             * merge restore() performs, not the recovered value on its own.
             *
             * The difference is not academic. A COEP of unsafe-none is never
             * written to the file, so it cannot be read back, and the recovered
             * cross_origin_policies arrives with two of its three keys. Described
             * raw, that read as "your COEP is about to disappear", when
             * array_replace_recursive() keeps it untouched. Nothing may be written
             * that was not shown, and nothing may be shown that will not happen.
             */
            $applied = ( is_array( $value ) && is_array( $now ) )
                ? array_replace_recursive( $now, $value )
                : $value;

            /*
             * Compared on the values, never on their descriptions. A description
             * is a summary and summaries collide: two different policies both
             * described as "14 directives" would have compared equal, so the CSP
             * would have been restored without ever appearing in the list the
             * owner approves.
             */
            if ( $now == $applied ) { // phpcs:ignore WordPress.PHP.StrictComparisons.LooseComparison -- arrays compare by key/value pairs regardless of order, which is what "same configuration" means here.
                continue;
            }

            $rows[] = array(
                'label'     => isset( $labels[ $key ] ) ? $labels[ $key ] : $key,
                'current'   => self::describe( $key, $now ),
                'recovered' => self::describe( $key, $applied ),
                'detail'    => ( 'csp' === $key ) ? self::describe_csp_changes( $now, $applied ) : '',
            );
        }

        return $rows;
    }

    /**
     * Name the CSP directives that actually differ.
     *
     * Two policies can both be "14 directives" and mean very different things,
     * so the count alone is not something anyone can make a decision on.
     *
     * @param mixed $now       Current csp value.
     * @param array $recovered Recovered csp value.
     * @return string
     */
    private static function describe_csp_changes( $now, $recovered ) {
        $before = ( is_array( $now ) && isset( $now['directives'] ) && is_array( $now['directives'] ) ) ? $now['directives'] : array();
        $after  = ( isset( $recovered['directives'] ) && is_array( $recovered['directives'] ) ) ? $recovered['directives'] : array();

        $changed = array();

        foreach ( array_keys( $before + $after ) as $name ) {
            $a = isset( $before[ $name ] ) ? $before[ $name ] : null;
            $b = isset( $after[ $name ] ) ? $after[ $name ] : null;

            if ( $a !== $b ) {
                $changed[] = $name;
            }
        }

        if ( empty( $changed ) ) {
            return '';
        }

        sort( $changed );

        /* translators: %s: comma-separated list of Content Security Policy directive names. */
        return sprintf( __( 'Differs in: %s', 'vigilante' ), implode( ', ', $changed ) );
    }

    /**
     * One-line human description of a setting value.
     *
     * @param string $key   Setting key.
     * @param mixed  $value Setting value.
     * @return string
     */
    private static function describe( $key, $value ) {
        if ( null === $value || '' === $value ) {
            return __( 'not set', 'vigilante' );
        }

        if ( 'hsts' === $key ) {
            if ( empty( $value['enabled'] ) ) {
                return __( 'off', 'vigilante' );
            }

            $parts = array( 'max-age=' . absint( isset( $value['max_age'] ) ? $value['max_age'] : 0 ) );

            if ( ! empty( $value['include_subdomains'] ) ) {
                $parts[] = 'includeSubDomains';
            }

            if ( ! empty( $value['preload'] ) ) {
                $parts[] = 'preload';
            }

            return implode( '; ', $parts );
        }

        if ( 'csp' === $key ) {
            if ( empty( $value['enabled'] ) ) {
                return __( 'off', 'vigilante' );
            }

            $count = ( isset( $value['directives'] ) && is_array( $value['directives'] ) ) ? count( $value['directives'] ) : 0;

            /* translators: %d: number of Content Security Policy directives. */
            return sprintf( _n( '%d directive', '%d directives', $count, 'vigilante' ), $count );
        }

        if ( 'cross_origin_policies' === $key ) {
            $bits = array();

            foreach ( array( 'opener_policy', 'embedder_policy', 'resource_policy' ) as $sub ) {
                if ( ! empty( $value[ $sub ] ) ) {
                    $bits[] = $value[ $sub ];
                }
            }

            return $bits ? implode( ', ', $bits ) : __( 'not set', 'vigilante' );
        }

        return is_scalar( $value ) ? (string) $value : __( 'not set', 'vigilante' );
    }

    /**
     * Write the recovered settings, keeping an undo copy.
     *
     * @param Vigilante_Settings $settings Settings instance.
     * @return true|WP_Error
     */
    public static function restore( $settings ) {
        $recovered = self::get_recovered_settings();

        if ( empty( $recovered ) ) {
            return new WP_Error( 'nothing_to_restore', __( 'There is nothing to restore.', 'vigilante' ) );
        }

        $current = $settings->get_section( 'security_headers' );

        // Keep what it looked like first, so this is reversible too.
        update_option( self::UNDO_OPTION, $current, false );

        $settings->update_section( 'security_headers', array_replace_recursive( $current, $recovered ) );
        $settings->clear_cache();

        update_option( self::DISMISSED_OPTION, 1, false );

        return self::rewrite_rules();
    }

    /**
     * Put back the settings as they were before restoring.
     *
     * @param Vigilante_Settings $settings Settings instance.
     * @return true|WP_Error
     */
    public static function undo( $settings ) {
        $previous = get_option( self::UNDO_OPTION );

        if ( ! is_array( $previous ) || empty( $previous ) ) {
            return new WP_Error( 'no_undo', __( 'There is nothing to undo.', 'vigilante' ) );
        }

        $settings->update_section( 'security_headers', $previous );
        $settings->clear_cache();
        delete_option( self::UNDO_OPTION );

        return self::rewrite_rules();
    }

    /**
     * Stop offering the recovery, without changing any setting.
     */
    public static function dismiss() {
        update_option( self::DISMISSED_OPTION, 1, false );
    }

    /**
     * Regenerate the .htaccess from the settings, through the normal path.
     *
     * @return true|WP_Error
     */
    private static function rewrite_rules() {
        $settings = new Vigilante_Settings();

        if ( ! $settings->is_module_enabled( 'security_headers' ) ) {
            return true;
        }

        require_once VIGILANTE_INCLUDES_DIR . 'class-security-headers.php';

        $result = ( new Vigilante_Security_Headers( $settings ) )->apply_rules();

        // Not being on Apache is not a failure: the settings are what matters,
        // and there is no block to write on nginx.
        if ( is_wp_error( $result ) && 'not_apache' === $result->get_error_code() ) {
            return true;
        }

        return is_wp_error( $result ) ? $result : true;
    }
}
