<?php
/**
 * One click repair of Vigilant's own files.
 *
 * Detecting tampering and leaving the person with "download a zip and upload
 * it" is half a tool, so this reinstalls Vigilant from WordPress.org with the
 * mechanism WordPress already uses for "Replace current with uploaded":
 * Plugin_Upgrader::install() with overwrite_package, which empties the plugin
 * folder (so injected files go with it), copies the clean one, and touches
 * nothing else. Settings, tables and the activity log are kept, because
 * uninstall.php never runs here.
 *
 * What it deliberately does NOT do:
 *
 *  - It never installs the version the plugin header claims. Whoever changed
 *    the files can write that header, and a header saying 2.10.2 would turn
 *    this button into a downgrade to a version with public vulnerabilities.
 *    The version comes from WordPress.org and is refused if it is older than
 *    the one anchored for this installation.
 *  - The package address is built here from a fixed host and a version that
 *    matches a strict pattern. Nothing from the request, from the update
 *    transient or from the API response is used as a URL.
 *  - It cannot promise anything if the repair code itself was changed: that is
 *    written in SECURITY.md, and the check that does not depend on this server
 *    is still the one against WordPress.org from outside.
 *
 * @package Vigilante
 * @since   3.0.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Self_Repair
 */
class Vigilante_Self_Repair {

    /**
     * admin-post action, and the nonce that guards it.
     */
    const ACTION = 'vigilante_repair_self';

    /**
     * Slug on WordPress.org. Not the folder name: the folder can be renamed,
     * and this is what identifies the package to download.
     */
    const SLUG = 'vigilante';

    /**
     * Host that serves the official packages.
     */
    const PACKAGE_HOST = 'https://downloads.wordpress.org/plugin/';

    /**
     * Register the handler. It is an admin-post action and not a hidden admin
     * page so inventario-superficie.php sees it like any other entry point.
     */
    public static function init() {
        add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
    }

    /**
     * Whether this person can repair Vigilant on this site.
     *
     * update_plugins is what WordPress denies when file changes are turned off
     * (DISALLOW_FILE_MODS) and, on a network, to everyone but a super
     * administrator: both are exactly the answer this button needs.
     *
     * @return bool
     */
    public static function can_repair() {
        return current_user_can( 'manage_options' )
            && current_user_can( 'update_plugins' )
            && self::folder_is_the_distributed_one();
    }

    /**
     * Whether this copy lives in the folder the official package installs into.
     *
     * Plugin_Upgrader::install() puts the package where the package says: the
     * destination is WP_PLUGIN_DIR plus the folder name inside the zip
     * (wp-admin/includes/class-wp-upgrader.php:642), and the zip of
     * WordPress.org always carries "vigilante". On an installation whose folder
     * was renamed, repairing would leave a clean copy beside the one that is
     * running, report success, and change nothing of what was tampered with.
     * So it is not offered there: the box gives the steps by hand instead.
     *
     * @param string|null $basename Plugin basename, read from the constant when null.
     * @return bool
     */
    public static function folder_is_the_distributed_one( $basename = null ) {
        if ( null === $basename ) {
            $basename = defined( 'VIGILANTE_PLUGIN_BASENAME' ) ? VIGILANTE_PLUGIN_BASENAME : '';
        }
        $basename = (string) $basename;
        if ( '' === $basename || false === strpos( $basename, '/' ) ) {
            return false;
        }
        return self::SLUG === dirname( $basename );
    }

    /**
     * URL of the confirmation screen.
     *
     * @return string
     */
    public static function action_url() {
        return wp_nonce_url( admin_url( 'admin-post.php?action=' . self::ACTION ), self::ACTION );
    }

    /**
     * Version WordPress.org distributes right now, or an empty string when it
     * cannot be used (no answer, a version that is not a version, or one older
     * than what this installation already anchored).
     *
     * @return string
     */
    public static function target_version() {
        $latest = self::wporg_version();
        if ( '' === $latest ) {
            return '';
        }
        $floor = self::floor_version();
        if ( '' !== $floor && version_compare( $latest, $floor, '<' ) ) {
            return '';
        }
        return $latest;
    }

    /**
     * Lowest version this repair may install: whatever this installation has
     * anchored, or the version on disk when there is no state yet.
     *
     * @return string
     */
    private static function floor_version() {
        $state   = get_option( Vigilante_Self_Integrity::STATE_OPTION, array() );
        $anchored = ( is_array( $state ) && ! empty( $state['version'] ) ) ? (string) $state['version'] : '';
        if ( self::is_version( $anchored ) ) {
            return $anchored;
        }
        return self::is_version( VIGILANTE_VERSION ) ? VIGILANTE_VERSION : '';
    }

    /**
     * Ask WordPress.org for the current stable version.
     *
     * @return string
     */
    private static function wporg_version() {
        if ( ! function_exists( 'plugins_api' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
        }
        $info = plugins_api(
            'plugin_information',
            array(
                'slug'   => self::SLUG,
                'fields' => array(
                    'sections'     => false,
                    'screenshots'  => false,
                    'versions'     => false,
                    'reviews'      => false,
                    'banners'      => false,
                    'icons'        => false,
                    'contributors' => false,
                ),
            )
        );
        if ( is_wp_error( $info ) || empty( $info->version ) ) {
            return '';
        }
        $version = (string) $info->version;
        return self::is_version( $version ) ? $version : '';
    }

    /**
     * A version is three or four numbers and nothing else. Anything else never
     * reaches the address of a package.
     *
     * @param string $version Candidate.
     * @return bool
     */
    private static function is_version( $version ) {
        return (bool) preg_match( '/^[0-9]+(\.[0-9]+){1,3}$/', (string) $version );
    }

    /**
     * Address of the official package for a version.
     *
     * @param string $version Version, already checked by is_version().
     * @return string
     */
    private static function package_url( $version ) {
        return self::PACKAGE_HOST . self::SLUG . '.' . $version . '.zip';
    }

    /**
     * admin-post entry point: a GET shows what is going to happen, and only a
     * POST does it.
     */
    public static function handle() {
        if ( ! self::can_repair() ) {
            wp_die(
                esc_html__( 'You are not allowed to repair Vigilant on this site.', 'vigilante' ),
                esc_html__( 'Repair Vigilant', 'vigilante' ),
                array( 'response' => 403 )
            );
        }
        check_admin_referer( self::ACTION );

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The nonce is checked above, for both methods.
        $confirmed = ( isset( $_POST['vigilante_repair_confirm'] ) );

        $version = self::target_version();
        if ( $confirmed ) {
            self::run( $version );
            return;
        }
        self::confirm_screen( $version );
    }

    /**
     * Screen that asks before touching anything.
     *
     * @param string $version Version that would be installed, may be empty.
     */
    private static function confirm_screen( $version ) {
        self::screen_start( __( 'Repair Vigilant', 'vigilante' ) );

        if ( '' === $version ) {
            self::render_unavailable();
            self::screen_end();
            return;
        }

        echo '<p>';
        printf(
            /* translators: %s: plugin version, like 3.0.0 */
            esc_html__( 'This downloads Vigilant %s from WordPress.org and replaces the files of the plugin with that copy.', 'vigilante' ),
            esc_html( $version )
        );
        echo '</p>';
        echo '<ul style="list-style:disc;margin-left:20px;">';
        echo '<li>' . esc_html__( 'Your settings, your tables and your activity log are kept: nothing is uninstalled and nothing is deactivated.', 'vigilante' ) . '</li>';
        echo '<li>' . esc_html__( 'Files that are not part of Vigilant but live in its folder are removed with the rest of the folder.', 'vigilante' ) . '</li>';
        echo '<li>' . esc_html__( 'If your server needs FTP credentials to change files, WordPress asks for them, as it does for any update.', 'vigilante' ) . '</li>';
        echo '<li>' . esc_html__( 'When it is done, Vigilant checks the new files against WordPress.org and against its manifest, and reports the result in File Integrity.', 'vigilante' ) . '</li>';
        echo '</ul>';
        echo '<p>' . esc_html__( 'If your site is deployed with Git, Composer or a sync tool, repair it there instead: your next deployment would put the changed files back.', 'vigilante' ) . '</p>';

        echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php?action=' . self::ACTION ) ) . '">';
        wp_nonce_field( self::ACTION );
        echo '<input type="hidden" name="vigilante_repair_confirm" value="1" />';
        echo '<p>';
        echo '<button type="submit" class="button button-primary">' . esc_html__( 'Repair Vigilant now', 'vigilante' ) . '</button> ';
        echo '<a class="button" href="' . esc_url( self::back_url() ) . '">' . esc_html__( 'Cancel', 'vigilante' ) . '</a>';
        echo '</p>';
        echo '</form>';

        self::screen_end();
    }

    /**
     * Do it.
     *
     * @param string $version Version to install.
     */
    private static function run( $version ) {
        self::screen_start( __( 'Repair Vigilant', 'vigilante' ) );

        if ( '' === $version ) {
            self::render_unavailable();
            self::screen_end();
            return;
        }

        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

        $basename    = defined( 'VIGILANTE_PLUGIN_BASENAME' ) ? VIGILANTE_PLUGIN_BASENAME : '';
        $was_active  = $basename && is_plugin_active( $basename );
        $was_network = $basename && is_plugin_active_for_network( $basename );

        $skin = new WP_Upgrader_Skin(
            array(
                'url'   => admin_url( 'admin-post.php?action=' . self::ACTION . '&_wpnonce=' . wp_create_nonce( self::ACTION ) ),
                'nonce' => self::ACTION,
            )
        );
        $upgrader = new Plugin_Upgrader( $skin );
        $result   = $upgrader->install( self::package_url( $version ), array( 'overwrite_package' => true ) );

        /*
         * Someone opening the plugins screen during the seconds the folder is
         * being replaced makes WordPress deactivate a plugin whose file is not
         * there (validate_active_plugins()). Silent, so the activation routine
         * does not run again: the plugin was never meant to stop.
         */
        if ( $was_active && $basename && ! is_plugin_active( $basename ) ) {
            activate_plugin( $basename, '', $was_network, true );
        }

        if ( is_wp_error( $result ) ) {
            echo '<p><strong>' . esc_html__( 'The repair could not be completed.', 'vigilante' ) . '</strong> ' . esc_html( $result->get_error_message() ) . '</p>';
            self::render_manual_steps();
        } elseif ( ! $result ) {
            echo '<p><strong>' . esc_html__( 'The repair could not be completed.', 'vigilante' ) . '</strong></p>';
            self::render_manual_steps();
        } else {
            echo '<p><strong>' . esc_html__( 'Vigilant files have been replaced with the copy from WordPress.org.', 'vigilante' ) . '</strong> '
                . esc_html__( 'Vigilant checked them again right away: File Integrity shows the result.', 'vigilante' ) . '</p>';
        }

        echo '<p><a class="button button-primary" href="' . esc_url( self::back_url() ) . '">' . esc_html__( 'Back to File Integrity', 'vigilante' ) . '</a></p>';
        self::screen_end();
    }

    /**
     * When WordPress.org cannot be asked, or answers with a version older than
     * the one anchored here, there is nothing safe to install: say why, and
     * give the steps by hand.
     */
    private static function render_unavailable() {
        echo '<p><strong>' . esc_html__( 'Vigilant cannot repair itself right now.', 'vigilante' ) . '</strong> '
            . esc_html__( 'WordPress.org did not answer with a version that can be installed on this site, either because your server could not reach it or because the version it offers is older than the one anchored here.', 'vigilante' ) . '</p>';
        self::render_manual_steps();
    }

    /**
     * The steps by hand, from the shared catalogue.
     */
    private static function render_manual_steps() {
        echo '<ol style="margin-left:20px;">';
        foreach ( Vigilante_Self_Integrity_Guidance::manual_steps( 'general' ) as $step ) {
            echo '<li>' . esc_html( $step ) . '</li>';
        }
        echo '</ol>';
    }

    /**
     * Where the buttons of these screens go back to.
     *
     * @return string
     */
    private static function back_url() {
        return admin_url( 'admin.php?page=vigilante&tab=file-integrity#vigilante-section-fi-self' );
    }

    /**
     * Minimal admin chrome, the same one core uses for the screens that run an
     * upgrader.
     *
     * @param string $title Screen title.
     */
    private static function screen_start( $title ) {
        if ( ! function_exists( 'iframe_header' ) ) {
            require_once ABSPATH . 'wp-admin/includes/template.php';
        }
        /*
         * admin-post.php leaves $hook_suffix unset, and iframe_header() fires
         * admin_enqueue_scripts with it: a null there is a fatal error in any
         * plugin that declares a string parameter for that hook (measured with
         * Plugin Check installed). Give the screen a name before printing it.
         */
        if ( empty( $GLOBALS['hook_suffix'] ) || ! is_string( $GLOBALS['hook_suffix'] ) ) {
            $GLOBALS['hook_suffix'] = 'vigilante_page_repair';
        }
        if ( function_exists( 'set_current_screen' ) ) {
            set_current_screen( $GLOBALS['hook_suffix'] );
        }
        iframe_header( $title );
        echo '<div class="wrap" style="margin:20px;">';
        echo '<h1>' . esc_html( $title ) . '</h1>';
    }

    /**
     * Close what screen_start() opened.
     */
    private static function screen_end() {
        echo '</div>';
        iframe_footer();
        exit;
    }
}
