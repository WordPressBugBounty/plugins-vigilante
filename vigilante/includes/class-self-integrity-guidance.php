<?php
/**
 * Guidance texts for self-protection (what a finding means, and how to fix it).
 *
 * Single source used by the File Integrity box, the Security Check detail, the
 * Security Audit details, the admin notices and the alert email, so the five
 * never drift apart. Strings and a mapping only: nothing here reads state or
 * touches the filesystem.
 *
 * Several finding codes share one explanation, so the entry point is a case
 * key (see case_key()), which is also what the File Integrity box groups by:
 * ten modified files are one case with ten paths, not ten explanations.
 *
 * @package Vigilante
 * @since   3.0.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Self_Integrity_Guidance
 */
class Vigilante_Self_Integrity_Guidance {

    /**
     * Case key for a finding. Codes with the same answer share a key.
     *
     * @param string $code     Finding code.
     * @param string $severity info|warning|critical.
     * @param string $variant  Optional variant set by the finding (unreadable,
     *                         exec, link, dir, walk).
     * @return string
     */
    public static function case_key( $code, $severity = 'critical', $variant = '' ) {
        switch ( (string) $code ) {
            case 'self_modified':
                if ( 'unreadable' === $variant ) {
                    return 'unreadable';
                }
                return ( 'critical' === $severity ) ? 'modified_code' : 'modified_asset';
            case 'self_missing':
                return 'missing';
            case 'self_symlink':
                return 'link';
            case 'self_extra':
                if ( 'link' === $variant ) {
                    return 'link';
                }
                if ( 'dir' === $variant || 'walk' === $variant ) {
                    return 'unlistable';
                }
                return ( 'critical' === $severity ) ? 'extra_exec' : 'extra_file';
            case 'manifest_replaced':
            case 'manifest_stale':
                return 'manifest_replaced';
            case 'manifest_missing':
            case 'manifest_invalid':
                return ( 'critical' === $severity ) ? 'manifest_replaced' : 'manifest_soft';
            case 'manifest_unverified':
                return 'unverified';
            case 'distribution_mismatch':
                return 'distribution';
            case 'self_downgraded':
                return 'downgrade';
            case 'no_anchors':
                return 'no_anchors';
            case 'cron_cleared_repeatedly':
                return 'cron_repeated';
            case 'self_disabled':
                return 'disabled';
            case 'self_hooks_removed':
                return 'hooks_removed';
            case 'self_stale':
                return 'stale';
        }
        return 'unknown';
    }

    /**
     * Guidance for one finding.
     *
     * @param array|string $finding Finding array, or a bare code.
     * @return array { key, title, meaning, steps, repair }
     */
    public static function for_finding( $finding ) {
        if ( is_array( $finding ) ) {
            $code     = isset( $finding['code'] ) ? (string) $finding['code'] : '';
            $severity = isset( $finding['severity'] ) ? (string) $finding['severity'] : 'critical';
            $variant  = isset( $finding['variant'] ) ? (string) $finding['variant'] : '';
        } else {
            $code     = (string) $finding;
            $severity = 'critical';
            $variant  = '';
        }
        return self::case_data( self::case_key( $code, $severity, $variant ) );
    }

    /**
     * Guidance for the state itself, when there is nothing wrong to explain
     * (verified, verified with fewer references, turned off, never run).
     *
     * @param array $args {
     *     @type string $status   Stored status (ok, degraded, warning, critical).
     *     @type int    $files    Files checked.
     *     @type array  $anchors  manifest/wporg/fingerprint booleans.
     *     @type bool   $enabled  Whether the self-check is on.
     *     @type bool   $has_run  Whether it has ever run.
     * }
     * @return array { key, title, meaning, steps, repair }
     */
    public static function for_status( $args = array() ) {
        $status  = isset( $args['status'] ) ? (string) $args['status'] : '';
        $files   = isset( $args['files'] ) ? (int) $args['files'] : 0;
        $anchors = ( isset( $args['anchors'] ) && is_array( $args['anchors'] ) ) ? $args['anchors'] : array();
        $enabled = ! isset( $args['enabled'] ) || (bool) $args['enabled'];
        $has_run = ! isset( $args['has_run'] ) || (bool) $args['has_run'];

        if ( ! $enabled ) {
            return self::case_data( 'disabled' );
        }
        if ( ! $has_run ) {
            return self::case_data( 'never_run' );
        }
        if ( $files < 1 ) {
            return self::case_data( 'no_anchors' );
        }

        $present = count( array_filter( $anchors ) );
        if ( $present >= 3 ) {
            return self::case_data( 'verified' );
        }
        if ( empty( $anchors['wporg'] ) ) {
            return self::case_data( 'verified_no_wporg' );
        }
        return self::case_data( 'verified_partial' );
    }

    /**
     * Explanation for one Security Audit entry about self-protection: which
     * files it was about, what it means and what to do, so the popup of the
     * log says the same as the File Integrity box.
     *
     * @param string       $action     Event action.
     * @param string|array $extra_data extra_data column (JSON string or array).
     * @param string       $severity   Severity of the log entry.
     * @return array|null { title, meaning, steps, files }
     */
    public static function for_log_event( $action, $extra_data = '', $severity = 'info' ) {
        $cases = array(
            'self_integrity_fail'       => '',
            'self_verified_post_update' => 'post_update',
            'self_integrity_restored'   => 'restored',
            'self_integrity_scan'       => 'checked',
            'self_integrity_captured'   => 'captured',
            'self_rebaselined'          => 'captured',
            'cron_restored'             => 'cron_restored',
            'cron_scheduled'            => 'cron_restored',
        );
        $action = (string) $action;
        if ( ! isset( $cases[ $action ] ) ) {
            return null;
        }

        $data = is_string( $extra_data ) ? json_decode( $extra_data, true ) : $extra_data;
        $data = is_array( $data ) ? $data : array();

        $files = array();
        $codes = array();
        if ( ! empty( $data['findings'] ) && is_array( $data['findings'] ) ) {
            foreach ( $data['findings'] as $entry ) {
                // The log stores each finding as "code:file".
                $parts  = explode( ':', (string) $entry, 2 );
                $code   = $parts[0];
                $file   = isset( $parts[1] ) ? $parts[1] : '';
                $codes[] = $code;
                if ( '' !== $file ) {
                    $files[] = $file;
                }
            }
        }
        foreach ( array( 'restored', 'scheduled' ) as $hook_key ) {
            if ( ! empty( $data[ $hook_key ] ) && is_array( $data[ $hook_key ] ) ) {
                foreach ( $data[ $hook_key ] as $hook ) {
                    $files[] = (string) $hook;
                }
            }
        }

        $key = $cases[ $action ];
        if ( '' === $key ) {
            $key = $codes ? self::case_key( $codes[0], 'critical' === $severity ? 'critical' : 'warning' ) : 'unknown';
        }
        if ( 'cron_restored' === $key && 'critical' === $severity ) {
            $key = 'cron_repeated';
        }

        $guidance          = self::case_data( $key );
        $guidance['files'] = array_values( array_unique( $files ) );
        if ( count( array_unique( $codes ) ) > 1 ) {
            $guidance['meaning'] .= ' ' . __( 'This entry covers more than one kind of finding: File Integrity lists each one with what it means and what to do.', 'vigilante' );
        }
        return $guidance;
    }

    /**
     * What to do when the repair button is not available.
     *
     * @param string $reason general|no_caps|network|renamed.
     * @return array List of steps.
     */
    public static function manual_steps( $reason = 'general' ) {
        if ( 'no_caps' === $reason ) {
            return array(
                __( 'Plugin files cannot be changed from WordPress on this site, so Vigilant cannot repair itself here. Ask whoever manages your server to reinstall Vigilant from WordPress.org.', 'vigilante' ),
            );
        }
        if ( 'renamed' === $reason ) {
            return array(
                __( 'This copy of Vigilant lives in a folder with a different name, and the package WordPress.org distributes always installs as vigilante, so repairing from here would leave a clean copy beside the one that is running.', 'vigilante' ),
                __( 'Download Vigilant from WordPress.org and replace the contents of the folder it is installed in, keeping the folder name, or rename the folder back to vigilante and repair from here.', 'vigilante' ),
            );
        }
        if ( 'network' === $reason ) {
            return array(
                __( 'Only your network administrator can repair Vigilant, because its files are shared by every site in the network. Let them know what this page reports.', 'vigilante' ),
            );
        }
        return array(
            __( 'Download Vigilant from WordPress.org and install it from Plugins > Add New Plugin > Upload Plugin, choosing Replace current with uploaded. Your settings, tables and log are kept.', 'vigilante' ),
            __( 'Do not delete Vigilant to reinstall it: deleting a plugin removes its settings, its tables and its log.', 'vigilante' ),
        );
    }

    /**
     * The three steps shared by every case that a reinstall fixes.
     *
     * @param bool $tail Whether to add the what-if-it-comes-back step.
     * @return array
     */
    private static function repair_steps( $tail = true ) {
        $steps = array(
            __( 'Repair Vigilant: it downloads a clean copy from WordPress.org and replaces only the plugin files, so your settings, tables and log are kept.', 'vigilante' ),
            __( 'Run a new scan from this tab to confirm the finding is gone.', 'vigilante' ),
        );
        if ( $tail ) {
            $steps[] = __( 'If it comes back after repairing, someone can still write to your server: change your hosting, FTP and administrator passwords, review the administrator accounts and ask your host to check the server.', 'vigilante' );
        }
        return $steps;
    }

    /**
     * Title, meaning and steps of each case.
     *
     * @param string $key Case key.
     * @return array { key, title, meaning, steps, repair }
     */
    public static function case_data( $key ) {
        $repair = true;
        switch ( $key ) {
            case 'modified_code':
                $title   = __( 'Code file modified', 'vigilante' );
                $meaning = __( 'This Vigilant code file no longer matches the version published on WordPress.org. Something with write access to your server changed it: an attacker, a script, or a manual edit.', 'vigilante' );
                $steps   = self::repair_steps();
                break;
            case 'missing':
                $title   = __( 'File missing', 'vigilante' );
                $meaning = __( 'A file that is part of Vigilant has been deleted. A missing module stops protecting your site without showing any error.', 'vigilante' );
                $steps   = self::repair_steps();
                break;
            case 'unreadable':
                $title   = __( 'File cannot be read', 'vigilante' );
                $meaning = __( 'Vigilant cannot read this file, so it cannot check it. Files distributed by WordPress.org are always readable.', 'vigilante' );
                $steps   = array(
                    __( 'Repair Vigilant, which restores the file with standard permissions.', 'vigilante' ),
                    __( 'If repairing fails, ask your host to fix the permissions of wp-content/plugins/vigilante.', 'vigilante' ),
                );
                break;
            case 'link':
                $title   = __( 'Symbolic link inside Vigilant', 'vigilante' );
                $meaning = __( 'A Vigilant file is a symbolic link, or points outside the plugin folder. WordPress.org never distributes links, so someone put it there.', 'vigilante' );
                $steps   = self::repair_steps();
                break;
            case 'extra_exec':
                $title   = __( 'Executable file added', 'vigilante' );
                $meaning = __( 'There is an executable file (PHP or similar) in the Vigilant folder that is not part of Vigilant. Hiding files inside a security plugin is a common way to keep a backdoor.', 'vigilante' );
                $steps   = array_merge(
                    array( __( 'If you want to know how it got there, ask your host to check when the file was created before you repair, because repairing removes it.', 'vigilante' ) ),
                    self::repair_steps()
                );
                break;
            case 'unlistable':
                $title   = __( 'Part of the folder cannot be checked', 'vigilante' );
                $meaning = __( 'Vigilant cannot list one of its folders, or found far more files than it ships, so part of its own folder cannot be checked. A web server can still run files hidden in a folder that cannot be listed.', 'vigilante' );
                $steps   = array(
                    __( 'Repair Vigilant, which replaces the folder with a clean copy.', 'vigilante' ),
                    __( 'If repairing fails, ask your host to check the permissions of wp-content/plugins/vigilante.', 'vigilante' ),
                );
                break;
            case 'extra_file':
                $title   = __( 'Extra file that is not code', 'vigilante' );
                $meaning = __( 'There is a file in the Vigilant folder that is not part of Vigilant, and it is not executable code. It is often a PHP error log written by your server, or something left behind by a backup or sync tool.', 'vigilante' );
                $steps   = array(
                    __( 'If it is an error_log, your server is writing PHP errors inside Vigilant folder: open it, and if the errors mention Vigilant, report them in the Vigilant support forum.', 'vigilante' ),
                    __( 'Repairing Vigilant removes the file, because the folder is replaced with a clean copy.', 'vigilante' ),
                );
                break;
            case 'manifest_replaced':
                $title   = __( 'Manifest replaced, deleted or damaged', 'vigilante' );
                $meaning = __( 'MANIFEST.sha256, the list of fingerprints Vigilant uses to check its own files, was replaced, deleted or damaged without a plugin update. Replacing that list is how someone would hide changes to the plugin.', 'vigilante' );
                $steps   = self::repair_steps();
                break;
            case 'manifest_soft':
                $title   = __( 'Manifest missing or damaged', 'vigilante' );
                $meaning = __( 'MANIFEST.sha256 is missing or is not a valid manifest. Vigilant still checks its files against WordPress.org, but one of its three references is gone.', 'vigilante' );
                $steps   = array(
                    __( 'Repair Vigilant to restore the manifest.', 'vigilante' ),
                );
                break;
            case 'distribution':
                $title   = __( 'Different from the WordPress.org copy', 'vigilante' );
                $meaning = __( 'These files match the manifest inside the plugin, but not the copy WordPress.org distributes for this version. On a development copy that is expected; on a live site it means the whole plugin, manifest included, came from somewhere else.', 'vigilante' );
                $steps   = array(
                    __( 'If you installed Vigilant from WordPress.org, repair it.', 'vigilante' ),
                    __( 'If you are running a development build on purpose, install the published version when you finish testing.', 'vigilante' ),
                );
                break;
            case 'modified_asset':
                $title   = __( 'Stylesheet, script or image modified', 'vigilante' );
                $meaning = __( 'A stylesheet, script or image of Vigilant no longer matches the distributed version. Usually an optimization or cache plugin, or your host, rewrote it while minifying or combining files.', 'vigilante' );
                $steps   = array(
                    __( 'If you use an optimization or cache plugin, exclude wp-content/plugins/vigilante from it, then repair Vigilant.', 'vigilante' ),
                    __( 'If you do not use one, repair Vigilant and run a new scan.', 'vigilante' ),
                );
                break;
            case 'downgrade':
                $title   = __( 'Older version installed', 'vigilante' );
                $meaning = __( 'Vigilant was replaced by an older version. Older versions can contain vulnerabilities that are already fixed and public.', 'vigilante' );
                $steps   = array(
                    __( 'If you did not downgrade it on purpose, repair Vigilant: it installs the version WordPress.org distributes now.', 'vigilante' ),
                );
                break;
            case 'unverified':
                $title   = __( 'Version changed, not confirmed yet', 'vigilante' );
                $meaning = __( 'The Vigilant version changed without the WordPress updater (an FTP upload, a file manager, a deployment), and the new files cannot be confirmed yet because WordPress.org has not published checksums for that version.', 'vigilante' );
                $steps   = array(
                    __( 'If you just updated Vigilant by hand with a copy from WordPress.org, you do not need to do anything: the next checks confirm it once WordPress.org publishes the checksums, usually within a day.', 'vigilante' ),
                    __( 'If you did not update it, or the copy did not come from WordPress.org, repair Vigilant.', 'vigilante' ),
                );
                break;
            case 'no_anchors':
                $title   = __( 'Vigilant could not check its files', 'vigilante' );
                $meaning = __( 'The manifest is not available and WordPress.org could not be reached, so there was nothing to check the files against.', 'vigilante' );
                $steps   = array(
                    __( 'Open Tools > Site Health. If your server cannot connect to WordPress.org, ask your host to allow it.', 'vigilante' ),
                    __( 'Then repair Vigilant to restore the manifest.', 'vigilante' ),
                );
                break;
            case 'cron_repeated':
                $title   = __( 'Scheduled tasks keep disappearing', 'vigilante' );
                $meaning = __( 'Vigilant scheduled tasks keep being removed and Vigilant keeps scheduling them again. While they are gone there are no scheduled scans, no daily check and no alerts.', 'vigilante' );
                $steps   = array(
                    __( 'Check whether a cleanup or optimization plugin removes scheduled events, and exclude the ones whose name starts with vigilante_. A plugin such as WP Crontrol lists them.', 'vigilante' ),
                    __( 'If you cannot find the cause, treat it as a possible compromise: review recently installed plugins and the administrator accounts.', 'vigilante' ),
                );
                $repair  = false;
                break;
            case 'cron_restored':
                $title   = __( 'Scheduled task restored', 'vigilante' );
                $meaning = __( 'One of Vigilant scheduled tasks had disappeared and Vigilant scheduled it again. A cron cleanup plugin, a database restore or a site migration can do that.', 'vigilante' );
                $steps   = array(
                    __( 'Nothing to do if it does not happen again. A plugin such as WP Crontrol lists the scheduled events of your site.', 'vigilante' ),
                );
                $repair  = false;
                break;
            case 'restored':
                $title   = __( 'Integrity restored', 'vigilante' );
                $meaning = __( 'The files that had been reported match what WordPress.org distributes again, so what was reported before is closed.', 'vigilante' );
                $steps   = array();
                $repair  = false;
                break;
            case 'post_update':
                $title   = __( 'Checked right after updating', 'vigilante' );
                $meaning = __( 'WordPress updated Vigilant and Vigilant checked its own files at the end of that same request, which is when a half copied or replaced file would show up.', 'vigilante' );
                $steps   = array();
                $repair  = false;
                break;
            case 'checked':
                $title   = __( 'Files checked', 'vigilante' );
                $meaning = __( 'Vigilant checked its own files against the references available and found nothing to report.', 'vigilante' );
                $steps   = array();
                $repair  = false;
                break;
            case 'captured':
                $title   = __( 'Reference saved', 'vigilante' );
                $meaning = __( 'Vigilant saved the fingerprint of its manifest in your database. That fingerprint is what makes a swapped or deleted manifest detectable later.', 'vigilante' );
                $steps   = array();
                $repair  = false;
                break;
            case 'verified':
                $title   = __( 'Verified', 'vigilante' );
                $meaning = __( 'Vigilant checked its own files against its three references and they all match: the checksums WordPress.org publishes for this version, the manifest shipped inside the plugin, and the fingerprint kept in your database.', 'vigilante' );
                $steps   = array();
                $repair  = false;
                break;
            case 'verified_no_wporg':
                $title   = __( 'Verified with fewer references', 'vigilante' );
                $meaning = __( 'The files match the manifest shipped inside the plugin and the fingerprint kept in your database, but WordPress.org has not published checksums for this version yet, which is normal for a few hours after a release, or your server could not reach it.', 'vigilante' );
                $steps   = array(
                    __( 'Nothing to do. If this lasts more than two days, open Tools > Site Health and check that your server can connect to WordPress.org.', 'vigilante' ),
                );
                $repair  = false;
                break;
            case 'verified_partial':
                $title   = __( 'Verified with fewer references', 'vigilante' );
                $meaning = __( 'The files were checked, but one of the three references was not available for this check.', 'vigilante' );
                $steps   = array(
                    __( 'Nothing to do. The next check uses every reference that is available then.', 'vigilante' ),
                );
                $repair  = false;
                break;
            case 'disabled':
                $title   = __( 'Self-protection is switched off by code', 'vigilante' );
                $meaning = __( 'Nothing is checking that Vigilant own files are intact, so a change to them would go unnoticed. There is no setting that does this: something on this site is using the vigilante_self_integrity_enabled filter, and the files listed here are the ones that hook it.', 'vigilante' );
                $steps   = array(
                    __( 'If you did not ask for this, treat it as a compromise: a plugin or a snippet that switches off the check of a security plugin is doing the one thing an attacker needs first.', 'vigilante' ),
                    __( 'Open the files listed above and remove that filter, or deactivate whatever added it. The check starts again on its own.', 'vigilante' ),
                    __( 'If you turned it off on purpose because this site must not contact WordPress.org, nothing else is wrong: the plugin says so on every screen while it lasts.', 'vigilante' ),
                );
                $repair  = false;
                break;
            case 'hooks_removed':
                $title   = __( 'Something removed the self-protection hooks', 'vigilante' );
                $meaning = __( 'Code on this site unhooked the checks that run after updates and on each admin page, so Vigilant would keep showing its last result as if it were current. WordPress says nothing when a callback is removed, so the file that did it cannot be named; the plugins loaded in that request are in the entry of the Security Audit.', 'vigilante' );
                $steps   = array(
                    __( 'Look at the Security Audit entry for the list of plugins loaded when it happened, and deactivate them one by one until it stops.', 'vigilante' ),
                    __( 'If none of them explains it, treat it as a compromise: change your hosting, FTP and administrator passwords and ask your host to check the server.', 'vigilante' ),
                );
                $repair  = false;
                break;
            case 'stale':
                $title   = __( 'Not checked recently', 'vigilante' );
                $meaning = __( 'The last check is more than three days old, so what you see is not a current result. It happens on sites nobody opens and with no cron running, and it also happens when something stopped the check.', 'vigilante' );
                $steps   = array(
                    __( 'Run a new scan from this tab. If the date does not move, your scheduled tasks are not running: check them with a plugin such as WP Crontrol.', 'vigilante' ),
                );
                $repair  = false;
                break;
            case 'never_run':
                $title   = __( 'Not checked yet', 'vigilante' );
                $meaning = __( 'Vigilant has not checked its own files yet. It checks them in every integrity scan, right after every update, and once a day.', 'vigilante' );
                $steps   = array(
                    __( 'Run a scan from this tab to check them now.', 'vigilante' ),
                );
                $repair  = false;
                break;
            default:
                $key     = 'unknown';
                $title   = __( 'Finding in Vigilant own files', 'vigilante' );
                $meaning = __( 'Vigilant reported something about its own files that this version has no explanation for.', 'vigilante' );
                $steps   = self::repair_steps();
                break;
        }

        return array(
            'key'     => $key,
            'title'   => $title,
            'meaning' => $meaning,
            'steps'   => $steps,
            'repair'  => $repair,
        );
    }
}
