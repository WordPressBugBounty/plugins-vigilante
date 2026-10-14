<?php
/**
 * Security Analyzer — Orchestrator.
 *
 * Runs the six check categories, aggregates their results into a scored
 * report, persists the result and history, and powers the weekly cron
 * with a regression-based email digest.
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Main entry point for the Security Analyzer.
 *
 * Lazy-loaded — instantiated from AJAX handlers and the weekly cron, not from
 * Vigilante_Main::init_modules(), so the analyzer never runs on front-end hits.
 */
class Vigilante_Security_Analyzer {

    const OPTION_LAST_SCAN    = 'vigilante_analyzer_last_scan';
    const OPTION_HISTORY      = 'vigilante_analyzer_history';
    const OPTION_FIX_LOG      = 'vigilante_analyzer_fix_log';
    const HISTORY_LIMIT       = 30;
    const REGRESSION_THRESHOLD = 10; // Points dropped before sending the alert email.
    /*
     * Highest score a site can show while the self-protection check reports
     * tampering: every other result of this report was computed by the same
     * code whose files were reported as changed, so a high number next to it
     * would be a lie. 29 sits inside grade E of
     * Vigilante_SA_Helpers::grade_for_score().
     */
    const SCORE_CAP_ON_TAMPER = 29;

    /**
     * Sum of the declared "max" of every category: what a scan earns when
     * every check can be measured. It is what the widget shows before the
     * first scan. A report is graded against what it did measure, which
     * summarize_categories() adds up from the checks themselves.
     *
     * @return int
     */
    public static function total_max_points() {
        $total = 0;
        foreach ( self::get_categories() as $meta ) {
            $total += (int) $meta['max'];
        }
        return $total;
    }

    /**
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * @var Vigilante_Activity_Log|null
     */
    private $activity_log;

    /**
     * Metadata about each category used by the UI (label + weight).
     *
     * @return array<string,array{slug:string,label:string,max:int}>
     */
    public static function get_categories() {
        return array(
            'ssl'         => array(
                'slug'  => 'ssl',
                'label' => __( 'SSL / TLS', 'vigilante' ),
                'max'   => 12,
            ),
            'headers'     => array(
                'slug'  => 'headers',
                'label' => __( 'HTTP Security Headers', 'vigilante' ),
                'max'   => 18,
            ),
            'wp_exposure' => array(
                'slug'  => 'wp_exposure',
                'label' => __( 'WordPress Exposure', 'vigilante' ),
                // 18 -> 13: the active theme row is informational now. Whether
                // the theme has an update pending is already scored by the
                // theme_updates check of the internal category.
                'max'   => 13,
            ),
            'access'      => array(
                'slug'  => 'access',
                'label' => __( 'Access & Authentication', 'vigilante' ),
                'max'   => 18,
            ),
            'files'       => array(
                'slug'  => 'files',
                'label' => __( 'Sensitive Files', 'vigilante' ),
                // 3.0.7: 10 -> 9 (wp_cron_public became informative).
                'max'   => 9,
            ),
            'internal'    => array(
                'slug'  => 'internal',
                'label' => __( 'Internal Checks (exclusive)', 'vigilante' ),
                // Sum of the max values of every check in
                // Vigilante_SA_Category_Internal. Update when adding/removing
                // checks or changing their max value.
                // 3.0.0: 30 -> 40 (self_integrity check added, worth 10: the
                // integrity of the plugin that runs every other check).
                'max'   => 40,
            ),
            'reputation'  => array(
                'slug'     => 'reputation',
                'label'    => __( 'Reputation / Blacklists', 'vigilante' ),
                'max'      => 0,
                'info_only' => true,
            ),
        );
    }

    /**
     * @param Vigilante_Settings         $settings
     * @param Vigilante_Activity_Log|null $activity_log
     */
    public function __construct( Vigilante_Settings $settings, $activity_log = null ) {
        $this->settings     = $settings;
        $this->activity_log = $activity_log;
        $this->require_dependencies();
    }

    /**
     * Load category + helper classes (one-time per request).
     */
    private function require_dependencies() {
        $dir = VIGILANTE_INCLUDES_DIR . 'security-analyzer/';
        require_once $dir . 'class-sa-check-result.php';
        require_once $dir . 'class-sa-helpers.php';
        require_once $dir . 'class-sa-category-ssl.php';
        require_once $dir . 'class-sa-category-headers.php';
        require_once $dir . 'class-sa-category-wp-exposure.php';
        require_once $dir . 'class-sa-category-access.php';
        require_once $dir . 'class-sa-category-files.php';
        require_once $dir . 'class-sa-category-internal.php';
        require_once $dir . 'class-sa-category-reputation.php';
    }

    /**
     * Run the scan in the requested phase and return the aggregated report.
     *
     * @param string $phase 'fast' | 'slow' | 'all'.
     * @return array Report (see build_report()).
     */
    public function run_scan( $phase = 'all' ) {
        if ( ! in_array( $phase, array( 'fast', 'slow', 'all' ), true ) ) {
            $phase = 'all';
        }

        Vigilante_SA_Helpers::reset_cache();
        $started = time();

        $results = array();

        $cat_ssl     = new Vigilante_SA_Category_SSL( $this->settings );
        $cat_headers = new Vigilante_SA_Category_Headers( $this->settings );
        $cat_expose  = new Vigilante_SA_Category_WP_Exposure( $this->settings );
        $cat_access  = new Vigilante_SA_Category_Access( $this->settings );
        $cat_files   = new Vigilante_SA_Category_Files( $this->settings );
        $cat_intern  = new Vigilante_SA_Category_Internal( $this->settings, $this->activity_log );
        $cat_reput   = new Vigilante_SA_Category_Reputation( $this->settings );

        foreach ( $cat_ssl->run( $phase ) as $r ) {
            $results[] = $r;
        }
        foreach ( $cat_headers->run( $phase ) as $r ) {
            $results[] = $r;
        }
        foreach ( $cat_expose->run( $phase ) as $r ) {
            $results[] = $r;
        }
        foreach ( $cat_access->run( $phase ) as $r ) {
            $results[] = $r;
        }
        foreach ( $cat_files->run( $phase ) as $r ) {
            $results[] = $r;
        }
        foreach ( $cat_intern->run( $phase ) as $r ) {
            $results[] = $r;
        }
        foreach ( $cat_reput->run( $phase ) as $r ) {
            $results[] = $r;
        }

        $report            = $this->build_report( $results, $phase, $started );
        $report['ran_at']  = $started;
        $report['phase']   = $phase;
        $report['elapsed'] = max( 0, time() - $started );

        // Merge-persist: 'fast' and 'slow' phases each update part of the report;
        // 'all' replaces everything. Dashboard widget shows whatever's latest.
        $this->persist_scan( $report, $phase );

        // Push to history only when the whole scan has finished (either 'all' in one call,
        // or a 'slow' phase that immediately follows a 'fast' phase within the same minute).
        if ( 'all' === $phase ) {
            $this->push_history( $report );
        } elseif ( 'slow' === $phase ) {
            // The slow phase closes a scan the fast one started, so what goes
            // to the history is the two merged, as persist_scan() has just
            // stored them. The report of this phase alone carries only its own
            // checks, and the trend showed every manual scan as a collapse.
            $this->push_history( $this->get_last_scan() );
        }

        return $report;
    }

    /**
     * Aggregate check results into the scan report structure.
     *
     * @param Vigilante_SA_Check_Result[] $results
     * @param string                       $phase
     * @param int                          $started Unix timestamp.
     * @return array
     */
    private function build_report( $results, $phase, $started ) {
        $categories = array();
        foreach ( self::get_categories() as $slug => $meta ) {
            $categories[ $slug ] = array(
                'slug'   => $slug,
                'label'  => $meta['label'],
                'max'    => 0,
                'earned' => 0,
                'checks' => array(),
                'counts' => array(
                    'pass' => 0,
                    'warn' => 0,
                    'fail' => 0,
                    'info' => 0,
                    'skip' => 0,
                ),
            );
        }

        foreach ( $results as $r ) {
            if ( ! ( $r instanceof Vigilante_SA_Check_Result ) || ! isset( $categories[ $r->category ] ) ) {
                continue;
            }
            $categories[ $r->category ]['checks'][] = $r->to_array();
        }

        return array_merge(
            array(
                'ran_at' => $started,
                'phase'  => $phase,
            ),
            self::summarize_categories( $categories )
        );
    }

    /**
     * Merge the new partial/full scan with whatever was last persisted.
     * Fast + slow phases arrive separately from the UI; we store a consistent
     * merged report so reloading the Dashboard shows complete data.
     *
     * @param array  $report
     * @param string $phase
     */
    private function persist_scan( array $report, $phase ) {
        if ( 'all' === $phase ) {
            update_option( self::OPTION_LAST_SCAN, $report, false );
            return;
        }

        $existing = $this->get_last_scan();
        if ( ! is_array( $existing ) ) {
            update_option( self::OPTION_LAST_SCAN, $report, false );
            return;
        }

        // Merge: only replace categories whose checks are actually present in the new phase.
        foreach ( $report['categories'] as $slug => $cat ) {
            if ( empty( $cat['checks'] ) ) {
                continue;
            }
            // Track which check ids were produced now so we can overwrite them selectively.
            $new_ids = array();
            foreach ( $cat['checks'] as $c ) {
                if ( isset( $c['id'] ) ) {
                    $new_ids[ $c['id'] ] = true;
                }
            }

            // Start from existing category bucket (preserve other-phase checks).
            if ( ! isset( $existing['categories'][ $slug ] ) ) {
                $existing['categories'][ $slug ] = $cat;
                continue;
            }
            $merged_checks = array();
            foreach ( (array) $existing['categories'][ $slug ]['checks'] as $old_c ) {
                if ( isset( $old_c['id'] ) && isset( $new_ids[ $old_c['id'] ] ) ) {
                    continue; // Will be replaced below.
                }
                $merged_checks[] = $old_c;
            }
            foreach ( $cat['checks'] as $new_c ) {
                $merged_checks[] = $new_c;
            }
            $existing['categories'][ $slug ]['checks'] = $merged_checks;
        }

        // Recompute totals from the merged categories, with the ones that have
        // not run yet in their place: the loop above only copies those that
        // came with checks.
        $rebuilt         = self::summarize_categories( self::with_every_category( $existing['categories'] ) );
        $existing        = array_merge( $existing, $rebuilt );
        $existing['ran_at']  = $report['ran_at'];
        $existing['phase']   = $phase;
        $existing['elapsed'] = isset( $report['elapsed'] ) ? $report['elapsed'] : 0;

        update_option( self::OPTION_LAST_SCAN, $existing, false );
    }

    /**
     * Totals, counts and grade of a set of categories, added up from their checks
     *
     * The one place where a report is scored: a fresh scan, two phases merged
     * and a stored report read back all go through here.
     *
     * A check that could not be measured (skip) and one that is only
     * informative (info) are left out of both sides of the fraction, in their
     * category and in the total. Until 3.0.4 the score was divided by the
     * declared maximum of every category, so each of them counted as a zero:
     * a probe that timed out lowered the score as if the check had failed, and
     * a site that had switched COOP off on purpose could not reach 100. The
     * maximum of a category is therefore the sum of the checks it did score,
     * which also means it cannot drift from them when a check is added.
     *
     * A category none of whose checks has run yet is another matter: the scan
     * is not finished. It counts with its declared maximum and nothing earned,
     * or a first scan whose remote phase never arrives (a timeout, a closed
     * tab) would be graded over the local checks alone and read better than a
     * finished one.
     *
     * @since 3.0.5
     *
     * @param array $categories Categories with their checks.
     * @return array categories, total_earned, total_max, total_evaluated, score, grade, capped_by, counts.
     */
    public static function summarize_categories( array $categories ) {
        $total_earned = 0;
        $total_max    = 0;
        $capped_by    = '';
        $counts       = array(
            'pass' => 0,
            'warn' => 0,
            'fail' => 0,
            'info' => 0,
            'skip' => 0,
        );

        $declared = self::get_categories();
        $started  = false;
        foreach ( $categories as $cat ) {
            if ( is_array( $cat ) && ! empty( $cat['checks'] ) ) {
                $started = true;
                break;
            }
        }

        foreach ( $categories as $slug => $cat ) {
            $cat_earned = 0;
            $cat_max    = 0;
            $cat_counts = array(
                'pass' => 0,
                'warn' => 0,
                'fail' => 0,
                'info' => 0,
                'skip' => 0,
            );
            $checks     = ( is_array( $cat ) && isset( $cat['checks'] ) ) ? (array) $cat['checks'] : array();

            // Not run yet, in a scan that has started: pending, in full.
            if ( empty( $checks ) && $started && isset( $declared[ $slug ] ) && empty( $declared[ $slug ]['info_only'] ) ) {
                $cat_max = (int) $declared[ $slug ]['max'];
            }

            foreach ( $checks as $c ) {
                $state = isset( $c['state'] ) ? (string) $c['state'] : Vigilante_SA_Check_Result::STATE_SKIP;
                $cat_counts[ $state ] = isset( $cat_counts[ $state ] ) ? $cat_counts[ $state ] + 1 : 1;
                $counts[ $state ]     = isset( $counts[ $state ] ) ? $counts[ $state ] + 1 : 1;

                // Self-protection caps the score (see SCORE_CAP_ON_TAMPER).
                if ( 'self_integrity' === ( isset( $c['id'] ) ? $c['id'] : '' )
                    && Vigilante_SA_Check_Result::STATE_FAIL === $state ) {
                    $capped_by = 'self_integrity';
                }

                if ( Vigilante_SA_Check_Result::STATE_INFO === $state || Vigilante_SA_Check_Result::STATE_SKIP === $state ) {
                    continue;
                }
                $cat_earned += isset( $c['score'] ) ? (int) $c['score'] : 0;
                $cat_max    += isset( $c['max'] ) ? (int) $c['max'] : 0;
            }

            if ( ! is_array( $cat ) ) {
                $categories[ $slug ] = array();
            }
            $categories[ $slug ]['earned'] = $cat_earned;
            $categories[ $slug ]['max']    = $cat_max;
            $categories[ $slug ]['counts'] = $cat_counts;

            $total_earned += $cat_earned;
            $total_max    += $cat_max;
        }

        $grade = Vigilante_SA_Helpers::compute_grade( $total_earned, $total_max );

        if ( 'self_integrity' === $capped_by && $grade['score'] > self::SCORE_CAP_ON_TAMPER ) {
            $grade['score'] = self::SCORE_CAP_ON_TAMPER;
            $grade['grade'] = Vigilante_SA_Helpers::grade_for_score( self::SCORE_CAP_ON_TAMPER );
        }

        return array(
            'categories'      => $categories,
            'total_earned'    => $total_earned,
            'total_max'       => $total_max,
            // Same figure as total_max since 3.0.5, kept for whoever reads it.
            'total_evaluated' => $total_max,
            'score'           => $grade['score'],
            'grade'           => $grade['grade'],
            'capped_by'       => $capped_by,
            'counts'          => $counts,
        );
    }

    /**
     * The categories of a report, with every declared one present
     *
     * A report stored after the local phase alone only holds the categories
     * that phase filled, and summarize_categories() can only count as pending
     * a category it is given. Without this, a first scan whose remote phase
     * never arrived was graded over the four categories it had: 100 over 85
     * points where the whole report gives 75 over 113. Found by the second
     * cross review of 3.0.5.
     *
     * @since 3.0.5
     *
     * @param array $categories Categories of a stored or merged report.
     * @return array The same, plus an empty entry for each one that was missing.
     */
    private static function with_every_category( array $categories ) {
        foreach ( self::get_categories() as $slug => $meta ) {
            if ( isset( $categories[ $slug ] ) && is_array( $categories[ $slug ] ) ) {
                continue;
            }
            $categories[ $slug ] = array(
                'slug'   => $slug,
                'label'  => $meta['label'],
                'max'    => 0,
                'earned' => 0,
                'checks' => array(),
            );
        }

        return $categories;
    }

    /**
     * Append a minimal history entry (no per-check detail) to the circular buffer.
     *
     * @param array $report
     */
    private function push_history( array $report ) {
        $history = $this->get_score_history( self::HISTORY_LIMIT );
        if ( ! is_array( $history ) ) {
            $history = array();
        }

        $entry = array(
            'ran_at'       => (int) $report['ran_at'],
            'score'        => (int) $report['score'],
            'grade'        => (string) $report['grade'],
            'total_earned' => (int) $report['total_earned'],
            'categories'   => array(),
        );
        foreach ( $report['categories'] as $slug => $cat ) {
            $entry['categories'][ $slug ] = array(
                'earned' => (int) $cat['earned'],
                'max'    => (int) $cat['max'],
            );
        }

        $history[] = $entry;
        if ( count( $history ) > self::HISTORY_LIMIT ) {
            $history = array_slice( $history, -self::HISTORY_LIMIT );
        }
        update_option( self::OPTION_HISTORY, $history, false );
    }

    /**
     * Return the last persisted scan, or an empty placeholder structure.
     *
     * @return array
     */
    public function get_last_scan() {
        $raw = get_option( self::OPTION_LAST_SCAN, null );
        if ( ! is_array( $raw ) ) {
            return array(
                'ran_at'       => 0,
                'score'        => 0,
                'grade'        => '',
                'total_earned' => 0,
                'total_max'    => self::total_max_points(),
                'counts'       => array(
                    'pass' => 0,
                    'warn' => 0,
                    'fail' => 0,
                    'info' => 0,
                    'skip' => 0,
                ),
                'categories'   => array(),
            );
        }

        // A stored report is read back under the rules in force: its checks
        // are the ones that ran, and what they add up to and the letter they
        // earn are worked out now. Otherwise the widget would show the sum
        // and the letter of the version that stored it until the next scan,
        // and the weekly comparison would set a score against one worked out
        // differently.
        if ( isset( $raw['categories'] ) && is_array( $raw['categories'] ) ) {
            $raw['categories'] = self::retire_stored_rows( $raw['categories'] );
            $raw = array_merge( $raw, self::summarize_categories( self::with_every_category( $raw['categories'] ) ) );
        }

        return $raw;
    }

    /**
     * Rows stored by an earlier version for a check that no longer scores
     *
     * The wp-cron.php row scored until 3.0.6, and its text and its Fix link
     * sent the reader to "Protect wp-cron.php", a setting that no longer
     * exists. A report stored before the update is read back until the next
     * scan, so that row is shown as what it is now: information, with no
     * points, no link and a text that says how to refresh it.
     *
     * @since 3.0.7
     *
     * @param array $categories Stored categories.
     * @return array
     */
    private static function retire_stored_rows( array $categories ) {
        foreach ( $categories as $slug => $cat ) {
            if ( ! is_array( $cat ) || empty( $cat['checks'] ) || ! is_array( $cat['checks'] ) ) {
                continue;
            }

            foreach ( $cat['checks'] as $i => $check ) {
                if ( ! is_array( $check ) || ! isset( $check['id'], $check['state'] ) || 'wp_cron_public' !== $check['id'] ) {
                    continue;
                }

                if ( in_array( $check['state'], array( Vigilante_SA_Check_Result::STATE_INFO, Vigilante_SA_Check_Result::STATE_SKIP ), true ) ) {
                    continue;
                }

                $categories[ $slug ]['checks'][ $i ]['state']    = Vigilante_SA_Check_Result::STATE_INFO;
                $categories[ $slug ]['checks'][ $i ]['score']    = 0;
                $categories[ $slug ]['checks'][ $i ]['max']      = 0;
                $categories[ $slug ]['checks'][ $i ]['fix_link'] = '';
                $categories[ $slug ]['checks'][ $i ]['detail']   = __( 'This row no longer scores. Run Security Check again to see what wp-cron.php answers now.', 'vigilante' );
            }
        }

        return $categories;
    }

    /**
     * Return history (oldest first, max = HISTORY_LIMIT).
     *
     * @param int $limit
     * @return array
     */
    public function get_score_history( $limit = self::HISTORY_LIMIT ) {
        $raw = get_option( self::OPTION_HISTORY, array() );
        if ( ! is_array( $raw ) ) {
            return array();
        }
        $limit = max( 1, (int) $limit );
        return array_slice( $raw, -$limit );
    }

    /**
     * Return the catalog for UI (check labels, max points, fix links).
     * Built from a single dry-run to avoid maintaining a duplicate mapping.
     *
     * @return array
     */
    public function get_catalog() {
        $cats = self::get_categories();
        $out  = array();
        foreach ( $cats as $slug => $meta ) {
            $out[ $slug ] = array(
                'slug'   => $slug,
                'label'  => $meta['label'],
                'max'    => $meta['max'],
                'checks' => array(),
            );
        }
        return $out;
    }

    /**
     * Weekly cron handler — run a full scan and email the admin when the score
     * has dropped by >= REGRESSION_THRESHOLD points vs the previous history entry,
     * or when new critical failures appeared.
     */
    public function cron_weekly_scan() {
        $previous = $this->get_last_scan();
        $report   = $this->run_scan( 'all' );

        // Bail if notifications aren't wanted.
        $analyzer_settings = (array) $this->settings->get_section( 'security_analyzer' );
        $weekly_enabled    = ! isset( $analyzer_settings['weekly_scan_enabled'] ) || ! empty( $analyzer_settings['weekly_scan_enabled'] );
        $email_enabled     = ! empty( $analyzer_settings['email_on_regression'] );

        if ( ! $weekly_enabled || ! $email_enabled ) {
            return;
        }

        if ( empty( $previous['score'] ) ) {
            return; // First run: never email.
        }

        $delta = (int) $previous['score'] - (int) $report['score'];
        $new_fails = $this->diff_new_failures( $previous, $report );

        if ( $delta < self::REGRESSION_THRESHOLD && empty( $new_fails ) ) {
            return;
        }

        $this->send_regression_email( $previous, $report, $new_fails );
    }

    /**
     * Collect check ids that are FAIL now but weren't FAIL (were PASS/WARN/INFO/SKIP) before.
     *
     * @param array $prev
     * @param array $curr
     * @return array<int,array{label:string,category:string,id:string}>
     */
    private function diff_new_failures( array $prev, array $curr ) {
        $prev_states = array();
        foreach ( (array) ( $prev['categories'] ?? array() ) as $slug => $cat ) {
            foreach ( (array) ( $cat['checks'] ?? array() ) as $c ) {
                if ( isset( $c['id'] ) ) {
                    $prev_states[ $c['id'] ] = isset( $c['state'] ) ? $c['state'] : '';
                }
            }
        }

        $diffs = array();
        foreach ( (array) ( $curr['categories'] ?? array() ) as $slug => $cat ) {
            foreach ( (array) ( $cat['checks'] ?? array() ) as $c ) {
                if ( ! isset( $c['id'], $c['state'] ) ) {
                    continue;
                }
                if ( Vigilante_SA_Check_Result::STATE_FAIL !== $c['state'] ) {
                    continue;
                }
                $was = isset( $prev_states[ $c['id'] ] ) ? $prev_states[ $c['id'] ] : '';
                if ( Vigilante_SA_Check_Result::STATE_FAIL === $was ) {
                    continue;
                }
                $diffs[] = array(
                    'id'       => $c['id'],
                    'label'    => isset( $c['label'] ) ? $c['label'] : $c['id'],
                    'category' => $slug,
                );
            }
        }
        return $diffs;
    }

    /**
     * Send the regression alert email.
     *
     * @param array $prev      Previous scan.
     * @param array $curr      Current scan.
     * @param array $new_fails New failures diff.
     */
    private function send_regression_email( array $prev, array $curr, array $new_fails ) {
        if ( ! class_exists( 'Vigilante_Email_Template' ) ) {
            require_once VIGILANTE_INCLUDES_DIR . 'class-email-template.php';
        }

        $to = Vigilante_Email_Template::get_admin_recipients();
        if ( empty( $to ) ) {
            return;
        }

        $subject = sprintf(
            /* translators: 1: previous grade, 2: previous score, 3: current grade, 4: current score */
            __( '[Vigilant] Security Score dropped from %1$s (%2$d) to %3$s (%4$d)', 'vigilante' ),
            $prev['grade'],
            (int) $prev['score'],
            $curr['grade'],
            (int) $curr['score']
        );

        $body  = '<p>' . esc_html(
            sprintf(
                /* translators: 1: site name */
                __( 'Vigilant ran the weekly Security Check on %s and the result changed.', 'vigilante' ),
                get_bloginfo( 'name' )
            )
        ) . '</p>';

        $body .= Vigilante_Email_Template::data_table(
            array(
                __( 'Previous Score', 'vigilante' ) => $prev['grade'] . ' — ' . (int) $prev['score'] . '/100',
                __( 'Current Score', 'vigilante' )  => $curr['grade'] . ' — ' . (int) $curr['score'] . '/100',
                __( 'Points lost', 'vigilante' )    => (int) $prev['score'] - (int) $curr['score'],
                __( 'New failing checks', 'vigilante' ) => count( $new_fails ),
            )
        );

        if ( ! empty( $new_fails ) ) {
            $body .= '<h3>' . esc_html__( 'Checks that started failing', 'vigilante' ) . '</h3>';
            $body .= '<ul>';
            foreach ( $new_fails as $f ) {
                $body .= '<li><strong>' . esc_html( $f['label'] ) . '</strong> <em>(' . esc_html( $f['category'] ) . ')</em></li>';
            }
            $body .= '</ul>';
        }

        $report_url = admin_url( 'admin.php?page=vigilante&tab=dashboard#vigilante-analyzer' );
        $body      .= '<p><a href="' . esc_url( $report_url ) . '" style="display:inline-block;background:#2271b1;color:#fff;padding:8px 16px;text-decoration:none;border-radius:4px;">' . esc_html__( 'View full report', 'vigilante' ) . '</a></p>';

        Vigilante_Email_Template::send( $to, $subject, __( 'Security Check regression detected', 'vigilante' ), $body, true );
    }
}
