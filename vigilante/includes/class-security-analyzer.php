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
    // Legacy constant kept for backward compatibility. The real source of truth
    // is total_max_points(), which sums the declared "max" of every category
    // in get_categories(). Bump this only when manually verifying the sum.
    const TOTAL_MAX_POINTS    = 106;
    const REGRESSION_THRESHOLD = 10; // Points dropped before sending the alert email.

    /**
     * Sum of the declared "max" of every category. This is the canonical
     * maximum a scan can earn. Using this instead of the constant prevents
     * the desync we hit in 2.6.0 (a new check raised the internal category
     * max but the global total stayed at the pre-bump value).
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
                'max'   => 18,
            ),
            'access'      => array(
                'slug'  => 'access',
                'label' => __( 'Access & Authentication', 'vigilante' ),
                'max'   => 20,
            ),
            'files'       => array(
                'slug'  => 'files',
                'label' => __( 'Sensitive Files', 'vigilante' ),
                'max'   => 10,
            ),
            'internal'    => array(
                'slug'  => 'internal',
                'label' => __( 'Internal Checks (exclusive)', 'vigilante' ),
                // Sum of the max values of every check in
                // Vigilante_SA_Category_Internal. Update when adding/removing
                // checks or changing their max value.
                'max'   => 30,
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
        if ( 'all' === $phase || 'slow' === $phase ) {
            $this->push_history( $report );
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
        $cat_meta = self::get_categories();

        $categories = array();
        foreach ( $cat_meta as $slug => $meta ) {
            $categories[ $slug ] = array(
                'slug'   => $slug,
                'label'  => $meta['label'],
                'max'    => $meta['max'],
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

        $total_earned = 0;
        $total_max    = 0;
        $counts       = array(
            'pass' => 0,
            'warn' => 0,
            'fail' => 0,
            'info' => 0,
            'skip' => 0,
        );

        foreach ( $results as $r ) {
            if ( ! ( $r instanceof Vigilante_SA_Check_Result ) ) {
                continue;
            }
            $slug = $r->category;
            if ( ! isset( $categories[ $slug ] ) ) {
                continue;
            }
            $categories[ $slug ]['checks'][]             = $r->to_array();
            $categories[ $slug ]['counts'][ $r->state ]  = isset( $categories[ $slug ]['counts'][ $r->state ] )
                ? $categories[ $slug ]['counts'][ $r->state ] + 1
                : 1;
            $counts[ $r->state ] = isset( $counts[ $r->state ] ) ? $counts[ $r->state ] + 1 : 1;

            if ( $r->counts_for_score() ) {
                $categories[ $slug ]['earned'] += $r->score;
                $total_earned                  += $r->score;
                $total_max                     += $r->max;
            }
        }

        // Normalize against the declared category max so skipped checks don't erode the score.
        $declared_max = self::total_max_points();
        $grade        = Vigilante_SA_Helpers::compute_grade( $total_earned, $declared_max );

        return array(
            'ran_at'         => $started,
            'phase'          => $phase,
            'total_earned'   => $total_earned,
            'total_max'      => $declared_max,
            'total_evaluated'=> $total_max, // Actual evaluated max (excluding skipped).
            'score'          => $grade['score'],
            'grade'          => $grade['grade'],
            'counts'         => $counts,
            'categories'     => $categories,
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

        // Recompute totals from the merged categories.
        $rebuilt         = $this->rebuild_from_categories( $existing['categories'] );
        $existing        = array_merge( $existing, $rebuilt );
        $existing['ran_at']  = $report['ran_at'];
        $existing['phase']   = $phase;
        $existing['elapsed'] = isset( $report['elapsed'] ) ? $report['elapsed'] : 0;

        update_option( self::OPTION_LAST_SCAN, $existing, false );
    }

    /**
     * Recompute totals and grade from a categories array (used when merging phases).
     *
     * @param array $categories
     * @return array subset with total_earned, total_max, total_evaluated, score, grade, counts.
     */
    private function rebuild_from_categories( array $categories ) {
        $total_earned     = 0;
        $total_evaluated  = 0;
        $counts           = array(
            'pass' => 0,
            'warn' => 0,
            'fail' => 0,
            'info' => 0,
            'skip' => 0,
        );

        // Resolve the canonical "max" of every category from the declared meta.
        // Without this, merging fast/slow phases preserves a stale "max" from
        // the previous scan, which is what produced the 28/22 desync after
        // 2.6.0 added the closed_plugins check.
        $cat_meta = self::get_categories();

        foreach ( $categories as $slug => $cat ) {
            $cat_earned = 0;
            $cat_counts = array(
                'pass' => 0,
                'warn' => 0,
                'fail' => 0,
                'info' => 0,
                'skip' => 0,
            );
            foreach ( (array) $cat['checks'] as $c ) {
                $state = isset( $c['state'] ) ? $c['state'] : Vigilante_SA_Check_Result::STATE_SKIP;
                $cat_counts[ $state ] = isset( $cat_counts[ $state ] ) ? $cat_counts[ $state ] + 1 : 1;
                $counts[ $state ]     = isset( $counts[ $state ] ) ? $counts[ $state ] + 1 : 1;

                if ( Vigilante_SA_Check_Result::STATE_INFO === $state || Vigilante_SA_Check_Result::STATE_SKIP === $state ) {
                    continue;
                }
                $cat_earned      += isset( $c['score'] ) ? (int) $c['score'] : 0;
                $total_earned    += isset( $c['score'] ) ? (int) $c['score'] : 0;
                $total_evaluated += isset( $c['max'] ) ? (int) $c['max'] : 0;
            }
            $categories[ $slug ]['earned'] = $cat_earned;
            $categories[ $slug ]['counts'] = $cat_counts;

            // Force the canonical max so old cached scans get repaired the
            // moment they're touched (no need to wait for a clean "all" phase).
            if ( isset( $cat_meta[ $slug ]['max'] ) ) {
                $categories[ $slug ]['max'] = (int) $cat_meta[ $slug ]['max'];
            }
        }

        $total_max = self::total_max_points();
        $grade     = Vigilante_SA_Helpers::compute_grade( $total_earned, $total_max );

        return array(
            'categories'     => $categories,
            'total_earned'   => $total_earned,
            'total_max'      => $total_max,
            'total_evaluated'=> $total_evaluated,
            'score'          => $grade['score'],
            'grade'          => $grade['grade'],
            'counts'         => $counts,
        );
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
        return $raw;
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
