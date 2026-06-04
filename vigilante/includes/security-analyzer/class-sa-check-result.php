<?php
/**
 * Security Analyzer — Check result value object.
 *
 * Represents the outcome of a single check inside the Security Analyzer.
 * Categories return arrays of these, the orchestrator aggregates them
 * into the scan report.
 *
 * @package Vigilante
 * @since   2.1.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Immutable-ish value object describing a single analyzer check result.
 *
 * Lightweight on purpose — just a typed container so category classes
 * don't return nested associative arrays with inconsistent keys.
 */
class Vigilante_SA_Check_Result {

    /**
     * State constants.
     */
    const STATE_PASS = 'pass'; // Check fully passed.
    const STATE_WARN = 'warn'; // Partial / non-critical issue.
    const STATE_FAIL = 'fail'; // Check failed.
    const STATE_INFO = 'info'; // Informational (no score impact, e.g. theme version).
    const STATE_SKIP = 'skip'; // Could not evaluate (no network, permission issue).

    /**
     * Unique ID (e.g. "csp", "admin_username"). Matches catalog key.
     *
     * @var string
     */
    public $id;

    /**
     * Category slug (ssl, headers, wp_exposure, access, files, internal).
     *
     * @var string
     */
    public $category;

    /**
     * Current state (pass/warn/fail/info/skip).
     *
     * @var string
     */
    public $state;

    /**
     * Points awarded on this run (0..max).
     *
     * @var int
     */
    public $score;

    /**
     * Maximum points this check can award.
     *
     * @var int
     */
    public $max;

    /**
     * Translated short label (e.g. "HTTPS enabled").
     *
     * @var string
     */
    public $label;

    /**
     * Translated longer detail explaining the result.
     *
     * @var string
     */
    public $detail;

    /**
     * Admin URL linking to the relevant setting, or empty string if none.
     *
     * @var string
     */
    public $fix_link;

    /**
     * Optional extra payload (e.g. expiry days, current value). Serializable scalars only.
     *
     * @var array
     */
    public $data;

    /**
     * Constructor.
     *
     * @param array $args Keys: id, category, state, score, max, label, detail, fix_link, data.
     */
    public function __construct( array $args ) {
        $this->id       = isset( $args['id'] ) ? (string) $args['id'] : '';
        $this->category = isset( $args['category'] ) ? (string) $args['category'] : '';
        $this->state    = isset( $args['state'] ) ? (string) $args['state'] : self::STATE_SKIP;
        $this->score    = isset( $args['score'] ) ? (int) $args['score'] : 0;
        $this->max      = isset( $args['max'] ) ? (int) $args['max'] : 0;
        $this->label    = isset( $args['label'] ) ? (string) $args['label'] : '';
        $this->detail   = isset( $args['detail'] ) ? (string) $args['detail'] : '';
        $this->fix_link = isset( $args['fix_link'] ) ? (string) $args['fix_link'] : '';
        $this->data     = isset( $args['data'] ) && is_array( $args['data'] ) ? $args['data'] : array();

        // Clamp score within [0, max].
        if ( $this->score < 0 ) {
            $this->score = 0;
        }
        if ( $this->max > 0 && $this->score > $this->max ) {
            $this->score = $this->max;
        }
    }

    /**
     * Serialize to array for persistence/JSON.
     *
     * @return array
     */
    public function to_array() {
        return array(
            'id'       => $this->id,
            'category' => $this->category,
            'state'    => $this->state,
            'score'    => $this->score,
            'max'      => $this->max,
            'label'    => $this->label,
            'detail'   => $this->detail,
            'fix_link' => $this->fix_link,
            'data'     => $this->data,
        );
    }

    /**
     * Whether this result should influence the aggregate score.
     * INFO results are always excluded; SKIP results award nothing and max is ignored
     * so they don't unfairly drag the score down when the analyzer couldn't evaluate.
     *
     * @return bool
     */
    public function counts_for_score() {
        return self::STATE_INFO !== $this->state && self::STATE_SKIP !== $this->state;
    }

    /**
     * Shorthand constructors keep category classes readable.
     */
    public static function pass( $args ) {
        $args['state'] = self::STATE_PASS;
        if ( ! isset( $args['score'] ) && isset( $args['max'] ) ) {
            $args['score'] = $args['max'];
        }
        return new self( $args );
    }

    public static function warn( $args ) {
        $args['state'] = self::STATE_WARN;
        // Warn awards half points by default if not explicitly set.
        if ( ! isset( $args['score'] ) && isset( $args['max'] ) ) {
            $args['score'] = (int) floor( $args['max'] / 2 );
        }
        return new self( $args );
    }

    public static function fail( $args ) {
        $args['state'] = self::STATE_FAIL;
        $args['score'] = 0;
        return new self( $args );
    }

    public static function info( $args ) {
        $args['state'] = self::STATE_INFO;
        $args['score'] = 0;
        $args['max']   = 0;
        return new self( $args );
    }

    public static function skip( $args ) {
        $args['state'] = self::STATE_SKIP;
        $args['score'] = 0;
        return new self( $args );
    }
}
