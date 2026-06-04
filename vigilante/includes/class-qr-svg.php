<?php
/**
 * QR Code SVG Generator
 *
 * Minimal QR code generator for TOTP URIs. Outputs SVG.
 * Supports byte mode, ECL L, versions 1-10.
 * No external dependencies, pure PHP.
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_QR_SVG
 *
 * Generates QR code as inline SVG string
 */
class Vigilante_QR_SVG {

    /**
     * GF(2^8) exponential table
     *
     * @var array
     */
    private $gf_exp = array();

    /**
     * GF(2^8) logarithm table
     *
     * @var array
     */
    private $gf_log = array();

    /**
     * QR modules matrix
     *
     * @var array
     */
    private $modules = array();

    /**
     * Function pattern mask (true = reserved module)
     *
     * @var array
     */
    private $reserved = array();

    /**
     * QR code size (modules per side)
     *
     * @var int
     */
    private $size = 0;

    /**
     * Data capacity per version at ECL L (byte mode)
     *
     * @var array
     */
    private static $capacity = array(
        1  => 17,
        2  => 32,
        3  => 53,
        4  => 78,
        5  => 106,
        6  => 134,
        7  => 154,
        8  => 192,
        9  => 230,
        10 => 271,
    );

    /**
     * Total data codewords per version at ECL L
     *
     * @var array
     */
    private static $total_codewords = array(
        1  => 19,
        2  => 34,
        3  => 55,
        4  => 80,
        5  => 108,
        6  => 136,
        7  => 156,
        8  => 194,
        9  => 232,
        10 => 274,
    );

    /**
     * EC codewords per block at ECL L
     *
     * @var array
     */
    private static $ec_codewords = array(
        1  => 7,
        2  => 10,
        3  => 15,
        4  => 20,
        5  => 26,
        6  => 18,
        7  => 20,
        8  => 24,
        9  => 30,
        10 => 18,
    );

    /**
     * Block structure at ECL L: array( [num_blocks_group1, dc_per_block_g1, num_blocks_group2, dc_per_block_g2] )
     *
     * @var array
     */
    private static $blocks = array(
        1  => array( 1, 19, 0, 0 ),
        2  => array( 1, 34, 0, 0 ),
        3  => array( 1, 55, 0, 0 ),
        4  => array( 1, 80, 0, 0 ),
        5  => array( 1, 108, 0, 0 ),
        6  => array( 2, 68, 0, 0 ),
        7  => array( 2, 78, 0, 0 ),
        8  => array( 2, 97, 0, 0 ),
        9  => array( 2, 116, 0, 0 ),
        10 => array( 2, 68, 2, 69 ),
    );

    /**
     * Alignment pattern center positions per version
     *
     * @var array
     */
    private static $alignment = array(
        2  => array( 6, 18 ),
        3  => array( 6, 22 ),
        4  => array( 6, 26 ),
        5  => array( 6, 30 ),
        6  => array( 6, 34 ),
        7  => array( 6, 22, 38 ),
        8  => array( 6, 24, 42 ),
        9  => array( 6, 26, 46 ),
        10 => array( 6, 28, 52 ),
    );

    /**
     * Constructor - initialize GF(2^8) tables
     */
    public function __construct() {
        $this->init_galois_field();
    }

    /**
     * Generate QR code as SVG string
     *
     * @param string $data    Data to encode.
     * @param int    $px_size Pixel size per module (default 4).
     * @param int    $margin  Quiet zone modules (default 4).
     * @return string SVG markup or empty string on failure.
     */
    public function generate( $data, $px_size = 4, $margin = 4 ) {
        if ( empty( $data ) ) {
            return '';
        }

        // Select version
        $version = $this->select_version( strlen( $data ) );
        if ( ! $version ) {
            return '';
        }

        $this->size = 17 + $version * 4;

        // Initialize matrix
        $this->modules  = array_fill( 0, $this->size, array_fill( 0, $this->size, null ) );
        $this->reserved = array_fill( 0, $this->size, array_fill( 0, $this->size, false ) );

        // Place function patterns
        $this->place_finder_patterns();
        $this->place_alignment_patterns( $version );
        $this->place_timing_patterns();
        $this->reserve_format_area();

        if ( $version >= 7 ) {
            $this->reserve_version_area();
        }

        // Encode data
        $encoded = $this->encode_data( $data, $version );
        if ( empty( $encoded ) ) {
            return '';
        }

        // Add error correction
        $final_data = $this->add_error_correction( $encoded, $version );

        // Place data bits
        $this->place_data_bits( $final_data );

        // Apply best mask
        $best_mask = $this->apply_best_mask();

        // Place format information
        $this->place_format_info( $best_mask );

        // Place version information
        if ( $version >= 7 ) {
            $this->place_version_info( $version );
        }

        // Generate SVG
        return $this->render_svg( $px_size, $margin );
    }

    /**
     * Initialize GF(2^8) exp and log tables with polynomial 0x11D
     */
    private function init_galois_field() {
        $x = 1;
        for ( $i = 0; $i < 255; $i++ ) {
            $this->gf_exp[ $i ] = $x;
            $this->gf_log[ $x ] = $i;
            $x <<= 1;
            if ( $x & 0x100 ) {
                $x ^= 0x11d;
            }
        }
        // Extend exp table for convenience
        for ( $i = 255; $i < 512; $i++ ) {
            $this->gf_exp[ $i ] = $this->gf_exp[ $i - 255 ];
        }
    }

    /**
     * Multiply two values in GF(2^8)
     *
     * @param int $a First value.
     * @param int $b Second value.
     * @return int Product.
     */
    private function gf_mul( $a, $b ) {
        if ( 0 === $a || 0 === $b ) {
            return 0;
        }
        return $this->gf_exp[ $this->gf_log[ $a ] + $this->gf_log[ $b ] ];
    }

    /**
     * Generate Reed-Solomon generator polynomial
     *
     * @param int $num_ec Number of EC codewords.
     * @return array Generator polynomial coefficients.
     */
    private function rs_generator( $num_ec ) {
        $gen = array( 1 );
        for ( $i = 0; $i < $num_ec; $i++ ) {
            $new_gen = array_fill( 0, count( $gen ) + 1, 0 );
            for ( $j = 0; $j < count( $gen ); $j++ ) {
                $new_gen[ $j ]     ^= $gen[ $j ];
                $new_gen[ $j + 1 ] ^= $this->gf_mul( $gen[ $j ], $this->gf_exp[ $i ] );
            }
            $gen = $new_gen;
        }
        return $gen;
    }

    /**
     * Reed-Solomon encode a data block
     *
     * @param array $data   Data codewords.
     * @param int   $num_ec Number of EC codewords.
     * @return array EC codewords.
     */
    private function rs_encode( $data, $num_ec ) {
        $gen = $this->rs_generator( $num_ec );
        $enc = array_merge( $data, array_fill( 0, $num_ec, 0 ) );

        for ( $i = 0; $i < count( $data ); $i++ ) {
            $coef = $enc[ $i ];
            if ( 0 !== $coef ) {
                for ( $j = 0; $j < count( $gen ); $j++ ) {
                    $enc[ $i + $j ] ^= $this->gf_mul( $gen[ $j ], $coef );
                }
            }
        }

        return array_slice( $enc, count( $data ) );
    }

    /**
     * Select minimum QR version for data length
     *
     * @param int $length Data length in bytes.
     * @return int|false Version number or false.
     */
    private function select_version( $length ) {
        foreach ( self::$capacity as $v => $cap ) {
            if ( $length <= $cap ) {
                return $v;
            }
        }
        return false;
    }

    /**
     * Encode data in byte mode
     *
     * @param string $data    Raw data string.
     * @param int    $version QR version.
     * @return array Codewords array.
     */
    private function encode_data( $data, $version ) {
        $bits = '';

        // Mode indicator: 0100 (byte mode)
        $bits .= '0100';

        // Character count indicator
        $cc_bits = $version <= 9 ? 8 : 16;
        $bits .= str_pad( decbin( strlen( $data ) ), $cc_bits, '0', STR_PAD_LEFT );

        // Data bytes
        for ( $i = 0; $i < strlen( $data ); $i++ ) {
            $bits .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
        }

        // Terminator (up to 4 bits)
        // $total_codewords already contains DATA codewords count (EC excluded)
        $total_dc = self::$total_codewords[ $version ];
        $max_bits = $total_dc * 8;

        $term_len = max( 0, min( 4, $max_bits - strlen( $bits ) ) );
        $bits .= str_repeat( '0', $term_len );

        // Pad to byte boundary
        if ( strlen( $bits ) % 8 !== 0 ) {
            $bits .= str_repeat( '0', 8 - ( strlen( $bits ) % 8 ) );
        }

        // Convert to codewords
        $codewords = array();
        for ( $i = 0; $i < strlen( $bits ); $i += 8 ) {
            $codewords[] = intval( substr( $bits, $i, 8 ), 2 );
        }

        // Pad with alternating 236/17 to fill capacity
        $pad = array( 236, 17 );
        $pad_idx = 0;
        while ( count( $codewords ) < $total_dc ) {
            $codewords[] = $pad[ $pad_idx % 2 ];
            $pad_idx++;
        }

        return $codewords;
    }

    /**
     * Get total number of blocks for a version
     *
     * @param int $version QR version.
     * @return int Total blocks.
     */
    private function get_total_blocks( $version ) {
        $b = self::$blocks[ $version ];
        return $b[0] + $b[2];
    }

    /**
     * Add error correction and interleave blocks
     *
     * @param array $data    Data codewords.
     * @param int   $version QR version.
     * @return array Final codeword sequence.
     */
    private function add_error_correction( $data, $version ) {
        $b      = self::$blocks[ $version ];
        $ec_per = self::$ec_codewords[ $version ];

        $data_blocks = array();
        $ec_blocks   = array();
        $offset      = 0;

        // Group 1
        for ( $i = 0; $i < $b[0]; $i++ ) {
            $block = array_slice( $data, $offset, $b[1] );
            $data_blocks[] = $block;
            $ec_blocks[]   = $this->rs_encode( $block, $ec_per );
            $offset += $b[1];
        }

        // Group 2
        for ( $i = 0; $i < $b[2]; $i++ ) {
            $block = array_slice( $data, $offset, $b[3] );
            $data_blocks[] = $block;
            $ec_blocks[]   = $this->rs_encode( $block, $ec_per );
            $offset += $b[3];
        }

        // Interleave data codewords
        $result   = array();
        $max_data = max( $b[1], $b[3] );
        for ( $i = 0; $i < $max_data; $i++ ) {
            foreach ( $data_blocks as $block ) {
                if ( $i < count( $block ) ) {
                    $result[] = $block[ $i ];
                }
            }
        }

        // Interleave EC codewords
        for ( $i = 0; $i < $ec_per; $i++ ) {
            foreach ( $ec_blocks as $block ) {
                if ( $i < count( $block ) ) {
                    $result[] = $block[ $i ];
                }
            }
        }

        // Add remainder bits (version-dependent)
        $remainder_bits = array( 0, 0, 7, 7, 7, 7, 0, 0, 0, 0, 0 );
        // Not added as codewords, but as bits during placement

        return $result;
    }

    /**
     * Place finder patterns at three corners
     */
    private function place_finder_patterns() {
        $positions = array(
            array( 0, 0 ),
            array( 0, $this->size - 7 ),
            array( $this->size - 7, 0 ),
        );

        foreach ( $positions as $pos ) {
            $r = $pos[0];
            $c = $pos[1];
            for ( $dr = 0; $dr < 7; $dr++ ) {
                for ( $dc = 0; $dc < 7; $dc++ ) {
                    $dark = ( 0 === $dr || 6 === $dr || 0 === $dc || 6 === $dc )
                         || ( $dr >= 2 && $dr <= 4 && $dc >= 2 && $dc <= 4 );
                    $this->set_module( $r + $dr, $c + $dc, $dark, true );
                }
            }
        }

        // Separators
        for ( $i = 0; $i < 8; $i++ ) {
            // Top-left
            $this->set_module( 7, $i, false, true );
            $this->set_module( $i, 7, false, true );
            // Top-right
            $this->set_module( 7, $this->size - 8 + $i, false, true );
            $this->set_module( $i, $this->size - 8, false, true );
            // Bottom-left
            $this->set_module( $this->size - 8, $i, false, true );
            $this->set_module( $this->size - 8 + $i, 7, false, true );
        }
    }

    /**
     * Place alignment patterns
     *
     * @param int $version QR version.
     */
    private function place_alignment_patterns( $version ) {
        if ( ! isset( self::$alignment[ $version ] ) ) {
            return;
        }

        $positions = self::$alignment[ $version ];
        $combos    = array();

        foreach ( $positions as $r ) {
            foreach ( $positions as $c ) {
                $combos[] = array( $r, $c );
            }
        }

        foreach ( $combos as $pos ) {
            $r = $pos[0];
            $c = $pos[1];

            // Skip if overlapping finder pattern
            if ( $this->reserved[ $r ][ $c ] ) {
                continue;
            }

            for ( $dr = -2; $dr <= 2; $dr++ ) {
                for ( $dc = -2; $dc <= 2; $dc++ ) {
                    $dark = ( abs( $dr ) === 2 || abs( $dc ) === 2 || ( 0 === $dr && 0 === $dc ) );
                    $this->set_module( $r + $dr, $c + $dc, $dark, true );
                }
            }
        }
    }

    /**
     * Place timing patterns
     */
    private function place_timing_patterns() {
        for ( $i = 8; $i < $this->size - 8; $i++ ) {
            if ( ! $this->reserved[ 6 ][ $i ] ) {
                $this->set_module( 6, $i, 0 === $i % 2, true );
            }
            if ( ! $this->reserved[ $i ][ 6 ] ) {
                $this->set_module( $i, 6, 0 === $i % 2, true );
            }
        }
    }

    /**
     * Reserve format information area
     */
    private function reserve_format_area() {
        // Around top-left finder
        for ( $i = 0; $i <= 8; $i++ ) {
            if ( $i !== 6 ) {
                $this->reserve( 8, $i );
            }
            if ( $i !== 6 && $i < 8 ) {
                $this->reserve( $i, 8 );
            }
        }
        $this->reserve( 8, 8 );

        // Bottom-left
        for ( $i = $this->size - 7; $i < $this->size; $i++ ) {
            $this->reserve( $i, 8 );
        }

        // Top-right
        for ( $i = $this->size - 8; $i < $this->size; $i++ ) {
            $this->reserve( 8, $i );
        }

        // Dark module
        $this->set_module( $this->size - 8, 8, true, true );
    }

    /**
     * Reserve version information area (version >= 7)
     */
    private function reserve_version_area() {
        for ( $i = 0; $i < 6; $i++ ) {
            for ( $j = $this->size - 11; $j < $this->size - 8; $j++ ) {
                $this->reserve( $i, $j );
                $this->reserve( $j, $i );
            }
        }
    }

    /**
     * Place format information bits
     *
     * @param int $mask Mask pattern (0-7).
     */
    private function place_format_info( $mask ) {
        // ECL L = 01, mask pattern 3 bits
        $format_data = ( 1 << 3 ) | $mask; // ECL L = 01
        $format_ecc  = $this->calc_format_ecc( $format_data );
        $format_bits = ( $format_data << 10 ) | $format_ecc;
        $format_bits ^= 0x5412; // XOR with mask pattern 101010000010010

        // Position sequences for format info
        $positions_a = array(
            array( 0, 8 ), array( 1, 8 ), array( 2, 8 ), array( 3, 8 ),
            array( 4, 8 ), array( 5, 8 ), array( 7, 8 ), array( 8, 8 ),
            array( 8, 7 ), array( 8, 5 ), array( 8, 4 ), array( 8, 3 ),
            array( 8, 2 ), array( 8, 1 ), array( 8, 0 ),
        );

        $positions_b = array();
        for ( $i = $this->size - 1; $i >= $this->size - 7; $i-- ) {
            $positions_b[] = array( 8, $i );
        }
        $positions_b[] = array( 8, $this->size - 8 );
        for ( $i = $this->size - 7; $i < $this->size; $i++ ) {
            $positions_b[] = array( $i, 8 );
        }

        for ( $i = 0; $i < 15; $i++ ) {
            $bit = ( $format_bits >> ( 14 - $i ) ) & 1;
            $this->modules[ $positions_a[ $i ][0] ][ $positions_a[ $i ][1] ] = (bool) $bit;
            $this->modules[ $positions_b[ $i ][0] ][ $positions_b[ $i ][1] ] = (bool) $bit;
        }
    }

    /**
     * Calculate format ECC (BCH(15,5))
     *
     * @param int $data 5-bit format data.
     * @return int 10-bit ECC.
     */
    private function calc_format_ecc( $data ) {
        $g    = 0x537; // Generator polynomial
        $bits = $data << 10;
        for ( $i = 4; $i >= 0; $i-- ) {
            if ( $bits & ( 1 << ( $i + 10 ) ) ) {
                $bits ^= $g << $i;
            }
        }
        return $bits;
    }

    /**
     * Place version information bits (version >= 7)
     *
     * @param int $version QR version.
     */
    private function place_version_info( $version ) {
        $ver_data = $this->calc_version_ecc( $version );

        for ( $i = 0; $i < 18; $i++ ) {
            $bit = ( $ver_data >> $i ) & 1;
            $r   = intval( $i / 3 );
            $c   = $this->size - 11 + ( $i % 3 );
            $this->modules[ $r ][ $c ] = (bool) $bit;
            $this->modules[ $c ][ $r ] = (bool) $bit;
        }
    }

    /**
     * Calculate version ECC (BCH(18,6))
     *
     * @param int $version Version number.
     * @return int 18-bit version info.
     */
    private function calc_version_ecc( $version ) {
        $g    = 0x1F25; // Generator polynomial
        $bits = $version << 12;
        $tmp  = $bits;
        for ( $i = 5; $i >= 0; $i-- ) {
            if ( $tmp & ( 1 << ( $i + 12 ) ) ) {
                $tmp ^= $g << $i;
            }
        }
        return $bits | $tmp;
    }

    /**
     * Place data bits in zigzag pattern
     *
     * @param array $codewords Data and EC codewords.
     */
    private function place_data_bits( $codewords ) {
        $bits = '';
        foreach ( $codewords as $cw ) {
            $bits .= str_pad( decbin( $cw ), 8, '0', STR_PAD_LEFT );
        }

        $bit_idx = 0;
        $col     = $this->size - 1;

        while ( $col > 0 ) {
            // Skip vertical timing pattern column
            if ( 6 === $col ) {
                $col--;
            }

            for ( $row = 0; $row < $this->size; $row++ ) {
                // Determine actual row based on direction
                $upward    = ( ( ( $this->size - 1 - $col ) >> 1 ) & 1 ) === 0;
                $actual_row = $upward ? $this->size - 1 - $row : $row;

                for ( $c_offset = 0; $c_offset <= 1; $c_offset++ ) {
                    $actual_col = $col - $c_offset;

                    if ( $actual_col < 0 || $actual_col >= $this->size ) {
                        continue;
                    }

                    if ( $this->reserved[ $actual_row ][ $actual_col ] ) {
                        continue;
                    }

                    if ( $bit_idx < strlen( $bits ) ) {
                        $this->modules[ $actual_row ][ $actual_col ] = '1' === $bits[ $bit_idx ];
                        $bit_idx++;
                    } else {
                        $this->modules[ $actual_row ][ $actual_col ] = false;
                    }
                }
            }

            $col -= 2;
        }
    }

    /**
     * Apply best mask pattern
     *
     * @return int Best mask index (0-7).
     */
    private function apply_best_mask() {
        $best_mask    = 0;
        $best_penalty = PHP_INT_MAX;
        $original     = $this->modules;

        for ( $mask = 0; $mask < 8; $mask++ ) {
            $this->modules = $this->deep_copy( $original );
            $this->apply_mask( $mask );
            $this->place_format_info( $mask );

            $penalty = $this->calc_penalty();

            if ( $penalty < $best_penalty ) {
                $best_penalty = $penalty;
                $best_mask    = $mask;
            }
        }

        // Apply the best mask
        $this->modules = $this->deep_copy( $original );
        $this->apply_mask( $best_mask );

        return $best_mask;
    }

    /**
     * Apply a specific mask pattern to data modules
     *
     * @param int $mask Mask index (0-7).
     */
    private function apply_mask( $mask ) {
        for ( $r = 0; $r < $this->size; $r++ ) {
            for ( $c = 0; $c < $this->size; $c++ ) {
                if ( $this->reserved[ $r ][ $c ] ) {
                    continue;
                }
                $invert = false;
                switch ( $mask ) {
                    case 0:
                        $invert = ( ( $r + $c ) % 2 === 0 );
                        break;
                    case 1:
                        $invert = ( $r % 2 === 0 );
                        break;
                    case 2:
                        $invert = ( $c % 3 === 0 );
                        break;
                    case 3:
                        $invert = ( ( $r + $c ) % 3 === 0 );
                        break;
                    case 4:
                        $invert = ( ( intval( $r / 2 ) + intval( $c / 3 ) ) % 2 === 0 );
                        break;
                    case 5:
                        $invert = ( ( ( $r * $c ) % 2 ) + ( ( $r * $c ) % 3 ) === 0 );
                        break;
                    case 6:
                        $invert = ( ( ( ( $r * $c ) % 2 ) + ( ( $r * $c ) % 3 ) ) % 2 === 0 );
                        break;
                    case 7:
                        $invert = ( ( ( ( $r + $c ) % 2 ) + ( ( $r * $c ) % 3 ) ) % 2 === 0 );
                        break;
                }
                if ( $invert ) {
                    $this->modules[ $r ][ $c ] = ! $this->modules[ $r ][ $c ];
                }
            }
        }
    }

    /**
     * Calculate penalty score for current matrix
     *
     * Simplified: evaluates rule 1 (runs) and rule 3 (finder-like patterns)
     *
     * @return int Penalty score.
     */
    private function calc_penalty() {
        $penalty = 0;
        $n       = $this->size;

        // Rule 1: Adjacent modules in row/column of same color (>=5)
        for ( $r = 0; $r < $n; $r++ ) {
            $run_len = 1;
            for ( $c = 1; $c < $n; $c++ ) {
                if ( $this->modules[ $r ][ $c ] === $this->modules[ $r ][ $c - 1 ] ) {
                    $run_len++;
                } else {
                    if ( $run_len >= 5 ) {
                        $penalty += $run_len - 2;
                    }
                    $run_len = 1;
                }
            }
            if ( $run_len >= 5 ) {
                $penalty += $run_len - 2;
            }
        }

        for ( $c = 0; $c < $n; $c++ ) {
            $run_len = 1;
            for ( $r = 1; $r < $n; $r++ ) {
                if ( $this->modules[ $r ][ $c ] === $this->modules[ $r - 1 ][ $c ] ) {
                    $run_len++;
                } else {
                    if ( $run_len >= 5 ) {
                        $penalty += $run_len - 2;
                    }
                    $run_len = 1;
                }
            }
            if ( $run_len >= 5 ) {
                $penalty += $run_len - 2;
            }
        }

        // Rule 2: 2x2 blocks of same color
        for ( $r = 0; $r < $n - 1; $r++ ) {
            for ( $c = 0; $c < $n - 1; $c++ ) {
                $val = $this->modules[ $r ][ $c ];
                if ( $val === $this->modules[ $r ][ $c + 1 ]
                  && $val === $this->modules[ $r + 1 ][ $c ]
                  && $val === $this->modules[ $r + 1 ][ $c + 1 ] ) {
                    $penalty += 3;
                }
            }
        }

        // Rule 4: Proportion of dark modules
        $dark = 0;
        for ( $r = 0; $r < $n; $r++ ) {
            for ( $c = 0; $c < $n; $c++ ) {
                if ( $this->modules[ $r ][ $c ] ) {
                    $dark++;
                }
            }
        }
        $total      = $n * $n;
        $percent    = ( $dark * 100 ) / $total;
        $prev_five  = intval( $percent / 5 ) * 5;
        $next_five  = $prev_five + 5;
        $penalty   += min( abs( $prev_five - 50 ), abs( $next_five - 50 ) ) * 2;

        return $penalty;
    }

    /**
     * Render the QR matrix as SVG markup
     *
     * @param int $px_size Pixel size per module.
     * @param int $margin  Quiet zone in modules.
     * @return string SVG markup.
     */
    private function render_svg( $px_size, $margin ) {
        $total = ( $this->size + $margin * 2 ) * $px_size;

        $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' . $total . ' ' . $total . '" width="' . $total . '" height="' . $total . '">';
        $svg .= '<rect width="100%" height="100%" fill="#ffffff"/>';
        $svg .= '<path d="';

        for ( $r = 0; $r < $this->size; $r++ ) {
            for ( $c = 0; $c < $this->size; $c++ ) {
                if ( $this->modules[ $r ][ $c ] ) {
                    $x = ( $c + $margin ) * $px_size;
                    $y = ( $r + $margin ) * $px_size;
                    $svg .= 'M' . $x . ',' . $y . 'h' . $px_size . 'v' . $px_size . 'h-' . $px_size . 'z';
                }
            }
        }

        $svg .= '" fill="#000000"/>';
        $svg .= '</svg>';

        return $svg;
    }

    /**
     * Set a module value and optionally mark as reserved
     *
     * @param int  $row      Row index.
     * @param int  $col      Column index.
     * @param bool $dark     True for dark module.
     * @param bool $reserved Mark as function pattern.
     */
    private function set_module( $row, $col, $dark, $reserved = false ) {
        if ( $row >= 0 && $row < $this->size && $col >= 0 && $col < $this->size ) {
            $this->modules[ $row ][ $col ]  = (bool) $dark;
            if ( $reserved ) {
                $this->reserved[ $row ][ $col ] = true;
            }
        }
    }

    /**
     * Reserve a module position without setting value
     *
     * @param int $row Row index.
     * @param int $col Column index.
     */
    private function reserve( $row, $col ) {
        if ( $row >= 0 && $row < $this->size && $col >= 0 && $col < $this->size ) {
            $this->reserved[ $row ][ $col ] = true;
        }
    }

    /**
     * Deep copy a 2D array
     *
     * @param array $arr Original array.
     * @return array Copy.
     */
    private function deep_copy( $arr ) {
        $copy = array();
        foreach ( $arr as $r => $row ) {
            $copy[ $r ] = $row; // PHP arrays are copied by value
        }
        return $copy;
    }
}
