<?php
/**
 * Vigilant: verify MANIFEST.sha256 from the command line.
 *
 * Plain PHP >= 7.4, no WordPress required. Verifies the plugin tree against
 * MANIFEST.sha256 (modified, missing and extra files, symbolic links, and
 * folders that cannot be listed),
 * and optionally cross-checks the manifest against the SHA-256 checksums
 * that WordPress.org publishes for the released version (the manifest must
 * describe exactly what WordPress.org distributes).
 *
 * Usage:
 *   php bin/verify-manifest.php [/path/to/plugin/root]
 *   php bin/verify-manifest.php --wporg          (version read from vigilante.php)
 *   php bin/verify-manifest.php --wporg=3.0.0
 *
 * Exit codes:
 *   0  everything verified clean
 *   1  local tree does not match the manifest (modified/missing/extra files, links,
 *      or folders that cannot be listed)
 *   2  manifest missing, unreadable or not valid, wp.org checksums unavailable, or
 *      the plugin folder cannot be listed
 *   3  manifest disagrees with what wp.org distributes
 *
 * The tree is the same the plugin checks at runtime
 * (includes/class-self-integrity.php): readme.txt, changelog.txt and the
 * manifest itself at the root, the files svn writes in .svn/ at the root, and
 * .DS_Store and Thumbs.db anywhere are not in the manifest. A link, or a file
 * a web server may run (PHP extensions, .htaccess, .user.ini, php.ini), is
 * never skipped, and an extension anywhere in the name counts (x.php.jpg).
 * Text files are also compared with a UTF-8 BOM removed and CRLF line endings
 * turned into LF, as the plugin does, so a host rewriting them is not reported
 * (sha256sum -c reports them).
 *
 * @package Vigilante
 * @since   3.0.0
 */

// Outside WordPress only the command line may run this tool (from the web it
// answers 404); loaded inside WordPress it does nothing.
if ( ! defined( 'ABSPATH' ) ) {
	if ( 'cli' !== PHP_SAPI ) {
		http_response_code( 404 );
		exit;
	}
} else {
	return;
}

// phpcs:disable WordPress.WP.AlternativeFunctions -- Command line tool that runs outside WordPress, where WP_Filesystem and the HTTP API do not exist: fwrite() to STDOUT/STDERR, file_get_contents() and fopen() are the only way. The guard above makes the file inert inside WordPress and unreachable from the web. Closed at the end of the file.

/*
 * Exclusions. The same three lists live in includes/class-self-integrity.php
 * and in the release tool generate-manifest.php, and the release checks
 * compare them.
 */
$vigilante_root_excluded_files = array( 'MANIFEST.sha256', 'readme.txt', 'changelog.txt' );
$vigilante_svn_metadata        = '#^\.svn/(?:wc\.db|wc\.db-journal|format|entries|pristine/[0-9a-f]{2}/[0-9a-f]{40}\.svn-base)$#';
$vigilante_junk_file_names     = array( '.DS_Store', 'Thumbs.db' );
$vigilante_executable_ext      = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'pht', 'phar', 'inc' );
$vigilante_executable_names    = array( '.htaccess', '.user.ini', 'php.ini' );

$vigilante_is_excluded = function ( $relative ) use ( $vigilante_root_excluded_files, $vigilante_svn_metadata, $vigilante_junk_file_names ) {
	$relative = (string) $relative;
	$segments = explode( '/', $relative );
	if ( 1 === count( $segments ) && in_array( $segments[0], $vigilante_root_excluded_files, true ) ) {
		return true;
	}
	if ( preg_match( $vigilante_svn_metadata, $relative ) ) {
		return true;
	}
	return in_array( end( $segments ), $vigilante_junk_file_names, true );
};

$vigilante_is_executable = function ( $relative ) use ( $vigilante_executable_ext, $vigilante_executable_names ) {
	$name = strtolower( basename( (string) $relative ) );
	if ( in_array( $name, $vigilante_executable_names, true ) ) {
		return true;
	}
	// Every extension counts, not only the last one (x.php.jpg runs as PHP with AddHandler).
	$parts = explode( '.', $name );
	array_shift( $parts );
	foreach ( $parts as $part ) {
		if ( in_array( $part, $vigilante_executable_ext, true ) ) {
			return true;
		}
	}
	return false;
};

// Text files a host may rewrite (UTF-8 BOM, CRLF): compared normalized too, as the plugin does.
// Line endings count in every text file, a UTF-8 BOM only where it changes nothing (not in PHP,
// where it is output, nor in JSON, which json_decode() then rejects), and nothing above 5 MB.
$vigilante_normalized_hash = function ( $path ) use ( $vigilante_is_executable ) {
	$extension = strtolower( pathinfo( (string) $path, PATHINFO_EXTENSION ) );
	if ( ! in_array( $extension, array( 'php', 'js', 'css', 'json', 'txt', 'md', 'html', 'htm', 'xml', 'svg', 'po', 'pot', 'ini' ), true ) ) {
		return null;
	}
	$size = filesize( $path );
	if ( false === $size || $size > 5242880 ) {
		return null;
	}
	// The read stops past the limit too: the size can change between the check and the read.
	$content = file_get_contents( $path, false, null, 0, 5242881 );
	if ( false === $content || strlen( $content ) > 5242880 ) {
		return null;
	}
	// Not in an executable name either: x.php.svg runs as PHP where a handler matches any extension.
	if ( "\xEF\xBB\xBF" === substr( $content, 0, 3 ) && in_array( $extension, array( 'js', 'css', 'txt', 'md', 'html', 'htm', 'xml', 'svg', 'po', 'pot' ), true ) && ! $vigilante_is_executable( $path ) ) {
		$content = substr( $content, 3 );
	}
	return hash( 'sha256', str_replace( array( "\r\n", "\r" ), "\n", $content ) );
};

// Paths come from the disk and from wp.org: printed with control characters
// escaped, so a crafted file name cannot rewrite what the terminal shows.
$vigilante_printable = function ( $text ) {
	$text = addcslashes( (string) $text, "\0..\37\177" );
	if ( ! preg_match( '//u', $text ) ) {
		// Not valid UTF-8: every byte above ASCII is shown as \xNN.
		return preg_replace_callback(
			'/[\x80-\xFF]/',
			function ( $m ) {
				return sprintf( '\\x%02X', ord( $m[0] ) );
			},
			$text
		);
	}
	// C1 controls, the bidirectional marks that reorder what a terminal shows (a name
	// that reads informe-php.png and is informe-<U+202E>gnp.php), and the invisible or blank
	// characters that let one name pass for another (zero width, line separators, BOM, soft
	// hyphen, grapheme joiner, Hangul and Mongolian fillers).
	return preg_replace_callback(
		'/[\x{0080}-\x{009F}\x{00AD}\x{034F}\x{061C}\x{115F}\x{1160}\x{180E}\x{200B}-\x{200F}\x{2028}-\x{202E}\x{2060}-\x{2069}\x{3164}\x{FEFF}\x{FFA0}]/u',
		function ( $m ) {
			// Two or three byte UTF-8 sequences only; decoded by hand (mbstring is optional).
			$b    = array_values( unpack( 'C*', $m[0] ) );
			$code = 2 === count( $b ) ? ( ( $b[0] & 0x1F ) << 6 ) | ( $b[1] & 0x3F ) : ( ( $b[0] & 0x0F ) << 12 ) | ( ( $b[1] & 0x3F ) << 6 ) | ( $b[2] & 0x3F );
			return sprintf( '\\u{%04X}', $code );
		},
		$text
	);
};

$vigilante_is_safe_path = function ( $path ) {
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
};

// ---------------------------------------------------------------------------
// Arguments.
// ---------------------------------------------------------------------------
$vigilante_root  = dirname( __DIR__ );
$vigilante_wporg = null; // null = off, '' = auto version, 'X.Y.Z' = explicit.

$vigilante_argv = array_slice( isset( $argv ) ? $argv : array(), 1 );
foreach ( $vigilante_argv as $vigilante_arg ) {
	if ( '--wporg' === $vigilante_arg ) {
		$vigilante_wporg = '';
	} elseif ( 0 === strpos( $vigilante_arg, '--wporg=' ) ) {
		$vigilante_wporg = substr( $vigilante_arg, 8 );
	} elseif ( '-' !== substr( $vigilante_arg, 0, 1 ) ) {
		$vigilante_root = rtrim( $vigilante_arg, '/' );
	} else {
		fwrite( STDERR, 'Unknown option: ' . $vigilante_arg . "\n" );
		exit( 2 );
	}
}

if ( ! is_dir( $vigilante_root ) ) {
	fwrite( STDERR, 'ERROR: not a directory: ' . $vigilante_root . "\n" );
	exit( 2 );
}

// ---------------------------------------------------------------------------
// Read the manifest.
// ---------------------------------------------------------------------------
$vigilante_manifest_path = $vigilante_root . '/MANIFEST.sha256';
if ( is_link( $vigilante_manifest_path ) || ! is_readable( $vigilante_manifest_path ) ) {
	fwrite( STDERR, 'ERROR: MANIFEST.sha256 not found, unreadable or a link at ' . $vigilante_manifest_path . "\n" );
	exit( 2 );
}
// 2000 lines take well under a megabyte: a bigger file is not a valid manifest and is not read,
// and the read stops past the limit too, since the size can change between the check and the read.
$vigilante_manifest_size = filesize( $vigilante_manifest_path );
if ( false === $vigilante_manifest_size ) {
	fwrite( STDERR, "ERROR: could not read the size of MANIFEST.sha256\n" );
	exit( 2 );
}
if ( $vigilante_manifest_size > 1048576 ) {
	fwrite( STDERR, "ERROR: MANIFEST.sha256 is larger than 1 MB, so it is not a valid manifest and was not read\n" );
	exit( 2 );
}

$vigilante_manifest_raw = file_get_contents( $vigilante_manifest_path, false, null, 0, 1048577 );
if ( false !== $vigilante_manifest_raw && strlen( $vigilante_manifest_raw ) > 1048576 ) {
	fwrite( STDERR, "ERROR: MANIFEST.sha256 is larger than 1 MB, so it is not a valid manifest and was not read\n" );
	exit( 2 );
}
if ( false !== $vigilante_manifest_raw ) {
	// A rewrite of the line endings reaches the manifest too, and gives nobody anything.
	if ( "\xEF\xBB\xBF" === substr( $vigilante_manifest_raw, 0, 3 ) ) {
		$vigilante_manifest_raw = substr( $vigilante_manifest_raw, 3 );
	}
	$vigilante_manifest_raw = str_replace( array( "\r\n", "\r" ), "\n", $vigilante_manifest_raw );
}
if ( false === $vigilante_manifest_raw ) {
	fwrite( STDERR, "ERROR: could not read MANIFEST.sha256\n" );
	exit( 2 );
}

$vigilante_manifest = array();
$vigilante_lines    = 0;
$vigilante_length   = strlen( $vigilante_manifest_raw );
$vigilante_offset   = 0;
// Line by line over the string, not explode(): a manifest of line breaks would build an array of
// millions of empty strings and exhaust memory. Blank lines count towards the limit too.
while ( $vigilante_offset < $vigilante_length ) {
	$vigilante_end    = strpos( $vigilante_manifest_raw, "\n", $vigilante_offset );
	$vigilante_end    = false === $vigilante_end ? $vigilante_length : $vigilante_end;
	$vigilante_line   = substr( $vigilante_manifest_raw, $vigilante_offset, $vigilante_end - $vigilante_offset );
	$vigilante_offset = $vigilante_end + 1;
	$vigilante_lines++;
	if ( $vigilante_lines > 2000 ) {
		fwrite( STDERR, "ERROR: MANIFEST.sha256 has more than 2000 lines\n" );
		exit( 2 );
	}
	if ( '' === trim( $vigilante_line ) ) {
		continue;
	}
	if ( ! preg_match( '/^([0-9a-f]{64})  (.+)$/', $vigilante_line, $vigilante_m ) || ! $vigilante_is_safe_path( $vigilante_m[2] ) || isset( $vigilante_manifest[ $vigilante_m[2] ] ) ) {
		fwrite( STDERR, 'ERROR: not a valid manifest line (format, unsafe path or repeated path): ' . $vigilante_printable( $vigilante_line ) . "\n" );
		exit( 2 );
	}
	if ( $vigilante_is_excluded( $vigilante_m[2] ) ) {
		continue;
	}
	$vigilante_manifest[ $vigilante_m[2] ] = $vigilante_m[1];
}

if ( empty( $vigilante_manifest ) ) {
	fwrite( STDERR, "ERROR: MANIFEST.sha256 is empty\n" );
	exit( 2 );
}

// ---------------------------------------------------------------------------
// Local verification: mismatches, missing files, links, extra files.
// ---------------------------------------------------------------------------
$vigilante_mismatch = array();
$vigilante_missing  = array();
$vigilante_links    = array();
$vigilante_extra    = array();
$vigilante_hidden   = array();
$vigilante_realroot = realpath( $vigilante_root );

foreach ( $vigilante_manifest as $vigilante_relative => $vigilante_expected ) {
	$vigilante_path = $vigilante_root . '/' . $vigilante_relative;
	$vigilante_real = realpath( $vigilante_path );
	if ( is_link( $vigilante_path ) || ( false !== $vigilante_real && false !== $vigilante_realroot && 0 !== strpos( $vigilante_real, $vigilante_realroot . DIRECTORY_SEPARATOR ) ) ) {
		$vigilante_links[] = $vigilante_relative;
		continue;
	}
	if ( ! is_file( $vigilante_path ) ) {
		$vigilante_missing[] = $vigilante_relative;
		continue;
	}
	if ( ! is_readable( $vigilante_path ) ) {
		$vigilante_mismatch[] = $vigilante_relative;
		continue;
	}
	if ( hash_file( 'sha256', $vigilante_path ) !== $vigilante_expected && $vigilante_normalized_hash( $vigilante_path ) !== $vigilante_expected ) {
		$vigilante_mismatch[] = $vigilante_relative;
	}
}

// A folder that cannot be listed hides what is inside it, and a web server can
// still run a file in it by name: it is reported, and the walk goes on past it
// instead of stopping with an uncaught exception.
try {
	$vigilante_iterator = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $vigilante_root, RecursiveDirectoryIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::SELF_FIRST,
		RecursiveIteratorIterator::CATCH_GET_CHILD
	);
} catch ( Exception $vigilante_e ) {
	fwrite( STDERR, 'ERROR: cannot list ' . $vigilante_root . "\n" );
	exit( 2 );
}
foreach ( $vigilante_iterator as $vigilante_file ) {
	$vigilante_relative = str_replace( '\\', '/', substr( $vigilante_file->getPathname(), strlen( $vigilante_root ) + 1 ) );
	$vigilante_is_link  = $vigilante_file->isLink();
	if ( ! $vigilante_is_link && $vigilante_file->isDir() ) {
		// On Windows is_executable() of a folder is always false: only readability counts there.
		if ( ! $vigilante_file->isReadable() || ( '\\' !== DIRECTORY_SEPARATOR && ! $vigilante_file->isExecutable() ) ) {
			$vigilante_hidden[] = $vigilante_relative . '/';
		}
		continue;
	}
	if ( ! $vigilante_is_link && ! $vigilante_file->isFile() ) {
		continue;
	}
	if ( isset( $vigilante_manifest[ $vigilante_relative ] ) ) {
		continue;
	}
	$vigilante_executable = $vigilante_is_executable( $vigilante_relative );
	if ( $vigilante_is_excluded( $vigilante_relative ) && ! $vigilante_is_link && ! $vigilante_executable ) {
		continue;
	}
	if ( $vigilante_is_link ) {
		$vigilante_links[] = $vigilante_relative;
	} else {
		$vigilante_extra[] = $vigilante_relative;
	}
}

sort( $vigilante_mismatch, SORT_STRING );
sort( $vigilante_missing, SORT_STRING );
sort( $vigilante_links, SORT_STRING );
sort( $vigilante_extra, SORT_STRING );
sort( $vigilante_hidden, SORT_STRING );

foreach ( $vigilante_mismatch as $vigilante_relative ) {
	fwrite( STDOUT, 'MODIFIED: ' . $vigilante_printable( $vigilante_relative ) . "\n" );
}
foreach ( $vigilante_missing as $vigilante_relative ) {
	fwrite( STDOUT, 'MISSING:  ' . $vigilante_printable( $vigilante_relative ) . "\n" );
}
foreach ( $vigilante_links as $vigilante_relative ) {
	fwrite( STDOUT, 'LINK:     ' . $vigilante_printable( $vigilante_relative ) . "\n" );
}
foreach ( $vigilante_extra as $vigilante_relative ) {
	fwrite( STDOUT, 'EXTRA:    ' . $vigilante_printable( $vigilante_relative ) . "\n" );
}
foreach ( $vigilante_hidden as $vigilante_relative ) {
	fwrite( STDOUT, 'UNLISTED: ' . $vigilante_printable( $vigilante_relative ) . "\n" );
}

$vigilante_local_clean = empty( $vigilante_mismatch ) && empty( $vigilante_missing ) && empty( $vigilante_links ) && empty( $vigilante_extra ) && empty( $vigilante_hidden );
if ( $vigilante_local_clean ) {
	fwrite( STDOUT, 'Local tree OK: ' . count( $vigilante_manifest ) . " files match MANIFEST.sha256, no extras.\n" );
}

// ---------------------------------------------------------------------------
// Optional wp.org cross-check.
// ---------------------------------------------------------------------------
$vigilante_wporg_clean = true;
if ( null !== $vigilante_wporg ) {
	$vigilante_version = $vigilante_wporg;
	if ( '' === $vigilante_version ) {
		$vigilante_main = (string) file_get_contents( $vigilante_root . '/vigilante.php' );
		if ( preg_match( '/^\s*\*\s*Version:\s*([0-9][0-9a-zA-Z.\-]*)\s*$/m', $vigilante_main, $vigilante_m ) ) {
			$vigilante_version = $vigilante_m[1];
		} else {
			fwrite( STDERR, "ERROR: could not parse Version: header from vigilante.php; pass --wporg=X.Y.Z\n" );
			exit( 2 );
		}
	}

	$vigilante_url = 'https://downloads.wordpress.org/plugin-checksums/vigilante/' . rawurlencode( $vigilante_version ) . '.json';

	// TLS verification stays ON. Some PHP builds ship without a default CA
	// bundle; fall back to the system one if available.
	$vigilante_ssl = array(
		'verify_peer'      => true,
		'verify_peer_name' => true,
	);
	if ( '' === (string) ini_get( 'openssl.cafile' ) && is_readable( '/etc/ssl/cert.pem' ) ) {
		$vigilante_ssl['cafile'] = '/etc/ssl/cert.pem';
	}
	$vigilante_context = stream_context_create(
		array(
			'http' => array(
				'timeout'       => 15,
				'ignore_errors' => true,
				'user_agent'    => 'Vigilant verify-manifest (https://wordpress.org/plugins/vigilante/)',
			),
			'ssl'  => $vigilante_ssl,
		)
	);
	$vigilante_stream = fopen( $vigilante_url, 'r', false, $vigilante_context );
	$vigilante_body   = false;
	$vigilante_status = 0;
	if ( false !== $vigilante_stream ) {
		$vigilante_body = stream_get_contents( $vigilante_stream, 2097152 );
		$vigilante_meta = stream_get_meta_data( $vigilante_stream );
		fclose( $vigilante_stream );
		if ( ! empty( $vigilante_meta['wrapper_data'] ) && is_array( $vigilante_meta['wrapper_data'] ) ) {
			foreach ( $vigilante_meta['wrapper_data'] as $vigilante_header ) {
				if ( is_string( $vigilante_header ) && preg_match( '#^HTTP/\S+\s+(\d{3})#', $vigilante_header, $vigilante_m ) ) {
					$vigilante_status = (int) $vigilante_m[1];
				}
			}
		}
	}

	if ( false === $vigilante_body || 200 !== $vigilante_status ) {
		fwrite( STDERR, 'ERROR: could not fetch wp.org checksums for ' . $vigilante_printable( $vigilante_version ) . ' (HTTP ' . $vigilante_status . ").\n" );
		fwrite( STDERR, "Right after a release wp.org may not have generated them yet: retry later.\n" );
		exit( 2 );
	}

	$vigilante_json = json_decode( $vigilante_body, true );
	if ( ! is_array( $vigilante_json ) || empty( $vigilante_json['files'] ) || ! is_array( $vigilante_json['files'] ) ) {
		fwrite( STDERR, "ERROR: unexpected wp.org checksums payload.\n" );
		exit( 2 );
	}

	$vigilante_wporg_files = array();
	foreach ( $vigilante_json['files'] as $vigilante_relative => $vigilante_sums ) {
		if ( ! is_array( $vigilante_sums ) || ! isset( $vigilante_sums['sha256'] ) ) {
			continue;
		}
		// wp.org publishes a string, or an array when the file changed on the same tag.
		$vigilante_wporg_files[ str_replace( '\\', '/', (string) $vigilante_relative ) ] = array_map( 'strval', (array) $vigilante_sums['sha256'] );
	}

	// Direction 1: every manifest entry must be distributed with the same hash.
	foreach ( $vigilante_manifest as $vigilante_relative => $vigilante_expected ) {
		if ( ! isset( $vigilante_wporg_files[ $vigilante_relative ] ) ) {
			fwrite( STDOUT, 'WPORG-MISSING: ' . $vigilante_printable( $vigilante_relative ) . " (in manifest, not distributed by wp.org)\n" );
			$vigilante_wporg_clean = false;
			continue;
		}
		if ( ! in_array( $vigilante_expected, $vigilante_wporg_files[ $vigilante_relative ], true ) ) {
			fwrite( STDOUT, 'WPORG-MISMATCH: ' . $vigilante_printable( $vigilante_relative ) . " (manifest hash differs from what wp.org distributes)\n" );
			$vigilante_wporg_clean = false;
		}
	}

	// Direction 2: everything wp.org distributes must be in the manifest,
	// except what is never in it (the manifest, readme.txt, changelog.txt).
	foreach ( $vigilante_wporg_files as $vigilante_relative => $vigilante_hashes ) {
		if ( $vigilante_is_excluded( $vigilante_relative ) ) {
			continue;
		}
		if ( ! isset( $vigilante_manifest[ $vigilante_relative ] ) ) {
			fwrite( STDOUT, 'WPORG-EXTRA: ' . $vigilante_printable( $vigilante_relative ) . " (distributed by wp.org, not in manifest)\n" );
			$vigilante_wporg_clean = false;
		}
	}

	if ( $vigilante_wporg_clean ) {
		fwrite( STDOUT, 'wp.org cross-check OK for ' . $vigilante_printable( $vigilante_version ) . ': manifest and distributed checksums agree.' . "\n" );
	} else {
		fwrite( STDOUT, "wp.org cross-check FAILED: the manifest does not describe what wp.org distributes (see SECURITY.md).\n" );
	}
}

// phpcs:enable WordPress.WP.AlternativeFunctions

if ( ! $vigilante_wporg_clean ) {
	exit( 3 );
}
if ( ! $vigilante_local_clean ) {
	exit( 1 );
}
exit( 0 );
