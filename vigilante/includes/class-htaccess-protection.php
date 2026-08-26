<?php
/**
 * HTAccess Protection Class
 *
 * Manages firewall rules via .htaccess
 * 
 * IMPORTANT: Each option in this class corresponds EXACTLY to a checkbox in the admin UI.
 * The option names match those in class-settings.php firewall section.
 *
 * @package Vigilante
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_Htaccess_Protection
 *
 * Applies firewall rules to .htaccess for Apache/LiteSpeed servers
 */
class Vigilante_Htaccess_Protection {

    /**
     * Settings instance
     *
     * @var Vigilante_Settings
     */
    private $settings;

    /**
     * Firewall options
     *
     * @var array
     */
    private $options;

    /**
     * Block markers
     */
    const MARKER_START = '# BEGIN Vigilante Protection';
    const MARKER_END   = '# END Vigilante Protection';

    /**
     * Old plugin markers to clean
     */
    private $old_markers = array(
        array( '# BEGIN SECURITY HEADERS', '# END SECURITY HEADERS' ),
        array( '# BEGIN 8G FIREWALL', '# END 8G FIREWALL' ),
        array( '# BEGIN ADDITIONAL PROTECTIONS', '# END ADDITIONAL PROTECTIONS' ),
        array( '# BEGIN AyudaWP Security', '# END AyudaWP Security' ),
    );

    /**
     * Constructor
     *
     * @param Vigilante_Settings $settings Settings instance.
     */
    public function __construct( $settings ) {
        $this->settings = $settings;

        $firewall        = $settings->get_section( 'firewall' );
        $security_headers = $settings->get_section( 'security_headers' );

        // Server Protection keys moved from firewall to security_headers in v2.0.0.
        $this->options = array_merge(
            $firewall,
            array(
                'hide_server_signature'         => ! empty( $security_headers['hide_server_signature'] ),
                'remove_fingerprinting_headers' => ! empty( $security_headers['remove_fingerprinting_headers'] ),
            )
        );
    }

    /**
     * Apply all .htaccess rules
     *
     * @return bool|WP_Error
     */
    /**
     * @param bool $automatic True when Vigilant is refreshing the block by
     *                        itself rather than because someone pressed Save.
     *                        See Vigilante_Htaccess_Manager::add_block().
     */
    public function apply_rules( $automatic = false ) {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        
        $manager = Vigilante_Htaccess_Manager::get_instance();

        if ( ! $manager->is_apache() ) {
            return new WP_Error( 'not_apache', __( 'Server is not Apache/LiteSpeed', 'vigilante' ) );
        }

        if ( ! $manager->is_writable() ) {
            return new WP_Error( 'not_writable', __( '.htaccess is not writable', 'vigilante' ) );
        }

        // Clean old plugin rules first
        $this->remove_old_rules();

        $rules = $this->generate_rules_content();

        $result = $manager->add_block( self::MARKER_START, self::MARKER_END, $rules, 'before_wordpress', $automatic );

        // Regenerate critical file baseline so the integrity scan does not
        // flag our own modifications as unauthorized changes.
        if ( true === $result ) {
            /** This action is documented in class-wpconfig-security.php */
            do_action( 'vigilante_critical_file_written', '.htaccess' );
        }

        return $result;
    }

    /**
     * Remove .htaccess rules
     *
     * @return bool|WP_Error
     */
    public function remove_rules() {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        
        $manager = Vigilante_Htaccess_Manager::get_instance();

        $result = $manager->remove_block( self::MARKER_START, self::MARKER_END );

        if ( true === $result ) {
            /** This action is documented in class-wpconfig-security.php */
            do_action( 'vigilante_critical_file_written', '.htaccess' );
        }

        return $result;
    }

    /**
     * Remove old plugin rules
     *
     * @return bool
     */
    public function remove_old_rules() {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        
        $manager = Vigilante_Htaccess_Manager::get_instance();

        foreach ( $this->old_markers as $markers ) {
            $manager->remove_block( $markers[0], $markers[1] );
        }

        return true;
    }

    /**
     * Check if rules are active
     *
     * @return bool
     */
    public function are_rules_active() {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        
        $manager = Vigilante_Htaccess_Manager::get_instance();

        return $manager->block_exists( self::MARKER_START );
    }

    /**
     * Check if server is Apache/LiteSpeed
     *
     * @return bool
     */
    public function is_apache() {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        return Vigilante_Htaccess_Manager::get_instance()->is_apache();
    }

    /**
     * Check if .htaccess is writable
     *
     * @return bool
     */
    public function is_htaccess_writable() {
        require_once VIGILANTE_INCLUDES_DIR . 'class-htaccess-manager.php';
        return Vigilante_Htaccess_Manager::get_instance()->is_writable();
    }

    /**
     * Generate firewall rules content (without markers)
     * 
     * OPTION MAPPING (UI checkbox -> setting key -> htaccess rule):
     * 
     * Section "File Protection (.htaccess)":
     * - "Directory Browsing"      -> disable_directory_browsing  -> Options -Indexes
     * - "Server Signature"        -> hide_server_signature       -> ServerSignature Off
     * - "Protect wp-config.php"   -> protect_wp_config           -> Files wp-config.php
     * - "Protect wp-cron.php"     -> protect_wp_cron             -> Files wp-cron.php (opt-in)
     * - "Protect wp-includes"     -> protect_wp_includes         -> RewriteRule wp-includes
     * - "PHP in Uploads"          -> protect_uploads_php         -> RewriteRule uploads/*.php
     * - "Sensitive Files"         -> protect_sensitive_files     -> FilesMatch extensions
     * - "Limit HTTP Methods"      -> limit_http_methods          -> RewriteCond REQUEST_METHOD
     * 
     * Section "Firewall Protection" (htaccess portion):
     * - "Block Bad Bots"          -> block_bad_bots              -> RewriteCond USER_AGENT
     * - "Block Bad Query Strings" -> block_bad_query_strings     -> RewriteCond QUERY_STRING
     *
     * @return string
     */
    private function generate_rules_content() {
        $rules = array();
        
        $rules[] = '# Vigilante for WordPress - Firewall v' . VIGILANTE_VERSION;
        $rules[] = '# Generated: ' . gmdate( 'Y-m-d H:i:s' ) . ' UTC';
        $rules[] = '# https://servicios.ayudawp.com';
        $rules[] = '';

        // =====================================================================
        // SECTION: Basic Server Configuration
        // =====================================================================

        // Option: hide_server_signature
        // UI: "Server Signature" checkbox
        if ( ! empty( $this->options['hide_server_signature'] ) ) {
            $rules[] = '# Hide server signature';
            $rules[] = 'ServerSignature Off';
            $rules[] = '';
        }

        // Option: disable_directory_browsing
        // UI: "Directory Browsing" checkbox
        if ( ! empty( $this->options['disable_directory_browsing'] ) ) {
            $rules[] = '# Disable directory listing';
            $rules[] = 'Options -Indexes';
            $rules[] = '';
        }

        // =====================================================================
        // SECTION: Bot and Request Filtering (htaccess-based)
        // =====================================================================

        // Negated exception conditions shared by every blocking rule below.
        $whitelist_exceptions = $this->generate_whitelist_exceptions();

        // Option: block_bad_bots
        // UI: "Block Bad Bots" checkbox
        if ( ! empty( $this->options['block_bad_bots'] ) ) {
            $rules[] = '# Block malicious bots and crawlers';
            $rules[] = '# Exception: WooCommerce IPN callbacks (payment gateways use various User-Agents)';
            $rules[] = '<IfModule mod_rewrite.c>';
            $rules[] = '    RewriteEngine On';
            $rules   = array_merge( $rules, $whitelist_exceptions );
            $rules[] = '    RewriteCond %{QUERY_STRING} !wc-api= [NC]';
            // Tokens must be specific bot names. The pattern matches as a bare
            // substring anywhere in the UA ([NC], no word anchors), so a short
            // generic token 403s legitimate clients: "rma" used to match inside
            // "Performance" and blocked WP Rocket's page fetch (fixed in 2.9.3
            // together with custo/disco/library/loader/extract/miner/scan/titan).
            $rules[] = '    RewriteCond %{HTTP_USER_AGENT} (ahrefs|alexibot|backlink|bandit|black.hole|blackwidow|blekkobot|blowfish|botalot|buddy|builtbottough|bullseye|bunnyslippers|ccbot|cheesebot|cherrypicker|chinaclaw|collector|copier|copyrightcheck|cosmos|crescent|demon|discobot|dittospyder|dotbot|dragonfly|drip|easydl|ebingbong|ecatch|eirgrabber|emailcollector|emailsiphon|emailwolf|eyenetie|flashget|foobot|frontpage|getright|getweb|go.ahead.got.it|gotit|grabnet|grafula|gsa-crawler|harvest|hloader|hmview|httplib|httrack|humanlinks|id-search|ilsebot|indy.library|infotekies|interget|intraformant|iron33|jennybot|jetbot|jetcar|joc|jorgee|kenjin|keyword|larbin|leechftp|lexibot|libweb|libwww|linkextractorpro|linkscan|linkwalker|lwp-trivial|mag-net|magnet|markwatch|mass.downloader|masscan|majestic|mj12bot|morfeus|moget|msiecrawler|navroad|nearsite|netants|netmechanic|netspider|nicerspro|npbot|nutch|octopus|offline.explorer|offline.navigator|openfind|outfoxbot|pagegrabber|papa|pavuk|pcbrowser|pockey|propowerbot|prowebwalker|psbot|pump|queryn|radiation|realdownload|reget|retriever|rogerbot|screaming|semalt|semrush|serpstat|siclab|sistrix|siteexplorer|sitelock|sitesucker|skygrid|smartdownload|snoopy|sogou|sosospider|spankbot|spbot|sqlmap|stackrambler|stripper|sucker|superbot|superhttp|surfbot|surveybot|suzuran|swiftbot|takeout|teleport|telesoft|thenomad|tighttwatbot|tocrawl|true_robot|turingos|turnitinbot|ufoseek|urlspiderpro|vacuum|voidbot|voideye|webauto|webbandit|webcollector|webcopier|webcopy|webfetch|webgo|webleacher|webmasterworldforum|webpictures|webreaper|webripper|websauger|webspider|webster|webstripper|webwhacker|webzip|wget|widow|wisenutbot|wotbox|wwwoffle|xaldon|xenu|zade|zeus|zmeu|zune|zyborg) [NC]';
            $rules[] = '    RewriteRule .* - [F,L]';
            $rules[] = '</IfModule>';
            $rules[] = '';
        }

        // Option: block_bad_query_strings
        // UI: "Block Bad Query Strings" checkbox
        if ( ! empty( $this->options['block_bad_query_strings'] ) ) {
            $rules[] = '# Block malicious query strings';
            $rules[] = '<IfModule mod_rewrite.c>';
            $rules[] = '    RewriteEngine On';
            $rules   = array_merge( $rules, $whitelist_exceptions );
            $rules[] = '    # SQL injection patterns';
            $rules[] = '    RewriteCond %{QUERY_STRING} (union.*select) [NC,OR]';
            $rules[] = '    RewriteCond %{QUERY_STRING} (concat\(.*\)) [NC,OR]';
            $rules[] = '    # Script injection';
            $rules[] = '    RewriteCond %{QUERY_STRING} (<script) [NC,OR]';
            $rules[] = '    RewriteCond %{QUERY_STRING} (javascript:) [NC,OR]';
            $rules[] = '    # Path traversal';
            $rules[] = '    RewriteCond %{QUERY_STRING} (\.\.\/) [NC,OR]';
            $rules[] = '    # Sensitive files access';
            $rules[] = '    RewriteCond %{QUERY_STRING} (etc\/passwd) [NC,OR]';
            $rules[] = '    RewriteCond %{QUERY_STRING} (boot\.ini) [NC,OR]';
            $rules[] = '    # PHP exploits';
            $rules[] = '    RewriteCond %{QUERY_STRING} (base64_encode) [NC,OR]';
            $rules[] = '    RewriteCond %{QUERY_STRING} (base64_decode) [NC,OR]';
            $rules[] = '    RewriteCond %{QUERY_STRING} (GLOBALS=) [NC,OR]';
            $rules[] = '    RewriteCond %{QUERY_STRING} (_REQUEST=) [NC,OR]';
            $rules[] = '    # Command injection';
            $rules[] = '    RewriteCond %{QUERY_STRING} (proc\/self) [NC,OR]';
            $rules[] = '    # Null bytes';
            $rules[] = '    RewriteCond %{QUERY_STRING} (%00) [NC]';
            $rules[] = '    RewriteRule .* - [F,L]';
            $rules[] = '</IfModule>';
            $rules[] = '';
        }

        // Option: limit_http_methods
        // UI: "Limit HTTP Methods" checkbox
        // Note: REST API excluded - needs PUT, PATCH, DELETE for plugins like SiteGround Optimizer
        if ( ! empty( $this->options['limit_http_methods'] ) ) {
            $rules[] = '# Block suspicious HTTP methods (allow only GET, POST, HEAD)';
            $rules[] = '# Exception: REST API endpoints need PUT, PATCH, DELETE';
            $rules[] = '<IfModule mod_rewrite.c>';
            $rules[] = '    RewriteEngine On';
            $rules   = array_merge( $rules, $whitelist_exceptions );
            $rules[] = '    RewriteCond %{REQUEST_URI} !^/wp-json/ [NC]';
            $rules[] = '    RewriteCond %{REQUEST_METHOD} ^(connect|debug|move|trace|track) [NC]';
            $rules[] = '    RewriteRule .* - [F,L]';
            $rules[] = '</IfModule>';
            $rules[] = '';
        }

        // =====================================================================
        // SECTION: File Protection
        // =====================================================================

        // Option: protect_wp_config
        // UI: "Protect wp-config.php" checkbox
        // This is SEPARATE from protect_sensitive_files
        if ( ! empty( $this->options['protect_wp_config'] ) ) {
            $rules[] = '# Block direct access to wp-config.php';
            $rules[] = '<Files "wp-config.php">';
            $rules[] = '    <IfModule mod_authz_core.c>';
            $rules[] = '        Require all denied';
            $rules[] = '    </IfModule>';
            $rules[] = '    <IfModule !mod_authz_core.c>';
            $rules[] = '        Order Allow,Deny';
            $rules[] = '        Deny from all';
            $rules[] = '    </IfModule>';
            $rules[] = '</Files>';
            $rules[] = '';
        }

        // Option: protect_wp_cron
        // UI: "Protect wp-cron.php" checkbox (off by default — opt-in only)
        // Blocks direct HTTP access to wp-cron.php to prevent cron-spam DoS abuse.
        // ONLY safe when the host has a real server-side cron job calling wp-cron.php;
        // otherwise scheduled WP tasks stop running. Pairs with the wp-config
        // DISABLE_WP_CRON constant in WP Hardening for full coverage.
        if ( ! empty( $this->options['protect_wp_cron'] ) ) {
            $rules[] = '# Block direct HTTP access to wp-cron.php (host-side cron required)';
            $rules[] = '<Files "wp-cron.php">';
            $rules[] = '    <IfModule mod_authz_core.c>';
            $rules[] = '        Require all denied';
            $rules[] = '    </IfModule>';
            $rules[] = '    <IfModule !mod_authz_core.c>';
            $rules[] = '        Order Allow,Deny';
            $rules[] = '        Deny from all';
            $rules[] = '    </IfModule>';
            $rules[] = '</Files>';
            $rules[] = '';
        }

        // Option: protect_sensitive_files
        // UI: "Sensitive Files" checkbox - blocks .sql, .bak, .log, .ini, etc.
        if ( ! empty( $this->options['protect_sensitive_files'] ) ) {
            $rules[] = '# Block access to sensitive file types (.sql, .bak, .log, .ini, etc.)';
            $rules[] = '<FilesMatch "\.(sql|bak|old|tmp|swp|save|backup|log|ini|htpasswd)$">';
            $rules[] = '    <IfModule mod_authz_core.c>';
            $rules[] = '        Require all denied';
            $rules[] = '    </IfModule>';
            $rules[] = '    <IfModule !mod_authz_core.c>';
            $rules[] = '        Order Allow,Deny';
            $rules[] = '        Deny from all';
            $rules[] = '    </IfModule>';
            $rules[] = '</FilesMatch>';
            $rules[] = '';
            
            // Also block common WordPress sensitive files
            $rules[] = '# Block access to WordPress sensitive files';
            $rules[] = '<FilesMatch "^(readme\.html|license\.txt|licencia\.txt|debug\.log|error_log|php_error\.log|\.htaccess)$">';
            $rules[] = '    <IfModule mod_authz_core.c>';
            $rules[] = '        Require all denied';
            $rules[] = '    </IfModule>';
            $rules[] = '    <IfModule !mod_authz_core.c>';
            $rules[] = '        Order Allow,Deny';
            $rules[] = '        Deny from all';
            $rules[] = '    </IfModule>';
            $rules[] = '</FilesMatch>';
            $rules[] = '';
        }

        // Option: protect_uploads_php
        // UI: "PHP in Uploads" checkbox
        if ( ! empty( $this->options['protect_uploads_php'] ) ) {
            $rules[] = '# Block PHP execution in uploads directory';
            $rules[] = '<IfModule mod_rewrite.c>';
            $rules[] = '    RewriteEngine On';
            $rules[] = '    RewriteRule ^wp-content/uploads/.*\.ph(p[345]?|t|tml|ar)$ - [F,L]';
            $rules[] = '</IfModule>';
            $rules[] = '';
        }

        // Option: protect_wp_includes
        // UI: "Protect wp-includes" checkbox
        if ( ! empty( $this->options['protect_wp_includes'] ) ) {
            $rules[] = '# Block direct access to WordPress includes directory';
            $rules[] = '<IfModule mod_rewrite.c>';
            $rules[] = '    RewriteEngine On';
            $rules[] = '    RewriteBase /';
            $rules[] = '    RewriteRule ^wp-admin/includes/ - [F,L]';
            $rules[] = '    RewriteRule !^wp-includes/ - [S=3]';
            $rules[] = '    RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]';
            $rules[] = '    RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]';
            $rules[] = '    RewriteRule ^wp-includes/theme-compat/ - [F,L]';
            $rules[] = '</IfModule>';
            $rules[] = '';
        }

        // Option: block_php_in_plugins (if enabled in settings, default false)
        if ( ! empty( $this->options['block_php_in_plugins'] ) ) {
            $rules[] = '# Block direct PHP access in plugins';
            $rules[] = '<IfModule mod_rewrite.c>';
            $rules[] = '    RewriteEngine On';
            $rules[] = '    RewriteRule ^wp-content/plugins/.*\.php$ - [F,L]';
            $rules[] = '</IfModule>';
            $rules[] = '';
        }

        // Option: block_php_in_themes (if enabled in settings, default false)
        if ( ! empty( $this->options['block_php_in_themes'] ) ) {
            $rules[] = '# Block direct PHP access in themes (except main templates)';
            $rules[] = '<IfModule mod_rewrite.c>';
            $rules[] = '    RewriteEngine On';
            $rules[] = '    RewriteCond %{REQUEST_URI} !^/wp-content/themes/[^/]+/(functions|single|page|index|archive|category|tag|taxonomy|author|search|404|comments|header|footer|sidebar|front-page|home|template-[^/]+|woocommerce[^/]*)\.php$ [NC]';
            $rules[] = '    RewriteRule ^wp-content/themes/[^/]+/.*\.php$ - [F,L]';
            $rules[] = '</IfModule>';
            $rules[] = '';
        }

        // =====================================================================
        // SECTION: Fingerprinting Prevention
        // =====================================================================
        
        // Option: remove_fingerprinting_headers
        // UI: "Remove Fingerprinting Headers" checkbox
        if ( ! empty( $this->options['remove_fingerprinting_headers'] ) ) {
            $rules[] = '# Remove server fingerprinting headers';
            $rules[] = '<IfModule mod_headers.c>';
            $rules[] = '    Header always unset X-Powered-By';
            $rules[] = '    Header always unset Server';
            $rules[] = '</IfModule>';
        }

        return implode( "\n", $rules );
    }

    /**
     * Generate rules for display/preview
     *
     * @return string
     */
    public function generate_rules() {
        return self::MARKER_START . "\n" . $this->generate_rules_content() . "\n" . self::MARKER_END;
    }

    /**
     * Get rules preview for admin
     *
     * @return array
     */
    public function get_rules_preview() {
        $preview = array();

        if ( ! empty( $this->options['hide_server_signature'] ) ) {
            $preview[] = __( 'Hide server signature', 'vigilante' );
        }

        if ( ! empty( $this->options['disable_directory_browsing'] ) ) {
            $preview[] = __( 'Disable directory listing', 'vigilante' );
        }

        if ( ! empty( $this->options['remove_fingerprinting_headers'] ) ) {
            $preview[] = __( 'Remove fingerprinting headers (X-Powered-By, Server)', 'vigilante' );
        }

        if ( ! empty( $this->options['block_bad_bots'] ) ) {
            $preview[] = __( 'Block malicious bots and crawlers', 'vigilante' );
        }

        if ( ! empty( $this->options['block_bad_query_strings'] ) ) {
            $preview[] = __( 'Block malicious query strings', 'vigilante' );
        }

        if ( ! empty( $this->options['limit_http_methods'] ) ) {
            $preview[] = __( 'Block suspicious HTTP methods', 'vigilante' );
        }

        if ( ! empty( $this->options['protect_wp_config'] ) ) {
            $preview[] = __( 'Block direct access to wp-config.php', 'vigilante' );
        }

        if ( ! empty( $this->options['protect_sensitive_files'] ) ) {
            $preview[] = __( 'Block access to sensitive files (.sql, .bak, .log, etc.)', 'vigilante' );
        }

        if ( ! empty( $this->options['protect_uploads_php'] ) ) {
            $preview[] = __( 'Block PHP execution in uploads', 'vigilante' );
        }

        if ( ! empty( $this->options['protect_wp_includes'] ) ) {
            $preview[] = __( 'Protect wp-includes directory', 'vigilante' );
        }

        return $preview;
    }

    /**
     * Build negated RewriteCond exception lines from the firewall whitelists.
     *
     * The PHP firewall exempts whitelisted IPs and User-Agents from every
     * check, but the rules this class writes run inside Apache before PHP
     * even starts, so the same exemptions must be emitted as negated
     * conditions ahead of each blocking rule. RewriteCond lines are AND-ed
     * with a following [OR] chain, so a whitelisted visitor short-circuits
     * the block while everyone else still hits the filters.
     *
     * @since 2.9.3
     * @return array Lines to insert right after "RewriteEngine On".
     */
    private function generate_whitelist_exceptions() {
        $lines = array();

        // The connection address is always checked. When the site declared a
        // trusted proxy header (Firewall visitor IP detection, v2.7.0), the
        // real visitor IP travels in that header, so it is checked too.
        $ip_variables = array( '%{REMOTE_ADDR}' => false );

        $proxy_variables = array(
            'cf-connecting-ip' => array( '%{HTTP:CF-Connecting-IP}', false ),
            'x-real-ip'        => array( '%{HTTP:X-Real-IP}', false ),
            // X-Forwarded-For may carry a comma-separated proxy chain; the
            // client is the first hop, so a trailing list is allowed.
            'x-forwarded-for'  => array( '%{HTTP:X-Forwarded-For}', true ),
        );

        $trusted = isset( $this->options['trusted_proxy_header'] ) ? (string) $this->options['trusted_proxy_header'] : '';

        if ( isset( $proxy_variables[ $trusted ] ) ) {
            $ip_variables[ $proxy_variables[ $trusted ][0] ] = $proxy_variables[ $trusted ][1];
        }

        $ip_list = isset( $this->options['ip_whitelist'] ) ? (array) $this->options['ip_whitelist'] : array();

        foreach ( $ip_list as $entry ) {
            $pattern = $this->ip_entry_to_pattern( trim( (string) $entry ) );

            if ( null === $pattern ) {
                // Not expressible as a literal match (off-octet CIDR, IPv6
                // CIDR). The PHP firewall layer still honours the entry.
                continue;
            }

            foreach ( $ip_variables as $variable => $is_chain ) {
                if ( 'exact' === $pattern['type'] && ! $is_chain ) {
                    $lines[] = '    RewriteCond ' . $variable . ' "!=' . $pattern['ip'] . '" [NC]';
                } elseif ( 'exact' === $pattern['type'] ) {
                    $lines[] = '    RewriteCond ' . $variable . ' "!^' . $pattern['regex'] . '(,|$)" [NC]';
                } else {
                    $lines[] = '    RewriteCond ' . $variable . ' "!^' . $pattern['regex'] . '" [NC]';
                }
            }
        }

        $ua_list = isset( $this->options['ua_whitelist'] ) ? (array) $this->options['ua_whitelist'] : array();

        foreach ( $ua_list as $ua ) {
            $ua = trim( (string) $ua );

            /*
             * A double quote would break the directive syntax (500 on the whole
             * site), "%" is expanded by mod_rewrite, and a backslash is an
             * escape character twice over: once for Apache inside a quoted
             * argument and once for the regex engine. An entry ending in one
             * escaped the closing quote and answered 500 for every request
             * (reproduced from the settings screen on 25 aug 2026). None of the
             * three can be expressed here safely, so the entry is skipped; the
             * PHP firewall layer still honours it, which is where the matching
             * actually has to be right.
             */
            if ( '' === $ua
                || false !== strpos( $ua, '"' )
                || false !== strpos( $ua, '%' )
                || false !== strpos( $ua, '\\' )
                || preg_match( '/[^\x20-\x7e]/', $ua )
            ) {
                continue;
            }

            $lines[] = '    RewriteCond %{HTTP_USER_AGENT} "!' . preg_quote( $ua ) . '" [NC]';
        }

        if ( ! empty( $lines ) ) {
            array_unshift( $lines, '    # Exceptions: firewall IP / User-Agent whitelist entries bypass these filters' );
        }

        return $lines;
    }

    /**
     * Translate one firewall IP whitelist entry into a literal form that
     * mod_rewrite can match in .htaccess context.
     *
     * Supported: exact IPv4/IPv6, IPv4 wildcards (203.0.113.*), IPv6
     * wildcards (2a02:c207:*) and IPv4 CIDR blocks on octet boundaries
     * (/8, /16, /24, /32). Anything else returns null: .htaccess-level
     * mod_rewrite has no portable CIDR matching, so those entries are
     * covered by the PHP firewall layer only.
     *
     * @since 2.9.3
     * @param string $entry Whitelist entry as stored.
     * @return array|null Array with keys type (exact|prefix), regex and,
     *                    for exact matches, ip. Null when unsupported.
     */
    private function ip_entry_to_pattern( $entry ) {
        if ( '' === $entry ) {
            return null;
        }

        // Exact address. IPv6 is normalized to its compressed lowercase
        // form, which is how Apache reports REMOTE_ADDR.
        if ( filter_var( $entry, FILTER_VALIDATE_IP ) ) {
            $ip = $entry;

            if ( false !== strpos( $entry, ':' ) ) {
                $packed = inet_pton( $entry );

                if ( false === $packed ) {
                    return null;
                }

                $ip = inet_ntop( $packed );
            }

            return array(
                'type'  => 'exact',
                'ip'    => $ip,
                'regex' => preg_quote( $ip ),
            );
        }

        // IPv4 wildcard: 203.0.113.* or 203.0.*
        if ( preg_match( '/^((?:\d{1,3}\.){1,3})\*$/', $entry, $m ) ) {
            return array(
                'type'  => 'prefix',
                'regex' => preg_quote( $m[1] ),
            );
        }

        // IPv6 wildcard: 2a02:c207:*
        if ( preg_match( '/^([0-9a-f]{1,4}(?::[0-9a-f]{1,4})*:)\*$/i', $entry, $m ) ) {
            return array(
                'type'  => 'prefix',
                'regex' => preg_quote( strtolower( $m[1] ) ),
            );
        }

        // IPv4 CIDR on an octet boundary.
        if ( preg_match( '/^(\d{1,3}(?:\.\d{1,3}){3})\/(8|16|24|32)$/', $entry, $m ) && filter_var( $m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            if ( '32' === $m[2] ) {
                return array(
                    'type'  => 'exact',
                    'ip'    => $m[1],
                    'regex' => preg_quote( $m[1] ),
                );
            }

            $octets = explode( '.', $m[1] );
            $keep   = (int) $m[2] / 8;
            $prefix = implode( '.', array_slice( $octets, 0, $keep ) ) . '.';

            return array(
                'type'  => 'prefix',
                'regex' => preg_quote( $prefix ),
            );
        }

        return null;
    }
}