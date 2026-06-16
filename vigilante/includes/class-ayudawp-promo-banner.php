<?php
/**
 * Vigilante Promotional Banner
 *
 * Promotional banner for Vigilante plugin.
 *
 * @package Vigilante
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Vigilante Promo Banner class
 */
class Vigilante_Promo_Banner {

    /**
     * Current plugin slug to exclude from recommendations
     *
     * @var string
     */
    private $current_plugin_slug;

    /**
     * CSS class prefix for styling
     *
     * @var string
     */
    private $css_prefix;

    /**
     * Constructor
     *
     * @param string $current_plugin_slug Slug of the current plugin to exclude.
     * @param string $css_prefix          CSS class prefix for styling.
     */
    public function __construct( $current_plugin_slug, $css_prefix ) {
        $this->current_plugin_slug = $current_plugin_slug;
        $this->css_prefix          = $css_prefix;
    }

    /**
     * Get AyudaWP plugins catalog
     *
     * @return array Array of plugins with slug, icon, title, description, and button text.
     */
    private function get_plugins_catalog() {
        // Catalog kept in alphabetical order by slug. Source of truth lives in
        // /mis-plugins/ayudawp-promo-banner-catalog.md. The current host slug is
        // excluded at runtime in get_random_plugins().
        return array(
            'ai-content-signals' => array(
                'icon'        => 'dashicons-flag',
                'title'       => __( 'Control AI content usage', 'vigilante' ),
                'description' => __( 'Cloudflare-endorsed plugin to define how AI systems can use your content: for training, search results, or both.', 'vigilante' ),
                'button'      => __( 'Install AI Content Signals', 'vigilante' ),
            ),
            'ai-share-summarize' => array(
                'icon'        => 'dashicons-share',
                'title'       => __( 'Boost your AI presence', 'vigilante' ),
                'description' => __( 'Add social sharing and AI summarize buttons. Help visitors share your content and let AIs learn from your site while getting backlinks.', 'vigilante' ),
                'button'      => __( 'Install AI Share & Summarize', 'vigilante' ),
            ),
            'anticache' => array(
                'icon'        => 'dashicons-hammer',
                'title'       => __( 'Development toolkit', 'vigilante' ),
                'description' => __( 'Bypass all caching during development. Auto-detects cache plugins, enables debug mode, and includes maintenance screen.', 'vigilante' ),
                'button'      => __( 'Install Anti-Cache Kit', 'vigilante' ),
            ),
            'auto-capitalize-names-ayudawp' => array(
                'icon'        => 'dashicons-editor-textcolor',
                'title'       => __( 'Fix customer names', 'vigilante' ),
                'description' => __( 'Auto-capitalize names and addresses in WordPress and WooCommerce. Keep invoices and reports professionally formatted.', 'vigilante' ),
                'button'      => __( 'Install Auto Capitalize', 'vigilante' ),
            ),
            'easy-actions-scheduler-cleaner-ayudawp' => array(
                'icon'        => 'dashicons-database-remove',
                'title'       => __( 'Clean Action Scheduler', 'vigilante' ),
                'description' => __( 'Remove millions of completed, failed, and old actions from WooCommerce Action Scheduler. Reduce database size instantly.', 'vigilante' ),
                'button'      => __( 'Install Scheduler Cleaner', 'vigilante' ),
            ),
            'easy-store-management-ayudawp' => array(
                'icon'        => 'dashicons-store',
                'title'       => __( 'Simplify store management', 'vigilante' ),
                'description' => __( 'Clean up WordPress admin for Store Managers. Hide unnecessary menus, keep only orders, products, and customers, plus quick access shortcuts.', 'vigilante' ),
                'button'      => __( 'Install Easy Store', 'vigilante' ),
            ),
            'eu-withdrawal-compliance' => array(
                'icon'        => 'dashicons-undo',
                'title'       => __( 'EU withdrawal compliance', 'vigilante' ),
                'description' => __( 'Add the EU online withdrawal function required by Directive 2023/2673 from June 2026. Public form, My Account button, email notice and SHA-256 receipt hash.', 'vigilante' ),
                'button'      => __( 'Install EU Withdrawal', 'vigilante' ),
            ),
            'gozer' => array(
                'icon'        => 'dashicons-admin-network',
                'title'       => __( 'Restrict site access', 'vigilante' ),
                'description' => __( 'Force visitors to log in before accessing your site with extensive exception controls for pages, posts, and user roles.', 'vigilante' ),
                'button'      => __( 'Install Gozer', 'vigilante' ),
            ),
            'lightbox-images-for-divi' => array(
                'icon'        => 'dashicons-format-gallery',
                'title'       => __( 'Lightbox for Divi', 'vigilante' ),
                'description' => __( 'Add native lightbox functionality to Divi theme images. No jQuery, fast loading, fully customizable.', 'vigilante' ),
                'button'      => __( 'Install Divi Lightbox', 'vigilante' ),
            ),
            'multiple-sale-prices-scheduler' => array(
                'icon'        => 'dashicons-calendar-alt',
                'title'       => __( 'Schedule sale prices', 'vigilante' ),
                'description' => __( 'Set multiple future sale prices for WooCommerce products. Plan promotions in advance with start and end dates.', 'vigilante' ),
                'button'      => __( 'Install Sale Scheduler', 'vigilante' ),
            ),
            'native-aeo-pack' => array(
                'icon'        => 'dashicons-visibility',
                'title'       => __( 'All-in-one SEO, AEO & GEO', 'vigilante' ),
                'description' => __( 'Meta tags, Open Graph, JSON-LD schema, robots and native sitemap control: the clean metadata search engines and AI assistants read, built on WordPress core.', 'vigilante' ),
                'button'      => __( 'Install Visibility', 'vigilante' ),
            ),
            'no-gutenberg' => array(
                'icon'        => 'dashicons-edit-page',
                'title'       => __( 'Back to Classic Editor', 'vigilante' ),
                'description' => __( 'Completely remove Gutenberg, FSE styles, and block widgets. Restore the classic editing experience with better performance.', 'vigilante' ),
                'button'      => __( 'Install No Gutenberg', 'vigilante' ),
            ),
            'periscopio' => array(
                'icon'        => 'dashicons-rss',
                'title'       => __( 'Custom Dashboard News', 'vigilante' ),
                'description' => __( 'Add your own custom feeds and links to the news and events dashboard widget and replace WordPress default one.', 'vigilante' ),
                'button'      => __( 'Install Periscope', 'vigilante' ),
            ),
            'post-visibility-control' => array(
                'icon'        => 'dashicons-hidden',
                'title'       => __( 'Control post visibility', 'vigilante' ),
                'description' => __( 'Hide posts from homepage, archives, feeds, or REST API while keeping them accessible via direct URL.', 'vigilante' ),
                'button'      => __( 'Install Post Visibility', 'vigilante' ),
            ),
            'scheduled-posts-showcase' => array(
                'icon'        => 'dashicons-clock',
                'title'       => __( 'Show visitors what is coming up next', 'vigilante' ),
                'description' => __( 'Display your scheduled and future posts on the frontend to gain and retain visits.', 'vigilante' ),
                'button'      => __( 'Install Scheduled Posts Showcase', 'vigilante' ),
            ),
            'search-replace-text-blocks' => array(
                'icon'        => 'dashicons-search',
                'title'       => __( 'Search & replace in blocks', 'vigilante' ),
                'description' => __( 'Find and replace text across all your Gutenberg blocks. Bulk edit content without touching the database directly.', 'vigilante' ),
                'button'      => __( 'Install Search Replace Blocks', 'vigilante' ),
            ),
            'seo-read-more-buttons-ayudawp' => array(
                'icon'        => 'dashicons-admin-links',
                'title'       => __( 'Better read more links', 'vigilante' ),
                'description' => __( 'Customize excerpt "read more" links with buttons, custom text, and nofollow option. Improve CTR and SEO.', 'vigilante' ),
                'button'      => __( 'Install SEO Read More', 'vigilante' ),
            ),
            'show-only-lowest-prices-in-woocommerce-variable-products' => array(
                'icon'        => 'dashicons-tag',
                'title'       => __( 'Cleaner variable prices', 'vigilante' ),
                'description' => __( 'Display only the lowest price for WooCommerce variable products instead of confusing price ranges.', 'vigilante' ),
                'button'      => __( 'Install Lowest Price', 'vigilante' ),
            ),
            'terms-conditions-consent-log' => array(
                'icon'        => 'dashicons-yes-alt',
                'title'       => __( 'Tamper-evident consent log', 'vigilante' ),
                'description' => __( 'GDPR art. 7.1 audit trail for any acceptance checkbox: WooCommerce checkout, CF7, WPForms, comments and shortcode. Timestamp, IP, version and SHA-256 sealed text.', 'vigilante' ),
                'button'      => __( 'Install Consent Log', 'vigilante' ),
            ),
            'vigia' => array(
                'icon'        => 'dashicons-visibility',
                'title'       => __( 'Monitor AI crawler activity', 'vigilante' ),
                'description' => __( 'Track which AI bots visit your site, analyze their behavior, and take control with blocking rules and robots.txt management.', 'vigilante' ),
                'button'      => __( 'Install VigIA', 'vigilante' ),
            ),
            'vigilante' => array(
                'icon'        => 'dashicons-shield',
                'title'       => __( 'Complete WordPress security', 'vigilante' ),
                'description' => __( 'All-in-one security plugin: firewall, login protection, security headers, 2FA, file integrity monitoring, and activity logging.', 'vigilante' ),
                'button'      => __( 'Install Vigilant', 'vigilante' ),
            ),
            'widget-visibility-control' => array(
                'icon'        => 'dashicons-welcome-widgets-menus',
                'title'       => __( 'Smart widget display', 'vigilante' ),
                'description' => __( 'Show or hide widgets based on pages, post types, categories, user roles, and more. Works with any theme.', 'vigilante' ),
                'button'      => __( 'Install Widget Visibility', 'vigilante' ),
            ),
            'wpo-tweaks' => array(
                'icon'        => 'dashicons-food',
                'title'       => __( 'Put WordPress on a diet', 'vigilante' ),
                'description' => __( 'Disable bloat and apply 30+ performance tweaks (critical CSS, lazy loading, cache rules) with zero configuration for a leaner, faster site.', 'vigilante' ),
                'button'      => __( 'Install DietPress', 'vigilante' ),
            ),
        );
    }

    /**
     * Get AyudaWP services catalog
     *
     * @return array Array of services with icon, title, description, button text, and URL.
     */
    private function get_services_catalog() {
        return array(
            'maintenance' => array(
                'icon'        => 'dashicons-admin-tools',
                'title'       => __( 'Need help with your website?', 'vigilante' ),
                'description' => __( 'Professional WordPress maintenance: security monitoring, regular backups, performance optimization, and priority support.', 'vigilante' ),
                'button'      => __( 'Learn more', 'vigilante' ),
                'url'         => 'https://mantenimiento.ayudawp.com',
            ),
            'consultancy' => array(
                'icon'        => 'dashicons-businessman',
                'title'       => __( 'WordPress consultancy', 'vigilante' ),
                'description' => __( 'One-on-one online sessions to solve your WordPress doubts, get expert advice, and make better decisions for your project.', 'vigilante' ),
                'button'      => __( 'Book a session', 'vigilante' ),
                'url'         => 'https://servicios.ayudawp.com/producto/consultoria-online-wordpress/',
            ),
            'hacked' => array(
                'icon'        => 'dashicons-sos',
                'title'       => __( 'Hacked website?', 'vigilante' ),
                'description' => __( 'Fast recovery service for compromised WordPress sites. We clean malware, fix vulnerabilities, and restore your site security.', 'vigilante' ),
                'button'      => __( 'Get help now', 'vigilante' ),
                'url'         => 'https://servicios.ayudawp.com/producto/wordpress-hackeado/',
            ),
            'development' => array(
                'icon'        => 'dashicons-editor-code',
                'title'       => __( 'Custom development', 'vigilante' ),
                'description' => __( 'Need a custom plugin, theme modifications, or specific functionality? We build tailored WordPress solutions for your needs.', 'vigilante' ),
                'button'      => __( 'Request a quote', 'vigilante' ),
                'url'         => 'https://servicios.ayudawp.com/producto/desarrollo-wordpress/',
            ),
            'hosting' => array(
                'icon'        => 'dashicons-cloud-saved',
                'title'       => __( 'Hosting built for WordPress', 'vigilante' ),
                'description' => __( 'Google Cloud servers, automatic geo-located daily backups, and 24/7 expert support. Speed, security, and migration tools included.', 'vigilante' ),
                'button'      => __( 'Learn more', 'vigilante' ),
                /* translators: SiteGround affiliate URL. Change this URL in translations to use a localized landing page. */
                'url'         => __( 'https://stgrnd.co/telladowpbox', 'vigilante' ),
            ),
        );
    }

    /**
     * Get random plugins excluding current
     *
     * @param int $count Number of plugins to return.
     * @return array Array of random plugins.
     */
    private function get_random_plugins( $count = 2 ) {
        $plugins = $this->get_plugins_catalog();

        // Remove current plugin from recommendations.
        unset( $plugins[ $this->current_plugin_slug ] );

        // Handle edge case where count exceeds available plugins.
        $available_count = count( $plugins );
        if ( $count >= $available_count ) {
            return $plugins;
        }

        // Get random keys.
        $random_keys = array_rand( $plugins, $count );

        // array_rand returns a single key if count is 1, not an array.
        if ( ! is_array( $random_keys ) ) {
            $random_keys = array( $random_keys );
        }

        $result = array();
        foreach ( $random_keys as $key ) {
            $result[ $key ] = $plugins[ $key ];
        }

        return $result;
    }

    /**
     * Get random service
     *
     * @return array Single random service data.
     */
    private function get_random_service() {
        $services   = $this->get_services_catalog();
        $random_key = array_rand( $services );

        return $services[ $random_key ];
    }

    /**
     * Render the promotional sidebar widgets
     *
     * Outputs 2 random plugin widgets + 1 random service widget in vertical layout.
     */
    public function render() {
        $plugins = $this->get_random_plugins( 2 );
        $service = $this->get_random_service();
        $prefix  = $this->css_prefix;

        // Render plugin widgets.
        foreach ( $plugins as $slug => $plugin ) :
            ?>
            <div class="<?php echo esc_attr( $prefix ); ?>-sidebar-widget <?php echo esc_attr( $prefix ); ?>-promo-widget">
                <span class="dashicons <?php echo esc_attr( $plugin['icon'] ); ?>"></span>
                <h3><?php echo esc_html( $plugin['title'] ); ?></h3>
                <p><?php echo esc_html( $plugin['description'] ); ?></p>
                <a href="<?php echo esc_url( admin_url( 'plugin-install.php?tab=plugin-information&plugin=' . $slug . '&TB_iframe=true&width=772&height=618' ) ); ?>" class="button thickbox">
                    <?php echo esc_html( $plugin['button'] ); ?>
                </a>
            </div>
            <?php
        endforeach;

        // Render service widget.
        ?>
        <div class="<?php echo esc_attr( $prefix ); ?>-sidebar-widget <?php echo esc_attr( $prefix ); ?>-promo-widget">
            <span class="dashicons <?php echo esc_attr( $service['icon'] ); ?>"></span>
            <h3><?php echo esc_html( $service['title'] ); ?></h3>
            <p><?php echo esc_html( $service['description'] ); ?></p>
            <a href="<?php echo esc_url( $service['url'] ); ?>" target="_blank" rel="noopener noreferrer" class="button button-primary">
                <?php echo esc_html( $service['button'] ); ?>
            </a>
        </div>
        <?php
    }
}