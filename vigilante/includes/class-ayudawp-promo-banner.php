<?php
/**
 * Vigilante Promotional Banner
 *
 * Promotional banner that rotates AyudaWP's WordPress services. On every
 * settings-page load it shows a random subset of service cards.
 *
 * Mirror of ayudawp-promo-banner-catalog-servicios.md (the single source of
 * truth). Plugin cross-promotion was dropped in 2.9.3: the banner shows only
 * services, so there is no host/sibling plugin to exclude and no
 * wordpress.org install modal (Thickbox) to load for it.
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
     * How many service cards the banner shows at once.
     *
     * @var int
     */
    const CARDS = 3;

    /**
     * CSS class prefix for styling
     *
     * @var string
     */
    private $css_prefix;

    /**
     * Constructor
     *
     * @param string $css_prefix CSS class prefix for styling.
     */
    public function __construct( $css_prefix ) {
        $this->css_prefix = $css_prefix;
    }

    /**
     * Get AyudaWP services catalog
     *
     * Mirror of ayudawp-promo-banner-catalog-servicios.md. All strings use
     * the literal text domain (WPCS / make-pot requirement).
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
                /* translators: Maintenance service URL. Change this URL in translations to use a localized landing page. */
                'url'         => __( 'https://mantenimiento.ayudawp.com/en/', 'vigilante' ),
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
     * Get a random subset of services to display.
     *
     * @param int $count Number of services to return.
     * @return array Subset of the catalog, keyed by service key.
     */
    private function get_random_services( $count = self::CARDS ) {
        $services = $this->get_services_catalog();

        $count       = max( 1, min( (int) $count, count( $services ) ) );
        $random_keys = array_rand( $services, $count );
        if ( ! is_array( $random_keys ) ) {
            $random_keys = array( $random_keys );
        }

        $result = array();
        foreach ( $random_keys as $key ) {
            $result[ $key ] = $services[ $key ];
        }

        return $result;
    }

    /**
     * Render the promotional sidebar widgets
     *
     * Outputs 3 random service widgets in vertical layout.
     */
    public function render() {
        $services = $this->get_random_services();
        $prefix   = $this->css_prefix;

        foreach ( $services as $service ) :
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
        endforeach;
    }
}
