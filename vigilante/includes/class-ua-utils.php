<?php
/**
 * User-Agent utilities
 *
 * One place decides what a line of the User-Agent blacklist would block, so the
 * save, the import, the Firewall tab, the Dashboard and the activity log popup
 * cannot tell different stories about the same line.
 *
 * @package Vigilante
 * @since   3.0.11
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Vigilante_UA_Utils
 */
class Vigilante_UA_Utils {

    /**
     * Verdicts, from the one that weighs most to the one that weighs least.
     *
     * Own, site and browser keep the line out of the list when it is new.
     * Engine is stored with a warning. Ok is stored as it is.
     */
    const VERDICT_OWN     = 'own';
    const VERDICT_SITE    = 'site';
    const VERDICT_BROWSER = 'browser';
    const VERDICT_ENGINE  = 'engine';
    const VERDICT_OK      = 'ok';

    /**
     * The User-Agent of the browsers people use, as they send it.
     *
     * Chrome, Edge and Safari send the same string to everybody on the same
     * version and system (Chrome's User-Agent reduction freezes the system
     * part: macOS always reads 10_15_7, Windows 10.0, Android "10; K"), and
     * bots copy these strings to pass as a visitor. A blacklist line contained
     * in one of them blocks every person who uses that browser: on 7 Nov 2026
     * a line copied from a bot that pretended to be Chrome on Mac locked an
     * administrator out of her own site (B123).
     *
     * The browser versions here go stale; normalize() takes out of both sides
     * the versions that can be in use, so a line written for a newer version
     * is still recognised.
     *
     * @return array<int, array{label: string, ua: string}>
     */
    public static function browser_references() {
        return array(
            array(
                'label' => __( 'Chrome on Mac', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Chrome on Windows', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Chrome on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'Chrome on iPhone', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/156.0.0.0 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'Edge on Windows', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0',
            ),
            array(
                'label' => __( 'Safari on Mac', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.1 Safari/605.1.15',
            ),
            array(
                'label' => __( 'Safari on iPhone', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.1 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'Firefox on Windows', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            array(
                'label' => __( 'Firefox on Mac', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            array(
                'label' => __( 'Firefox on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Android 15; Mobile; rv:157.0) Gecko/157.0 Firefox/157.0',
            ),
            // Added after the first blind review of 3.0.11: without them a whole
            // Chrome on Linux User-Agent, or "X11", was stored and blocked
            // everybody on Linux.
            array(
                'label' => __( 'Chrome on Linux', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Firefox on Linux', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            array(
                'label' => __( 'Chrome on ChromeOS', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Opera on Windows', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 OPR/141.0.0.0',
            ),
            array(
                'label' => __( 'Samsung Internet on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 15; SAMSUNG SM-S931B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/29.0 Chrome/156.0.0.0 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'Firefox on iPhone', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/157.0 Mobile/15E148 Safari/605.1.15',
            ),
            array(
                'label' => __( 'Edge on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36 EdgA/156.0.0.0',
            ),
            // Added after the second blind review: the system versions are not
            // taken out (Windows NT 5.1 has to stay apart from 10.0), so the
            // ones still in use are listed as browsers send them.
            array(
                'label' => __( 'Firefox on Ubuntu', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            array(
                'label' => __( 'Firefox on Fedora', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            array(
                'label' => __( 'Safari on iPad', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPad; CPU OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.1 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'Chrome on iPad', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPad; CPU OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/156.0.0.0 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'Safari on an older iPhone', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.7 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'Edge on iPhone', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.1 EdgiOS/156.0.0.0 Mobile/15E148 Safari/605.1.15',
            ),
            array(
                'label' => __( 'Firefox on an Android tablet', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Android 14; Tablet; rv:157.0) Gecko/157.0 Firefox/157.0',
            ),
            array(
                'label' => __( 'Samsung Internet on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/29.0 Chrome/156.0.0.0 Mobile Safari/537.36',
            ),
            // Added after the second blind review of 3.0.12: browsers with no
            // reference were not recognised in a piece of their User-Agent.
            array(
                'label' => __( 'Edge on Mac', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0',
            ),
            array(
                'label' => __( 'Opera on Mac', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 OPR/141.0.0.0',
            ),
            array(
                'label' => __( 'Opera on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36 OPR/93.0.0.0',
            ),
            array(
                'label' => __( 'Yandex Browser on Windows', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 YaBrowser/26.1.0.0 Yowser/2.5 Safari/537.36',
            ),
            array(
                'label' => __( 'Android apps that show web pages (WebView)', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 12; Pixel 6 Build/SQ3A.220705.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Mobile Safari/537.36',
            ),
            // Added when Fernando decided on 8 Nov 2026 that what the blind
            // reviews of 3.0.12 left open goes in this version.
            //
            // Windows 7 and 8.1 stopped at Chrome 109 and Firefox ESR 115, and
            // people still use them, with those and with forks that carry a
            // newer Chromium (Supermium, Thorium). Windows XP and Vista (NT 5.1
            // and 6.0) stay blockable: no browser in use runs there.
            array(
                'label' => __( 'Chrome on Windows 7', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Chrome on Windows 7', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Chrome on Windows 8.1', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Firefox on Windows 7', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0',
            ),
            array(
                'label' => __( 'Firefox on Windows (32-bit)', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:157.0) Gecko/20100101 Firefox/157.0',
            ),
            // Browsers inside apps, which carry the version of the app.
            array(
                'label' => __( 'the Facebook app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/480.0.0.40.94;FBBV/700000000;FBDV/iPhone15,2;FBMD/iPhone;FBSN/iOS;FBSV/18.6;FBSS/3;FBCR/;FBID/phone;FBLC/es_ES;FBOP/80]',
            ),
            array(
                'label' => __( 'the Facebook app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; SM-S918B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/480.0.0.40.94;]',
            ),
            array(
                'label' => __( 'the Instagram app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 350.0.0.25.104 (iPhone15,2; iOS 18_6; es_ES; es; scale=3.00; 1179x2556; 600000000)',
            ),
            array(
                'label' => __( 'the Instagram app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; SM-S918B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Mobile Safari/537.36 Instagram 350.0.0.47.109 Android (34/14; 480dpi; 1080x2340; samsung; SM-S918B; dm3q; qcom; es_ES; 600000000)',
            ),
            array(
                'label' => __( 'the Google app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/350.0.711567543 Mobile/15E148 Safari/604.1',
            ),
            array(
                'label' => __( 'the Google app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; SM-S918B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Mobile Safari/537.36 GSA/15.49.43.29.arm64',
            ),
            array(
                'label' => __( 'WeChat', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; 23078RKD5C Build/UP1A.230905.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.6723.103 Mobile Safari/537.36 XWEB/1300333 MMWEBSDK/20240404 MMWEBID/5090 MicroMessenger/8.0.49.2600(0x28003133) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64',
            ),
            array(
                'label' => __( 'the TikTok app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 musical_ly_41.3.0 JsSdk/2.0 NetType/WIFI Channel/App Store ByteLocale/es Region/ES BytedanceWebview/d8a21c6',
            ),
            array(
                'label' => __( 'DuckDuckGo browser', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Mobile DuckDuckGo/5 Safari/537.36',
            ),
            array(
                'label' => __( 'DuckDuckGo browser', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 DuckDuckGo/7 Safari/605.1.15',
            ),
            // Browsers of phones, TVs and consoles that keep an old engine.
            array(
                'label' => __( 'Opera Mini', 'vigilante' ),
                'ua'    => 'Opera/9.80 (Android; Opera Mini/88.0.2254/191.303; U; es) Presto/2.12.423 Version/12.16',
            ),
            array(
                'label' => __( 'Yandex Browser on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 YaBrowser/26.1.0.0 SA/3 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'Huawei Browser', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 10; HarmonyOS; NOH-NX9; HMSCore 6.14.0.302) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 HuaweiBrowser/15.0.4.312 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'UC Browser', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; U; Android 13; es-ES; SM-A536B Build/TP1A.220624.014) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/78.0.3904.108 UCBrowser/13.4.0.1306 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'KaiOS phones', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Mobile; LYF/F300B/LYF-F300B-001-01-15-130718-i;Android; rv:48.0) Gecko/48.0 Firefox/48.0 KAIOS/2.5',
            ),
            array(
                'label' => __( 'KaiOS phones', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Mobile; Nokia 2780 Flip; rv:84.0) Gecko/84.0 Firefox/84.0 KAIOS/3.1',
            ),
            array(
                'label' => __( 'LG TVs (webOS)', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.128 Safari/537.36 WebAppManager',
            ),
            array(
                'label' => __( 'Samsung TVs (Tizen)', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (SMART-TV; LINUX; Tizen 6.5) AppleWebKit/537.36 (KHTML, like Gecko) 85.0.4183.93/6.5 TV Safari/537.36',
            ),
            array(
                'label' => __( 'PlayStation', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (PlayStation; PlayStation 5/2.26) AppleWebKit/605.1.15 (KHTML, like Gecko)',
            ),
            array(
                'label' => __( 'Xbox', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox Series X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edge/44.18363.8131',
            ),
            // Added after the fourth blind review of 3.0.12.
            array(
                'label' => __( 'Chrome on Windows 7', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Chrome on Windows 8.1', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Firefox on Windows 7', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 6.1; rv:115.0) Gecko/20100101 Firefox/115.0',
            ),
            array(
                'label' => __( 'Firefox on Windows 7', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:115.0) Gecko/20100101 Firefox/115.0',
            ),
            array(
                'label' => __( 'Firefox on Windows 8.1', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0',
            ),
            array(
                'label' => __( 'Android tablets (WebView)', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; SM-X710 Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Samsung Internet on a tablet', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/29.0 Chrome/156.0.0.0 Safari/537.36',
            ),
            array(
                'label' => __( 'Yandex Browser on Android', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; arm_64; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 YaBrowser/26.1.0.0 SA/3 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'Huawei Browser', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 12; HarmonyOS; NOH-NX9; HMSCore 6.14.0.302) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.196 HuaweiBrowser/15.0.4.312 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'UC Browser', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; U; Android 14; es-ES; SM-A546B Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/123.0.6312.80 UCBrowser/13.8.2.1324 Mobile Safari/537.36',
            ),
            array(
                'label' => __( 'LG TVs (webOS)', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.211 Safari/537.36 WebAppManager',
            ),
            array(
                'label' => __( 'Samsung TVs (Tizen)', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (SMART-TV; LINUX; Tizen 8.0) AppleWebKit/537.36 (KHTML, like Gecko) 108.0.5359.1/8.0 TV Safari/537.36',
            ),
            array(
                'label' => __( 'PlayStation', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (PlayStation 4 11.00) AppleWebKit/605.1.15 (KHTML, like Gecko)',
            ),
            array(
                'label' => __( 'Xbox', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edge/44.18363.8131',
            ),
            array(
                'label' => __( 'the LinkedIn app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [LinkedInApp]/9.31.1',
            ),
            array(
                'label' => __( 'the Pinterest app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [Pinterest/iOS]',
            ),
            array(
                'label' => __( 'the Pinterest app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; SM-S918B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Mobile Safari/537.36 [Pinterest/Android]',
            ),
            array(
                'label' => __( 'the Telegram app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; SM-S918B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Mobile Safari/537.36 Telegram-Android/11.4.2 (Samsung SM-S918B; Android 14; SDK 34; HIGH)',
            ),
            array(
                'label' => __( 'the Snapchat app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Snapchat/13.20.0.39 (like Safari/8621.1.15.10.7, panda)',
            ),
            array(
                'label' => __( 'the Messenger app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 14; SM-S918B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Mobile Safari/537.36 [FB_IAB/Orca-Android;FBAV/480.0.0.40.94;]',
            ),
            array(
                'label' => __( 'the Messenger app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 LightSpeed [FBAN/MessengerLiteForiOS;FBAV/480.0.0.40.94;FBBV/700000000;FBDV/iPhone15,2;FBMD/iPhone;FBSN/iOS;FBSV/18.6;FBSS/3;FBCR/;FBID/phone;FBLC/es_ES;FBOP/0]',
            ),
            array(
                'label' => __( 'the LINE app', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari Line/14.15.0',
            ),
            array(
                'label' => __( 'Xiaomi browser', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; U; Android 14; es-es; 23078RKD5C Build/UP1A.230905.011) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.6099.230 Mobile Safari/537.36 XiaoMi/MiuiBrowser/14.15.1-gn',
            ),
            array(
                'label' => __( 'Amazon Silk', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Linux; Android 11; KFRASWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/131.5.3 like Chrome/131.0.6778.260 Safari/537.36',
            ),
            array(
                'label' => __( 'DuckDuckGo browser', 'vigilante' ),
                'ua'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15 Ddg/18.6',
            ),
        );
    }

    /**
     * Search engines a line can block by accident. Stored with a warning.
     *
     * @return array<int, array{label: string, ua: string}>
     */
    public static function engine_references() {
        return array(
            array(
                'label' => 'Googlebot',
                'ua'    => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            ),
            array(
                'label' => 'Googlebot',
                'ua'    => 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            ),
            array(
                'label' => 'Bingbot',
                'ua'    => 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            ),
        );
    }

    /**
     * The User-Agent WordPress sends when it calls itself (WP-Cron, the REST
     * API and loopback tests of Site Health), built as WP_Http builds it
     * (wp-includes/class-wp-http.php, the user-agent argument).
     *
     * @return string
     */
    public static function site_user_agent() {
        $default = 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' );
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter, applied as WP_Http applies it so the value matches what the site sends.
        $filtered = apply_filters( 'http_headers_useragent', $default, home_url( '/' ) );

        return is_string( $filtered ) ? $filtered : $default;
    }

    /**
     * The User-Agent of the request being served, as the firewall reads it.
     *
     * Only used to stop administrators from blacklisting their own browser:
     * it is chosen by the caller, who is the administrator saving, and all it
     * can do is keep a line out of the list they are writing.
     *
     * @return string
     */
    public static function current_user_agent() {
        return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
    }

    /**
     * Lower case, with the version numbers people's browsers vary in taken out.
     *
     * The browser's own versions, and the systems that people keep using in
     * many versions: Android together with the device that follows it, iOS
     * and iPadOS, macOS and the processor of Linux. Until the third blind
     * review of 3.0.11 only the first were taken out, and "Android 14",
     * "iPhone OS 17_5" or the whole User-Agent of a Samsung of another model
     * were stored and blocked the people who use them. A device named on its
     * own ("SM-S918B") is still not recognised: nothing lists every phone.
     *
     * Only a version that can be in use is taken out (version_in_use()). In
     * 3.0.11 every version was, so "Chrome/49.0.2623", "Firefox/3.6" or
     * "Android 4.4" read as the browsers of today and were refused, while the
     * firewall compares lines as written and those block only that old
     * version, which is one of the usual signatures of a bot (B125, reported
     * by Albert Calzada). An old version is left as written on both sides, so
     * a constant that a browser still sends, such as the "Version/4.0" of the
     * Android WebView, is compared as it is.
     *
     * Gecko carries the browser version in Firefox for Android ("Gecko/157.0",
     * B125 too): without it, the whole User-Agent of a newer Firefox for
     * Android was stored. On the desktop it is the constant "Gecko/20100101".
     *
     * Windows stays as it is, on purpose: Windows NT 5.1 (XP) is a usual
     * signature of bots, and somebody may block it.
     *
     * @param string $value        A User-Agent or a blacklist line.
     * @param bool   $open_as_is   Leave a version at the end of the line as
     *                             written, because it may be the beginning of a
     *                             constant such as "Gecko/20100101" (3.0.12).
     * @param bool   $fold_device  Turn the device after the Android version
     *                             into "device" and the processor of Linux into
     *                             "arch", so another model is still recognised;
     *                             false leaves them as written, for a line that
     *                             starts inside them (3.0.12).
     * @return string
     */
    public static function normalize( $value, $open_as_is = false, $fold_device = true ) {
        // The same references are normalized for every line that is checked:
        // remembered for the request (150 ms for 100 saved lines without it,
        // measured on 8 Nov 2026). Bounded, for long processes such as cron.
        static $memo  = array();
        static $bytes = 0;
        $key = md5( ( $open_as_is ? '1' : '0' ) . ( $fold_device ? '1' : '0' ) . (string) $value );
        if ( isset( $memo[ $key ] ) ) {
            return $memo[ $key ];
        }
        $result = self::normalize_uncached( $value, $open_as_is, $fold_device );
        // Bounded by size, not by count: one pasted line can be very long. Each
        // entry also costs its key and the array slot, about 200 bytes.
        $bytes += strlen( $result ) + 200;
        if ( $bytes > 2097152 ) {
            $memo  = array();
            $bytes = strlen( $result ) + 200;
        }
        $memo[ $key ] = $result;

        return $result;
    }

    /**
     * What normalize() returns, worked out.
     *
     * @since 3.0.12
     *
     * @param string $value       A User-Agent or a blacklist line.
     * @param bool   $open_as_is  As in normalize().
     * @param bool   $fold_device As in normalize().
     * @return string
     */
    private static function normalize_uncached( $value, $open_as_is, $fold_device ) {
        $families = array(
            'chrome'         => 'chrome',
            'crios'          => 'chrome',
            'edg'            => 'chrome',
            'edga'           => 'chrome',
            'edgios'         => 'chrome',
            'firefox'        => 'firefox',
            'fxios'          => 'firefox',
            'gecko'          => 'firefox',
            'rv'             => 'firefox',
            'opr'            => 'opr',
            'samsungbrowser' => 'samsung',
            'yabrowser'      => 'yandex',
            'version'        => 'safari',
            'fbav'           => 'facebook',
            'instagram'      => 'instagram',
            'gsa'            => 'google',
            'micromessenger' => 'wechat',
            'huaweibrowser'  => 'huawei',
            'ucbrowser'      => 'uc',
            'kaios'          => 'kaios',
            'duckduckgo'     => 'duckduckgo',
            'opera mini'     => 'operamini',
            'tizen'          => 'tizen',
            'fbsv'           => 'ios',
            'ios'            => 'ios',
            'android'        => 'android',
            'os'             => 'ios',
            'iphone os'      => 'ios',
            'mac os x'       => 'mac',
        );

        // Name, separator, version and, for Android, the device that follows.
        $rules = array(
            '#\b(chrome|crios|firefox|fxios|gecko|edg|edga|edgios|opr|version|samsungbrowser|yabrowser)(/)([0-9][0-9.]*)()#',
            '#\b(fbav|gsa|micromessenger|huaweibrowser|ucbrowser|kaios|duckduckgo|opera mini)(/)([0-9][0-9.]*)()#',
            '#\b(instagram|tizen)( )([0-9][0-9.]*)()#',
            '#\b(fbsv)(/)([0-9][0-9.]*)()#',
            '#\b(rv)(:)([0-9][0-9.]*)()#',
            '#\b(android)( )([0-9][0-9.]*)((?:; [^;)]*)?)#',
            '#\b((?:iphone )?os|ios)( )([0-9][0-9_.]*)()#',
            '#\b(mac os x)( )([0-9][0-9_.]*)()#',
        );

        $value = strtolower( (string) $value );
        foreach ( $rules as $pattern ) {
            $length = strlen( $value );
            $result = preg_replace_callback(
                $pattern,
                function ( $m ) use ( $length, $families, $open_as_is, $fold_device ) {
                    $name    = $m[1][0];
                    $version = $m[3][0];
                    // At the end of a line, a version can be the beginning of a
                    // longer one: the firewall compares by substring.
                    $open = '' === $m[4][0] && $m[3][1] + strlen( $version ) === $length;

                    if ( ( $open && $open_as_is ) || ! isset( $families[ $name ] ) || ! self::version_in_use( $families[ $name ], $version, $open ) ) {
                        return $m[0][0];
                    }

                    if ( 'android' === $name ) {
                        return $fold_device ? 'android 0; device' : 'android 0' . $m[4][0];
                    }

                    return $name . $m[2][0] . '0';
                },
                $value,
                -1,
                $count,
                PREG_OFFSET_CAPTURE
            );

            // PCRE gave up: '' is never a hit (line_hits()).
            if ( null === $result ) {
                return '';
            }
            $value = $result;
        }

        if ( ! $fold_device ) {
            return $value;
        }

        return (string) preg_replace( '#\blinux (?:x86_64|aarch64|arm[a-z0-9]*|i[3-6]86)#', 'linux arch', $value );
    }

    /**
     * A line that starts inside the name of a token, read as that token.
     *
     * "rome/120.0.0.0" is the end of "Chrome/120.0.0.0" and blocks the people
     * on Chrome 120, but normalize() only sees a version after a whole name.
     * When the line starts with the end of a known name (or with its
     * separator alone) followed by a version in use for that token, the
     * version is taken out as normalize() would do it.
     *
     * @since 3.0.12
     *
     * @param string $line        Blacklist line.
     * @param bool   $fold_device As in normalize().
     * @return array{0: string, 1: string}|null The start, normalized, and the rest of the line; null when it does not start that way.
     */
    private static function normalize_cut_start( $line, $fold_device = true ) {
        $value  = strtolower( (string) $line );
        $tokens = array(
            array( 'chrome', '/', 'chrome' ),
            array( 'crios', '/', 'chrome' ),
            array( 'edg', '/', 'chrome' ),
            array( 'edga', '/', 'chrome' ),
            array( 'edgios', '/', 'chrome' ),
            array( 'firefox', '/', 'firefox' ),
            array( 'fxios', '/', 'firefox' ),
            array( 'gecko', '/', 'firefox' ),
            array( 'rv', ':', 'firefox' ),
            array( 'opr', '/', 'opr' ),
            array( 'samsungbrowser', '/', 'samsung' ),
            array( 'yabrowser', '/', 'yandex' ),
            array( 'fbav', '/', 'facebook' ),
            array( 'instagram', ' ', 'instagram' ),
            array( 'gsa', '/', 'google' ),
            array( 'micromessenger', '/', 'wechat' ),
            array( 'huaweibrowser', '/', 'huawei' ),
            array( 'ucbrowser', '/', 'uc' ),
            array( 'kaios', '/', 'kaios' ),
            array( 'duckduckgo', '/', 'duckduckgo' ),
            array( 'opera mini', '/', 'operamini' ),
            array( 'tizen', ' ', 'tizen' ),
            array( 'fbsv', '/', 'ios' ),
            array( 'version', '/', 'safari' ),
            array( 'android', ' ', 'android' ),
            array( 'iphone os', ' ', 'ios' ),
            array( 'mac os x', ' ', 'mac' ),
        );

        foreach ( $tokens as $token ) {
            list( $name, $separator, $family ) = $token;
            // Every end of the name shorter than the name itself, down to none.
            for ( $from = 1; $from <= strlen( $name ); $from++ ) {
                $piece = substr( $name, $from );
                if ( '' === $piece && ' ' === $separator ) {
                    continue;
                }
                $pattern = '#^' . preg_quote( $piece . $separator, '#' ) . ( 'android' === $name ? '([0-9][0-9.]*)((?:; [^;)]*)?)#' : '([0-9][0-9_.]*)()#' );
                if ( ! preg_match( $pattern, $value, $m ) ) {
                    continue;
                }
                $open = '' === $m[2] && strlen( $m[0] ) === strlen( $value );
                if ( ! self::version_in_use( $family, $m[1], $open ) ) {
                    continue;
                }
                if ( 'android' === $name && ! $fold_device ) {
                    return array( $piece . ' 0', (string) substr( $value, strlen( $piece . $separator . $m[1] ) ) );
                }
                $start = 'android' === $name ? $piece . ' 0; device' : $piece . $separator . '0';
                return array( $start, (string) substr( $value, strlen( $m[0] ) ) );
            }
        }

        return null;
    }

    /**
     * Whether a version can be carried by a browser or a system people use.
     *
     * The ranges go well past the references, because the references go
     * stale while the plugin is installed, and start low enough to keep the
     * people on old systems (Chrome 109, the last one for Windows 7, Firefox
     * ESR, iOS 12 on an iPhone 6, Android 7). What is below is taken as a bot
     * signature.
     *
     * A version that is complete (something follows its first number, or the
     * line goes on after it) is in use when that number is in the range. One
     * at the end of a line with nothing after its digits is in use when some
     * number of the range starts with them, because the firewall compares by
     * substring: "Chrome/15" blocks Chrome 150 to 159 and "Android 1" blocks
     * Android 10 to 19.
     *
     * @since 3.0.12
     *
     * @param string $family  Family of the token, a key of version_ranges().
     * @param string $version Version as written, such as "156.0.0.0" or "10_15_7".
     * @param bool   $open    Whether nothing follows it in the line.
     * @return bool
     */
    private static function version_in_use( $family, $version, $open ) {
        // The highest numbers leave about ten years over the references, and
        // no more: "Firefox/3" or "Android 3" are signatures of old bots.
        $ranges = array(
            'chrome'    => array( 100, 299 ),
            'firefox'   => array( 100, 299 ),
            'opr'       => array( 85, 299 ),
            'samsung'   => array( 16, 59 ),
            // Yandex numbers its versions by year and month (25.8).
            'yandex'    => array( 22, 39 ),
            // The apps and the browsers of phones, TVs and consoles (3.0.12).
            'facebook'   => array( 350, 999 ),
            'instagram'  => array( 250, 999 ),
            // The Google app is numbered 13 to 16 on Android and 250 and
            // over on iOS.
            'google'     => array( 12, 999 ),
            'wechat'     => array( 7, 15 ),
            'huawei'     => array( 10, 39 ),
            'uc'         => array( 12, 39 ),
            'kaios'      => array( 2, 9 ),
            'duckduckgo' => array( 5, 29 ),
            'operamini'  => array( 40, 199 ),
            'tizen'      => array( 4, 15 ),
            'safari'    => array( 12, 39 ),
            'android'   => array( 7, 29 ),
            'ios'       => array( 12, 39 ),
            // Every browser sends macOS as 10_15_7 or 10.15 since the
            // User-Agent reduction: "Mac OS X 13_0" blocks nobody.
            'mac'       => array( 10, 10 ),
            // macOS is written 10_15_7: what varies is the number after "10_".
            'mac_minor' => array( 11, 19 ),
        );

        if ( ! isset( $ranges[ $family ] ) || ! preg_match( '/^([0-9]+)(.*)$/s', $version, $parts ) ) {
            return true;
        }

        if ( 'mac' === $family && '10' === $parts[1] && '' !== $parts[2] ) {
            if ( ! preg_match( '/^([0-9]+)(.*)$/s', (string) substr( $parts[2], 1 ), $minor ) ) {
                // "10_" at the end of a line is the beginning of 10_15_7.
                return $open;
            }
            return self::number_in_range( $minor[1], '' !== $minor[2] || ! $open, $ranges['mac_minor'] );
        }

        return self::number_in_range( $parts[1], '' !== $parts[2] || ! $open, $ranges[ $family ] );
    }

    /**
     * Whether a number, or a number that starts with these digits, is in a range.
     *
     * @since 3.0.12
     *
     * @param string $digits   Digits as written.
     * @param bool   $complete True when nothing more can follow them.
     * @param int[]  $range    Lowest and highest.
     * @return bool
     */
    private static function number_in_range( $digits, $complete, $range ) {
        if ( $complete ) {
            $number = (int) $digits;
            return $number >= $range[0] && $number <= $range[1];
        }

        for ( $number = $range[0]; $number <= $range[1]; $number++ ) {
            if ( 0 === strpos( (string) $number, $digits ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a blacklist line would match a given User-Agent.
     *
     * Compared as written and with the versions in use taken out of both
     * sides: the first catches a fragment of a version number, the second a
     * whole User-Agent copied from a newer browser than the references.
     *
     * @param string $line       Blacklist line, trimmed.
     * @param string $user_agent User-Agent.
     * @return bool
     */
    public static function line_hits( $line, $user_agent ) {
        if ( '' === $line || '' === $user_agent ) {
            return false;
        }

        if ( false !== strpos( strtolower( $user_agent ), strtolower( $line ) ) ) {
            return true;
        }

        // A line longer than the User-Agent cannot be inside it: normalizing
        // only makes a device or a processor name a few letters longer. Until
        // the fourth blind review of 3.0.12, a pasted line of 700 KB took 11 s
        // on every view of the Dashboard and the Firewall tab.
        if ( strlen( $line ) > strlen( $user_agent ) + 64 ) {
            return false;
        }

        // Each way the line can be read. A version at the end of the line is
        // the beginning of a version in use, or of a constant ("Gecko/20" is
        // in "Gecko/20100101"). A line that starts inside the name of a token
        // ("rome/120.0.0.0", "oid 14") has its version read as that token's,
        // and one that starts inside a version (".0 Firefox/150") is read
        // without that piece too. The first reading alone stored all of them,
        // and they block people (first blind review of 3.0.12).
        // All of it twice: with the Android device and the Linux processor
        // folded, so another model is recognised, and as written, for a line
        // that starts inside them ("K) AppleWebKit", "x86_64) AppleWebKit").
        foreach ( array( true, false ) as $fold ) {
            $normalized_ua = self::normalize( $user_agent, false, $fold );
            foreach ( self::line_readings( $line, $fold ) as $reading ) {
                if ( false !== strpos( $normalized_ua, $reading ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The readings of a line that line_hits() compares, remembered for the request.
     *
     * An empty needle would match everything; normalize() only returns '' for
     * a line that was empty, or if PCRE failed, and neither is a hit. A
     * reading with no letter left matches nothing in particular. Both are
     * left out.
     *
     * @since 3.0.12
     *
     * @param string $line Blacklist line.
     * @param bool   $fold As the third argument of normalize().
     * @return string[]
     */
    private static function line_readings( $line, $fold ) {
        static $memo  = array();
        static $bytes = 0;
        $key = md5( ( $fold ? '1' : '0' ) . (string) $line );
        if ( isset( $memo[ $key ] ) ) {
            return $memo[ $key ];
        }

        $readings = array( self::normalize( $line, false, $fold ), self::normalize( $line, true, $fold ) );
        $cut      = self::normalize_cut_start( $line, $fold );
        if ( null !== $cut ) {
            $readings[] = $cut[0] . self::normalize( $cut[1], false, $fold );
            $readings[] = $cut[0] . self::normalize( $cut[1], true, $fold );
        }
        foreach ( $readings as $reading ) {
            if ( preg_match( '#^[0-9._]+(?=[ ;)])#', $reading, $piece ) ) {
                $readings[] = (string) substr( $reading, strlen( $piece[0] ) );
            }
        }

        $result = array_values(
            array_filter(
                array_unique( $readings ),
                function ( $reading ) {
                    return '' !== $reading && 1 === preg_match( '/[a-z]/', $reading );
                }
            )
        );

        // Bounded by size, as in normalize(), the slots included: a line with
        // no letter has no reading and would otherwise count nothing.
        $size   = strlen( implode( '', $result ) ) + 200 * ( 1 + count( $result ) );
        $bytes += $size;
        if ( $bytes > 2097152 ) {
            $memo  = array();
            $bytes = $size;
        }
        $memo[ $key ] = $result;

        return $result;
    }

    /**
     * What a blacklist line would block.
     *
     * @param string $line     Blacklist line.
     * @param string $saver_ua User-Agent of the person saving, '' when there is none.
     * @return array{verdict: string, labels: string[]}
     */
    public static function classify_blacklist_line( $line, $saver_ua = '' ) {
        $line = trim( (string) $line );

        // empty() as the firewall reads the list (first_match()): a line "0"
        // matches nothing there, so it blocks nobody.
        if ( empty( $line ) ) {
            return array( 'verdict' => self::VERDICT_OK, 'labels' => array() );
        }

        if ( '' !== $saver_ua && self::line_hits( $line, (string) $saver_ua ) ) {
            return array( 'verdict' => self::VERDICT_OWN, 'labels' => array() );
        }

        if ( self::line_hits( $line, self::site_user_agent() ) ) {
            return array( 'verdict' => self::VERDICT_SITE, 'labels' => array() );
        }

        $labels = array();
        foreach ( self::browser_references() as $reference ) {
            if ( self::line_hits( $line, $reference['ua'] ) ) {
                $labels[] = $reference['label'];
            }
        }
        if ( ! empty( $labels ) ) {
            return array( 'verdict' => self::VERDICT_BROWSER, 'labels' => array_values( array_unique( $labels ) ) );
        }

        foreach ( self::engine_references() as $reference ) {
            if ( self::line_hits( $line, $reference['ua'] ) ) {
                $labels[] = $reference['label'];
            }
        }
        if ( ! empty( $labels ) ) {
            return array( 'verdict' => self::VERDICT_ENGINE, 'labels' => array_values( array_unique( $labels ) ) );
        }

        if ( self::looks_like_current_browser( $line ) ) {
            return array( 'verdict' => self::VERDICT_BROWSER, 'labels' => array( __( 'the browser it was copied from', 'vigilante' ) ) );
        }

        return array( 'verdict' => self::VERDICT_OK, 'labels' => array() );
    }

    /**
     * Whether a line is a User-Agent, or a piece of one, of a browser in use.
     *
     * The references cannot list every browser, app and device: until the
     * second blind review of 3.0.12, the whole User-Agent of Edge on Mac, of
     * Opera on Android or of the browser inside the Facebook app was saved,
     * and blocked everybody who uses it. Refused here, whatever else the line
     * holds, when it is not a bot's:
     *
     * - a TV, a console or a KaiOS phone, which keep an old engine;
     * - a field only an app sends (FBLC/, NetType/, musical_ly), whatever its
     *   value, since those carry the language or the network of each person;
     * - the version in use of a token only browsers and apps send (Edg/, OPR/,
     *   SamsungBrowser/, FBAV/, GSA/, HuaweiBrowser/);
     * - with the body of a browser User-Agent (AppleWebKit, Gecko or Presto),
     *   a Chrome, Firefox or Safari version in use, or, when it names no
     *   browser, its iOS or Android version. Chrome 107 and later writes
     *   macOS as 10_15_7, so a modern Chrome with another macOS is a bot.
     *
     * A line that names a bot or a testing tool is left alone: no browser
     * sends "compatible;", a "+http" address, "bot/", Lighthouse or GTmetrix,
     * so it blocks that bot only.
     *
     * @since 3.0.12
     *
     * @param string $line Blacklist line.
     * @return bool
     */
    private static function looks_like_current_browser( $line ) {
        $value = strtolower( (string) $line );

        foreach ( array( 'compatible;', '+http', 'bot/', 'crawler', 'spider', 'lighthouse', 'gtmetrix', 'ptst/', 'pagespeed', 'pingdom' ) as $bot ) {
            if ( false !== strpos( $value, $bot ) ) {
                return false;
            }
        }

        $marks = array(
            // TVs, consoles, KaiOS.
            'web0s', 'webappmanager', 'smart-tv', 'smarttv', 'tizen', 'playstation', 'xbox', 'kaios',
            // Fields of the Facebook, Messenger and Instagram apps.
            'fban/', 'fb_iab/', 'fbav/', 'fbbv/', 'fbdv/', 'fbmd/', 'fbsn/', 'fbsv/', 'fbss/', 'fbcr/', 'fbid/', 'fblc/', 'fbop/', 'iabmv/', 'orca-android', 'messengerforios', 'messengerliteforios',
            // WeChat, TikTok and other apps.
            'micromessenger', 'mmwebsdk/', 'mmwebid/', 'xweb/', 'weixin', 'nettype/', 'language/', 'bytelocale/', 'region/', 'bytedancewebview', 'musical_ly', 'trill_', 'jssdk/', 'linkedinapp', '[pinterest/', 'telegram-android', 'snapchat/', 'miuibrowser', 'ddg/',
        );
        foreach ( $marks as $mark ) {
            if ( false !== strpos( $value, $mark ) ) {
                return true;
            }
        }
        // Instagram on Android writes the API level and the version: "Android (35/15".
        if ( preg_match( '#\bandroid \([0-9]+/[0-9]+#', $value ) ) {
            return true;
        }

        $length   = strlen( $value );
        $families = array(
            'chrome'         => 'chrome',
            'crios'          => 'chrome',
            'edg'            => 'chrome',
            'edga'           => 'chrome',
            'edgios'         => 'chrome',
            'firefox'        => 'firefox',
            'fxios'          => 'firefox',
            'opr'            => 'opr',
            'samsungbrowser' => 'samsung',
            'yabrowser'      => 'yandex',
            'version'        => 'safari',
            'fbav'           => 'facebook',
            'instagram'      => 'instagram',
            'gsa'            => 'google',
            'micromessenger' => 'wechat',
            'huaweibrowser'  => 'huawei',
            'ucbrowser'      => 'uc',
            'kaios'          => 'kaios',
            'duckduckgo'     => 'duckduckgo',
            'opera mini'     => 'operamini',
            'ios'            => 'ios',
        );

        // Tokens only browsers and apps send: their version decides, body or
        // not. "iOS 18_6" is how the apps write it; Safari writes "OS 18_6".
        foreach ( array( '#\b(crios|edg|edga|edgios|fxios|opr|samsungbrowser|yabrowser|gsa|huaweibrowser|ucbrowser|duckduckgo|opera mini)/([0-9][0-9.]*)#', '#\b(instagram|ios) ([0-9][0-9_.]*)#' ) as $pattern ) {
            if ( preg_match_all( $pattern, $value, $found, PREG_SET_ORDER | PREG_OFFSET_CAPTURE ) ) {
                foreach ( $found as $m ) {
                    if ( self::version_in_use( $families[ $m[1][0] ], $m[2][0], $m[2][1] + strlen( $m[2][0] ) === $length ) ) {
                        return true;
                    }
                }
            }
        }

        if ( false === strpos( $value, 'applewebkit/' ) && false === strpos( $value, 'gecko/' ) && false === strpos( $value, 'presto/' ) ) {
            return false;
        }

        // Opera 12 and Opera Mini write Version/12 after Presto: it is not Safari.
        $presto  = false !== strpos( $value, 'presto/' );
        $old_mac = (bool) preg_match( '#\bmac os x 10[._](?!15(?![0-9]))[0-9]#', $value );
        $named   = false;
        if ( preg_match_all( '#\b(chrome|firefox|version)/([0-9][0-9.]*)#', $value, $found, PREG_SET_ORDER | PREG_OFFSET_CAPTURE ) ) {
            foreach ( $found as $m ) {
                if ( $presto && 'version' === $m[1][0] ) {
                    continue;
                }
                $named  = true;
                $family = $families[ $m[1][0] ];
                if ( ! self::version_in_use( $family, $m[2][0], $m[2][1] + strlen( $m[2][0] ) === $length ) ) {
                    continue;
                }
                if ( $old_mac && 'chrome' === $family && (int) $m[2][0] >= 107 ) {
                    continue;
                }
                return true;
            }
        }
        if ( $named ) {
            return false;
        }

        if ( preg_match_all( '#\b(android|(?:iphone )?os|ios) ([0-9][0-9_.]*)#', $value, $found, PREG_SET_ORDER | PREG_OFFSET_CAPTURE ) ) {
            foreach ( $found as $m ) {
                if ( self::version_in_use( 'android' === $m[1][0] ? 'android' : 'ios', $m[2][0], $m[2][1] + strlen( $m[2][0] ) === $length ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether a verdict keeps a new line out of the blacklist.
     *
     * @param string $verdict Verdict.
     * @return bool
     */
    public static function blocks_people( $verdict ) {
        return in_array( $verdict, array( self::VERDICT_OWN, self::VERDICT_SITE, self::VERDICT_BROWSER ), true );
    }

    /**
     * Split a submitted blacklist into what is stored and what is not.
     *
     * A line that was already stored keeps applying unless $drop_stored is
     * true, which only the explicit save of the Firewall tab asks for: the
     * settings sanitize callback runs on every write of the option, and
     * dropping stored lines there would change what a site has saved on the
     * save of any other tab or on an update, without anybody deciding it.
     *
     * @param array  $lines       Submitted lines.
     * @param array  $stored      Lines stored before this write.
     * @param string $saver_ua    User-Agent of the person saving.
     * @param bool   $drop_stored Whether stored lines that block people go too.
     * @return array{kept: string[], rejected: array<int, array{line: string, verdict: string, labels: string[]}>, warned: array<int, array{line: string, verdict: string, labels: string[]}>}
     */
    public static function filter_blacklist( $lines, $stored, $saver_ua, $drop_stored = false ) {
        $stored = array_map( 'trim', array_map( 'strval', (array) $stored ) );
        $result = array(
            'kept'     => array(),
            'rejected' => array(),
            'warned'   => array(),
        );

        foreach ( (array) $lines as $line ) {
            if ( ! is_string( $line ) ) {
                continue;
            }
            $line = trim( $line );
            if ( '' === $line ) {
                continue;
            }

            $verdict = self::classify_blacklist_line( $line, $saver_ua );
            $was_stored = in_array( $line, $stored, true );

            if ( self::blocks_people( $verdict['verdict'] ) && ( ! $was_stored || $drop_stored ) ) {
                $result['rejected'][] = array_merge( array( 'line' => $line ), $verdict );
                continue;
            }

            if ( self::VERDICT_ENGINE === $verdict['verdict'] && ! $was_stored ) {
                $result['warned'][] = array_merge( array( 'line' => $line ), $verdict );
            }

            $result['kept'][] = $line;
        }

        return $result;
    }

    /**
     * Stored lines that block people, for the tab and the Dashboard.
     *
     * The User-Agent of whoever is looking is left out on purpose: what is
     * stored has to read the same for every administrator.
     *
     * @param array $stored Stored blacklist.
     * @return array<int, array{line: string, verdict: string, labels: string[]}>
     */
    public static function stored_lines_blocking_people( $stored ) {
        $found = array();
        foreach ( (array) $stored as $line ) {
            if ( ! is_string( $line ) || '' === trim( $line ) ) {
                continue;
            }
            $verdict = self::classify_blacklist_line( $line, '' );
            if ( self::blocks_people( $verdict['verdict'] ) ) {
                $found[] = array_merge( array( 'line' => trim( $line ) ), $verdict );
            }
        }

        return $found;
    }

    /**
     * The first line of a list contained in a User-Agent, as the firewall reads
     * it: by substring, case-insensitive.
     *
     * @param string $user_agent User-Agent.
     * @param array  $list       List lines.
     * @return string The line, or '' when none matches.
     */
    public static function first_match( $user_agent, $list ) {
        $user_agent = strtolower( (string) $user_agent );
        if ( '' === $user_agent ) {
            return '';
        }

        foreach ( (array) $list as $entry ) {
            if ( ! is_string( $entry ) ) {
                continue;
            }
            $entry = trim( $entry );
            // empty() and not '' on purpose: the firewall has always skipped a
            // line reading "0", and a line that matched every User-Agent with
            // a zero in it would block nearly everybody after an update.
            if ( ! empty( $entry ) && false !== strpos( $user_agent, strtolower( $entry ) ) ) {
                return $entry;
            }
        }

        return '';
    }

    /**
     * A line cut for a notice: whole User-Agents run to 130 characters.
     *
     * @param string $line Line.
     * @return string
     */
    public static function short( $line ) {
        $line = (string) $line;
        $len  = function_exists( 'mb_strlen' ) ? mb_strlen( $line ) : strlen( $line );
        if ( $len <= 60 ) {
            return $line;
        }

        return ( function_exists( 'mb_substr' ) ? mb_substr( $line, 0, 57 ) : substr( $line, 0, 57 ) ) . '…';
    }

    /**
     * The sentence that says why a line is not stored, or what it blocks.
     *
     * Plain text: whoever prints it escapes it.
     *
     * @param array $entry An entry from filter_blacklist() or stored_lines_blocking_people().
     * @return string
     */
    public static function explain( $entry ) {
        $labels = isset( $entry['labels'] ) ? (array) $entry['labels'] : array();

        switch ( isset( $entry['verdict'] ) ? $entry['verdict'] : '' ) {
            case self::VERDICT_OWN:
                return __( 'It is in the User-Agent of your own browser, so it would block you and everyone who uses the same browser.', 'vigilante' );
            case self::VERDICT_SITE:
                return __( 'It is in the requests WordPress sends to itself, so scheduled tasks would stop running and the Site Health tests would fail.', 'vigilante' );
            case self::VERDICT_BROWSER:
                return sprintf(
                    /* translators: %s: comma separated list of browsers, e.g. "Chrome on Mac, Safari on Mac". */
                    __( 'Normal browsers send it too (%s), so it blocks the people who use them. To stop a bot that pretends to be a browser, block its IP.', 'vigilante' ),
                    implode( ', ', $labels )
                );
            case self::VERDICT_ENGINE:
                return sprintf(
                    /* translators: %s: search engine crawlers, e.g. "Googlebot". */
                    __( 'It blocks %s. If you only want to keep it from indexing the site, robots.txt is the better tool.', 'vigilante' ),
                    implode( ', ', $labels )
                );
        }

        return '';
    }
}
