=== Vigilant - 100% Free Security Suite: Firewall, 2FA, Login, Headers, Scanner… ===
Contributors: fernandot, ayudawp
Tags: security, firewall, 2fa, malware, scanner
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 3.0.4
License: GPL v2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Premium WordPress Security - 100% FREE: Firewall, 2FA, Security Headers, Login and Malware Protection, File Monitor, Security Audit & more

== Description ==

### Premium Security. Zero Cost.

Vigilant provides enterprise-level WordPress security features completely free. No premium version, no upsells, no hidden features behind paywalls.

Protect your site with a complete security suite: firewall, two-factor authentication, brute force protection, security headers, file integrity monitoring, closed plugin detection, malware detection, user management, security audit logging, under attack mode, verification of its own files and much more.

Once activated, Vigilant immediately applies firewall rules against common attacks (SQL injection, XSS, file inclusion), security headers, login attempt monitoring, XML-RPC blocking, WordPress version hiding and sensitive file protection (.htaccess, wp-config.php).

### One-Click Security Presets

Choose a preset and get protected instantly:

**Standard** - Balanced security suitable for most websites. Enables all modules with sensible defaults that won't interfere with normal site operation.

**Maximum Security** - Strictest settings for high-security sites. Tighter rate limits, stronger CSP rules, mandatory admin notifications. May require fine-tuning for some setups.

You can always customize individual settings after applying a preset.

== Under Attack Mode ==

Is your site under active attack? Activate Under Attack mode with one click and stop malicious traffic instantly:

* **JavaScript challenge** - Every visitor must pass an automatic browser verification before accessing your site. Real browsers solve it in seconds, bots get blocked completely
* **Aggressive rate limiting** - Requests limited to 30 per minute with 15-minute blocks for offenders
* **HTTP method restriction** - Only GET, POST and HEAD allowed; PUT, DELETE, PATCH, OPTIONS and TRACE are blocked
* **Empty user agent blocking** - Requests without a user agent header are rejected
* **Full XML-RPC lockdown** during the attack
* **REST API restriction** - Only authenticated users can access the REST API
* **Auto-deactivation** - Mode turns off after 4 hours so you never forget it's on
* **Email notifications** when the mode activates and deactivates
* **HMAC-signed cookies** - Verified visitors get a signed cookie so they only see the challenge once

Under Attack mode works independently from your preset configuration. Your regular settings are preserved and restored when the mode deactivates.

== Two-Factor Authentication (2FA) ==

Add a second verification step to your WordPress login:

* **Authenticator app (TOTP)** - Google Authenticator, Authy, Microsoft Authenticator or any TOTP-compatible app
* **Email codes** - One-time 6-digit verification codes sent via email
* QR code setup directly in user profiles
* 10 backup codes for emergency access if you lose your device
* Configurable grace period for users to set up their authenticator app
* Trusted devices - optionally let users skip 2FA on recognized devices for 30 days
* Role-based enforcement - require 2FA for administrators, editors or any role
* Exclude specific users from 2FA requirements
* Admin tool to reset TOTP for users who lost their authenticator
* Configurable code expiry, attempt limits and email sender name
* User notification emails when 2FA is enabled or the method changes

== Firewall Protection ==

Block malicious requests before they reach WordPress:

* SQL injection blocking
* XSS (Cross-Site Scripting) attack prevention
* File inclusion protection (LFI/RFI)
* Directory traversal blocking
* Bad query string filtering (catches generic suspicious patterns the specific blockers miss)
* Bad bot detection and blocking
* Block requests with empty user agent
* Rate limiting against DDoS and brute force, with optional progressive lockouts
* IP whitelist and blacklist management (IPv4 and IPv6, with CIDR ranges and wildcards)
* User-Agent whitelist and blacklist with partial matching
* Visitor IP detection control - read the real IP directly from the connection (a spoof-proof default) or from a proxy header when behind Cloudflare, a reverse proxy or a load balancer, with an admin notice if a proxy is detected but not configured
* HTTP method restriction
* Server-level file protection via .htaccess: block direct access to wp-config.php, .htaccess, wp-includes/ and sensitive files (.log, .sql, .bak, .ini, debug.log, readme.html, etc.), and optionally wp-cron.php external access
* Block PHP execution in /uploads (one of the most common post-exploit vectors)
* Disable directory browsing

== Login Security ==

Stop unauthorized access attempts:

* Limit login attempts with configurable thresholds
* Progressive lockouts - longer blocks for repeat offenders
* Custom login URL - hide wp-login.php from bots
* Login URL change notifications to all admin-area users
* Hide login error messages - don't reveal valid usernames
* XML-RPC control: leave it on, block only the pingback methods (recommended, it closes the amplification vector while the mobile app and Jetpack keep working), or disable it completely
* Application passwords control
* Email notification when an IP is blocked for exceeding login attempts
* Admin login notifications via email
* IP whitelist for trusted locations

== User Security ==

Comprehensive user account protection:

* Block insecure usernames (admin, test, root, etc.) on new registrations
* Warn about existing users with insecure usernames so you can rename or remove them
* Block author scanning - intercept `?author=N` URLs so WordPress doesn't redirect them to `/author/USERNAME/` and leak the login slug
* Force strong passwords with minimum length
* Password expiration with configurable intervals
* Password history - prevent reusing old passwords
* Force password reset - by specific users, by role, or all users (post-hack recovery)
* Session limits - control concurrent logins per user
* Session management - view and revoke active sessions
* Email verification for new registrations
* Registration approval workflow - manually approve new users
* Admin account monitoring - alerts for new admins, email changes, password changes, privilege escalation
* Display name protection - prevent exposing login username publicly

== Security Headers ==

Achieve Grade A security ratings:

* Content Security Policy (CSP) with a WordPress-compatible default policy and Report-Only mode for safe testing before enforcing
* HSTS (HTTP Strict Transport Security) with includeSubdomains and preload options
* X-Frame-Options - prevent clickjacking
* X-Content-Type-Options - prevent MIME sniffing
* Referrer Policy control
* Permissions Policy (camera, microphone, geolocation, payment, USB)
* Cross-Origin policies (COEP, COOP, CORP)
* HTTPS enforcer with automatic mixed content fix
* Server fingerprint hiding - the `Server:` header is neutralized and `X-Powered-By` and other fingerprinting headers are stripped from responses

== File Integrity Monitoring ==

Detect unauthorized changes to your files and compromised plugins:

* WordPress core against official checksums, plus files added to wp-admin and wp-includes
* Plugins against WordPress.org checksums, themes against their WordPress.org package
* Whatever has no official copy (other plugins and themes, must-use plugins, drop-ins, the rest of wp-content) searched for hidden code
* Critical config files (wp-config.php, .htaccess) monitored against baseline, detecting code injection even in files with no official checksum
* Closed and removed plugins detection: a daily check against WordPress.org flags any installed plugin that was closed or silently removed, with per-plugin Ignore
* Line-level diff view of changes, with per-file approval workflow
* Extra file detection in plugins and themes (files not in original distribution)
* Uploads scanning for PHP, double extensions and .htaccess files
* What each finding usually is and what to do about it
* Root directory scanning for non-core PHP files (common attack vector)
* String concatenation obfuscation detection
* Configurable notification levels and an ignore list to dismiss known files
* Excluded paths and file extensions
* Scheduled automatic scans (daily, weekly)
* HTML formatted email alerts with severity sections, including a dedicated section for closed plugins

== Self-Protection ==

A tampered security plugin is worse than none, because it keeps reporting that everything is fine. Vigilant verifies its own files against the checksums WordPress.org publishes, a SHA-256 manifest shipped with the plugin and a fingerprint of that manifest stored in the database:

* At the start of every integrity scan, right after every update, and when the version on disk changes outside the WordPress updater
* Modified, missing and added files, symbolic links and a replaced or deleted manifest are reported, by email with the default settings
* Its own scheduled tasks are watched and scheduled again if something removes them
* Its own block in File Integrity and a check in Security Check, with what each finding means and how to fix it, and no way to switch it off
* One click repair that reinstalls Vigilant from WordPress.org, keeping your settings, tables and log

It detects tampering, not vulnerabilities in Vigilant itself. SECURITY.md explains what it covers, what it does not, and how to verify your installation from outside the server.

== Security Audit ==

Track everything happening on your site:

* Successful and failed login attempts
* Two-factor authentication events
* User account changes (creation, deletion, role changes)
* Content modifications (posts, pages)
* Plugin and theme activations/deactivations
* Security events and blocked threats
* HTTP request method tracking and filtering (GET, POST, PUT, DELETE)
* Enhanced log detail popup with grouped sections and quick actions
* One-click add IP or User-Agent to firewall whitelist/blacklist from log entries
* Direct IP lookup links to AbuseIPDB
* Configurable retention period, CSV export, and filtering by event type, severity, request method or date

**Audit Alerts** - get an email when the audit log points to something worth your attention, off by default and configured under Security Audit:

* Immediate alerts the moment a serious event is logged, by minimum severity (a new administrator, a closed plugin or a privilege escalation are all logged as Critical)
* Threshold alerts when a category spikes - firewall blocks, login failures, user, plugin, file integrity, security, system and content events - over a 30-minute, 1, 6 or 24 hour window, counting only warning and critical events so routine activity never trips them
* A single anti-repeat cooldown keeps a storm of events down to one notice instead of flooding your inbox
* Active alerts surface in Settings & Tools, the Dashboard, the Configuration Score and the Security Check
* "Send test email" button to confirm delivery

== Security Check ==

On-demand security audit built into the Dashboard. No external services, no accounts, no API keys - everything runs on your server:

* More than 50 checks across 6 categories: SSL/TLS, HTTP Headers, WP Exposure, Access & Auth, Sensitive Files and Internal Checks
* Single 0-100 score with A-E grade, plus per-category breakdown and explanatory details for every check
* 16 exclusive internal checks impossible from the outside: PHP end-of-life status, pending updates, inactive plugins, closed or removed plugins, Vigilant self-protection, file permissions, default salts detection, `wp_` table prefix, `admin` username, administrators without 2FA enrolled, module status, recent audit errors, last File Integrity scan result and whether audit alerts are configured
* DNS-only reputation lookup against Spamhaus ZEN, Barracuda BRBL and SpamCop SCBL (informational - listings are flagged but don't deduct from the score)
* Two-phase scan: fast local checks appear in under a second, remote checks stream in as they complete
* Weekly automatic scan with opt-in email alert if the score drops by 10+ points or a new critical check starts failing
* 30-scan history with sparkline trend and delta chip
* "Go to setting" fix link on every failing check, jumping straight to the exact Vigilant field that resolves it
* Smart header diagnostics that report "configured but not being served" when a cache/CDN overrides your headers

== WordPress Hardening ==

Layered protection at the WordPress level - admin, content, head, feeds and database:

* Lock down the admin: disable the built-in plugin and theme file editor, block installations and updates from the admin area, and force HTTPS for the admin area. Compatible with any hosting layout, respecting values already in place and never overriding them
* Disable WordPress's internal page-view cron when you already have a real server-side cron job configured
* Dashboard warning when debug mode is left enabled in production, so error output never leaks to visitors
* Hide your WordPress version everywhere it can leak: from the HTML head, from RSS and Atom feeds, and optionally from every script and style URL on the front-end (stripping only the WordPress version itself, leaving plugin and theme cache busting intact)
* Automatic daily removal of readme.html, license.txt and licencia.txt from the WordPress root, which otherwise expose your version
* HTML head cleanup - remove the RSD link, Windows Live Writer manifest, shortlink header and REST API discovery link
* Database hardening - check for the default `wp_` table prefix and one-click rename tool with full backup before the change
* Comment security - honeypot field against spam bots, force moderation on every new comment, close comments on old posts, disable pingbacks and trackbacks
* Feed management - completely disable RSS and Atom feeds, or only disable them when the site has no published content

== REST API Security ==

Control API access to your site:

* Three access modes: public (default WordPress behavior), authenticated only (closes the API to anonymous visitors), or selective (custom allow/block lists)
* Block user enumeration via `/wp-json/wp/v2/users`
* Protect any list of sensitive endpoints from anonymous access
* Per-plugin compatibility toggles so authenticated mode doesn't break the front-end: WooCommerce, Contact Form 7, Gravity Forms, WPForms, Elementor, Jetpack. oEmbed and Site Health endpoints stay accessible by default

== Security Tools ==

Utilities included:

* **Database Backup** - Download a full or partial database backup as ZIP with table selection
* **Database Prefix Change** - Change the default wp_ prefix to a random secure prefix
* **Export/Import Settings** - Transfer your configuration between sites
* **Configuration Backup** - Download wp-config.php, .htaccess and robots.txt as a ZIP
* **Reset to Defaults** - Start fresh with one click

== Safe by Design ==

Vigilant validates .htaccess and wp-config.php before writing to them, and keeps no copy of them, because they hold your database password: download a backup from Settings & Tools first.

Deactivating removes its blocks from both files and brings back the lines it had commented out. Switch Under Attack mode off before deactivating.

Vigilant checks its own files too, and tells you how to check them yourself: every release ships a MANIFEST.sha256 that sha256sum can verify, and WordPress.org publishes the same checksums for comparison.

== Why Vigilant? ==

Most WordPress security plugins reserve their best features for paid plans. Vigilant gives you everything upfront - no premium tier, no feature locks, no upsells. Firewall, 2FA with authenticator app, security headers, file integrity scanner, security audit, on-demand Security Check with weekly regression alerts, and more. All free, all maintained, all following WordPress coding standards.

We maintain a detailed feature comparison between Vigilant and other popular security plugins (Wordfence, Solid Security, AIOS, Sucuri, SG Security). See what each offers in its free version and where Vigilant fills the gaps.

&rarr; [View the full comparison](https://vigilante.works/comparison.html)

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/vigilante/` or install directly from the WordPress plugin repository
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to 'Vigilant' in the admin menu
4. Apply a security preset or customize individual module settings

**Requirements:**

* WordPress 6.2 or higher
* PHP 7.4 or higher
* Apache or LiteSpeed server (for .htaccess features)
* SSL certificate recommended for HSTS

== Frequently Asked Questions ==

= Will this plugin slow down my site? =

No. Vigilant is optimized for performance. The firewall uses efficient pattern matching, database queries are cached with transients, and .htaccess rules execute at server level before PHP even loads.

= What happens when I activate the plugin? =

Vigilant applies its default settings: all modules on, with balanced values for most sites. On Apache and LiteSpeed that writes two blocks to .htaccess, and it writes one block of constants to wp-config.php.

If wp-config.php already defines DISALLOW_FILE_EDIT, DISALLOW_FILE_MODS, FORCE_SSL_ADMIN, FORCE_SSL_LOGIN, DISABLE_WP_CRON, WP_DEBUG, WP_DEBUG_LOG, WP_DEBUG_DISPLAY or SCRIPT_DEBUG, Vigilant comments that line out, marks it and sets the value from its own settings in WP Hardening. If you rely on one of them, check that tab after activating. Your lines come back when you deactivate.

Vigilant keeps no copy of those two files. If you want one, make it before activating.

= What happens when I deactivate the plugin? =

Vigilant removes its Protection and Security Headers blocks from .htaccess, removes its constants from wp-config.php, brings back the lines it had commented out there and clears its scheduled tasks.

Two things to know:

* Switch Under Attack mode off first. Its .htaccess block is removed when the mode ends, not on deactivation.
* If you delete the plugin folder by FTP instead of deactivating, nothing is reverted: remove the blocks between the Vigilante markers by hand.

= How does two-factor authentication work? =

Vigilant supports two 2FA methods. With the **authenticator app** (TOTP), you scan a QR code in your profile to link an app like Google Authenticator or Authy, then enter a 6-digit code from the app on every login. With **email codes**, you receive a one-time code via email after entering your password. If enabled by the site administrator, you can mark your device as trusted to skip 2FA for 30 days.

= What if I lose my phone or authenticator app? =

When you set up TOTP, Vigilant generates 10 backup codes. You can use any of them as a one-time replacement for the authenticator code. If you run out of backup codes, an administrator can reset your TOTP from the plugin settings.

= What if I don't receive the 2FA email code? =

Check your spam folder first. You can click "Resend code" on the verification form. Codes expire after 10 minutes by default. If issues persist, an administrator can temporarily disable 2FA from the plugin settings.

= Can I switch between email and authenticator app? =

Yes. Go to Login Security > Two-Factor Authentication and change the verification method. If notifications are enabled, affected users will receive an email explaining the new method and how to set it up.

= Which user roles require 2FA? =

By default, 2FA is enforced for administrators and editors. You can customize which roles require 2FA in the Login Security settings, and exclude specific users individually.

= How do I recover if I'm locked out? =

Access your site via FTP/SFTP and either rename the plugin folder to disable it temporarily, or delete the `vigilante_login_attempts` table rows for your IP address in the database.

= Will the firewall block legitimate users? =

The firewall is configured to allow normal WordPress operations, including the block editor, REST API, and popular page builders. If you experience issues, you can whitelist specific IPs or adjust rate limiting thresholds.

Block Bad Bots also stops SEO crawlers (Ahrefs, Semrush, Majestic, Screaming Frog) and command line clients (curl, wget, python-requests). To let one of them through, add its name to the User-Agent Whitelist.

= Why is a blocked request missing from the Security Audit? =

Requests are blocked in two places:

* Rules in .htaccess (bad bots, bad query strings, unusual HTTP methods, protected files) answer 403 before WordPress loads, so nothing is logged.
* The PHP firewall logs what it blocks. "Bad bot blocked" shows the entry of the list that matched; the full User-Agent is in its own column.

A page served by a page cache or a CDN reaches neither. Read the log as a floor, not as a count of every attack.

= Can I use this with other security plugins? =

While Vigilant works standalone, running multiple security plugins can cause conflicts. We recommend testing in a staging environment first if you need to combine security solutions.

= Does this work with caching plugins? =

Yes. Vigilant is compatible with popular caching plugins. The firewall runs before cache layers, and .htaccess rules don't interfere with caching mechanisms.

= Does this work with WooCommerce? =

Yes. Vigilant includes compatibility settings for WooCommerce. The REST API security module automatically allows WooCommerce endpoints, and the firewall won't block payment gateway connections.

= How do I test my security headers? =

Use the built-in header testing tool in the Security Headers tab, or visit securityheaders.com with your site URL to get a security grade.

= What is Security Check? =

Security Check is an on-demand audit built into the Dashboard. It runs more than 50 checks across 6 categories (SSL/TLS, HTTP headers, WordPress exposure, access and authentication, sensitive files, and internal checks) and returns a 0–100 score with an A–E grade. Unlike external online scanners, it runs entirely on your server and has access to 16 exclusive internal checks: PHP end-of-life status, pending updates, closed/removed plugins, Vigilant self-protection, file permissions, default salts detection, administrators without 2FA enrolled, and more.

= Does Security Check send my data to an external service? =

No. All checks run on your server. The only external traffic is three DNS lookups against public blacklists (Spamhaus, Barracuda, SpamCop) for the reputation category: standard DNS queries with no authentication, no API keys, and nothing sent beyond your site's IP address.

= What does the Security Check score measure? =

It adds the points of every check that passes. Some checks test the live site: HTTPS, the headers the browser receives, files that should not be reachable. Others read a Vigilant setting, such as the custom login URL, the login attempt limit or two-factor, and tell you whether it is on, not whether a CDN or your host changes the result. The Configuration Score on the Dashboard only looks at settings, so the two numbers can differ.

= How often should I run Security Check? =

Run it manually after any significant change (plugin update, server migration, new user role configuration). For ongoing monitoring, enable the weekly automatic scan from the widget. You'll only receive an email if the score drops by 10 points or more, or if a new critical check starts failing — so no spam from routine scans.

= What is password expiration? =

You can require users to change their passwords after a set number of days (30, 60, 90, etc.). Users are warned before it expires. Once it does, they are taken to their profile to set a new one before they can do anything else. Password history prevents reusing recent passwords.

= What is registration approval? =

When enabled, new user registrations require manual approval by an administrator before the account becomes active. Pending users cannot log in until approved. You can configure auto-rejection after a set number of days.

= What does email verification do? =

New users must verify their email address by clicking a link before their account becomes active. This prevents fake registrations and ensures valid contact information.

= How do session limits work? =

You can limit how many concurrent sessions each user can have. When the limit is reached, either the new login is blocked or the oldest session is terminated, depending on your configuration.

= Can I export the security audit log? =

Yes. The security audit log can be exported to CSV format for external analysis or compliance reporting. You can also filter logs by event type, user, or date range before exporting.

= Which events are sent by email? =

Every event is logged as Info, Warning or Critical. By email you get:

* Security Audit alerts: Critical events by default, such as a closed plugin. Choose "Warning and Critical" to get more.
* Admin monitoring, in Users: a new administrator, a change of role to administrator and changes to an administrator's email or password. Each has its own checkbox.
* File Integrity: the findings of each scan, according to the level you chose.
* Self-protection: always, when Vigilant's own files change.

= What files does the integrity scanner check? =

It checks:

* WordPress core, against the checksums WordPress.org publishes, plus any file added to wp-admin or wp-includes.
* Plugins from WordPress.org, against their checksums.
* Themes from WordPress.org, against the package WordPress.org publishes for the installed version. It is downloaded once per version.
* In both, files that changed, files that are missing and PHP files that are not in the published copy.
* Plugins and themes from anywhere else, must-use plugins and drop-ins (advanced-cache.php, object-cache.php and the like). There is no official copy of them, so they are searched for obfuscated code.
* The uploads directory, for PHP and other scripts, double extensions, .htaccess files and PHP configuration files.
* The other folders of wp-content (languages, upgrade and the like), for hidden code in their PHP files, unless they are in Excluded Paths. A translation file has to hold text and nothing else.
* The site root, wp-content and the plugins folder, for loose files that do not belong there, backups left within reach and a .user.ini or php.ini that loads another file.
* wp-config.php and .htaccess, for any change since you last approved them.

The results name what could not be compared. For those, a clean result means no hidden code was found, not that every file is the original one. A PHP file too large to be searched (over 8 MB) is listed as not searched.

= What do the file integrity findings mean? =

* Modified: the file does not match the copy on WordPress.org. Usually an update that did not finish or a manual edit. Reinstalling the plugin, theme or WordPress fixes it.
* Suspicious: code where none is expected (PHP in uploads or in the site root) or obfuscated code. Real infections land here, and so do the cache or template files some plugins generate.
* Extra: a file that WordPress, the plugin or the theme does not ship. Often legitimate. A copy of wp-config.php or a database dump in the site root should be moved out.
* Critical config: wp-config.php or .htaccess changed since you last approved them.
* Closed or removed: WordPress.org closed the plugin. Replace it.

= I got an email saying wp-config.php or .htaccess changed. Was I hacked? =

Usually not. Cache, security and redirection plugins rewrite their own blocks in those files, often on every update, and Vigilant reports every change it did not make itself.

Open File Integrity, press Review changes and read the lines. If they belong to a plugin you use, press Approve: that records the current content as the reference and does not touch the file. Lines you cannot explain need a closer look, above all the ones that load a file (auto_prepend_file, include) or send requests to a PHP file.

You get that email once per change, not after every scan. The change stays listed in File Integrity until you approve it.

= The scan keeps reporting files that are fine. What can I do? =

* Ignore hides one file.
* For a folder where a plugin keeps generating PHP (compiled templates, caches), add the folder to Excluded Paths, for example wp-content/uploads/cache.
* If the scan says it ran out of time in a folder of wp-content, such as a very large cache, add that folder to Excluded Paths too.
* A .htaccess inside uploads that only denies access protects that folder, and is not reported. WooCommerce writes several.

= What does Vigilant write to .htaccess and wp-config.php? =

On Apache and LiteSpeed, two blocks in .htaccess, between the lines `# BEGIN Vigilante Protection` and `# END Vigilante Protection`, and `# BEGIN Vigilante Security Headers` and `# END Vigilante Security Headers`. While Under Attack mode is on there is a third one, `# BEGIN Vigilante Under Attack`.

In wp-config.php, one block between `/* BEGIN Vigilante Security Constants */` and `/* END Vigilante Security Constants */`, and the prefix `// [VIGILANTE_ORIGINAL]` on any line of yours that defined one of the same constants.

Vigilant writes these blocks when you save its settings and after it updates, not in between. If another plugin or a person removes one, save that tab again to write it back.

= I updated from a version that stored wp-config.php in the database. Is there anything else to do? =

Previous versions kept a copy of wp-config.php in an option so the integrity scan could show which lines had changed, and that copy carried the database password and the eight authentication keys and salts. Updating removes the copy, but no update can undo an exposure that already happened. So if your database, or any backup of it, may have been read by somebody else while that copy was stored, replace the eight keys and salts in your wp-config.php with fresh ones from the WordPress.org secret-key service, and change the database password if your host lets you. Replacing the salts signs everybody out, yourself included, which is the whole point of doing it.

= Does a scan always check the whole site? =

Not on a very large one. A scan runs for 60 seconds at most and starts from the beginning each time. With many plugins, a large uploads folder or a large cache, it may not reach every plugin and theme, and it is the same part that is left out on every scan.

* File Integrity says when the last scan was partial, and names the plugins, the themes and the areas it did not reach. The scan email says it too.
* Security Check does not count a partial scan as a clean one.
* If the server stops the scan before it ends, or WordPress does not run its scheduled tasks, nothing is stored. File Integrity and Security Check then say that no scan has finished since the date shown.
* To check what was left out, File Integrity lists the folders the scan did check: add them to Excluded Paths, run a scan by hand, and take them out again.
* While the whole folder of a plugin or of a theme, or the uploads folder, is in Excluded Paths, File Integrity and Security Check keep saying so: no scan looks inside it.
* Adding large folders that do not need checking to Excluded Paths leaves more time for the rest.

= How often does the file integrity scan run? =

You can configure automatic scans to run daily or weekly. You can also run manual scans at any time. Email notifications support three levels: every finding, serious findings only (suspicious and extra files, changes in wp-config.php or .htaccess and closed plugins), or disabled. The email goes out when a scan finds something new, so a finding you were already told about is not repeated.

= How do I know Vigilant itself has not been tampered with? =

Vigilant verifies its own files against the checksums WordPress.org publishes for your version, the MANIFEST.sha256 file shipped with the plugin and a fingerprint of that manifest stored in your database. The result appears in File Integrity, with the results of the last scan, and in Security Check. To check from outside WordPress, run `wp plugin verify-checksums vigilante`, or `php bin/verify-manifest.php` inside the plugin folder, which also reports added files and accepts line endings rewritten by the host. SECURITY.md lists every option.

= What is the MANIFEST.sha256 file? =

A list of the SHA-256 checksum of every file in the plugin, in the standard format of the sha256sum tool, generated as the last step of each release. It is what lets Vigilant, and you, notice a changed file even when WordPress.org cannot be reached. readme.txt and changelog.txt are not in it, because WordPress.org allows updating them without a new version.

= Does self-protection detect vulnerabilities in Vigilant? =

No. It detects that Vigilant's files were changed, deleted or added to, not bugs in its code. Vulnerabilities are fixed in new releases, so keep Vigilant updated, and report any you find as SECURITY.md explains.

= What is the difference between Standard and Maximum presets? =

Standard applies balanced settings suitable for most sites. Maximum applies stricter rules: lower rate limits, tighter CSP policies, required admin notifications, session limits, and more aggressive hardening. Maximum may require adjustments for sites with complex functionality.

= Where are backups stored? =

Nowhere on the server. The configuration backup (wp-config.php, .htaccess and robots.txt) is a ZIP built on the fly and sent to your browser, and Vigilant keeps no copy of those files, because they hold your database password and other secrets. A database backup you download is generated as a temporary ZIP with an unguessable name and removed right after the download.

= What is Under Attack mode? =

Under Attack mode is an emergency feature you can activate when your site is experiencing an active attack. It adds a JavaScript challenge that real browsers solve automatically in a few seconds, while bots and automated scripts are blocked completely. It also applies aggressive rate limiting, blocks restricted HTTP methods, and restricts API access.

= Will Under Attack mode affect my logged-in users? =

No. Logged-in users, admin pages, cron jobs, AJAX requests, and the login page are all excluded from the JavaScript challenge. Only unauthenticated frontend visitors see the verification page.

= What if I forget to turn off Under Attack mode? =

It automatically deactivates after 4 hours. You will also receive an email notification when it activates and deactivates.

= Does Under Attack mode change my regular security settings? =

No. It operates independently from your preset configuration (Standard or Maximum). Your regular settings are untouched and continue working normally after Under Attack mode deactivates.

= How does the database backup work? =

Go to Vigilant > Tools > Database Backup. Select which tables to include (or leave all selected), then click Download. The backup is generated as a temporary ZIP with an unguessable name, streamed to your browser and deleted from the server immediately after the download.

= What does changing the database prefix do? =

WordPress uses wp_ as default table prefix. Changing it to a random prefix adds a layer of protection against SQL injection attacks that target default table names. Go to Vigilant > WP Hardening > Database Hardening. Always create a backup before changing the prefix.

= How do I exclude management services like ManageWP from the firewall? =

Go to Vigilant > Firewall > User-Agent Lists and add the service name (e.g., ManageWP, MainWP, UptimeRobot) to the User-Agent Whitelist. Partial matching is used, so entering "ManageWP" will match any User-Agent string containing that keyword.

If you also use a custom login URL, add the management dashboard's IP address to the firewall IP Whitelist as well. Some operations (for example pushing a plugin update from MainWP) reach wp-admin without a WordPress session and with a generic WordPress user agent rather than the service name, so the User-Agent rule alone would not match them. A whitelisted IP is allowed past the hidden login/wp-admin protection (it still has to authenticate).

= Can I send security notifications to someone other than the site admin? =

Yes. Go to Vigilant > Settings & Tools > Notification settings. You can add additional email recipients (one per line) and optionally uncheck the WordPress admin email. This is useful for maintenance professionals managing multiple sites who need to receive all security alerts.

= Can I customize notification recipients programmatically? =

Yes. Use the `vigilante_notification_recipients` filter. It receives and returns an array of email addresses used for all administrative notifications:

`add_filter( 'vigilante_notification_recipients', function( $recipients ) {
    $recipients[] = 'security-team@example.com';
    return $recipients;
} );`

== Screenshots ==

1. Security Dashboard - Security score, module controls, and preset selection
2. Two-Factor Authentication - Second verification step during login
3. Login Security - Brute force protection, 2FA, lockouts, and custom login URL
4. User Security - Complete user protection tools and settings
5. Password Expiration - Force periodic password changes with history
6. Registration Approval and Session Limits - Control new users and concurrent logins
7. File Integrity - Scanner settings and verification results
8. Security Audit - Filterable event viewer with export option
9. Database Backup - Download full or partial database backups with table selection
10. Security Check - On-demand audit widget with score, per-category breakdown, and fix links

== Changelog ==

= 3.0.4 =
Fixes the expired password notice, which was missing when the password expired during an open session, lands the user at the top of the profile where the notice is, fixes a redirect loop for WooCommerce customers, and limits an account with an expired password to its own profile form.

* Improved: when a password has expired, the user is taken to the top of their profile, where the notice says why, instead of straight to the password field with the notice out of sight above it. The notice now has a link to the field.
* Fix: the notice that a password has expired was missing when it expired while the user was still logged in. The user was sent to the profile with no explanation, and the notice only appeared after logging in again.
* Fix: on the last day before a password expires the warning notice was not shown, so the forced change arrived with no warning the day before.
* Fix: in a WooCommerce store, an account with no access to the admin area, a customer for example, whose role is in Affected Roles was caught in a redirect loop when its password expired. WooCommerce sent it from the profile to My Account and Vigilant sent it back, so it could neither use the store nor change the password. That account is now let into its profile screen in the admin area while the change is pending, and only into that screen. The password is changed there, not in My Account, and once it is saved WooCommerce takes the account back to My Account as usual.
* Fix: while a password change was pending, every request to the profile screen was let through, and that screen can be asked for other things: a plugin page, an importer, an action passed in the address, or the profile of another user for an account allowed to edit users. An account with an expired password could go on using those. Only its own profile form is let through now, to be shown or to be saved. On a network, the profile screens of the network admin and of the user dashboard lead to the profile of the site, where the notice is.
* Fix: on a site whose WordPress Address and Site Address are on different hosts, a headless site for example, or whose address has accented or non-Latin letters saved as written, a user with an expired password was caught in a redirect loop. The redirect to the profile came out as a redirect to the dashboard, which sent the user to the profile again. It now reaches the profile.

= 3.0.3 =
File Integrity now compares themes with their WordPress.org package, searches all the code that has no official copy, and looks at must-use plugins, drop-ins, wp-admin, wp-includes and the rest of wp-content. Scan emails are sent once per new finding.

* Improved: File Integrity compares themes from WordPress.org with the package WordPress.org publishes for the installed version. WordPress.org has no checksums for themes, so until now no theme file was compared with anything. The package is downloaded once per version.
* Improved: File Integrity searches every PHP file of a plugin or theme with no official copy for hidden code, not only the first 50, and reads files of up to 8 MB. A file over 512,000 bytes was not opened, so it passed as clean. One over 8 MB is listed as not searched.
* Improved: File Integrity looks at files added to wp-admin and wp-includes, at must-use plugins and drop-ins, at loose PHP files in wp-content, and at folders with PHP among the plugins or the themes that WordPress does not list as one.
* Improved: File Integrity searches the PHP files of the other folders of wp-content (languages, upgrade and the like) for hidden code. A translation file that holds anything other than text is reported, because WordPress loads translation files on every request.
* Improved: a new installation no longer starts with wp-content/cache among the excluded paths, so that folder is searched too. A site that already has it there keeps it.
* Improved: File Integrity reports a .htaccess, .user.ini or php.ini outside uploads that makes the server run code or load a file.
* Improved: File Integrity finds, in code with no official copy, request data run as code or as a command, a function chosen by the request and a file included from another server. The same text in a comment is not reported.
* Improved: a file on which the search for hidden code cannot finish is listed as not searched instead of passing as clean.
* Improved: File Integrity now compares wp-includes/version.php, and compares sites that are not in English with the English checksums while WordPress.org has none for their language, instead of leaving the core unchecked.
* Improved: File Integrity reports files deleted from a plugin or a theme, and reports a failed request to WordPress.org as an error instead of treating the plugin as one with no official copy.
* Improved: File Integrity reports more file types in uploads (.pht, .php8, names such as shell.php.suspected, .user.ini, php.ini, shell and CGI scripts), a .user.ini or php.ini in the site root that loads a file on every request, and backups left in the site root.
* Improved: the File Integrity tab says what each kind of finding usually is and what to do about it, names the plugins and themes that could not be compared, and says when a scan was partial instead of saying that every file passed.
* Improved: when a scan runs out of time, File Integrity and the scan email name the plugins, the themes and the areas it did not reach, and File Integrity lists the folders to exclude so that a scan run by hand reaches the rest. A scan runs for 60 seconds at most and starts from the beginning each time, so on a very large site the same part is left unchecked on every scan.
* Improved: File Integrity and Security Check say when Excluded Paths holds the whole folder of a plugin or of a theme, or the uploads folder. No scan looks inside them, and Security Check no longer counts such a scan as clean.
* Improved: File Integrity and Security Check say when no scheduled scan has finished for longer than the schedule allows. A scan the server stops halfway stores no result, and neither does one WordPress never starts, so the last one that did finish kept showing as the current one.
* Improved: the scan email is sent when a scan finds something new, not after every scan, and its subject names wp-config.php or .htaccess when that is all that changed.
* Improved: two-factor events can be filtered in Security Audit, and PHP 8.5 is in the end-of-life table of Security Check.
* Fix: a .htaccess in uploads that only denies access is no longer reported, and neither is the rule that forbids PHP or a commented line. Options +ExecCGI and CGI or SSI handlers, which were listed as custom rules, are now suspicious.
* Fix: the two-line index.php placeholder WordPress ships is no longer reported as PHP in uploads or as an extra file.
* Fix: the bundled themes and Akismet no longer show as modified or missing core files when they update or are deleted.
* Fix: a hexadecimal string of some 12,000 characters or more was not found by the search for hidden code. The longer the payload, the less it was found.
* Fix: a function name split in pieces was not found when a long chain of joined strings came before it in the file.
* Fix: a file built for the purpose could keep the search for hidden code busy long enough to cut the scan short.
* Fix: the scan of uploads stopped after 10,000 files without saying so.
* Fix: a folder the scan could not read stopped the scan of uploads, of a plugin or of a theme without saying so, and nothing after it was checked. The scan now goes on and reports the folder.
* Fix: Scan now stored only the second half of the scan in the score history of Security Check.
* Fix: Security Check passed a file integrity scan that had not checked everything, as long as it had found nothing in what it did check.
* Fix: the Limit HTTP Methods label, and the comment written to .htaccess, described a rule that is not the one applied.
* Fix: the alert setting of Security Audit said a new administrator is logged as Critical. It is logged as Warning, and has its own email in Users.
* Fix: the readme described automatic backups of .htaccess and wp-config.php that no longer exist.
* Fix: removed 11 strings and a method that nothing used.

= 3.0.2 =
Fixes addresses with accents or non-Latin letters in the HTTPS redirect, the Under Attack check and a custom login address, stops the www alias landing on the dashboard, saves File Integrity paths as written, and stops the default CSP from breaking the styles of sites served over http.

* Fix: the HTTP to HTTPS redirect keeps the percent-encoded characters of the address. A visit to /categor%C3%ADa/ was sent to /categora/, a 404, a path in Cyrillic to //, and every parameter lost its encoded characters.
* Fix: the same redirect takes its host from the one the site declares, not from the Host header. A visit to the www alias of the site, or to the server by its IP, was sent with a permanent redirect to the dashboard instead of the same page. A site that served other hostnames of its own through allowed_redirect_hosts now gets the declared host for all of them, while the admin area of a site whose WordPress lives on a host of its own stays on that host.
* Fix: a hidden login address written in a non-Latin script matched nothing, so the login page was hidden and its own address answered 404. It now matches in upper and lower case hex and as raw UTF-8. An address that only matched after its encoded characters were deleted, such as /my-log%41in/ for /my-login/, no longer opens the login page.
* Fix: after solving the Under Attack challenge the visitor lands on the page they asked for, with its accents and parameters intact.
* Fix: the activity log keeps the address of a blocked request as it was sent, instead of with its encoded characters deleted.
* Fix: ignoring a file in File Integrity whose name has encoded characters (a literal %20, for example) or repeated spaces now works. The path was saved with those characters deleted, so it never matched the file and the warning came back, and the saved entry could match a different file with the mangled name.
* Fix: an excluded path in File Integrity whose name has encoded characters (a literal %20, for example) or repeated spaces is now saved as written, also when exporting and importing the settings. It was saved with them deleted, so it never matched, and when the encoded characters were the last part of the name it was saved as the folder above it, which silenced the scan of everything inside that folder. A line with HTML tags is now dropped. Entries already saved are not changed, so one that was saved cut has to be written again.
* Fix: the admin area and its open endpoints are recognised from the path as sent. /wp-admin/admin-ajax.php%20 is no longer taken for admin-ajax.php, nor /wp-%41admin/page for a page of the admin area.
* Fix: on a site whose address is http://, the default Content-Security-Policy no longer includes upgrade-insecure-requests. With Apache and the headers module active, that directive made browsers ask for every stylesheet, script and image over https, where the site does not answer, so the site lost its styles. The directive is now written only when the site address is https://, so a site served over https through a proxy or CDN that terminates TLS should have its site address set to https://. The rules are rewritten on update, so a site that was already affected recovers by updating, and the Security Headers tab says so next to the policy.
* Fix: the Dashboard reads the XML-RPC setting where it lives now. The Configuration Score never gave the three points for blocking XML-RPC, and the recommendation to disable it always showed, because both read a checkbox that stopped being saved in 2.9.7. A site that blocks XML-RPC, as the factory settings do, will see its score go up by two or three points without changing anything, and the recommendation, when it applies, now leads to WP Hardening.
* Fix: the Security Check card on the Dashboard said it ran 13 internal checks when there are 16, and no longer gives a number.

= 3.0.1 =
Fixes the role lists of two factor, password rules and password expiry, which came back ticked after saving, and stops a saved tab from clearing lists that have no field on screen.

* Improved: SECURITY.md describes the self-protection alert and the File Integrity block as they work now, and two code comments that still described the previous behaviour.
* Fix: unticking a role in Enforce for roles, in Apply Password Rules To or in Affected Roles of password expiration is saved and stays unticked. Lists of values were merged position by position, both when saving and when reading the settings, so a list shorter than the one shipped came back with the tail of that one attached and a role could not be removed at all.
* Fix: a literal 0 is no longer written into those lists when the first role of a group is unticked.
* Fix: unticking every role in a group is now sent as an empty list instead of as nothing at all, so it can be told apart from a form that never carried that field.
* Fix: saving a tab no longer empties a list that has no field on that screen, such as the allowed HTTP methods of the firewall or the list of insecure usernames. Those values survived only because reading the settings put the shipped ones back on top.
* Fix: self-protection adopts a manifest that WordPress.org confirms for the installed version, instead of reporting it as replaced for good. A site that had installed a test copy of a version and then the published one stayed critical, and the repair could not clear it, because it reinstalls those same official files.
* Fix: the lists that had no field on any screen are put back on update. Saving a tab emptied them in the database, and until now that was hidden by the settings falling back to the shipped values when read. A site that had saved the Firewall tab would otherwise have started answering 403 to every HTTP method. The four are the allowed HTTP methods, the insecure usernames, the roles of registration approval and the public REST endpoints, and each one goes back to its shipped value, so a list you shortened on purpose is untouched.
* Fix: those four settings also fall back to their shipped value when the stored list is empty, wherever the empty list came from. None of them can be emptied from any screen, so an empty one is a leftover, and it used to mean block every method, allow every registration through while the switch says otherwise, or cut the public REST API.
* Fix: adopting a manifest that WordPress.org confirms is logged for what it is, instead of as a version change that did not happen.

= 3.0.0 =
Vigilant now verifies its own files against WordPress.org, a shipped SHA-256 manifest and a database fingerprint, checks itself after every update and restores its own scheduled tasks. The Security Check score may change slightly: a new check was added.

* New: self-protection. Vigilant verifies its own files against three references: the SHA-256 checksums WordPress.org publishes for the installed version, a MANIFEST.sha256 file shipped inside the plugin, and a fingerprint of that manifest kept in the database. The check runs first in every File Integrity scan, outside the scan time budget and without the excluded paths and extensions of the scan, and once a day when nothing else checked in the last 24 hours. It reports modified, missing, unreadable and added files, folders that cannot be listed, symbolic links, files the manifest lists but WordPress.org does not distribute, and a replaced, deleted or invalid manifest. A modified PHP or JavaScript file, or a data file the plugin loads, is critical, and so is an added file a web server can run, whatever extension of its name says so; a modified stylesheet or image is a warning, because optimisation plugins and hosts often rewrite them, and text files whose line endings the host rewrote are not reported, nor is the manifest when it was rewritten that way. File Integrity shows the result as the first block of the scan results, with what each finding means and how to fix it. There is no setting to switch it off: a security plugin that can be told not to check itself has a switch whose only real user is whoever just changed its files.
* New: Vigilant checks itself at the end of every update WordPress makes to it, including an update made by uploading a zip file, once a failed update has had its previous copy restored, and notices a version change made outside the updater, such as a manual or FTP upload, on the next admin page opened by an administrator or on the daily maintenance task. A new version that WordPress.org cannot confirm raises a warning instead of being trusted, the fingerprint is not taken again when the plugin is reactivated, and a downgrade is reported by email wherever it is detected.
* New: self-protection has its own alert, and no setting switches it off. A critical finding about Vigilant own files always sends an email, wherever it is detected, deduplicated by set of findings and sent once on a network, from the site that owns the shared files and always to the network administration email as well. It no longer travels in the File Integrity scan email, which follows a notification setting: switching off the report about changed files was also switching off the alarm about the plugin itself. Warnings stay on screen, where they do not train anyone to ignore an email, except a downgrade and a version change that cannot be verified against WordPress.org, which are always sent. There are no reminders either: each distinct set of findings is reported once.
* New: switching self-protection off cannot be done quietly. There is no setting for it, so the only way is the vigilante_self_integrity_enabled filter, and Vigilant reports that as critical on every admin screen, names the files that hook it and writes it to the Security Audit. Code that removes the hooks of the check is detected at the end of each admin page and reported the same way, with the plugins that were loaded in that request. And a result older than three days stops counting as verified, whatever stopped the check, so an old green is never shown as if it were current.
* New: scheduled task watchdog. If something removes the daily maintenance, the hourly checks, the weekly Security Check, the closed plugins check or the scheduled integrity scan, Vigilant schedules it again and logs it, and the same task removed again within 30 days is reported as critical by email. Tasks you switched off are left alone. On sites activated before one of those tasks existed, the first pass schedules it once, without reporting it. On a multisite network it watches the main site.
* New: Security Check includes a Vigilant self-protection check in the Internal category, the heaviest single check of the analyzer, which now scores out of 40 instead of 30. While Vigilant own files are reported as changed, both scores of the plugin are held at the bottom of the scale and say why: every other result is produced by that same code. The stored report is cleared on update, so the score may move after the next check.
* New: self-protection has its own block in File Integrity, the first one of the results, coloured by severity, with the files it found, what each finding means and what to do about it. The same wording appears in the Security Check detail, in the details of each Security Audit entry and in the alert email, so the five never say different things. A change to Vigilant own files is also counted in red on the Vigilant menu, summarised at the top of its dashboard and shown on every admin screen until it is fixed; a warning is shown on the Vigilant screens. Findings about Vigilant own files are no longer listed with the rest of the scan, and they cannot be ignored.
* New: one click repair. When Vigilant finds its own files changed, it can download a clean copy from WordPress.org and replace only the plugin files, keeping your settings, your tables and your log, after a screen that says exactly what it is going to do. It installs the version WordPress.org distributes, never the version the files claim, and never an older one than the version this site had verified. On a network it takes a super administrator, and where WordPress cannot change plugin files the screen gives the steps by hand instead.
* New: SECURITY.md, with how to report a vulnerability, what self-protection covers and what it does not, and how to verify an installation yourself, and bin/verify-manifest.php, a command line tool that checks the plugin folder against the manifest and the manifest against WordPress.org.
* Improved: File Integrity no longer scans Vigilant as a regular plugin, so its files are not reported twice, and updating removes Vigilant own files from the ignore list, where they would silence the new check.
* Improved: on a multisite network a finding about Vigilant own files cannot be ignored on any site, by anyone, clearing the scan results without network rights keeps it, and its alert also reaches the network administration email.

For older changelog entries, please check the [changelog.txt](https://plugins.svn.wordpress.org/vigilante/trunk/changelog.txt) file

== Upgrade Notice ==

= 3.0.4 =
Fixes the expired password notice, which was missing when the password expired during an open session, lands the user at the top of the profile where the notice is, fixes a redirect loop for WooCommerce customers, and limits an account with an expired password to its own profile form.

== Support ==

Need private support or custom development?

Do you need one-on-one help, priority troubleshooting, or a custom feature, integration, or tweak built specifically for your site? I offer private support and custom development. Just [contact me](mailto:vigilante@ayudawp.com) and tell me what you need.

Need help or have suggestions?

* [Official website](https://servicios.ayudawp.com/)
* [WordPress support forum](https://wordpress.org/support/plugin/vigilante/)
* [YouTube channel](https://www.youtube.com/AyudaWordPressES)
* [Documentation and tutorials](https://ayudawp.com/)

Love the plugin? Please leave us a 5-star review and help spread the word!

== About AyudaWP ==

We are specialists in WordPress security, SEO, AI and performance optimization plugins. We create tools that solve real problems for WordPress site owners while maintaining the highest coding standards and accessibility requirements.
