=== Vigilant - 100% Free Security Suite: Firewall, 2FA, Login, Headers, Scanner… ===
Contributors: fernandot, ayudawp
Tags: security, firewall, 2fa, malware, scanner
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 3.0.8
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
* **HTTP method restriction** - Only GET, POST and HEAD allowed; PUT, DELETE, PATCH and OPTIONS are blocked
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
* Server-level file protection via .htaccess: block direct access to wp-config.php, .htaccess, wp-includes/ and sensitive files (.log, .sql, .bak, .ini, debug.log, readme.html, etc.)
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
* Active alerts surface in Settings & Tools, the Dashboard, the configuration level and the Security Check
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

It adds the points of every check that passes, out of the checks it could run.

* Some checks test the live site: HTTPS, the headers the browser receives, files that should not be reachable.
* Others read a Vigilant setting, such as the custom login URL, the login attempt limit or two-factor. They count while the module that applies the setting is switched on, and tell you whether it is on, not whether a CDN or your host changes the result.
* A check that could not be run, because the site did not answer in time for example, is left out of the score and counted as not measured.

The letter follows one scale: A is 100, B from 85, C from 70, D from 50 and E below. The Dashboard also shows Vigilant configuration, a bar with no letter: it only counts what is switched on, so the two figures can differ.

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

= Vigilant says that its scheduled tasks were missing. What should I do? =

Usually nothing. Vigilant has already scheduled them again, and the notice is not about changed files.

* WordPress itself drops a scheduled task when it cannot save its next run, for example if the database does not answer at that moment.
* A cleanup or optimization plugin can remove scheduled events: exclude the ones whose name starts with vigilante_.
* The notice goes away by itself after a week with no task missing.
* If it turns critical, the same task was missing three times in one week or four in a month: something is removing it. Look for the plugin or the hosting job that does it, and if you find neither, review recently installed plugins and the administrator accounts.

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

= 3.0.8 =
Security Check tells a firewall verification screen, a stale cache and headers set only on files apart from a missing header. A File Integrity scan stopped by the server is now reported, and the scan fits the time limit of PHP.

* Improved: when a security header arrives more than once, Security Check says so in its row, because it is being sent from more than one place and only one should be left. The policy that Vigilant itself sends from PHP with upgrade-insecure-requests alone does not count as a repetition.
* Improved: Security Check also asks for the home page as it is generated now, and says when the copy that visitors get comes from a cache and does not carry the same security headers, so that the cache can be emptied.
* Improved: when a File Integrity scan is stopped before it can save its result, because PHP runs out of time or memory or the server cuts the request, the tab and Security Check say so, with the cause when PHP gives it, and the Security Audit records it. Until now such a scan left no trace.
* Improved: in the Security Audit, Escape closes the details popup, and the actions for the IP and for the User Agent are now in two separate blocks, each with its value and buttons that say what they act on, so that a User Agent is not blacklisted by mistake instead of the IP.
* Fix: Security Check took the verification screen of a firewall or an anti-bot service for the site. A challenge answered with 403 passed as a protected user list, a refused wp-cron.php or a protected file, and one answered with 202 as the home page. Those checks now say that they could not measure and whose screen it was, for the screens that can be told apart: the challenges of SiteGround, Cloudflare and AWS WAF, the block pages of Cloudflare, Sucuri, Imperva, DataDome and Wordfence, and the challenge of the Under Attack mode of Vigilant itself. A file or a page served with 2xx is never taken for a screen. The Test Headers button says the same.
* Fix: on a server that applies the header rules of .htaccess to files and not to the pages PHP generates, as some hosting with PHP as CGI does, Security Check said that mod_headers was not enabled. It now checks an image of WordPress and says what happens. A copy kept by a cache is told apart in the same way, and the policy that Vigilant sends from PHP no longer counts as a header of its .htaccess block that arrives.
* Fix: X-Content-Type-Options and Cross-Origin-Opener-Policy with a value other than the expected one were reported as missing. The row now says which value arrives and which one is expected.
* Fix: a blacklist that does not answer this server was reported as not listing the site. When the answer is empty, each list is now asked about the test entry it keeps listed on purpose, and an answer that is not a blacklist code, which some DNS providers give to every name, is no longer read as a listing.
* Fix: the Limit HTTP Methods option and the description of Under Attack promised to block TRACE. Apache answers TRACE before it reads .htaccess, so only the hosting can switch it off, and the option now says so.
* Fix: with self-protection switched off by a filter that returns __return_false, as in the example of SECURITY.md, the email and File Integrity named wp-includes/functions.php as the file that switched it off. A function or a method of WordPress itself, such as __return_false or is_admin, is no longer named, also when it is passed as a closure, and the steps say how to find the filter. A callback written as Class::method or an object that can be called is now traced to its file, and when something hooks the filter that cannot be traced to a file, the screens say so.
* Fix: in the Security Audit, a scheduled task created for the first time was explained as one that had disappeared, a critical entry listed every task restored in that pass instead of the ones that keep disappearing, and the entries about self-protection switched off or about its hooks removed had no explanation.
* Fix: a Content-Security-Policy with upgrade-insecure-requests alone, the one Vigilant sends from PHP, scored in Security Check as a full policy, and with CSP off in Vigilant it read as delivered by something other than Vigilant. It restricts nothing, so it no longer counts as a policy, and a site whose only CSP is that one loses those points.
* Fix: a Content-Security-Policy-Report-Only scored in Security Check as a policy in force. In that mode the browser reports what the policy would block and blocks nothing, so the row is now a warning with half the points, and when the policy is the one of Vigilant it says how to put it in force. The strictest preset sets CSP to report-only, so a site that applied it gets half the points of that row until the mode is turned off.
* Fix: the attempt to open the hidden wp-admin logged before translations load showed in English in a translated log. It is now translated when it is shown, older entries included.
* Fix: with WPML active, the hidden wp-admin answered a visitor with no session with a server error instead of a not found page, and left a fatal error in the PHP log on every visit. The page is now written without the template of WordPress, with the same text and the same 404, and always as an HTML page, where a request that asked for JSON or XML got the error in that format.
* Fix: the File Integrity scan saved its result only after asking WordPress.org about every installed plugin, so a server that stopped the request at that point lost a scan that had finished. It is now saved as soon as the files are checked, and when little time is left the closed plugins check is left to its daily run.
* Fix: the Run Scan Now button deleted the previous result before scanning, so a scan stopped halfway left the tab empty, and it ran with the memory limit of php.ini instead of the one WordPress gives the dashboard.
* Fix: the scan did not take the time limit of PHP into account, so on hosting that gives a request 30 seconds a scan could be stopped halfway. It now asks for more time and, when the hosting does not allow it, stops in time to save its result, measuring the time as PHP counts it on that server, and says so in the list of what it did not check.

= 3.0.7 =
Scheduled tasks run again when a cron job calls wp-cron.php by its address. Saving WP Hardening no longer breaks a wp-config.php with a define over several lines, and PHP in uploads can no longer be reached in three ways that bypassed the rule.

* Improved: the Security Check row about wp-cron.php is informational and no longer scores. A request to that file only runs the scheduled tasks that are already due, so a reachable wp-cron.php is normal. When the server refuses it, the row says that a cron job calling its address gets the same answer. A report stored before the update shows that row without points until the next scan. With it, the total of Security Check is one point lower.
* Fix: Protect wp-cron.php denied every request to wp-cron.php, including the cron job of a server that calls its address with wget, curl or the cron of a hosting panel, and the scheduled tasks stopped running. The option is retired, and Vigilant takes its rule out of .htaccess when it rewrites its rules after the update; if the file cannot be rewritten, the Security Check row about wp-cron.php says that the server refuses it. A cron job that runs wp-cron.php with PHP was never affected, and on those sites wp-cron.php can be reached again, which only lets anybody run the tasks that are already due.
* Fix: Block Bad Bots turned away a cron job that calls wp-cron.php with wget (in .htaccess) or with curl, so on a server set up that way the scheduled tasks did not run. That list now lets requests to wp-cron.php through. Every other firewall rule still applies to them.
* Fix: with the Firewall module switched off, the Vigilant block of .htaccess kept the firewall rules in force: bad bots, bad query strings, HTTP methods, wp-config.php, sensitive files, directory listing and PHP in uploads, wp-includes, plugins and themes. It now carries only the Server Identity rules of the Security Headers tab while they are on, and goes away when both are off. Sites with the module off get the block rewritten on update.
* Fix: importing settings with the Firewall module off removed that .htaccess block even when Server Signature or Remove Fingerprinting Headers asked for it, and deactivating and activating Vigilant left it out in the same case. The refresh after an update now also takes out a block that nothing asks for, as saving does.
* Fix: in a WordPress installed in a subfolder, or on a network by subdirectories, a restrictive Content Security Policy also reached the admin, because the exception for it only matched /wp-admin at the root of the domain. It now matches /wp-admin as a folder anywhere in the address, and no longer covers root addresses that merely start with /wp-admin, such as /wp-admin-tips/.
* Fix: on PHP 8, with Under Attack on, a visitor could cause a fatal error on the challenge page by sending its redirect field as a list, and the same happened with redirect_to when a login with two-factor authentication started. Both are now read only as text.
* Fix: when the WordPress block of .htaccess had lost its END line, the notice and the log entry said that a Vigilant block was broken. They now name the WordPress block.
* Fix: saving the WP Hardening tab with a define() of wp-config.php written over several lines, such as WP_DEBUG, commented out only its first line and left the file with a syntax error that took the site down. Every line of it is commented now, a define() that shares its line with other code is left alone, and Vigilant never writes wp-config.php unless the result is valid PHP.
* Fix: saving WP Hardening commented out the constants of the owner that Vigilant manages, such as DISALLOW_FILE_MODS, DISABLE_WP_CRON, FORCE_SSL_ADMIN or WP_DEBUG_LOG, even when their setting was off, so they stopped applying with nothing in their place. Only the constants that the Vigilant block defines are commented now. Where this already happened, they come back the next time that tab is saved.
* Fix: Vigilant wrote wp-config.php up to four times in a row to apply those settings, so a failure halfway left it changed. It now prepares the whole change, writes the file once with a lock and reads it back, and if the write is cut short it puts the previous content back.
* Fix: the rule that blocks PHP in uploads could be bypassed in three ways: a path after the file name (file.php/anything) ran the file, another letter case (file.PHP) served its source code or ran it, depending on the server, and an .htaccess with rewrite rules of its own in a folder of uploads, which image plugins write, switched the rule off below it. On Apache 2.4 it now holds in the three cases, and it also covers .php7, .php8 and .phps. The File Integrity finding about such an .htaccess now says that it only switches the rule off outside Apache 2.4.
* Fix: each time Vigilant wrote its .htaccess rules it deleted the blocks named # BEGIN SECURITY HEADERS, # BEGIN 8G FIREWALL and # BEGIN ADDITIONAL PROTECTIONS, taking them for leftovers of an old version. No version of Vigilant wrote them: they are usually rules pasted from a guide or written by another plugin, and they now stay.
* Fix: switching Under Attack on or off showed in File Integrity as a change to .htaccess, and its block was not checked for a missing marker before Vigilant wrote that file.

= 3.0.6 =
Vigilant now tells you when it cannot write wp-config.php or .htaccess. Until now, saving said that the settings were saved while the constants or the server rules never reached the file.

* Improved: the wp-config.php section of the WP Hardening tab says when that file is not writable, or is kept one folder above WordPress, where Vigilant does not write it, for as long as that lasts. In amber while everything those settings ask for is already in force, and in red, naming the constants that are missing or left over, when it is not. The notice is brought up to date after each save, without reloading the page.
* Improved: the Server Protection section of the Firewall tab and the Security Headers tab say when .htaccess is not writable on a server that uses that file.
* Improved: while wp-config.php cannot be changed and some of the WP Hardening settings are not in force because of it, the Dashboard recommends looking at it and names the constants that are not applied.
* Improved: the notice about users awaiting approval no longer loads every one of them on each admin screen just to count them.
* Improved: a site that keeps wp-config.php or .htaccess read-only on purpose will see these notices too, in those sections and after saving those tabs. They are true there as well: no change made in those tabs reaches the file until it can be written.
* Fix: when wp-config.php could not be written, saving the WP Hardening tab or moving a module switch answered that the settings were saved, the constants never reached the file and nothing said so. Activating the plugin with the file not writable left it the same way. The save now shows a second notice next to the usual one, which stays on screen and names the constants that were not applied. Saving that tab with nothing left to write still says that the file is not writable. And when moving a module switch leaves something unwritten, the page is no longer reloaded, so the notice can be read.
* Fix: the same happened with .htaccess. Saving the Firewall or the Security Headers tab, or switching one of those two modules on or off, with a .htaccess that is not writable now says that the server rules were not updated. It also says so, with the reason, when Vigilant leaves the file as it is for another cause, such as one of its blocks having lost a marker.
* Fix: the description of the Maximum preset said that its Content Security Policy was set to report-only mode. The preset enforces it, and the description now says so.
* Fix: the Test Headers button said nothing when its request failed outright. It now shows an error.

= 3.0.5 =
The Dashboard shows one grade, the one of Security Check, on a stricter scale. It counts a setting only while its module is on and leaves out what it could not measure, so some scores go down. The notice about scheduled tasks no longer says that files were modified.

* Improved: the Dashboard shows one grade. Security Check, which measures the site, keeps its letter and comes first. What was the Configuration Score is now Vigilant configuration: a bar with a percentage and no letter, next to the recommendations and the modules it counts. Two letters side by side read as two grades of the same site that did not agree.
* Improved: Security Check and each of its categories use a stricter scale of letters: A is a perfect score, B starts at 85, C at 70, D at 50 and E is anything below. Until now a B ran from 70 to 99, so a site with many failing checks sat one letter away from a perfect one. The numbers do not change with this, but many sites will see a lower letter.
* Improved: Security Check leaves a check it could not run out of the score, and says how many were not measured. Until now such a check counted as a zero, so a request to your own site that timed out lowered the score as if the check had failed, and the result changed from one scan to the next. A check that is only informational, such as a header switched off on purpose, no longer keeps the score from reaching 100.
* Improved: the percentage of Vigilant configuration is worked out over the same total on every site, and a module that is switched off loses its points and the points of its settings. Until now those settings left the total too, so a site with most modules off kept a middling figure, and switching Security Audit off with no alert configured raised it. Sites with modules switched off will see a lower percentage.
* Improved: the Active theme row of Security Check is informational and no longer gives 5 points. Whether the theme has an update pending is already scored by another check. This can move the score by a point or two.
* Improved: Security Check says when a security header reaches the browser from a Vigilant block in the .htaccess of a folder above the site, which is what happens to a WordPress installed in a subfolder of another one. Until now only the Content-Security-Policy check said so.
* Improved: when Vigilant finds one of its scheduled tasks missing and schedules it again, the second time in 30 days is now a warning, with no email and no effect on the scores, and it goes away by itself after a week with no task missing. It only becomes critical, with one email a week at most, from the third time within one week or the fourth within 30 days. Until now the second time was already critical, both scores dropped to E, and the notice stayed for 30 days whatever was done. WordPress itself drops a scheduled task when it cannot save its next run, so two in a month does not mean that something is removing them.
* Improved: the hourly task of Vigilant is no longer watched. It does nothing, and being hourly it was the one most often lost.
* Improved: Vigilant no longer waits for an administrator to open the dashboard to schedule again a task that went missing: it also checks from the scheduled tasks of WordPress itself, which run twice a day. Until now, when the daily maintenance task was removed, it stayed missing and nothing watched the others until an administrator came by.
* Improved: the steps of the notice about scheduled tasks say first that Vigilant has scheduled the tasks again, then what to look for, and leave a possible compromise for the case that keeps repeating.
* Fix: Security Check passed checks on a setting that was saved while the module that applies it was switched off, so the protection was not running: the custom login URL, the login attempt limit, two-factor, XML-RPC, the RSD, Windows Live Writer and shortlink tags, and the checks that read Security Audit and File Integrity. With the Security Headers module off, the Content-Security-Policy and HSTS checks said that something was removing the header and gave half the points. They now fail and name the module that is off. Sites with modules switched off will see a lower score, and the weekly scan, where its email is switched on, will report the checks that start failing.
* Fix: the Test Headers button graded the settings of its tab without asking the site for anything, so it could show a B where no header reached the browser. It now measures what arrives, with the checks and the scale of Security Check. And Security Check says when a header is switched on in Vigilant but does not arrive, with the likely cause, and gives it no points.
* Fix: three texts of Security Check that could be read wrong. The check of /wp-admin/ said that visitors were sent to the login page whatever the redirect was. The two checks of users over the REST API were named almost the same: one is the list of users, the other only tells a visitor who they are, and WordPress answers that one with a 401 on any site, so it is now informational and no longer gives 2 points. And a single user was counted as 1 user records.
* Fix: Security Check counted an administrator as protected by two-factor when the role was not among the enforced roles or the account was among the excluded users.
* Fix: Security Check passed the checks for exposed files (.env, .git/config, debug.log, copies of wp-config.php, developer scripts and wp-cron.php) when the request it sends to the site got no answer. They are now shown as not measured.
* Fix: the file permissions check of Security Check reads wp-config.php when it is one folder above WordPress, and says so when it cannot find it instead of passing.
* Fix: on the Dashboard, switching a module saved the change twice and showed for a moment a score worked out differently from the one the page shows once reloaded.
* Fix: in Security Check, the bar of each category kept its color after a scan until the page was reloaded.
* Fix: when the critical notice was about scheduled tasks, the email, the File Integrity box, the admin notice, the Dashboard recommendation and the note on the scores said that the files of Vigilant had been modified, with every file intact. They now say that scheduled tasks keep being removed, count tasks instead of files, and no longer ask for a repair or for a new scan, which cleared nothing.
* Fix: when the hooks of Vigilant self-protection had been removed, the email, the File Integrity box, the admin notice, the Dashboard recommendation and the note on the scores said that the files of Vigilant had been modified, and with self-protection switched off by code so did the email and the note on the scores. They now say what was found. With self-protection switched off by code, the Dashboard also asked to turn it on, which no setting does: it now says that something on the site switched it off and where to look.
* Fix: when WordPress updated Vigilant in the background and the daily maintenance of Vigilant fell due in that same run, Vigilant took the update for a version change made outside the updater, wrote it down as such and could send a warning email. It now waits for the check it runs at the end of every update, and so do the other checks while WordPress is running its background updates in another process. An update is handled by the version that is being replaced, so this takes effect from the update that follows this one.
* Fix: File Integrity reported as suspicious a call to the old PHP function that builds a function from a string when the call was only inside a comment, where plugins leave it next to the code that replaced it. Comments are no longer searched for it, and a live call is reported as before.

= 3.0.4 =
Fixes the expired password notice, which was missing when the password expired during an open session, lands the user at the top of the profile where the notice is, fixes a redirect loop for WooCommerce customers, and limits an account with an expired password to its own profile form.

* Improved: when a password has expired, the user is taken to the top of their profile, where the notice says why, instead of straight to the password field with the notice out of sight above it. The notice now has a link to the field.
* Fix: the notice that a password has expired was missing when it expired while the user was still logged in. The user was sent to the profile with no explanation, and the notice only appeared after logging in again.
* Fix: on the last day before a password expires the warning notice was not shown, so the forced change arrived with no warning the day before.
* Fix: in a WooCommerce store, an account with no access to the admin area, a customer for example, whose role is in Affected Roles was caught in a redirect loop when its password expired. WooCommerce sent it from the profile to My Account and Vigilant sent it back, so it could neither use the store nor change the password. That account is now let into its profile screen in the admin area while the change is pending, and only into that screen. The password is changed there, not in My Account, and once it is saved WooCommerce takes the account back to My Account as usual.
* Fix: while a password change was pending, every request to the profile screen was let through, and that screen can be asked for other things: a plugin page, an importer, an action passed in the address, or the profile of another user for an account allowed to edit users. An account with an expired password could go on using those. Only its own profile form is let through now, to be shown or to be saved. On a network, the profile screens of the network admin and of the user dashboard lead to the profile of the site, where the notice is.
* Fix: on a site whose WordPress Address and Site Address are on different hosts, a headless site for example, or whose address has accented or non-Latin letters saved as written, a user with an expired password was caught in a redirect loop. The redirect to the profile came out as a redirect to the dashboard, which sent the user to the profile again. It now reaches the profile.

For older changelog entries, please check the [changelog.txt](https://plugins.svn.wordpress.org/vigilante/trunk/changelog.txt) file

== Upgrade Notice ==

= 3.0.8 =
Security Check tells a firewall verification screen, a stale cache and headers set only on files apart from a missing header. A File Integrity scan stopped by the server is now reported, and the scan fits the time limit of PHP.

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
