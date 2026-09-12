=== Vigilant - 100% Free Security Suite: Firewall, 2FA, Login, Headers, Scanner… ===
Contributors: fernandot, ayudawp
Tags: security, firewall, 2fa, malware, scanner
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.11.8
License: GPL v2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Premium WordPress Security - 100% FREE: Firewall, 2FA, Security Headers, Login and Malware Protection, File Monitor, Security Audit & more

== Description ==

### Premium Security. Zero Cost.

Vigilant provides enterprise-level WordPress security features completely free. No premium version, no upsells, no hidden features behind paywalls.

Protect your site with a complete security suite: firewall, two-factor authentication, brute force protection, security headers, file integrity monitoring, closed plugin detection, malware detection, user management, security audit logging, under attack mode and much more.

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

* WordPress core verification against official checksums
* Plugin and theme file monitoring with WordPress.org checksums
* Critical config files (wp-config.php, .htaccess) monitored against baseline, detecting code injection even in files with no official checksum
* Closed and removed plugins detection - daily check against the WordPress.org repository, flagging any installed plugin closed for malware, security issues or guideline violations, including both explicit closures and silent "removed" takedowns, with per-slug Ignore for legacy plugins you can't uninstall yet
* Line-level diff view of changes, with per-file approval workflow
* Suspicious code scanning for plugins and themes without checksums
* Extra file detection in plugins and themes (files not in original distribution)
* Uploads directory scanning for PHP files, double extensions and .htaccess, with smart classification of dangerous rules vs protective ones
* Root directory scanning for non-core PHP files (common attack vector)
* String concatenation obfuscation detection
* Configurable notification levels and an ignore list to dismiss known files
* Excluded paths and file extensions
* Scheduled automatic scans (daily, weekly)
* HTML formatted email alerts with severity sections, including a dedicated section for closed plugins

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

* 40+ checks across 6 categories: SSL/TLS, HTTP Headers, WP Exposure, Access & Auth, Sensitive Files and Internal Checks
* Single 0-100 score with A-E grade, plus per-category breakdown and explanatory details for every check
* 15 exclusive internal checks impossible from the outside: PHP end-of-life status, pending updates, inactive plugins, closed or removed plugins, file permissions, default salts detection, `wp_` table prefix, `admin` username, administrators without 2FA enrolled, module status, recent audit errors, last File Integrity scan result and whether audit alerts are configured
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
* **Manual Backup** - Create backups of .htaccess and wp-config.php on demand
* **Reset to Defaults** - Start fresh with one click

== Safe by Design ==

Your existing .htaccess, wp-config.php and robots.txt are automatically backed up before any modifications. Backups are stored in the WordPress database, never as files under the web root, and verified with MD5 checksums.

When you deactivate Vigilant, all security rules are automatically removed and your original configuration files are restored. No leftover code, no broken sites.

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

Vigilant immediately backs up your existing .htaccess and wp-config.php to the database, then applies default security settings. All modules are enabled with balanced defaults suitable for most sites.

= What happens when I deactivate the plugin? =

All security modifications are automatically reverted. The .htaccess rules are removed, wp-config.php constants are restored to their original values, and scheduled tasks are cleared. Your site returns to its pre-Vigilant state.

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

= Can I use this with other security plugins? =

While Vigilant works standalone, running multiple security plugins can cause conflicts. We recommend testing in a staging environment first if you need to combine security solutions.

= Does this work with caching plugins? =

Yes. Vigilant is compatible with popular caching plugins. The firewall runs before cache layers, and .htaccess rules don't interfere with caching mechanisms.

= Does this work with WooCommerce? =

Yes. Vigilant includes compatibility settings for WooCommerce. The REST API security module automatically allows WooCommerce endpoints, and the firewall won't block payment gateway connections.

= How do I test my security headers? =

Use the built-in header testing tool in the Security Headers tab, or visit securityheaders.com with your site URL to get a security grade.

= What is Security Check? =

Security Check is an on-demand audit built into the Dashboard. It runs 40+ checks across 6 categories (SSL/TLS, HTTP headers, WordPress exposure, access and authentication, sensitive files, and internal checks) and returns a 0–100 score with an A–E grade. Unlike external online scanners, it runs entirely on your server and has access to 14 exclusive internal checks: PHP end-of-life status, pending updates, closed/removed plugins, file permissions, default salts detection, administrators without 2FA enrolled, and more.

= Does Security Check send my data to an external service? =

No. All checks run on your server. The only external traffic is three DNS-only lookups against public blacklists (Spamhaus, Barracuda, SpamCop) for the reputation category — these are standard DNS queries with no authentication, no API keys, and no payload beyond your site's IP address. If you disable the reputation category, Security Check makes zero external network calls.

= How often should I run Security Check? =

Run it manually after any significant change (plugin update, server migration, new user role configuration). For ongoing monitoring, enable the weekly automatic scan from the widget. You'll only receive an email if the score drops by 10 points or more, or if a new critical check starts failing — so no spam from routine scans.

= What is password expiration? =

You can require users to change their passwords after a set number of days (30, 60, 90, etc.). Users receive warnings before expiration and are forced to change their password on next login when it expires. Password history prevents reusing recent passwords.

= What is registration approval? =

When enabled, new user registrations require manual approval by an administrator before the account becomes active. Pending users cannot log in until approved. You can configure auto-rejection after a set number of days.

= What does email verification do? =

New users must verify their email address by clicking a link before their account becomes active. This prevents fake registrations and ensures valid contact information.

= How do session limits work? =

You can limit how many concurrent sessions each user can have. When the limit is reached, either the new login is blocked or the oldest session is terminated, depending on your configuration.

= Can I export the security audit log? =

Yes. The security audit log can be exported to CSV format for external analysis or compliance reporting. You can also filter logs by event type, user, or date range before exporting.

= What files does the integrity scanner check? =

The scanner compares WordPress core files, plugin files, and theme files against official checksums from WordPress.org. Plugins and themes without available checksums are also scanned using strict obfuscation pattern detection. The uploads directory is scanned for PHP files, double extensions, and .htaccess files. Extra PHP files not present in original distributions are detected and, if they contain suspicious code, automatically flagged as suspicious.

= I updated from a version that stored wp-config.php in the database. Is there anything else to do? =

Previous versions kept a copy of wp-config.php in an option so the integrity scan could show which lines had changed, and that copy carried the database password and the eight authentication keys and salts. Updating removes the copy, but no update can undo an exposure that already happened. So if your database, or any backup of it, may have been read by somebody else while that copy was stored, replace the eight keys and salts in your wp-config.php with fresh ones from the WordPress.org secret-key service, and change the database password if your host lets you. Replacing the salts signs everybody out, yourself included, which is the whole point of doing it.

= How often does the file integrity scan run? =

You can configure automatic scans to run daily or weekly. You can also run manual scans at any time. Email notifications support three levels: all issues, suspicious files only, or disabled.

= What is the difference between Standard and Maximum presets? =

Standard applies balanced settings suitable for most sites. Maximum applies stricter rules: lower rate limits, tighter CSP policies, required admin notifications, session limits, and more aggressive hardening. Maximum may require adjustments for sites with complex functionality.

= Where are backups stored? =

Configuration backups (.htaccess, wp-config.php, robots.txt) are stored in the WordPress database, not as files under the web root, so they can never be served over HTTP. A database backup you download is generated as a temporary ZIP with an unguessable name and removed right after the download.

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

= 2.11.8 =
Security fixes: the Under Attack challenge and its rate limit, the visitor IP behind X-Forwarded-For, secrets left in the integrity scan copy of wp-config.php, and several permission checks on networks.

* Fix: in Under Attack mode, a visitor can no longer break the challenge of other visitors who share the same IP address. The challenge used a single nonce per address, reused by every page loaded from it, and any answer carrying that nonce deleted it before the proof of work was checked, so a client behind the same NAT, or any visitor when the site sits behind a proxy with no trusted IP header configured, could keep the others in a challenge loop by sending wrong answers. Each challenge page now carries its own signed token, tied to the address and to the time it was issued, which is checked without being stored or deleted, and serving the challenge no longer writes a transient for each address. Reported by the wordpress.org automated security review of 2.11.7.
* Fix: the copy of wp-config.php that the file integrity scan keeps to show which lines changed now hides every text value in the code, not only the database credentials, the keys and salts and the constants whose name reads like a credential, and everything in comments except plain words. FTP_PASS, SMTP passwords, keys written inside serialize( array() ), any const, putenv() and the fallback after getenv() were stored as they were, within reach of anyone able to read the database or a backup of it, and the check that drops the copy when a secret survives only looked for the twelve WordPress constants; it now looks for every constant the file names and every environment variable it reads. The site address, folders, memory limits, table prefix and include paths stay readable in the diff, and when a value in force cannot be hidden safely the scan says so instead of showing the lines. The copy of the root .htaccess now hides SetEnv values, headers whose name reads like a credential such as Authorization or X-Api-Key, php_value settings that look like a credential and keys compared in RewriteCond. Copies already stored are cleaned the first time an admin page loads or a scan runs on each site after updating, and so are the lines kept in the last scan results; on a network they are also cleaned on every site when a network administrator opens the dashboard of the main site, sites nobody opens included. The lines of wp-config.php are shown again after the next scan. Present since 2.11.2, the version that started redacting this copy.
* Fix: on a network, the changed lines of wp-config.php and the root .htaccess are only shown to network administrators, on the main site. The scan of every site with file integrity on worked them out, stored them in that site's options and showed them to its administrator, and on the main site they were also shown to administrators without network rights, while approving the change has needed a network administrator since 2.11.3. Everybody else still sees that the file changed and its size before and after, with a note saying where the lines are.
* Fix: with visitor IP detection set to X-Forwarded-For, Vigilant now reads the visitor address from the end of the header, where the proxy writes it, and not from its first entry, which the visitor writes. By sending the header, anyone could be taken for an address of their choice: out of the IP blacklist, into the whitelist, which skips the firewall, the Under Attack challenge and the hidden login URL, and with a new address on every request for rate limiting and login lockouts. Addresses of your own network at the end of the header (private, loopback, link-local and the shared 100.64.0.0/10 range) are taken as proxies and skipped, an IPv4 address written as IPv6 is read as IPv4, and a list in CF-Connecting-IP or X-Real-IP is read the same way. Behind a CDN with a reverse proxy in front of PHP that adds to the header, or behind a load balancer that adds its own public address, every visitor is now seen with the address of that CDN or balancer, so choose the header of the CDN if it has one; the Firewall tab warns when your own request shows that shape. The whitelist exceptions written in .htaccess now match the last address of the header. Present since 2.7.0, which added the setting.
* Fix: in Under Attack mode, a visitor who passed the challenge is no longer exempt from rate limiting. The exemption lasted as long as the mode, and the proof of work takes a script a few milliseconds, so a bot could solve it once and then send requests without any limit. Verified visitors now get 300 requests per minute, or the limit set in the firewall if it is higher, while everybody else keeps 30, and they are counted apart from the unverified visitors at their address, so a client that gets that address blocked does not block them.
* Fix: the HTTP method filter of the firewall no longer lets a request through because /wp-json/ appears anywhere in its address, the query string included. Only addresses under the REST API path of the site skip it.
* Fix: on a network, an administrator without network rights can no longer add wp-config.php or the root .htaccess to the ignore list, and that list no longer hides a change to either file. The administrator of the main site could close the warning about a change that only a network administrator can approve by sending the file name to the ignore action. Clearing the scan results now keeps that warning too, for anyone who cannot approve it, and on the main site turning off the critical-file scan, whether its own switch or the whole File Integrity module, is no longer available to an administrator without network rights, since that silences the same warning.
* Fix: on a network, switching Under Attack mode on only purges caches when a network administrator does it. The purge empties the object cache, asks the cache plugins to clear their caches and deletes the SiteGround Optimizer cache folder, most of which reach every site of the network, and the administrator of any subsite could run it every time they switched the mode on. The challenge, the rate limit and the REST API restriction work as before; pages already in a page cache are served from it until it expires or is purged.
* Fix: in an installation with more than one network, only the main site of the main network writes wp-config.php and the root .htaccess, which every network shares, or changes the database prefix. The main site of any other network, and its network administrator, were treated as their owner.
* Fix: the lock that keeps two requests from writing .htaccess at the same time is now atomic. It relied on add_option(), which two requests arriving together could both win, so two writers could still overwrite each other. The network cleanup of stored wp-config.php copies added in 2.11.6 now uses the same kind of lock, so right after an update it runs one request at a time instead of every request repeating the same batch of sites.
* Fix: a .htaccess file that PHP can write but not read is no longer replaced by the Vigilant rules alone. It was treated as empty, so writing the rules removed every other rule in it; now it is left as it is, and the refresh after an update records once that it could not be rewritten instead of retrying every hour.
* Fix: on a network, a setting that had never been saved keeps its default value when an administrator without network rights saves other settings. A module switch in that situation could be stored as off.
* Fix: on a network, approving or rejecting a pending registration now needs permission over that user, which WordPress only gives to network administrators. The pending flag belongs to the account, which every site shares, so the administrator of any subsite could approve a registration waiting on another site, the main site included, and open that account's login everywhere, or reject it. The other account tools have required this since 2.10.3; on a network the approval buttons now appear disabled for everybody else. On a single site that permission is the ability to edit users, which administrators have, and a role without it now sees those buttons disabled too.
* Fix: on a network, visiting another site's dashboard no longer clears a forced password change set by a site with password expiration. The flag is shared by every site, and each site cleared it whenever its own policy did not apply to that user.
* Fix: the one minute wait between two-factor email codes now holds whatever the time zone of the database server. Codes were stored with the database server's local time and compared with UTC, so the wait never applied on servers behind UTC and blocked a legitimate resend for hours on servers ahead of it.
* Fix: a wrong email verification link no longer reveals whether an account is waiting for verification. The expiry was checked before the token, so an account with nothing pending answered expired while a waiting one answered invalid.
* Fix: removed old copies of four admin actions that never ran, because the plugin always used a newer version of each, so a future fix cannot land in the copy that does not run.
* Fix: removed three more methods that nothing called (a login-statistics query, a table-name helper and a duplicate author-enumeration guard whose job another class already does), and with the first one a database suppression that had no written justification. Housekeeping found by a read-through of the direct database queries and the output escaping, which turned up no injection and no cross-site scripting.

= 2.11.7 =
Security fix for networks: switching Under Attack mode off no longer undoes changes a network administrator made, while the mode was on, to the settings behind the wp-config.php and .htaccess all sites share.

* Fix: on a network, switching Under Attack mode off no longer undoes the changes a network administrator made, while the mode was on, to the settings the shared wp-config.php and .htaccess are built from. Switching the mode off puts back the configuration saved when it was switched on, and any administrator of the main site can do it, so an administrator of the main site without network rights could roll those changes back to their earlier values, which the next rewrite of the shared files would publish for the whole network. Those settings are now compared with what the mode applied: the ones nobody changed go back to their earlier values, as before, and the ones that changed keep their new value, whoever switches the mode off and also when it expires by itself. If the mode was already on when you update, they are only put back when a network administrator switches it off. Single sites keep the previous behavior. Reported by the wordpress.org automated security review of 2.11.6.

= 2.11.6 =
Security fixes: Vigilant deletes the copies of wp-config.php, with its database password and keys, that earlier versions kept in the database. On networks, only a network administrator can change or remove the hardening in the wp-config.php and .htaccess all sites share.

* Fix: on a network, deactivating Vigilant on a subsite no longer removes the hardening constants from wp-config.php. That file is shared by every site, and since 2.9.8 only a network administrator on the main site can write or remove the constants block from the settings screen, but the deactivation routine carried its own copy of the removal without that check. With Plugins enabled for site administrators in Network Settings, the administrator of any subsite can deactivate a per-site copy of Vigilant, and doing so removed the block for the whole network: file editing and the installation and updating of plugins, themes and core were unlocked again if they had been locked, forced SSL for the admin was dropped, and the original value of any constant the block had replaced came back. Deactivation now goes through the same removal as the settings screen, with the same check, so the block comes out when a network administrator deactivates Vigilant on the main site, or across the network from whichever site the request comes from, or when WP-CLI does it with no user on the main site or for the whole network; a network-wide deactivation requested on a subsite now removes the .htaccess rules too, which it used to leave behind. Nothing is removed while Vigilant is still active on the main site on its own, which is the case when it was activated there before it was activated for the network, and a copy that stays active on any site keeps its scheduled tasks and sends no deactivation email. Any other deactivation leaves the block in place, including a network administrator deactivating Vigilant on a subsite and a main site administrator without network rights deactivating it there; to remove the block after that, a network administrator can activate and deactivate Vigilant on the main site, or delete the lines between the Vigilant markers in wp-config.php and uncomment the ones marked [VIGILANTE_ORIGINAL]. The deactivation routine had removed the block without that check since 1.0.0, and it became a way around the network rule when 2.9.8 introduced the rule.
* Fix: on a network, only a network administrator can now change the settings that Vigilant writes to the wp-config.php and .htaccess every site shares. Since 2.9.8 the settings screens have shown the file protections, the security headers and the wp-config.php constants as read-only to other users, but saving a tab, importing a settings file, applying a preset, restoring the defaults and adding an address to the whitelist from the activity log only checked that the user administered the site. On the main site those settings are the ones the shared files are built from, so an administrator of the main site without network rights could still change them: the file was not rewritten at that moment, but the new value stayed stored, and the refresh after the next update, or the next save by a network administrator, wrote it to the files of the whole network. Besides the settings already shown as read-only, that covered blocking bad bots and bad query strings, the visitor IP detection, the IP and User-Agent whitelists and the switches of the Firewall, Security Headers and WP Hardening modules, which on the main site now also appear disabled to anyone who is not a network administrator. Saving, importing, applying a preset, restoring the defaults and the whitelist button now leave them as they were, and activating Under Attack mode as such a user no longer changes them either; switching Under Attack mode off still puts back the settings it saved when it was switched on, these included. On subsites, the firewall settings and module switches that only protect that site stay editable by its administrator, while the HTTPS settings of the Headers tab, which only act on that site but have been read-only there since 2.9.8, can no longer be changed by importing a settings file either. If an administrator without network rights may have changed these settings on the main site before this update, review them as a network administrator: the refresh that runs after the update writes the stored values to the .htaccess.
* Fix: Vigilant no longer keeps full copies of wp-config.php in the database, and deletes the ones earlier versions left there. Activating the plugin copied wp-config.php, .htaccess and robots.txt into the options table, keeping up to five sets, and writing the hardening constants kept one more copy of wp-config.php. That file holds the database password and the authentication keys and salts, so every copy put them within reach of anyone able to read the database or a backup of it, and nothing ever read those copies back. After the update they are deleted on the first request that reaches WordPress, which a page served from a page cache does not, and on a network the cleanup goes through every site, 50 at a time, including sites where Vigilant is no longer active, as long as it still runs on one. The file integrity scan still keeps the redacted copy it compares against, without those secrets. The Create Backup tool, which downloads the files as a ZIP, works as before. Present since 2.7.0, which moved these copies from files into the database.
* Fix: deactivating Vigilant no longer changes the permissions of wp-config.php, and writing its rules no longer changes those of the root .htaccess, on single sites as well as on networks. Both used the default WordPress file mode, which is never stricter than 0644, so a wp-config.php kept at 0600 or 0640 was left readable at 0644 or wider on deactivation, and a .htaccess kept at 0640 was left at 0644 or wider every time the rules were written. If you have deactivated Vigilant while it managed constants in wp-config.php, check the permissions of that file. The wp-config.php part was present since 1.0.0.
* Fix: Vigilant no longer cuts a file when one of its blocks has a BEGIN line without its END. Rewriting a Vigilant block in .htaccess, which happens after every update and whenever Vigilant writes its rules, dropped everything below the broken block on any site, the WordPress rules included, and removing the block on deactivation did the same on any site whose rules carry no WordPress markers, as happens when they are pasted by hand. Deactivating also cut wp-config.php from the broken block down, including the line that loads WordPress. Saving or switching off WP Hardening with a broken constants block did not cut wp-config.php, but saving added a second block after the broken one, and switching it off uncommented the original constants while the broken block stayed. The file is now left as it is, and so is the broken block, which keeps working until it is removed by hand. After an update the activity log records it once for that update; saving the Firewall, Headers or WP Hardening tab does not report it, and the rules are only written again once the broken block is gone. Present since 1.0.0.
* Fix: on a network, activating Vigilant on a subsite, or its daily maintenance there, no longer deletes readme.html, license.txt and licencia.txt from the root folder every site shares. Only the main site removes them now, following its own settings.
* Fix: removed unused code that could overwrite wp-config.php, .htaccess and robots.txt from those database copies without the network check, and an unused uninstall routine, so no future change can call them by mistake.

= 2.11.5 =
The file integrity scan now inspects the content inside the blocks Vigilant writes in wp-config.php and the root .htaccess, which earlier versions skipped. Blocks already on disk are recognised once after updating, so a file nobody changed is not reported.

* Fix: the file integrity scan now checks the content inside the blocks Vigilant writes in wp-config.php and the root .htaccess. Those blocks, and the lines Vigilant comments out when it manages a constant, were left out of the hash so that Vigilant rewriting its own block would not read as somebody else's change; the side effect was that a change made inside them did not move the hash and did not show up in a scan. From now on a block is left out only when it is exactly a block Vigilant wrote, which is recorded at the moment Vigilant writes it, and a commented-out original line only while uncommenting it would still give a plain constant define. Anything else is hashed like the rest of the file and reported for review. The blocks already on disk are recognised once, on the first scan after updating, so a file nobody changed is not reported; a block that cannot be recognised as Vigilant's own is reported instead, and the activity log names the file. Present since 1.14.0, the version that first kept these blocks out of the hash.

For older changelog entries, please check the [changelog.txt](https://plugins.svn.wordpress.org/vigilante/trunk/changelog.txt) file

== Upgrade Notice ==

= 2.11.8 =
Security fixes: the Under Attack challenge and its rate limit, the visitor IP behind X-Forwarded-For, secrets left in the integrity scan copy of wp-config.php, and several permission checks on networks.

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
