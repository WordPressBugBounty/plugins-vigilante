=== Vigilant - 100% Free Security Suite: Firewall, 2FA, Login, Headers, Scanner…   ===
Contributors: fernandot, ayudawp
Tags: security, firewall, 2fa, malware, scanner
Requires at least: 6.2
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 2.8.0
License: GPL v2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Premium WordPress Security - 100% FREE: Firewall, 2FA, Security Headers, Login and Malware Protection, File Monitor, Security Audit & more

== Description ==

### Premium Security. Zero Cost.

Vigilant provides enterprise-level WordPress security features completely free. No premium version, no upsells, no hidden features behind paywalls.

Protect your site with a complete security suite: firewall, two-factor authentication, brute force protection, security headers, file integrity monitoring, closed plugin detection, malware detection, user management, security audit logging, under attack mode and much more.

### Instant Protection

Once activated, Vigilant immediately applies essential security measures:

* Firewall rules against common attacks (SQL injection, XSS, file inclusion)
* Security headers for browser protection
* Login attempt monitoring
* XML-RPC blocking
* WordPress version hiding
* Sensitive file protection (.htaccess, wp-config.php)
* Automatic backup of your existing configuration files

### One-Click Security Presets

Choose a preset and get protected instantly:

**Standard** - Balanced security suitable for most websites. Enables all modules with sensible defaults that won't interfere with normal site operation.

**Maximum Security** - Strictest settings for high-security sites. Tighter rate limits, stronger CSP rules, mandatory admin notifications. May require fine-tuning for some setups.

You can always customize individual settings after applying a preset.

### Under Attack Mode

Is your site under active attack? Activate Under Attack mode with one click and stop malicious traffic instantly:

* **JavaScript challenge** - Every visitor must pass an automatic browser verification before accessing your site. Real browsers solve it in seconds, bots get blocked completely
* **Aggressive rate limiting** - Requests limited to 30 per minute with 15-minute blocks for offenders
* **HTTP method restriction** - Only GET, POST, and HEAD allowed. PUT, DELETE, PATCH, OPTIONS, and TRACE are blocked
* **Empty user agent blocking** - Requests without a user agent header are rejected
* **Full XML-RPC lockdown** - All XML-RPC access is blocked during the attack
* **REST API restriction** - Only authenticated users can access the REST API
* **Auto-deactivation** - Mode automatically turns off after 4 hours so you never forget it's on
* **Email notifications** - Get notified when the mode is activated and deactivated
* **HMAC-signed cookies** - Verified visitors receive a cryptographically signed cookie so they only see the challenge once

Under Attack mode works independently from your preset configuration. Your regular security settings are preserved and restored when the mode deactivates.

### Core Security Features

**Two-Factor Authentication (2FA)**

Add a second verification step to your WordPress login. Choose the method that works best for your team:

* **Authenticator app (TOTP)** - Google Authenticator, Authy, Microsoft Authenticator, or any TOTP-compatible app
* **Email codes** - One-time 6-digit verification codes sent via email
* QR code setup directly in user profiles
* 10 backup codes for emergency access if you lose your device
* Configurable grace period for users to set up their authenticator app
* Trusted devices feature - optionally allow users to skip 2FA on recognized devices for 30 days
* Role-based enforcement - require 2FA for administrators, editors, or any role
* Exclude specific users from 2FA requirements
* Admin tool to reset TOTP for users who lost their authenticator
* Configurable code expiry, attempt limits, and email sender name
* User notification emails when 2FA is enabled or method changes

**Firewall Protection**

Block malicious requests before they reach WordPress:

* SQL injection blocking
* XSS (Cross-Site Scripting) attack prevention
* File inclusion protection (LFI/RFI)
* Directory traversal blocking
* Bad query string filtering (catches generic suspicious patterns the specific blockers miss)
* Bad bot detection and blocking
* Block requests with empty user agent
* Block legacy HTTP/1.0 requests (almost always automated tools, never modern browsers)
* Rate limiting against DDoS and brute force, with optional progressive lockouts
* IP whitelist and blacklist management (IPv4 and IPv6, with CIDR ranges and wildcards)
* User-Agent whitelist and blacklist with partial matching
* Visitor IP detection control - read the real IP directly from the connection (a spoof-proof default) or from a proxy header when behind Cloudflare, a reverse proxy or a load balancer, with an admin notice if a proxy is detected but not configured
* HTTP method restriction
* Server-level file protection via .htaccess: block direct access to wp-config.php, .htaccess, wp-includes/, and sensitive files (.log, .sql, .bak, .ini, debug.log, readme.html, etc.), and optionally wp-cron.php external access
* Block PHP execution in /uploads (one of the most common post-exploit vectors)
* Disable directory browsing

**Login Security**

Stop unauthorized access attempts:

* Limit login attempts with configurable thresholds
* Progressive lockouts - longer blocks for repeat offenders
* Custom login URL - hide wp-login.php from bots
* Login URL change notifications to all admin-area users
* Hide login error messages - don't reveal valid usernames
* XML-RPC disable - block this common attack vector, with a separate toggle for just the pingback method if you still need other XML-RPC features
* Application passwords control
* Email notification when an IP is blocked for exceeding login attempts
* Admin login notifications via email
* IP whitelist for trusted locations

**User Security**

Comprehensive user account protection:

* Block insecure usernames (admin, test, root, etc.) on new registrations
* Warn about existing users with insecure usernames so you can rename or remove them
* Block author scanning — intercept `?author=N` URLs so WordPress doesn't redirect them to `/author/USERNAME/` and leak the login slug
* Force strong passwords with minimum length
* Password expiration with configurable intervals
* Password history - prevent reusing old passwords
* Force password reset — by specific users, by role, or all users (post-hack recovery)
* Session limits - control concurrent logins per user
* Session management - view and revoke active sessions
* Email verification for new registrations
* Registration approval workflow - manually approve new users
* Admin account monitoring - alerts for new admins, email changes, password changes, privilege escalation
* Display name protection - prevent exposing login username publicly

**Security Headers**

Achieve Grade A security ratings:

* Content Security Policy (CSP) with visual builder and Report-Only mode for safe testing before enforcing
* HSTS (HTTP Strict Transport Security) with includeSubdomains and preload options
* X-Frame-Options - prevent clickjacking
* X-Content-Type-Options - prevent MIME sniffing
* Referrer Policy control
* Permissions Policy (camera, microphone, geolocation, payment, USB)
* Cross-Origin policies (COEP, COOP, CORP)
* HTTPS enforcer with automatic mixed content fix
* Server fingerprint hiding — `Server: Apache/x.y.z` header neutralized, `X-Powered-By` and other fingerprinting headers stripped from responses

**File Integrity Monitoring**

Detect unauthorized changes to your files and compromised plugins:

* WordPress core verification against official checksums
* Plugin and theme file monitoring with WordPress.org checksums
* Critical config files (wp-config.php, .htaccess) monitored against baseline — detects code injection even in files with no official checksum
* Closed and removed plugins detection — daily check against the WordPress.org plugin repository, flags any installed plugin closed for malware, security issues, guideline violations or supply chain compromises. Detects two flavors of closure: explicit with closure date and reason, and "removed" (metadata hidden by wp.org, typical of Security Issue takedowns). Per-slug Ignore for legacy plugins you can't uninstall yet
* Line-level diff view of changes, with per-file approval workflow
* Suspicious code scanning for plugins and themes without checksums
* Extra file detection in plugins and themes (files not in original distribution)
* Two-level detection: strict obfuscation combos for plugins, broad patterns for uploads
* Uploads directory scanning for PHP files, double extensions, and .htaccess
* Root directory scanning for non-core PHP files (common attack vector)
* Smart .htaccess classification in uploads - distinguishes dangerous rules from protective ones
* String concatenation obfuscation detection
* Configurable notification levels (all issues, suspicious only, or disabled)
* Ignore list to dismiss known files from results
* Excluded paths and file extensions
* Scheduled automatic scans (daily, weekly)
* HTML formatted email alerts with severity sections, including a dedicated section for closed plugins

**Security Audit**

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
* Configurable retention period
* Export logs to CSV
* Filter by event type, severity, request method, or date

**Audit Alerts**

Get an email when the audit log points to something worth your attention — off by default, configured under Security Audit:

* Immediate alerts the moment a serious event is logged, by minimum severity (a new administrator, a closed plugin or a privilege escalation are all logged as Critical)
* Threshold alerts when a category spikes — firewall blocks, login failures, user, plugin, file integrity, security, system and content events — over a 30-minute, 1, 6 or 24 hour window, counting only warning and critical events so routine activity never trips them
* A single anti-repeat cooldown keeps a storm of events down to one notice instead of flooding your inbox
* Active alerts surface in Settings & Tools, the Dashboard, the Configuration Score and the Security Check
* "Send test email" button to confirm delivery, shared by Settings & Tools, File Integrity and Audit Alerts

**Security Check**

On-demand security audit built into the Dashboard. No external services, no accounts, no API keys — everything runs on your server:

* 40+ checks across 6 categories: SSL/TLS, HTTP Headers, WP Exposure, Access & Auth, Sensitive Files, and Internal Checks
* Single 0–100 score with A–E grade, plus per-category breakdown and explanatory details for every check
* 15 exclusive internal checks impossible from the outside: PHP end-of-life status, pending updates, inactive plugins, closed or removed plugins in the WordPress.org repository, file permissions, default salts detection, `wp_` table prefix, `admin` username, administrators without 2FA enrolled, module status, recent audit errors, last File Integrity scan result, and whether audit alerts are configured
* DNS-only reputation lookup against Spamhaus ZEN, Barracuda BRBL and SpamCop SCBL (informational — listings are flagged but don't deduct from the score)
* Two-phase scan: fast local checks appear in under a second, remote checks stream in as they complete
* Weekly automatic scan with opt-in email alert if the score drops by 10+ points or a new critical check starts failing
* 30-scan history with sparkline trend and delta chip so you can see how changes to your site affect security over time
* "Go to setting" fix link on every failing check — jump straight to the exact Vigilant field that resolves it, with a visual pulse on arrival
* Smart header diagnostics report "configured but not being served" when a cache/CDN overrides your headers, instead of just marking it green or red

**WordPress Hardening**

Layered protection at the WordPress level — admin, content, head, feeds, and database:

* Lock down the WordPress admin: disable the built-in plugin and theme file editor, block installations and updates from the admin area, and force HTTPS for the admin area. Compatible with any hosting layout, including managed hosts and custom configurations that already define some of these settings on their own — Vigilant always respects values already in place and never overrides them
* Disable WordPress's internal page-view cron when you already have a real server-side cron job configured, removing the small performance hit caused by triggering scheduled tasks on every visit
* Dashboard warning when debug mode is left enabled in production, so error output never leaks to visitors
* Hide your WordPress version everywhere it can leak: from the HTML head, from RSS and Atom feeds, and optionally from every script and style URL on the front-end. The asset cleanup is precise — it only strips the WordPress version itself, leaving versions added by plugins and themes intact so their cache busting keeps working
* Automatic daily removal of readme.html, license.txt, and licencia.txt from the WordPress root, which otherwise expose your WordPress version to anyone visiting them directly
* HTML head cleanup — remove the RSD link, Windows Live Writer manifest, shortlink header, and REST API discovery link
* Database hardening — security check for the default `wp_` table prefix and one-click rename tool with full backup before the change
* Comment security — honeypot field against spam bots, force moderation on every new comment, close comments on old posts after a configurable number of days, disable pingbacks and trackbacks
* Feed management — completely disable RSS and Atom feeds, or only disable them when the site has no published content

**REST API Security**

Control API access to your site:

* Three access modes: public (default WordPress behavior), authenticated only (closes the API to anonymous visitors), or selective (custom allow/block lists)
* Block user enumeration via `/wp-json/wp/v2/users`
* Protect any list of sensitive endpoints from anonymous access
* Per-plugin compatibility toggles so authenticated mode doesn't break the front-end: WooCommerce, Contact Form 7, Gravity Forms, WPForms, Elementor, Jetpack. oEmbed and Site Health endpoints stay accessible by default so embeds and the Tools > Site Health screen keep working

### Security Tools

Utilities included:

* **Database Backup** - Download a full or partial database backup as ZIP with table selection
* **Database Prefix Change** - Change the default wp_ prefix to a random secure prefix
* **Export/Import Settings** - Transfer your configuration between sites
* **Manual Backup** - Create backups of .htaccess and wp-config.php on demand
* **Reset to Defaults** - Start fresh with one click

### Safe by Design

**Automatic Backup System**

Your existing .htaccess, wp-config.php, and robots.txt are automatically backed up before any modifications. Backups are stored in the WordPress database, never as files under the web root, and verified with MD5 checksums.

**Clean Rollback**

When you deactivate Vigilant, all security rules are automatically removed and your original configuration files are restored. No leftover code, no broken sites.

### Why choose Vigilant?

Most WordPress security plugins reserve their best features for paid plans. Vigilant gives you everything upfront — no premium tier, no feature locks, no upsells. Firewall, 2FA with authenticator app, security headers, file integrity scanner, security audit, on-demand Security Check with weekly regression alerts, and more. All free, all maintained, all following WordPress coding standards.

If your current security plugin asks you to pay for features that should be basic, take a look at what Vigilant offers out of the box.

### How does Vigilant compare?

We maintain a detailed feature comparison between Vigilant and other popular security plugins (Wordfence, Solid Security, AIOS, Sucuri, SG Security). See what each plugin offers in its free version and where Vigilant fills the gaps.

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

= 2.8.0 =
* New: Audit Alerts. Vigilant can now email you when something on the site deserves your attention, configured under Security Audit and off by default. Immediate alerts send an email the moment a serious event is logged, by severity — a new administrator, a closed plugin or a privilege escalation are all logged as Critical. Threshold alerts watch for a spike of warning or critical events in a category (firewall, login, users, plugins, file integrity, security, system, and the content categories) within a 1, 6 or 24 hour window, ignoring routine info-level activity. A per-event and per-category cooldown keeps a storm of events down to a single notice instead of flooding your inbox. The active alerts appear in Settings & Tools next to the other notifications, and the Dashboard, Configuration Score and Security Check now reflect whether alerts are set up.
* New: "Send test email" button in Settings & Tools, File Integrity and Audit Alerts, so you can confirm that notifications actually reach your inbox.

For older changelog entries, please check the [changelog.txt](https://plugins.svn.wordpress.org/vigilante/trunk/changelog.txt) file

== Upgrade Notice ==

= 2.8.0 =
New Audit Alerts: get an email when a serious event is logged or when activity spikes in a category (firewall, login, users, plugins), with a cooldown to avoid floods. Set it up under Security Audit; it is off by default.

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
