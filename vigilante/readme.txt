=== Vigilant - 100% Free Security Suite: Firewall, 2FA, Login, Headers, Scanner… ===
Contributors: fernandot, ayudawp
Tags: security, firewall, 2fa, malware, scanner
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.11.4
License: GPL v2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Premium WordPress Security - 100% FREE: Firewall, 2FA, Security Headers, Login and Malware Protection, File Monitor, Security Audit & more

== Description ==

### Premium Security. Zero Cost.

Vigilant provides enterprise-level WordPress security features completely free. No premium version, no upsells, no hidden features behind paywalls.

Protect your site with a complete security suite: firewall, two-factor authentication, brute force protection, security headers, file integrity monitoring, closed plugin detection, malware detection, user management, security audit logging, under attack mode and much more.

Once activated, Vigilant immediately applies firewall rules against common attacks (SQL injection, XSS, file inclusion), security headers, login attempt monitoring, XML-RPC blocking, WordPress version hiding and sensitive file protection (.htaccess, wp-config.php), after automatically backing up your existing configuration files.

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

Versions before 2.11.2 kept a copy of wp-config.php in an option so the integrity scan could show which lines had changed, and that copy carried the database password and the eight authentication keys and salts. Updating removes the copy, but no update can undo an exposure that already happened. So if your database, or any backup of it, may have been read by somebody else while that copy was stored, replace the eight keys and salts in your wp-config.php with fresh ones from the WordPress.org secret-key service, and change the database password if your host lets you. Replacing the salts signs everybody out, yourself included, which is the whole point of doing it.

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

= 2.11.4 =
* Fix: the cleanup that removes the credentials stored by versions before 2.11.2 now runs whether the File Integrity module is on or off. Both cleanup paths were registered inside that module, so a site with file monitoring turned off kept the database password and the eight keys and salts in its options table with 2.11.3 installed and nothing to show for it, and a network whose main site had the module off did not register the network sweep either, which was the one path that reached the sites nobody visits. Turning the module off is not a decision to keep those credentials, and for whoever did it the cleanup matters more rather than less. With the module off there is no scan, so on such a site the cleanup arrives on the first admin page load, and on a network the sweep from the main site reaches the sites nobody opens. Reported by @calzbert, who reviewed the 2.11.3 diff and found every fix in this release.
* Fix: reactivating the plugin no longer replays eleven migrations, one of which empties the trusted devices and the pending second-factor codes. The schema version and the plugin version are written to the same option on two different scales, and the activator wrote the schema one unconditionally, so a site that was completely up to date read as older than almost every migration and ran them all again: every user of that site had to pass the second factor once more, every time somebody toggled the plugin. The schema version no longer walks the stored value backwards, and the migration that deletes rows carries a marker of its own so that no version comparison can replay it. A site that is already sitting on the lower scale, which is also where a subsite created after a network-wide activation starts, may still ask for the second factor once more when it updates.
* Fix: on a network, updating no longer loses the approved record of wp-config.php. The migration to a single network record kept the per-site copies only while that record did not exist at all, and the record can be born holding just one of the two files: the plugin rewrites the root .htaccess by itself on a normal page load, and doing so creates it. From then on the migration considered its job done, dropped every per-site copy, and the approved record of wp-config.php went with them, so the next scan took whatever was on disk as approved. The two files are now carried over one by one, and a per-site copy is only dropped once the network record has an entry for every file the copy had. An entry the network record already holds is kept as it is, so what this recovers is a file the network record did not have yet, which is the wp-config.php case above. Where the copies disagree the main site wins, then the site being cleaned: the scan runs under wp-cron on any site and in no particular order, and until 2.11.3 approving these files took manage_options, which the administrator of every subsite holds, so an approval made on one site could otherwise retire a warning the main site still had pending review.
* Fix: the one-off network sweep added in 2.11.3 no longer rearms itself on every release, and an interrupted one is still finished. Its marker recorded the running version, so every future update walked the whole network to find nothing, which is the expensive walk the marker exists to avoid; but that same marker was what got a walk cut short resumed later. There are two marks now, one for started and one for finished, so a walk that did not get through is picked up by the next version and a completed one is never repeated.
* Fix: the Approve button for wp-config.php and the root .htaccess is no longer shown to people who cannot use it. Since 2.11.3 approving those two files takes a network administrator, but the button was still painted on every site, so the administrator of a subsite saw the warning, pressed Approve and got a permission error with no explanation. A line saying who approves these files takes its place.
* Fix: the file integrity scan is no longer scheduled on sites where the module is switched off. Any admin screen that used the scanner as a tool re-registered its hooks and booked the recurring event, which then fired with nothing listening. Sites that already have that orphan event keep it until the plugin is deactivated.
* Fix: uninstalling and the delete-data option now remove the migration markers, including the one earlier versions left behind in the options table and the network one that survived a delete-and-reactivate.

= 2.11.3 =
* Improved: on a network, the baseline of the critical files is one record for the whole network instead of one per site. Both watched files, wp-config.php and the root .htaccess, belong to the installation and not to any single site, so until now every site kept its own copy of the same file: on a network of fifty sites, fifty copies of the same thing. Approving a change to either file now takes a network administrator, because the file and the record of it belong to the network, and manage_options is held by the administrator of every subsite.
* Fix: on a network, the cleanup that strips credentials from baselines written by earlier versions reaches every site. It ran on admin_init over per-site options, so it cleaned the site whose dashboard someone opened and no other, and the daily scan did not clean them either, because it left untouched any entry whose hash still matched. A subsite nobody visits kept the database password and the eight keys and salts in its options table indefinitely, with 2.11.2 installed and nothing to show for it. The scan now rewrites any stored copy that is not the copy it would store today, so each site cleans itself through wp-cron with front-end traffic alone, and a one-off sweep from the main site clears the rest of the network at once. Reported by @calzbert.
* Fix: changing the database table prefix no longer leaves a copy of wp-config.php next to the original. The copy was named after a timestamp and carried no .php extension, so a server would hand it over as plain text with the database credentials and the eight salts inside. It was deleted right afterwards, but a request that died in between left it there for good, which is precisely the moment when the owner is busy with a site that will not load. Nothing is lost by removing it, because that copy was never read back: the only path that undoes the change restores from memory. Present since 1.2.0.

= 2.11.2 =
* Improved: the User-Agent whitelist no longer skips the whole firewall. It still keeps a remote manager such as ManageWP or MainWP from being turned away by the bot rules, which is what it is for, but a request carrying a whitelisted agent is now checked for SQL injection, script injection, remote file inclusion, traversal and HTTP method like any other. A header the client chooses cannot stand in for an identity: anyone who guessed a configured substring walked past every one of those rules. The list is empty unless you filled it in, so only sites that had configured one were affected.
* Improved: Under Attack mode resolves the visitor address through the same helper as the firewall, honouring the trusted proxy header you configured instead of believing CF-Connecting-IP or X-Forwarded-For from whoever sends them. Those four things it decides with that address, the whitelist, the challenge nonce, the verification cookie and the rate limit exemption, could be steered by sending an invented header. If your site is behind Cloudflare or a reverse proxy, set the trusted proxy header in the firewall settings so both modules see the real client address.
* Fix: the integrity baseline no longer keeps the contents of wp-config.php in the database. It stored the whole file so it could show which lines changed, which meant the database password and the eight authentication keys and salts sat in an option, within reach of anyone who later read the database or a backup of it. Credential values are replaced with a marker before the copy is stored, the file hash still covers the whole file so a change to a secret is still detected, and the copy already saved on your site is cleaned on the first admin page load after updating. If a secret cannot be removed from the copy for any reason, nothing is stored and the scan reports the change without a line diff.

= 2.11.1 =
* Improved: the buttons in the notification emails land on the exact section they talk about. The file integrity email opens the last scan results, the plugin status one the closed and removed plugins list, the lockout one the login protection status and the Under Attack one its own panel, instead of leaving the reader at the top of a tab.
* Improved: a firewall block on a REST API route answers with JSON instead of the HTML Forbidden page, so the block editor and any other REST client can show what actually happened. Same status code, same message, the envelope core uses for an error.
* Fix: the remote file inclusion rule no longer stops the block editor from embedding. An external URL in any parameter was the whole signature, and that is the shape of a link rather than of an inclusion: the block editor asks core to resolve the pasted URL through /wp-json/oembed/1.0/proxy, so embedding a video was refused with a 403 on every site with the rule on, while the classic editor kept working because it posts that URL instead of putting it in the address. A URL now counts as an inclusion attempt when it travels in a parameter that is read as a path, or when it points at something includable. Core's embed proxy is exempt for users who can edit posts, which is what that endpoint requires anyway. The same false positive turned away a search for a URL and any return_url or redirect parameter.
* Fix: the address of a blocked request is recorded as it arrived. It went through a sanitiser that deletes percent encoded characters instead of decoding them, so a blocked embed was stored as httpswww.youtube.comwatchv and there was no way to tell from the log what had been blocked.
* Fix: the activity log detail shows the address of a firewall block. Every one of them was recorded under a key the log screen does not read, so that field was empty for the module that logs the most and diagnosing a block meant reading the database by hand. Entries recorded before this update show it too, and a block by blacklisted address now records the address as well.
* Fix: the links that point at a setting now land on that setting. Fifteen of the 42 Fix links in the Security Check, and the notice about users awaiting approval, used anchors that are not in the page: four still carried the name the firewall section had before it was renamed to Server Protection in 2.0.0, and two pointed at a Tools section that does not exist, when what resolves those findings lives in the firewall. A link like this fails silently, because the browser simply stays where it is, so it looks like the link was always meant to work that way. The link in the weekly report email was ignored by the highlight code as well, so it neither scrolled nor flashed on arrival.

= 2.11.0 =
* New: the activity log export now carries the action, the address and the User-Agent of every entry, and every column neutralises spreadsheet formulas and doubles quotes, not only the message.
* Improved: a remembered device is recognised by a random secret kept in an HttpOnly cookie, not by its User-Agent. Knowing the browser string of a remembered device was enough to skip the second factor once the password was known. Every device remembered before this update has to pass the second factor once more.
* Improved: the remember-this-device option is enforced on the server. With it off, no stored device is honoured and none is saved, whatever the form sends.
* Improved: the authenticator code has an attempt limit per pending session and accepts one time step of clock drift instead of two. Nothing counted those attempts before, because the lockout runs on the authenticate filter and the verification form never passes through it.
* Improved: the login screen no longer says whether an account exists, is waiting for approval, has an unverified email or has too many sessions. All of these show the same generic message now, since each of them was only shown once the password was right.
* Improved: application passwords are no longer blocked by the second factor, which they already are on their own. A REST or XML-RPC login with the main password is still refused, but without sending a code or opening a verification session, so a connector that retries no longer causes one email per attempt.
* Improved: on a network, Under Attack mode no longer rewrites the shared .htaccess from a subsite. That part is reserved to a network administrator on the main site, and the rest of the mode stays available on every subsite. The rewrite goes through the same locked and verified path as the other blocks Vigilant writes, and a failure in that step is recorded in the activity log instead of being swallowed. On a host where WordPress cannot write files directly, those cache rules are skipped and recorded, as every other block Vigilant writes already was; the rest of the mode is unaffected, and the admin notice shows the block to add to the .htaccess by hand.
* Improved: uninstalling on a network cleans the tables and options of every site, not only the one running the uninstall.
* Improved: the firewall keeps the active rate-limit block in a transient per address and reads that on every request, instead of loading the whole list of blocked addresses, which had no upper bound and grew with every new address of a distributed attack. The list the Firewall tab shows is capped at 500 entries. A block that was active at the moment of the update is not carried over: that address has to exceed the limit again to be blocked.
* Fix: the second factor can no longer be skipped through a login form other than wp-login.php. Both modules let a request through when it carried the verification action, the form nonce and a pending session token, but all three are within reach of whoever knows the password: the nonce is printed on the verification form and the token is issued to the visitor who just sent the password. On wp-login.php that request is routed to the verification handler and stopped, but any other form that calls wp_signon(), the WooCommerce login among them, reached the authentication filter and completed the login without a code. The shortcut is gone: the only path that completes a login with the second factor is the verification handler itself. Found in the cross review of this release and reproduced against 2.10.5.
* Fix: the login lockout works on sites whose timezone is not UTC. The attempts table stored the time of the last attempt in local time and the lockout expiry in UTC, and compared them against each other, so with a positive offset the lockout was never seen as active and with a negative one the attempts were never counted. Present since 1.0.0, found while testing this release.
* Fix: an address that is already locked out no longer receives a new lockout, a new critical entry and a new email on every attempt made during the lockout.
* Fix: a pending second-factor session is no longer indexed by IP address. Behind a proxy or a CDN, where visitors share an apparent address, one visitor could be handed the pending session of another user together with the form to complete it.
* Fix: a verification form submitted with an expired nonce explains what happened and records the attempt, instead of silently redrawing the form.
* Fix: the settings import discards any section or key outside the plugin schema instead of merging it into the stored configuration. Saving from the settings screen applies the same rule.
* Fix: email verification codes are stored hashed, and the authenticator secret requires the AUTH_KEY security key to be defined instead of falling back to a value written in the code.

For older changelog entries, please check the [changelog.txt](https://plugins.svn.wordpress.org/vigilante/trunk/changelog.txt) file

== Upgrade Notice ==

= 2.11.4 =
Closes a gap in the credential cleanup: it did not run on sites with File Integrity turned off. Also stops the plugin replaying old migrations when it is reactivated, which was clearing every trusted device.

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
