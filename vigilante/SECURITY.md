# Security policy

## Reporting a vulnerability

Please report security issues privately to **security@ayudawp.com**. Do not post them in the WordPress.org support forums, where they are public from the first message.

A useful report includes the Vigilant version, what an attacker needs beforehand (an account and its role, a setting, nothing at all), the steps or the request that reproduce it, and what happens. You will get an acknowledgement within 72 hours. Fixes are released as soon as they are verified, the report is credited in the changelog unless you prefer otherwise, and details are published only after an update is available.

Reports through the Wordfence, WPScan or Patchstack disclosure programs reach us as well.

## Supported versions

Only the latest release receives security fixes. Updating is the fix.

## How Vigilant checks its own files

A security plugin that has been tampered with is worse than none, because it keeps saying everything is fine. Vigilant verifies its own files against three references:

1. The SHA-256 checksums WordPress.org publishes for the installed version.
2. `MANIFEST.sha256`, shipped inside the plugin, with the SHA-256 of every distributed file.
3. A fingerprint of that manifest, stored in the database the first time Vigilant sees it (not when WordPress.org distributes something else for that version, nor afterwards, for that version or for any other version WordPress.org cannot confirm, until WordPress.org confirms one or the WordPress updater installs another version) and refreshed only by a new version that the WordPress updater installed and left in place, or that WordPress.org confirms. Reactivating the plugin checks against the stored fingerprint instead of taking a new one.

It checks:

- At the start of every File Integrity scan, manual or scheduled, before anything else and outside the scan time budget.
- At the end of the request in which WordPress updates Vigilant, including an update made by uploading a zip file, once a failed update has had its previous copy restored.
- When the version on disk changes outside the updater (a manual or FTP upload, or a downgrade), on the next admin page loaded by an administrator or on the daily maintenance task.
- Once a day, from the daily maintenance task or the next admin page loaded by an administrator, whenever nothing else checked in the last 24 hours (the File Integrity module or its scheduled scans switched off, or a weekly schedule).

It also watches its own scheduled tasks and schedules them again if something removes them. A removal is logged; the same task removed again within 30 days is reported as critical by email. Tasks you switched off are left alone, and on sites activated before a task existed, its first pass schedules it once without reporting anything.

What it reports: a modified file (critical for PHP, JavaScript, the data files in `includes/` and any file a web server can be told to run, whatever extension of its name says so, a warning for other assets), a missing or unreadable file (critical), an added file (critical if a web server can be told to run it, a warning otherwise), a folder that cannot be listed (critical, because files hidden in it can still be run by name), a symbolic link, a file listed in the manifest that WordPress.org does not distribute, a replaced, deleted or invalid manifest, a version change that WordPress.org cannot confirm, and a downgrade. A text file whose line endings were rewritten by the host is not reported, and neither is the manifest itself rewritten that way; a byte order mark is only forgiven in files it does not change, never in PHP (where it is output) or JSON (which then no longer loads).

Findings about Vigilant's own files have their own alert, and no setting silences it. A critical finding is always emailed, wherever it was detected: in a scan, after an update, on a version change, in the daily check or by the task watchdog. So are a downgrade and a version change that WordPress.org cannot confirm. It is sent once per set of findings, with no reminders, to the notification recipients and, on a network, to the network administration email as well. Warnings stay on screen. These findings do not travel in the File Integrity scan email, which follows its notification setting, because switching off the report about changed files must not switch off the alarm about the plugin itself. They cannot be hidden with the ignore list either, by anyone, and updating removes Vigilant's own files from that list. The only way to stop them is to remove every notification recipient, and on a network the network administration email still gets them.

## There is no off switch

The self-check has no setting. It runs in every File Integrity scan, after every update and once a day, whether or not the File Integrity module is on, because a plugin that can be told not to check itself offers that switch to whoever just changed its files.

The one case that deserved an exception is a site that must not talk to WordPress.org at all. That is a filter, in code:

```php
add_filter( 'vigilante_self_integrity_enabled', '__return_false' );
```

With it in place Vigilant reports it as a critical finding, on every admin screen, and names the files that hook the filter, resolved from the callbacks themselves. Switching the check off is allowed; doing it quietly is not.

Two more ways of stopping it are covered the same way:

- **Code that removes the hooks.** A canary runs at the end of every admin page and checks that the two entry points of the self-check are still hooked. If they are gone it is reported as critical and logged with the plugins loaded in that request. WordPress fires nothing when a callback is removed, so the file that called `remove_action` cannot be named: that list of plugins is the short list of suspects.
- **A check that stops running.** A result older than three days stops counting as verified and is reported as a warning, whatever stopped it: a filter, a removed hook, a cron nobody runs, or a site nobody opens. The screen never shows an old green as if it were current.

None of this stops code that runs inside WordPress from neutralising the plugin; nothing can. What it does is make sure the screen does not say "verified" while that happens.

## Alerts

Self-protection has its own email, and no setting switches it off. It does not travel in the File Integrity scan email any more: that one follows a notification setting, and switching off "tell me about changed files" was also switching off the alarm about the plugin itself.

- **Critical findings always send it**, wherever they are detected: a scan, the check right after an update, a version change made outside the updater, the scheduled task watchdog, the check being switched off by code, or its hooks being removed.
- **It is deduplicated by set of findings**, so the same thing does not write twice, and it is sent again when the set changes or after it has been cleared.
- **On a network it is sent once**, from the site that owns the shared files, and it always reaches the network administration email as well.
- **Warnings do not send email on their own**, with two exceptions that always do: a downgrade, wherever it is detected, and a version change whose manifest cannot be verified against WordPress.org. The rest are on screen, in the Vigilant menu and in the File Integrity block; sending an alert every scan because an optimisation plugin rewrites a stylesheet is how alerts stop being read.
- **There are no reminders.** Each distinct set of findings is reported once. Whoever ignores the first email ignores the fifth, and the screen keeps saying it for as long as it lasts.
- Self-protection events are not part of the Security Audit alerting engine either: that engine is for events with an IP and a user behind them, and having two settings for the same email is how one of them ends up silencing what the other promised.

## Repairing Vigilant

When the check reports that Vigilant's own files are not what WordPress.org distributes, File Integrity offers a Repair button. It asks first, and then it does what the WordPress updater does for any plugin: it downloads the package from WordPress.org and replaces the plugin folder with it.

- Only the files change. Settings, database tables and the activity log are kept, because nothing is uninstalled and the plugin is not deactivated.
- Files that are not part of Vigilant but live in its folder go with the folder, which is how an injected file is removed.
- The version installed is the one WordPress.org distributes at that moment, never the one the files on disk claim, and never older than the version this site had already verified. Whoever can change the files can also write the version header, and a repair that trusted it would be a downgrade to a version with public vulnerabilities.
- The address of the package is built by the plugin from a fixed host and a version that matches a strict pattern. Nothing from the request is used.
- It is not offered on an installation whose plugin folder was renamed: the package always installs as `vigilante`, so repairing there would leave a clean copy beside the one that runs. The screen gives the steps by hand instead.
- It needs the capability to update plugins: a super administrator on a network, nobody when `DISALLOW_FILE_MODS` is set. In those cases the screen gives the steps by hand.
- After replacing the files, Vigilant checks them again against WordPress.org and against the manifest, and reports the result.

**What the repair cannot promise:** if whoever changed the files also changed the code that repairs them, this button is as trustworthy as the rest of the copy. The check that does not depend on this server is still the one made from outside, below.

## What this does NOT cover

- **Vulnerabilities in Vigilant's own code.** This detects tampering, not bugs. A flaw in the code that was published is invisible to these checks, because the files are exactly the ones that were published. Fixed vulnerabilities are listed in `changelog.txt`, each with the version that fixed it.
- **An attacker who can write to the database.** They can replace the stored fingerprint, as with any security plugin. They cannot switch the check off: there is no setting for it, and the only way to stop it is the `vigilante_self_integrity_enabled` filter, which lives in code.
- **An attacker who can write to the plugin folder can also edit the code that performs the check.** The WordPress.org checksums are the one reference outside their reach, which is why the checks below that compare with WordPress.org from outside the site are the authoritative ones.
- **The first hours after a release.** Until WordPress.org publishes the checksums of a new version, the check runs with two of the three references and shows as degraded.
- **`readme.txt` and `changelog.txt`** are not in the manifest, because WordPress.org allows updating a released readme without a new version. The WordPress.org checksums still list them.
- **Multisite networks.** Every site keeps its own result, but the email is sent only from the site that owns the files shared by the whole installation, and the task watchdog only covers that site.
- **A deployment that puts the files back.** On a site deployed with Git, Composer or a sync tool, repairing from WordPress.org is undone by the next deployment: fix it there instead.
- **Other plugins and themes.** That is the job of the File Integrity scan, not of self-protection.
- **Windows servers.** There a folder is only reported as one that cannot be listed when it cannot be read, because PHP cannot tell whether a folder can be searched.

## Verify your installation

From the most convenient to the most authoritative:

1. **In WordPress:** the File Integrity tab opens with a self-protection block, coloured by severity, holding the result of the last check, the files it found and what to do about each one. Security Check includes a "Vigilant self-protection" check.
2. **Against the shipped manifest:**
   ```
   cd wp-content/plugins/vigilante
   sha256sum -c --strict MANIFEST.sha256        # Linux
   shasum -a 256 -c --strict MANIFEST.sha256    # macOS
   ```
   This checks every listed file, but it does not notice a file that was added to the folder, it reports a file whose line endings the host rewrote, and it fails on every line when the host rewrote the line endings of `MANIFEST.sha256` itself. The verifier below handles all three.
3. **Against WordPress.org, with WP-CLI:** `wp plugin verify-checksums vigilante`
4. **The manifest itself against WordPress.org:** `php wp-content/plugins/vigilante/bin/verify-manifest.php --wporg`. It also reports files added to the folder. Exit code 0 means the files match the manifest and the manifest matches what WordPress.org distributes; 1, a local file does not match or was added, or a folder cannot be listed; 2, the manifest or the checksums are not available, or the plugin folder cannot be read; 3, the manifest disagrees with WordPress.org.
5. **From outside the server:** download the release from WordPress.org, or run `svn export https://plugins.svn.wordpress.org/vigilante/tags/X.Y.Z`, and compare.

The authoritative check is the external one: a compromised server can lie about its own files.

## How each release is checked

Before a version is tagged, it goes through a fixed set of checks and their numbers are written in the changelog entry of that version in `changelog.txt`. They include an escaping test of the admin JavaScript, an inventory of every AJAX and REST entry point with its capability checks, a scan for dangerous PHP and JavaScript constructs, a count of the coding standards suppressions that touch security, Plugin Check, a consistency check of versions and release notes, permanent regression tests on a single site and on a multisite network (including the proof of concept of every published vulnerability), and a review of the change by someone who did not write it.

`MANIFEST.sha256` is generated as the last step, after every other file is final. Anyone can reproduce it from a downloaded copy of the plugin folder:

```
find . -type f ! -name '.DS_Store' ! -name 'Thumbs.db' ! -path './MANIFEST.sha256' ! -path './readme.txt' ! -path './changelog.txt' | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do shasum -a 256 -- "$f"; done
```

Left out: the manifest itself, `readme.txt` and `changelog.txt` at the plugin root, `.DS_Store` and `Thumbs.db` files, and the Subversion metadata of a working copy, which a downloaded copy does not have. A file a web server can be told to run (PHP in any of its extensions, `.htaccess`, `.user.ini`, `php.ini`) is never left out, wherever it is, and the manifest is not generated at all if the folder holds a symbolic link or a folder that cannot be listed.

## Connections to other servers

Vigilant does not use accounts, API keys or services of its own. It connects only to WordPress.org (core, plugin and theme checksums for File Integrity, plugin status for closed plugins, and its own checksums for self-protection) and, in the reputation category of Security Check, makes DNS lookups against public blacklists. Each of those features can be switched off.
