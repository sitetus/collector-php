# Changelog

## 0.7.6 — 2026-11-18

`files` module: the content scan recognises two more shapes of planted code. A small loader that downloaded a file-manager backdoor and ran it, and the downloaded file itself, matched none of the existing signatures: neither holds an encoded block, and neither hands request input straight to a command.

- New rule `remote_loader`: code that runs what it has just fetched. Three shapes are recognised: the evaluating construct whose argument, in the same statement, contains a call that reads a file or an address (the address may be held in a variable, so any such read counts); the assertion construct whose argument contains a network read or a read of a literal web or FTP address; and an include or require whose target is a literal web or FTP address, a `data:` stream or the request body. A fetch whose result is only assigned, an assertion over a local file, and an include of a local path do not match.
- New rule `shell_toolkit`: a file that calls at least four different functions of the command-execution family (the six functions PHP has for running a program) and reads request input (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` or `$_FILES`) anywhere in the scanned part. Why four: code that looks for a function the host left enabled tries two or three of them and does not read request input in the same file, while a file manager offers them all to whoever sends the request. Only the bare function call counts — a method or a declaration of the same name does not — and the scan does not tell code from comments or strings, so a call written in a comment counts too.
- Both rules read the same part of a file as the others (the first and last 8 KB) under the same limits, and a file is still reported under one rule: the first that matches, with the very general long-base64 rule tried last.
- What they do not cover: a loader that saves the download to disk and includes it from there, and a toolkit whose calls all sit in the middle of a file longer than 16 KB.
- `php_files.suspicious.rules` can now carry `remote_loader` and `shell_toolkit`. Envelope format, signature material and the other modules are unchanged; a panel that does not know the two ids still lists the file as suspicious.

## 0.7.5 — 2026-11-18

A new optional module, off unless the installation selects it, says whether the Laravel application key is one that is already publicly known. The comparison happens on the server; one yes/no leaves it.

- New opt-in module `secret_check` (Laravel only). Like every module it is not in the file unless it was selected when the package was generated; without it the collector reads no configuration value for its content, as before, and the file carries neither the module's code nor its list.
- With the module selected, `APP_KEY` (`app.key`) is the only configuration value read for its content, in memory only. It is hashed (SHA-256) and the first 6 bytes are looked up in a sorted list of 1,258 such truncated hashes of publicly known keys — product defaults, keys from tutorials, keys published in public repositories — embedded in the module's part of the file. The key is compared exactly as configured, `base64:` prefix included, which is the form the public lists hold; the decoded key bytes are not hashed.
- The module's section in `modules` is `{"public": {"app_key": true}}` or `{"public": {"app_key": false}}`. When there is nothing to check it is `{"unsupported": "<reason>"}` instead: `no_application` (not Laravel, or the application did not boot), `no_config` (the configuration could not be read), `no_secret` (`APP_KEY` is not set or is not a string) or `no_data` (the list could not be read — never reported as "not public").
- The key, its length, its hash and any part of its hash never leave the server and are never written or logged. The embedded list contains no key, only truncated hashes.
- A "yes" tells the panel that the key is an entry of a public list. A key on no list can match by chance with a probability of 1,258 in 2^48 (about 1 in 224 billion).
- The list is derived from the MIT-licensed key lists of `synacktiv/laravel-crypto-killer` (Copyright (c) 2024 Synacktiv). The plain lists are not in the repository; `src/data/NOTICE` names the source, its licence and the commit used, and `build/known-secrets.php` regenerates the data file.
- Selecting the module makes the file about 15 KB larger; a file without it is the size it was.
- Envelope format and signature material are unchanged, and an installation that does not select the module sends exactly what 0.7.4 sent. The module key is new: the panel is updated before it offers the module.

## 0.7.4 — 2026-11-18

Four new readings about where the site sits on its server, and a signature gate that says why it refused a request from the panel.

- New Level 1 row `hosting_layout`: whether a folder on the project's path is named `public_html` or `private_html` (the folders a web server's per-account address serves), whether the web server's document root is the project root itself, the first 12 characters of a keyed hash (HMAC-SHA-256 with the installation's project key) of the account the PHP process runs as, and the hosting panel as one word (`cpanel`, `plesk`, `directadmin`, `unknown`). The row is always `ok`: the collector reports, the panel judges. No path and no account name leave the server.
- New Level 1 row `os_release`: the `ID` and `VERSION_ID` values of `/etc/os-release` (for example `ubuntu 22.04`), so the panel can match the operating system against its end-of-life dates. No other line of the file is read into the envelope; a value outside the expected alphabet is dropped, not sent. Unreadable file or no `ID`: `unknown`.
- `listening_ports` also reports the Docker API (2375) and etcd (2379) when they listen on every interface; both answer without authentication.
- New Level 2 row `db_account_scope` (MySQL and MariaDB): the host part of the server's answer to `CURRENT_USER()` reduced to one word — `local` (localhost, 127.0.0.1, ::1), `any` (the bare wildcard `%`) or `specific` (a named host, an address, or a pattern that narrows the wildcard). The account name and the host are never sent; on another driver, a database on another server or a failed query the row is absent.
- Signature gate: a request that carries the installation's project key and still cannot be accepted now gets a bodiless `403` with a reason instead of a `404` — `X-Sitetus-Error: unsupported-algo` with `X-Sitetus-Supports: <algorithms this PHP can verify>` when the file's signature algorithm cannot be verified on the server (Ed25519 without the `sodium` extension), `X-Sitetus-Error: signature` when the signature does not verify. A missing header or another project key is still an empty `404`; `skew`, `nonce-store` and `nonce` are unchanged. An expired or sleeping installation still answers `404` to everyone. A request without a valid signature writes nothing to the nonce store.
- Envelope format and signature material are unchanged. The new rows can carry `null` in their detail, which a panel older than this release rejects: the panel is updated first.

## 0.7.3 — 2026-11-17

`files` module: the web-shell signature scan tells a partial scan from a clean one and no longer reads data stored behind `__halt_compiler()`.

- A PHP file that ends its code with `__halt_compiler()` (Wordfence's `wflogs` store, Phar stubs) is judged by the code before the marker only; the payload after it is never compiled and does not match the long-base64 rule any more. A site running Wordfence was reported as carrying suspicious code every morning because of `wp-content/wflogs/config-transient.php`.
- `php_files.suspicious` carries a new `partial` flag: `true` when the directory walk stopped at its budget (3 seconds, 20,000 entries) or the content scan did not reach every file. The panel reads "nothing matched" in a partial scan as unknown rather than clean; a match stands either way. Older panels ignore the key.
- The content scan is separated from the directory walk: the walk only reads names and modification times, the signature scan then reads at most 2,000 files under its own 3-second budget. Files modified in the last 7 days are read on every request; the rest is read from a start that moves 200 files further along the list every day (same rule as the core integrity module), so a set larger than one request can read is covered within a few days instead of leaving its tail unread for ever. Reported names are sorted.
- `php_files.suspicious.rules` names the signature that matched each listed file (`eval_decoder`, `eval_request`, `request_call`, `shell_request`, `preg_eval`, `create_function`, `long_base64`), in the order of `names`, so the panel can weigh a rule without a new collector release. Only the rule id leaves the server, never content.
- Envelope format, signature material and the other modules are unchanged.

## 0.7.2 — 2026-10-13

First release on a public repository.

- Directory walks are sorted, so the file names an envelope lists come in the same order on every operating system.
- A skipped tree (`storage/`, `vendor/`, upload and cache directories) is now skipped whole: its root directory is no longer counted as world-writable by the permissions module.
- The Laravel wrapper moved to its own repository and package (`sitetus/laravel-collector`); this repository holds the single-file collector only.
- Source comments no longer cite internal documents; the README and the security policy are in English; this changelog replaces the release-notes section of the former internal specification; the generated file's header points at `github.com/sitetus/collector-php`.

## 0.7.1 — 2026-10-09

`bot_traffic` counts five more bots: Google-Agent, DuckAssistBot, MistralAI-Index, MistralAI-User and MistralAI-Training (from the providers' own pages, 3 October 2026; added to the source after 0.7.0, shipped in the build with this release).

- Google-Agent is counted as itself even when its documentation address contains "googlebot"; Mistral's three suffixed tokens are matched before the shorter ones.
- Envelope format, signature material and the other modules are unchanged; an older panel ignores an unknown bot key.

## 0.7.0 — 2026-10-03

`maintenance_mode` moves from Level 2 to Level 1: it is read from the marker file without a framework bootstrap, so it works outside Laravel too.

- Laravel: `storage/framework/down` — from the JSON only `time` and whether a `secret` is **present** are read; the secret itself and every other field never leave the server. Other frameworks: a `.maintenance` file in the web root (WordPress core format; active when younger than 10 minutes, otherwise `stale_file`).
- `detail` carries `active`, `since_seconds`, `framework` and `has_secret`.
- The Level 2 `isDownForMaintenance()` row is removed so the same id is not sent twice. Envelope format, signature material and modules are unchanged; an older panel reads the row as a boolean, as in 0.4.0.

## 0.6.1 — 2026-10-02

The `files` module classifies control files in upload directories (`.htaccess`, `.user.ini`, `web.config`, `php.ini`) before counting them as threats: the first 4 KB are read locally and only a class leaves the server.

- `enabling` — a rule that turns PHP execution on or changes how files are executed; `protective` — deny / engine-off rules only; `unknown` — comments only, unrecognised directives, unreadable, or longer than 4 KB.
- Up to 0.6.0 the protective `.htaccess` files shipped by WooCommerce, Wordfence, Sucuri and hosting providers opened a critical "executable upload" finding.
- `control_files.count` / `names` now mean enabling + unknown; the `enabling` (count + names), `protective` (count only) and `unknown` (count + names) sub-fields are new. Envelope format, signature material and the other modules are unchanged; an older panel reads `count` as before, with fewer false alarms.

## 0.6.0 — 2026-10-02

Two posture rows in Level 2.

- `storage_link`: are the `filesystems.links` symlinks in place and really links — only the `present` / `is_link` flags travel, never a path; a missing link while the public disk is defined is a warning.
- `session_driver`: the `session.driver` name; `file` / `array` / `cookie` in production is a warning.
- No separate row for `queue.default = sync`: `queue_depth` has warned on the `sync` / `null` driver since 0.4.0.
- Envelope format, signature material and modules are unchanged; an older panel shows an unknown id as "no data".

## 0.5.2 — 2026-09-30

`bot_traffic` counts three more bots: Meta-WebIndexer, Amzn-SearchBot and Amzn-User (from the providers' own pages, 29 September 2026).

- Amazon's two new fetchers are counted as themselves even when their documentation address contains "amazonbot".
- Envelope format, signature material and the other modules are unchanged; an older panel ignores an unknown bot key.

## 0.5.1 — 2026-09-25

Hardening after a security review.

- The single-file build had crashed on signed pulls since 0.3.0 (the `Modules\ModuleRunner` reference was not rewritten when the sources were flattened; CI only ran `php -l`). Fixed, with an end-to-end **build → strip modules → signed request** test.
- PHP warnings can no longer leak into the response body (`display_errors` off, an error handler and an output buffer around the whole run; the `runtime.ini` flags are read at the start of the request, before any guard changes them).
- After Level 2 the application's own error and exception handlers are restored.
- The nonce window is twice the clock-skew tolerance; a store that cannot be written answers `403 nonce-store` instead of accepting the request.
- `bot_traffic` looks only at the documented log locations, examines at most 200 candidate files and reads lines of at most 16 KB.
- Modules open regular files only. `ini_get` / `glob` listed in `disable_functions` yield "no data" instead of an error. Reads are capped (lock file 8 MB, heartbeat 64 KB). Invalid UTF-8 no longer breaks the JSON envelope.
- Composer wrapper: the module default is empty (opt-in means opt-in) and the core is pinned to `^0.5.1`.
- The distribution archive carries no test files (`.gitattributes`); the CI token is read-only.

## 0.5.0 — 2026-09-17

Opt-in `bot_traffic` module.

- Reads the tail (at most 20 MB) of the newest readable web-server access log locally (combined / common log format; under the project `storage/logs/access.log` or `logs/`, on hosting accounts `~/logs`, `~/access-logs`, `~/domains/*/logs`, system-wide `/var/log/nginx|apache2|httpd`).
- Reports, per vendor-documented AI bot, only counters: requests, last seen (unix time), 2xx–3xx / 401-403-429-503 / other; plus the window (first and last line time, days), the number of lines read and the log location **class** (`project` / `hosting` / `system`).
- No IP, path, referer or user-agent string leaves the server. Counts go by the User-Agent token, which is spoofable, and are labelled so.
- `unsupported: no_log` when no log is readable. Budgets: 20 MB, 400,000 lines, 2.5 s.

## 0.4.0 — 2026-09-16

Operational posture.

- Level 1: `opcache` (loaded / enabled flags, hit rate, cached scripts, memory used) and `load` (5-minute load average per core from `/proc/loadavg` and `/proc/cpuinfo`; `unknown` outside Linux).
- Level 2: `cache_store` (driver name; `array` / `file` / `null` warn), `queue_depth` (pending jobs with the driver name and the age of the oldest job on the database driver; `sync` warns), `pending_migrations`, `maintenance_mode` and `redis_version` (only when the application uses Redis for cache, queue or session; from `INFO server` only the version string).
- `files` module: the first and last 8 KB of up to 2,000 PHP files in the web root are scanned locally for web-shell signatures (eval / assert with base64_decode / gzinflate / str_rot13, variable functions or shell calls fed from the request, `preg_replace /e`, `create_function`, base64 blocks of 800+ characters); `php_files.suspicious` carries a count and names, never content.

## 0.3.0 — 2026-09-16

- Level 1: `php_ini` (count of risky flags; `display_errors`, `expose_php`, `allow_url_include`, `allow_url_fopen`, `disable_functions` count, `open_basedir`, memory and upload limits — flags and sizes, never paths or values), `log_size` (total of `storage/logs/*.log` in MB) and `listening_ports` (known data services bound to `0.0.0.0` / `::` from `/proc/net/tcp`; `unknown` when unreadable).
- Level 2: `mail_driver` (the `mail.default` driver name only; `log` / `array` fail — no mail ever leaves the site).
- A health entry may carry a bounded scalar `detail` (at most 20 booleans, numbers or short strings).

## 0.2.0 — 2026-09-15

Opt-in, read-only modules.

- `files` (mtime and size of a fixed per-framework list of sensitive files; executable or double-extension files and PHP control files in upload directories; a hash and count of the web root's PHP file set and the names of PHP files changed in the last 7 days), `archives` (forgotten backups and database dumps in the web root, depth 2) and `permissions` (world-writable entries under the project root; `unsupported` on Windows).
- Every walk has an entry budget, a depth cap and a wall-clock budget. Names leave the server as relative paths under the scanned root only: at most 50 names per list, 200 bytes per name, control characters replaced, invalid UTF-8 reduced to ASCII; `budget_exhausted: true` when a budget runs out.
- The module list is per installation; module code sits between `SITETUS_MODULE_START/END` markers so the package builder can strip every module the installation did not select — a module whose code is not in the file reports `unavailable`.
- Composer wrapper: runs the modules selected by `SITETUS_MODULES`, with envelope parity to the single file.

## 0.1.0 — 2026-09-06

First release: a single-file, read-only PHP (≥ 7.4) collector that answers signed pull requests with a JSON envelope and does nothing else.

- Signed pull verification (Ed25519 primary, RSA-SHA256 fallback): constant-time comparisons, an anonymous bodyless 404 for every invalid request, 403 skew with a server-time header, a flock'ed file nonce store, permanent sleep after `expires_at` or 90 days without a valid request.
- Level 1 inventory and health: framework detection by file signatures, package inventory from `composer.lock` or `installed.json`, disk, writability, caches, `.env` permissions, backup recency, heartbeat files and origin TLS expiry.
- Level 2 (guarded Laravel bootstrap, after verification only): database connectivity and a seven-flag configuration allowlist.
- `build/build.php` concatenates `src/` into a lint-clean `dist/index.php` with a quoted `{{PLACEHOLDER}}` configuration block and prints its SHA-256.
- Composer wrapper `sitetus/laravel-collector` (PHP ≥ 8.1): the service provider registers the pull route only when configured, publishes the config and records the scheduler and queue heartbeats itself; the envelope is byte-identical to the single file except `collector.name`, plus the `custom_checks` section — `Sitetus::check()` registers developer-defined checks whose outcome is `{id, status, value?}` with numeric or boolean values only.
