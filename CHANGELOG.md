# Changelog

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
