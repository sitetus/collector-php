<?php

namespace Sitetus\Collector;

/**
 * Level 1 health checks: numbers, statuses and flags only —
 * never raw logs, paths, usernames or connection strings. Messages are keys
 * from a fixed dictionary (msg.*).
 */
final class Health
{
    /**
     * WordPress core treats a `.maintenance` file older than this as gone.
     */
    public const WORDPRESS_MAINTENANCE_SECONDS = 600;

    /**
     * Services `listening_ports` reports when they listen on every
     * interface. 0.7.4 adds the Docker API and etcd, which answer without
     * authentication.
     */
    public const WATCHED_SERVICES = [
        6379 => 'redis',
        3306 => 'mysql',
        5432 => 'postgres',
        11211 => 'memcached',
        27017 => 'mongodb',
        9200 => 'elasticsearch',
        2375 => 'docker_api',
        2379 => 'etcd',
    ];

    /**
     * @var string
     */
    private $hashKey;

    /**
     * @param string $hashKey the installation's project key; keys the account hash of `hosting_layout`
     */
    public function __construct(string $hashKey = '')
    {
        $this->hashKey = $hashKey;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function level1Checks(?string $root): array
    {
        $checks = [];

        $checks[] = $this->diskUsage($root);

        if ($root !== null) {
            $checks[] = $this->writable('storage_writable', $root.'/storage');
            $checks[] = $this->writable('bootstrap_cache_writable', $root.'/bootstrap/cache');
            $checks[] = $this->fileExists('config_cached', $root.'/bootstrap/cache/config.php');
            $checks[] = $this->routesCached($root);
            $checks[] = $this->envFilePermissions($root);
            $checks[] = $this->backupRecency($root);
            $checks[] = $this->heartbeat('scheduler_heartbeat', $root.'/storage/app/sitetus-heartbeat.json');
            $checks[] = $this->heartbeat('queue_heartbeat', $root.'/storage/app/sitetus-queue-heartbeat.json');
            $checks[] = $this->logSize($root);
            // 0.7.0: maintenance mode from the marker file, no bootstrap needed.
            $checks[] = $this->maintenanceMode($root);
            // 0.7.4: where the project sits relative to the web folder.
            $checks[] = $this->hostingLayout($root);
        }

        $checks[] = $this->originTlsExpiry();
        // 0.3.0: php.ini hygiene and locally listening services.
        $checks[] = $this->phpIni();
        $checks[] = $this->listeningPorts();
        // 0.7.4: distribution id and version for end-of-life matching.
        $checks[] = $this->osRelease();
        // 0.4.0: OPcache state and CPU load per core.
        $checks[] = $this->opcache();
        $checks[] = $this->loadAverage();

        return $checks;
    }

    /**
     * 0.7.0: maintenance mode read from the marker file, so it needs no
     * bootstrap and works outside Laravel too (until 0.6.1 this was the
     * Level 2 `isDownForMaintenance()` bool). Laravel writes
     * storage/framework/down (JSON) on `artisan down`: only the start time
     * and WHETHER a bypass secret is set leave the server — never the secret,
     * never another field. Elsewhere WordPress core drops `.maintenance` in
     * the web root while it updates and ignores it after 10 minutes: a fresh
     * file counts as active, an older one is reported as stale (not active).
     * File contents are never transmitted.
     *
     * @return array<string, mixed>
     */
    public function maintenanceMode(string $root): array
    {
        $down = $root.'/storage/framework/down';

        if (is_file($down)) {
            $payload = json_decode((string) @file_get_contents($down, false, null, 0, 65536), true);
            $since = is_array($payload) && isset($payload['time']) && is_numeric($payload['time'])
                ? (int) $payload['time']
                : (int) @filemtime($down);
            $hasSecret = is_array($payload) && isset($payload['secret']) && is_string($payload['secret']) && $payload['secret'] !== '';

            return $this->maintenanceActive('laravel', $since, $hasSecret);
        }

        $marker = $root.'/.maintenance';

        if (is_file($marker)) {
            $mtime = (int) @filemtime($marker);

            if ($mtime > 0 && time() - $mtime < self::WORDPRESS_MAINTENANCE_SECONDS) {
                return $this->maintenanceActive('generic', $mtime, null);
            }

            return ['id' => 'maintenance_mode', 'status' => 'ok', 'value' => false, 'detail' => ['active' => false, 'stale_file' => true]];
        }

        return ['id' => 'maintenance_mode', 'status' => 'ok', 'value' => false, 'detail' => ['active' => false]];
    }

    /**
     * @return array<string, mixed>
     */
    private function maintenanceActive(string $framework, int $since, ?bool $hasSecret): array
    {
        $detail = [
            'active' => true,
            'since_seconds' => max(0, time() - $since),
            'framework' => $framework,
        ];

        if ($hasSecret !== null) {
            $detail['has_secret'] = $hasSecret;
        }

        return ['id' => 'maintenance_mode', 'status' => 'warn', 'value' => true, 'detail' => $detail];
    }

    /**
     * OPcache off means every request recompiles every file. Only the
     * enabled flag and two counters leave the server; the status API may
     * be restricted (opcache.restrict_api), which just drops the counters.
     *
     * @return array<string, mixed>
     */
    public function opcache(): array
    {
        $loaded = extension_loaded('Zend OPcache');
        $enabled = $loaded && $this->iniFlag(PHP_SAPI === 'cli' ? 'opcache.enable_cli' : 'opcache.enable');
        $detail = ['loaded' => $loaded, 'enabled' => $enabled];

        if ($enabled && function_exists('opcache_get_status')) {
            $status = @opcache_get_status(false);

            if (is_array($status)) {
                $hits = (int) ($status['opcache_statistics']['hits'] ?? 0);
                $misses = (int) ($status['opcache_statistics']['misses'] ?? 0);
                $detail['hit_rate'] = $hits + $misses > 0 ? (int) round($hits / ($hits + $misses) * 100) : null;
                $detail['cached_scripts'] = (int) ($status['opcache_statistics']['num_cached_scripts'] ?? 0);
                $detail['memory_used_mb'] = (int) round(((int) ($status['memory_usage']['used_memory'] ?? 0)) / 1048576);
            }
        }

        return ['id' => 'opcache', 'status' => $enabled ? 'ok' : 'warn', 'value' => $enabled, 'detail' => $detail];
    }

    /**
     * 5-minute load average per CPU core from /proc (Linux only): above 2
     * the box is saturated, above 4 requests queue up. Numbers only.
     *
     * @return array<string, mixed>
     */
    public function loadAverage(): array
    {
        if (! @is_readable('/proc/loadavg')) {
            return ['id' => 'load', 'status' => 'unknown', 'message' => 'msg.unsupported_os'];
        }

        $parts = preg_split('/\s+/', trim((string) @file_get_contents('/proc/loadavg')));

        if (! is_array($parts) || count($parts) < 3) {
            return ['id' => 'load', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }

        $cpus = 0;

        if (@is_readable('/proc/cpuinfo')) {
            $cpus = (int) preg_match_all('/^processor\s*:/m', (string) @file_get_contents('/proc/cpuinfo'));
        }

        $cpus = max(1, $cpus);
        $perCore = round((float) $parts[1] / $cpus, 2);

        return [
            'id' => 'load',
            'status' => $perCore > 4 ? 'fail' : ($perCore > 2 ? 'warn' : 'ok'),
            'value' => $perCore,
            'detail' => [
                'load_1' => round((float) $parts[0], 2),
                'load_5' => round((float) $parts[1], 2),
                'load_15' => round((float) $parts[2], 2),
                'cpus' => $cpus,
            ],
        ];
    }

    /**
     * php.ini hygiene as seen by the web SAPI: flags and limits only, never
     * paths. display_errors / allow_url_include on → fail; expose_php on →
     * warn. `detail` carries the individual flags for the panel.
     *
     * @return array<string, mixed>
     */
    public function phpIni(): array
    {
        $displayErrors = $this->iniFlag('display_errors');
        $exposePhp = $this->iniFlag('expose_php');
        $allowUrlInclude = $this->iniFlag('allow_url_include');
        $allowUrlFopen = $this->iniFlag('allow_url_fopen');
        $disableFunctions = self::ini('disable_functions');
        $openBasedir = self::ini('open_basedir');

        $risky = 0;
        $status = 'ok';

        if ($displayErrors || $allowUrlInclude) {
            $status = 'fail';
            $risky += ($displayErrors ? 1 : 0) + ($allowUrlInclude ? 1 : 0);
        }

        if ($exposePhp) {
            $risky++;

            if ($status === 'ok') {
                $status = 'warn';
            }
        }

        return [
            'id' => 'php_ini',
            'status' => $status,
            'value' => $risky,
            'detail' => [
                'display_errors' => $displayErrors,
                'expose_php' => $exposePhp,
                'allow_url_include' => $allowUrlInclude,
                'allow_url_fopen' => $allowUrlFopen,
                'disable_functions' => $disableFunctions === '' ? 0 : count(array_filter(array_map('trim', explode(',', $disableFunctions)))),
                'open_basedir' => $openBasedir !== '',
                'memory_limit' => self::ini('memory_limit'),
                'upload_max_filesize' => self::ini('upload_max_filesize'),
                'post_max_size' => self::ini('post_max_size'),
                'max_execution_time' => self::ini('max_execution_time'),
            ],
        ];
    }

    /**
     * Total size of storage/logs/*.log in MB — a log that grows into the
     * gigabytes fills the disk long before the disk check trips.
     *
     * @return array<string, mixed>
     */
    public function logSize(string $root): array
    {
        $directory = $root.'/storage/logs';

        if (! is_dir($directory)) {
            return ['id' => 'log_size', 'status' => 'unknown', 'message' => 'msg.path_missing'];
        }

        $entries = self::glob($directory.'/*.log');
        $bytes = 0;
        $files = 0;

        foreach (is_array($entries) ? $entries : [] as $entry) {
            $size = @filesize($entry);

            if ($size !== false) {
                $bytes += $size;
                $files++;
            }
        }

        $megabytes = (int) round($bytes / 1048576);
        $status = 'ok';

        if ($megabytes >= 1024) {
            $status = 'fail';
        } elseif ($megabytes >= 100) {
            $status = 'warn';
        }

        return ['id' => 'log_size', 'status' => $status, 'value' => $megabytes, 'unit' => 'MB', 'detail' => ['files' => $files]];
    }

    /**
     * Data services listening on every interface (0.0.0.0 / ::), read from
     * /proc/net/tcp{,6} — the risk-free equivalent of an external port
     * scan. A firewall may still block them, hence warn, never fail.
     *
     * @return array<string, mixed>
     */
    public function listeningPorts(): array
    {
        $services = self::WATCHED_SERVICES;
        $tables = ['/proc/net/tcp', '/proc/net/tcp6'];
        $readable = false;
        $exposed = [];

        foreach ($tables as $table) {
            if (! @is_readable($table)) {
                continue;
            }

            $lines = @file($table, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

            if (! is_array($lines)) {
                continue;
            }

            $readable = true;
            array_shift($lines);

            foreach ($lines as $line) {
                $columns = preg_split('/\s+/', trim($line));

                if (! is_array($columns) || count($columns) < 4 || $columns[3] !== '0A') {
                    continue;
                }

                $local = explode(':', $columns[1]);

                if (count($local) !== 2) {
                    continue;
                }

                $address = $local[0];
                $port = hexdec($local[1]);
                $anyInterface = trim($address, '0') === '';

                if ($anyInterface && isset($services[$port]) && ! isset($exposed[$port])) {
                    $exposed[$port] = $services[$port].':'.$port;
                }
            }
        }

        if (! $readable) {
            return ['id' => 'listening_ports', 'status' => 'unknown', 'message' => 'msg.unsupported_os'];
        }

        ksort($exposed);

        return [
            'id' => 'listening_ports',
            'status' => $exposed === [] ? 'ok' : 'warn',
            'value' => count($exposed),
            'detail' => ['exposed' => implode(',', $exposed)],
        ];
    }

    /**
     * 0.7.4: where the project sits on the host. Four facts, no verdict (the
     * status is always ok): whether a folder on the project's path carries a
     * web-folder name, whether the web server's document root is the project
     * root itself, a 12-character keyed hash prefix of the account the
     * process runs as, and the hosting panel as one word. No path, no account name
     * and no host name leaves the server.
     *
     * @return array<string, mixed>
     */
    public function hostingLayout(string $root): array
    {
        $resolved = self::resolvedPath($root);
        $inWebFolder = self::pathHasWebFolder($root) || ($resolved !== null && self::pathHasWebFolder($resolved));
        $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) && is_string($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : null;

        return [
            'id' => 'hosting_layout',
            'status' => 'ok',
            'value' => $inWebFolder,
            'detail' => [
                'project_in_web_folder' => $inWebFolder,
                'docroot_is_project_root' => self::docrootIsProjectRoot($documentRoot, $root),
                'account_hash' => self::accountHash(self::processAccountName(), $this->hashKey),
                'panel' => self::hostingPanel(),
            ],
        ];
    }

    /**
     * True when one of the folders on the path — the last one included — is
     * named public_html or private_html (case-insensitive, whole name
     * only): the folders a web server's per-account address serves. Other
     * web-folder names (httpdocs, htdocs, www) are not reachable that way
     * and are not counted.
     */
    public static function pathHasWebFolder(string $path): bool
    {
        $segments = preg_split('#[/\\\\]+#', $path);

        foreach (is_array($segments) ? $segments : [] as $segment) {
            if (in_array(strtolower($segment), ['public_html', 'private_html'], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the web server's document root is the project root itself;
     * null when the document root is not known or either path cannot be
     * resolved (open_basedir). Both paths are compared after realpath().
     */
    public static function docrootIsProjectRoot(?string $documentRoot, string $root): ?bool
    {
        if ($documentRoot === null || trim($documentRoot) === '') {
            return null;
        }

        $resolvedDocumentRoot = self::resolvedPath($documentRoot);
        $resolvedRoot = self::resolvedPath($root);

        if ($resolvedDocumentRoot === null || $resolvedRoot === null) {
            return null;
        }

        // Windows file systems do not tell the case of a name apart.
        if (DIRECTORY_SEPARATOR === '\\') {
            return strcasecmp($resolvedDocumentRoot, $resolvedRoot) === 0;
        }

        return $resolvedDocumentRoot === $resolvedRoot;
    }

    /**
     * First 12 hex characters of the HMAC-SHA-256 of an account name, keyed
     * with the installation's project key, so the same name gives another
     * value on every installation; null when the name or the key is not
     * known. The name itself never leaves the server.
     */
    public static function accountHash(?string $name, string $key): ?string
    {
        if ($name === null || $name === '' || $key === '') {
            return null;
        }

        return substr(hash_hmac('sha256', $name, $key), 0, 12);
    }

    /**
     * The hosting panel, from the presence of its install folder — one word
     * of a fixed list. `$exists` answers "is this path a directory" (tests).
     */
    public static function hostingPanel(?callable $exists = null): string
    {
        $exists = $exists !== null ? $exists : static function (string $path): bool {
            return function_exists('is_dir') && @is_dir($path);
        };

        $panels = [
            'cpanel' => ['/usr/local/cpanel'],
            'plesk' => ['/usr/local/psa', '/opt/psa'],
            'directadmin' => ['/usr/local/directadmin'],
        ];

        foreach ($panels as $panel => $directories) {
            foreach ($directories as $directory) {
                try {
                    if ($exists($directory) === true) {
                        return $panel;
                    }
                } catch (\Throwable $exception) {
                    continue;
                }
            }
        }

        return 'unknown';
    }

    /**
     * Name of the account the process runs as: the effective user from
     * posix where the extension is there, else the owner of the running
     * script. Used locally for the hash only.
     */
    private static function processAccountName(): ?string
    {
        try {
            if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
                // Before PHP 8 a disabled function still exists and answers
                // null: without the check that would read as user id 0.
                $uid = @posix_geteuid();
                $entry = is_int($uid) ? @posix_getpwuid($uid) : null;

                if (is_array($entry) && isset($entry['name']) && is_string($entry['name']) && $entry['name'] !== '') {
                    return $entry['name'];
                }
            }

            if (function_exists('get_current_user')) {
                $name = @get_current_user();

                if (is_string($name) && $name !== '') {
                    return $name;
                }
            }
        } catch (\Throwable $exception) {
            return null;
        }

        return null;
    }

    private static function resolvedPath(string $path): ?string
    {
        if (! function_exists('realpath')) {
            return null;
        }

        $resolved = @realpath($path);

        return is_string($resolved) && $resolved !== '' ? $resolved : null;
    }

    /**
     * 0.7.4: the distribution's id and version from /etc/os-release, so the
     * panel can match the operating system against its end-of-life dates.
     * Only the ID and VERSION_ID values are taken; the host name, the kernel
     * and every other line stay on the server.
     *
     * @return array<string, mixed>
     */
    public function osRelease(string $path = '/etc/os-release'): array
    {
        if (! @is_readable($path) || ! @is_file($path)) {
            return [
                'id' => 'os_release',
                'status' => 'unknown',
                'message' => PHP_OS_FAMILY === 'Linux' ? 'msg.not_readable' : 'msg.unsupported_os',
            ];
        }

        $parsed = self::parseOsRelease((string) @file_get_contents($path, false, null, 0, 65536));

        if ($parsed === null) {
            return ['id' => 'os_release', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }

        return [
            'id' => 'os_release',
            'status' => 'ok',
            'value' => $parsed['version_id'] !== null ? $parsed['id'].' '.$parsed['version_id'] : $parsed['id'],
            'detail' => $parsed,
        ];
    }

    /**
     * ID and VERSION_ID of an os-release file; every other key is ignored.
     * A value outside the expected alphabet is dropped whole, never trimmed
     * into shape: null without a usable ID, `version_id` null without a
     * usable VERSION_ID (rolling distributions have none).
     *
     * @return array{id: string, version_id: ?string}|null
     */
    public static function parseOsRelease(string $content): ?array
    {
        $values = ['ID' => null, 'VERSION_ID' => null];

        foreach (preg_split('/\r\n|\r|\n/', $content) ?: [] as $line) {
            if (preg_match('/^\s*(ID|VERSION_ID)=(.*)$/', $line, $match) !== 1 || $values[$match[1]] !== null) {
                continue;
            }

            $values[$match[1]] = strtolower(trim(trim($match[2]), '"\''));
        }

        if ($values['ID'] === null || preg_match('/^[a-z0-9._-]{1,32}$/', $values['ID']) !== 1) {
            return null;
        }

        $versionId = $values['VERSION_ID'] !== null && preg_match('/^[0-9a-z._-]{1,16}$/', $values['VERSION_ID']) === 1
            ? $values['VERSION_ID']
            : null;

        return ['id' => $values['ID'], 'version_id' => $versionId];
    }

    private function iniFlag(string $name): bool
    {
        $value = strtolower(trim(self::ini($name)));

        return in_array($value, ['1', 'on', 'true', 'yes', 'stdout', 'stderr'], true);
    }

    /**
     * 0.5.1 (audit 25.09): ini_get and glob may sit in disable_functions on
     * strict hosts — a disabled function throws an Error on PHP 8, which the
     * `@` operator does not swallow. Both are wrapped so the check answers
     * "unknown" instead of taking the whole pull down.
     */
    public static function ini(string $name): string
    {
        if (! function_exists('ini_get')) {
            return '';
        }

        $value = @ini_get($name);

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * @return array<int, string>
     */
    public static function glob(string $pattern, int $flags = 0): array
    {
        if (! function_exists('glob')) {
            return [];
        }

        $matches = @glob($pattern, $flags);

        return is_array($matches) ? $matches : [];
    }

    /**
     * CLI PHP version as reported by the scheduler heartbeat file, if any.
     */
    public function cliPhpVersion(?string $root): ?string
    {
        if ($root === null) {
            return null;
        }

        $payload = $this->readHeartbeat($root.'/storage/app/sitetus-heartbeat.json');

        // A heartbeat file the site's own code wrote may hold anything; only a
        // scalar becomes a version string (0.5.1: an array raised a warning).
        return is_array($payload) && isset($payload['php']) && is_scalar($payload['php']) ? (string) $payload['php'] : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function diskUsage(?string $root): array
    {
        $target = $root !== null ? $root : __DIR__;

        if (! function_exists('disk_free_space') || ! function_exists('disk_total_space')) {
            return ['id' => 'disk_usage', 'status' => 'unknown', 'message' => 'msg.function_disabled'];
        }

        $free = @disk_free_space($target);
        $total = @disk_total_space($target);

        if ($free === false || $total === false || $total <= 0) {
            return ['id' => 'disk_usage', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }

        $usedPercent = (int) round((1 - $free / $total) * 100);

        $status = 'ok';

        if ($usedPercent >= 90) {
            $status = 'fail';
        } elseif ($usedPercent >= 80) {
            $status = 'warn';
        }

        return ['id' => 'disk_usage', 'status' => $status, 'value' => $usedPercent, 'unit' => '%'];
    }

    /**
     * @return array<string, mixed>
     */
    private function writable(string $id, string $path): array
    {
        if (! is_dir($path)) {
            return ['id' => $id, 'status' => 'unknown', 'message' => 'msg.path_missing'];
        }

        return ['id' => $id, 'status' => is_writable($path) ? 'ok' : 'fail'];
    }

    /**
     * @return array<string, mixed>
     */
    private function fileExists(string $id, string $path): array
    {
        return ['id' => $id, 'status' => is_file($path) ? 'ok' : 'warn'];
    }

    /**
     * @return array<string, mixed>
     */
    private function routesCached(string $root): array
    {
        $matches = self::glob($root.'/bootstrap/cache/routes-*.php');

        return ['id' => 'routes_cached', 'status' => $matches !== [] ? 'ok' : 'warn'];
    }

    /**
     * @return array<string, mixed>
     */
    private function envFilePermissions(string $root): array
    {
        $path = $root.'/.env';

        if (! is_file($path)) {
            return ['id' => 'env_file_permissions', 'status' => 'unknown', 'message' => 'msg.path_missing'];
        }

        $perms = @fileperms($path);

        if ($perms === false) {
            return ['id' => 'env_file_permissions', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }

        $octal = sprintf('%04o', $perms & 0777);
        $worldReadable = (bool) ($perms & 0004);

        return [
            'id' => 'env_file_permissions',
            'status' => $worldReadable ? 'warn' : 'ok',
            'value' => $octal,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function backupRecency(string $root): array
    {
        $directories = [
            $root.'/storage/app/backups',
            $root.'/storage/app/backup',
            $root.'/backups',
        ];

        $newest = null;

        foreach ($directories as $directory) {
            if (! is_dir($directory)) {
                continue;
            }

            $entries = self::glob($directory.'/*');

            foreach ($entries as $entry) {
                $mtime = @filemtime($entry);

                if ($mtime !== false && ($newest === null || $mtime > $newest)) {
                    $newest = $mtime;
                }
            }
        }

        if ($newest === null) {
            return ['id' => 'backup_recency', 'status' => 'unknown', 'message' => 'msg.no_backup_found'];
        }

        $ageDays = (int) floor((time() - $newest) / 86400);

        $status = 'ok';

        if ($ageDays > 7) {
            $status = 'fail';
        } elseif ($ageDays > 2) {
            $status = 'warn';
        }

        return ['id' => 'backup_recency', 'status' => $status, 'value' => $ageDays, 'unit' => 'days'];
    }

    /**
     * @return array<string, mixed>
     */
    private function heartbeat(string $id, string $path)
    {
        $payload = $this->readHeartbeat($path);

        if (! is_array($payload) || ! isset($payload['ts'])) {
            return ['id' => $id, 'status' => 'unknown', 'message' => 'msg.heartbeat_missing'];
        }

        $ageMinutes = (int) floor((time() - (int) $payload['ts']) / 60);

        $status = 'ok';

        if ($ageMinutes > 60) {
            $status = 'fail';
        } elseif ($ageMinutes > 10) {
            $status = 'warn';
        }

        return ['id' => $id, 'status' => $status, 'value' => $ageMinutes, 'unit' => 'minutes'];
    }

    /**
     * @return array<string, mixed>|null
     */
    private function readHeartbeat(string $path)
    {
        if (! is_file($path)) {
            return null;
        }

        // The heartbeat is a few hundred bytes; never read more than 64 KB of
        // whatever the site put there (0.5.1).
        $decoded = json_decode((string) @file_get_contents($path, false, null, 0, 65536), true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Origin certificate expiry: only when a certificate file is
     * readable from this account — on most shared hosts it is not, which is
     * an honest "unknown".
     *
     * @return array<string, mixed>
     */
    private function originTlsExpiry(): array
    {
        if (! function_exists('openssl_x509_parse')) {
            return ['id' => 'origin_tls_expiry', 'status' => 'unknown', 'message' => 'msg.function_disabled'];
        }

        $host = isset($_SERVER['SERVER_NAME']) ? preg_replace('/[^a-z0-9.-]/i', '', (string) $_SERVER['SERVER_NAME']) : null;

        $candidates = [];

        if ($host !== null && $host !== '') {
            $candidates[] = '/etc/letsencrypt/live/'.$host.'/cert.pem';
            $candidates[] = '/etc/letsencrypt/live/'.$host.'/fullchain.pem';
        }

        foreach ($candidates as $candidate) {
            if (! @is_readable($candidate)) {
                continue;
            }

            $parsed = @openssl_x509_parse((string) @file_get_contents($candidate));

            if (is_array($parsed) && isset($parsed['validTo_time_t'])) {
                $daysLeft = (int) floor(((int) $parsed['validTo_time_t'] - time()) / 86400);

                $status = 'ok';

                if ($daysLeft <= 3) {
                    $status = 'fail';
                } elseif ($daysLeft <= 14) {
                    $status = 'warn';
                }

                return ['id' => 'origin_tls_expiry', 'status' => $status, 'value' => $daysLeft, 'unit' => 'days'];
            }
        }

        return ['id' => 'origin_tls_expiry', 'status' => 'unknown', 'message' => 'msg.not_readable'];
    }
}
