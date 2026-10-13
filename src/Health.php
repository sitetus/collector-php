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
        }

        $checks[] = $this->originTlsExpiry();
        // 0.3.0: php.ini hygiene and locally listening services.
        $checks[] = $this->phpIni();
        $checks[] = $this->listeningPorts();
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
        $services = [
            6379 => 'redis',
            3306 => 'mysql',
            5432 => 'postgres',
            11211 => 'memcached',
            27017 => 'mongodb',
            9200 => 'elasticsearch',
        ];
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
