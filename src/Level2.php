<?php

namespace Sitetus\Collector;

/**
 * Level 2: Laravel bootstrap AFTER signature verification only.
 * Guarded with try/catch, output buffering, display_errors off and a time
 * limit; no memory_limit raise. Reads ONLY the flag allowlist via config()
 * — no other key is ever read. 0.6.0 adds the `filesystems.links` paths,
 * which are inspected on disk and never transmitted (two flags travel).
 */
final class Level2
{
    /**
     * @return array{checks: array<int, array<string, mixed>>, warnings: array<int, string>}
     */
    public function run(string $root): array
    {
        $checks = [];
        $warnings = [];

        $displayErrors = Health::ini('display_errors');
        $errorReporting = error_reporting();

        @ini_set('display_errors', '0');

        if (function_exists('set_time_limit')) {
            @set_time_limit(20);
        }

        ob_start();

        try {
            require $root.'/vendor/autoload.php';

            $app = require $root.'/bootstrap/app.php';

            $kernel = $app->make(\Illuminate\Contracts\Console\Kernel::class);
            $kernel->bootstrap();

            $checks = $this->checksFromApp($app);
        } catch (\Throwable $exception) {
            $checks[] = ['id' => 'app_bootstrap', 'status' => 'fail'];
            $warnings[] = 'msg.bootstrap_failed';
        } finally {
            ob_end_clean();

            // 0.5.1 (audit 25.09): the customer's bootstrap installs its own
            // error and exception handlers (and raises error_reporting). They
            // must not outlive Level 2 — a later failure would otherwise render
            // the site's debug page instead of the envelope. Ours swallow
            // notices and answer a bodiless 500 to anything uncaught.
            set_error_handler(static function (): bool {
                return true;
            });
            set_exception_handler(static function (): void {
                if (PHP_SAPI !== 'cli' && ! headers_sent()) {
                    http_response_code(500);
                }
            });
            error_reporting($errorReporting);
            @ini_set('display_errors', $displayErrors);
        }

        return ['checks' => $checks, 'warnings' => $warnings];
    }

    /**
     * Shared with the Composer wrapper (envelopes are byte-identical):
     * given an already-booted container, produce the exact same check list
     * the single file produces after its guarded bootstrap.
     *
     * @param mixed $app any container exposing make()
     * @return array<int, array<string, mixed>>
     */
    public function checksFromApp($app): array
    {
        $checks = [['id' => 'app_bootstrap', 'status' => 'ok']];

        $checks = array_merge($checks, $this->databaseChecks($app));
        $checks = array_merge($checks, $this->flagChecks($app));
        $checks[] = $this->debugToolsCheck($app);
        $checks[] = $this->mailDriverCheck($app);
        // 0.4.0: operational posture — driver NAMES and counts only.
        $checks[] = $this->cacheStoreCheck($app);
        $checks[] = $this->queueDepthCheck($app);
        $checks[] = $this->pendingMigrationsCheck($app);
        // 0.7.0: maintenance_mode moved to Level 1 (Health::maintenanceMode).
        // 0.6.0: storage link flags and the session driver NAME.
        $checks[] = $this->storageLinkCheck($app);
        $checks[] = $this->sessionDriverCheck($app);
        $checks = array_merge($checks, $this->serviceVersionChecks($app));

        return $checks;
    }

    /**
     * 0.6.0: the links `filesystems.links` declares (default public/storage →
     * storage/app/public) must exist AND be links; a plain directory in the
     * link's place means uploads are invisible or stale. Two flags travel
     * (present, is_link), never a path. Warns only when the public disk is
     * configured; nothing declared = ok; an uninspectable parent = unknown.
     *
     * @param mixed $app
     * @return array<string, mixed>
     */
    private function storageLinkCheck($app): array
    {
        try {
            $config = $app->make('config');
            $links = $config->get('filesystems.links', []);

            if (! is_array($links) || $links === []) {
                return ['id' => 'storage_link', 'status' => 'ok', 'value' => true];
            }

            $present = true;
            $isLink = true;

            foreach ($links as $link => $target) {
                $link = (string) $link;

                if (! is_dir(dirname($link))) {
                    return ['id' => 'storage_link', 'status' => 'unknown', 'message' => 'msg.not_readable'];
                }

                $exists = file_exists($link);
                $present = $present && $exists;
                $isLink = $isLink && $exists && $this->isLinkTo($link, (string) $target);
            }

            $publicDisk = is_array($config->get('filesystems.disks.public'));
            $healthy = $present && $isLink;

            return [
                'id' => 'storage_link',
                'status' => $healthy || ! $publicDisk ? 'ok' : 'warn',
                'value' => $healthy,
                'detail' => ['present' => $present, 'is_link' => $isLink],
            ];
        } catch (\Throwable $exception) {
            return ['id' => 'storage_link', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }
    }

    /**
     * A symlink, or a path (Windows junction) that resolves to the very same
     * directory as the target; a plain directory resolves to itself.
     */
    private function isLinkTo(string $link, string $target): bool
    {
        if (is_link($link)) {
            return true;
        }

        $resolvedLink = realpath($link);
        $resolvedTarget = realpath($target);

        return $resolvedLink !== false && $resolvedTarget !== false && $resolvedLink === $resolvedTarget;
    }

    /**
     * 0.6.0: session.driver NAME — file (not shared between web nodes),
     * array (nobody stays logged in) or cookie (session data travels in
     * the cookie) in production → warn. Same shape as cache_store.
     *
     * @param mixed $app
     * @return array<string, mixed>
     */
    private function sessionDriverCheck($app): array
    {
        try {
            $config = $app->make('config');
            $driver = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $config->get('session.driver', '')));
            $production = (string) $config->get('app.env') === 'production';
            $weak = in_array($driver, ['file', 'array', 'cookie'], true);

            return ['id' => 'session_driver', 'status' => $production && $weak ? 'warn' : 'ok', 'value' => $driver !== '' ? $driver : 'unknown'];
        } catch (\Throwable $exception) {
            return ['id' => 'session_driver', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }
    }

    /**
     * 0.4.0: cache.default driver NAME — array (nothing survives the
     * request) or file (slow, no sharing) in production → warn.
     *
     * @param mixed $app
     * @return array<string, mixed>
     */
    private function cacheStoreCheck($app): array
    {
        try {
            $driver = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $app->make('config')->get('cache.default', '')));
            $weak = in_array($driver, ['array', 'file', 'null'], true);

            return ['id' => 'cache_store', 'status' => $weak ? 'warn' : 'ok', 'value' => $driver !== '' ? $driver : 'unknown'];
        } catch (\Throwable $exception) {
            return ['id' => 'cache_store', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }
    }

    /**
     * 0.4.0: queue.default driver name, the number of waiting jobs and the
     * age of the oldest one (database and redis drivers; sync = no queue).
     *
     * @param mixed $app
     * @return array<string, mixed>
     */
    private function queueDepthCheck($app): array
    {
        try {
            $config = $app->make('config');
            $connection = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $config->get('queue.default', '')));
            $driver = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $config->get('queue.connections.'.$connection.'.driver', $connection)));
            $detail = ['driver' => $driver !== '' ? $driver : 'unknown'];

            if ($driver === 'sync' || $driver === 'null') {
                return ['id' => 'queue_depth', 'status' => 'warn', 'value' => 0, 'detail' => $detail];
            }

            if ($driver === 'database') {
                $table = preg_replace('/[^a-z0-9_]/', '', (string) $config->get('queue.connections.'.$connection.'.table', 'jobs'));
                $db = $app->make('db')->connection();
                $count = (int) $db->table($table)->count();
                $oldest = $db->table($table)->min('available_at');
                $detail['oldest_minutes'] = $oldest === null ? 0 : (int) max(0, floor((time() - (int) $oldest) / 60));
            } else {
                $count = (int) $app->make('queue')->connection($connection)->size();
                $detail['oldest_minutes'] = null;
            }

            $status = ($count > 1000 || ($detail['oldest_minutes'] ?? 0) > 30) ? 'warn' : 'ok';

            return ['id' => 'queue_depth', 'status' => $status, 'value' => $count, 'detail' => $detail];
        } catch (\Throwable $exception) {
            return ['id' => 'queue_depth', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }
    }

    /**
     * 0.4.0: migration files that have not run — a deploy that forgot
     * `migrate` is a broken site waiting to happen. Count only.
     *
     * @param mixed $app
     * @return array<string, mixed>
     */
    private function pendingMigrationsCheck($app): array
    {
        try {
            $migrator = $app->make('migrator');
            $repository = $migrator->getRepository();

            if (! $repository->repositoryExists()) {
                return ['id' => 'pending_migrations', 'status' => 'unknown', 'message' => 'msg.path_missing'];
            }

            $ran = $repository->getRan();
            $paths = array_merge($migrator->paths(), [$app->databasePath('migrations')]);
            $files = $migrator->getMigrationFiles(array_values(array_unique($paths)));
            $pending = 0;

            foreach (array_keys($files) as $name) {
                if (! in_array($name, $ran, true)) {
                    $pending++;
                }
            }

            return ['id' => 'pending_migrations', 'status' => $pending > 0 ? 'warn' : 'ok', 'value' => $pending, 'detail' => ['ran' => count($ran)]];
        } catch (\Throwable $exception) {
            return ['id' => 'pending_migrations', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }
    }

    /**
     * 0.4.0: versions of data services the app is configured for (Redis
     * today), so the panel's EOL matching covers them. Version string only;
     * emitted only when the service is actually in use.
     *
     * @param mixed $app
     * @return array<int, array<string, mixed>>
     */
    private function serviceVersionChecks($app): array
    {
        $checks = [];

        try {
            $config = $app->make('config');
            $usesRedis = in_array('redis', [
                (string) $config->get('cache.stores.'.$config->get('cache.default').'.driver', ''),
                (string) $config->get('queue.connections.'.$config->get('queue.default').'.driver', ''),
                (string) $config->get('session.driver', ''),
            ], true);

            if ($usesRedis) {
                $info = $app->make('redis')->connection()->info('server');
                $version = is_array($info) ? (string) ($info['redis_version'] ?? ($info['Server']['redis_version'] ?? '')) : '';
                $version = preg_replace('/[^0-9A-Za-z.\-]/', '', $version);

                $checks[] = $version !== ''
                    ? ['id' => 'redis_version', 'status' => 'ok', 'value' => $version]
                    : ['id' => 'redis_version', 'status' => 'unknown', 'message' => 'msg.not_readable'];
            }
        } catch (\Throwable $exception) {
            $checks[] = ['id' => 'redis_version', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }

        return $checks;
    }

    /**
     * 0.3.0: MAIL_MAILER=log|array in production means no mail
     * ever leaves the site — order confirmations silently vanish. Only the
     * driver NAME (config mail.default) is read; no credentials.
     *
     * @param mixed $app
     * @return array<string, mixed>
     */
    private function mailDriverCheck($app): array
    {
        try {
            $driver = strtolower((string) $app->make('config')->get('mail.default', ''));
            $driver = preg_replace('/[^a-z0-9_\-]/', '', $driver);
            $silent = in_array($driver, ['log', 'array', 'failover-log'], true);

            return ['id' => 'mail_driver', 'status' => $silent ? 'fail' : 'ok', 'value' => $driver !== '' ? $driver : 'unknown'];
        } catch (\Throwable $exception) {
            return ['id' => 'mail_driver', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }
    }

    /**
     * @param mixed $app
     * @return array<int, array<string, mixed>>
     */
    private function databaseChecks($app): array
    {
        $checks = [];

        try {
            $db = $app->make('db');
            $connection = $db->connection();

            $startedAt = microtime(true);
            $connection->select('select 1');
            $latencyMs = (int) round((microtime(true) - $startedAt) * 1000);

            $checks[] = ['id' => 'db_connectivity', 'status' => 'ok', 'value' => $latencyMs, 'unit' => 'ms'];

            try {
                $version = (string) $connection->getPdo()->getAttribute(\PDO::ATTR_SERVER_VERSION);
                $checks[] = ['id' => 'db_server_version', 'status' => 'ok', 'value' => $version];
            } catch (\Throwable $exception) {
                $checks[] = ['id' => 'db_server_version', 'status' => 'unknown', 'message' => 'msg.not_readable'];
            }

            try {
                $schema = $connection->getSchemaBuilder();

                if ($schema->hasTable('failed_jobs')) {
                    $count = (int) $connection->table('failed_jobs')->count();
                    $checks[] = ['id' => 'failed_jobs', 'status' => $count > 0 ? 'warn' : 'ok', 'value' => $count];
                } else {
                    $checks[] = ['id' => 'failed_jobs', 'status' => 'unknown', 'message' => 'msg.path_missing'];
                }
            } catch (\Throwable $exception) {
                $checks[] = ['id' => 'failed_jobs', 'status' => 'unknown', 'message' => 'msg.not_readable'];
            }
        } catch (\Throwable $exception) {
            $checks[] = ['id' => 'db_connectivity', 'status' => 'fail'];
        }

        return $checks;
    }

    /**
     * Flag allowlist — no other config key is read, ever.
     *
     * @param mixed $app
     * @return array<int, array<string, mixed>>
     */
    private function flagChecks($app): array
    {
        $checks = [];

        try {
            $config = $app->make('config');

            $appDebug = (bool) $config->get('app.debug');
            $appEnv = (string) $config->get('app.env');
            $appUrl = (string) $config->get('app.url');
            $appKey = (string) $config->get('app.key');

            $checks[] = ['id' => 'flag_app_debug', 'status' => $appDebug ? 'fail' : 'ok', 'value' => $appDebug];
            $checks[] = ['id' => 'flag_app_env', 'status' => $appEnv === 'production' ? 'ok' : 'warn', 'value' => $appEnv];
            $checks[] = [
                'id' => 'flag_app_url_https',
                'status' => strpos($appUrl, 'https://') === 0 ? 'ok' : 'warn',
                'value' => strpos($appUrl, 'https://') === 0,
            ];
            $checks[] = ['id' => 'flag_app_key_set', 'status' => $appKey !== '' ? 'ok' : 'fail', 'value' => $appKey !== ''];

            $sessionSecure = (bool) $config->get('session.secure');
            $sessionHttpOnly = (bool) $config->get('session.http_only');
            $sessionSameSite = (string) $config->get('session.same_site');

            $checks[] = ['id' => 'flag_session_secure', 'status' => $sessionSecure ? 'ok' : 'warn', 'value' => $sessionSecure];
            $checks[] = ['id' => 'flag_session_http_only', 'status' => $sessionHttpOnly ? 'ok' : 'warn', 'value' => $sessionHttpOnly];
            $checks[] = ['id' => 'flag_session_same_site', 'status' => $sessionSameSite !== '' ? 'ok' : 'warn', 'value' => $sessionSameSite];
        } catch (\Throwable $exception) {
            $checks[] = ['id' => 'flag_app_debug', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }

        return $checks;
    }

    /**
     * @param mixed $app
     * @return array<string, mixed>
     */
    private function debugToolsCheck($app): array
    {
        try {
            $config = $app->make('config');

            $telescopeEnabled = class_exists('Laravel\\Telescope\\Telescope')
                && (bool) $config->get('telescope.enabled', false);
            $debugbarEnabled = class_exists('Barryvdh\\Debugbar\\LaravelDebugbar')
                && (bool) $config->get('debugbar.enabled', false);

            $enabled = $telescopeEnabled || $debugbarEnabled;

            return ['id' => 'debug_tools_enabled', 'status' => $enabled ? 'fail' : 'ok', 'value' => $enabled];
        } catch (\Throwable $exception) {
            return ['id' => 'debug_tools_enabled', 'status' => 'unknown', 'message' => 'msg.not_readable'];
        }
    }
}
