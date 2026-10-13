<?php

namespace Sitetus\Collector;

/**
 * Envelope assembly. Section absence is never an error; the panel
 * shows "no data". Extensions are reported from an allowlist only.
 */
final class Envelope
{
    /** @var array<int, string> */
    private const EXTENSION_ALLOWLIST = [
        'curl', 'openssl', 'sodium', 'mbstring', 'intl', 'pdo_mysql', 'pdo_pgsql',
        'pdo_sqlite', 'redis', 'gd', 'imagick', 'zip', 'bcmath', 'opcache', 'xdebug',
    ];

    /** @var Config */
    private $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * @param array<string, mixed> $framework
     * @param array<string, mixed>|null $packages
     * @param array<int, array<string, mixed>> $healthChecks
     * @param array<int, string> $warnings
     * @return array<string, mixed>
     */
    /**
     * @param array<int, array<string, mixed>> $customChecks Composer wrapper only
     * @param array<string, mixed>|null $modules opt-in module results
     */
    public function build(
        int $level,
        array $framework,
        ?array $packages,
        array $healthChecks,
        ?string $cliPhpVersion,
        string $rootPathSource,
        array $warnings,
        float $startedAt,
        string $selfPath,
        array $customChecks = [],
        ?array $modules = null,
        ?array $runtimeIni = null
    ): array {
        $envelope = [
            'schema_version' => Config::SCHEMA_VERSION,
            'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'collector' => [
                'name' => $this->config->collectorName,
                'version' => Config::VERSION,
                'lang' => 'php',
                'file_hash' => (string) hash_file('sha256', $selfPath),
            ],
            'project_key' => $this->config->projectKey,
            'mode' => 'monitor',
            'level' => $level,
            'runtime' => $this->runtime($cliPhpVersion, $runtimeIni),
            'framework' => $framework,
            'meta' => [
                'warnings' => array_values($warnings),
                'duration_ms' => (int) round((microtime(true) - $startedAt) * 1000),
                'root_path_source' => $rootPathSource,
            ],
        ];

        if ($packages !== null) {
            $envelope['packages'] = $packages;
        }

        if ($healthChecks !== []) {
            $envelope['health'] = ['checks' => array_values($healthChecks)];
        }

        if ($customChecks !== []) {
            $envelope['custom_checks'] = array_values($customChecks);
        }

        if ($modules !== null) {
            $envelope['modules'] = $modules;
        }

        return $envelope;
    }

    /**
     * The ini flags the envelope reports, read as the request arrived —
     * before the diagnostics guard and Level 2 change display_errors
     * (0.5.1, audit 25.09).
     *
     * @return array<string, bool>
     */
    public static function runtimeIniSnapshot(): array
    {
        return [
            'expose_php' => self::iniBool('expose_php'),
            'display_errors' => self::iniBool('display_errors'),
        ];
    }

    /**
     * @param array<string, bool>|null $runtimeIni
     * @return array<string, mixed>
     */
    private function runtime(?string $cliPhpVersion, ?array $runtimeIni = null): array
    {
        $ini = $runtimeIni !== null ? $runtimeIni : self::runtimeIniSnapshot();
        $extensions = [];

        foreach (self::EXTENSION_ALLOWLIST as $extension) {
            if (extension_loaded($extension)) {
                $version = phpversion($extension);
                $extensions[] = [
                    'name' => $extension,
                    'version' => is_string($version) && $version !== '' ? $version : null,
                ];
            }
        }

        $runtime = [
            'php_version' => PHP_VERSION,
            'sapi' => PHP_SAPI,
            'os' => PHP_OS_FAMILY,
            'extensions' => $extensions,
            'ini' => [
                'expose_php' => (bool) ($ini['expose_php'] ?? false),
                'display_errors' => (bool) ($ini['display_errors'] ?? false),
                'opcache_enabled' => function_exists('opcache_get_status') && extension_loaded('Zend OPcache'),
                'xdebug_loaded' => extension_loaded('xdebug'),
            ],
        ];

        if ($cliPhpVersion !== null) {
            $runtime['cli_php_version'] = $cliPhpVersion;
        }

        return $runtime;
    }

    private static function iniBool(string $key): bool
    {
        // ini_get may be in disable_functions on strict hosts (0.5.1).
        $value = function_exists('ini_get') ? @ini_get($key) : false;

        return $value === '1' || strtolower((string) $value) === 'on';
    }
}
