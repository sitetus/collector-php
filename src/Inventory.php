<?php

namespace Sitetus\Collector;

/**
 * Level 1 project inventory: project root discovery, framework
 * detection by file signatures, composer package inventory from
 * composer.lock or vendor/composer/installed.json. Reads files only; never
 * includes or executes project code.
 */
final class Inventory
{
    /**
     * 0.5.1: composer.lock / installed.json are read with a cap — a lock of
     * many megabytes is not a package list any more.
     */
    public const MAX_LOCK_BYTES = 8 * 1024 * 1024;

    /** @var Config */
    private $config;

    /** @var string|null */
    private $rootPathSource;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    public function rootPath(): ?string
    {
        if ($this->config->rootOverride !== null) {
            $this->rootPathSource = 'override';

            return rtrim($this->config->rootOverride, '/\\');
        }

        // Default layout: public/<random>/index.php → two levels up.
        $default = dirname($this->config->installDir, 2);

        if ($this->looksLikeProjectRoot($default)) {
            $this->rootPathSource = 'default';

            return $default;
        }

        $candidate = $this->config->installDir;

        for ($level = 1; $level <= 3; $level++) {
            $candidate = dirname($candidate);

            if ($this->looksLikeProjectRoot($candidate)) {
                $this->rootPathSource = 'discovered';

                return $candidate;
            }
        }

        $this->rootPathSource = 'default';

        return null;
    }

    public function rootPathSource(): string
    {
        return $this->rootPathSource !== null ? $this->rootPathSource : 'default';
    }

    /**
     * @return array{detected: string, name: ?string, version: ?string, detection_method: ?string}
     */
    public function detectFramework(?string $root): array
    {
        if ($root === null) {
            return ['detected' => 'unknown', 'name' => null, 'version' => null, 'detection_method' => null];
        }

        if (is_file($root.'/artisan') && is_file($root.'/bootstrap/app.php')) {
            return [
                'detected' => 'laravel',
                'name' => 'Laravel',
                'version' => $this->packageVersionFromLock($root, 'laravel/framework'),
                'detection_method' => 'artisan_file',
            ];
        }

        if (is_file($root.'/wp-config.php') || is_file($root.'/wp-includes/version.php')) {
            return [
                'detected' => 'wordpress',
                'name' => 'WordPress',
                'version' => $this->wordPressVersion($root),
                'detection_method' => 'wp_config_file',
            ];
        }

        if (is_file($root.'/spark') && is_dir($root.'/app/Config')) {
            return [
                'detected' => 'codeigniter',
                'name' => 'CodeIgniter',
                'version' => $this->packageVersionFromLock($root, 'codeigniter4/framework'),
                'detection_method' => 'spark_file',
            ];
        }

        if (is_file($root.'/bin/console') && is_file($root.'/symfony.lock')) {
            return [
                'detected' => 'symfony',
                'name' => 'Symfony',
                'version' => $this->packageVersionFromLock($root, 'symfony/framework-bundle'),
                'detection_method' => 'symfony_lock',
            ];
        }

        if (is_file($root.'/yii')) {
            return [
                'detected' => 'yii',
                'name' => 'Yii',
                'version' => $this->packageVersionFromLock($root, 'yiisoft/yii2'),
                'detection_method' => 'yii_file',
            ];
        }

        if (is_file($root.'/composer.json')) {
            return ['detected' => 'generic', 'name' => null, 'version' => null, 'detection_method' => 'composer_json'];
        }

        return ['detected' => 'unknown', 'name' => null, 'version' => null, 'detection_method' => null];
    }

    /**
     * @return array{ecosystem: string, source: string, lock_hash: string, items: array<int, array{name: string, version: string}>, dev_installed: bool}|null
     */
    public function packages(?string $root): ?array
    {
        if ($root === null) {
            return null;
        }

        $lockPath = $root.'/composer.lock';

        if (is_file($lockPath)) {
            $decoded = json_decode((string) @file_get_contents($lockPath, false, null, 0, self::MAX_LOCK_BYTES), true);

            if (is_array($decoded)) {
                return [
                    'ecosystem' => 'composer',
                    'source' => 'composer.lock',
                    'lock_hash' => (string) hash_file('sha256', $lockPath),
                    'items' => $this->itemsFromPackageList(isset($decoded['packages']) ? $decoded['packages'] : []),
                    'dev_installed' => $this->devPackagesInstalled($root),
                ];
            }
        }

        $installedPath = $root.'/vendor/composer/installed.json';

        if (is_file($installedPath)) {
            $decoded = json_decode((string) @file_get_contents($installedPath, false, null, 0, self::MAX_LOCK_BYTES), true);

            if (is_array($decoded)) {
                // Composer 2 wraps the list in "packages"; Composer 1 is a bare array.
                $list = isset($decoded['packages']) && is_array($decoded['packages']) ? $decoded['packages'] : $decoded;

                return [
                    'ecosystem' => 'composer',
                    'source' => 'installed.json',
                    'lock_hash' => (string) hash_file('sha256', $installedPath),
                    'items' => $this->itemsFromPackageList($list),
                    'dev_installed' => $this->devPackagesInstalled($root),
                ];
            }
        }

        return null;
    }

    private function looksLikeProjectRoot(string $path): bool
    {
        // Probing an ancestor outside open_basedir raises a warning; it must not
        // surface (0.5.1 — the guard in handle() swallows it, this keeps run() quiet too).
        return @is_file($path.'/composer.json')
            || @is_file($path.'/artisan')
            || @is_file($path.'/wp-config.php');
    }

    /**
     * @param array<int, mixed> $list
     * @return array<int, array{name: string, version: string}>
     */
    private function itemsFromPackageList(array $list): array
    {
        $items = [];

        foreach ($list as $package) {
            if (! is_array($package) || ! isset($package['name'], $package['version'])
                || ! is_scalar($package['name']) || ! is_scalar($package['version'])) {
                continue;
            }

            $items[] = [
                'name' => (string) $package['name'],
                'version' => ltrim((string) $package['version'], 'v'),
            ];
        }

        return $items;
    }

    private function devPackagesInstalled(string $root): bool
    {
        $markers = [
            '/vendor/phpunit/phpunit',
            '/vendor/laravel/telescope',
            '/vendor/barryvdh/laravel-debugbar',
            '/vendor/spatie/laravel-ignition',
            '/vendor/facade/ignition',
        ];

        foreach ($markers as $marker) {
            if (is_dir($root.$marker)) {
                return true;
            }
        }

        return false;
    }

    private function packageVersionFromLock(string $root, string $packageName): ?string
    {
        $packages = $this->packages($root);

        if ($packages === null) {
            return null;
        }

        foreach ($packages['items'] as $item) {
            if ($item['name'] === $packageName) {
                return $item['version'];
            }
        }

        return null;
    }

    private function wordPressVersion(string $root): ?string
    {
        $versionFile = $root.'/wp-includes/version.php';

        if (! is_file($versionFile)) {
            return null;
        }

        $contents = (string) @file_get_contents($versionFile, false, null, 0, 65536);

        if (preg_match('/\$wp_version\s*=\s*\'([^\']{1,64})\'/', $contents, $match) === 1) {
            return $match[1];
        }

        return null;
    }
}
