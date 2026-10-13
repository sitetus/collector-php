<?php

namespace Sitetus\Collector\Modules;

/**
 * Module `permissions` — world-writable files and directories in the
 * project root. Writable-by-design trees
 * (storage/, caches, upload directories) are skipped; on Windows the mode
 * bits mean nothing and the module reports `unsupported`.
 */
final class PermissionScan
{
    public const ID = 'permissions';

    /**
     * @return array<string, mixed>
     */
    public function run(string $root, string $framework): array
    {
        if (PHP_OS_FAMILY === 'Windows') {
            return ['unsupported' => true];
        }

        $scanner = new Scanner(5000, 3, 2.0);
        $names = [];
        $counts = ['dirs' => 0, 'files' => 0, 'php' => 0];

        $scanner->walk($root, function (string $absolute, string $relative, bool $isDir) use (&$names, &$counts): void {
            $perms = @fileperms($absolute);

            if ($perms === false || ($perms & 0002) === 0) {
                return;
            }

            if ($isDir) {
                $counts['dirs']++;
            } elseif (Scanner::extension($relative) === 'php') {
                $counts['php']++;
            } else {
                $counts['files']++;
            }

            Scanner::push($names, ['name' => Scanner::safeName($relative), 'dir' => $isDir, 'mode' => substr(sprintf('%o', $perms), -4)]);
        }, $this->skipDirectories($framework));

        return [
            'unsupported' => false,
            'world_writable' => ['dirs' => $counts['dirs'], 'files' => $counts['files'], 'php_files' => $counts['php']],
            'names' => $names,
            'budget_exhausted' => $scanner->exhausted(),
        ];
    }

    /**
     * @return array<int, string>
     */
    private function skipDirectories(string $framework): array
    {
        $common = ['vendor', 'node_modules', '.git'];

        if ($framework === 'laravel') {
            return array_merge($common, ['storage', 'bootstrap/cache', 'public/storage', 'public/uploads']);
        }

        if ($framework === 'wordpress') {
            return array_merge($common, ['wp-content/uploads', 'wp-content/cache', 'wp-content/upgrade']);
        }

        return array_merge($common, ['uploads', 'cache', 'tmp']);
    }
}
