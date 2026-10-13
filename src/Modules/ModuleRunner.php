<?php

namespace Sitetus\Collector\Modules;

use Sitetus\Collector\Config;

/**
 * Runs the opt-in modules the installation enabled (Config::$modules) and
 * builds the envelope's `modules` section. A module whose code
 * was left out of this build (the panel strips unselected modules between
 * the SITETUS_MODULE markers) is reported as `unavailable` — nothing can
 * run that is not in the file.
 *
 * 0.5.1 (audit 25.09): the module ids are literals and every reference to
 * a module class sits behind class_exists(), so a build with stripped
 * modules never touches a missing class.
 */
final class ModuleRunner
{
    public const ALL = ['files', 'archives', 'permissions', 'bot_traffic'];

    /** @var Config */
    private $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * @param array{detected: string} $framework
     * @return array<string, mixed>|null null when no module is enabled
     */
    public function run(?string $root, array $framework, int $now): ?array
    {
        $enabled = array_values(array_intersect(self::ALL, $this->config->modules));

        if ($enabled === [] || $root === null) {
            return $enabled === [] ? null : ['enabled' => $enabled, 'skipped' => 'msg.root_unknown'];
        }

        $detected = (string) $framework['detected'];
        $webRoot = self::webRoot($root, $detected);
        $section = ['enabled' => $enabled, 'web_root' => $detected === 'laravel' ? 'public' : '.'];

        foreach ($enabled as $module) {
            $section[$module] = $this->runModule($module, $root, $webRoot, $detected, $now);
        }

        return $section;
    }

    public static function webRoot(string $root, string $framework): string
    {
        return $framework === 'laravel' && is_dir($root.'/public') ? $root.'/public' : $root;
    }

    /**
     * @return array<string, mixed>
     */
    private function runModule(string $module, string $root, string $webRoot, string $framework, int $now): array
    {
        try {
            switch ($module) {
                case 'files':
                    return class_exists(FileTrace::class)
                        ? (new FileTrace())->run($root, $webRoot, $framework, $now)
                        : ['unavailable' => true];
                case 'archives':
                    return class_exists(ArchiveScan::class)
                        ? (new ArchiveScan())->run($webRoot)
                        : ['unavailable' => true];
                case 'permissions':
                    return class_exists(PermissionScan::class)
                        ? (new PermissionScan())->run($root, $framework)
                        : ['unavailable' => true];
                case 'bot_traffic':
                    return class_exists(BotTraffic::class)
                        ? (new BotTraffic())->run($root, $now)
                        : ['unavailable' => true];
            }
        } catch (\Throwable $exception) {
            return ['error' => 'msg.module_failed'];
        }

        return ['unavailable' => true];
    }
}
