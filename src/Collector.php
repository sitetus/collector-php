<?php

namespace Sitetus\Collector;

use Sitetus\Collector\Modules\ModuleRunner;

/**
 * Orchestration: verify the request, collect Level 1, attempt
 * Level 2 only for verified requests on detected Laravel projects, respond
 * with the JSON envelope. The 404 path carries no body and no custom
 * headers — indistinguishable from a missing file.
 */
final class Collector
{
    /** @var Config */
    private $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Entry point for the single-file build. Reads the superglobals, writes
     * the response, returns nothing. Kept thin; run() is the testable core.
     *
     * 0.5.1 (audit 25.09): PHP diagnostics never reach the response body.
     * display_errors is turned off, warnings are swallowed and any stray
     * output produced while collecting is discarded before the envelope is
     * written — the body is the JSON envelope or nothing.
     */
    public function handle(): void
    {
        $headers = [];

        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $name = strtolower(str_replace('_', '-', substr($key, 5)));
                $headers[$name] = (string) $value;
            }
        }

        $method = isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : 'GET';
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/';
        $path = (string) parse_url($uri, PHP_URL_PATH);
        $body = (string) file_get_contents('php://input');

        // The runtime flags are read before anything below touches them.
        $runtimeIni = Envelope::runtimeIniSnapshot();

        @ini_set('display_errors', '0');
        set_error_handler(static function (): bool {
            return true;
        });
        ob_start();

        try {
            $result = $this->run($method, $path, $headers, $body, time(), __FILE__, $runtimeIni);
        } finally {
            while (ob_get_level() > 0) {
                ob_end_clean();
            }

            restore_error_handler();
        }

        http_response_code($result['status']);

        foreach ($result['headers'] as $name => $value) {
            header($name.': '.$value);
        }

        if ($result['body'] !== null) {
            header('Content-Type: application/json');
            echo $result['body'];
        }
    }

    /**
     * @param array<string, string> $headers lower-cased header names
     * @param array<string, bool>|null $runtimeIni the ini flags as seen before any guard changed them
     * @return array{status: int, headers: array<string, string>, body: ?string}
     */
    public function run(string $method, string $path, array $headers, string $body, int $now, string $selfPath, ?array $runtimeIni = null): array
    {
        $startedAt = microtime(true);

        // Level 2 turns display_errors off for the customer's bootstrap; the
        // envelope must report the value the site actually runs with (0.5.1).
        $runtimeIni = $runtimeIni !== null ? $runtimeIni : Envelope::runtimeIniSnapshot();

        $verifier = new RequestVerifier($this->config, new NonceStore($this->config->noncePath()));

        list($status, $extraHeaders) = $verifier->verify($method, $path, $headers, $body, $now);

        if ($status !== 200) {
            return ['status' => $status, 'headers' => $extraHeaders, 'body' => null];
        }

        $inventory = new Inventory($this->config);
        $health = new Health();

        $root = $inventory->rootPath();
        $framework = $inventory->detectFramework($root);
        $packages = $inventory->packages($root);
        $checks = $health->level1Checks($root);
        $warnings = [];
        $level = 1;

        if ($root !== null && $framework['detected'] === 'laravel' && is_file($root.'/vendor/autoload.php')) {
            $level2 = new Level2();
            $result = $level2->run($root);

            $checks = array_merge($checks, $result['checks']);
            $warnings = array_merge($warnings, $result['warnings']);
            $level = 2;
        }

        // Opt-in modules run last, each under its own budget; a
        // module failure degrades to msg.module_failed, never to an error.
        $modules = (new ModuleRunner($this->config))->run($root, $framework, $now);

        $envelope = (new Envelope($this->config))->build(
            $level,
            $framework,
            $packages,
            $checks,
            $health->cliPhpVersion($root),
            $inventory->rootPathSource(),
            $warnings,
            $startedAt,
            $selfPath,
            [],
            $modules,
            $runtimeIni
        );

        // Invalid UTF-8 in a version string or a file name must not turn the
        // whole response into an empty body (0.5.1).
        $json = json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

        return [
            'status' => 200,
            'headers' => [],
            'body' => (string) $json,
        ];
    }
}
