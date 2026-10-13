<?php

namespace Sitetus\Collector\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sitetus\Collector\Config;
use Sitetus\Collector\Tests\Support;

/**
 * 0.5.1 (audit 25.09): the single-file build is exercised end to end — built
 * by build/build.php, module-stripped and placeholder-filled the way the
 * panel does it, then loaded in a fresh PHP process and given a correctly
 * signed request. Linting alone let a "class not found" ship in 0.3.0–0.5.0.
 */
final class BuildArtifactTest extends TestCase
{
    /** @var array<int, string> */
    private $dirs = [];

    protected function setUp(): void
    {
        if (! function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('sodium not available');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            Support::removeDir($dir);
        }
    }

    public function testBuiltAndStrippedFileAnswersASignedPullWithModulesRunningOrUnavailable(): void
    {
        $repo = dirname(__DIR__, 2);
        $work = Support::tmpDir('build');
        $this->dirs[] = $work;

        // 1. Build into scratch, never into dist/.
        $built = $work.'/built.php';
        exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg($repo.'/build/build.php').' '.escapeshellarg($built).' 2>&1', $buildOutput, $buildExit);
        $this->assertSame(0, $buildExit, implode("\n", $buildOutput));

        // 2. A project the file will sit in: root/public/<random>/index.php.
        $root = Support::tmpDir('project');
        $this->dirs[] = $root;
        $installDir = $root.'/public/r4nd0m';
        mkdir($installDir, 0777, true);
        file_put_contents($root.'/composer.json', '{}');
        file_put_contents($root.'/composer.lock', json_encode(['packages' => [['name' => 'monolog/monolog', 'version' => '3.7.0']]]));
        file_put_contents($root.'/public/index.php', "<?php\n");

        // 3. Strip two modules the way the panel does (same regex), keep files + permissions,
        //    but list `archives` in the configuration anyway: its code is gone, so it must
        //    report `unavailable` — never a fatal.
        $source = (string) file_get_contents($built);
        $stripped = (string) preg_replace_callback(
            '/\/\* SITETUS_MODULE_START:([a-z_]+) \*\/\n?(.*?)\n?\/\* SITETUS_MODULE_END:\1 \*\/\n?/s',
            static function (array $match): string {
                return in_array($match[1], ['archives', 'bot_traffic'], true) ? '' : $match[0];
            },
            $source
        );
        $this->assertStringNotContainsString('final class ArchiveScan', $stripped);
        $this->assertStringContainsString('final class FileTrace', $stripped);

        $keyPair = sodium_crypto_sign_keypair();
        $replacements = [
            '{{PROJECT_KEY}}' => 'testproject12345678a',
            '{{PUBLIC_KEY}}' => base64_encode(sodium_crypto_sign_publickey($keyPair)),
            '{{ALGO}}' => 'ed25519',
            '{{EXPIRES_AT}}' => '',
            '{{ROOT_OVERRIDE}}' => '',
            '{{NONCE_FILE}}' => '.nonce-build-test.json',
            '{{MODULES}}' => 'files,permissions,archives',
        ];
        $installed = $installDir.'/index.php';
        file_put_contents($installed, strtr($stripped, $replacements));

        // 4. A signed request, verified and answered inside a fresh PHP process that has
        //    nothing but the built file.
        $config = Config::fromArray([
            'project_key' => $replacements['{{PROJECT_KEY}}'],
            'public_key' => $replacements['{{PUBLIC_KEY}}'],
            'algo' => 'ed25519',
            'expires_at' => '',
            'root_override' => '',
            'nonce_file' => $replacements['{{NONCE_FILE}}'],
        ], $installDir);
        $now = time();
        $headers = Support::signedHeaders($config, sodium_crypto_sign_secretkey($keyPair), $now, null, 'GET', '/public/r4nd0m/');

        $runner = $work.'/runner.php';
        file_put_contents($runner, <<<'PHP'
<?php
define('SITETUS_COLLECTOR_NO_RUN', true);
$input = json_decode((string) file_get_contents($argv[2]), true);
require $argv[1];
$config = \Sitetus\Collector\Config::fromArray($__sitetusConfig, dirname($argv[1]));
$result = (new \Sitetus\Collector\Collector($config))->run('GET', $input['path'], $input['headers'], '', $input['now'], $argv[1]);
echo json_encode($result);
PHP
        );
        $inputFile = $work.'/input.json';
        file_put_contents($inputFile, json_encode(['path' => '/public/r4nd0m/', 'headers' => $headers, 'now' => $now]));

        exec(escapeshellarg(PHP_BINARY).' -d display_errors=1 '.escapeshellarg($runner).' '.escapeshellarg($installed).' '.escapeshellarg($inputFile).' 2>&1', $runOutput, $runExit);
        $raw = implode("\n", $runOutput);
        $this->assertSame(0, $runExit, $raw);

        $result = json_decode($raw, true);
        $this->assertIsArray($result, $raw);
        $this->assertSame(200, $result['status'], $raw);

        $envelope = json_decode((string) $result['body'], true);
        $this->assertIsArray($envelope, $raw);
        $this->assertSame(Config::VERSION, $envelope['collector']['version']);
        $this->assertSame(hash_file('sha256', $installed), $envelope['collector']['file_hash']);
        $this->assertSame('monolog/monolog', $envelope['packages']['items'][0]['name']);
        $this->assertSame(['files', 'archives', 'permissions'], $envelope['modules']['enabled']);
        $this->assertArrayHasKey('tracked', $envelope['modules']['files']);
        $this->assertSame(['unavailable' => true], $envelope['modules']['archives']);
        $this->assertArrayNotHasKey('bot_traffic', $envelope['modules']);

        // 5. An unsigned request against the same file is a bodiless 404.
        file_put_contents($inputFile, json_encode(['path' => '/public/r4nd0m/', 'headers' => [], 'now' => $now]));
        exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg($runner).' '.escapeshellarg($installed).' '.escapeshellarg($inputFile).' 2>&1', $anonOutput, $anonExit);
        $anon = json_decode(implode("\n", $anonOutput), true);
        $this->assertSame(0, $anonExit);
        $this->assertSame(404, $anon['status']);
        $this->assertNull($anon['body']);
    }
}
