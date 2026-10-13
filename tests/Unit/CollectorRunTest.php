<?php

namespace Sitetus\Collector\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sitetus\Collector\Collector;
use Sitetus\Collector\Config;
use Sitetus\Collector\Tests\Support;

final class CollectorRunTest extends TestCase
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

    public function testVerifiedRequestReturnsSchemaValidEnvelope(): void
    {
        // root/public/<random>/ layout with a composer.lock at the root.
        $root = Support::tmpDir('project');
        $this->dirs[] = $root;
        $installDir = $root.'/public/r4nd0m';
        mkdir($installDir, 0777, true);
        file_put_contents($root.'/composer.json', '{}');
        file_put_contents($root.'/composer.lock', json_encode([
            'packages' => [['name' => 'monolog/monolog', 'version' => '3.7.0']],
        ]));

        list($config, $secret) = Support::ed25519Config($installDir);

        $now = time();
        $headers = Support::signedHeaders($config, $secret, $now, null, 'GET', '/public/r4nd0m/');

        $result = (new Collector($config))->run('GET', '/public/r4nd0m/', $headers, '', $now, __FILE__);

        $this->assertSame(200, $result['status']);

        $envelope = json_decode((string) $result['body'], true);

        $this->assertSame(1, $envelope['schema_version']);
        $this->assertSame('sitetus-php', $envelope['collector']['name']);
        $this->assertSame('php', $envelope['collector']['lang']);
        $this->assertSame(hash_file('sha256', __FILE__), $envelope['collector']['file_hash']);
        $this->assertSame($config->projectKey, $envelope['project_key']);
        $this->assertSame('monitor', $envelope['mode']);
        $this->assertSame(1, $envelope['level']);
        $this->assertSame(PHP_VERSION, $envelope['runtime']['php_version']);
        $this->assertSame('generic', $envelope['framework']['detected']);
        $this->assertSame('composer.lock', $envelope['packages']['source']);
        $this->assertSame('monolog/monolog', $envelope['packages']['items'][0]['name']);
        $this->assertSame('default', $envelope['meta']['root_path_source']);
        $this->assertIsInt($envelope['meta']['duration_ms']);
        $this->assertNotEmpty($envelope['health']['checks']);

        // Minimality: the envelope never carries these keys anywhere.
        $flat = json_encode($envelope);
        $this->assertStringNotContainsString('APP_KEY', (string) $flat);
        $this->assertStringNotContainsString('password', strtolower((string) $flat));
    }

    public function testUnverifiedRequestGetsBodylessAnonymous404(): void
    {
        list($config, $secret, $installDir) = Support::ed25519Config();
        $this->dirs[] = $installDir;

        $result = (new Collector($config))->run('GET', '/x/', [], '', time(), __FILE__);

        $this->assertSame(404, $result['status']);
        $this->assertNull($result['body']);
        $this->assertSame([], $result['headers']);
    }

    public function testBuiltSingleFileParsesAndExposesClasses(): void
    {
        $output = Support::tmpDir('build').'/index.php';
        $this->dirs[] = dirname($output);

        exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/../../build/build.php').' '.escapeshellarg($output), $out, $exit);

        $this->assertSame(0, $exit, implode("\n", $out));
        $this->assertFileExists($output);

        // Placeholders must be intact for the panel's package builder.
        $contents = (string) file_get_contents($output);
        $this->assertStringContainsString('{{PROJECT_KEY}}', $contents);
        $this->assertStringContainsString('SITETUS_CONFIG_START', $contents);

        // The file must lint on this PHP version too.
        exec(escapeshellarg(PHP_BINARY).' -l '.escapeshellarg($output), $lintOut, $lintExit);
        $this->assertSame(0, $lintExit, implode("\n", $lintOut));
    }
}
