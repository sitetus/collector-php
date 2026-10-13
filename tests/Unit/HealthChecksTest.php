<?php

namespace Sitetus\Collector\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sitetus\Collector\Health;
use Sitetus\Collector\Tests\Support;

/**
 * 0.3.0 health readings: php.ini hygiene, log size and
 * locally listening services — numbers, flags and fixed names only.
 * 0.7.0: maintenance mode from the marker file (Laravel down file,
 * WordPress-style .maintenance) — never the bypass secret or contents.
 */
final class HealthChecksTest extends TestCase
{
    /** @var array<int, string> */
    private $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            Support::removeDir($dir);
        }
    }

    public function testPhpIniReportsFlagsAndLimitsWithoutPaths(): void
    {
        $check = (new Health())->phpIni();

        $this->assertSame('php_ini', $check['id']);
        $this->assertContains($check['status'], ['ok', 'warn', 'fail']);
        $this->assertIsInt($check['value']);
        $this->assertIsBool($check['detail']['display_errors']);
        $this->assertIsBool($check['detail']['expose_php']);
        $this->assertIsBool($check['detail']['allow_url_include']);
        $this->assertIsInt($check['detail']['disable_functions']);
        $this->assertIsString($check['detail']['memory_limit']);
        $this->assertCount(10, $check['detail']);

        // Never a filesystem path in the detail (open_basedir is a bool).
        foreach ($check['detail'] as $value) {
            $this->assertFalse(is_string($value) && (strpos($value, '/') !== false || strpos($value, '\\') !== false));
        }
    }

    public function testLogSizeSumsTheLogDirectoryInMegabytes(): void
    {
        $root = Support::tmpDir('logsize');
        $this->dirs[] = $root;

        $this->assertSame('unknown', (new Health())->logSize($root)['status']);

        mkdir($root.'/storage/logs', 0777, true);
        file_put_contents($root.'/storage/logs/laravel.log', str_repeat('x', 3 * 1048576));
        file_put_contents($root.'/storage/logs/worker.log', str_repeat('y', 1048576));
        file_put_contents($root.'/storage/logs/notes.txt', 'ignored');

        $check = (new Health())->logSize($root);

        $this->assertSame('ok', $check['status']);
        $this->assertSame(4, $check['value']);
        $this->assertSame('MB', $check['unit']);
        $this->assertSame(2, $check['detail']['files']);
    }

    public function testMaintenanceModeReadsTheLaravelDownFileWithoutItsSecret(): void
    {
        $root = Support::tmpDir('maintenance');
        $this->dirs[] = $root;
        mkdir($root.'/storage/framework', 0777, true);
        file_put_contents($root.'/storage/framework/down', json_encode([
            'time' => time() - 7200,
            'retry' => 60,
            'secret' => 'bypass-token-123',
            'status' => 503,
        ]));

        $check = (new Health())->maintenanceMode($root);

        $this->assertSame('maintenance_mode', $check['id']);
        $this->assertSame('warn', $check['status']);
        $this->assertTrue($check['value']);
        $this->assertTrue($check['detail']['active']);
        $this->assertSame('laravel', $check['detail']['framework']);
        $this->assertTrue($check['detail']['has_secret']);
        $this->assertGreaterThanOrEqual(7200, $check['detail']['since_seconds']);
        $this->assertLessThan(7260, $check['detail']['since_seconds']);
        $this->assertStringNotContainsString('bypass-token-123', (string) json_encode($check));
        $this->assertArrayNotHasKey('retry', $check['detail']);
    }

    public function testMaintenanceModeIsOffWithoutAMarkerFile(): void
    {
        $root = Support::tmpDir('maintenance');
        $this->dirs[] = $root;
        mkdir($root.'/storage/framework', 0777, true);

        $check = (new Health())->maintenanceMode($root);

        $this->assertSame('ok', $check['status']);
        $this->assertFalse($check['value']);
        $this->assertSame(['active' => false], $check['detail']);
    }

    public function testFreshWordPressMaintenanceFileCountsAsActiveWithoutASecretFlag(): void
    {
        $root = Support::tmpDir('maintenance');
        $this->dirs[] = $root;
        file_put_contents($root.'/.maintenance', '<?php $upgrading = '.time().";\n");

        $check = (new Health())->maintenanceMode($root);

        $this->assertSame('warn', $check['status']);
        $this->assertTrue($check['value']);
        $this->assertSame('generic', $check['detail']['framework']);
        $this->assertArrayNotHasKey('has_secret', $check['detail']);
        $this->assertLessThan(60, $check['detail']['since_seconds']);
        $this->assertStringNotContainsString('upgrading', (string) json_encode($check));
    }

    public function testStaleWordPressMaintenanceFileIsReportedButNotActive(): void
    {
        $root = Support::tmpDir('maintenance');
        $this->dirs[] = $root;
        file_put_contents($root.'/.maintenance', '<?php $upgrading = 1;');
        touch($root.'/.maintenance', time() - Health::WORDPRESS_MAINTENANCE_SECONDS - 60);

        $check = (new Health())->maintenanceMode($root);

        $this->assertSame('ok', $check['status']);
        $this->assertFalse($check['value']);
        $this->assertSame(['active' => false, 'stale_file' => true], $check['detail']);
    }

    public function testListeningPortsReadsProcNetOrReportsUnsupported(): void
    {
        $check = (new Health())->listeningPorts();

        $this->assertSame('listening_ports', $check['id']);

        if (! @is_readable('/proc/net/tcp')) {
            $this->assertSame('unknown', $check['status']);
            $this->assertSame('msg.unsupported_os', $check['message']);

            return;
        }

        $this->assertContains($check['status'], ['ok', 'warn']);
        $this->assertIsInt($check['value']);
        $this->assertIsString($check['detail']['exposed']);
    }

    public function testOpcacheReportsOnlyTheFlagAndCounters(): void
    {
        $check = (new Health())->opcache();

        $this->assertSame('opcache', $check['id']);
        $this->assertContains($check['status'], ['ok', 'warn']);
        $this->assertIsBool($check['value']);
        $this->assertIsBool($check['detail']['loaded']);
        $this->assertSame($check['value'], $check['detail']['enabled']);
        $this->assertSame($check['value'] ? 'ok' : 'warn', $check['status']);

        foreach ($check['detail'] as $value) {
            $this->assertTrue(is_bool($value) || is_int($value) || $value === null);
        }
    }

    public function testLoadAverageReadsProcOrReportsUnsupported(): void
    {
        $check = (new Health())->loadAverage();

        $this->assertSame('load', $check['id']);

        if (! @is_readable('/proc/loadavg')) {
            $this->assertSame('unknown', $check['status']);
            $this->assertSame('msg.unsupported_os', $check['message']);

            return;
        }

        $this->assertContains($check['status'], ['ok', 'warn', 'fail']);
        $this->assertIsFloat($check['value']);
        $this->assertGreaterThanOrEqual(1, $check['detail']['cpus']);
    }
}
