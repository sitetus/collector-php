<?php

namespace Sitetus\Collector\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sitetus\Collector\Level2;
use Sitetus\Collector\Tests\Support;

/**
 * 0.6.0 Level 2 posture rows (storage link flags, session driver name),
 * driven through checksFromApp() with a stand-in container so the shape
 * matches what the single file and the Composer wrapper emit. Only flags
 * and driver names travel; never a path.
 */
final class Level2PostureTest extends TestCase
{
    /** @var array<int, string> */
    private $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            Support::removeDir($dir);
        }
    }

    public function testStorageLinkIsHealthyWhenTheDeclaredLinkPointsAtItsTarget(): void
    {
        $root = $this->projectRoot();

        if (! @symlink($root.'/storage/app/public', $root.'/public/storage')) {
            $this->markTestSkipped('symlink() is not permitted on this host.');
        }

        $check = $this->checkById($this->container($this->config($root)), 'storage_link');

        $this->assertSame('ok', $check['status']);
        $this->assertTrue($check['value']);
        $this->assertSame(['present' => true, 'is_link' => true], $check['detail']);
    }

    public function testMissingStorageLinkWarnsOnlyWhenThePublicDiskIsConfigured(): void
    {
        $root = $this->projectRoot();

        $withDisk = $this->checkById($this->container($this->config($root)), 'storage_link');

        $this->assertSame('warn', $withDisk['status']);
        $this->assertFalse($withDisk['value']);
        $this->assertSame(['present' => false, 'is_link' => false], $withDisk['detail']);

        $withoutDisk = $this->checkById($this->container($this->config($root, ['filesystems.disks.public' => null])), 'storage_link');

        $this->assertSame('ok', $withoutDisk['status']);
        $this->assertFalse($withoutDisk['value']);
    }

    public function testPlainDirectoryInTheLinkPlaceIsPresentButNotALink(): void
    {
        $root = $this->projectRoot();
        mkdir($root.'/public/storage');

        $check = $this->checkById($this->container($this->config($root)), 'storage_link');

        $this->assertSame('warn', $check['status']);
        $this->assertSame(['present' => true, 'is_link' => false], $check['detail']);
        $this->assertArrayNotHasKey('message', $check);
    }

    public function testNoDeclaredLinksIsFineAndAnUninspectableParentIsUnknown(): void
    {
        $root = $this->projectRoot();

        $none = $this->checkById($this->container($this->config($root, ['filesystems.links' => []])), 'storage_link');

        $this->assertSame('ok', $none['status']);
        $this->assertTrue($none['value']);
        $this->assertArrayNotHasKey('detail', $none);

        $unknown = $this->checkById($this->container($this->config($root, [
            'filesystems.links' => [$root.'/nowhere/storage' => $root.'/storage/app/public'],
        ])), 'storage_link');

        $this->assertSame('unknown', $unknown['status']);
        $this->assertSame('msg.not_readable', $unknown['message']);
    }

    public function testStorageLinkDetailCarriesFlagsOnlyNeverAPath(): void
    {
        $root = $this->projectRoot();

        $check = $this->checkById($this->container($this->config($root)), 'storage_link');

        foreach ($check['detail'] as $value) {
            $this->assertIsBool($value);
        }

        $this->assertStringNotContainsString($root, json_encode($check));
    }

    public function testSessionDriverWarnsForLocalDriversInProductionOnly(): void
    {
        $root = $this->projectRoot();

        $file = $this->checkById($this->container($this->config($root, ['session.driver' => 'file'])), 'session_driver');
        $redis = $this->checkById($this->container($this->config($root, ['session.driver' => 'redis'])), 'session_driver');
        $local = $this->checkById($this->container($this->config($root, ['session.driver' => 'file', 'app.env' => 'local'])), 'session_driver');
        $cookie = $this->checkById($this->container($this->config($root, ['session.driver' => 'cookie'])), 'session_driver');

        $this->assertSame(['id' => 'session_driver', 'status' => 'warn', 'value' => 'file'], $file);
        $this->assertSame(['id' => 'session_driver', 'status' => 'ok', 'value' => 'redis'], $redis);
        $this->assertSame(['id' => 'session_driver', 'status' => 'ok', 'value' => 'file'], $local);
        $this->assertSame('warn', $cookie['status']);
    }

    public function testUnreadableConfigurationLeavesBothRowsUnknown(): void
    {
        $container = new class
        {
            /** @return mixed */
            public function make(string $abstract)
            {
                throw new \RuntimeException('no '.$abstract);
            }
        };

        $checks = (new Level2())->checksFromApp($container);

        $this->assertSame(['id' => 'storage_link', 'status' => 'unknown', 'message' => 'msg.not_readable'], $this->pick($checks, 'storage_link'));
        $this->assertSame(['id' => 'session_driver', 'status' => 'unknown', 'message' => 'msg.not_readable'], $this->pick($checks, 'session_driver'));
    }

    private function projectRoot(): string
    {
        $root = Support::tmpDir('level2');
        $this->dirs[] = $root;

        mkdir($root.'/public', 0777, true);
        mkdir($root.'/storage/app/public', 0777, true);

        return $root;
    }

    /**
     * Production defaults with the standard public disk and link; overrides
     * replace single keys (null removes the key).
     *
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function config(string $root, array $overrides = []): array
    {
        return array_merge([
            'app.env' => 'production',
            'session.driver' => 'database',
            'filesystems.disks.public' => ['driver' => 'local'],
            'filesystems.links' => [$root.'/public/storage' => $root.'/storage/app/public'],
        ], $overrides);
    }

    /**
     * @param array<string, mixed> $values
     * @return object
     */
    private function container(array $values)
    {
        $config = new class($values)
        {
            /** @var array<string, mixed> */
            private $values;

            /** @param array<string, mixed> $values */
            public function __construct(array $values)
            {
                $this->values = $values;
            }

            /**
             * @param mixed $default
             * @return mixed
             */
            public function get(string $key, $default = null)
            {
                return array_key_exists($key, $this->values) ? $this->values[$key] : $default;
            }
        };

        return new class($config)
        {
            /** @var object */
            private $config;

            public function __construct(object $config)
            {
                $this->config = $config;
            }

            /** @return mixed */
            public function make(string $abstract)
            {
                if ($abstract === 'config') {
                    return $this->config;
                }

                throw new \RuntimeException('not bound: '.$abstract);
            }
        };
    }

    /**
     * @param object $container
     * @return array<string, mixed>
     */
    private function checkById($container, string $id): array
    {
        return $this->pick((new Level2())->checksFromApp($container), $id);
    }

    /**
     * @param array<int, array<string, mixed>> $checks
     * @return array<string, mixed>
     */
    private function pick(array $checks, string $id): array
    {
        foreach ($checks as $check) {
            if ($check['id'] === $id) {
                return $check;
            }
        }

        $this->fail('check '.$id.' missing');
    }
}
