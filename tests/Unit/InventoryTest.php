<?php

namespace Sitetus\Collector\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sitetus\Collector\Config;
use Sitetus\Collector\Inventory;
use Sitetus\Collector\Tests\Support;

final class InventoryTest extends TestCase
{
    /** @var array<int, string> */
    private $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            Support::removeDir($dir);
        }
    }

    private function makeRoot(): string
    {
        $root = Support::tmpDir('root');
        $this->dirs[] = $root;

        return $root;
    }

    private function inventoryFor(string $root): Inventory
    {
        $installDir = $root.'/public/abc123';
        mkdir($installDir, 0777, true);

        return new Inventory(Config::fromArray([
            'project_key' => 'p', 'public_key' => '', 'algo' => 'ed25519',
            'expires_at' => '', 'root_override' => '', 'nonce_file' => '.n.json',
        ], $installDir));
    }

    public function testDetectsLaravelAndReadsComposerLock(): void
    {
        $root = $this->makeRoot();
        file_put_contents($root.'/artisan', '');
        mkdir($root.'/bootstrap', 0777, true);
        file_put_contents($root.'/bootstrap/app.php', '');
        file_put_contents($root.'/composer.json', '{}');
        file_put_contents($root.'/composer.lock', json_encode([
            'packages' => [
                ['name' => 'laravel/framework', 'version' => 'v11.20.0'],
                ['name' => 'guzzlehttp/guzzle', 'version' => '7.9.2'],
            ],
        ]));

        $inventory = $this->inventoryFor($root);
        $resolvedRoot = $inventory->rootPath();
        $framework = $inventory->detectFramework($resolvedRoot);
        $packages = $inventory->packages($resolvedRoot);

        $this->assertSame('default', $inventory->rootPathSource());
        $this->assertSame('laravel', $framework['detected']);
        $this->assertSame('11.20.0', $framework['version']);
        $this->assertSame('composer.lock', $packages['source']);
        $this->assertCount(2, $packages['items']);
        $this->assertSame('guzzlehttp/guzzle', $packages['items'][1]['name']);
        $this->assertSame(hash_file('sha256', $root.'/composer.lock'), $packages['lock_hash']);
        $this->assertFalse($packages['dev_installed']);
    }

    public function testFallsBackToInstalledJsonAndFlagsDevPackages(): void
    {
        $root = $this->makeRoot();
        file_put_contents($root.'/composer.json', '{}');
        mkdir($root.'/vendor/composer', 0777, true);
        mkdir($root.'/vendor/phpunit/phpunit', 0777, true);
        file_put_contents($root.'/vendor/composer/installed.json', json_encode([
            'packages' => [['name' => 'monolog/monolog', 'version' => '3.7.0']],
        ]));

        $inventory = $this->inventoryFor($root);
        $packages = $inventory->packages($inventory->rootPath());

        $this->assertSame('installed.json', $packages['source']);
        $this->assertSame('monolog/monolog', $packages['items'][0]['name']);
        $this->assertTrue($packages['dev_installed']);
    }

    public function testDetectsWordPressWithVersion(): void
    {
        $root = $this->makeRoot();
        file_put_contents($root.'/wp-config.php', '<?php');
        mkdir($root.'/wp-includes', 0777, true);
        file_put_contents($root.'/wp-includes/version.php', "<?php\n\$wp_version = '6.6.2';\n");

        $inventory = $this->inventoryFor($root);
        $framework = $inventory->detectFramework($inventory->rootPath());

        $this->assertSame('wordpress', $framework['detected']);
        $this->assertSame('6.6.2', $framework['version']);
    }

    public function testUnknownWhenNothingMatches(): void
    {
        $root = $this->makeRoot();

        $inventory = $this->inventoryFor($root);
        $resolvedRoot = $inventory->rootPath();

        $this->assertNull($resolvedRoot);
        $this->assertSame('unknown', $inventory->detectFramework($resolvedRoot)['detected']);
        $this->assertNull($inventory->packages($resolvedRoot));
    }

    public function testRootOverrideWins(): void
    {
        $root = $this->makeRoot();
        file_put_contents($root.'/composer.json', '{}');

        $installDir = Support::tmpDir('elsewhere');
        $this->dirs[] = $installDir;

        $inventory = new Inventory(Config::fromArray([
            'project_key' => 'p', 'public_key' => '', 'algo' => 'ed25519',
            'expires_at' => '', 'root_override' => $root, 'nonce_file' => '.n.json',
        ], $installDir));

        $this->assertSame($root, $inventory->rootPath());
        $this->assertSame('override', $inventory->rootPathSource());
    }
}
