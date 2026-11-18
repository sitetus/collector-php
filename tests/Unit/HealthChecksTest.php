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

    public function testProjectUnderAWebFolderNameIsRecognisedOnEitherSeparatorAndCase(): void
    {
        $this->assertTrue(Health::pathHasWebFolder('/home/acme/public_html/shop'));
        $this->assertTrue(Health::pathHasWebFolder('C:\\home\\acme\\PUBLIC_HTML\\shop'));
        $this->assertTrue(Health::pathHasWebFolder('/home/acme/private_html/app/'));
        // The project root itself counts.
        $this->assertTrue(Health::pathHasWebFolder('/home/acme/public_html'));
    }

    public function testProjectOutsideAWebFolderOrUnderALookAlikeNameIsNotInOne(): void
    {
        $this->assertFalse(Health::pathHasWebFolder('/home/acme/apps/shop'));
        $this->assertFalse(Health::pathHasWebFolder('/var/www/shop'));
        // Web folders the per-account address does not serve.
        $this->assertFalse(Health::pathHasWebFolder('/var/www/vhosts/example.test/httpdocs/app'));
        $this->assertFalse(Health::pathHasWebFolder('/home/acme/htdocs/example.test'));
        $this->assertFalse(Health::pathHasWebFolder('/www/wwwroot/shop'));
        $this->assertFalse(Health::pathHasWebFolder('/home/acme/www2/shop'));
        $this->assertFalse(Health::pathHasWebFolder('/home/acme/mywww/public_html.bak/shop'));
        $this->assertFalse(Health::pathHasWebFolder('/srv/wwwroot/shop'));
        $this->assertFalse(Health::pathHasWebFolder(''));
    }

    public function testDocumentRootIsComparedWithTheProjectRootAfterResolvingBoth(): void
    {
        $root = Support::tmpDir('layout');
        $this->dirs[] = $root;
        mkdir($root.'/public');

        $this->assertTrue(Health::docrootIsProjectRoot($root, $root));
        $this->assertTrue(Health::docrootIsProjectRoot($root.'/public/..', $root.'/'));
        $this->assertFalse(Health::docrootIsProjectRoot($root.'/public', $root));
    }

    public function testUnknownDocumentRootIsNullNotFalse(): void
    {
        $root = Support::tmpDir('layout');
        $this->dirs[] = $root;

        $this->assertNull(Health::docrootIsProjectRoot(null, $root));
        $this->assertNull(Health::docrootIsProjectRoot('', $root));
        $this->assertNull(Health::docrootIsProjectRoot($root.'/does-not-exist', $root));
    }

    public function testAccountHashIsATwelveCharacterPrefixAndNullWithoutAName(): void
    {
        $this->assertSame(substr(hash_hmac('sha256', 'acmeshop', 'key-one'), 0, 12), Health::accountHash('acmeshop', 'key-one'));
        $this->assertSame(1, preg_match('/^[0-9a-f]{12}$/', (string) Health::accountHash('acmeshop', 'key-one')));
        // The same name gives another value on another installation.
        $this->assertNotSame(Health::accountHash('acmeshop', 'key-one'), Health::accountHash('acmeshop', 'key-two'));
        $this->assertNull(Health::accountHash(null, 'key-one'));
        $this->assertNull(Health::accountHash('', 'key-one'));
        $this->assertNull(Health::accountHash('acmeshop', ''));
    }

    public function testHostingPanelIsOneWordFromItsInstallFolder(): void
    {
        $only = static function (string $present): callable {
            return static function (string $path) use ($present): bool {
                return $path === $present;
            };
        };

        $this->assertSame('cpanel', Health::hostingPanel($only('/usr/local/cpanel')));
        $this->assertSame('plesk', Health::hostingPanel($only('/usr/local/psa')));
        $this->assertSame('plesk', Health::hostingPanel($only('/opt/psa')));
        $this->assertSame('directadmin', Health::hostingPanel($only('/usr/local/directadmin')));
        $this->assertSame('unknown', Health::hostingPanel($only('/usr/local/something-else')));
        $this->assertSame('unknown', Health::hostingPanel(static function (string $path): bool {
            throw new \RuntimeException('open_basedir');
        }));
        $this->assertContains(Health::hostingPanel(), ['cpanel', 'plesk', 'directadmin', 'unknown']);
    }

    public function testHostingLayoutRowCarriesFlagsAHashPrefixAndAPanelWordNeverAPathOrAName(): void
    {
        $root = Support::tmpDir('layout');
        $this->dirs[] = $root;

        $previous = $_SERVER['DOCUMENT_ROOT'] ?? null;
        $_SERVER['DOCUMENT_ROOT'] = $root;

        try {
            $check = (new Health())->hostingLayout($root);
        } finally {
            if ($previous === null) {
                unset($_SERVER['DOCUMENT_ROOT']);
            } else {
                $_SERVER['DOCUMENT_ROOT'] = $previous;
            }
        }

        $this->assertSame('hosting_layout', $check['id']);
        $this->assertSame('ok', $check['status']);
        $this->assertIsBool($check['value']);
        $this->assertSame(['project_in_web_folder', 'docroot_is_project_root', 'account_hash', 'panel'], array_keys($check['detail']));
        $this->assertSame($check['value'], $check['detail']['project_in_web_folder']);
        $this->assertTrue($check['detail']['docroot_is_project_root']);
        $this->assertTrue($check['detail']['account_hash'] === null || preg_match('/^[0-9a-f]{12}$/', $check['detail']['account_hash']) === 1);
        $this->assertContains($check['detail']['panel'], ['cpanel', 'plesk', 'directadmin', 'unknown']);

        $encoded = (string) json_encode($check);
        $this->assertStringNotContainsString('/', $encoded);
        $this->assertStringNotContainsString('\\', $encoded);
        $this->assertStringNotContainsString(basename($root), $encoded);

        // The account name travels only as a hash prefix, never as a value.
        $this->assertNotContains(get_current_user(), array_values($check['detail']));
    }

    public function testHostingLayoutLeavesTheDocumentRootFlagNullWhenTheServerDoesNotNameOne(): void
    {
        $root = Support::tmpDir('layout');
        $this->dirs[] = $root;

        $previous = $_SERVER['DOCUMENT_ROOT'] ?? null;
        unset($_SERVER['DOCUMENT_ROOT']);

        try {
            $check = (new Health())->hostingLayout($root);
        } finally {
            if ($previous !== null) {
                $_SERVER['DOCUMENT_ROOT'] = $previous;
            }
        }

        $this->assertSame('ok', $check['status']);
        $this->assertNull($check['detail']['docroot_is_project_root']);
    }

    public function testHostingLayoutIsSentOnlyWhenAProjectRootIsKnown(): void
    {
        $root = Support::tmpDir('layout');
        $this->dirs[] = $root;

        $this->assertContains('hosting_layout', array_column((new Health())->level1Checks($root), 'id'));
        $this->assertNotContains('hosting_layout', array_column((new Health())->level1Checks(null), 'id'));
        $this->assertContains('os_release', array_column((new Health())->level1Checks(null), 'id'));
    }

    public function testOsReleaseTakesOnlyTheIdAndTheVersionId(): void
    {
        $content = implode("\n", [
            'PRETTY_NAME="Ubuntu 22.04.4 LTS"',
            'NAME="Ubuntu"',
            'VERSION_ID="22.04"',
            'VERSION="22.04.4 LTS (Jammy Jellyfish)"',
            'VERSION_CODENAME=jammy',
            'ID=ubuntu',
            'ID_LIKE=debian',
            'BUILD_ID=secret-build',
            'VARIANT_ID=server',
            'HOME_URL="https://www.ubuntu.com/"',
        ]);

        $this->assertSame(['id' => 'ubuntu', 'version_id' => '22.04'], Health::parseOsRelease($content));
        $this->assertSame(['id' => 'almalinux', 'version_id' => '9.4'], Health::parseOsRelease("ID=\"AlmaLinux\"\r\nVERSION_ID='9.4'\r\n"));
    }

    public function testOsReleaseWithoutAVersionIdKeepsTheIdAndWithoutAnIdIsNothing(): void
    {
        $this->assertSame(['id' => 'arch', 'version_id' => null], Health::parseOsRelease("NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n"));
        $this->assertNull(Health::parseOsRelease("NAME=Something\nID_LIKE=debian\nVERSION_ID=12\n"));
        $this->assertNull(Health::parseOsRelease(''));
    }

    public function testOsReleaseDropsAValueOutsideTheExpectedAlphabetInsteadOfSendingIt(): void
    {
        $this->assertNull(Health::parseOsRelease("ID=\"web01.example.test /srv\"\nVERSION_ID=12\n"));
        $this->assertNull(Health::parseOsRelease('ID='.str_repeat('a', 33)."\n"));
        $this->assertSame(['id' => 'debian', 'version_id' => null], Health::parseOsRelease("ID=debian\nVERSION_ID=\"12 (bookworm)\"\n"));
        $this->assertSame(['id' => 'debian', 'version_id' => null], Health::parseOsRelease("ID=debian\nVERSION_ID=".str_repeat('1', 17)."\n"));
    }

    public function testOsReleaseRowReadsTheFileAndSendsOnlyTheTwoValues(): void
    {
        $root = Support::tmpDir('osrelease');
        $this->dirs[] = $root;
        file_put_contents($root.'/os-release', "NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n");

        $check = (new Health())->osRelease($root.'/os-release');

        $this->assertSame([
            'id' => 'os_release',
            'status' => 'ok',
            'value' => 'debian 12',
            'detail' => ['id' => 'debian', 'version_id' => '12'],
        ], $check);

        file_put_contents($root.'/os-release', "ID=arch\n");
        $this->assertSame('arch', (new Health())->osRelease($root.'/os-release')['value']);

        file_put_contents($root.'/os-release', "NAME=Nothing\n");
        $this->assertSame(
            ['id' => 'os_release', 'status' => 'unknown', 'message' => 'msg.not_readable'],
            (new Health())->osRelease($root.'/os-release')
        );
    }

    public function testOsReleaseIsUnknownWhenTheFileCannotBeRead(): void
    {
        $root = Support::tmpDir('osrelease');
        $this->dirs[] = $root;

        $check = (new Health())->osRelease($root.'/missing');

        $this->assertSame('os_release', $check['id']);
        $this->assertSame('unknown', $check['status']);
        $this->assertSame(PHP_OS_FAMILY === 'Linux' ? 'msg.not_readable' : 'msg.unsupported_os', $check['message']);
        $this->assertArrayNotHasKey('value', $check);
    }

    public function testListeningPortsWatchesTheTwoUnauthenticatedServices(): void
    {
        $this->assertSame('docker_api', Health::WATCHED_SERVICES[2375]);
        $this->assertSame('etcd', Health::WATCHED_SERVICES[2379]);
        $this->assertSame(
            [2375, 2379, 3306, 5432, 6379, 9200, 11211, 27017],
            (static function (array $ports): array {
                sort($ports);

                return $ports;
            })(array_keys(Health::WATCHED_SERVICES))
        );
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
