<?php

namespace Sitetus\Collector\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sitetus\Collector\Config;
use Sitetus\Collector\Envelope;
use Sitetus\Collector\Level2;
use Sitetus\Collector\Modules\ModuleRunner;
use Sitetus\Collector\Modules\SecretCheck;
use Sitetus\Collector\Tests\Support;

/**
 * 0.7.5 opt-in module `secret_check`: is the application key an entry of a
 * public list of known keys? The key is hashed and looked up on the server
 * in a list of truncated hashes; one yes/no travels. Off unless selected;
 * it needs the booted application, handed to the module runner. Every key
 * here is made up (see tests/fixtures/known-secrets); no entry of a real
 * list appears. The key, its length and its hash never reach the envelope.
 */
final class SecretCheckModuleTest extends TestCase
{
    private const LISTED_APP_KEY = 'base64:made-up-listed-app-key-not-a-real-one-0000=';

    private const UNLISTED_APP_KEY = 'base64:made-up-private-app-key-not-on-any-list-00=';

    /** @var array<int, string> */
    private $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            Support::removeDir($dir);
        }
    }

    public function testGeneratorWritesSortedDeduplicatedSixByteRecords(): void
    {
        $directory = Support::tmpDir('known');
        $this->dirs[] = $directory;
        $repo = dirname(__DIR__, 2);

        exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg($repo.'/build/known-secrets.php')
            .' '.escapeshellarg($repo.'/tests/fixtures/known-secrets/laravel.txt')
            .' '.escapeshellarg('--out='.$directory).' 2>&1', $lines, $exit);
        $output = implode("\n", $lines);

        $this->assertSame(0, $exit, $output);

        // Trimmed, comment and empty line skipped, the duplicate folded, the
        // APP_KEY="..." line kept as written and as the bare value.
        $this->assertSame($this->records([
            'base64:made-up-fixture-key-one-not-a-real-key-000=',
            'base64:made-up-fixture-key-two-not-a-real-key-000=',
            'MadeUpFixtureLegacyKeyNotARealOne',
            'APP_KEY="base64:made-up-fixture-key-three-not-real-key-00="',
            'base64:made-up-fixture-key-three-not-real-key-00=',
        ]), (string) file_get_contents($directory.'/known_secrets_laravel.bin'));

        $this->assertStringContainsString('laravel: 1 files, 7 lines, 6 entries, 5 unique records, 30 bytes', $output);
        $this->assertStringNotContainsString('made-up', $output);
    }

    public function testGeneratorRefusesToRunWithoutAList(): void
    {
        $directory = Support::tmpDir('known');
        $this->dirs[] = $directory;

        exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg(dirname(__DIR__, 2).'/build/known-secrets.php')
            .' '.escapeshellarg('--out='.$directory).' 2>&1', $lines, $exit);

        $this->assertSame(1, $exit);
        $this->assertFileDoesNotExist($directory.'/known_secrets_laravel.bin');
    }

    public function testLookupFindsEveryRecordAndNothingElse(): void
    {
        $values = [];

        for ($i = 0; $i < 257; $i++) {
            $values[] = 'made-up-value-'.$i;
        }

        $data = $this->records($values);

        // Either end and everything in between.
        foreach ($values as $value) {
            $this->assertTrue(SecretCheck::contains($data, $value));
        }

        for ($i = 257; $i < 400; $i++) {
            $this->assertFalse(SecretCheck::contains($data, 'made-up-value-'.$i));
        }

        // The prefix is part of the entry, and so is every byte.
        $one = $this->records([self::LISTED_APP_KEY]);

        $this->assertTrue(SecretCheck::contains($one, self::LISTED_APP_KEY));
        $this->assertFalse(SecretCheck::contains($one, substr(self::LISTED_APP_KEY, strlen('base64:'))));
        $this->assertFalse(SecretCheck::contains($one, self::LISTED_APP_KEY.' '));
        $this->assertFalse(SecretCheck::contains($one, ''));
    }

    public function testEmptyOrDamagedDataMatchesNothing(): void
    {
        $this->assertFalse(SecretCheck::contains('', self::LISTED_APP_KEY));
        $this->assertFalse(SecretCheck::contains($this->records([self::LISTED_APP_KEY]).'x', self::LISTED_APP_KEY));
    }

    public function testCommittedListIsWholeStrictlyAscendingRecords(): void
    {
        $data = (string) file_get_contents(dirname(__DIR__, 2).'/src/data/known_secrets_laravel.bin');

        $this->assertSame(0, strlen($data) % SecretCheck::RECORD_BYTES);

        $records = str_split($data, SecretCheck::RECORD_BYTES);
        $sorted = array_values(array_unique($records));
        sort($sorted, SORT_STRING);

        $this->assertSame($sorted, $records);
        $this->assertFalse(SecretCheck::contains($data, self::UNLISTED_APP_KEY));
    }

    public function testListedKeyIsReportedAsPublic(): void
    {
        $section = $this->section('secret_check', $this->container(['app.key' => self::LISTED_APP_KEY]));

        $this->assertSame(['secret_check'], $section['enabled']);
        $this->assertSame(['public' => ['app_key' => true]], $section['secret_check']);
    }

    public function testUnlistedKeyIsReportedAsNotPublic(): void
    {
        $section = $this->section('secret_check', $this->container(['app.key' => self::UNLISTED_APP_KEY]));

        $this->assertSame(['public' => ['app_key' => false]], $section['secret_check']);
    }

    public function testCommittedListAnswersForAKeyOnNoList(): void
    {
        $root = $this->projectRoot();
        $section = (new ModuleRunner($this->config($root, 'secret_check')))
            ->run($root, ['detected' => 'laravel'], time(), $this->container(['app.key' => self::UNLISTED_APP_KEY]));

        $this->assertSame(['public' => ['app_key' => false]], $section['secret_check']);
    }

    /**
     * @dataProvider valuesThatAreNotAKey
     *
     * @param mixed $value
     */
    public function testKeyThatIsNotSetIsSaidWithOneWord($value): void
    {
        $section = $this->section('secret_check', $this->container(['app.key' => $value]));

        $this->assertSame(['unsupported' => 'no_secret'], $section['secret_check']);
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function valuesThatAreNotAKey(): array
    {
        return [
            'null' => [null],
            'empty string' => [''],
            'false' => [false],
            'integer' => [12345],
            'array' => [[self::LISTED_APP_KEY]],
            'object' => [new \stdClass()],
        ];
    }

    public function testJwtSecretIsNotRead(): void
    {
        $config = new class
        {
            /** @var array<int, string> */
            public $asked = [];

            /**
             * @param mixed $default
             * @return mixed
             */
            public function get(string $key, $default = null)
            {
                $this->asked[] = $key;

                return $key === 'app.key' ? 'base64:made-up-private-app-key-not-on-any-list-00=' : $default;
            }
        };

        $app = new class($config)
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
                return $this->config;
            }
        };

        $this->assertSame(['public' => ['app_key' => false]], (new SecretCheck($this->listFile()))->run($app));
        $this->assertSame(['app.key'], $config->asked);
    }

    public function testWithoutABootedApplicationThereIsNothingToCheck(): void
    {
        // Not Laravel, or the bootstrap failed: the runner is handed no application.
        $this->assertSame(['unsupported' => 'no_application'], $this->section('secret_check', null)['secret_check']);
        $this->assertSame(['unsupported' => 'no_application'], (new SecretCheck($this->listFile()))->run(null));
    }

    public function testUnreadableConfigurationIsSaidWithOneWordAndNoMessage(): void
    {
        $container = new class
        {
            /** @return mixed */
            public function make(string $abstract)
            {
                throw new \RuntimeException('made-up failure text that must not travel');
            }
        };

        $section = $this->section('secret_check', $container);

        $this->assertSame(['unsupported' => 'no_config'], $section['secret_check']);
        $this->assertStringNotContainsString('made-up failure', (string) json_encode($section));
    }

    public function testMissingOrDamagedListIsNeverAnsweredAsNotPublic(): void
    {
        $directory = Support::tmpDir('known');
        $this->dirs[] = $directory;
        $container = $this->container(['app.key' => self::LISTED_APP_KEY]);

        $this->assertSame(['unsupported' => 'no_data'], (new SecretCheck($directory.'/missing.bin'))->run($container));

        file_put_contents($directory.'/empty.bin', '');
        $this->assertSame(['unsupported' => 'no_data'], (new SecretCheck($directory.'/empty.bin'))->run($container));

        file_put_contents($directory.'/damaged.bin', $this->records([self::LISTED_APP_KEY]).'x');
        $this->assertSame(['unsupported' => 'no_data'], (new SecretCheck($directory.'/damaged.bin'))->run($container));
    }

    public function testModuleIsOffUnlessSelected(): void
    {
        $container = $this->container(['app.key' => self::LISTED_APP_KEY]);
        $root = $this->projectRoot();

        // Nothing selected: no modules section at all.
        $this->assertSame([], Config::fromArray([], __DIR__)->modules);
        $this->assertNull((new ModuleRunner($this->config($root, '')))->run($root, ['detected' => 'laravel'], time(), $container));

        // Other modules selected: no secret_check key.
        $others = (new ModuleRunner($this->config($root, 'archives,permissions')))->run($root, ['detected' => 'laravel'], time(), $container);

        $this->assertSame(['archives', 'permissions'], $others['enabled']);
        $this->assertArrayNotHasKey('secret_check', $others);
        $this->assertStringNotContainsString('app_key', (string) json_encode($others));
    }

    /**
     * @dataProvider keysForTheLeakTest
     */
    public function testWholeEnvelopeCarriesNeitherTheKeyNorItsLengthNorItsHash(string $appKey, bool $expected): void
    {
        $container = $this->container(['app.key' => $appKey]);
        $root = $this->projectRoot();
        $config = $this->config($root, 'secret_check');

        $envelope = (new Envelope($config))->build(
            2,
            ['detected' => 'laravel'],
            null,
            (new Level2())->checksFromApp($container),
            null,
            'detected',
            [],
            microtime(true),
            __FILE__,
            [],
            ['enabled' => ['secret_check'], 'web_root' => 'public', 'secret_check' => (new SecretCheck($this->listFile()))->run($container)]
        );
        $encoded = (string) json_encode($envelope);

        // The section is fixed words and one boolean: no room for a length.
        $this->assertSame(['public' => ['app_key' => $expected]], $envelope['modules']['secret_check']);
        $this->assertSame('{"public":{"app_key":'.($expected ? 'true' : 'false').'}}', json_encode($envelope['modules']['secret_check']));

        // The key, or any 8 characters of it.
        $this->assertStringNotContainsString($appKey, $encoded);

        for ($offset = 0; $offset + 8 <= strlen($appKey); $offset++) {
            $this->assertStringNotContainsString(substr($appKey, $offset, 8), $encoded);
        }

        // Its SHA-256 (and the other digests one might reach for): no
        // window of 8 hex characters, in either case; the 6-byte record in
        // none of its spellings.
        foreach (['sha256', 'sha1', 'md5'] as $algorithm) {
            $hex = hash($algorithm, $appKey);

            for ($offset = 0; $offset + 8 <= strlen($hex); $offset++) {
                $this->assertStringNotContainsString(substr($hex, $offset, 8), $encoded);
                $this->assertStringNotContainsString(strtoupper(substr($hex, $offset, 8)), $encoded);
            }
        }

        $record = substr(hash('sha256', $appKey, true), 0, SecretCheck::RECORD_BYTES);

        $this->assertStringNotContainsString(base64_encode($record), $encoded);
        $this->assertStringNotContainsString(rtrim(strtr(base64_encode($record), '+/', '-_'), '='), $encoded);
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function keysForTheLeakTest(): array
    {
        return [
            'listed' => [self::LISTED_APP_KEY, true],
            'not listed' => [self::UNLISTED_APP_KEY, false],
        ];
    }

    /**
     * The modules section as the runner builds it; when there is an
     * application, the module answers from a made-up list in place of the
     * committed one.
     *
     * @param mixed $app
     * @return array<string, mixed>
     */
    private function section(string $modules, $app): array
    {
        $root = $this->projectRoot();
        $section = (new ModuleRunner($this->config($root, $modules)))->run($root, ['detected' => 'laravel'], time(), $app);

        $this->assertIsArray($section);

        if (is_object($app)) {
            $section['secret_check'] = (new SecretCheck($this->listFile()))->run($app);
        }

        return $section;
    }

    private function listFile(): string
    {
        $directory = Support::tmpDir('known');
        $this->dirs[] = $directory;

        file_put_contents($directory.'/list.bin', $this->records([
            self::LISTED_APP_KEY,
            'base64:made-up-second-listed-key-not-a-real-one-0=',
            'MadeUpThirdListedLegacyKeyNotReal',
        ]));

        return $directory.'/list.bin';
    }

    /**
     * The bytes of a list holding the given made-up values: first 6 bytes
     * of each SHA-256, deduplicated, sorted, concatenated.
     *
     * @param array<int, string> $values
     */
    private function records(array $values): string
    {
        $records = [];

        foreach ($values as $value) {
            $records[] = substr(hash('sha256', $value, true), 0, 6);
        }

        $records = array_values(array_unique($records));
        sort($records, SORT_STRING);

        return implode('', $records);
    }

    private function projectRoot(): string
    {
        $root = Support::tmpDir('secretcheck');
        $this->dirs[] = $root;
        mkdir($root.'/public', 0777, true);

        return $root;
    }

    private function config(string $root, string $modules): Config
    {
        return Config::fromArray([
            'project_key' => 'testproject12345678a',
            'public_key' => 'x',
            'algo' => 'ed25519',
            'expires_at' => '',
            'root_override' => '',
            'nonce_file' => '.nonce-test.json',
            'modules' => $modules,
        ], $root.'/public/r4nd0m');
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

                throw new \RuntimeException('no '.$abstract);
            }
        };
    }
}
