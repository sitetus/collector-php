<?php

namespace Sitetus\Collector\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sitetus\Collector\Config;
use Sitetus\Collector\Modules\ModuleRunner;
use Sitetus\Collector\Modules\Scanner;
use Sitetus\Collector\Tests\Support;

/**
 * Opt-in modules are read-only, bounded and name-safe.
 */
final class ModulesTest extends TestCase
{
    /** @var array<int, string> */
    private $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            Support::removeDir($dir);
        }
    }

    private function laravelProject(): string
    {
        $root = Support::tmpDir('modproject');
        $this->dirs[] = $root;

        foreach (['public', 'storage/app/public/2026', 'bootstrap', 'vendor', 'public/uploads'] as $dir) {
            mkdir($root.'/'.$dir, 0777, true);
        }

        file_put_contents($root.'/artisan', '');
        file_put_contents($root.'/bootstrap/app.php', '<?php');
        file_put_contents($root.'/composer.lock', '{"packages":[]}');
        file_put_contents($root.'/.env', 'APP_KEY=x');
        file_put_contents($root.'/vendor/autoload.php', '<?php');
        file_put_contents($root.'/public/index.php', '<?php echo 1;');
        file_put_contents($root.'/public/.htaccess', 'RewriteEngine On');
        // 0.4.0: an injected web shell in the web root — obfuscated eval.
        file_put_contents($root.'/public/wp-cache.php', '<?php $x = "c2hlbGw="; @eval(base64_decode($_POST["k"]) . $x);');
        // Upload-directory threats: a shell, a double extension, a control
        // file and a "png" that starts with PHP code; one genuine image.
        file_put_contents($root.'/storage/app/public/2026/shell.php', '<?php system($_GET["c"]);');
        file_put_contents($root.'/storage/app/public/2026/resim.php.jpg', 'GIF89a');
        file_put_contents($root.'/storage/app/public/.htaccess', 'AddType application/x-httpd-php .png');
        file_put_contents($root.'/storage/app/public/2026/kapak.png', "<?php echo 'x';");
        file_put_contents($root.'/storage/app/public/2026/gercek.png', "\x89PNG\r\n\x1a\n");
        // Archives in the web root (downloadable) and outside it (not scanned).
        file_put_contents($root.'/public/site-backup.zip', 'PK');
        file_put_contents($root.'/public/uploads/dump.sql.gz', 'x');
        file_put_contents($root.'/storage/old.zip', 'PK');

        return $root;
    }

    private function configWithModules(string $root, string $modules): Config
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

    public function testConfigParsesModuleListAndIgnoresPlaceholder(): void
    {
        $root = $this->laravelProject();

        $this->assertSame(['files', 'archives'], $this->configWithModules($root, ' files, archives ,')->modules);
        $this->assertSame([], $this->configWithModules($root, '{{MODULES}}')->modules);
        $this->assertSame([], $this->configWithModules($root, 'files;drop')->modules);
    }

    public function testNoModuleEnabledMeansNoSection(): void
    {
        $root = $this->laravelProject();

        $runner = new ModuleRunner($this->configWithModules($root, ''));

        $this->assertNull($runner->run($root, ['detected' => 'laravel'], time()));
    }

    public function testFileTraceReportsSensitiveFilesUploadThreatsAndPhpSet(): void
    {
        $root = $this->laravelProject();
        $section = (new ModuleRunner($this->configWithModules($root, 'files')))->run($root, ['detected' => 'laravel'], time());

        $this->assertSame(['files'], $section['enabled']);
        $this->assertSame('public', $section['web_root']);

        $tracked = [];

        foreach ($section['files']['tracked'] as $entry) {
            $tracked[$entry['id']] = $entry;
        }

        $this->assertTrue($tracked['public_index']['exists']);
        $this->assertSame(13, $tracked['public_index']['size']);
        $this->assertFalse($tracked['git_head']['exists']);
        $this->assertArrayNotHasKey('content', $tracked['env']);

        $uploads = $section['files']['uploads'];
        $this->assertContains('storage/app/public', $uploads['directories']);
        $this->assertSame(2, $uploads['executable']['count']);
        $this->assertContains('storage/app/public/2026/shell.php', $uploads['executable']['names']);
        $this->assertContains('storage/app/public/2026/resim.php.jpg', $uploads['executable']['names']);
        $this->assertSame(1, $uploads['control_files']['count']);
        $this->assertSame(['storage/app/public/.htaccess'], $uploads['control_files']['names']);
        // 0.6.1: the AddType file makes PHP run → enabling; nothing protective or unreadable here.
        $this->assertSame(['count' => 1, 'names' => ['storage/app/public/.htaccess']], $uploads['control_files']['enabling']);
        $this->assertSame(['count' => 0], $uploads['control_files']['protective']);
        $this->assertSame(['count' => 0, 'names' => []], $uploads['control_files']['unknown']);
        $this->assertSame(1, $uploads['content_mismatch']['count']);
        $this->assertSame(['storage/app/public/2026/kapak.png'], $uploads['content_mismatch']['names']);
        $this->assertFalse($uploads['budget_exhausted']);

        // Web root PHP set: public/index.php + the planted shell (uploads live under storage/).
        $this->assertSame(2, $section['files']['php_files']['count']);
        $this->assertSame(64, strlen($section['files']['php_files']['set_hash']));
        $this->assertSame(2, $section['files']['php_files']['recent']['count']);
        // 0.4.0: only the shell matches a web-shell signature; the name leaves, never the content.
        $this->assertSame(1, $section['files']['php_files']['suspicious']['count']);
        $this->assertSame(['wp-cache.php'], $section['files']['php_files']['suspicious']['names']);
        $this->assertSame(2, $section['files']['php_files']['suspicious']['inspected']);
        $this->assertStringNotContainsString('base64', json_encode($section));
    }

    /**
     * 0.6.1: WooCommerce, Wordfence, Sucuri and hosts drop protective
     * control files under uploads; only the ones that make PHP run (or
     * cannot be read through) stay in count/names. Content never leaves.
     */
    public function testFileTraceClassifiesUploadControlFilesByWhatTheyDo(): void
    {
        $root = Support::tmpDir('wpproject');
        $this->dirs[] = $root;
        $uploads = $root.'/wp-content/uploads';

        foreach (['woocommerce_uploads', 'wflogs', 'sucuri', '2026/09', '2026/08', 'cache', 'big', 'ini'] as $dir) {
            mkdir($uploads.'/'.$dir, 0777, true);
        }

        mkdir($root.'/wp-includes', 0777, true);
        file_put_contents($root.'/index.php', '<?php');
        file_put_contents($root.'/wp-config.php', '<?php');
        file_put_contents($root.'/wp-includes/version.php', '<?php');

        // Protective: WooCommerce-style deny, Wordfence-style nested deny,
        // Sucuri-style IIS deny, a .user.ini with only harmless keys.
        file_put_contents($uploads.'/woocommerce_uploads/.htaccess', "Options -Indexes\ndeny from all\n");
        file_put_contents($uploads.'/wflogs/.htaccess', "<Files \"*\">\n  <IfModule mod_access.c>\n    Deny from all\n  </IfModule>\n  <IfModule !mod_access_compat>\n    <IfModule mod_authz_host.c>\n      Deny from all\n    </IfModule>\n  </IfModule>\n  <IfModule mod_access_compat>\n    Deny from all\n  </IfModule>\n</Files>\n");
        file_put_contents($uploads.'/sucuri/web.config', "<?xml version=\"1.0\"?>\n<configuration>\n  <system.webServer>\n    <security>\n      <authorization>\n        <deny users=\"*\" />\n      </authorization>\n    </security>\n  </system.webServer>\n</configuration>\n");
        file_put_contents($uploads.'/ini/.user.ini', "upload_max_filesize = 64M\npost_max_size = 64M\n");

        // Enabling: a handler that runs PHP for images, a prepend file, an IIS handler mapping.
        file_put_contents($uploads.'/2026/09/.htaccess', "# make jpg executable\nAddHandler application/x-httpd-php .jpg\n");
        file_put_contents($uploads.'/2026/09/.user.ini', "auto_prepend_file = /home/site/wp-content/uploads/2026/09/x.jpg\n");
        file_put_contents($uploads.'/2026/08/web.config', "<configuration>\n  <system.webServer>\n    <handlers>\n      <add name=\"PHP_via_FastCGI\" path=\"*.jpg\" verb=\"*\" modules=\"FastCgiModule\" scriptProcessor=\"C:\\php\\php-cgi.exe\" />\n    </handlers>\n  </system.webServer>\n</configuration>\n");

        // Unknown: comment-only, and a deny file too long to read through.
        file_put_contents($uploads.'/cache/.htaccess', "# generated by the cache plugin\n\n");
        file_put_contents($uploads.'/big/.htaccess', "deny from all\n".str_repeat("# padding\n", 600));

        $section = (new ModuleRunner($this->configWithModules($root, 'files')))->run($root, ['detected' => 'wordpress'], time());
        $control = $section['files']['uploads']['control_files'];

        $this->assertSame(3, $control['enabling']['count']);
        $this->assertSame(['wp-content/uploads/2026/08/web.config', 'wp-content/uploads/2026/09/.htaccess', 'wp-content/uploads/2026/09/.user.ini'], $control['enabling']['names']);
        $this->assertSame(['count' => 4], $control['protective']);
        $this->assertSame(2, $control['unknown']['count']);
        $this->assertSame(['wp-content/uploads/big/.htaccess', 'wp-content/uploads/cache/.htaccess'], $control['unknown']['names']);
        // Backward-compatible count/names = what is still worth a look.
        $this->assertSame(5, $control['count']);
        $this->assertSame(array_merge($control['enabling']['names'], $control['unknown']['names']), $control['names']);
        $this->assertSame(0, $section['files']['uploads']['executable']['count']);

        $json = json_encode($section);
        $this->assertStringNotContainsString('deny from all', $json);
        $this->assertStringNotContainsString('auto_prepend_file', $json);
        $this->assertStringNotContainsString('FastCgiModule', $json);
    }

    public function testArchiveScanSeesOnlyTheWebRoot(): void
    {
        $root = $this->laravelProject();
        $section = (new ModuleRunner($this->configWithModules($root, 'archives')))->run($root, ['detected' => 'laravel'], time());

        $names = array_column($section['archives']['names'], 'name');
        sort($names);

        $this->assertSame(2, $section['archives']['count']);
        $this->assertSame(['site-backup.zip', 'uploads/dump.sql.gz'], $names);
        $this->assertNotContains('old.zip', $names);
    }

    public function testPermissionScanFlagsWorldWritableEntriesOutsideWritableTrees(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $root = $this->laravelProject();
            $section = (new ModuleRunner($this->configWithModules($root, 'permissions')))->run($root, ['detected' => 'laravel'], time());

            $this->assertTrue($section['permissions']['unsupported']);

            return;
        }

        $root = $this->laravelProject();
        mkdir($root.'/app', 0777);
        file_put_contents($root.'/app/Kernel.php', '<?php');
        chmod($root.'/app', 0777);
        chmod($root.'/app/Kernel.php', 0666);
        chmod($root.'/storage', 0777);
        chmod($root.'/bootstrap', 0755);

        $section = (new ModuleRunner($this->configWithModules($root, 'permissions')))->run($root, ['detected' => 'laravel'], time());
        $names = array_column($section['permissions']['names'], 'name');

        $this->assertFalse($section['permissions']['unsupported']);
        $this->assertContains('app', $names);
        $this->assertContains('app/Kernel.php', $names);
        $this->assertNotContains('storage', $names);
        $this->assertSame(1, $section['permissions']['world_writable']['php_files']);
    }

    public function testBotTrafficCountsDocumentedAiBotsFromTheAccessLogTail(): void
    {
        $root = $this->laravelProject();
        mkdir($root.'/storage/logs', 0777, true);
        $lines = [
            '203.0.113.5 - - [15/Sep/2026:08:00:01 +0000] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot"',
            '203.0.113.5 - - [15/Sep/2026:08:00:02 +0000] "GET /hakkimizda HTTP/1.1" 403 12 "-" "Mozilla/5.0 (compatible; OAI-SearchBot/1.0)"',
            '198.51.100.7 - - [16/Sep/2026:09:10:00 +0000] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)"',
            '198.51.100.9 - - [16/Sep/2026:09:11:00 +0000] "GET / HTTP/1.1" 429 0 "-" "GPTBot/1.2 (+https://openai.com/gptbot)"',
            '198.51.100.9 - - [16/Sep/2026:09:12:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 Applebot-Extended"',
            '192.0.2.1 - - [16/Sep/2026:09:13:00 +0000] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/128.0"',
            // 0.5.2: Amazon's search fetcher names amazonbot in its address and is still counted as itself.
            '192.0.2.8 - - [16/Sep/2026:09:14:00 +0000] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; Amzn-SearchBot/0.1; +https://developer.amazon.com/amazonbot)"',
            '192.0.2.9 - - [16/Sep/2026:09:15:00 +0000] "GET / HTTP/1.1" 403 12 "-" "Mozilla/5.0 (compatible; Amzn-User/0.1)"',
            '192.0.2.10 - - [16/Sep/2026:09:16:00 +0000] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)"',
            '192.0.2.11 - - [16/Sep/2026:09:17:00 +0000] "GET / HTTP/1.1" 200 5123 "-" "meta-webindexer/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)"',
            // 0.7.1: Google's browsing agent is counted as itself even when its address names googlebot;
            // DuckDuckGo's answer crawler and Mistral's three suffixed bots each land on their own key.
            '192.0.2.12 - - [16/Sep/2026:09:18:00 +0000] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; Google-Agent/1.0; +https://developers.google.com/search/docs/crawling-indexing/googlebot)"',
            '192.0.2.13 - - [16/Sep/2026:09:19:00 +0000] "GET / HTTP/1.1" 403 12 "-" "Mozilla/5.0 (compatible; DuckAssistBot/1.0; +http://duckduckgo.com/duckassistbot.html)"',
            '192.0.2.14 - - [16/Sep/2026:09:20:00 +0000] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; MistralAI-Index/1.0; +https://docs.mistral.ai/robots)"',
            '192.0.2.15 - - [16/Sep/2026:09:21:00 +0000] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (compatible; MistralAI-User/1.0; +https://docs.mistral.ai/robots)"',
            '192.0.2.16 - - [16/Sep/2026:09:22:00 +0000] "GET / HTTP/1.1" 429 0 "-" "Mozilla/5.0 (compatible; MistralAI-Training/1.0; +https://docs.mistral.ai/robots)"',
            'garbage line that is not a log entry',
        ];
        file_put_contents($root.'/storage/logs/access.log', implode("\n", $lines)."\n");

        $section = (new ModuleRunner($this->configWithModules($root, 'bot_traffic')))->run($root, ['detected' => 'laravel'], time());
        $traffic = $section['bot_traffic'];

        $this->assertSame('project', $traffic['source']);
        $this->assertSame(16, $traffic['lines']);
        $this->assertSame(2, $traffic['window_days']);
        $this->assertSame(['requests' => 2, 'ok' => 1, 'blocked' => 1, 'other' => 0, 'last_seen' => 1789459202], $traffic['bots']['oai_searchbot']);
        $this->assertSame(1, $traffic['bots']['perplexitybot']['requests']);
        $this->assertSame(1, $traffic['bots']['gptbot']['blocked']);
        $this->assertSame(1, $traffic['bots']['applebot_extended']['requests']);
        $this->assertArrayNotHasKey('applebot', $traffic['bots']);
        $this->assertSame(1, $traffic['bots']['amzn_searchbot']['requests']);
        $this->assertSame(1, $traffic['bots']['amzn_user']['blocked']);
        $this->assertSame(1, $traffic['bots']['amazonbot']['requests']);
        $this->assertSame(1, $traffic['bots']['meta_webindexer']['requests']);
        $this->assertSame(1, $traffic['bots']['google_agent']['requests']);
        $this->assertArrayNotHasKey('googlebot', $traffic['bots']);
        $this->assertSame(1, $traffic['bots']['duckassistbot']['blocked']);
        $this->assertSame(1, $traffic['bots']['mistralai_index']['ok']);
        $this->assertSame(1, $traffic['bots']['mistralai_user']['ok']);
        $this->assertSame(1, $traffic['bots']['mistralai_training']['blocked']);
        $this->assertCount(25, \Sitetus\Collector\Modules\BotTraffic::BOTS);
        // Only counters leave: no IP, path or user-agent string anywhere in the section.
        $this->assertStringNotContainsString('203.0.113.5', json_encode($section));
        $this->assertStringNotContainsString('hakkimizda', json_encode($section));
        $this->assertStringNotContainsString('Mozilla', json_encode($section));

        // No readable access log → honest unsupported.
        $bare = Support::tmpDir('nolog');
        $this->dirs[] = $bare;
        $this->assertSame(['unsupported' => 'no_log'], (new \Sitetus\Collector\Modules\BotTraffic())->run($bare, time()));
    }

    public function testMissingModuleCodeReportsUnavailable(): void
    {
        $root = $this->laravelProject();
        $config = $this->configWithModules($root, 'files,archives');
        // A build without the archives block: simulate by asking the runner
        // for a module the class map cannot resolve.
        $runner = new ModuleRunner($config);
        $section = $runner->run($root, ['detected' => 'laravel'], time());

        $this->assertArrayHasKey('archives', $section);
        $this->assertArrayHasKey('files', $section);
    }

    public function testNamesAreSanitisedAndListsCapped(): void
    {
        $this->assertSame('a/b?c', Scanner::safeName("a\\b\x01c"));

        $long = Scanner::safeName(str_repeat('x', 300));
        $this->assertLessThanOrEqual(Scanner::NAME_MAX_BYTES, strlen($long));
        $this->assertStringEndsWith('…', $long);

        $list = [];

        for ($i = 0; $i < 60; $i++) {
            Scanner::push($list, $i);
        }

        $this->assertCount(Scanner::LIST_MAX, $list);
    }

    public function testStrippedBuildStillRunsAndReportsUnavailable(): void
    {
        $root = $this->laravelProject();
        $dist = dirname(__DIR__, 2).'/dist/index.php';

        if (! is_file($dist)) {
            $this->markTestSkipped('dist/index.php not built');
        }

        $source = (string) file_get_contents($dist);
        $stripped = (string) preg_replace('/\/\* SITETUS_MODULE_START:archives \*\/.*?\/\* SITETUS_MODULE_END:archives \*\/\n?/s', '', $source);
        $stripped = str_replace("'{{MODULES}}'", "'files,archives'", $stripped);
        $stripped = str_replace('(new Collector(Config::fromArray($__sitetusConfig, __DIR__)))->handle();', '', $stripped);

        $this->assertStringNotContainsString('final class ArchiveScan', $stripped);
        $this->assertStringContainsString('final class FileTrace', $stripped);

        $lint = tempnam(sys_get_temp_dir(), 'sitetus');
        file_put_contents($lint, $stripped);
        exec(escapeshellarg(PHP_BINARY).' -l '.escapeshellarg($lint).' 2>&1', $output, $exit);
        unlink($lint);

        $this->assertSame(0, $exit, implode("\n", $output));
    }
}
