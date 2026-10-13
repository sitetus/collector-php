<?php

/**
 * Single-file build: concatenates src/ classes into dist/index.php
 * with the configuration placeholder block. The panel's package builder
 * replaces the {{...}} placeholders per installation; the dist file itself
 * contains no secrets and no installation identity.
 *
 * Usage: php build/build.php [output]
 */

$root = dirname(__DIR__);
$output = $argv[1] ?? $root.'/dist/index.php';

$classFiles = [
    'Config.php',
    'NonceStore.php',
    'RequestVerifier.php',
    'Inventory.php',
    'Health.php',
    'Level2.php',
    'Envelope.php',
    'Modules/Scanner.php',
    'Modules/ModuleRunner.php',
    'Collector.php',
];

/*
 * Opt-in modules are wrapped in SITETUS_MODULE markers: the panel
 * removes the block of every module the installation did not select, so
 * the delivered file physically contains only what it may run.
 */
$moduleFiles = [
    'files' => 'Modules/FileTrace.php',
    'archives' => 'Modules/ArchiveScan.php',
    'permissions' => 'Modules/PermissionScan.php',
    'bot_traffic' => 'Modules/BotTraffic.php',
];

$strip = function (string $file) use ($root): string {
    $source = file_get_contents($root.'/src/'.$file);

    if ($source === false) {
        fwrite(STDERR, "Missing source file: {$file}\n");
        exit(1);
    }

    // Strip the opening tag and the namespace declaration; the build wraps
    // everything in a single namespace block. Module classes live in the
    // Modules sub-namespace in src/, flattened here.
    $source = preg_replace('/^<\?php\s+/', '', $source);
    $source = preg_replace('/^namespace\s+Sitetus\\\\Collector(\\\\Modules)?;\s*/m', '', $source);
    $source = preg_replace('/^use\s+Sitetus\\\\Collector\\\\[A-Za-z\\\\]+;\s*/m', '', $source);

    return trim($source);
};

$sections = [];

foreach ($classFiles as $file) {
    $sections[] = $strip($file);
}

foreach ($moduleFiles as $id => $file) {
    $sections[] = "/* SITETUS_MODULE_START:{$id} */\n".$strip($file)."\n/* SITETUS_MODULE_END:{$id} */";
}

$header = <<<'PHP'
<?php
/**
 * Sitetus Collector — tek dosya derlemesi.
 *
 * Bu dosya salt-okunurdur: panelden gelen imzali istege JSON zarfla yanit
 * verir, baska hicbir sey yapmaz. Kaynak kod ve yapmayacaklar listesi:
 * https://github.com/sitetus/collector-php
 *
 * Bu kurulumun yapabildikleri: envanter + saglik bayraklari (her zaman)
 * ve yalniz asagidaki 'modules' listesindeki secmeli modüller. Listede
 * olmayan modülün kodu bu dosyada YOKTUR; panel dosyaya kod gonderemez.
 * Dosyanin SHA-256 parmak izi panelde "Kurulum ozellikleri" altinda
 * gorunur ve her cekimde dogrulanir.
 *
 * Build: {{BUILD_VERSION}} · Bu dosyayi elle duzenlemeyin.
 */

namespace Sitetus\Collector;

/* SITETUS_CONFIG_START */
$__sitetusConfig = array(
    'project_key' => '{{PROJECT_KEY}}',
    'public_key' => '{{PUBLIC_KEY}}',
    'algo' => '{{ALGO}}',
    'expires_at' => '{{EXPIRES_AT}}',
    'root_override' => '{{ROOT_OVERRIDE}}',
    'nonce_file' => '{{NONCE_FILE}}',
    'modules' => '{{MODULES}}',
);
/* SITETUS_CONFIG_END */

PHP;

$footer = <<<'PHP'

if (PHP_SAPI !== 'cli' && (!defined('SITETUS_COLLECTOR_NO_RUN') || !SITETUS_COLLECTOR_NO_RUN)) {
    (new Collector(Config::fromArray($__sitetusConfig, __DIR__)))->handle();
}
PHP;

$content = $header."\n".implode("\n\n", $sections)."\n".$footer."\n";
$content = str_replace('{{BUILD_VERSION}}', \date('Y-m-d').'-dev', $content);

if (! is_dir(dirname($output))) {
    mkdir(dirname($output), 0775, true);
}

file_put_contents($output, $content);

// Syntax check the artifact.
exec(escapeshellarg(PHP_BINARY).' -l '.escapeshellarg($output).' 2>&1', $lintOutput, $lintExit);

if ($lintExit !== 0) {
    fwrite(STDERR, implode("\n", $lintOutput)."\n");
    exit(1);
}

echo 'Built '.$output.' ('.strlen($content)." bytes)\n";
echo 'SHA-256: '.hash_file('sha256', $output)."\n";
