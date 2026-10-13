<?php

namespace Sitetus\Collector\Modules;

/**
 * Module `files` — file integrity and web-shell trace. Read-only,
 * stat-based:
 *  - mtime + size of a fixed per-framework list of sensitive files;
 *  - executable or double-extension files and PHP control files inside
 *    upload directories; 0.6.1: a control file's first 4 KB are read
 *    locally and only a class leaves — `enabling` (makes PHP run),
 *    `protective` (deny / engine off only) or `unknown`;
 *  - extension/content mismatch: the first 64 bytes of image/document
 *    uploads are read locally and ONLY a flag leaves the server;
 *  - a hash + count of the web root's PHP file set and the names of PHP
 *    files modified in the last 7 days (bounded), so the panel can tell
 *    "new PHP file, no deploy" without the collector keeping state.
 */
final class FileTrace
{
    public const ID = 'files';

    private const EXECUTABLE = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'cgi', 'pl', 'sh', 'py'];

    private const CONTROL_FILES = ['.htaccess', '.user.ini', 'web.config', 'php.ini'];

    private const CONTENT_CHECK = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'pdf', 'ico', 'bmp'];

    private const RECENT_DAYS = 7;

    private const CONTENT_SCAN_MAX_FILES = 2000;

    private const CONTENT_SCAN_BYTES = 8192;

    private const CONTROL_READ_BYTES = 4096;

    /**
     * .user.ini / php.ini keys that make PHP run something of the uploader's
     * choosing (or lift a guard); any other key is treated as harmless.
     *
     * @var array<int, string>
     */
    private const INI_ENABLING_KEYS = ['auto_prepend_file', 'auto_append_file', 'allow_url_include', 'disable_functions'];

    /**
     * @var array<int, string>
     */
    private const SUSPICIOUS_PATTERNS = [
        '/\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|convert_uu)\s*\(/i',
        '/\b(?:eval|assert)\s*\(\s*(?:@\s*)?\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b/i',
        '/\$_(?:POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/i',
        '/\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*(?:@\s*)?\$_(?:POST|GET|REQUEST|COOKIE)\b/i',
        '/\bpreg_replace\s*\(\s*["\'][^"\']*\/[a-z]*e[a-z]*["\']/i',
        '/\bcreate_function\s*\(\s*["\']["\']\s*,\s*(?:base64_decode|gzinflate|str_rot13)/i',
        '/[A-Za-z0-9+\/]{800,}={0,2}/',
    ];

    /**
     * @return array<string, mixed>
     */
    public function run(string $root, string $webRoot, string $framework, int $now): array
    {
        $result = [
            'tracked' => $this->tracked($root, $framework),
            'uploads' => $this->uploads($root, $framework),
            'php_files' => $this->phpFiles($webRoot, $now),
        ];

        return $result;
    }

    /**
     * @return array<int, array{id: string, exists: bool, mtime?: int, size?: int}>
     */
    private function tracked(string $root, string $framework): array
    {
        $list = [];

        foreach ($this->trackedPaths($framework) as $id => $relative) {
            $path = $root.'/'.$relative;
            $stat = is_file($path) ? @stat($path) : false;

            if ($stat === false) {
                $list[] = ['id' => $id, 'exists' => false];

                continue;
            }

            $list[] = ['id' => $id, 'exists' => true, 'mtime' => (int) $stat['mtime'], 'size' => (int) $stat['size']];
        }

        return $list;
    }

    /**
     * @return array<string, string> id => relative path under the project root
     */
    private function trackedPaths(string $framework): array
    {
        if ($framework === 'laravel') {
            return [
                'public_index' => 'public/index.php',
                'public_htaccess' => 'public/.htaccess',
                'env' => '.env',
                'composer_lock' => 'composer.lock',
                'vendor_autoload' => 'vendor/autoload.php',
                'bootstrap_app' => 'bootstrap/app.php',
                'git_head' => '.git/HEAD',
            ];
        }

        if ($framework === 'wordpress') {
            return [
                'index' => 'index.php',
                'htaccess' => '.htaccess',
                'wp_config' => 'wp-config.php',
                'wp_settings' => 'wp-settings.php',
                'wp_version' => 'wp-includes/version.php',
                'wp_load' => 'wp-load.php',
            ];
        }

        return [
            'index' => 'index.php',
            'htaccess' => '.htaccess',
            'composer_lock' => 'composer.lock',
            'git_head' => '.git/HEAD',
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function uploads(string $root, string $framework): array
    {
        $executable = [];
        $control = ['enabling' => [], 'unknown' => []];
        $mismatch = [];
        $counts = ['executable' => 0, 'enabling' => 0, 'protective' => 0, 'unknown' => 0, 'mismatch' => 0];
        $scanner = new Scanner(20000, 8, 3.0);
        $scanned = [];

        foreach ($this->uploadDirectories($framework) as $relativeDir) {
            $directory = $root.'/'.$relativeDir;

            if (! is_dir($directory)) {
                continue;
            }

            $scanned[] = $relativeDir;

            $scanner->walk($directory, function (string $absolute, string $relative, bool $isDir) use (&$executable, &$control, &$mismatch, &$counts, $relativeDir): void {
                if ($isDir) {
                    return;
                }

                $name = Scanner::safeName($relativeDir.'/'.$relative);
                $base = strtolower(basename($relative));
                $extension = Scanner::extension($relative);

                if (in_array($base, self::CONTROL_FILES, true)) {
                    $class = $this->classifyControlFile($absolute, $base);
                    $counts[$class]++;

                    if ($class !== 'protective') {
                        Scanner::push($control[$class], $name);
                    }

                    return;
                }

                if (in_array($extension, self::EXECUTABLE, true) || $this->hasExecutableInnerExtension($base)) {
                    $counts['executable']++;
                    Scanner::push($executable, $name);

                    return;
                }

                if (in_array($extension, self::CONTENT_CHECK, true) && $this->looksLikeCode($absolute)) {
                    $counts['mismatch']++;
                    Scanner::push($mismatch, $name);
                }
            });
        }

        // `count`/`names` keep their pre-0.6.1 meaning for older panels, now
        // narrowed to what is still worth a look: enabling + unknown.
        return [
            'directories' => $scanned,
            'executable' => ['count' => $counts['executable'], 'names' => $executable],
            'control_files' => [
                'count' => $counts['enabling'] + $counts['unknown'],
                'names' => array_slice(array_merge($control['enabling'], $control['unknown']), 0, Scanner::LIST_MAX),
                'enabling' => ['count' => $counts['enabling'], 'names' => $control['enabling']],
                'protective' => ['count' => $counts['protective']],
                'unknown' => ['count' => $counts['unknown'], 'names' => $control['unknown']],
            ],
            'content_mismatch' => ['count' => $counts['mismatch'], 'names' => $mismatch],
            'budget_exhausted' => $scanner->exhausted(),
        ];
    }

    /**
     * 0.6.1: what a control file found under an uploads directory does.
     * WooCommerce, Wordfence, Sucuri and many hosts drop PROTECTIVE
     * `.htaccess` files there (deny from all, engine off); only a file that
     * makes PHP run — or one we cannot read through — is worth the panel's
     * attention. At most the first 4 KB are read, locally; the content
     * never leaves. A file longer than that is `unknown` unless its head
     * already enables execution.
     *
     * @return string enabling|protective|unknown
     */
    private function classifyControlFile(string $absolute, string $base): string
    {
        if (! @is_file($absolute) || @is_link($absolute)) {
            return 'unknown';
        }

        $handle = @fopen($absolute, 'rb');

        if ($handle === false) {
            return 'unknown';
        }

        $head = (string) fread($handle, self::CONTROL_READ_BYTES);
        fclose($handle);

        $truncated = (int) @filesize($absolute) > self::CONTROL_READ_BYTES;

        if ($base === 'web.config') {
            $class = $this->classifyIisConfig($head);
        } elseif ($base === '.user.ini' || $base === 'php.ini') {
            $class = $this->classifyIni($head);
        } else {
            $class = $this->classifyApacheConfig($head);
        }

        return $truncated && $class !== 'enabling' ? 'unknown' : $class;
    }

    /**
     * Apache `.htaccess`: enabling when a handler/type/engine/prepend/CGI
     * or rewrite-to-PHP directive is present; protective when only deny,
     * engine-off, handler-removal or `-ExecCGI`/`-Indexes` rules are.
     * Comment-only or unrecognised directives → unknown.
     */
    private function classifyApacheConfig(string $text): string
    {
        $enabling = false;
        $protective = false;

        foreach (preg_split('/\r\n|\r|\n/', $text) ?: [] as $line) {
            $line = trim($line);

            if ($line === '' || $line[0] === '#') {
                continue;
            }

            if (preg_match('/^(?:AddHandler|AddType|SetHandler)\b.*\bphp/i', $line) === 1
                || preg_match('/^AddHandler\s+cgi-script\b/i', $line) === 1
                || preg_match('/^php_flag\s+engine\s+on\b/i', $line) === 1
                || preg_match('/^php_(?:admin_)?(?:value|flag)\s+auto_(?:prepend|append)_file\s+\S/i', $line) === 1
                || preg_match('/^php_(?:admin_)?flag\s+allow_url_include\s+on\b/i', $line) === 1) {
                $enabling = true;

                continue;
            }

            if (preg_match('/^(?:deny\s+from\s+all|require\s+all\s+denied)\b/i', $line) === 1
                || preg_match('/^php_flag\s+engine\s+off\b/i', $line) === 1
                || preg_match('/^Remove(?:Handler|Type)\b.*\bphp/i', $line) === 1
                || preg_match('/^SetHandler\s+(?:default-handler|none)\b/i', $line) === 1) {
                $protective = true;

                continue;
            }

            if (preg_match('/^Options\b(.*)$/i', $line, $match) === 1) {
                foreach (preg_split('/\s+/', trim($match[1])) ?: [] as $option) {
                    if (preg_match('/^\+?ExecCGI$/i', $option) === 1) {
                        $enabling = true;
                    } elseif (preg_match('/^-(?:ExecCGI|Indexes)$/i', $option) === 1) {
                        $protective = true;
                    }
                }

                continue;
            }

            if (preg_match('/^RewriteRule\s+\S+\s+(\S+)(?:\s+\[([^\]]*)\])?/i', $line, $match) === 1) {
                $flags = strtoupper($match[2] ?? '');

                if (preg_match('/(?:^|,)(?:F|G|R=403|R=404|R=410)(?:,|$)/', $flags) === 1) {
                    $protective = true;
                } elseif (stripos($match[1], '.php') !== false) {
                    $enabling = true;
                }
            }
        }

        if ($enabling) {
            return 'enabling';
        }

        return $protective ? 'protective' : 'unknown';
    }

    /**
     * IIS `web.config`: a handler mapping that runs PHP (or any `*.php`
     * path mapping) is enabling; request filtering that denies, a
     * `<deny users="*">` rule or a handler removal is protective.
     */
    private function classifyIisConfig(string $text): string
    {
        $text = (string) preg_replace('/<!--.*?(?:-->|$)/s', '', $text);
        $handlers = '';

        if (preg_match('/<handlers\b(.*?)(?:<\/handlers>|$)/is', $text, $match) === 1) {
            $handlers = $match[1];
        }

        if (preg_match('/<add\b[^>]*\bpath\s*=\s*["\'][^"\']*\.php["\']/i', $text) === 1
            || ($handlers !== '' && preg_match('/<add\b[^>]*php/i', $handlers) === 1)) {
            return 'enabling';
        }

        $filtering = '';

        if (preg_match('/<requestFiltering\b(.*?)(?:<\/requestFiltering>|$)/is', $text, $match) === 1) {
            $filtering = $match[1];
        }

        if (preg_match('/<deny\b[^>]*\busers\s*=\s*["\']\*["\']/i', $text) === 1
            || ($filtering !== '' && preg_match('/\ballow(?:ed|Unlisted)\s*=\s*["\']false["\']/i', $filtering) === 1)
            || ($handlers !== '' && preg_match('/<(?:remove\b[^>]*php|clear\b)/i', $handlers) === 1)) {
            return 'protective';
        }

        return 'unknown';
    }

    /**
     * `.user.ini` / `php.ini`: a prepend/append file, `allow_url_include`
     * switched on or any `disable_functions` line is enabling; a file that
     * only carries other keys (upload_max_filesize, engine = off, …) is
     * harmless; no directive at all → unknown.
     */
    private function classifyIni(string $text): string
    {
        $directives = 0;

        foreach (preg_split('/\r\n|\r|\n/', $text) ?: [] as $line) {
            $line = trim($line);

            if ($line === '' || $line[0] === ';' || $line[0] === '#' || $line[0] === '[') {
                continue;
            }

            if (preg_match('/^([A-Za-z0-9_.]+)\s*=\s*(.*)$/', $line, $match) !== 1) {
                continue;
            }

            $directives++;
            $key = strtolower($match[1]);
            $value = strtolower(trim($match[2], " \t\"'"));

            if (! in_array($key, self::INI_ENABLING_KEYS, true)) {
                continue;
            }

            if ($key === 'allow_url_include' && ! in_array($value, ['1', 'on', 'true', 'yes'], true)) {
                continue;
            }

            if (($key === 'auto_prepend_file' || $key === 'auto_append_file') && $value === '') {
                continue;
            }

            return 'enabling';
        }

        return $directives > 0 ? 'protective' : 'unknown';
    }

    /**
     * @return array<int, string>
     */
    private function uploadDirectories(string $framework): array
    {
        if ($framework === 'laravel') {
            return ['storage/app/public', 'public/storage', 'public/uploads', 'public/upload', 'public/media'];
        }

        if ($framework === 'wordpress') {
            return ['wp-content/uploads'];
        }

        return ['uploads', 'upload', 'files', 'media', 'public/uploads'];
    }

    /**
     * "resim.jpg.php" is caught by the extension; "shell.php.jpg" is the
     * double-extension trick some servers still execute.
     */
    private function hasExecutableInnerExtension(string $base): bool
    {
        $parts = explode('.', $base);

        if (count($parts) < 3) {
            return false;
        }

        foreach (array_slice($parts, 1, -1) as $inner) {
            if (in_array($inner, self::EXECUTABLE, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Only the first 64 bytes are read, locally; nothing of them is sent.
     */
    private function looksLikeCode(string $absolute): bool
    {
        // 0.5.1: never open anything but a regular file — a FIFO would block the pull.
        if (! @is_file($absolute) || @is_link($absolute)) {
            return false;
        }

        $handle = @fopen($absolute, 'rb');

        if ($handle === false) {
            return false;
        }

        $head = (string) fread($handle, 64);
        fclose($handle);

        $trimmed = ltrim($head, "\xEF\xBB\xBF \t\r\n");

        return strncmp($trimmed, '<?php', 5) === 0
            || strncmp($trimmed, '<?=', 3) === 0
            || strncmp($trimmed, '<script', 7) === 0
            || strncmp($trimmed, '#!', 2) === 0;
    }

    /**
     * @return array<string, mixed>
     */
    private function phpFiles(string $webRoot, int $now): array
    {
        $scanner = new Scanner(20000, 6, 3.0);
        $count = 0;
        $recent = [];
        $recentCount = 0;
        $suspicious = [];
        $suspiciousCount = 0;
        $inspected = 0;
        $fingerprint = hash_init('sha256');
        $threshold = $now - self::RECENT_DAYS * 86400;

        $scanner->walk($webRoot, function (string $absolute, string $relative, bool $isDir) use (&$count, &$recent, &$recentCount, &$suspicious, &$suspiciousCount, &$inspected, $fingerprint, $threshold): void {
            if ($isDir || ! in_array(Scanner::extension($relative), self::EXECUTABLE, true)) {
                return;
            }

            $mtime = (int) @filemtime($absolute);
            $count++;
            hash_update($fingerprint, $relative.'|'.$mtime."\n");

            if ($mtime >= $threshold) {
                $recentCount++;
                Scanner::push($recent, ['name' => Scanner::safeName($relative), 'mtime' => $mtime]);
            }

            // 0.4.0: web-shell / injected-code signatures in the head and
            // tail of the file (read locally, only a name leaves).
            if ($inspected < self::CONTENT_SCAN_MAX_FILES) {
                $inspected++;

                if ($this->hasSuspiciousCode($absolute)) {
                    $suspiciousCount++;
                    Scanner::push($suspicious, Scanner::safeName($relative));
                }
            }
        }, ['vendor', 'node_modules', '.git']);

        return [
            'count' => $count,
            'set_hash' => hash_final($fingerprint),
            'recent' => ['count' => $recentCount, 'names' => $recent],
            'suspicious' => ['count' => $suspiciousCount, 'names' => $suspicious, 'inspected' => $inspected],
            'budget_exhausted' => $scanner->exhausted(),
        ];
    }

    /**
     * The classic obfuscated-shell shapes: eval/assert over a decoder
     * (base64/gzinflate/str_rot13/strrev), request-driven variable
     * functions or shell calls, preg_replace /e, create_function, and
     * very long base64 blobs. First and last 8 KB only.
     */
    private function hasSuspiciousCode(string $absolute): bool
    {
        // 0.5.1: regular files only (a FIFO would block the pull).
        if (! @is_file($absolute) || @is_link($absolute)) {
            return false;
        }

        $size = (int) @filesize($absolute);
        $handle = @fopen($absolute, 'rb');

        if ($handle === false) {
            return false;
        }

        $sample = (string) fread($handle, self::CONTENT_SCAN_BYTES);

        if ($size > self::CONTENT_SCAN_BYTES * 2) {
            @fseek($handle, -self::CONTENT_SCAN_BYTES, SEEK_END);
            $sample .= "\n".(string) fread($handle, self::CONTENT_SCAN_BYTES);
        } elseif ($size > self::CONTENT_SCAN_BYTES) {
            $sample .= (string) fread($handle, self::CONTENT_SCAN_BYTES);
        }

        fclose($handle);

        foreach (self::SUSPICIOUS_PATTERNS as $pattern) {
            if (preg_match($pattern, $sample) === 1) {
                return true;
            }
        }

        return false;
    }
}
