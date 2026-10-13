<?php

namespace Sitetus\Collector\Modules;

/**
 * Module `bot_traffic` — did the AI crawlers actually come?
 * Reads the TAIL of the newest readable web-server access log (≤ 20 MB,
 * combined/common log format) locally and reports, per vendor-documented
 * AI bot, only counters: requests, last seen (unix), and how many of them
 * got 2xx / 403-429 / other. No URL, no IP, no user-agent string leaves
 * the server. robots.txt says "allowed"; this says "they showed up" —
 * and whether the edge sent them away. Counts go by the User-Agent
 * token, which is spoofable; the panel labels them so.
 */
final class BotTraffic
{
    public const ID = 'bot_traffic';

    public const TAIL_BYTES = 20971520;

    public const MAX_LINES = 400000;

    public const BUDGET_SECONDS = 2.5;

    /**
     * 0.5.1 (audit 25.09): log discovery is bounded too — at most this many
     * files are examined, within the same time budget as the read itself.
     */
    public const MAX_CANDIDATE_FILES = 200;

    public const MAX_LINE_BYTES = 16384;

    /**
     * Envelope keys use underscores (panel validator: [a-z0-9_]); the panel
     * maps them back to the documented User-Agent tokens.
     *
     * @var array<string, string> envelope key => user-agent token (lower-case)
     */
    public const BOTS = [
        'oai_searchbot' => 'oai-searchbot',
        'chatgpt_user' => 'chatgpt-user',
        'gptbot' => 'gptbot',
        'claude_searchbot' => 'claude-searchbot',
        'claude_user' => 'claude-user',
        'claudebot' => 'claudebot',
        'googlebot' => 'googlebot',
        'google_extended' => 'google-extended',
        'bingbot' => 'bingbot',
        'perplexitybot' => 'perplexitybot',
        'perplexity_user' => 'perplexity-user',
        'applebot' => 'applebot',
        'applebot_extended' => 'applebot-extended',
        // 0.5.2: Meta's index crawler and Amazon's search / user fetchers (providers' pages, 29.09.2026).
        'meta_webindexer' => 'meta-webindexer',
        'meta_externalfetcher' => 'meta-externalfetcher',
        'meta_externalagent' => 'meta-externalagent',
        'amzn_searchbot' => 'amzn-searchbot',
        'amzn_user' => 'amzn-user',
        'amazonbot' => 'amazonbot',
        'ccbot' => 'ccbot',
        // 0.7.1: Google's browsing agent, DuckDuckGo's answer crawler, Mistral's three bots (providers' pages, 03.10.2026).
        'google_agent' => 'google-agent',
        'duckassistbot' => 'duckassistbot',
        'mistralai_index' => 'mistralai-index',
        'mistralai_user' => 'mistralai-user',
        'mistralai_training' => 'mistralai-training',
    ];

    /**
     * @return array<string, mixed>
     */
    public function run(string $root, int $now): array
    {
        $started = microtime(true);
        $log = $this->newestReadableLog($root, $started);

        if ($log === null) {
            return ['unsupported' => 'no_log'];
        }

        $handle = @fopen($log['path'], 'rb');

        if ($handle === false) {
            return ['unsupported' => 'no_log'];
        }

        $size = (int) @filesize($log['path']);

        if ($size > self::TAIL_BYTES) {
            @fseek($handle, -self::TAIL_BYTES, SEEK_END);
            @fgets($handle, self::MAX_LINE_BYTES); // drop the partial first line
        }

        $lines = 0;
        $oldest = null;
        $newest = null;
        $bots = [];

        while (($line = fgets($handle, self::MAX_LINE_BYTES)) !== false) {
            $lines++;

            if ($lines > self::MAX_LINES || (microtime(true) - $started) > self::BUDGET_SECONDS) {
                break;
            }

            $parsed = $this->parse($line);

            if ($parsed === null) {
                continue;
            }

            if ($parsed['time'] !== null) {
                $oldest = $oldest === null ? $parsed['time'] : min($oldest, $parsed['time']);
                $newest = $newest === null ? $parsed['time'] : max($newest, $parsed['time']);
            }

            $key = $this->botKey($parsed['agent']);

            if ($key === null) {
                continue;
            }

            $bots[$key] ??= ['requests' => 0, 'ok' => 0, 'blocked' => 0, 'other' => 0, 'last_seen' => 0];
            $bots[$key]['requests']++;

            if ($parsed['status'] >= 200 && $parsed['status'] < 400) {
                $bots[$key]['ok']++;
            } elseif (in_array($parsed['status'], [401, 403, 429, 503], true)) {
                $bots[$key]['blocked']++;
            } else {
                $bots[$key]['other']++;
            }

            if ($parsed['time'] !== null && $parsed['time'] > $bots[$key]['last_seen']) {
                $bots[$key]['last_seen'] = $parsed['time'];
            }
        }

        fclose($handle);
        ksort($bots);

        return [
            'source' => $log['kind'],
            'lines' => $lines,
            'from' => $oldest,
            'to' => $newest,
            'window_days' => $oldest !== null && $newest !== null ? (int) max(1, ceil(($newest - $oldest) / 86400)) : 0,
            'bots' => $bots,
        ];
    }

    /**
     * Common candidate locations (project-relative first, then the usual
     * shared-hosting and system paths); the newest readable file wins.
     * Only a location CLASS is reported, never the path.
     *
     * @return array{path: string, kind: string}|null
     */
    private function newestReadableLog(string $root, float $started): ?array
    {
        // 0.5.1: exactly the documented locations — the account's own
        // log folders, never the parent of the home directory.
        $home = dirname($root);
        $candidates = [
            'project' => [$root.'/storage/logs/access.log', $root.'/logs/access.log', $root.'/logs/access_log', $root.'/log/access.log'],
            'hosting' => [$home.'/logs', $home.'/access-logs', $home.'/access_logs', $home.'/domains/*/logs'],
            'system' => ['/var/log/nginx/access.log', '/var/log/apache2/access.log', '/var/log/httpd/access_log', '/var/log/apache2/other_vhosts_access.log'],
        ];

        $best = null;
        $examined = 0;

        foreach ($candidates as $kind => $paths) {
            foreach ($paths as $pattern) {
                $expanded = strpos($pattern, '*') !== false ? (function_exists('glob') ? (@glob($pattern, GLOB_ONLYDIR) ?: []) : []) : [$pattern];

                foreach ($expanded as $path) {
                    $files = @is_dir($path) ? (function_exists('glob') ? (@glob(rtrim($path, '/').'/*') ?: []) : []) : [$path];

                    foreach ($files as $file) {
                        if (++$examined > self::MAX_CANDIDATE_FILES || (microtime(true) - $started) > self::BUDGET_SECONDS) {
                            return $best === null ? null : ['path' => $best['path'], 'kind' => $best['kind']];
                        }

                        if (! @is_file($file) || ! @is_readable($file) || ! $this->looksLikeAccessLog($file)) {
                            continue;
                        }

                        $mtime = (int) @filemtime($file);

                        if ($best === null || $mtime > $best['mtime']) {
                            $best = ['path' => $file, 'kind' => $kind, 'mtime' => $mtime];
                        }
                    }
                }
            }
        }

        return $best === null ? null : ['path' => $best['path'], 'kind' => $best['kind']];
    }

    private function looksLikeAccessLog(string $file): bool
    {
        $name = strtolower(basename($file));

        if (preg_match('/\.(gz|zip|bz2|xz)$/', $name) === 1 || strpos($name, 'error') !== false) {
            return false;
        }

        if (strpos($name, 'access') === false && preg_match('/\.log$/', $name) !== 1 && strpos($name, '_log') === false) {
            return false;
        }

        $handle = @fopen($file, 'rb');

        if ($handle === false) {
            return false;
        }

        $head = (string) fread($handle, 512);
        fclose($handle);

        return $this->parse(strtok($head, "\n") ?: '') !== null;
    }

    /**
     * Combined / common log format: ip - - [time] "METHOD path HTTP/x" status bytes "referer" "agent".
     *
     * @return array{time: int|null, status: int, agent: string}|null
     */
    private function parse(string $line): ?array
    {
        if (preg_match('/^\S+ \S+ \S+ \[([^\]]+)\] "[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?/', $line, $match) !== 1) {
            return null;
        }

        $time = null;
        $parsedTime = \DateTime::createFromFormat('d/M/Y:H:i:s O', $match[1]);

        if ($parsedTime instanceof \DateTime) {
            $time = $parsedTime->getTimestamp();
        }

        return ['time' => $time, 'status' => (int) $match[2], 'agent' => strtolower($match[3] ?? '')];
    }

    private function botKey(string $agent): ?string
    {
        if ($agent === '') {
            return null;
        }

        // Most specific token first (e.g. applebot-extended before applebot; Amazon's two
        // fetchers before amazonbot, whose name also sits in their documentation address;
        // 0.7.1: google-agent before googlebot and Mistral's three suffixed tokens first).
        foreach (['applebot_extended', 'google_extended', 'google_agent', 'meta_webindexer', 'meta_externalfetcher', 'meta_externalagent', 'amzn_searchbot', 'amzn_user', 'perplexity_user', 'claude_searchbot', 'claude_user', 'oai_searchbot', 'chatgpt_user', 'mistralai_index', 'mistralai_user', 'mistralai_training'] as $key) {
            if (strpos($agent, self::BOTS[$key]) !== false) {
                return $key;
            }
        }

        foreach (self::BOTS as $key => $token) {
            if (strpos($agent, $token) !== false) {
                return $key;
            }
        }

        return null;
    }
}
