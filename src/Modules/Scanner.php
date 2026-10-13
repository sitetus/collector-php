<?php

namespace Sitetus\Collector\Modules;

/**
 * Bounded, read-only directory walk shared by the opt-in modules.
 * Every walk has an entry budget, a depth cap and a wall-clock
 * budget so a huge tree can neither stall the customer's server nor
 * inflate the envelope. Names leave the server as relative paths under
 * the scanned root only, sanitised and capped (abuse rule).
 */
final class Scanner
{
    public const NAME_MAX_BYTES = 200;

    public const LIST_MAX = 50;

    /** @var int */
    private $maxEntries;

    /** @var int */
    private $maxDepth;

    /** @var float */
    private $budgetSeconds;

    /** @var float */
    private $startedAt;

    /** @var int */
    private $visited = 0;

    /** @var bool */
    private $exhausted = false;

    public function __construct(int $maxEntries, int $maxDepth, float $budgetSeconds)
    {
        $this->maxEntries = $maxEntries;
        $this->maxDepth = $maxDepth;
        $this->budgetSeconds = $budgetSeconds;
        $this->startedAt = microtime(true);
    }

    /**
     * Walks $root breadth-first; $visitor receives (absolute path,
     * relative path, is_dir). Directories listed in $skip (relative,
     * forward slashes) are not entered.
     *
     * @param array<int, string> $skip
     */
    public function walk(string $root, callable $visitor, array $skip = []): void
    {
        $root = rtrim($root, '/\\');

        if (! is_dir($root) || ! is_readable($root)) {
            return;
        }

        $queue = [['', 0]];
        $skipMap = array_fill_keys(array_map(function (string $path): string {
            return trim(str_replace('\\', '/', $path), '/');
        }, $skip), true);

        while ($queue !== []) {
            list($relative, $depth) = array_shift($queue);
            $directory = $relative === '' ? $root : $root.'/'.$relative;
            // Sorted on purpose: the envelope must list the same files in the same
            // order on every operating system.
            $entries = @scandir($directory, SCANDIR_SORT_ASCENDING);

            if ($entries === false) {
                continue;
            }

            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }

                if ($this->exhausted()) {
                    return;
                }

                $childRelative = $relative === '' ? $entry : $relative.'/'.$entry;

                // A skipped tree is skipped whole: its root is neither visited nor
                // descended into (storage/, vendor/, uploads/ are writable by design).
                if (isset($skipMap[$childRelative])) {
                    continue;
                }

                $this->visited++;
                $childAbsolute = $directory.'/'.$entry;
                $isDir = is_dir($childAbsolute) && ! is_link($childAbsolute);

                $visitor($childAbsolute, $childRelative, $isDir);

                if ($isDir && $depth + 1 < $this->maxDepth) {
                    $queue[] = [$childRelative, $depth + 1];
                }
            }
        }
    }

    public function exhausted(): bool
    {
        if (! $this->exhausted && ($this->visited >= $this->maxEntries || microtime(true) - $this->startedAt > $this->budgetSeconds)) {
            $this->exhausted = true;
        }

        return $this->exhausted;
    }

    public function visited(): int
    {
        return $this->visited;
    }

    /**
     * Relative path safe to transmit: forward slashes, printable characters
     * only, capped length. Never absolute, never outside the scanned root.
     */
    public static function safeName(string $relative): string
    {
        $name = str_replace('\\', '/', $relative);
        $name = (string) preg_replace('/[\x00-\x1F\x7F]/u', '?', $name);

        if (! mb_check_encoding($name, 'UTF-8')) {
            $name = (string) preg_replace('/[^\x20-\x7E]/', '?', $name);
        }

        if (strlen($name) > self::NAME_MAX_BYTES) {
            // "…" is three bytes; the result never exceeds NAME_MAX_BYTES.
            $name = mb_strcut($name, 0, self::NAME_MAX_BYTES - 3).'…';
        }

        return $name;
    }

    /**
     * Append a name to a capped list; returns false once the list is full
     * (the caller keeps counting but stops listing).
     *
     * @param array<int, mixed> $list
     * @param mixed $entry
     */
    public static function push(array &$list, $entry): bool
    {
        if (count($list) >= self::LIST_MAX) {
            return false;
        }

        $list[] = $entry;

        return true;
    }

    public static function extension(string $name): string
    {
        return strtolower((string) pathinfo($name, PATHINFO_EXTENSION));
    }
}
