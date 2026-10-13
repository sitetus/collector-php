<?php

namespace Sitetus\Collector\Modules;

/**
 * Module `archives` — forgotten backups and database dumps inside the
 * web root. Anything under the web root is downloadable by
 * whoever guesses the name, so the panel treats a hit as a finding.
 * Depth 2, bounded walk, names + sizes only.
 */
final class ArchiveScan
{
    public const ID = 'archives';

    private const EXTENSIONS = ['zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'rar', '7z', 'sql', 'bak', 'old', 'orig', 'dump'];

    /**
     * @return array<string, mixed>
     */
    public function run(string $webRoot): array
    {
        $scanner = new Scanner(5000, 2, 2.0);
        $names = [];
        $count = 0;
        $bytes = 0;

        $scanner->walk($webRoot, function (string $absolute, string $relative, bool $isDir) use (&$names, &$count, &$bytes): void {
            if ($isDir || ! $this->isArchive($relative)) {
                return;
            }

            $size = (int) @filesize($absolute);
            $count++;
            $bytes += $size;
            Scanner::push($names, ['name' => Scanner::safeName($relative), 'size' => $size]);
        }, ['vendor', 'node_modules', '.git']);

        return [
            'count' => $count,
            'bytes' => $bytes,
            'names' => $names,
            'budget_exhausted' => $scanner->exhausted(),
        ];
    }

    private function isArchive(string $relative): bool
    {
        $lower = strtolower($relative);

        if (substr($lower, -7) === '.sql.gz' || substr($lower, -8) === '.sql.zip' || substr($lower, -7) === '.tar.gz') {
            return true;
        }

        return in_array(Scanner::extension($relative), self::EXTENSIONS, true);
    }
}
