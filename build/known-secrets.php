<?php

/**
 * Generates the list of truncated hashes the `secret_check` module compares
 * the application key with: src/data/known_secrets_laravel.bin.
 *
 * Each record is the first 6 bytes of the SHA-256 of one entry of a public
 * list of known Laravel application keys; records are deduplicated, sorted
 * and concatenated as raw bytes. The plain lists are never copied into
 * this repository: fetch them into a scratch directory and pass their
 * paths. The source, its licence and the commit the committed file was
 * built from are in src/data/NOTICE.
 *
 * Usage: php build/known-secrets.php <list-file> [<list-file> ...] [--out=<dir>]
 *
 * Normalisation: one APP_KEY per line as it stands in `.env` (the `base64:`
 * prefix is part of the entry). Surrounding whitespace is removed, empty
 * lines and lines starting with `#` are skipped. A line written as
 * `APP_KEY=value` or wrapped in quotes is kept as it is and also added as
 * the bare value.
 *
 * Prints counts and sizes only, never an entry.
 */

const SITETUS_KNOWN_SECRET_RECORD_BYTES = 6;

$inputs = [];
$outputDirectory = dirname(__DIR__).'/src/data';

foreach (array_slice($argv, 1) as $argument) {
    if (strpos($argument, '--out=') === 0 && strlen($argument) > 6) {
        $outputDirectory = rtrim(substr($argument, 6), '/\\');
    } elseif (strpos($argument, '--') === 0) {
        fwrite(STDERR, "Unknown option. Usage: php build/known-secrets.php <list-file> [<list-file> ...] [--out=<dir>]\n");
        exit(1);
    } else {
        $inputs[] = $argument;
    }
}

if ($inputs === []) {
    fwrite(STDERR, "At least one list file is required.\n");
    exit(1);
}

if (! is_dir($outputDirectory) && ! mkdir($outputDirectory, 0775, true)) {
    fwrite(STDERR, "Cannot create the output directory.\n");
    exit(1);
}

/**
 * @return array<int, string> the forms of one line that become records
 */
$forms = static function (string $line): array {
    $entry = trim($line);

    if ($entry === '' || $entry[0] === '#') {
        return [];
    }

    $forms = [$entry];
    $bare = strpos($entry, 'APP_KEY=') === 0 ? trim(substr($entry, 8)) : $entry;

    if (strlen($bare) >= 2 && ($bare[0] === '"' || $bare[0] === "'") && substr($bare, -1) === $bare[0]) {
        $bare = substr($bare, 1, -1);
    }

    if ($bare !== '' && $bare !== $entry) {
        $forms[] = $bare;
    }

    return $forms;
};

$records = [];
$lines = 0;
$entries = 0;

foreach ($inputs as $path) {
    $handle = @fopen($path, 'rb');

    if ($handle === false) {
        fwrite(STDERR, "Cannot read a list file.\n");
        exit(1);
    }

    while (($line = fgets($handle)) !== false) {
        $lines++;

        foreach ($forms($line) as $form) {
            $entries++;
            $records[substr(hash('sha256', $form, true), 0, SITETUS_KNOWN_SECRET_RECORD_BYTES)] = true;
        }
    }

    fclose($handle);
}

$records = array_map('strval', array_keys($records));
sort($records, SORT_STRING);

$data = implode('', $records);

if ($records === [] || file_put_contents($outputDirectory.'/known_secrets_laravel.bin', $data) !== strlen($data)) {
    fwrite(STDERR, "The lists produced no records or the output could not be written.\n");
    exit(1);
}

echo sprintf(
    "laravel: %d files, %d lines, %d entries, %d unique records, %d bytes, sha256 %s\n",
    count($inputs),
    $lines,
    $entries,
    count($records),
    strlen($data),
    hash('sha256', $data)
);
