<?php

namespace Sitetus\Collector\Modules;

/**
 * Module `secret_check` — is the application key one that is already
 * public (a framework or product default, a key from a tutorial, a key
 * published in a public repository)? Off unless the installation selected
 * it; a file built without it holds neither this code nor its list.
 * Laravel only: it needs the booted application.
 *
 * The comparison happens on this server. The only configuration value read
 * for its content is `app.key`: it is hashed in memory (SHA-256) and the
 * first 6 bytes are looked up in a sorted list of such truncated hashes.
 * The list holds no key. What travels is one yes/no. Never sent, logged,
 * stored or put in a message: the key, its length, its hash or any part of
 * its hash.
 *
 * `app.key` is compared exactly as configured, `base64:` prefix included:
 * that is the form the public lists hold. The decoded key bytes are not
 * hashed.
 *
 * The single file carries the list inside this module's block
 * (SecretCheckData, written by the build); the source tree reads
 * src/data/known_secrets_laravel.bin. See src/data/NOTICE for the source.
 */
final class SecretCheck
{
    public const ID = 'secret_check';

    public const RECORD_BYTES = 6;

    /** @var string|null */
    private $dataFile;

    /**
     * @param string|null $dataFile the list file; null = the embedded list, or src/data
     */
    public function __construct(?string $dataFile = null)
    {
        $this->dataFile = $dataFile;
    }

    /**
     * @param mixed $app the booted application (any container exposing make()), or null
     * @return array<string, mixed>
     */
    public function run($app): array
    {
        if (! is_object($app)) {
            return ['unsupported' => 'no_application'];
        }

        // A list that cannot be read is not a "no": say so instead.
        $data = $this->data();

        if ($data === null) {
            return ['unsupported' => 'no_data'];
        }

        try {
            $appKey = $app->make('config')->get('app.key');
        } catch (\Throwable $exception) {
            return ['unsupported' => 'no_config'];
        }

        if (! is_string($appKey) || $appKey === '') {
            return ['unsupported' => 'no_secret'];
        }

        return ['public' => ['app_key' => self::contains($data, $appKey)]];
    }

    /**
     * Binary search for the secret's record in a sorted list of 6-byte
     * records. A list that is empty or not a whole number of records
     * matches nothing.
     */
    public static function contains(string $data, string $secret): bool
    {
        if ($secret === '' || $data === '' || strlen($data) % self::RECORD_BYTES !== 0) {
            return false;
        }

        $needle = substr(hash('sha256', $secret, true), 0, self::RECORD_BYTES);
        $low = 0;
        $high = intdiv(strlen($data), self::RECORD_BYTES) - 1;

        while ($low <= $high) {
            $middle = intdiv($low + $high, 2);
            $order = strcmp(substr($data, $middle * self::RECORD_BYTES, self::RECORD_BYTES), $needle);

            if ($order === 0) {
                return true;
            }

            if ($order < 0) {
                $low = $middle + 1;
            } else {
                $high = $middle - 1;
            }
        }

        return false;
    }

    /**
     * The list, or null when it is missing, empty or damaged.
     */
    private function data(): ?string
    {
        try {
            $embedded = __NAMESPACE__.'\\SecretCheckData';

            if ($this->dataFile === null && class_exists($embedded, false)) {
                $data = $embedded::get();
            } else {
                $path = $this->dataFile !== null ? $this->dataFile : dirname(__DIR__).'/data/known_secrets_laravel.bin';
                $data = is_file($path) ? @file_get_contents($path) : null;
            }
        } catch (\Throwable $exception) {
            return null;
        }

        if (! is_string($data) || $data === '' || strlen($data) % self::RECORD_BYTES !== 0) {
            return null;
        }

        return $data;
    }
}
