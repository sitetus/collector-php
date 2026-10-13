<?php

namespace Sitetus\Collector;

/**
 * File-based nonce store: flock'ed JSON, replay window pruning,
 * capped at the most recent 1000 entries, plus the last-valid-request
 * timestamp used by sleep mode.
 *
 * 0.5.1 (audit 25.09): a nonce is kept for twice the clock-skew tolerance,
 * so a request whose timestamp is still acceptable can never be replayed
 * after its nonce was pruned; and a failed write denies the request
 * instead of silently accepting it with an empty store.
 */
final class NonceStore
{
    public const WINDOW_SECONDS = 2 * RequestVerifier::SKEW_SECONDS;

    public const MAX_ENTRIES = 1000;

    /** @var string */
    private $path;

    public function __construct(string $path)
    {
        $this->path = $path;
    }

    /**
     * Returns true when the nonce is fresh (recorded now); false on replay.
     * Null when the store cannot be written (spec: 403 nonce-store).
     */
    public function registerNonce(string $nonce, int $now): ?bool
    {
        $handle = @fopen($this->path, 'c+');

        if ($handle === false) {
            return null;
        }

        try {
            if (! flock($handle, LOCK_EX)) {
                return null;
            }

            $raw = stream_get_contents($handle);
            $data = is_string($raw) && $raw !== '' ? json_decode($raw, true) : null;

            if (! is_array($data)) {
                $data = ['last_valid' => null, 'nonces' => []];
            }

            $nonces = isset($data['nonces']) && is_array($data['nonces']) ? $data['nonces'] : [];

            // Prune entries outside the replay window.
            foreach ($nonces as $seen => $ts) {
                if ((int) $ts < $now - self::WINDOW_SECONDS) {
                    unset($nonces[$seen]);
                }
            }

            if (array_key_exists($nonce, $nonces)) {
                return false;
            }

            $nonces[$nonce] = $now;

            if (count($nonces) > self::MAX_ENTRIES) {
                asort($nonces);
                $nonces = array_slice($nonces, -self::MAX_ENTRIES, null, true);
            }

            $data['nonces'] = $nonces;
            $data['last_valid'] = $now;

            $json = json_encode($data);

            if (! is_string($json)) {
                return null;
            }

            if (! ftruncate($handle, 0) || ! rewind($handle)) {
                return null;
            }

            $written = fwrite($handle, $json);

            if ($written !== strlen($json) || ! fflush($handle)) {
                return null;
            }

            return true;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * Unix timestamp of the last valid signed request, or null when the store
     * does not exist yet (fresh installation).
     */
    public function lastValidRequestAt(): ?int
    {
        if (! is_file($this->path)) {
            return null;
        }

        $raw = @file_get_contents($this->path, false, null, 0, 262144);
        $data = is_string($raw) ? json_decode($raw, true) : null;

        if (! is_array($data) || ! isset($data['last_valid'])) {
            return null;
        }

        return (int) $data['last_valid'];
    }
}
