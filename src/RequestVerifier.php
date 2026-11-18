<?php

namespace Sitetus\Collector;

/**
 * Verification order and responses (binding):
 *  1. a signature header missing / project_key mismatch         → 404
 *  2. the file's algorithm cannot be verified on this server    → 403 unsupported-algo (+ supported list)
 *  3. another algorithm requested / signature does not verify   → 403 signature
 *  4. expires_at passed / sleep mode                            → 404
 *  5. time window ±10 min                                       → 403 skew (+ server time)
 *  6. nonce replay / unwritable store                           → 403 nonce | nonce-store
 *
 * 0.7.4: steps 2 and 3 used to be an anonymous 404. They answer only a
 * caller that already sent the right project key, carry fixed words and
 * are decided before the nonce store is opened — a request without a valid
 * signature neither reads nor writes it.
 *
 * No request parameter is ever used as a path, command or include target.
 */
final class RequestVerifier
{
    public const SLEEP_AFTER_SECONDS = 7776000; // 90 gun

    public const SKEW_SECONDS = 600;

    /** @var Config */
    private $config;

    /** @var NonceStore */
    private $nonceStore;

    /** @var array<int, string> */
    private $supportedAlgos;

    /**
     * @param array<int, string>|null $supportedAlgos algorithms this server can verify; null = detect
     */
    public function __construct(Config $config, NonceStore $nonceStore, ?array $supportedAlgos = null)
    {
        $this->config = $config;
        $this->nonceStore = $nonceStore;
        $this->supportedAlgos = $supportedAlgos !== null ? array_values($supportedAlgos) : self::supportedAlgorithms();
    }

    /**
     * The signature algorithms this PHP can verify: Ed25519 needs the sodium
     * extension, RSA-SHA256 needs openssl. Fixed names only.
     *
     * @return array<int, string>
     */
    public static function supportedAlgorithms(): array
    {
        $algos = [];

        if (function_exists('sodium_crypto_sign_verify_detached')) {
            $algos[] = 'ed25519';
        }

        if (function_exists('openssl_verify') && function_exists('openssl_pkey_get_public')) {
            $algos[] = 'rsa-sha256';
        }

        return $algos;
    }

    /**
     * @param array<string, string> $headers lower-cased header map
     * @return array{0: int, 1: array<string, string>} [status, extra headers]; status 200 = verified
     */
    public function verify(string $method, string $path, array $headers, string $body, int $now): array
    {
        $signature = isset($headers['x-sitetus-signature']) ? (string) $headers['x-sitetus-signature'] : '';
        $projectKey = isset($headers['x-sitetus-key']) ? (string) $headers['x-sitetus-key'] : '';
        $timestamp = isset($headers['x-sitetus-timestamp']) ? (string) $headers['x-sitetus-timestamp'] : '';
        $nonce = isset($headers['x-sitetus-nonce']) ? (string) $headers['x-sitetus-nonce'] : '';
        $algo = isset($headers['x-sitetus-algo']) ? (string) $headers['x-sitetus-algo'] : '';

        // 1. Anonymous gate — a missing header or another project key is a
        //    404 without a word, as if the file did not exist.
        if ($signature === '' || $projectKey === '' || $timestamp === '' || $nonce === '' || $algo === '') {
            return [404, []];
        }

        if (! hash_equals($this->config->projectKey, $projectKey)) {
            return [404, []];
        }

        // 2. Lifecycle: an expired package or sleep mode stays a 404 for
        //    everyone, the holder of the project key included. Sleep is
        //    permanent by design; the exit is a fresh package from the panel.
        if ($this->config->expiresAt !== null && $now >= $this->config->expiresAt) {
            return [404, []];
        }

        $lastValid = $this->nonceStore->lastValidRequestAt();

        if ($lastValid !== null && $now - $lastValid > self::SLEEP_AFTER_SECONDS) {
            return [404, []];
        }

        // 3. The caller knows the project key: say why the signature cannot
        //    be accepted. Fixed words only, and nothing is written to the
        //    nonce store until the signature has verified.
        if (! in_array($this->config->algo, $this->supportedAlgos, true)) {
            return [403, [
                'X-Sitetus-Error' => 'unsupported-algo',
                'X-Sitetus-Supports' => implode(',', $this->supportedAlgos),
            ]];
        }

        // 4. Signature.
        if (! hash_equals($this->config->algo, $algo)) {
            return [403, ['X-Sitetus-Error' => 'signature']];
        }

        $material = self::signatureMaterial($method, $path, $projectKey, $timestamp, $nonce, $body);

        if (! $this->signatureValid($material, $signature)) {
            return [403, ['X-Sitetus-Error' => 'signature']];
        }

        // 5. Time window.
        if (abs($now - (int) $timestamp) > self::SKEW_SECONDS) {
            return [403, [
                'X-Sitetus-Error' => 'skew',
                'X-Sitetus-Server-Time' => (string) $now,
            ]];
        }

        // 6. Nonce.
        $fresh = $this->nonceStore->registerNonce($nonce, $now);

        if ($fresh === null) {
            return [403, ['X-Sitetus-Error' => 'nonce-store']];
        }

        if ($fresh === false) {
            return [403, ['X-Sitetus-Error' => 'nonce']];
        }

        return [200, []];
    }

    public static function signatureMaterial(
        string $method,
        string $path,
        string $projectKey,
        string $timestamp,
        string $nonce,
        string $body
    ): string {
        return $method."\n".$path."\n".$projectKey."\n".$timestamp."\n".$nonce."\n".hash('sha256', $body);
    }

    private function signatureValid(string $material, string $signatureBase64): bool
    {
        $signature = base64_decode($signatureBase64, true);

        if ($signature === false) {
            return false;
        }

        if ($this->config->algo === 'ed25519') {
            if (! function_exists('sodium_crypto_sign_verify_detached')) {
                return false;
            }

            $publicKey = base64_decode($this->config->publicKey, true);

            if ($publicKey === false || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                return false;
            }

            try {
                return sodium_crypto_sign_verify_detached($signature, $material, $publicKey);
            } catch (\Throwable $exception) {
                return false;
            }
        }

        if ($this->config->algo === 'rsa-sha256') {
            if (! function_exists('openssl_verify')) {
                return false;
            }

            $key = @openssl_pkey_get_public($this->config->publicKey);

            if ($key === false) {
                return false;
            }

            return openssl_verify($material, $signature, $key, OPENSSL_ALGO_SHA256) === 1;
        }

        return false;
    }
}
