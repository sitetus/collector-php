<?php

namespace Sitetus\Collector;

/**
 * Verification order and responses (binding):
 *  1. signature present + project_key match + valid signature  → else 404
 *  2. expires_at passed / sleep mode                           → 404
 *  3. time window ±10 min                                      → 403 skew (+ server time)
 *  4. nonce replay / unwritable store                          → 403 nonce | nonce-store
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

    public function __construct(Config $config, NonceStore $nonceStore)
    {
        $this->config = $config;
        $this->nonceStore = $nonceStore;
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

        // 1. Signature gate — any failure is an anonymous 404.
        if ($signature === '' || $projectKey === '' || $timestamp === '' || $nonce === '') {
            return [404, []];
        }

        if (! hash_equals($this->config->projectKey, $projectKey)) {
            return [404, []];
        }

        if (! hash_equals($this->config->algo, $algo)) {
            return [404, []];
        }

        $material = self::signatureMaterial($method, $path, $projectKey, $timestamp, $nonce, $body);

        if (! $this->signatureValid($material, $signature)) {
            return [404, []];
        }

        // 2. Lifecycle: expired package or sleep mode. Sleep is
        //    permanent by design; the exit is a fresh package from the panel.
        if ($this->config->expiresAt !== null && $now >= $this->config->expiresAt) {
            return [404, []];
        }

        $lastValid = $this->nonceStore->lastValidRequestAt();

        if ($lastValid !== null && $now - $lastValid > self::SLEEP_AFTER_SECONDS) {
            return [404, []];
        }

        // 3. Time window.
        if (abs($now - (int) $timestamp) > self::SKEW_SECONDS) {
            return [403, [
                'X-Sitetus-Error' => 'skew',
                'X-Sitetus-Server-Time' => (string) $now,
            ]];
        }

        // 4. Nonce.
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
