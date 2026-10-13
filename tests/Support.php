<?php

namespace Sitetus\Collector\Tests;

use Sitetus\Collector\Config;
use Sitetus\Collector\RequestVerifier;

/**
 * Shared helpers for collector tests (PHP 7.4 compatible).
 */
final class Support
{
    public static function tmpDir(string $name): string
    {
        $path = __DIR__.'/tmp/'.$name.'-'.bin2hex(random_bytes(4));
        mkdir($path, 0777, true);

        return $path;
    }

    public static function removeDir(string $path): void
    {
        if (! is_dir($path)) {
            return;
        }

        $items = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($items as $item) {
            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }

        rmdir($path);
    }

    /**
     * @return array{0: Config, 1: string, 2: string} [config, secretKey, installDir]
     */
    public static function ed25519Config(?string $installDir = null): array
    {
        $installDir = $installDir !== null ? $installDir : self::tmpDir('install');
        $keyPair = sodium_crypto_sign_keypair();

        $config = Config::fromArray([
            'project_key' => 'testproject12345678a',
            'public_key' => base64_encode(sodium_crypto_sign_publickey($keyPair)),
            'algo' => 'ed25519',
            'expires_at' => '',
            'root_override' => '',
            'nonce_file' => '.nonce-test.json',
        ], $installDir);

        return [$config, sodium_crypto_sign_secretkey($keyPair), $installDir];
    }

    /**
     * @return array<string, string>
     */
    public static function signedHeaders(
        Config $config,
        string $secretKey,
        int $timestamp,
        ?string $nonce = null,
        string $method = 'GET',
        string $path = '/x/'
    ): array {
        $nonce = $nonce !== null ? $nonce : bin2hex(random_bytes(16));

        $material = RequestVerifier::signatureMaterial(
            $method,
            $path,
            $config->projectKey,
            (string) $timestamp,
            $nonce,
            ''
        );

        return [
            'x-sitetus-key' => $config->projectKey,
            'x-sitetus-timestamp' => (string) $timestamp,
            'x-sitetus-nonce' => $nonce,
            'x-sitetus-algo' => 'ed25519',
            'x-sitetus-signature' => base64_encode(sodium_crypto_sign_detached($material, $secretKey)),
        ];
    }
}
