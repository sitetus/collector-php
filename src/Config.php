<?php

namespace Sitetus\Collector;

/**
 * Embedded installation configuration. Contains NO secrets: the public key
 * verifies the panel's signatures, project_key is an identifier,
 * and the nonce file name is random per installation.
 */
final class Config
{
    public const VERSION = '0.7.2';

    public const SCHEMA_VERSION = 1;

    public const COLLECTOR_NAME = 'sitetus-php';

    /** @var string */
    public $projectKey;

    /** @var string base64 (ed25519 raw 32B) or PEM (rsa) */
    public $publicKey;

    /** @var string ed25519|rsa-sha256 */
    public $algo;

    /** @var int|null unix UTC */
    public $expiresAt;

    /** @var string|null */
    public $rootOverride;

    /** @var string nonce store file name (random, lives next to index.php) */
    public $nonceFile;

    /** @var string install directory (where index.php lives) */
    public $installDir;

    /** @var string sitetus-php for the single file; wrappers override (the panel tells wrappers apart only by this name) */
    public $collectorName = self::COLLECTOR_NAME;

    /**
     * Opt-in modules enabled for this installation: files,
     * archives, permissions. Empty = none. The panel sets the list at package
     * time and strips the code of unselected modules from the file.
     *
     * @var array<int, string>
     */
    public $modules = [];

    /**
     * @param array<string, mixed> $values
     */
    public static function fromArray(array $values, string $installDir): self
    {
        $config = new self();
        $config->projectKey = (string) ($values['project_key'] ?? '');
        $config->publicKey = (string) ($values['public_key'] ?? '');
        $config->algo = (string) ($values['algo'] ?? 'ed25519');
        // Placeholder values are strings in the built file; only a numeric
        // value means an actual expiry, only a real path means an override.
        $config->expiresAt = isset($values['expires_at']) && is_numeric($values['expires_at'])
            ? (int) $values['expires_at']
            : null;
        $rootOverride = isset($values['root_override']) ? (string) $values['root_override'] : '';
        $config->rootOverride = $rootOverride !== '' && strpos($rootOverride, '{{') === false
            ? $rootOverride
            : null;
        $config->nonceFile = (string) ($values['nonce_file'] ?? '.sitetus-nonce.json');
        $config->installDir = $installDir;

        $modules = isset($values['modules']) ? $values['modules'] : '';
        $modules = is_array($modules) ? $modules : explode(',', (string) $modules);
        $config->modules = array_values(array_filter(array_map('trim', $modules), function (string $module): bool {
            return $module !== '' && strpos($module, '{{') === false && preg_match('/^[a-z_]+$/', $module) === 1;
        }));

        return $config;
    }

    public function noncePath(): string
    {
        return $this->installDir.DIRECTORY_SEPARATOR.$this->nonceFile;
    }
}
