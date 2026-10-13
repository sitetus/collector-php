<?php

namespace Sitetus\Collector\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sitetus\Collector\Config;
use Sitetus\Collector\NonceStore;
use Sitetus\Collector\RequestVerifier;
use Sitetus\Collector\Tests\Support;

final class RequestVerifierTest extends TestCase
{
    /** @var string */
    private $installDir;

    protected function setUp(): void
    {
        if (! function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('sodium not available');
        }
    }

    protected function tearDown(): void
    {
        if ($this->installDir !== null) {
            Support::removeDir($this->installDir);
        }
    }

    private function verifier(Config $config): RequestVerifier
    {
        return new RequestVerifier($config, new NonceStore($config->noncePath()));
    }

    public function testValidSignedRequestPasses(): void
    {
        list($config, $secret, $this->installDir) = Support::ed25519Config();

        $now = time();
        $headers = Support::signedHeaders($config, $secret, $now);

        list($status) = $this->verifier($config)->verify('GET', '/x/', $headers, '', $now);

        $this->assertSame(200, $status);
    }

    public function testUnsignedRequestIsAnAnonymous404(): void
    {
        list($config, $secret, $this->installDir) = Support::ed25519Config();

        list($status, $headers) = $this->verifier($config)->verify('GET', '/x/', [], '', time());

        $this->assertSame(404, $status);
        $this->assertSame([], $headers);
    }

    public function testWrongProjectKeyIs404(): void
    {
        list($config, $secret, $this->installDir) = Support::ed25519Config();

        $now = time();
        $headers = Support::signedHeaders($config, $secret, $now);
        $headers['x-sitetus-key'] = 'someone-elses-key000';

        list($status) = $this->verifier($config)->verify('GET', '/x/', $headers, '', $now);

        $this->assertSame(404, $status);
    }

    public function testTamperedMaterialIs404(): void
    {
        list($config, $secret, $this->installDir) = Support::ed25519Config();

        $now = time();
        $headers = Support::signedHeaders($config, $secret, $now, null, 'GET', '/x/');

        // Signed for /x/ but requested against another path.
        list($status) = $this->verifier($config)->verify('GET', '/other/', $headers, '', $now);

        $this->assertSame(404, $status);
    }

    public function testClockSkewIs403WithDiagnostics(): void
    {
        list($config, $secret, $this->installDir) = Support::ed25519Config();

        $now = time();
        $signedAt = $now - 700; // pencere disi
        $headers = Support::signedHeaders($config, $secret, $signedAt);

        list($status, $extra) = $this->verifier($config)->verify('GET', '/x/', $headers, '', $now);

        $this->assertSame(403, $status);
        $this->assertSame('skew', $extra['X-Sitetus-Error']);
        $this->assertSame((string) $now, $extra['X-Sitetus-Server-Time']);
    }

    public function testNonceReplayIs403(): void
    {
        list($config, $secret, $this->installDir) = Support::ed25519Config();

        $now = time();
        $headers = Support::signedHeaders($config, $secret, $now, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

        $verifier = $this->verifier($config);

        list($first) = $verifier->verify('GET', '/x/', $headers, '', $now);
        list($second, $extra) = $verifier->verify('GET', '/x/', $headers, '', $now);

        $this->assertSame(200, $first);
        $this->assertSame(403, $second);
        $this->assertSame('nonce', $extra['X-Sitetus-Error']);
    }

    public function testExpiredPackageIs404EvenWithValidSignature(): void
    {
        list($config, $secret, $this->installDir) = Support::ed25519Config();
        $config->expiresAt = time() - 10;

        $now = time();
        $headers = Support::signedHeaders($config, $secret, $now);

        list($status) = $this->verifier($config)->verify('GET', '/x/', $headers, '', $now);

        $this->assertSame(404, $status);
    }

    public function testSleepModeAfterNinetyDaysIs404(): void
    {
        list($config, $secret, $this->installDir) = Support::ed25519Config();

        $past = time() - 100;
        $verifier = $this->verifier($config);

        // A valid request records last_valid.
        list($first) = $verifier->verify('GET', '/x/', Support::signedHeaders($config, $secret, $past), '', $past);
        $this->assertSame(200, $first);

        // 91 days later even a validly signed request gets 404 (sleep).
        $later = $past + 91 * 86400;
        list($second) = $verifier->verify('GET', '/x/', Support::signedHeaders($config, $secret, $later), '', $later);

        $this->assertSame(404, $second);
    }

    public function testSharedSignatureVectorVerifies(): void
    {
        $this->installDir = Support::tmpDir('vector');

        $vector = json_decode((string) file_get_contents(__DIR__.'/../fixtures/signature-vector.json'), true);

        $config = Config::fromArray([
            'project_key' => $vector['project_key'],
            'public_key' => $vector['public_key_b64'],
            'algo' => 'ed25519',
            'expires_at' => '',
            'root_override' => '',
            'nonce_file' => '.nonce-test.json',
        ], $this->installDir);

        $headers = [
            'x-sitetus-key' => $vector['project_key'],
            'x-sitetus-timestamp' => $vector['timestamp'],
            'x-sitetus-nonce' => $vector['nonce'],
            'x-sitetus-algo' => $vector['algo'],
            'x-sitetus-signature' => $vector['signature_b64'],
        ];

        list($status) = $this->verifier($config)->verify(
            $vector['method'],
            $vector['path'],
            $headers,
            $vector['body'],
            (int) $vector['timestamp']
        );

        $this->assertSame(200, $status);
        $this->assertSame(
            $vector['material_sha256'],
            hash('sha256', RequestVerifier::signatureMaterial(
                $vector['method'],
                $vector['path'],
                $vector['project_key'],
                $vector['timestamp'],
                $vector['nonce'],
                $vector['body']
            ))
        );
    }

    public function testRsaSignatureRoundTrip(): void
    {
        if (! function_exists('openssl_sign')) {
            $this->markTestSkipped('openssl not available');
        }

        $this->installDir = Support::tmpDir('rsa');

        // Fixture keys: deterministic vectors shared with the panel repo
        // (openssl_pkey_new needs an openssl.cnf that Windows often lacks).
        $key = openssl_pkey_get_private((string) file_get_contents(__DIR__.'/../fixtures/rsa_private.pem'));
        $publicPem = (string) file_get_contents(__DIR__.'/../fixtures/rsa_public.pem');

        $this->assertNotFalse($key);

        $config = Config::fromArray([
            'project_key' => 'rsaproject1234567890',
            'public_key' => $publicPem,
            'algo' => 'rsa-sha256',
            'expires_at' => '',
            'root_override' => '',
            'nonce_file' => '.nonce-test.json',
        ], $this->installDir);

        $now = time();
        $nonce = bin2hex(random_bytes(16));
        $material = RequestVerifier::signatureMaterial('GET', '/x/', $config->projectKey, (string) $now, $nonce, '');
        openssl_sign($material, $signature, $key, OPENSSL_ALGO_SHA256);

        $headers = [
            'x-sitetus-key' => $config->projectKey,
            'x-sitetus-timestamp' => (string) $now,
            'x-sitetus-nonce' => $nonce,
            'x-sitetus-algo' => 'rsa-sha256',
            'x-sitetus-signature' => base64_encode($signature),
        ];

        list($status) = $this->verifier($config)->verify('GET', '/x/', $headers, '', $now);
        $this->assertSame(200, $status);

        // Corrupted signature falls back to 404.
        $headers['x-sitetus-signature'] = base64_encode('garbage-signature-value');
        list($bad) = $this->verifier($config)->verify('GET', '/x/', $headers, '', $now);
        $this->assertSame(404, $bad);
    }

    /**
     * 0.5.1 (audit 25.09): a nonce used to be pruned after the skew window
     * while its timestamp was still acceptable — with the panel clock ahead
     * of the server, a captured request could be replayed once. The nonce
     * now outlives the skew window.
     */
    public function testNonceOutlivesTheSkewWindowSoAReplayWithinSkewIsRefused(): void
    {
        list($config, $secret, $this->installDir) = Support::ed25519Config();

        $issued = 1790000000;
        $headers = Support::signedHeaders($config, $secret, $issued);

        // Panel clock 550 s ahead: the server sees the request at issued-550.
        list($first) = $this->verifier($config)->verify('GET', '/x/', $headers, '', $issued - 550);
        $this->assertSame(200, $first);

        // 601 s later the timestamp is still within skew — and the nonce must still be remembered.
        list($replay, $extra) = $this->verifier($config)->verify('GET', '/x/', $headers, '', $issued + 51);
        $this->assertSame(403, $replay);
        $this->assertSame('nonce', $extra['X-Sitetus-Error']);

        // Beyond skew the timestamp itself is refused.
        list($late, $extra) = $this->verifier($config)->verify('GET', '/x/', $headers, '', $issued + 601);
        $this->assertSame(403, $late);
        $this->assertSame('skew', $extra['X-Sitetus-Error']);
    }

    /**
     * 0.5.1: a store that cannot be written denies the request (403
     * nonce-store) instead of accepting it with an empty store.
     */
    public function testUnwritableNonceStoreRefusesTheRequest(): void
    {
        list($config, $secret, $this->installDir) = Support::ed25519Config();

        // A directory in the store's place: fopen('c+') fails.
        mkdir($config->noncePath(), 0777, true);

        $now = time();
        $headers = Support::signedHeaders($config, $secret, $now);

        list($status, $extra) = $this->verifier($config)->verify('GET', '/x/', $headers, '', $now);

        $this->assertSame(403, $status);
        $this->assertSame('nonce-store', $extra['X-Sitetus-Error']);
    }
}
