<?php

namespace Sitetus\Collector;

/**
 * Reads two database facts as one word each, from text the caller already
 * holds: from where an account may connect, and whether a configured host
 * is this server. Runs no query and needs no application, so the Laravel
 * bootstrap (Level 2) and the WordPress plugin share it.
 */
final class DatabaseAccount
{
    /**
     * The host part of a `user@host` account (the text after the last `@`)
     * as one word: `local` for localhost, 127.0.0.1 and ::1; `any` for the
     * bare wildcard `%`; `specific` for everything else, a pattern that
     * narrows the wildcard (`10.0.%`, `%.example.test`) included.
     * Null when there is no host part to read.
     */
    public static function scope(string $currentUser): ?string
    {
        $at = strrpos($currentUser, '@');

        if ($at === false) {
            return null;
        }

        $host = strtolower(trim(trim(substr($currentUser, $at + 1)), '`\'"'));

        if ($host === '') {
            return null;
        }

        if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
            return 'local';
        }

        if ($host === '%') {
            return 'any';
        }

        return 'specific';
    }

    /**
     * Whether a configured database host is this server: localhost, a
     * loopback address or a socket path (WordPress writes it after a colon).
     * Anything else — another server, a list of hosts — is not.
     *
     * @param mixed $host
     */
    public static function isLocalHost($host): bool
    {
        if (! is_string($host)) {
            return false;
        }

        $host = strtolower(trim($host));

        if ($host === '' || $host[0] === '/' || strpos($host, ':/') !== false) {
            return $host !== '';
        }

        $name = $host[0] === '[' ? trim((string) strstr($host, ']', true), '[') : (substr_count($host, ':') === 1 ? (string) strstr($host, ':', true) : $host);

        return in_array($name, ['localhost', '127.0.0.1', '::1'], true);
    }
}
