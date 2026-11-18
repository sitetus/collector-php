<?php

namespace Sitetus\Collector\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sitetus\Collector\Level2;

/**
 * 0.7.4 `db_account_scope`: from where the application's database account
 * may connect, as one word (local / any / specific). MySQL and MariaDB
 * only; the account name and the host never leave the server, and a
 * failure sends no row. Driven through checksFromApp() with a stand-in
 * container, as the other Level 2 rows are.
 */
final class Level2DatabaseScopeTest extends TestCase
{
    public function testLocalHostsAreLocal(): void
    {
        $this->assertSame('local', Level2::accountScope('shop_user@localhost'));
        $this->assertSame('local', Level2::accountScope('shop_user@LOCALHOST'));
        $this->assertSame('local', Level2::accountScope('shop_user@127.0.0.1'));
        $this->assertSame('local', Level2::accountScope('shop_user@::1'));
    }

    public function testOnlyTheBareWildcardIsAny(): void
    {
        $this->assertSame('any', Level2::accountScope('shop_user@%'));
        $this->assertSame('any', Level2::accountScope("shop_user@'%'"));
    }

    public function testNamedHostsAddressesAndNarrowedPatternsAreSpecific(): void
    {
        $this->assertSame('specific', Level2::accountScope('shop_user@192.168.1.%'));
        $this->assertSame('specific', Level2::accountScope('shop_user@%.example.test'));
        $this->assertSame('specific', Level2::accountScope('shop_user@db_host'));
        $this->assertSame('specific', Level2::accountScope('shop_user@10.0.0.5'));
        $this->assertSame('specific', Level2::accountScope('shop_user@app01.example.test'));
        $this->assertSame('specific', Level2::accountScope('shop_user@192.168.1.0/255.255.255.0'));
    }

    public function testOnlyTheTextAfterTheLastAtSignIsTheHost(): void
    {
        // A wildcard or an @ in the user name says nothing about the host.
        $this->assertSame('local', Level2::accountScope('odd%user@name@localhost'));
        $this->assertSame('specific', Level2::accountScope('shop_user@10.0.0.5'));
    }

    public function testAnswerWithoutAHostPartIsNotClassified(): void
    {
        $this->assertNull(Level2::accountScope('shop_user'));
        $this->assertNull(Level2::accountScope('shop_user@'));
        $this->assertNull(Level2::accountScope(''));
    }

    /**
     * @dataProvider mysqlFamilyDrivers
     */
    public function testMysqlFamilySendsOnlyTheScopeWord(string $driver): void
    {
        $checks = (new Level2())->checksFromApp($this->container($driver, 'shop_user@db-host-17.example.test'));

        $this->assertSame(
            ['id' => 'db_account_scope', 'status' => 'ok', 'value' => 'specific'],
            $this->pick($checks, 'db_account_scope')
        );

        $encoded = (string) json_encode($checks);
        $this->assertStringNotContainsString('shop_user', $encoded);
        $this->assertStringNotContainsString('db-host-17', $encoded);
        $this->assertStringNotContainsString('example.test', $encoded);
    }

    /**
     * @return array<string, array<int, string>>
     */
    public function mysqlFamilyDrivers(): array
    {
        return ['mysql' => ['mysql'], 'mariadb' => ['mariadb']];
    }

    public function testAccountOpenToEveryHostIsAnyAndALocalOneIsLocal(): void
    {
        $any = (new Level2())->checksFromApp($this->container('mysql', 'shop_user@%'));
        $local = (new Level2())->checksFromApp($this->container('mysql', 'shop_user@localhost'));

        $this->assertSame('any', $this->pick($any, 'db_account_scope')['value']);
        $this->assertSame('local', $this->pick($local, 'db_account_scope')['value']);
    }

    /**
     * @dataProvider otherDrivers
     */
    public function testAnotherDriverSendsNoRowAndRunsNoQuery(string $driver): void
    {
        $container = $this->container($driver, 'shop_user@%');
        $checks = (new Level2())->checksFromApp($container);

        $this->assertNull($this->pick($checks, 'db_account_scope'));
        $this->assertSame([], $container->make('db')->connection()->getPdo()->queries);
        $this->assertSame('ok', $this->pick($checks, 'db_connectivity')['status']);
    }

    /**
     * @return array<string, array<int, string>>
     */
    public function otherDrivers(): array
    {
        return ['pgsql' => ['pgsql'], 'sqlite' => ['sqlite'], 'sqlsrv' => ['sqlsrv']];
    }

    public function testFailedQuerySendsNoRowAndLeavesTheOtherRowsAlone(): void
    {
        $checks = (new Level2())->checksFromApp($this->container('mysql', null));

        $this->assertNull($this->pick($checks, 'db_account_scope'));
        $this->assertSame('ok', $this->pick($checks, 'db_connectivity')['status']);
        $this->assertSame('ok', $this->pick($checks, 'db_server_version')['status']);
        $this->assertStringNotContainsString('shop_user', (string) json_encode($checks));
    }

    /**
     * The row is read with this server's own MySQL port: a database on
     * another server sends no row and runs no query.
     *
     * @dataProvider remoteHosts
     *
     * @param mixed $host
     */
    public function testDatabaseOnAnotherServerSendsNoRow($host): void
    {
        $container = $this->container('mysql', 'shop_user@%', ['host' => $host]);
        $checks = (new Level2())->checksFromApp($container);

        $this->assertNull($this->pick($checks, 'db_account_scope'));
        $this->assertSame([], $container->make('db')->connection()->getPdo()->queries);
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function remoteHosts(): array
    {
        return [
            'named server' => ['db.example.test'],
            'private address' => ['10.0.0.5'],
            'address with port' => ['10.0.0.5:3306'],
            'host list' => [['127.0.0.1', '10.0.0.5']],
            'not set' => [null],
        ];
    }

    public function testLocalHostsAndSocketsAreThisServer(): void
    {
        foreach (['localhost', 'LOCALHOST', '127.0.0.1', '::1', '[::1]:3306', 'localhost:3306', 'localhost:/var/run/mysqld/mysqld.sock', '/var/run/mysqld/mysqld.sock'] as $host) {
            $this->assertTrue(Level2::isLocalDatabaseHost($host), $host);
        }

        $socket = (new Level2())->checksFromApp($this->container('mysql', 'shop_user@localhost', ['host' => 'db.example.test', 'unix_socket' => '/tmp/mysql.sock']));
        $this->assertSame('local', $this->pick($socket, 'db_account_scope')['value']);
    }

    public function testAnswerWithoutAHostSendsNoRow(): void
    {
        $checks = (new Level2())->checksFromApp($this->container('mysql', 'shop_user'));

        $this->assertNull($this->pick($checks, 'db_account_scope'));
    }

    /**
     * A container whose `db` connection answers CURRENT_USER() with
     * `$currentUser` (null = the query throws).
     *
     * @return object
     */
    private function container(string $driver, ?string $currentUser, array $config = ['host' => '127.0.0.1'])
    {
        $pdo = new class($currentUser)
        {
            /** @var string|null */
            private $currentUser;

            /** @var array<int, string> */
            public $queries = [];

            public function __construct(?string $currentUser)
            {
                $this->currentUser = $currentUser;
            }

            /** @return mixed */
            public function getAttribute(int $attribute)
            {
                return '8.0.36';
            }

            /** @return object */
            public function query(string $sql)
            {
                $this->queries[] = $sql;

                if ($this->currentUser === null) {
                    throw new \RuntimeException('Access denied for shop_user@db-host-17.example.test');
                }

                $currentUser = $this->currentUser;

                return new class($currentUser)
                {
                    /** @var string */
                    private $value;

                    public function __construct(string $value)
                    {
                        $this->value = $value;
                    }

                    /** @return mixed */
                    public function fetchColumn()
                    {
                        return $this->value;
                    }
                };
            }
        };

        $connection = new class($driver, $pdo, $config)
        {
            /** @var string */
            private $driver;

            /** @var object */
            private $pdo;

            /** @var array<string, mixed> */
            private $config;

            public function __construct(string $driver, object $pdo, array $config)
            {
                $this->driver = $driver;
                $this->pdo = $pdo;
                $this->config = $config;
            }

            /** @return mixed */
            public function getConfig(string $key)
            {
                return $this->config[$key] ?? null;
            }

            /**
             * @return array<int, mixed>
             */
            public function select(string $sql): array
            {
                return [];
            }

            public function getDriverName(): string
            {
                return $this->driver;
            }

            public function getPdo(): object
            {
                return $this->pdo;
            }

            /** @return mixed */
            public function getSchemaBuilder()
            {
                throw new \RuntimeException('no schema builder');
            }
        };

        $db = new class($connection)
        {
            /** @var object */
            private $connection;

            public function __construct(object $connection)
            {
                $this->connection = $connection;
            }

            public function connection(): object
            {
                return $this->connection;
            }
        };

        return new class($db)
        {
            /** @var object */
            private $db;

            public function __construct(object $db)
            {
                $this->db = $db;
            }

            /** @return mixed */
            public function make(string $abstract)
            {
                if ($abstract === 'db') {
                    return $this->db;
                }

                throw new \RuntimeException('not bound: '.$abstract);
            }
        };
    }

    /**
     * @param array<int, array<string, mixed>> $checks
     * @return array<string, mixed>|null
     */
    private function pick(array $checks, string $id): ?array
    {
        foreach ($checks as $check) {
            if ($check['id'] === $id) {
                return $check;
            }
        }

        return null;
    }
}
