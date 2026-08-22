<?php

declare(strict_types=1);

namespace Lukk\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lukk\LukkServiceProvider;
use Lukk\Tests\Fixtures\User;
use Orchestra\Testbench\TestCase as Orchestra;
use PDO;
use Throwable;

/**
 * The suite's default is sqlite `:memory:`, which serialises writers completely — so anything that
 * turns on an isolation level is invisible there. These tests run against a REAL engine.
 *
 *   docker compose up -d
 *   LUKK_TEST_PGSQL=1 vendor/bin/pest --group=concurrency
 *
 * Deliberately NOT `RefreshDatabase`: it wraps each test in a transaction, which would turn the
 * explicit COMMIT these tests depend on into a savepoint release — the second connection would
 * never see the row, and the race being measured could not happen. The schema is wiped and rebuilt
 * per test instead.
 *
 * Skipped rather than failed when the engine isn't reachable: the default suite must stay runnable
 * with nothing but PHP.
 */
class ConcurrencyTestCase extends Orchestra
{
    /** Which engine this run targets — `LUKK_TEST_ENGINE=mysql` to switch. */
    /** Which engine this run targets — `LUKK_TEST_ENGINE=mysql` to switch. */
    public static string $engine = 'pgsql';

    public static function engine(): string
    {
        return getenv('LUKK_TEST_ENGINE') ?: static::$engine;
    }

    public static function config(string $engine): array
    {
        return $engine === 'pgsql'
            ? ['driver' => 'pgsql', 'host' => '127.0.0.1', 'port' => 55432, 'database' => 'lukk', 'username' => 'lukk', 'password' => 'lukk', 'prefix' => '', 'search_path' => 'public', 'sslmode' => 'prefer']
            : ['driver' => 'mysql', 'host' => '127.0.0.1', 'port' => 33306, 'database' => 'lukk', 'username' => 'lukk', 'password' => 'lukk', 'prefix' => '', 'charset' => 'utf8mb4', 'collation' => 'utf8mb4_unicode_ci'];
    }

    public static function available(string $engine): bool
    {
        if (! getenv($engine === 'pgsql' ? 'LUKK_TEST_PGSQL' : 'LUKK_TEST_MYSQL')) {
            return false;
        }

        $c = self::config($engine);

        try {
            new PDO(
                $engine === 'pgsql'
                    ? "pgsql:host={$c['host']};port={$c['port']};dbname={$c['database']}"
                    : "mysql:host={$c['host']};port={$c['port']};dbname={$c['database']}",
                $c['username'], $c['password'], [PDO::ATTR_TIMEOUT => 3],
            );

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    protected function getPackageProviders($app): array
    {
        return [LukkServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', self::config(self::engine()));
        $app['config']->set('cache.default', 'array');
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('a', 32)));
        $app['config']->set('lukk.secret', str_repeat('a', 64));
        $app['config']->set('auth.guards.api', ['driver' => 'lukk-jwt', 'provider' => 'users']);
        $app['config']->set('auth.providers.users.model', User::class);
    }

    protected function setUp(): void
    {
        parent::setUp();

        if (! self::available(self::engine())) {
            $this->markTestSkipped('engine not reachable — run `docker compose up -d` and set LUKK_TEST_PGSQL/LUKK_TEST_MYSQL');
        }

        // A real engine persists between runs, and the base fixtures are created directly rather
        // than through migrations, so start from an empty schema every time.
        command('db:wipe', ['--force' => true]);

        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email');
            $table->string('password');
            $table->timestamp('email_verified_at')->nullable();
        });

        (include __DIR__.'/../database/migrations/2026_01_01_000000_create_refresh_tokens_table.php')->up();
    }
}
