<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Lukk\Models\RefreshToken;
use Lukk\Refresh\DatabaseRefreshTokenRepository;
use Lukk\Tests\Fixtures\TenantBRefreshToken;
use Lukk\Tests\Fixtures\User;

uses()->group('refresh');

it('never asks the schema a question while holding the rotation row lock', function () {
    // `familyIsPinned()` refuses this exact cost in its own docblock — "two extra round trips, one
    // of them `information_schema`, on every ordinary human request" — and CLAUDE.md's rotate rule
    // is that no application code runs under the row lock, because lock duration, reverse-order
    // deadlocks and PostgreSQL's 25P02 all follow from it. A schema probe placed inside `persist()`
    // put two round trips between the locked read and the insert on every cold rotation, widening
    // precisely the window `tests/Concurrency/` exists to bound. The answer comes from the row the
    // non-locking pre-read already returned instead.
    // Through the LOGIN route, which stamps `amr` — `startSession()` alone stamps none, so the
    // conditional write short-circuits before the probe and the test would prove nothing.
    $user = User::factory()->create();
    $refresh = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->json('refresh_token');
    app('auth')->forgetGuards();

    // COLD, as a real request is. The sign-in above already answered the question, so leaving the
    // memo warm would make this test pass whatever `persist()` does — the first version of it did
    // exactly that. A php-fpm request that only refreshes starts with nothing memoized.
    // `instance()` registers in the container's INSTANCES, which `getBindings()` does not list, and
    // the key is built from the model's connection and table — guessing either wrong clears nothing
    // and the test proves nothing, which is exactly what two earlier versions of this line did. Read
    // the instances directly so the clear cannot silently miss.
    $instances = (new ReflectionProperty(app(), 'instances'));
    $all = $instances->getValue(app());
    $cleared = 0;
    foreach (array_keys($all) as $abstract) {
        if (str_starts_with((string) $abstract, 'lukk.schema.amr.')) {
            app()->forgetInstance($abstract);
            $cleared++;
        }
    }

    // The sign-in above must have memoized something, or this test is not starting cold.
    expect($cleared)->toBeGreaterThan(0);

    $insideTransaction = [];
    DB::listen(function ($query) use (&$insideTransaction) {
        if (DB::transactionLevel() > 0 && preg_match('/pragma|information_schema|sqlite_master|table_schema/i', $query->sql)) {
            $insideTransaction[] = $query->sql;
        }
    });

    $this->postJson('/auth/refresh', ['refresh_token' => $refresh])->assertOk();

    expect($insideTransaction)->toBe([]);
});

it('answers per connection, not once for the whole application', function () {
    // One application serving two connections — a migrated tenant and one that has not run the 0.8
    // migration — must not get the first one's answer for the second. A globally keyed memo did, and
    // the failing INSERT then lands INSIDE the rotate transaction, which on PostgreSQL aborts it:
    // every later statement errors 25P02 and COMMIT silently becomes ROLLBACK. That is the precise
    // failure the probe exists to prevent, reintroduced by the memo.
    config(['database.connections.tenant_b' => array_merge(
        config('database.connections.testing'), ['database' => ':memory:']
    )]);

    // The default connection has the column; tenant_b is an older schema without it.
    DB::connection('tenant_b')->getSchemaBuilder()->create('refresh_tokens', function ($table) {
        $table->ulid('id')->primary();
        $table->unsignedBigInteger('user_id')->index();
        $table->string('guard')->nullable();
        $table->uuid('family_id')->index();
        $table->char('token_hash', 64)->unique();
        $table->ulid('previous_id')->nullable();
        $table->text('scope')->nullable();
        $table->timestamp('rotated_at')->nullable();
        $table->timestamp('revoked_at')->nullable();
        $table->timestamp('expires_at');
        $table->timestamps();
    });

    // Warm the memo on the DEFAULT connection, which does have `amr`.
    $user = User::factory()->create();
    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertOk();

    // Now persist against the other connection. A global memo would say "the column exists".
    Lukk\Lukk::useRefreshTokenModel(TenantBRefreshToken::class);
    $repository = new DatabaseRefreshTokenRepository;

    expectNoThrow(fn () => $repository->persist(
        1, (string) Str::uuid(), null, str_repeat('a', 64), time() + 600, null, '["pwd"]'
    ));
});

/** A refresh-token table on the default connection that predates the `amr` column. */
class LegacyTableRefreshToken extends RefreshToken
{
    protected $table = 'xrefresh_tokens';
}

/** The current schema, on a connection whose name runs into the legacy table's in an unseparated key. */
class TestingxConnectionRefreshToken extends RefreshToken
{
    protected $connection = 'testingx';

    protected $table = 'refresh_tokens';
}

function refreshTokensTable(string $connection, string $table, bool $amr): void
{
    DB::connection($connection)->getSchemaBuilder()->create($table, function ($t) use ($amr) {
        $t->ulid('id')->primary();
        $t->unsignedBigInteger('user_id')->index();
        $t->string('guard')->nullable();
        $t->uuid('family_id')->index();
        $t->char('token_hash', 64)->unique();
        $t->ulid('previous_id')->nullable();
        $t->text('scope')->nullable();
        if ($amr) {
            $t->text('amr')->nullable();
        }
        $t->timestamp('rotated_at')->nullable();
        $t->timestamp('revoked_at')->nullable();
        $t->timestamp('expires_at');
        $t->timestamps();
    });
}

it('answers per table as well as per connection, with keys that cannot run together', function (string $warm) {
    // Two tables on one connection — a renamed model beside the original — must not share an answer
    // either, and neither may a connection and table whose names merely concatenate to the same string
    // (`testing` + `xrefresh_tokens`, `testingx` + `refresh_tokens`).
    config(['database.connections.testingx' => array_merge(config('database.connections.testing'), ['database' => ':memory:'])]);
    DB::purge('testingx');
    refreshTokensTable('testing', 'xrefresh_tokens', amr: false);
    refreshTokensTable('testingx', 'refresh_tokens', amr: true);

    // Warm the memo on a schema that HAS the column.
    Lukk\Lukk::useRefreshTokenModel($warm);
    (new DatabaseRefreshTokenRepository)->persist(1, (string) Str::uuid(), null, str_repeat('a', 64), time() + 600, null, '["pwd"]');

    // Then write to the legacy table, which does not.
    Lukk\Lukk::useRefreshTokenModel(LegacyTableRefreshToken::class);

    expectNoThrow(fn () => (new DatabaseRefreshTokenRepository)->persist(
        1, (string) Str::uuid(), null, str_repeat('b', 64), time() + 600, null, '["pwd"]'
    ));
})->with([
    'another table on the same connection' => [RefreshToken::class],
    'a connection whose name runs into the table' => [TestingxConnectionRefreshToken::class],
]);

it('answers per database, when a tenancy package switches the database under one connection name', function (bool $firstHasAmr) {
    // Multi-tenant packages (stancl/tenancy) keep ONE connection name and point it at the tenant's
    // database per request. Keyed by the name alone, the memo carried one tenant's answer into the
    // next: "the column exists" made the other tenant's INSERT name a column it lacks (a failed
    // rotate — on PostgreSQL an aborted transaction), and "it does not" dropped `amr` for a tenant
    // that has it.
    $files = [];
    foreach ([$firstHasAmr, ! $firstHasAmr] as $i => $amr) {
        $files[$i] = tempnam(sys_get_temp_dir(), 'lukk-tenant-');
        config(['database.connections.tenant_b' => array_merge(config('database.connections.testing'), ['database' => $files[$i]])]);
        DB::purge('tenant_b');
        refreshTokensTable('tenant_b', 'refresh_tokens', amr: $amr);
    }

    Lukk\Lukk::useRefreshTokenModel(TenantBRefreshToken::class);

    try {
        foreach ($files as $i => $file) {
            config(['database.connections.tenant_b.database' => $file]);
            DB::purge('tenant_b');

            (new DatabaseRefreshTokenRepository)->persist(1, (string) Str::uuid(), null, str_repeat((string) $i, 64), time() + 600, null, '["pwd"]');
        }

        $stored = [];
        foreach ($files as $i => $file) {
            config(['database.connections.tenant_b.database' => $file]);
            DB::purge('tenant_b');
            $stored[$i] = DB::connection('tenant_b')->getSchemaBuilder()->hasColumn('refresh_tokens', 'amr')
                ? DB::connection('tenant_b')->table('refresh_tokens')->value('amr')
                : 'no column';
        }

        expect($stored)->toBe($firstHasAmr ? ['["pwd"]', 'no column'] : ['no column', '["pwd"]']);
    } finally {
        DB::purge('tenant_b');
        array_map(unlink(...), $files);
    }
})->with([
    'a tenant with the column, then one without' => [true],
    'a tenant without the column, then one with' => [false],
]);

it('answers per table prefix, when a tenancy package switches the prefix under one connection name', function () {
    // Prefix-per-tenant is the same switch one level down: one connection, one database, and the
    // tenant's tables told apart only by the prefix the connection currently applies.
    $file = tempnam(sys_get_temp_dir(), 'lukk-prefix-');
    $usePrefix = function (string $prefix) use ($file) {
        config(['database.connections.tenant_b' => array_merge(config('database.connections.testing'), ['database' => $file, 'prefix' => $prefix, 'prefix_indexes' => true])]);
        DB::purge('tenant_b');
    };
    $usePrefix('one_');
    refreshTokensTable('tenant_b', 'refresh_tokens', amr: true);
    $usePrefix('two_');
    refreshTokensTable('tenant_b', 'refresh_tokens', amr: false);
    Lukk\Lukk::useRefreshTokenModel(TenantBRefreshToken::class);

    try {
        $usePrefix('one_');
        (new DatabaseRefreshTokenRepository)->persist(1, (string) Str::uuid(), null, str_repeat('a', 64), time() + 600, null, '["pwd"]');
        $usePrefix('two_');

        expectNoThrow(fn () => (new DatabaseRefreshTokenRepository)->persist(
            1, (string) Str::uuid(), null, str_repeat('b', 64), time() + 600, null, '["pwd"]'
        ));
    } finally {
        DB::purge('tenant_b');
        unlink($file);
    }
});

it('asks again when the connection\'s search_path changes under one connection name', function () {
    // Schema-per-tenant on PostgreSQL switches `search_path`, not the database, and `hasColumn()`
    // answers for whichever schema that resolves to. sqlite has no schemas to tell apart, so this
    // pins the part that is engine-independent: a new search_path is a new question.
    $file = tempnam(sys_get_temp_dir(), 'lukk-path-');
    $useSearchPath = function (string $path) use ($file) {
        config(['database.connections.tenant_b' => array_merge(config('database.connections.testing'), ['database' => $file, 'search_path' => $path])]);
        DB::purge('tenant_b');
    };
    $useSearchPath('tenant_one');
    refreshTokensTable('tenant_b', 'refresh_tokens', amr: true);
    Lukk\Lukk::useRefreshTokenModel(TenantBRefreshToken::class);
    $probes = 0;
    DB::listen(function ($query) use (&$probes) {
        if (preg_match('/pragma|sqlite_master/i', $query->sql)) {
            $probes++;
        }
    });

    try {
        (new DatabaseRefreshTokenRepository)->persist(1, (string) Str::uuid(), null, str_repeat('a', 64), time() + 600, null, '["pwd"]');
        $afterFirst = $probes;
        (new DatabaseRefreshTokenRepository)->persist(1, (string) Str::uuid(), null, str_repeat('b', 64), time() + 600, null, '["pwd"]');
        $afterSame = $probes;
        $useSearchPath('tenant_two');
        (new DatabaseRefreshTokenRepository)->persist(1, (string) Str::uuid(), null, str_repeat('c', 64), time() + 600, null, '["pwd"]');

        // Asked once, remembered for the same search_path, asked again for a new one.
        expect($afterFirst)->toBeGreaterThan(0)
            ->and($afterSame)->toBe($afterFirst)
            ->and($probes)->toBeGreaterThan($afterSame);
    } finally {
        DB::purge('tenant_b');
        unlink($file);
    }
});
