<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Lukk\Auth\JwtGuard;
use Lukk\Contracts\TokenIssuer;
use Lukk\Contracts\TokenVerifier;
use Lukk\Lukk;
use Lukk\Tests\ConcurrencyTestCase;
use Lukk\Tests\Fixtures\EagerThingsUser;
use Lukk\Tests\Fixtures\IntKeyUser;
use Lukk\Tests\Fixtures\LegacyIdUser;
use Lukk\Tests\Fixtures\ReferringUser;
use Lukk\Tests\Fixtures\SnowflakeUser;
use Lukk\Tests\Fixtures\User;

uses(ConcurrencyTestCase::class)->group('concurrency');

/*
 * A co-issuer sharing the secret (the verify-only topology) mints its own access tokens, and nothing
 * makes its `fid` a UUID or its `sub` a key of the provider's type. sqlite compares anything with
 * anything, so the default suite sees no difference; PostgreSQL types its parameters against the column
 * — `family_id` is a native `uuid`, `users.id` a `bigint` — and refuses with 22P02/22003, which surfaced
 * as a 500 on every route that looks the family or the user up.
 */

function coIssuedAccess(array $claims): string
{
    $cfg = Lukk::guardConfig();

    return JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'],
        'jti' => 'co-'.bin2hex(random_bytes(6)), 'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
        ...$claims,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);
}

dataset('non-uuid family ids', [
    'a number' => [42],
    'an opaque string' => ['sess_42'],
]);

it('treats a family id that is no UUID as no family of lukk\'s, rather than a 500', function (int|string $fid) {
    $user = User::factory()->create(['password' => bcrypt('password')]);
    $live = $user->startSession();
    $token = fn () => coIssuedAccess(['sub' => (string) $user->getKey(), 'fid' => $fid]);

    $this->withToken($token())->postJson('/auth/confirm-password', ['password' => 'password'])->assertOk();
    app('auth')->forgetGuards();
    $this->withToken($token())->deleteJson('/auth/sessions/others')->assertNoContent();
    app('auth')->forgetGuards();

    // "Others" means every lukk family: a co-issuer's family is not one of them, so none is spared.
    expect(coIssuerFamilyIsLive($live->refreshToken))->toBeFalse();

    $this->withToken($token())->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertOk();
    app('auth')->forgetGuards();
    $this->withToken($token())->deleteJson('/auth/sessions')->assertNoContent();
    app('auth')->forgetGuards();
    $this->withToken($token())->postJson('/auth/logout')->assertNoContent();
})->with('non-uuid family ids');

it('refuses, with a 401, a subject the provider\'s key could never hold', function (string $sub) {
    User::factory()->create();

    $this->withToken(coIssuedAccess(['sub' => $sub]))->postJson('/auth/confirm-password', ['password' => 'password'])
        ->assertUnauthorized();
})->with([
    'not a number' => ['admin'],
    'past bigint' => ['99999999999999999999'],
    'a fraction' => ['1.5'],
    'negative zero-padded' => ['-01'],
]);

it('still resolves a numeric subject on an integer key', function () {
    $user = User::factory()->create();

    $this->withToken(coIssuedAccess(['sub' => (string) $user->getKey()]))->postJson('/auth/confirm-password', ['password' => 'password'])
        ->assertOk();
});

/*
 * A model's declarations do not say what the identifier column holds: a model whose key is not
 * incrementing but is still an integer (Snowflake ids), one whose auth identifier is another integer column,
 * and the stock 32-bit `increments('id')` with a subject past int4 all reached PostgreSQL with a value its
 * parameter type refuses — 22P02/22003, a 500 — where a `sub` naming no user is a 401. The guard reads the
 * column's type from the schema instead, and refuses such a subject before any lookup.
 */
dataset('integer columns lukk cannot see', [
    'a non-incrementing bigint key (Snowflake)' => [
        fn () => Schema::create('snowflake_users', fn (Blueprint $t) => $t->unsignedBigInteger('id')->primary()),
        SnowflakeUser::class, 'admin',
    ],
    'an integer auth identifier that is not the key' => [
        fn () => Schema::create('legacy_id_users', function (Blueprint $t) {
            $t->id();
            $t->integer('legacy_id')->unique();
        }),
        LegacyIdUser::class, 'admin',
    ],
    'a 32-bit key and a subject past it' => [
        fn () => Schema::create('int_key_users', fn (Blueprint $t) => $t->increments('id')),
        IntKeyUser::class, '3000000000',
    ],
]);

function coIssuerGuard(string|EloquentUserProvider $model, string $sub): ?Authenticatable
{
    $guard = new JwtGuard(app(TokenVerifier::class), is_string($model) ? new EloquentUserProvider(app('hash'), $model) : $model);

    return $guard(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer '.coIssuedAccess(['sub' => $sub])]));
}

it('answers a subject an integer column refuses as no user, whatever the model declares', function (Closure $table, string $model, string $sub) {
    $table();
    $model::query()->create(match ($model) {
        SnowflakeUser::class => ['id' => 1234567890123456789],
        LegacyIdUser::class => ['legacy_id' => 7],
        default => [],
    });

    expect(coIssuerGuard($model, $sub))->toBeNull();
})->with('integer columns lukk cannot see');

it('leaves the caller\'s transaction usable after refusing such a subject', function (Closure $table, string $model, string $sub) {
    // On PostgreSQL a failed statement aborts the whole transaction: every later statement is 25P02 and
    // COMMIT silently becomes ROLLBACK. A guard resolved inside an application's `DB::transaction()` must
    // fail only its own lookup.
    $table();

    $written = DB::transaction(function () use ($model, $sub) {
        DB::table('users')->insert(['email' => 'inside@example.com', 'password' => 'x']);
        expect(coIssuerGuard($model, $sub))->toBeNull();

        return DB::table('users')->where('email', 'inside@example.com')->count();
    });

    expect($written)->toBe(1)
        ->and(DB::table('users')->where('email', 'inside@example.com')->exists())->toBeTrue();
})->with('integer columns lukk cannot see');

it('still resolves a real user of each such model', function (Closure $table, string $model) {
    $table();
    $user = $model::query()->create(match ($model) {
        SnowflakeUser::class => ['id' => 1234567890123456789],
        LegacyIdUser::class => ['legacy_id' => 7],
        default => [],
    });

    expect(coIssuerGuard($model, (string) $user->getAuthIdentifier())?->getAuthIdentifier())->toEqual($user->getAuthIdentifier());
})->with('integer columns lukk cannot see');

it('reports a refusal in another statement of the lookup — an eager-loaded relation — instead of hiding it', function () {
    if (ConcurrencyTestCase::engine() !== 'pgsql') {
        test()->markTestSkipped('MySQL coerces the value instead of refusing it, so no statement fails');
    }

    // Only the lookup OF THE SUBJECT names no user when its type is refused. A mistyped `$with` relation
    // fails every lookup of a real user with the same 22P02: read as "no user", that was a 401 for
    // everybody and an outage nobody was told about.
    Schema::create('things', function (Blueprint $t) {
        $t->id();
        $t->uuid('owner_uuid');
    });
    $user = EagerThingsUser::query()->create(['email' => 'eager@example.com', 'password' => 'x']);

    expect(fn () => coIssuerGuard(EagerThingsUser::class, (string) $user->getKey()))
        ->toThrow(QueryException::class, '22P02');
});

/*
 * The column is found however the model names its table: schema-qualified (Laravel prefixes the LAST part:
 * `"public"."app_snow_s"`), aliased, on a prefixed connection.
 */
dataset('table spellings', [
    'schema-qualified' => ['public.snow_s', null, 'snow_s'],
    'aliased' => ['snow_s as s', null, 'snow_s'],
    'schema-qualified on a prefixed connection' => ['public.snow_s', 'app_', 'app_snow_s'],
]);

it('answers a refused subject as no user however the model spells its table', function (string $table, ?string $prefix, string $physical) {
    if (ConcurrencyTestCase::engine() !== 'pgsql') {
        test()->markTestSkipped('MySQL coerces the value instead of refusing it, and has no `public` schema');
    }

    config(['database.connections.spelled' => [...ConcurrencyTestCase::config('pgsql'), 'prefix' => (string) $prefix]]);
    Schema::create($physical, fn (Blueprint $t) => $t->unsignedBigInteger('id')->primary());
    $model = new class extends SnowflakeUser
    {
        protected $connection = 'spelled';

        public static string $spelling = '';

        public function getTable(): string
        {
            return self::$spelling;
        }
    };
    $model::$spelling = $table;
    DB::table($physical)->insert(['id' => 5]);

    expect(coIssuerGuard($model::class, 'admin'))->toBeNull()
        ->and(coIssuerGuard($model::class, '5')?->getKey())->toBe(5);
})->with('table spellings');

it('reports a same-table eager load that binds the subject, rather than reading it as no user', function () {
    if (ConcurrencyTestCase::engine() !== 'pgsql') {
        test()->markTestSkipped('MySQL coerces the value instead of refusing it, so no statement fails');
    }

    // Identifier `handle`; `$with` loads the user's reports through `manager_id` (bigint) keyed on that
    // handle. The eager load binds the subject and reads the users' own table — and fails for every user.
    Schema::create('managed_users', function (Blueprint $t) {
        $t->id();
        $t->string('handle')->unique();
        $t->unsignedBigInteger('manager_id')->nullable();
    });
    $model = new class extends SnowflakeUser
    {
        protected $table = 'managed_users';

        public $incrementing = true;

        protected $with = ['reports'];

        public function getAuthIdentifierName(): string
        {
            return 'handle';
        }

        public function reports(): HasMany
        {
            return $this->hasMany(self::class, 'manager_id', 'handle');
        }
    };
    DB::table('managed_users')->insert(['handle' => 'alice']);

    expect(fn () => coIssuerGuard($model::class, 'alice'))->toThrow(QueryException::class, '22P02');
});

it('refuses a subject that is no UUID for a uuid identifier, and resolves one that is', function () {
    Schema::create('uuid_users', fn (Blueprint $t) => $t->uuid('id')->primary());
    $model = new class extends SnowflakeUser
    {
        protected $table = 'uuid_users';

        protected $keyType = 'string';
    };
    DB::table('uuid_users')->insert(['id' => $uuid = (string) Str::uuid()]);

    expect(coIssuerGuard($model::class, 'admin'))->toBeNull()
        ->and(coIssuerGuard($model::class, $uuid)?->getKey())->toBe($uuid)
        ->and(coIssuerGuard($model::class, strtoupper($uuid))?->getKey())->toBe($uuid);
});

/*
 * A self-relation in the lookup (a `withCount`/`whereHas` scope, a `withQuery()` callback) gets a
 * `laravel_reserved_N` alias from a process-wide counter, so no rebuilt SQL ever matched the failing
 * statement: those installs were back to a 500. Decided before the lookup, it no longer matters.
 */
dataset('self-relations in the lookup', [
    'a withCount scope' => [fn () => new EloquentUserProvider(app('hash'), get_class(new class extends ReferringUser
    {
        protected static function booted(): void
        {
            self::addGlobalScope('referrals', fn ($query) => $query->withCount('referrals'));
        }
    }))],
    'a whereHas scope' => [fn () => new EloquentUserProvider(app('hash'), get_class(new class extends ReferringUser
    {
        protected static function booted(): void
        {
            self::addGlobalScope('referrals', fn ($query) => $query->whereHas('referrals'));
        }
    }))],
    'a withQuery() callback' => [fn () => (new EloquentUserProvider(app('hash'), ReferringUser::class))
        ->withQuery(fn ($query) => $query->whereHas('referrals'))],
]);

it('refuses a bad subject and resolves a real one through a self-relation in the lookup', function (Closure $provider) {
    Schema::create('referring_users', function (Blueprint $t) {
        $t->unsignedBigInteger('id')->primary();
        $t->unsignedBigInteger('referrer_id')->nullable();
    });
    DB::table('referring_users')->insert([['id' => 1, 'referrer_id' => null], ['id' => 2, 'referrer_id' => 1]]);
    $users = $provider();

    expect(coIssuerGuard($users, 'admin'))->toBeNull()
        ->and(coIssuerGuard($users, '1')?->getKey())->toBe(1);
})->with('self-relations in the lookup');

it('reports a scope whose own binding the column refuses, rather than reading it as no user', function () {
    if (ConcurrencyTestCase::engine() !== 'pgsql') {
        test()->markTestSkipped('MySQL coerces the value instead of refusing it, so no statement fails');
    }

    // A tenant scope comparing a bigint column with 'acme' fails EVERY lookup: a broken application, and
    // read as "no user" it was a 401 for everybody — an outage nobody was told about. It is the 500.
    Schema::create('tenant_users', function (Blueprint $t) {
        $t->unsignedBigInteger('id')->primary();
        $t->unsignedBigInteger('tenant_id');
    });
    DB::table('tenant_users')->insert(['id' => 1, 'tenant_id' => 9]);
    $model = new class extends SnowflakeUser
    {
        protected $table = 'tenant_users';

        protected static function booted(): void
        {
            self::addGlobalScope('tenant', fn ($query) => $query->where('tenant_id', 'acme'));
        }
    };

    expect(fn () => coIssuerGuard($model::class, '1'))->toThrow(QueryException::class, '22P02');
});

it('refuses a subject carrying a NUL, which PostgreSQL would have truncated to another account', function () {
    // pdo_pgsql passes a bound string as a C string: `alice\0x` looked up `alice`.
    Schema::create('handle_users', function (Blueprint $t) {
        $t->id();
        $t->string('handle')->unique();
    });
    DB::table('handle_users')->insert(['handle' => 'alice']);
    $model = new class extends SnowflakeUser
    {
        protected $table = 'handle_users';

        public function getAuthIdentifierName(): string
        {
            return 'handle';
        }
    };

    expect(coIssuerGuard($model::class, 'alice')?->getAuthIdentifier())->toBe('alice')
        ->and(coIssuerGuard($model::class, "alice\0x"))->toBeNull();
});

it('leaves the caller\'s transaction usable when reading the column type fails', function () {
    if (ConcurrencyTestCase::engine() !== 'pgsql') {
        test()->markTestSkipped('only PostgreSQL aborts a transaction on a failed statement');
    }

    // The catalog read must never cost the caller its transaction: a failed statement aborts it on
    // PostgreSQL. Made to fail for real here — a division by zero ON the connection — and then refused.
    Schema::create('snowflake_users', fn (Blueprint $t) => $t->unsignedBigInteger('id')->primary());
    DB::table('snowflake_users')->insert(['id' => 7]);
    DB::connection()->beforeExecuting(function (string $sql, array $bindings, Connection $connection) {
        if (str_contains($sql, 'pg_attribute') || str_contains($sql, 'information_schema.columns')) {
            try {
                $connection->getPdo()->exec('select 1/0');
            } catch (PDOException) {
            }

            throw new RuntimeException('catalog unavailable');
        }
    });

    $resolved = DB::transaction(function () {
        DB::table('users')->insert(['email' => 'inside@example.com', 'password' => 'x']);
        $user = coIssuerGuard(SnowflakeUser::class, '7');

        return [$user?->getKey(), DB::table('users')->where('email', 'inside@example.com')->count()];
    });

    expect($resolved)->toBe([7, 1]);
});

function coIssuerFamilyIsLive(string $refreshToken): bool
{
    return DB::table('refresh_tokens')
        ->where('token_hash', app(TokenIssuer::class)->hash($refreshToken))
        ->whereNull('revoked_at')->exists();
}
