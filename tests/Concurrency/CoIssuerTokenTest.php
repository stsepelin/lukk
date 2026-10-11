<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
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
use Lukk\Tests\Fixtures\UlidUser;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\Fixtures\UuidUser;

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
 * What the guard refuses with a 401 and NO query, and what it leaves to the provider.
 *
 * It refuses only what it knows without I/O: the identifier is the model's key, and that key is the stock
 * auto-incrementing integer (a canonical integer within signed 64 bits), a `HasUuids` UUID or a `HasUlids`
 * ULID. Any other shape — a Snowflake key that does not increment, an identifier that is another column,
 * a uuid column the model declares nothing about, a 32-bit `increments('id')` handed a value past int4 —
 * goes to the provider, and on PostgreSQL a subject its column cannot hold is a REPORTED 500: the token is
 * signed by a trusted issuer, so such a subject is that issuer's bug. Reading the schema to decide it cost
 * every request a catalog query on the write connection; interpreting the failed lookup hid real outages
 * as 401s. MySQL coerces instead, so there such a subject simply names no user.
 */

function coIssuerGuard(string|EloquentUserProvider $model, string $sub): ?Authenticatable
{
    $guard = new JwtGuard(app(TokenVerifier::class), is_string($model) ? new EloquentUserProvider(app('hash'), $model) : $model);

    return $guard(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer '.coIssuedAccess(['sub' => $sub])]));
}

/** The guard's result for `$sub`, and how many statements it ran on any connection. */
function guardWithQueries(string|EloquentUserProvider $model, string $sub): array
{
    $queries = 0;
    Event::listen(QueryExecuted::class, function () use (&$queries) {
        $queries++;
    });
    $user = coIssuerGuard($model, $sub);
    Event::forget(QueryExecuted::class);

    return [$user, $queries];
}

/** A refused parameter is the provider's error: reported on PostgreSQL, no match where the engine coerces. */
function expectSurfaces(Closure $guard): void
{
    ConcurrencyTestCase::engine() === 'pgsql'
        ? expect($guard)->toThrow(QueryException::class)
        : expect($guard())->toBeNull();
}

dataset('shapes refused without a query', [
    'the stock id(), a word' => [fn () => User::class, fn () => (string) User::factory()->create()->getKey(), 'admin'],
    'the stock id(), past 64 bits' => [fn () => User::class, fn () => (string) User::factory()->create()->getKey(), '99999999999999999999'],
    'the stock id(), a fraction' => [fn () => User::class, fn () => (string) User::factory()->create()->getKey(), '1.5'],
    'the stock id(), zero-padded' => [fn () => User::class, fn () => (string) User::factory()->create()->getKey(), '01'],
    'the stock id(), signed' => [fn () => User::class, fn () => (string) User::factory()->create()->getKey(), '+1'],
    'HasUuids' => [function () {
        Schema::create('uuid_users', fn (Blueprint $t) => $t->uuid('id')->primary());

        return UuidUser::class;
    }, fn () => (string) UuidUser::query()->create()->getKey(), 'admin'],
    'HasUlids' => [function () {
        Schema::create('ulid_users', fn (Blueprint $t) => $t->ulid('id')->primary());

        return UlidUser::class;
    }, fn () => (string) UlidUser::query()->create()->getKey(), 'admin'],
]);

it('refuses a subject the key cannot hold with no query, and resolves a real one with exactly one', function (Closure $model, Closure $real, string $bad) {
    $class = $model();
    $id = $real();

    [$refused, $none] = guardWithQueries($class, $bad);
    [$resolved, $one] = guardWithQueries($class, $id);

    expect($refused)->toBeNull()->and($none)->toBe(0)
        ->and((string) $resolved?->getAuthIdentifier())->toBe($id)->and($one)->toBe(1);
})->with('shapes refused without a query');

it('leaves the caller\'s transaction usable: a refused subject runs no statement', function () {
    $written = DB::transaction(function () {
        DB::table('users')->insert(['email' => 'inside@example.com', 'password' => 'x']);
        expect(coIssuerGuard(User::class, 'admin'))->toBeNull();

        return DB::table('users')->where('email', 'inside@example.com')->count();
    });

    expect($written)->toBe(1);
});

dataset('shapes left to the provider', [
    'a non-incrementing bigint key (Snowflake)' => [function () {
        Schema::create('snowflake_users', fn (Blueprint $t) => $t->unsignedBigInteger('id')->primary());
        DB::table('snowflake_users')->insert(['id' => 1234567890123456789]);

        return SnowflakeUser::class;
    }, '1234567890123456789', 'admin'],
    'an integer identifier that is not the key' => [function () {
        Schema::create('legacy_id_users', function (Blueprint $t) {
            $t->id();
            $t->integer('legacy_id')->unique();
        });
        DB::table('legacy_id_users')->insert(['legacy_id' => 7]);

        return LegacyIdUser::class;
    }, '7', 'admin'],
    'a 32-bit increments(\'id\') and a subject past it' => [function () {
        Schema::create('int_key_users', fn (Blueprint $t) => $t->increments('id'));
        DB::table('int_key_users')->insert(['id' => 5]);

        return IntKeyUser::class;
    }, '5', '3000000000'],
    'a uuid key the model declares nothing about' => [function () {
        Schema::create('plain_uuid_users', fn (Blueprint $t) => $t->uuid('id')->primary());
        DB::table('plain_uuid_users')->insert(['id' => 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11']);

        return get_class(new class extends SnowflakeUser
        {
            protected $table = 'plain_uuid_users';

            protected $keyType = 'string';
        });
    }, 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'admin'],
]);

it('leaves every other shape to the provider: a real user resolves, a subject the column refuses is reported', function (Closure $model, string $real, string $bad) {
    $class = $model();

    [$resolved, $queries] = guardWithQueries($class, $real);

    expect((string) $resolved?->getAuthIdentifier())->toBe($real)->and($queries)->toBe(1);
    expectSurfaces(fn () => coIssuerGuard($class, $bad));
})->with('shapes left to the provider');

/*
 * However the model names its table, the guard reads nothing from the schema: the stock key is refused
 * from the model alone, and a real user resolves with the one lookup.
 */
dataset('table spellings', [
    'schema-qualified' => ['public.spelled_users', null, 'spelled_users'],
    'aliased' => ['spelled_users as s', null, 'spelled_users'],
    'schema-qualified on a prefixed connection' => ['public.spelled_users', 'app_', 'app_spelled_users'],
]);

it('refuses a bad subject and resolves a real one however the model spells its table', function (string $table, ?string $prefix, string $physical) {
    if (ConcurrencyTestCase::engine() !== 'pgsql') {
        test()->markTestSkipped('MySQL has no `public` schema');
    }

    config(['database.connections.spelled' => [...ConcurrencyTestCase::config('pgsql'), 'prefix' => (string) $prefix]]);
    Schema::create($physical, fn (Blueprint $t) => $t->id());
    DB::table($physical)->insert(['id' => 5]);
    $model = new class extends IntKeyUser
    {
        protected $connection = 'spelled';

        public static string $spelling = '';

        public function getTable(): string
        {
            return self::$spelling;
        }
    };
    $model::$spelling = $table;

    [$refused, $none] = guardWithQueries($model::class, 'admin');
    [$resolved, $one] = guardWithQueries($model::class, '5');

    expect($refused)->toBeNull()->and($none)->toBe(0)
        ->and($resolved?->getKey())->toBe(5)->and($one)->toBe(1);
})->with('table spellings');

/*
 * A self-relation in the lookup (a `withCount`/`whereHas` scope, a `withQuery()` callback) gets a
 * `laravel_reserved_N` alias from a process-wide counter. Nothing here depends on the SQL, so it resolves.
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

it('resolves a real user through a self-relation in the lookup, and reports a subject its column refuses', function (Closure $provider) {
    Schema::create('referring_users', function (Blueprint $t) {
        $t->unsignedBigInteger('id')->primary();
        $t->unsignedBigInteger('referrer_id')->nullable();
    });
    DB::table('referring_users')->insert([['id' => 1, 'referrer_id' => null], ['id' => 2, 'referrer_id' => 1]]);
    $users = $provider();

    expect(coIssuerGuard($users, '1')?->getKey())->toBe(1);
    expectSurfaces(fn () => coIssuerGuard($users, 'admin'));
})->with('self-relations in the lookup');

it('reports a refusal in another statement of the lookup — an eager-loaded relation', function () {
    if (ConcurrencyTestCase::engine() !== 'pgsql') {
        test()->markTestSkipped('MySQL coerces the value instead of refusing it, so no statement fails');
    }

    // A mistyped `$with` relation fails every lookup of a real user: an outage, reported as one.
    Schema::create('things', function (Blueprint $t) {
        $t->id();
        $t->uuid('owner_uuid');
    });
    $user = EagerThingsUser::query()->create(['email' => 'eager@example.com', 'password' => 'x']);

    expect(fn () => coIssuerGuard(EagerThingsUser::class, (string) $user->getKey()))
        ->toThrow(QueryException::class, '22P02');
});

it('reports a scope whose own binding the column refuses', function () {
    if (ConcurrencyTestCase::engine() !== 'pgsql') {
        test()->markTestSkipped('MySQL coerces the value instead of refusing it, so no statement fails');
    }

    // A tenant scope comparing a bigint column with 'acme' fails EVERY lookup — a 500, never a 401.
    Schema::create('tenant_users', function (Blueprint $t) {
        $t->id();
        $t->unsignedBigInteger('tenant_id');
    });
    DB::table('tenant_users')->insert(['id' => 1, 'tenant_id' => 9]);
    $model = new class extends IntKeyUser
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
        ->and(guardWithQueries($model::class, "alice\0x"))->toBe([null, 0]);
});

function coIssuerFamilyIsLive(string $refreshToken): bool
{
    return DB::table('refresh_tokens')
        ->where('token_hash', app(TokenIssuer::class)->hash($refreshToken))
        ->whereNull('revoked_at')->exists();
}
