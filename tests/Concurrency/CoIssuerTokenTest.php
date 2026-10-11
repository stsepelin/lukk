<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Lukk\Auth\JwtGuard;
use Lukk\Contracts\TokenIssuer;
use Lukk\Contracts\TokenVerifier;
use Lukk\Lukk;
use Lukk\Tests\ConcurrencyTestCase;
use Lukk\Tests\Fixtures\EagerThingsUser;
use Lukk\Tests\Fixtures\IntKeyUser;
use Lukk\Tests\Fixtures\LegacyIdUser;
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
 * The key-type check is a fast path, not the whole answer: lukk cannot know every integer column. A model
 * whose key is not incrementing but is still an integer (Snowflake ids), one whose auth identifier is
 * another integer column, and the stock 32-bit `increments('id')` with a subject past int4 all reached
 * PostgreSQL with a value its parameter type refuses — 22P02/22003, a 500 — where a `sub` naming no user
 * is a 401.
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

it('does not swallow a refusal on a connection its savepoint did not cover', function () {
    if (ConcurrencyTestCase::engine() !== 'pgsql') {
        test()->markTestSkipped('MySQL coerces the value instead of refusing it, so no statement fails');
    }

    // A provider may look up on a connection other than its model's. The savepoint is taken on the
    // MODEL's connection; a refusal on the other one, inside that one's own transaction, leaves it aborted
    // — so it is reported, never answered as no user.
    config(['database.connections.other' => ConcurrencyTestCase::config(ConcurrencyTestCase::engine())]);
    Schema::create('snowflake_users', fn (Blueprint $t) => $t->unsignedBigInteger('id')->primary());
    $provider = new class(app('hash'), SnowflakeUser::class) extends EloquentUserProvider
    {
        public function retrieveById($identifier)
        {
            return SnowflakeUser::on('other')->where('id', $identifier)->first();
        }
    };

    DB::transaction(function () use ($provider) {
        DB::connection('other')->beginTransaction();

        try {
            expect(fn () => coIssuerGuard($provider, 'admin'))->toThrow(QueryException::class);
        } finally {
            DB::connection('other')->rollBack();
        }
    });
});

function coIssuerFamilyIsLive(string $refreshToken): bool
{
    return DB::table('refresh_tokens')
        ->where('token_hash', app(TokenIssuer::class)->hash($refreshToken))
        ->whereNull('revoked_at')->exists();
}
