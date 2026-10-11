<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\DB;
use Lukk\Contracts\TokenIssuer;
use Lukk\Lukk;
use Lukk\Tests\ConcurrencyTestCase;
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

function coIssuerFamilyIsLive(string $refreshToken): bool
{
    return DB::table('refresh_tokens')
        ->where('token_hash', app(TokenIssuer::class)->hash($refreshToken))
        ->whereNull('revoked_at')->exists();
}
