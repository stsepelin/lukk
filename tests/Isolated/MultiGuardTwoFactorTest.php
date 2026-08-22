<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Crypt;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Lukk;
use Lukk\Tests\Fixtures\Admin;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\MultiGuardTestCase;
use PragmaRX\Google2FA\Google2FA;

uses(MultiGuardTestCase::class)->group('multi-guard', 'two-factor');

/** Enrol a real, confirmed second factor on the given model. */
function enrolTwoFactor(object $model): string
{
    $secret = app(TwoFactorProvider::class)->generateSecret();

    $model->forceFill([
        'two_factor_secret' => Crypt::encryptString($secret),
        'two_factor_confirmed_at' => now(),
    ])->save();

    return $secret;
}

it('gives a secondary guard somewhere to answer its own two-factor challenge', function () {
    // `login` answers `{"two_factor": true}` on any guard whose resolved config enables the feature,
    // but the redemption route was mounted only on the default guard. An enrolled account on a
    // secondary guard was therefore challenged with no endpoint to complete the challenge —
    // enrolled, told to prove itself, and bricked.
    config(['lukk.features.two_factor' => true]);
    $admin = Admin::factory()->create(['email' => 'admin@example.test']);
    $secret = enrolTwoFactor($admin);

    $challenge = $this->postJson('/admin/auth/login', ['email' => $admin->email, 'password' => 'password'])
        ->assertOk()->assertJsonPath('two_factor', true)->json('challenge_token');

    app('auth')->forgetGuards();

    $this->postJson('/admin/auth/two-factor-challenge', [
        'challenge_token' => $challenge,
        'code' => app(Google2FA::class)->getCurrentOtp($secret),
    ])->assertOk()->assertJsonStructure(['access_token']);
});

it('honours a per-guard features.two_factor override at login', function () {
    // Read from the GLOBAL block, a guard that switched two-factor off was still challenged — the
    // exact pattern CLAUDE.md records as previously exploitable for `features.abilities` and
    // `gate_auth_routes`.
    config(['lukk.features.two_factor' => true, 'lukk.guards.admin.features.two_factor' => false]);
    $admin = Admin::factory()->create(['email' => 'nofa@example.test']);
    enrolTwoFactor($admin);

    $this->postJson('/admin/auth/login', ['email' => $admin->email, 'password' => 'password'])
        ->assertOk()
        ->assertJsonMissingPath('two_factor')
        ->assertJsonStructure(['access_token']);
});

it('refuses a challenge minted by another guard', function () {
    // Isolation used to rest entirely on the consumer giving each guard a distinct crypto identity.
    // Under the minimal shape — only `provider` and `path` differ — a challenge asserting "admins.1
    // cleared the first factor" was redeemable as "users.1 cleared the first factor": not a
    // second-factor bypass, but a FIRST-factor one, a session on a guard whose password was never
    // presented.
    // The admin guard SHARES the default guard's crypto identity — only `provider` and `path`
    // differ. That is the minimal multi-guard shape, and the only one where this is reachable: with
    // distinct issuer/audience/secret the challenge is already refused on audience, so a test using
    // the harness defaults passes without exercising the binding at all.
    config([
        'lukk.features.two_factor' => true,
        'lukk.guards.admin' => ['path' => 'admin/auth'] + config('lukk.guards.admin'),
        'lukk.guards.admin.issuer' => config('lukk.issuer'),
        'lukk.guards.admin.audience' => config('lukk.audience'),
        'lukk.guards.admin.secret' => config('lukk.secret'),
    ]);
    User::factory()->create();

    Lukk::useGuard('admin');
    $foreign = app(ChallengeToken::class)->issue('2fa', 1, 300);
    Lukk::useGuard(null);

    expect(app(ChallengeToken::class)->verify('2fa', $foreign))->toBeNull();
});

it('refuses a challenge with no exp claim', function () {
    // `exp` is not required by firebase/php-jwt, so a co-issuer could mint an eternal challenge —
    // against "challenge single-use + short TTL". `consume()` also reads `exp` AFTER the second
    // factor verifies, where an uncaught throw 500s the request and leaves the challenge unburned.
    $cfg = Lukk::guardConfig();
    $eternal = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '1',
        'jti' => 'no-exp', 'iat' => time(), 'nbf' => time(),
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => '2fa+challenge']);

    expect(app(ChallengeToken::class)->verify('2fa', $eternal))->toBeNull()
        ->and(app(ChallengeToken::class)->consume('2fa', $eternal))->toBeNull();
});

it('refuses a challenge whose sub is not a string', function () {
    // RFC 8725 §3.11 — validate claim types before use. Reachable from a co-issuer, and a `(string)`
    // cast of an object here is an uncaught Error, contradicting decode()'s "null on any failure".
    $cfg = Lukk::guardConfig();
    $token = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => ['not', 'a', 'string'],
        'jti' => 'bad-sub', 'iat' => time(), 'nbf' => time(), 'exp' => time() + 300,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => '2fa+challenge']);

    expect(app(ChallengeToken::class)->verify('2fa', $token))->toBeNull();
});
