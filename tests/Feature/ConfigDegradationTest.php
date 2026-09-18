<?php

declare(strict_types=1);

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Tests\Fixtures\FakeWebAuthnCeremony;
use Lukk\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

/**
 * No `lukk` config key is guaranteed at runtime.
 *
 * `mergeConfigDeep` early-returns when the configuration is cached — the production norm — so an app that
 * ran `config:cache` on one version and upgraded to one that adds a key gets no backfill at all. Every
 * read therefore carries a `?? default`.
 *
 * A default that nothing exercises is a comment. These run the FLOW each key sits on with that key
 * missing, in both shapes it goes missing in, so removing any one of the defaults turns one of them red —
 * which is what the defaults were worth before this file existed: removing 25 of the 30, one at a time,
 * left the whole suite green.
 */
uses()->group('config');

/** A key absent entirely, as a config cached before it existed would have it. */
function withoutLukk(string $key): void
{
    $lukk = (array) config('lukk');
    Arr::forget($lukk, $key);
    config()->set('lukk', $lukk);
}

dataset('missing', [
    'null (a per-guard env that is not set)' => [fn (string $key) => config()->set("lukk.$key", null)],
    'absent (a config cached before the key existed)' => [fn (string $key) => withoutLukk($key)],
]);

function signInFully(User $user): array
{
    return test()->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->json();
}

/** Put a user into a confirmed-2FA state and hand back the plaintext TOTP secret. */
function withTwoFactor(User $user): string
{
    $secret = app(TwoFactorProvider::class)->generateSecret();

    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString($secret),
        'two_factor_recovery_codes' => json_encode([Hash::make('RECOVERY-CODE-1')]),
        'two_factor_confirmed_at' => now(),
    ])->save();

    return $secret;
}

/**
 * How long a minted token is good for, from its own claims.
 *
 * Asserted instead of "does it still work", because it does: a TTL of 0 makes `exp === iat`, and the
 * verifier's `leeway` then accepts it for another five seconds — long enough for a test to spend it and
 * conclude nothing is wrong, which is exactly what the first version of this file concluded.
 */
function lifetimeOf(string $jwt): int
{
    $claims = json_decode((string) base64_decode(strtr(explode('.', $jwt)[1] ?? '', '-_', '+/'), true), true);

    return (int) $claims['exp'] - (int) $claims['iat'];
}

it('signs in, authenticates and rotates without it', function (Closure $break, string $key) {
    $break($key);
    $user = User::factory()->create();

    $tokens = signInFully($user);

    // The access token it just minted has to actually verify — an `access_ttl` of null makes `exp === iat`,
    // and a null `algorithm` is not a degraded HS256: the key ring answers "asymmetric" and reaches for a
    // keypair this install does not have.
    test()->withToken($tokens['access_token'])->postJson('/auth/session/claim')->assertSuccessful();
    app('auth')->forgetGuards();
    test()->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertOk();
})->with('missing')->with(['access_ttl', 'algorithm', 'leeway', 'grace_seconds', 'refresh_ttl', 'claim_seconds']);

it('completes a two-factor sign-in without it', function (Closure $break, string $key) {
    $break($key);
    $user = User::factory()->create();
    $secret = withTwoFactor($user);

    // A `challenge_ttl` of 0 mints a challenge whose `exp` equals its `iat`; 0 attempts on the second
    // factor is the "missing rate-limit key locks everyone out" shape; a null `window` is a TOTP that
    // never matches. Each one ends the same way: nobody with 2FA on can finish signing in.
    $challenge = test()->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->json('challenge_token');

    expect(lifetimeOf($challenge))->toBe(300);
    test()->postJson('/auth/two-factor-challenge', [
        'challenge_token' => $challenge,
        'code' => app(Google2FA::class)->getCurrentOtp($secret),
    ])->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
})->with('missing')->with([
    'two_factor.challenge_ttl',
    'two_factor.window',
    'rate_limits.two_factor.max_attempts',
    'rate_limits.two_factor.decay_seconds',
    'leeway',
    'algorithm',
]);

it('earns and spends a step-up confirmation without it', function (Closure $break, string $key) {
    $break($key);
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;

    // `confirm.ttl` unguarded is a token expired at birth; `confirm.header` unguarded is an empty header
    // name, so the confirmation the client presents is never found and the step-up never completes.
    $token = test()->withToken($access)->postJson('/auth/confirm-password', ['password' => 'password'])
        ->assertOk()->json('confirmation_token');

    expect(lifetimeOf($token))->toBe(300);
    $header = (string) (config('lukk.confirm.header') ?? 'X-Lukk-Confirmation');
    test()->withToken($access)->withHeaders([$header => $token])
        ->postJson('/auth/two-factor')->assertSuccessful();
})->with('missing')->with(['confirm.ttl', 'confirm.header', 'leeway', 'algorithm']);

it('registers a passkey without it', function (Closure $break, string $key) {
    app()->bind(WebAuthnCeremony::class, FakeWebAuthnCeremony::class);
    $break($key);
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $headers = confirmedHeaders($access);

    // A `challenge_ttl` of 0 is the sharp one: the cache FORGETS a key written with a non-positive TTL,
    // so the challenge is gone before the authenticator answers and every registration and login fails.
    $challenge = test()->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys/registration-options')->assertOk()->json('challenge');

    test()->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys', [
        'name' => 'My Key',
        'credential' => ['challenge' => $challenge, 'id' => 'cred-1', 'public_key' => 'PUB', 'sign_count' => 0],
    ])->assertNoContent();

    expect(app(PasskeyRepository::class)->findByCredentialId('cred-1'))->not->toBeNull();
})->with('missing')->with(['passkeys.challenge_ttl', 'passkeys.user_verification', 'passkeys.rp_name']);

it('hands out the documented number of recovery codes without it', function (Closure $break, string $key) {
    $break($key);
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;

    $codes = test()->withToken($access)->withHeaders(confirmedHeaders($access))
        ->postJson('/auth/two-factor')->assertOk()->json('recovery_codes');

    // Unguarded this is zero codes: 2FA enables, the user is shown an empty list, and the only way back
    // into a lost-authenticator account is gone.
    expect($codes)->toHaveCount(8);
})->with('missing')->with(['two_factor.recovery_codes']);

it('refuses tokens rather than inventing an identity, when the binding claims are missing', function (Closure $break, string $key) {
    // The deliberate exception: `issuer` and `audience` are NOT defaulted. Config's placeholder
    // (`https://api.example.com`) would be the wrong fallback — an admin guard whose `LUKK_ADMIN_AUDIENCE`
    // is unset would collapse onto the default guard's audience, which IS the isolation boundary between
    // them. So both fail closed, and this pins that they do, on both token kinds: the challenge used to
    // pass because `null === null` and `[] === []` both hold, leaving it bound to nothing at all.
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $secret = withTwoFactor($user);

    // Broken BEFORE anything is minted, which is the state that matters: a token minted while the key was
    // still there carries it and is refused by the plain comparison anyway. The hole was the token minted
    // AND verified without one — `iss` absent, `aud` empty, `null === null` and `[] === []` both true.
    $break($key);
    app('auth')->forgetGuards();

    expect(verifier()->verify($access))->toBeNull();
    test()->withToken($access)->postJson('/auth/session/claim')->assertUnauthorized();

    $challenge = test()->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->json('challenge_token');

    test()->postJson('/auth/two-factor-challenge', [
        'challenge_token' => $challenge,
        'code' => app(Google2FA::class)->getCurrentOtp($secret),
    ])->assertStatus(422);
})->with('missing')->with(['issuer', 'audience']);
