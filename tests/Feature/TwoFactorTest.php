<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiter;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

uses()->group('two-factor');

/** Put a user straight into a confirmed-2FA state and return the plaintext secret. */
function confirmedTwoFactor(User $user): string
{
    $secret = app(TwoFactorProvider::class)->generateSecret();

    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString($secret),
        'two_factor_recovery_codes' => json_encode([Hash::make('RECOVERY-CODE-1')]),
        'two_factor_confirmed_at' => now(),
    ])->save();

    return $secret;
}

function currentOtp(string $secret): string
{
    return app(Google2FA::class)->getCurrentOtp($secret);
}

it('requires a fresh confirmation to manage 2FA', function () {
    $token = User::factory()->create()->startSession()->accessToken;

    $this->withToken($token)->postJson('/auth/two-factor')->assertStatus(423);
});

it('rejects password confirmation with a wrong password', function () {
    $token = User::factory()->create()->startSession()->accessToken;

    $this->withToken($token)->postJson('/auth/confirm-password', ['password' => 'wrong'])->assertStatus(422);
});

it('enrolls 2FA but does not activate it until confirmed', function () {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->postJson('/auth/two-factor')
        ->assertOk()
        ->assertJsonStructure(['otpauth_uri', 'recovery_codes']);

    expect($user->fresh()->hasEnabledTwoFactor())->toBeFalse();
});

it('activates 2FA after confirming a valid code', function () {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);

    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor')->assertOk();

    $code = currentOtp($user->fresh()->twoFactorSecret());
    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor/confirm', ['code' => $code])->assertNoContent();

    expect($user->fresh()->hasEnabledTwoFactor())->toBeTrue();
});

it('rejects confirmation with a wrong code (stays unconfirmed)', function () {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);
    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor')->assertOk();

    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor/confirm', ['code' => '000000'])
        ->assertStatus(422);

    expect($user->fresh()->hasEnabledTwoFactor())->toBeFalse();
});

it('regenerates recovery codes, invalidating the old set', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $token = $user->startSession()->accessToken;

    $new = $this->withToken($token)->withHeaders(confirmedHeaders($token))->postJson('/auth/two-factor/recovery-codes')
        ->assertOk()
        ->assertJsonStructure(['recovery_codes'])
        ->json('recovery_codes');

    expect($new)->toHaveCount(8);
    expect($user->fresh()->useRecoveryCode('RECOVERY-CODE-1'))->toBeFalse();
    expect($user->fresh()->useRecoveryCode($new[0]))->toBeTrue();
});

it('disables 2FA', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $token = $user->startSession()->accessToken;

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->deleteJson('/auth/two-factor')->assertNoContent();

    expect($user->fresh()->hasEnabledTwoFactor())->toBeFalse();
});

it('returns a 2FA challenge at login instead of tokens when 2FA is confirmed', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()
        ->assertJson(['two_factor' => true])
        ->assertJsonStructure(['challenge_token'])
        ->assertJsonMissing(['access_token']);
});

it('completes the login by exchanging the challenge with a TOTP code', function () {
    $user = User::factory()->create();
    $secret = confirmedTwoFactor($user);

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => currentOtp($secret)])
        ->assertOk()
        ->assertJsonStructure(['access_token', 'refresh_token']);
});

it('completes the login with a recovery code and consumes it', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'RECOVERY-CODE-1'])
        ->assertOk()
        ->assertJsonStructure(['access_token']);

    expect($user->fresh()->useRecoveryCode('RECOVERY-CODE-1'))->toBeFalse();
});

it('rejects a wrong code and leaves the challenge usable for a retry', function () {
    $user = User::factory()->create();
    $secret = confirmedTwoFactor($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => '000000'])
        ->assertStatus(422);

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => currentOtp($secret)])
        ->assertOk()
        ->assertJsonStructure(['access_token']);
});

it('locks out the challenge after too many wrong codes (account-keyed)', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    foreach (range(1, 5) as $i) {
        $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => '000000'])
            ->assertStatus(422);
    }

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => '000000'])
        ->assertStatus(429);
});

it('honors the configured two-factor challenge rate limit', function () {
    config(['lukk.rate_limits.two_factor.max_attempts' => 2]);
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => '000000'])->assertStatus(422);
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => '000000'])->assertStatus(422);
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => '000000'])->assertStatus(429);
});

it('rejects an invalid or expired challenge token', function () {
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => 'nope', 'code' => '123456'])
        ->assertStatus(422);
});

it('rejects the challenge if 2FA was disabled after it was issued', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $user->forceFill(['two_factor_confirmed_at' => null])->save();

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => '123456'])
        ->assertStatus(422);
});

it('stamps amr=[pwd,otp] on the token issued after a 2FA login', function () {
    $user = User::factory()->create();
    $secret = confirmedTwoFactor($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $access = $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => currentOtp($secret)])
        ->json('access_token');

    expect(verifier()->verify($access)->amr)->toBe(['pwd', 'otp']);
});

it('throttles challenge verification per account, independent of the IP route limit', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    // Saturate ONLY the action's per-account limiter; the route's per-IP limiter
    // stays clean, so a 429 here proves the account-keyed check fired — not the
    // throttle middleware (which the other lock-out tests trip first).
    $key = 'lukk:2fa-challenge:'.$user->id;
    $max = (int) config('lukk.rate_limits.two_factor.max_attempts');
    foreach (range(1, $max) as $ignored) {
        app(RateLimiter::class)->hit($key);
    }

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => '000000'])
        ->assertStatus(429);
});

it('reports how many recovery codes remain', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user); // one hashed recovery code
    $access = $user->startSession()->accessToken;

    $this->withToken($access)->getJson('/auth/two-factor/recovery-codes')
        ->assertOk()
        ->assertExactJson(['remaining' => 1, 'total' => 8]);
});

it('the remaining count drops as recovery codes are consumed', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user); // one code: RECOVERY-CODE-1
    $access = $user->startSession()->accessToken;

    $this->withToken($access)->getJson('/auth/two-factor/recovery-codes')->assertJson(['remaining' => 1]);

    $user->useRecoveryCode('RECOVERY-CODE-1'); // consume it (single-use)
    $this->app['auth']->forgetGuards();        // force a fresh user resolve from DB

    $this->withToken($access)->getJson('/auth/two-factor/recovery-codes')->assertJson(['remaining' => 0]);
});

it('requires authentication to read the recovery-code count', function () {
    $this->getJson('/auth/two-factor/recovery-codes')->assertUnauthorized();
});

it('reports zero remaining when the recovery-code column is not a list', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $user->forceFill(['two_factor_recovery_codes' => '5'])->save(); // a scalar, not a JSON array

    expect($user->recoveryCodesRemaining())->toBe(0);
});
