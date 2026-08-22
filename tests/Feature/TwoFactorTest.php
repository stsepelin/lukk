<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\ChallengeTwoFactor;
use Lukk\Actions\ConfirmTwoFactor;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Models\Lockout;
use Lukk\Tests\Fixtures\PermissiveTotpProvider;
use Lukk\Tests\Fixtures\UndecryptableTwoFactorUser;
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

    expect($user->refresh()->hasEnabledTwoFactor())->toBeFalse();
});

it('activates 2FA after confirming a valid code', function () {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);

    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor')->assertOk();

    $code = currentOtp($user->refresh()->twoFactorSecret());
    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor/confirm', ['code' => $code])->assertNoContent();

    expect($user->refresh()->hasEnabledTwoFactor())->toBeTrue();
});

it('rejects confirmation with a wrong code (stays unconfirmed)', function () {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);
    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor')->assertOk();

    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor/confirm', ['code' => '000000'])
        ->assertStatus(422);

    expect($user->refresh()->hasEnabledTwoFactor())->toBeFalse();
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
    expect($user->refresh()->useRecoveryCode('RECOVERY-CODE-1'))->toBeFalse();
    expect($user->refresh()->useRecoveryCode($new[0]))->toBeTrue();
});

it('disables 2FA', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $token = $user->startSession()->accessToken;

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->deleteJson('/auth/two-factor')->assertNoContent();

    expect($user->refresh()->hasEnabledTwoFactor())->toBeFalse();
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

it('returns 422, not a 500, for a malformed two-factor-challenge input', function () {
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => 'x', 'code' => ['not', 'a', 'string']])
        ->assertStatus(422);
});

it('hides the two-factor secret and recovery codes from model serialization', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);

    $array = $user->refresh()->toArray();

    expect($array)->not->toHaveKey('two_factor_secret')
        ->and($array)->not->toHaveKey('two_factor_recovery_codes');
});

it('completes the login with a recovery code and consumes it', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'RECOVERY-CODE-1'])
        ->assertOk()
        ->assertJsonStructure(['access_token']);

    expect($user->refresh()->useRecoveryCode('RECOVERY-CODE-1'))->toBeFalse();
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

    expect(claims($access)->amr)->toBe(['pwd', 'otp']);
});

it('throttles challenge verification per account, independent of the IP route limit', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    // Saturate ONLY the action's per-account limiter; the route's per-IP limiter
    // stays clean, so a 429 here proves the account-keyed check fired — not the
    // throttle middleware (which the other lock-out tests trip first).
    // Guard-scoped, like every other lukk bucket.
    $key = 'lukk:2fa-challenge:'.config('lukk.guard', 'api').':'.$user->id;
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
    app('auth')->forgetGuards();        // force a fresh user resolve from DB

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

it('locks a user after a run of failed two-factor codes, which is the clause\'s real gap', function () {
    // The per-account 2FA limiter is a decaying 5/60s window, so lifetime guesses were unbounded —
    // roughly 7,200/day against a 6-digit code. This is the cap NIST SP 800-63B §5.2.2 asks for.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.rate_limits.two_factor.max_attempts' => 500]);
    $user = User::factory()->create();
    confirmedTwoFactor($user);

    $challenge = fn () => test()->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    for ($i = 0; $i < 3; $i++) {
        app('auth')->forgetGuards();
        $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge(), 'code' => '000000'])
            ->assertStatus(422);
    }

    app('auth')->forgetGuards();
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge(), 'code' => '000000'])
        ->assertStatus(423);
});

it('keeps the two-factor lock separate from the login lock for the same account', function () {
    // Different authenticators, different runs — burning one must not spend the other's budget.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.rate_limits.two_factor.max_attempts' => 500]);
    $user = User::factory()->create(['email' => 'victim@y.com']);
    confirmedTwoFactor($user);

    for ($i = 0; $i < 3; $i++) {
        app('auth')->forgetGuards();
        $challenge = $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'password'])->json('challenge_token');
        $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => '000000']);
    }

    // 2FA is locked, but the password step still works — it has its own untouched counter.
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'password'])
        ->assertOk()
        ->assertJson(['two_factor' => true]);
});

it('does not let a junk recovery_code smuggle a TOTP guess past the lock', function () {
    // The exemption is for a recovery-code-ONLY attempt. Keyed on the field's mere presence, it
    // handed the cap away: the challenge action tries the TOTP code first, so attaching any junk
    // recovery code resumed brute-forcing the 6-digit space against a locked account.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.rate_limits.two_factor.max_attempts' => 500]);
    $user = User::factory()->create();
    $secret = confirmedTwoFactor($user);

    $challenge = fn () => test()->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    for ($i = 0; $i < 3; $i++) {
        app('auth')->forgetGuards();
        $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge(), 'code' => '000000']);
    }

    // The two credentials are now mutually exclusive, so the smuggling shape is refused outright
    // — one request can no longer buy two verifications off a single limiter slot either.
    app('auth')->forgetGuards();
    $this->postJson('/auth/two-factor-challenge', [
        'challenge_token' => $challenge(), 'code' => '000000', 'recovery_code' => 'not-a-real-code',
    ])->assertStatus(422)->assertJsonValidationErrors(['code']);

    // And the lock still holds for a plain code attempt — including the RIGHT code, since a lock
    // the caller can shrug off isn't a lock.
    app('auth')->forgetGuards();
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge(), 'code' => currentOtp($secret)])
        ->assertStatus(423);
});

it('still lets a recovery code alone out of a two-factor lock', function () {
    // The exemption itself must survive the fix above: a recovery code is ~119 bits, single-use and
    // hashed, so a consecutive cap protects nothing — and gating it would strand a user whose
    // second factor an attacker deliberately burned.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.rate_limits.two_factor.max_attempts' => 500]);
    $user = User::factory()->create();
    confirmedTwoFactor($user);

    $challenge = fn () => test()->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    for ($i = 0; $i < 3; $i++) {
        app('auth')->forgetGuards();
        $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge(), 'code' => '000000']);
    }

    app('auth')->forgetGuards();
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge(), 'recovery_code' => 'RECOVERY-CODE-1'])
        ->assertOk()
        ->assertJsonStructure(['access_token']);
});

it('does not let recovery-code failures drive the two-factor lock', function () {
    // The cap exists for a 6-digit secret. Counting failures against a 119-bit one would hand
    // anyone holding a challenge token a way to lock the account without guessing a TOTP at all.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.rate_limits.two_factor.max_attempts' => 500]);
    $user = User::factory()->create();
    confirmedTwoFactor($user);

    $challenge = fn () => test()->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    foreach (range(1, 5) as $i) {
        app('auth')->forgetGuards();
        $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge(), 'recovery_code' => 'wrong-code'])
            ->assertStatus(422);
    }

    expect(Lockout::where('purpose', 'two_factor')->exists())->toBeFalse();
});

it('refuses a two-factor request that lost the reservation race', function () {
    // As with login: the state left by concurrent requests that all passed the gate together.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.rate_limits.two_factor.max_attempts' => 500]);
    $user = User::factory()->create();
    $secret = confirmedTwoFactor($user);
    Lockout::create([
        'purpose' => 'two_factor', 'subject' => (string) $user->getKey(), 'guard' => 'api',
        'attempts' => 3, 'locked_at' => null,
    ]);

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    app('auth')->forgetGuards();
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => currentOtp($secret)])
        ->assertStatus(423);
});

it('refuses to re-enrol over confirmed two-factor instead of silently disabling it', function () {
    // Re-enrolling overwrote the secret and nulled `two_factor_confirmed_at`, so a user who
    // reopened the QR screen and wandered off was left with 2FA OFF — and unlike DELETE there was
    // nothing an app could hang a "your second factor was removed" notification on.
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $access = $user->startSession()->accessToken;

    $this->withHeaders(confirmedHeaders($access))->postJson('/auth/two-factor')->assertStatus(409);

    // Still enabled, still the same secret, still challenging at login.
    expect($user->refresh()->hasEnabledTwoFactor())->toBeTrue();

    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->assertJson(['two_factor' => true]);
});

it('refuses a challenge when the second-factor secret cannot be read', function () {
    // `(string) null` is `''`. The bundled provider rejects an empty key, but a custom
    // `TwoFactorProvider` need not — so casting turned "the secret could not be decrypted" into a
    // SUCCESSFUL challenge. Refuse instead: an unreadable secret is not a passing second factor.
    config(['auth.providers.users.model' => UndecryptableTwoFactorUser::class]);
    $user = UndecryptableTwoFactorUser::factory()->create();

    expect(fn () => app(ChallengeTwoFactor::class)($user->getKey(), '000000', null))
        ->toThrow(ValidationException::class);
});

it('still accepts a recovery code when the second-factor secret cannot be read', function () {
    // Recovery codes are the escape hatch for "my authenticator is unusable" — and a secret the
    // server cannot decrypt is exactly that. Their verification never touches the secret, so
    // refusing before this branch would lock the account out of its own recovery path.
    config(['auth.providers.users.model' => UndecryptableTwoFactorUser::class]);
    $user = UndecryptableTwoFactorUser::factory()->create();
    $codes = $user->generateRecoveryCodes(8);

    $resolved = app(ChallengeTwoFactor::class)($user->getKey(), null, $codes[0]);

    expect($resolved->getAuthIdentifier())->toBe($user->getKey());
});

it('falls through to a recovery code when the real secret cannot be DECRYPTED', function () {
    // The bundled trait decrypts, and `Crypt::decryptString()` THROWS on a stale APP_KEY — it never
    // returns null. An earlier fix read the secret eagerly and guarded on null, so this case threw
    // before the recovery branch: a 500 per attempt, and because `VerifyTwoFactorChallenge` catches
    // only ValidationException the reserved lockout slot was never released, locking the account
    // permanently out of the very escape hatch recovery codes exist to be.
    //
    // No override, no custom accessor — a genuinely mis-encrypted column, which is what an APP_KEY
    // rotation leaves behind.
    $user = User::factory()->create();
    $codes = $user->generateRecoveryCodes(8);
    $user->forceFill([
        'two_factor_secret' => 'not-a-valid-ciphertext',
        'two_factor_confirmed_at' => now(),
    ])->save();

    expect(fn () => $user->twoFactorSecret())->toThrow(DecryptException::class);

    $resolved = app(ChallengeTwoFactor::class)($user->getKey(), null, $codes[0]);

    expect($resolved->getAuthIdentifier())->toBe($user->getKey());
});

it('refuses a TOTP code when the real secret cannot be decrypted', function () {
    // The other half: unreadable must never authenticate via TOTP either.
    $user = User::factory()->create();
    $user->forceFill([
        'two_factor_secret' => 'not-a-valid-ciphertext',
        'two_factor_confirmed_at' => now(),
    ])->save();

    expect(fn () => app(ChallengeTwoFactor::class)($user->getKey(), '000000', null))
        ->toThrow(ValidationException::class);
});

it('refuses an EMPTY secret, not just a null one', function () {
    // `''` is exactly what the deleted `(string) null` cast produced, so guarding only on null moves
    // the hole rather than closing it. Reachable two ways: a provider whose `generateSecret()`
    // returns '', and the common reflex of catching DecryptException and returning ''. The bundled
    // provider rejects '' — which is the ONLY reason this was never exploitable in-tree — but
    // `TwoFactorProvider` is a swap seam, so the guarantee cannot live there.
    app()->instance(TwoFactorProvider::class, new PermissiveTotpProvider);

    $user = User::factory()->create();
    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString(''),
        'two_factor_confirmed_at' => now(),
    ])->save();

    expect($user->twoFactorSecret())->toBe('')
        ->and(fn () => app(ChallengeTwoFactor::class)($user->getKey(), 'literally-anything', null))
        ->toThrow(ValidationException::class);
});

it('refuses to CONFIRM enrolment on an empty secret', function () {
    // Same hole on the enrolment path: an empty secret plus a permissive provider would stamp
    // `two_factor_confirmed_at` from an arbitrary code, marking the account as protected by a second
    // factor that verifies anything.
    app()->instance(TwoFactorProvider::class, new PermissiveTotpProvider);

    $user = User::factory()->create();
    $user->forceFill(['two_factor_secret' => Crypt::encryptString('')])->save();

    expect(fn () => app(ConfirmTwoFactor::class)($user, 'literally-anything'))
        ->toThrow(ValidationException::class)
        ->and($user->refresh()->two_factor_confirmed_at)->toBeNull();
});
