<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\ChallengeTwoFactor;
use Lukk\Actions\ConfirmPasswordUnchanged;
use Lukk\Actions\ConfirmTwoFactor;
use Lukk\Actions\EnableTwoFactor;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Events\RecoveryCodesGenerated;
use Lukk\Events\TwoFactorAuthenticationConfirmed;
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

it('clamps the TOTP window, so one env typo cannot widen the accepted set', function () {
    // RFC 6238 §5.2 recommends at most one time step for network delay. Each step admits two more
    // 30-second codes, so an unclamped `window: 100` made 201 of the million codes valid at any
    // instant — ~67x weaker per guess. It was the only unclamped numeric knob in the package.
    config(['lukk.two_factor.window' => 100]);
    app()->forgetInstance(TwoFactorProvider::class); // a singleton, resolved with the old window
    $secret = app(TwoFactorProvider::class)->generateSecret();

    // `getCurrentOtp()` takes no timestamp — it is `oathTotp($secret, getTimestamp())`. Address the
    // counter directly: 11 steps back is outside the clamp (10) but well inside the configured 100.
    $engine = app(Google2FA::class);
    $far = $engine->oathTotp($secret, $engine->getTimestamp() - 11);
    $near = $engine->oathTotp($secret, $engine->getTimestamp() - 9);

    expect(app(TwoFactorProvider::class)->verify($secret, $far))->toBeFalse()
        // …and the clamp is a ceiling, not a replacement: 9 steps back is still inside it.
        ->and(app(TwoFactorProvider::class)->verify($secret, $near))->toBeTrue();
});

it('renders 422, not a 500, for a non-scalar confirmation code', function () {
    // The one OTP-verifying controller without a typed `code`: `(string) $array` raised an
    // ErrorException, while its sibling `POST /auth/two-factor-challenge` answers 422 for the same
    // payload because `TwoFactorChallengeRequest` types the field.
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;

    $this->withToken($access)->withHeaders(confirmedHeaders($access))
        ->postJson('/auth/two-factor/confirm', ['code' => ['123456']])
        ->assertStatus(422);
});

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
        ->assertStatus(422)
        ->assertJsonValidationErrors(['code' => 'The provided two-factor code was invalid.']);

    expect($user->refresh()->hasEnabledTwoFactor())->toBeFalse();
});

it('regenerates recovery codes, invalidating the old set', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $token = mfaSession($user);

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
    $token = mfaSession($user);

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

it('stamps amr=[pwd,otp,mfa] on the token issued after a 2FA login', function () {
    $user = User::factory()->create();
    $secret = confirmedTwoFactor($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $access = $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => currentOtp($secret)])
        ->json('access_token');

    // `mfa` because a password and a TOTP are two different factor categories (RFC 8176's "mfa",
    // NIST SP 800-63B-4 §2.2.1) — unlike a single-factor passkey plus a TOTP, which is not.
    expect(claims($access)->amr)->toBe(['pwd', 'otp', 'mfa']);
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
    $access = mfaSession($user);

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

// ---------------------------------------------------------------------------
// `block_unverified_login` on the two-factor path. Password-only and passkey logins refused an
// unverified user with a 403; a user who had ALSO enrolled a second factor was handed a challenge
// first and then a full session by the redemption route, which never ran the gate. Enrolling MORE
// security made the account exempt from the verification policy.
// ---------------------------------------------------------------------------

it('refuses an unverified two-factor user at login, before any challenge is issued', function () {
    config(['lukk.email_verification.block_unverified_login' => true]);
    $user = User::factory()->create(['email_verified_at' => null]);
    confirmedTwoFactor($user);

    // The same 403 the password-only path answers with, at the same point — AFTER the credential
    // check, so it tells a caller nothing the password-only path does not. No challenge either:
    // redeeming one would burn a single-use recovery code on a login that is going to be refused.
    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertStatus(403)
        ->assertJsonMissingPath('challenge_token')
        ->assertJsonMissingPath('access_token');

    expect(DB::table('refresh_tokens')->count())->toBe(0);
});

it('still answers a wrong password with 422, not the unverified 403', function () {
    // The gate runs only after the credentials verify, so it must not become an oracle for them.
    config(['lukk.email_verification.block_unverified_login' => true]);
    $user = User::factory()->create(['email_verified_at' => null]);
    confirmedTwoFactor($user);

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'wrong'])->assertStatus(422);
});

it('refuses to redeem a challenge with a TOTP code once the user is unverified', function () {
    // A challenge minted while the account was verified (or before the flag was switched on) and
    // redeemed after an email change nulled `email_verified_at`: the redemption route must not be a
    // way around the gate the login route enforces.
    config(['lukk.email_verification.block_unverified_login' => true]);
    $user = User::factory()->create(['email_verified_at' => now()]);
    $secret = confirmedTwoFactor($user);

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->json('challenge_token');

    $user->forceFill(['email_verified_at' => null])->save();

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => currentOtp($secret)])
        ->assertStatus(403)
        ->assertJsonMissingPath('access_token');

    expect(DB::table('refresh_tokens')->count())->toBe(0);
});

it('refuses to redeem a challenge with a recovery code once the user is unverified', function () {
    config(['lukk.email_verification.block_unverified_login' => true]);
    $user = User::factory()->create(['email_verified_at' => now()]);
    confirmedTwoFactor($user);

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->json('challenge_token');

    $user->forceFill(['email_verified_at' => null])->save();

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'RECOVERY-CODE-1'])
        ->assertStatus(403)
        ->assertJsonMissingPath('access_token');

    expect(DB::table('refresh_tokens')->count())->toBe(0);
});

it('refuses an unverified user BEFORE spending the second factor', function () {
    // The 403 used to come after `ChallengeTwoFactor` had verified the factor — by then a single-use
    // recovery code was burned on a sign-in the policy was always going to refuse. Checked first, the
    // way a stale password is (`ConfirmPasswordUnchanged::holds()`), the code is still there to use
    // once the address is verified again.
    config(['lukk.email_verification.block_unverified_login' => true]);
    $user = User::factory()->create(['email_verified_at' => now()]);
    confirmedTwoFactor($user);

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->json('challenge_token');

    $user->forceFill(['email_verified_at' => null])->save();

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'RECOVERY-CODE-1'])
        ->assertStatus(403);

    expect($user->refresh()->recoveryCodesRemaining())->toBe(1);
});

it('still refuses an account that became unverified WHILE its factor was checked', function () {
    // The early refusal above does not replace the gate after verification: an email change landing
    // between the two must not get a session either.
    config(['lukk.email_verification.block_unverified_login' => true]);
    $user = User::factory()->create(['email_verified_at' => now()]);
    confirmedTwoFactor($user);

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->json('challenge_token');

    app()->bind(ChallengeTwoFactor::class, fn ($app) => new class($app) extends ChallengeTwoFactor
    {
        public function __construct($app)
        {
            parent::__construct($app['auth']->createUserProvider('users'), $app->make(TwoFactorProvider::class));
        }

        public function __invoke(int|string $userId, #[SensitiveParameter] ?string $code, #[SensitiveParameter] ?string $recoveryCode): Authenticatable
        {
            $user = parent::__invoke($userId, $code, $recoveryCode);
            $user->forceFill(['email_verified_at' => null])->save();

            return $user;
        }
    });

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'RECOVERY-CODE-1'])
        ->assertStatus(403)
        ->assertJsonMissingPath('access_token');

    expect(DB::table('refresh_tokens')->count())->toBe(0);
});

it('lets a verified two-factor user through when block_unverified_login is on', function () {
    config(['lukk.email_verification.block_unverified_login' => true]);
    $user = User::factory()->create(['email_verified_at' => now()]);
    $secret = confirmedTwoFactor($user);

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->assertJsonPath('two_factor', true)->json('challenge_token');

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => currentOtp($secret)])
        ->assertOk()
        ->assertJsonStructure(['access_token', 'refresh_token']);
});

it('does not gate an unverified two-factor user when block_unverified_login is off', function () {
    config(['lukk.email_verification.block_unverified_login' => false]);
    $user = User::factory()->create(['email_verified_at' => null]);
    $secret = confirmedTwoFactor($user);

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->assertJsonPath('two_factor', true)->json('challenge_token');

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'RECOVERY-CODE-1'])
        ->assertOk()
        ->assertJsonStructure(['access_token']);
});

// Same rule, sharpest 2FA consequence: an unusable `two_factor.recovery_codes` generates ZERO
// recovery codes. Enrolment still answers 200 with an empty list, and the only way back into an
// account whose authenticator is lost has quietly been removed. `config($key, 8)` would not save
// this either — its default applies to an ABSENT key, not to one holding null.
it('generates the documented number of recovery codes when the count is unusable', function (Closure $break) {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);

    $break();

    $codes = $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor')
        ->assertOk()->json('recovery_codes');

    expect($codes)->toHaveCount(8);
})->with([
    'null (a per-guard env that is not set)' => [fn () => config()->set('lukk.two_factor.recovery_codes', null)],
    'absent (a config cached before the key existed)' => [fn () => config()->set('lukk.two_factor', Arr::except(config('lukk.two_factor'), ['recovery_codes']))],
]);

// The regeneration path is a second binding reading the same key — and the one a user reaches when
// their codes are already spent, so an empty set there locks the account out on the next lost phone.
it('regenerates the documented number of recovery codes when the count is null', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $token = mfaSession($user);
    $headers = confirmedHeaders($token);

    config()->set('lukk.two_factor.recovery_codes', null);

    $response = $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor/recovery-codes')->assertOk();

    expect($response->json('recovery_codes'))->toHaveCount(8);
    expect($this->withToken($token)->getJson('/auth/two-factor/recovery-codes')->json('total'))->toBe(8);
});

it('names the conflict when enrolling over confirmed two-factor', function () {
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $access = mfaSession($user);

    $this->withToken($access)->withHeaders(confirmedHeaders($access))->postJson('/auth/two-factor')
        ->assertStatus(409)
        ->assertJsonValidationErrors(['two_factor' => 'Two-factor authentication is already enabled. Disable it first to enrol again.']);
});

it('clears a stale confirmation when enrolling, so the new secret starts unconfirmed', function () {
    // A confirmation left behind without a secret (a half-disabled row) must not carry over to a
    // secret nobody has proved they hold.
    $user = User::factory()->create();
    $user->forceFill(['two_factor_secret' => null, 'two_factor_confirmed_at' => now()])->save();

    app(EnableTwoFactor::class)($user);

    expect($user->refresh()->two_factor_confirmed_at)->toBeNull()
        ->and($user->hasEnabledTwoFactor())->toBeFalse();
});

it('labels the authenticator entry with the email, or the id when there is none', function () {
    $user = User::factory()->create(['email' => 'ada@example.test']);
    expect(app(EnableTwoFactor::class)($user)['otpauth_uri'])->toContain(rawurlencode('ada@example.test'));

    $anonymous = new class extends User
    {
        protected $table = 'users';

        public function getEmailAttribute(): ?string
        {
            return null;
        }
    };
    $id = User::factory()->create()->getKey();
    $model = $anonymous::query()->findOrFail($id);

    expect(app(EnableTwoFactor::class)($model)['otpauth_uri'])->toContain(':'.$id.'?');
});

it('requires a code to confirm enrolment', function () {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);
    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor')->assertOk();

    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor/confirm', [])
        ->assertStatus(422)
        ->assertJsonValidationErrors(['code' => 'The code field is required.']);
});

it('reports the configured recovery-code total as a number, and eight when unset', function (mixed $configured, int $total) {
    config(['lukk.two_factor.recovery_codes' => $configured]);
    $user = User::factory()->create();
    confirmedTwoFactor($user);

    $this->withToken($user->startSession()->accessToken)->getJson('/auth/two-factor/recovery-codes')
        ->assertOk()
        ->assertJsonPath('total', $total);
})->with([
    'a string from env' => ['10', 10],
    'unset' => [null, 8],
    // Clamped as generation clamps it: a set of 500 configured is a set of 100 issued, and a "codes
    // left" indicator reading 100 of 500 told the user four fifths of their codes were gone.
    'above the cap' => [500, 100],
    'zero' => [0, 1],
    'negative' => [-3, 1],
]);

it('assumes the password path for a challenge that does not say how the first factor was proved', function () {
    // A rolling deploy redeems 0.7-minted challenges on 0.8 code, and a co-issuer's challenge may
    // carry no `amr` at all. Both must keep recording `['pwd','otp']`, the behaviour they had. The
    // fallback and the parameter default masked each other — removing either alone left the suite
    // green — so this pins the redemption side on its own by minting a challenge without the claim.
    $user = User::factory()->create();
    $secret = app(TwoFactorProvider::class)->generateSecret();
    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString($secret),
        'two_factor_confirmed_at' => now(),
    ])->save();

    // Minted directly, with no first factor named — exactly the shape an older release produced.
    $challenge = app(ChallengeToken::class)->issue(
        '2fa', $user->getAuthIdentifier(), 300,
        passwordFingerprint: app(ConfirmPasswordUnchanged::class)->baseline($user),
    );

    $pair = $this->postJson('/auth/two-factor-challenge', [
        'challenge_token' => $challenge,
        'code' => currentOtp($secret),
    ])->assertOk()->json();

    expect(claims($pair['access_token'])->amr)->toBe(['pwd', 'otp', 'mfa']);
});

it('gives one session per challenge even when two redemptions read it as unspent together', function () {
    // Two concurrent redemptions, each with a different valid factor, both passed the up-front check
    // and both minted a session. A denylist that never reports a jti stands in for both reads landing
    // before either write; the second must lose the atomic spend.
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $user->forceFill(['two_factor_recovery_codes' => json_encode([Hash::make('R-ONE'), Hash::make('R-TWO')])])->save();
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $inner = app(Denylist::class);
    app()->instance(Denylist::class, new class($inner) implements Denylist
    {
        public function __construct(private readonly Denylist $inner) {}

        public function revokeJti(string $jti, int $ttlSeconds): void
        {
            $this->inner->revokeJti($jti, $ttlSeconds);
        }

        public function revokeFamily(string $familyId, int $ttlSeconds): void
        {
            $this->inner->revokeFamily($familyId, $ttlSeconds);
        }

        public function has(string $type, string $id): bool
        {
            return false;
        }

        public function hasAny(array $types): bool
        {
            return false;
        }
    });

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'R-ONE'])->assertOk();
    app('auth')->forgetGuards();
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'R-TWO'])
        ->assertStatus(422)->assertJsonValidationErrors('challenge_token');
});

it('answers 422, not 500, for a recovery code stored under a hasher the app has since left', function () {
    // After a move to argon2id with `hashing.argon.verify` on, checking a bcrypt-hashed code THROWS
    // ("does not use the Argon2id algorithm"), and the lost-authenticator path died with a 500. A
    // code the active hasher refuses to read is no match, exactly as sign-in treats a password.
    $user = User::factory()->create();
    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString(app(TwoFactorProvider::class)->generateSecret()),
        'two_factor_recovery_codes' => json_encode([Hash::make('RECOVERY-CODE-1')]),
        'two_factor_confirmed_at' => now(),
    ])->save();
    config(['hashing.driver' => 'argon2id', 'hashing.argon.verify' => true]);
    app()->forgetInstance('hash');
    Hash::clearResolvedInstances();
    DB::table('users')->where('id', $user->id)->update(['password' => Hash::make('password')]);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'RECOVERY-CODE-1'])->assertStatus(422);
});

it('refuses to re-confirm two-factor that is already on', function () {
    // It answered 204, overwrote `two_factor_confirmed_at` and fired `TwoFactorAuthenticationConfirmed`
    // again — telling the user an authenticator had been added when nothing changed. Mirrors enrolment,
    // which refuses an account that already has it.
    Event::fake([TwoFactorAuthenticationConfirmed::class]);
    $this->freezeSecond();
    $user = User::factory()->create();
    $secret = confirmedTwoFactor($user);
    $confirmedAt = $user->refresh()->two_factor_confirmed_at->getTimestamp();
    $token = start()($user->id, ['amr' => ['pwd', 'otp', 'mfa']])->accessToken;
    $headers = confirmedHeaders($token);
    $this->travel(60)->seconds();

    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor/confirm', ['code' => currentOtp($secret)])
        ->assertStatus(409)->assertJsonValidationErrors(['code' => 'Two-factor authentication is already enabled.']);

    expect($user->refresh()->two_factor_confirmed_at->getTimestamp())->toBe($confirmedAt);
    Event::assertNotDispatched(TwoFactorAuthenticationConfirmed::class);
});

it('answers a pending secret it cannot decrypt with 422, not a 500', function () {
    // APP_KEY rotated without `previous_keys`, or a corrupt row: `twoFactorSecret()` throws. The challenge
    // path already reads that as "no secret"; confirmation did not, and 500'd.
    $user = User::factory()->create();
    $user->forceFill(['two_factor_secret' => 'not-a-ciphertext', 'two_factor_confirmed_at' => null])->save();
    $token = $user->startSession()->accessToken;

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->postJson('/auth/two-factor/confirm', ['code' => '123456'])
        ->assertStatus(422)->assertJsonValidationErrors('code');

    expect($user->refresh()->two_factor_confirmed_at)->toBeNull();
});

it('refuses to regenerate recovery codes for an account with no two-factor at all', function () {
    // Eight codes that nothing ever asks for, and a `RecoveryCodesGenerated` notice about an authenticator
    // the account does not have. 409, as for enabling two-factor twice.
    Event::fake([RecoveryCodesGenerated::class]);
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->postJson('/auth/two-factor/recovery-codes')
        ->assertStatus(409)->assertJsonMissingPath('recovery_codes')
        ->assertJsonValidationErrors(['two_factor' => 'Two-factor authentication is not enabled.']);

    expect($user->refresh()->two_factor_recovery_codes)->toBeNull();
    Event::assertNotDispatched(RecoveryCodesGenerated::class);
});

it('regenerates recovery codes during enrolment, before the code is confirmed', function () {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);
    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor')->assertOk();

    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor/recovery-codes')
        ->assertOk()->assertJsonCount(8, 'recovery_codes');
});

it('refuses to regenerate recovery codes for a pending secret it cannot decrypt, rather than 500ing', function () {
    $user = User::factory()->create();
    $user->forceFill(['two_factor_secret' => 'not-a-ciphertext', 'two_factor_confirmed_at' => null])->save();
    $token = $user->startSession()->accessToken;

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->postJson('/auth/two-factor/recovery-codes')
        ->assertStatus(409);
});

it('regenerates recovery codes for a confirmed account whose TOTP secret cannot be decrypted', function () {
    // Confirmed is enough: the codes are that account's way back in when its authenticator is unusable.
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $user->forceFill(['two_factor_secret' => 'not-a-ciphertext'])->save();
    $token = mfaSession($user);

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->postJson('/auth/two-factor/recovery-codes')
        ->assertOk()->assertJsonCount(8, 'recovery_codes');
});

// ---------------------------------------------------------------------------
// NIST SP 800-63B-4 §4.2: account recovery is an event the subscriber is told about. A recovery code is
// the way back in when the authenticator is lost — and the way in for whoever stole the printed list —
// so its use must be observable for an app to notify the owner and prompt a fresh set.
// ---------------------------------------------------------------------------

it('announces a spent recovery code, with how many remain', function () {
    Event::fake(['Lukk\Events\RecoveryCodeUsed']);
    $user = User::factory()->create();
    confirmedTwoFactor($user);
    $user->forceFill(['two_factor_recovery_codes' => json_encode([Hash::make('RECOVERY-CODE-1'), Hash::make('RECOVERY-CODE-2')])])->save();

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'RECOVERY-CODE-2'])->assertOk();

    Event::assertDispatchedTimes('Lukk\Events\RecoveryCodeUsed', 1);
    Event::assertDispatched('Lukk\Events\RecoveryCodeUsed', fn ($e) => $e->user->is($user) && $e->remaining === 1);
});

it('announces nothing for a TOTP sign-in or a recovery code that does not match', function () {
    Event::fake(['Lukk\Events\RecoveryCodeUsed']);
    $user = User::factory()->create();
    $secret = confirmedTwoFactor($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'recovery_code' => 'WRONG-CODE'])->assertStatus(422);
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => currentOtp($secret)])->assertOk();

    Event::assertNotDispatched('Lukk\Events\RecoveryCodeUsed');
});
