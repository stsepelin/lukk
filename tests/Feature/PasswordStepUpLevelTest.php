<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Testing\TestResponse;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Models\Lockout;
use Lukk\Support\NewPasskey;
use Lukk\Tests\Fixtures\FakeWebAuthnCeremony;
use Lukk\Tests\Fixtures\User;

/*
 * NIST SP 800-63B-4 §4.1.2.1: binding or removing an authenticator happens at "the maximum AAL currently
 * available in the subscriber account", and the step-up token is what unlocks that. §2.2.3 lets an AAL2
 * SESSION reauthenticate with one factor — so a password step-up is fine inside a session that was
 * established with two factors (`amr` carries `mfa`), and refused in a single-factor session on an
 * account that could do better. The passkey path already applied the same bar.
 */

uses()->group('confirmation');

beforeEach(fn () => app()->bind(WebAuthnCeremony::class, FakeWebAuthnCeremony::class));

function stepUpWithPassword(object $test, string $access): TestResponse
{
    return $test->withToken($access)->postJson('/auth/confirm-password', ['password' => 'password']);
}

function withTotp(User $user): User
{
    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString(app(TwoFactorProvider::class)->generateSecret()),
        'two_factor_recovery_codes' => json_encode([Hash::make('R-1')]),
        'two_factor_confirmed_at' => now(),
    ])->save();

    return $user;
}

it('refuses a password step-up in a password-only session on an account with a multi-factor passkey', function () {
    $user = User::factory()->create();
    app(PasskeyRepository::class)->store($user->id, new NewPasskey('phone', 'PUB+uv', 0));
    $access = start()($user->id, ['amr' => ['pwd']])->accessToken;

    stepUpWithPassword($this, $access)->assertStatus(422)->assertJsonValidationErrors('password')->assertJsonMissingPath('confirmation_token');
});

it('refuses it on a two-factor account whose session did not use the second factor', function () {
    $user = withTotp(User::factory()->create());
    $access = start()($user->id, ['amr' => ['pop', 'user', 'otp']])->accessToken;

    stepUpWithPassword($this, $access)->assertStatus(422);
});

it('accepts it in a session that was multi-factor', function (array $amr) {
    $user = withTotp(User::factory()->create());
    $access = start()($user->id, ['amr' => $amr])->accessToken;

    stepUpWithPassword($this, $access)->assertOk()->assertJsonStructure(['confirmation_token']);
})->with([
    'password and a one-time code' => [['pwd', 'otp', 'mfa']],
    'a user-verifying passkey' => [['pop', 'user', 'mfa']],
]);

it('accepts it on an account with nothing stronger than the password', function () {
    $user = User::factory()->create();
    app(PasskeyRepository::class)->store($user->id, new NewPasskey('key', 'PUB', 0));
    $access = start()($user->id, ['amr' => ['pwd']])->accessToken;

    stepUpWithPassword($this, $access)->assertOk();
});

it('refuses before checking the password, so a refusal spends no lockout attempt and says nothing about it', function () {
    config(['lukk.features.lockout' => true]);
    $user = withTotp(User::factory()->create());
    $access = start()($user->id, ['amr' => ['pwd']])->accessToken;

    $this->withToken($access)->postJson('/auth/confirm-password', ['password' => 'wrong'])->assertStatus(422);

    expect(Lockout::count())->toBe(0);
});

it('leaves a session that carries no amr to the old rule', function () {
    // A token minted before the `amr` column was migrated loses the claim at its first refresh, and a
    // co-issuer's token never had one. Refusing those would strand every two-factor user on such an
    // install; the claim cannot be removed from a token lukk signed, so its absence is not an attack.
    $user = withTotp(User::factory()->create());

    stepUpWithPassword($this, $user->startSession()->accessToken)->assertOk();
});
