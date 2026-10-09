<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Lukk\Actions\EnsurePasswordStepUpMeetsAccountLevel;
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

it('refuses a session whose token carries no amr on an account with a second factor', function () {
    // It used to wave these through, reasoning that a signed token cannot be stripped of the claim. But
    // an ordinary refresh drops it where the `amr` column is not migrated, and `startSession()` (a magic
    // link, a social login) never stamps one — so a password-only attacker waited one refresh. Without
    // the claim nothing says the session was multi-factor, so it is treated as not.
    $user = withTotp(User::factory()->create());

    stepUpWithPassword($this, $user->startSession()->accessToken)->assertStatus(422)->assertJsonValidationErrors('password');
});

it('still accepts a session without amr on an account with nothing stronger than the password', function () {
    stepUpWithPassword($this, User::factory()->create()->startSession()->accessToken)->assertOk();
});

it('refuses after a refresh on a schema without the amr column', function () {
    Schema::table('refresh_tokens', fn ($t) => $t->dropColumn('amr'));
    $user = withTotp(User::factory()->create());
    $pair = start()($user->id, ['amr' => ['pwd', 'otp', 'mfa']]);

    $refreshed = rotate()($pair->refreshToken);

    stepUpWithPassword($this, $refreshed->accessToken)->assertStatus(422);
});

it('does not count a second factor this guard does not enforce', function () {
    // With two-factor switched off, login never asks for the code, so no session on this guard can ever
    // carry `mfa`: counting the enrolled TOTP made every step-up — and erasure behind it — unreachable.
    config(['lukk.features.two_factor' => false]);
    $user = withTotp(User::factory()->create());
    $access = start()($user->id, ['amr' => ['pwd']])->accessToken;

    stepUpWithPassword($this, $access)->assertOk();
});

it('lets a test acting as a user step up, which presents no token at all', function () {
    $user = withTotp(User::factory()->create());
    Lukk\Lukk::actingAs($user);

    $this->postJson('/auth/confirm-password', ['password' => 'password'])->assertOk();
});

it('ignores passkeys on an install whose config has lost the passkeys flag', function () {
    // A stale cached config without `features.passkeys` means the feature is off: a passkey row cannot
    // raise the bar for a password step-up then.
    $lukk = config('lukk');
    unset($lukk['features']['passkeys']);
    config(['lukk' => $lukk]);
    $user = User::factory()->create();
    app(PasskeyRepository::class)->store($user->id, new NewPasskey('phone', 'PUB+uv', 0));
    $access = start()($user->id, ['amr' => ['pwd']])->accessToken;

    stepUpWithPassword($this, $access)->assertOk();
});

it('leaves a request that carries no verified token to the old rule', function () {
    $user = withTotp(User::factory()->create());

    app(EnsurePasswordStepUpMeetsAccountLevel::class)(Request::create('/auth/confirm-password', 'POST'), $user);

    expect(true)->toBeTrue();
});
