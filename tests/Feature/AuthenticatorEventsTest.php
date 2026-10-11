<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Events\PasskeyDeleted;
use Lukk\Events\PasskeyRegistered;
use Lukk\Events\RecoveryCodesGenerated;
use Lukk\Events\TwoFactorAuthenticationConfirmed;
use Lukk\Events\TwoFactorAuthenticationDisabled;
use Lukk\Support\NewPasskey;
use Lukk\Tests\Fixtures\FakeWebAuthnCeremony;
use Lukk\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

/*
 * NIST SP 800-63B-4 §4.1.2.1: when an authenticator is bound, the CSP "SHALL" notify the subscriber
 * through a channel independent of the transaction that bound it; §4.6 asks the same when one is
 * removed. lukk sends no mail, so it owes the application an event at every such moment — without
 * one, an attacker holding a stolen session and step-up could bind their own key, or remove the
 * victim's second factor, and the victim would hear nothing.
 */

beforeEach(function () {
    app()->bind(WebAuthnCeremony::class, FakeWebAuthnCeremony::class);
    Event::fake([
        TwoFactorAuthenticationConfirmed::class,
        TwoFactorAuthenticationDisabled::class,
        RecoveryCodesGenerated::class,
        PasskeyRegistered::class,
        PasskeyDeleted::class,
    ]);
});

function enabledTwoFactorFor(User $user): void
{
    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString(app(TwoFactorProvider::class)->generateSecret()),
        'two_factor_recovery_codes' => json_encode([Hash::make('RECOVERY-CODE-1')]),
        'two_factor_confirmed_at' => now(),
    ])->save();
}

it('announces a second factor once it is confirmed, not when it is merely enrolled', function () {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);

    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor')->assertOk();
    Event::assertNotDispatched(TwoFactorAuthenticationConfirmed::class);

    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor/confirm', ['code' => '000000'])->assertStatus(422);
    Event::assertNotDispatched(TwoFactorAuthenticationConfirmed::class);

    $code = app(Google2FA::class)->getCurrentOtp($user->refresh()->twoFactorSecret());
    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor/confirm', ['code' => $code])->assertNoContent();

    Event::assertDispatchedTimes(TwoFactorAuthenticationConfirmed::class, 1);
    Event::assertDispatched(TwoFactorAuthenticationConfirmed::class, fn ($e) => $e->user->is($user));
});

it('announces a second factor being removed', function () {
    $user = User::factory()->create();
    enabledTwoFactorFor($user);
    $token = mfaSession($user);

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->deleteJson('/auth/two-factor')->assertNoContent();

    Event::assertDispatched(TwoFactorAuthenticationDisabled::class, fn ($e) => $e->user->is($user));
});

it('says nothing when disabling a second factor the account never had', function () {
    // Nothing was removed, and "your two-factor authentication was turned off" would be false.
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->deleteJson('/auth/two-factor')->assertNoContent();

    Event::assertNotDispatched(TwoFactorAuthenticationDisabled::class);
});

it('announces an abandoned, unconfirmed enrolment being cleared as a removal too', function () {
    // An unconfirmed secret protects nothing yet, but the user DID start binding it; the event says
    // the binding was undone, and the listener decides whether that is worth a message.
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);
    $this->withToken($token)->withHeaders($headers)->postJson('/auth/two-factor')->assertOk();

    $this->withToken($token)->withHeaders($headers)->deleteJson('/auth/two-factor')->assertNoContent();

    Event::assertDispatched(TwoFactorAuthenticationDisabled::class);
});

it('announces new recovery codes, which replace an authenticator', function () {
    // Recovery codes are a recovery authenticator (§4.2); a fresh set silently replaces the old one.
    $user = User::factory()->create();
    enabledTwoFactorFor($user);
    $token = mfaSession($user);

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->postJson('/auth/two-factor/recovery-codes')->assertOk();

    Event::assertDispatched(RecoveryCodesGenerated::class, fn ($e) => $e->user->is($user));
});

it('announces a passkey being registered, naming the credential', function () {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);
    $challenge = $this->withToken($token)->withHeaders($headers)->postJson('/auth/passkeys/registration-options')->json('challenge');

    $this->withToken($token)->withHeaders($headers)->postJson('/auth/passkeys', [
        'name' => 'Laptop',
        'credential' => ['challenge' => $challenge, 'id' => 'cred-new', 'public_key' => 'PUB', 'sign_count' => 0],
    ])->assertNoContent();

    Event::assertDispatched(PasskeyRegistered::class, fn ($e) => $e->user->is($user) && $e->credentialId === 'cred-new' && $e->name === 'Laptop');
});

it('does not announce a passkey that failed to register', function () {
    $user = User::factory()->create();
    $token = $user->startSession()->accessToken;

    $this->withToken($token)->withHeaders(confirmedHeaders($token))->postJson('/auth/passkeys', [
        'credential' => ['challenge' => 'never-issued', 'id' => 'cred-x', 'public_key' => 'PUB', 'sign_count' => 0],
    ])->assertStatus(422);

    Event::assertNotDispatched(PasskeyRegistered::class);
});

it('announces a passkey being removed, and only when one was', function () {
    $user = User::factory()->create();
    app(PasskeyRepository::class)->store($user->id, new NewPasskey('cred-gone', 'PUB', 0));
    $token = $user->startSession()->accessToken;
    $headers = confirmedHeaders($token);

    $this->withToken($token)->withHeaders($headers)->deleteJson('/auth/passkeys/cred-unknown')->assertNoContent();
    Event::assertNotDispatched(PasskeyDeleted::class);

    $this->withToken($token)->withHeaders($headers)->deleteJson('/auth/passkeys/cred-gone')->assertNoContent();
    Event::assertDispatchedTimes(PasskeyDeleted::class, 1);
    Event::assertDispatched(PasskeyDeleted::class, fn ($e) => $e->user->is($user) && $e->credentialId === 'cred-gone');
});
