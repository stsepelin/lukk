<?php

declare(strict_types=1);

use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Exceptions\PasskeyVerificationFailed;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Tests\Fixtures\User;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\InMemoryRepository;

uses()->group('passkeys');

beforeEach(function () {
    config([
        'lukk.passkeys.rp_id' => 'localhost',
        'lukk.passkeys.rp_name' => 'lukk',
        'lukk.passkeys.origins' => ['https://localhost'],
    ]);
});

// The emulator emits standard base64 (padded); browsers/web-auth use base64url.
function toBase64Url(mixed $value): mixed
{
    return is_array($value)
        ? array_map('toBase64Url', $value)
        : (is_string($value) ? rtrim(strtr($value, '+/', '-_'), '=') : $value);
}

it('registers and logs in through the real web-auth ceremony (end-to-end crypto)', function () {
    $authenticator = new Authenticator(new InMemoryRepository);

    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $headers = confirmedHeaders($access);

    // Registration: server options → emulator signs the attestation → server verifies + stores.
    $options = $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys/registration-options')->assertOk()->json();

    $attestation = toBase64Url($authenticator->getAttestation($options, 'https://localhost'));

    $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys', ['credential' => $attestation])
        ->assertNoContent();

    // Passwordless login: server challenge → emulator signs the assertion → server verifies → tokens.
    $start = $this->postJson('/auth/passkeys/login-options')->assertOk()->json();
    $assertion = toBase64Url($authenticator->getAssertion('localhost', null, $start['options']['challenge'], 'https://localhost'));

    $access = $this->postJson('/auth/passkeys/login', ['ceremony_id' => $start['ceremony_id'], 'credential' => $assertion])
        ->assertOk()
        ->json('access_token');

    expect(verifier()->verify($access)->amr)->toBe(['webauthn'])
        ->and(verifier()->verify($access)->sub)->toBe((string) $user->id);

    // A second login: the authenticator's signature counter has advanced (now > 0),
    // so the real counter step runs — and is accepted (no regression).
    $start = $this->postJson('/auth/passkeys/login-options')->json();
    $assertion = toBase64Url($authenticator->getAssertion('localhost', null, $start['options']['challenge'], 'https://localhost'));

    $this->postJson('/auth/passkeys/login', ['ceremony_id' => $start['ceremony_id'], 'credential' => $assertion])->assertOk();
});

it('rejects a presence-only assertion when user verification is required', function () {
    config(['lukk.passkeys.user_verification' => 'required']);
    $authenticator = new Authenticator(new InMemoryRepository);

    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $headers = confirmedHeaders($access);

    // Registration only checks presence, so it still succeeds...
    $options = $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys/registration-options')->assertOk()->json();
    $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys', ['credential' => toBase64Url($authenticator->getAttestation($options, 'https://localhost'))])
        ->assertNoContent();

    // ...but login now requires user verification, which the emulator (user-present
    // only) does not perform — so the assertion is rejected.
    $start = $this->postJson('/auth/passkeys/login-options')->assertOk()->json();
    $assertion = toBase64Url($authenticator->getAssertion('localhost', null, $start['options']['challenge'], 'https://localhost'));

    $this->postJson('/auth/passkeys/login', ['ceremony_id' => $start['ceremony_id'], 'credential' => $assertion])
        ->assertStatus(422);
});

it('rejects responses presented to the wrong ceremony', function () {
    $authenticator = new Authenticator(new InMemoryRepository);
    $ceremony = app(WebAuthnCeremony::class);

    $regChallenge = app(PasskeyChallengeStore::class)->generate();
    $attestation = toBase64Url($authenticator->getAttestation($ceremony->registrationOptions(1, 'u@e.com', $regChallenge, []), 'https://localhost'));
    $passkey = $ceremony->verifyRegistration(1, $attestation, $regChallenge);
    app(PasskeyRepository::class)->store(1, $passkey);
    $stored = app(PasskeyRepository::class)->findByCredentialId($passkey->credentialId);

    $loginChallenge = app(PasskeyChallengeStore::class)->generate();
    $assertion = toBase64Url($authenticator->getAssertion('localhost', null, $loginChallenge, 'https://localhost'));

    // Wrong response type for the ceremony (trips the type guard).
    expect(fn () => $ceremony->verifyRegistration(1, $assertion, $loginChallenge))->toThrow(PasskeyVerificationFailed::class);
    expect(fn () => $ceremony->verifyAssertion($attestation, $regChallenge, $stored))->toThrow(PasskeyVerificationFailed::class);

    // Right type, wrong challenge (the library's crypto check rejects it — a
    // WebauthnException becomes a PasskeyVerificationFailed, not a 500).
    expect(fn () => $ceremony->verifyRegistration(1, $attestation, $loginChallenge))->toThrow(PasskeyVerificationFailed::class);
    expect(fn () => $ceremony->verifyAssertion($assertion, $regChallenge, $stored))->toThrow(PasskeyVerificationFailed::class);
});
