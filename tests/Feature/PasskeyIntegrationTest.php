<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Crypt;
use Illuminate\Testing\TestResponse;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Exceptions\PasskeyVerificationFailed;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Passkeys\SpomkyWebAuthnCeremony;
use Lukk\Support\PasskeyRecord;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\Fixtures\UserVerifyingAuthenticator;
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
    // The software emulator only sets user-present (not user-verified), so this end-to-end
    // crypto test runs under "preferred"; the default "required" is asserted separately below,
    // and real authenticators satisfy it with a biometric/PIN.
    config(['lukk.passkeys.user_verification' => 'preferred']);
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

    // Through the REAL library: the emulator performs no user verification, so this is a
    // single-factor assertion and must say so — registered RFC 8176 values, and no `mfa`.
    expect(claims($access)->amr)->toBe(['pop', 'user'])
        ->and(claims($access)->sub)->toBe((string) $user->id);

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

    // Refused at REGISTRATION, per WebAuthn L3 §7.1 step 17. It used to enrol: the creation options
    // omitted `authenticatorSelection`, so `CheckUserVerification` read null and returned early. The
    // credential was then stored and listed while every assertion was refused by the check the
    // assertion side does perform — a passkey the visitor could see but never use, and a self-lockout
    // if they trusted that listing and pruned their other factors.
    $options = $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys/registration-options')->assertOk()->json();

    $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys', ['credential' => toBase64Url($authenticator->getAttestation($options, 'https://localhost'))])
        ->assertStatus(422);

    // And nothing was stored, so the list does not advertise a factor that cannot authenticate.
    $this->withToken($access)->getJson('/auth/passkeys')->assertOk()->assertJsonCount(0, 'passkeys');
});

it('rejects responses presented to the wrong ceremony', function () {
    // Not a UV test: the emulator is user-present only, and `required` now refuses it at registration.
    config(['lukk.passkeys.user_verification' => 'preferred']);
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

/**
 * Register a credential and run one login, all through the REAL library, with a user-verifying
 * emulator. Returns the login response.
 */
function realPasskeyLogin(object $test, User $user, UserVerifyingAuthenticator $authenticator, bool $verifyOnLogin): TestResponse
{
    // Enrolling needs a step-up, which on an account with a second factor needs a multi-factor session.
    $access = mfaSession($user);
    $headers = confirmedHeaders($access);

    $options = $test->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys/registration-options')->assertOk()->json();
    $test->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys', ['credential' => toBase64Url($authenticator->getAttestation($options, 'https://localhost'))])
        ->assertNoContent();

    app('auth')->forgetGuards();
    $authenticator->verifies = $verifyOnLogin;
    $start = $test->postJson('/auth/passkeys/login-options')->assertOk()->json();
    $assertion = toBase64Url($authenticator->getAssertion('localhost', null, $start['options']['challenge'], 'https://localhost'));

    return $test->postJson('/auth/passkeys/login', ['ceremony_id' => $start['ceremony_id'], 'credential' => $assertion]);
}

it('lets a user-verifying passkey stand in for an enrolled second factor, through the real library', function () {
    // The rule that skips a user's TOTP, pinned against real authenticator data rather than the fake:
    // the credential showed UV at registration (`uvInitialized`), and this assertion carries it too.
    config(['lukk.passkeys.user_verification' => 'preferred']);
    $user = User::factory()->create();
    $user->forceFill(['two_factor_secret' => Crypt::encryptString('SECRETSECRETSECR'), 'two_factor_confirmed_at' => now()])->save();

    $authenticator = new UserVerifyingAuthenticator(new InMemoryRepository);
    $authenticator->verifies = true;

    $access = realPasskeyLogin($this, $user, $authenticator, verifyOnLogin: true)->assertOk()->json('access_token');

    expect(claims($access)->amr)->toBe(['pop', 'user', 'mfa']);
});

it('does not rely on a UV flag from a credential registered without one, through the real library', function () {
    // WebAuthn L3 §4: "When [uvInitialized] is FALSE, including an authentication ceremony where it
    // would be updated to TRUE, the UV flag MUST NOT be relied upon as an authentication factor."
    // The library flips `uvInitialized` in memory during this very ceremony, so the answer has to be
    // read BEFORE it runs — this is the test that proves the ceremony does.
    config(['lukk.passkeys.user_verification' => 'preferred']);
    $user = User::factory()->create();
    $user->forceFill(['two_factor_secret' => Crypt::encryptString('SECRETSECRETSECR'), 'two_factor_confirmed_at' => now()])->save();

    $authenticator = new UserVerifyingAuthenticator(new InMemoryRepository);
    $authenticator->verifies = false; // registered with no PIN…

    realPasskeyLogin($this, $user, $authenticator, verifyOnLogin: true) // …and a PIN set later
        ->assertOk()->assertJsonStructure(['two_factor', 'challenge_token'])->assertJsonMissingPath('access_token');
});

it('reports a stored credential as multi-factor only once it has shown user verification', function () {
    config(['lukk.passkeys.user_verification' => 'preferred']);
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $headers = confirmedHeaders($access);

    foreach (['verifying' => true, 'presence-only' => false] as $name => $uv) {
        $authenticator = new UserVerifyingAuthenticator(new InMemoryRepository);
        $authenticator->verifies = $uv;
        $options = $this->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys/registration-options')->assertOk()->json();
        $this->withToken($access)->withHeaders($headers)
            ->postJson('/auth/passkeys', ['name' => $name, 'credential' => toBase64Url($authenticator->getAttestation($options, 'https://localhost'))])
            ->assertNoContent();
    }

    $repository = app(PasskeyRepository::class);
    $byName = collect($repository->credentialIdsFor($user->id))
        ->mapWithKeys(fn ($id) => [$repository->findByCredentialId($id)->name => $repository->findByCredentialId($id)]);

    expect(app(WebAuthnCeremony::class)->isMultiFactor($byName['verifying']))->toBeTrue()
        ->and(app(WebAuthnCeremony::class)->isMultiFactor($byName['presence-only']))->toBeFalse();
});

it('reads an unreadable stored credential as not multi-factor', function () {
    $record = new PasskeyRecord('cred', 1, 'not a serialized credential', 0);

    expect(app(WebAuthnCeremony::class)->isMultiFactor($record))->toBeFalse();
});

it('enforces the step-up\'s own user-verification requirement through the real library', function () {
    // The login setting is `preferred`, but this account has a password, so AAL2 is within its reach
    // and the step-up asks for — and must ENFORCE — `required` (NIST SP 800-63B-4 §4.1.2.1, WebAuthn
    // L3 §5.8.6). A ceremony that ignored the per-ceremony requirement and fell back to the login
    // setting would let a presence-only assertion through to lukk's own check.
    config(['lukk.passkeys.user_verification' => 'preferred']);
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $headers = confirmedHeaders($access);

    $authenticator = new UserVerifyingAuthenticator(new InMemoryRepository);
    $authenticator->verifies = false;
    $options = $this->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys/registration-options')->assertOk()->json();
    $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys', ['credential' => toBase64Url($authenticator->getAttestation($options, 'https://localhost'))])
        ->assertNoContent();

    $start = $this->withToken($access)->postJson('/auth/confirm-passkey/options')->assertOk()->json();
    expect($start['options']['userVerification'])->toBe('required');

    $assertion = toBase64Url($authenticator->getAssertion('localhost', null, $start['options']['challenge'], 'https://localhost'));

    $this->withToken($access)->postJson('/auth/confirm-passkey', ['ceremony_id' => $start['ceremony_id'], 'credential' => $assertion])
        ->assertStatus(422)->assertJsonMissingPath('confirmation_token');
});

it('tells the browser how long the server keeps the challenge', function () {
    // Without `timeout` (WebAuthn L3 §5.4, §5.5) the browser's own default — often five minutes or more —
    // applied while lukk forgot the challenge after `challenge_ttl`, so a user finishing a slow PIN or
    // biometric entry got "could not be verified". The prompt now closes when the challenge does.
    config(['lukk.passkeys.challenge_ttl' => 90]);
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;

    expect($this->postJson('/auth/passkeys/login-options')->json('options.timeout'))->toBe(90_000)
        ->and($this->withToken($access)->withHeaders(confirmedHeaders($access))->postJson('/auth/passkeys/registration-options')->json('timeout'))->toBe(90_000);
});

it('sends no timeout when none, or a non-positive one, is configured', function (mixed $timeout, ?int $sent) {
    $ceremony = new SpomkyWebAuthnCeremony([
        'rp_id' => 'localhost', 'rp_name' => 'lukk', 'origins' => ['https://localhost'], 'user_verification' => 'preferred', 'timeout' => $timeout,
    ]);

    expect($ceremony->authenticationOptions(str_repeat('A', 43), [])['timeout'] ?? null)->toBe($sent);
})->with([
    'positive' => [1, 1],
    'zero' => [0, null],
    'negative' => [-5, null],
    'not an integer' => ['90000', null],
]);

it('steps up with the owner bound as the expected user handle, through the real library', function (bool $withHandle) {
    // WebAuthn L3 §7.2 step 6: the step-up names whose credential it expects. The handle lukk
    // registered is that account's id, so a real assertion carrying it passes, and one from a
    // non-discoverable key, which omits it, passes on the credential's own binding.
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $headers = confirmedHeaders($access);
    $authenticator = new UserVerifyingAuthenticator(new InMemoryRepository);
    $options = $this->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys/registration-options')->assertOk()->json();
    $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys', ['credential' => toBase64Url($authenticator->getAttestation($options, 'https://localhost'))])
        ->assertNoContent();

    $start = $this->withToken($access)->postJson('/auth/confirm-passkey/options')->assertOk()->json();
    $assertion = toBase64Url($authenticator->getAssertion('localhost', null, $start['options']['challenge'], 'https://localhost'));
    expect($assertion['response']['userHandle'] ?? null)->not->toBeNull();
    if (! $withHandle) {
        unset($assertion['response']['userHandle']);
    }

    $this->withToken($access)->postJson('/auth/confirm-passkey', ['ceremony_id' => $start['ceremony_id'], 'credential' => $assertion])
        ->assertOk()->assertJsonStructure(['confirmation_token']);
})->with(['with the user handle' => true, 'without one' => false]);
