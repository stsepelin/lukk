<?php

declare(strict_types=1);

use Lukk\Exceptions\PasskeyVerificationFailed;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Passkeys\SpomkyWebAuthnCeremony;
use Lukk\Support\PasskeyRecord;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\InMemoryRepository;

uses()->group('passkeys');

// The ceremony fails loud rather than fall back to weak origin/RP validation.

it('refuses to construct without an rp_id', function () {
    expect(fn () => new SpomkyWebAuthnCeremony([
        'rp_id' => '',
        'rp_name' => 'Example',
        'origins' => ['https://app.example.com'],
        'user_verification' => 'preferred',
    ]))->toThrow(InvalidArgumentException::class);
});

it('refuses to construct with no allowed origins', function () {
    expect(fn () => new SpomkyWebAuthnCeremony([
        'rp_id' => 'example.com',
        'rp_name' => 'Example',
        'origins' => [],
        'user_verification' => 'preferred',
    ]))->toThrow(InvalidArgumentException::class);
});

/** The emulator emits padded base64; the ceremony reads base64url. */
function spomkyB64u(mixed $value): mixed
{
    return is_array($value)
        ? array_map('spomkyB64u', $value)
        : (is_string($value) ? rtrim(strtr($value, '+/', '-_'), '=') : $value);
}

function spomky(array $overrides = []): SpomkyWebAuthnCeremony
{
    return new SpomkyWebAuthnCeremony([
        'rp_id' => 'localhost',
        'rp_name' => 'lukk',
        'origins' => ['https://localhost'],
        'user_verification' => 'preferred',
        ...$overrides,
    ]);
}

/** Enrol one credential through the real ceremony; returns the authenticator and the stored record. */
function spomkyEnrolled(SpomkyWebAuthnCeremony $ceremony): array
{
    $authenticator = new Authenticator(new InMemoryRepository);
    $challenge = app(PasskeyChallengeStore::class)->generate();
    $attestation = spomkyB64u($authenticator->getAttestation($ceremony->registrationOptions(1, 'u@e.com', $challenge, []), 'https://localhost'));
    $passkey = $ceremony->verifyRegistration(1, $attestation, $challenge);

    return [$authenticator, new PasskeyRecord($passkey->credentialId, 1, $passkey->publicKey, $passkey->signCount, [], null, null, null), $attestation, $challenge];
}

function spomkyRefusal(Closure $call): PasskeyVerificationFailed
{
    try {
        $call();
    } catch (PasskeyVerificationFailed $e) {
        return $e;
    }

    throw new RuntimeException('Expected the ceremony to refuse.');
}

it('accepts only the listed origins, not any subdomain of the RP ID', function (string $origin) {
    // Without an explicit list the library falls back to matching the RP ID as a SUFFIX, so any
    // subdomain of it — or another port — would pass for a registrable domain the app shares.
    [$authenticator, $stored] = spomkyEnrolled(spomky());
    $challenge = app(PasskeyChallengeStore::class)->generate();
    $assertion = spomkyB64u($authenticator->getAssertion('localhost', null, $challenge, $origin));

    spomkyRefusal(fn () => spomky()->verifyAssertion($assertion, $challenge, $stored));

    $challenge = app(PasskeyChallengeStore::class)->generate();
    $assertion = spomkyB64u($authenticator->getAssertion('localhost', null, $challenge, 'https://localhost'));
    expect(spomky()->verifyAssertion($assertion, $challenge, $stored))->toBeInt();
})->with([
    'a subdomain' => ['https://evil.localhost'],
    'another port' => ['https://localhost:8443'],
]);

it('leaves the sign-count policy to lukk, reporting a regressed counter instead of refusing it', function () {
    // The library's default checker throws on a regression, which would pre-empt lukk's own policy
    // (which must never flag a synced passkey's 0). The ceremony only reports the counter.
    [$authenticator, $stored] = spomkyEnrolled(spomky());
    $source = json_decode($stored->publicKey, true);
    $source['counter'] = 1000;
    $ahead = new PasskeyRecord($stored->credentialId, 1, json_encode($source), 1000, [], null, null, null);

    $challenge = app(PasskeyChallengeStore::class)->generate();
    $assertion = spomkyB64u($authenticator->getAssertion('localhost', null, $challenge, 'https://localhost'));

    expect(spomky()->verifyAssertion($assertion, $challenge, $ahead))->toBeLessThan(1000);
});

it('names a response of the wrong kind rather than failing somewhere inside the library', function () {
    [$authenticator, $stored, $attestation, $regChallenge] = spomkyEnrolled(spomky());
    $challenge = app(PasskeyChallengeStore::class)->generate();
    $assertion = spomkyB64u($authenticator->getAssertion('localhost', null, $challenge, 'https://localhost'));

    expect(spomkyRefusal(fn () => spomky()->verifyRegistration(1, $assertion, $challenge))->getMessage())->toBe('Not an attestation response.')
        ->and(spomkyRefusal(fn () => spomky()->verifyAssertion($attestation, $regChallenge, $stored))->getMessage())->toBe('Not an assertion response.');
});

it('advertises ES256 and RS256, and excludes the given credentials', function () {
    $options = spomky()->registrationOptions(1, 'u@e.com', 'AQID', ['BAUG', 'BwgJ']);

    expect(array_column($options['pubKeyCredParams'], 'alg'))->toBe([-7, -257])
        ->and($options['excludeCredentials'])->toBe([
            ['type' => 'public-key', 'id' => 'BAUG'],
            ['type' => 'public-key', 'id' => 'BwgJ'],
        ]);
});

it('asks for the configured user verification and allows the given credentials at sign-in', function () {
    $options = spomky()->authenticationOptions('AQID', ['BAUG']);

    expect($options['userVerification'])->toBe('preferred')
        ->and($options['allowCredentials'])->toBe([['type' => 'public-key', 'id' => 'BAUG']]);
});
