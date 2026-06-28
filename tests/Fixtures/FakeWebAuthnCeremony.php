<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Exceptions\PasskeyVerificationFailed;
use Lukk\Support\NewPasskey;
use Lukk\Support\PasskeyRecord;

/**
 * Stands in for the real (library-backed) WebAuthn crypto so tests can drive the
 * lukk orchestration deterministically. It echoes the challenge into its
 * options and verifies that the client "response" carries the matching challenge
 * + credential id — enough to exercise the challenge lifecycle, sign-count policy,
 * and flow without a real authenticator.
 */
class FakeWebAuthnCeremony implements WebAuthnCeremony
{
    public function registrationOptions(int|string $userId, string $userName, string $challenge, array $excludeCredentialIds): array
    {
        return ['challenge' => $challenge, 'user' => $userName, 'excludeCredentials' => $excludeCredentialIds];
    }

    public function verifyRegistration(int|string $userId, array $response, string $challenge): NewPasskey
    {
        if (($response['challenge'] ?? null) !== $challenge) {
            throw new PasskeyVerificationFailed('challenge mismatch');
        }

        return new NewPasskey(
            credentialId: (string) $response['id'],
            publicKey: (string) ($response['public_key'] ?? 'PUB'),
            signCount: (int) ($response['sign_count'] ?? 0),
            transports: $response['transports'] ?? [],
        );
    }

    public function authenticationOptions(string $challenge, array $allowCredentialIds): array
    {
        return ['challenge' => $challenge, 'allowCredentials' => $allowCredentialIds];
    }

    public function verifyAssertion(array $response, string $challenge, PasskeyRecord $stored): int
    {
        if (($response['challenge'] ?? null) !== $challenge || ($response['id'] ?? null) !== $stored->credentialId) {
            throw new PasskeyVerificationFailed('assertion mismatch');
        }

        return (int) ($response['sign_count'] ?? $stored->signCount + 1);
    }
}
