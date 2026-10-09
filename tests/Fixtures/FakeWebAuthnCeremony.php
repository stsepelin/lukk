<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Exceptions\PasskeyVerificationFailed;
use Lukk\Support\NewPasskey;
use Lukk\Support\PasskeyAssertion;
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

    public function authenticationOptions(string $challenge, array $allowCredentialIds, ?string $userVerification = null): array
    {
        return [
            'challenge' => $challenge,
            'allowCredentials' => $allowCredentialIds,
            'userVerification' => $userVerification ?? (config('lukk.passkeys.user_verification') ?? 'required'),
        ];
    }

    /**
     * Mirrors the real rule (`SpomkyWebAuthnCeremony`): an assertion is multi-factor only when it
     * carries UV AND the stored credential was already `uvInitialized` — here, stored as `PUB+uv`.
     *
     * An EXPLICIT `required` is enforced, as the library enforces it; the CONFIGURED requirement is
     * not, because pinning the library's own config-level UV check is `PasskeyIntegrationTest`'s job
     * and enforcing it here would make every flow test model a UV-capable authenticator.
     */
    /** The owner the last assertion was checked against — `(string)` id, or null at sign-in. */
    public static ?string $lastOwner = null;

    public function verifyAssertion(array $response, string $challenge, PasskeyRecord $stored, ?string $userVerification = null, int|string|null $owner = null): PasskeyAssertion
    {
        self::$lastOwner = $owner === null ? null : (string) $owner;

        if (($response['challenge'] ?? null) !== $challenge || ($response['id'] ?? null) !== $stored->credentialId) {
            throw new PasskeyVerificationFailed('assertion mismatch');
        }

        $userVerified = ($response['uv'] ?? false) === true;

        if ($userVerification === 'required' && ! $userVerified) {
            throw new PasskeyVerificationFailed('user verification required');
        }

        return new PasskeyAssertion(
            signCount: (int) ($response['sign_count'] ?? $stored->signCount + 1),
            userVerified: $userVerified,
            multiFactor: $userVerified && $this->isMultiFactor($stored),
        );
    }

    public function isMultiFactor(PasskeyRecord $stored): bool
    {
        return str_ends_with($stored->publicKey, '+uv');
    }
}
