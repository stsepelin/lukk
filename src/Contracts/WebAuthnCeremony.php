<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Lukk\Support\NewPasskey;
use Lukk\Support\PasskeyRecord;

/**
 * The WebAuthn crypto seam — wraps an audited library (web-auth/webauthn-lib or
 * laragear/webauthn). lukk owns the challenge lifecycle and the sign-count
 * policy; this only builds ceremony options and verifies attestations/assertions
 * against a challenge we supply. NEVER hand-roll this.
 */
interface WebAuthnCeremony
{
    /**
     * @param  array<int,string>  $excludeCredentialIds
     * @return array<string,mixed> PublicKeyCredentialCreationOptions for the client
     */
    public function registrationOptions(int|string $userId, string $userName, string $challenge, array $excludeCredentialIds): array;

    /**
     * Verify a `navigator.credentials.create()` response against the challenge.
     * The user id is needed to bind the credential's user handle.
     *
     * @param  array<string,mixed>  $response
     */
    public function verifyRegistration(int|string $userId, array $response, string $challenge): NewPasskey;

    /**
     * Does this ceremony REQUIRE user verification — a PIN or biometric, not just presence?
     *
     * The answer decides whether a passkey may stand in for the user's second factor: with UV it is
     * two factors in one gesture, without it possession alone. Asked of the implementation rather
     * than read from config because config is not the authority — the ceremony is a singleton whose
     * setting is frozen at first resolution, and it is a swap seam, so a replacement may enforce
     * something else entirely. Inferring it from `lukk.passkeys.user_verification` failed OPEN in
     * both cases: the gate skipped an enrolled second factor on the strength of a `required` that
     * nothing had applied.
     */
    public function verifiesUser(): bool;

    /**
     * @param  array<int,string>  $allowCredentialIds
     * @return array<string,mixed> PublicKeyCredentialRequestOptions for the client
     */
    public function authenticationOptions(string $challenge, array $allowCredentialIds): array;

    /**
     * Verify a `navigator.credentials.get()` response against the challenge and
     * the stored credential; return the authenticator's new sign count.
     *
     * @param  array<string,mixed>  $response
     */
    public function verifyAssertion(array $response, string $challenge, PasskeyRecord $stored): int;
}
