<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Lukk\Support\NewPasskey;
use Lukk\Support\PasskeyAssertion;
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
     * @param  array<int,string>  $allowCredentialIds
     * @param  string|null  $userVerification  `required`/`preferred`/`discouraged` for THIS ceremony,
     *                                         or null for the configured requirement. A step-up that
     *                                         needs user verification asks for `required` (WebAuthn
     *                                         L3 §5.8.6) whatever the login setting is.
     * @return array<string,mixed> PublicKeyCredentialRequestOptions for the client
     */
    public function authenticationOptions(string $challenge, array $allowCredentialIds, ?string $userVerification = null): array;

    /**
     * Verify a `navigator.credentials.get()` response against the challenge and the stored
     * credential, enforcing `$userVerification` (or the configured requirement when null).
     *
     * Returns what the assertion PROVED, not just its counter: whether it carried user verification,
     * and whether that may be relied on as a second factor — see `PasskeyAssertion::$multiFactor`.
     * An implementation must report `multiFactor` true only for a credential that was already
     * `uvInitialized` before this ceremony; WebAuthn L3 §4 says the UV flag "MUST NOT be relied upon"
     * otherwise, and lukk skips a user's enrolled second factor on the strength of this answer.
     *
     * @param  array<string,mixed>  $response
     */
    public function verifyAssertion(array $response, string $challenge, PasskeyRecord $stored, ?string $userVerification = null): PasskeyAssertion;

    /**
     * Can this stored credential prove two factors in one gesture — has it shown user verification
     * to this RP (`uvInitialized`)? Used to work out the highest assurance an ACCOUNT can reach,
     * which a step-up must meet (NIST SP 800-63B-4 §4.1.2.1). False when unknown.
     */
    public function isMultiFactor(PasskeyRecord $stored): bool;
}
