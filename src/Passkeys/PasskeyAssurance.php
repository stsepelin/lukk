<?php

declare(strict_types=1);

namespace Lukk\Passkeys;

use Illuminate\Contracts\Auth\Authenticatable;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Support\VerifiedPasskey;

/**
 * How strongly an ACCOUNT can authenticate, and whether one passkey step-up meets that bar.
 *
 * NIST SP 800-63B-4 §4.1.2.1: binding an authenticator requires authentication at "the maximum AAL
 * currently available in the subscriber account". lukk's step-up token is what binds and removes
 * authenticators (passkey enrolment, `DELETE /auth/two-factor`), so the same bar applies to it.
 *
 * AAL2 is within an account's reach when it has a password (§2.2.1: a password alongside any
 * physical authenticator), or a passkey that is multi-factor on its own (§2.2.1, a multi-factor
 * authenticator; WebAuthn L3 §6.2.3). A TOTP does NOT raise it: an OTP authenticator is "something
 * you have" (§3.1.4), the same category as a single-factor passkey (§3.1.6), and §2.2.1 requires a
 * password or biometric comparison for two single-factor authenticators to reach AAL2.
 */
class PasskeyAssurance
{
    public function __construct(
        private readonly WebAuthnCeremony $ceremony,
        private readonly PasskeyRepository $passkeys,
    ) {}

    /** Can this account authenticate at AAL2 at all? */
    public function canReachMultiFactor(Authenticatable $user): bool
    {
        // `(string)` normalises the two "no usable password" states the framework short-circuits on.
        if ((string) $user->getAuthPassword() !== '') {
            return true;
        }

        return $this->hasMultiFactorCredential($user);
    }

    /** Whether any of the account's passkeys has shown user verification, so it alone reaches AAL2. */
    public function hasMultiFactorCredential(Authenticatable $user): bool
    {
        foreach ($this->passkeys->credentialIdsFor($user->getAuthIdentifier()) as $credentialId) {
            $record = $this->passkeys->findByCredentialId($credentialId);

            if ($record !== null && $this->ceremony->isMultiFactor($record)) {
                return true;
            }
        }

        return false;
    }

    /** Does this verified step-up meet the account's own highest available level? */
    public function permitsStepUp(Authenticatable $user, VerifiedPasskey $passkey): bool
    {
        return $passkey->multiFactor || ! $this->canReachMultiFactor($user);
    }

    /** What a step-up ceremony should ask the authenticator for (WebAuthn L3 §5.8.6). */
    public function requiredUserVerification(Authenticatable $user): string
    {
        return $this->canReachMultiFactor($user) ? 'required' : 'preferred';
    }

    /** @return list<string> */
    public function credentialIdsFor(Authenticatable $user): array
    {
        return array_values($this->passkeys->credentialIdsFor($user->getAuthIdentifier()));
    }
}
