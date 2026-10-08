<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Passkeys\PasskeyAssurance;
use Lukk\Passkeys\PasskeyChallengeStore;

/**
 * Negotiates a passkey STEP-UP ceremony for an already-authenticated user.
 *
 * Separate from `StartPasskeyLogin` because a step-up knows who is asking. That buys two things the
 * anonymous login options cannot:
 *
 *  - `userVerification: required` exactly when this ACCOUNT can reach AAL2 (a password, or any
 *    passkey that has shown user verification). WebAuthn L3 §5.8.6 is how an RP says it needs UV,
 *    and NIST SP 800-63B-4 §4.1.2.1 is why it does: the step-up mints the token that binds and
 *    removes authenticators, which must be authenticated at the account's highest available level.
 *    An account with nothing stronger gets `preferred`, so a key that cannot verify still works.
 *  - `allowCredentials` listing the user's own credentials, so a non-discoverable key can be used.
 */
class StartPasskeyConfirmation
{
    public function __construct(
        private readonly PasskeyChallengeStore $challenges,
        private readonly WebAuthnCeremony $ceremony,
        private readonly PasskeyAssurance $assurance,
    ) {}

    /** @return array{ceremony_id: string, options: array<string, mixed>} */
    public function __invoke(Authenticatable $user): array
    {
        $challenge = $this->challenges->generate();
        $ceremonyId = $this->challenges->putForCeremony($challenge);

        return [
            'ceremony_id' => $ceremonyId,
            'options' => $this->ceremony->authenticationOptions(
                $challenge,
                $this->assurance->credentialIdsFor($user),
                $this->assurance->requiredUserVerification($user),
            ),
        ];
    }
}
