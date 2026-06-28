<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Passkeys\PasskeyChallengeStore;

/**
 * Begin passkey registration: mint + store a single-use challenge (keyed to the
 * user) and return the creation options, excluding the user's existing credentials.
 */
class StartPasskeyRegistration
{
    public function __construct(
        private readonly PasskeyChallengeStore $challenges,
        private readonly WebAuthnCeremony $ceremony,
        private readonly PasskeyRepository $passkeys,
    ) {}

    /**
     * @return array<string,mixed>
     */
    public function __invoke(Authenticatable $user): array
    {
        $challenge = $this->challenges->generate();
        $this->challenges->putForUser($user->getAuthIdentifier(), $challenge);

        return $this->ceremony->registrationOptions(
            $user->getAuthIdentifier(),
            $user->email ?? (string) $user->getAuthIdentifier(),
            $challenge,
            $this->passkeys->credentialIdsFor($user->getAuthIdentifier()),
        );
    }
}
