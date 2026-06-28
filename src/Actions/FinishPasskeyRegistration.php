<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Exceptions\PasskeyVerificationFailed;
use Lukk\Passkeys\PasskeyChallengeStore;

/**
 * Verify a registration attestation against the pending challenge and persist
 * the new credential.
 */
class FinishPasskeyRegistration
{
    public function __construct(
        private readonly PasskeyChallengeStore $challenges,
        private readonly WebAuthnCeremony $ceremony,
        private readonly PasskeyRepository $passkeys,
    ) {}

    /**
     * @param  array<string,mixed>  $response
     */
    public function __invoke(Authenticatable $user, array $response, ?string $name = null): void
    {
        $challenge = $this->challenges->pullForUser($user->getAuthIdentifier());

        if ($challenge === null) {
            $this->fail();
        }

        try {
            $passkey = $this->ceremony->verifyRegistration($user->getAuthIdentifier(), $response, $challenge);
        } catch (PasskeyVerificationFailed) {
            $this->fail();
        }

        // credential_id is globally unique (PK); a duplicate would otherwise be a
        // raw DB error rather than a clean "could not be registered" response.
        if ($this->passkeys->findByCredentialId($passkey->credentialId) !== null) {
            $this->fail();
        }

        $this->passkeys->store($user->getAuthIdentifier(), $passkey, $name);
    }

    private function fail(): never
    {
        throw ValidationException::withMessages(['credential' => [__('The passkey could not be registered.')]]);
    }
}
