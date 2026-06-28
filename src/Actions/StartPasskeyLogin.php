<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Passkeys\PasskeyChallengeStore;

/**
 * Begin passkey login: mint a challenge under an opaque ceremony id (no identity
 * yet) and return the request options. Usernameless by default (discoverable
 * credentials → empty allowCredentials).
 */
class StartPasskeyLogin
{
    public function __construct(
        private readonly PasskeyChallengeStore $challenges,
        private readonly WebAuthnCeremony $ceremony,
    ) {}

    /**
     * @return array{ceremony_id:string,options:array<string,mixed>}
     */
    public function __invoke(): array
    {
        $challenge = $this->challenges->generate();
        $ceremonyId = $this->challenges->putForCeremony($challenge);

        return [
            'ceremony_id' => $ceremonyId,
            'options' => $this->ceremony->authenticationOptions($challenge, []),
        ];
    }
}
