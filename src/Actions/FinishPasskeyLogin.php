<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Validation\ValidationException;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Events\PasskeyCloneDetected;
use Lukk\Exceptions\PasskeyVerificationFailed;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Support\PasskeyRecord;

/**
 * Verify an assertion against the pending challenge + the stored credential, run
 * the sign-count regression check, bump the counter, and return the user id.
 */
class FinishPasskeyLogin
{
    public function __construct(
        private readonly PasskeyChallengeStore $challenges,
        private readonly WebAuthnCeremony $ceremony,
        private readonly PasskeyRepository $passkeys,
    ) {}

    public function __invoke(string $ceremonyId, array $response): int|string
    {
        $challenge = $this->challenges->pullForCeremony($ceremonyId);

        if ($challenge === null) {
            $this->fail();
        }

        $stored = $this->passkeys->findByCredentialId((string) ($response['id'] ?? ''));

        if ($stored === null) {
            $this->fail();
        }

        try {
            $newSignCount = $this->ceremony->verifyAssertion($response, $challenge, $stored);
        } catch (PasskeyVerificationFailed) {
            $this->fail();
        }

        $this->guardAgainstClone($stored, $newSignCount);
        $this->passkeys->updateSignCount($stored->credentialId, $newSignCount);

        return $stored->userId;
    }

    /**
     * A regression only counts once a non-zero counter has been seen — synced
     * passkeys legitimately report 0 forever, so 0 is never a clone signal.
     */
    private function guardAgainstClone(PasskeyRecord $stored, int $newSignCount): void
    {
        if ($stored->signCount > 0 && $newSignCount > 0 && $newSignCount <= $stored->signCount) {
            event(new PasskeyCloneDetected($stored->userId, $stored->credentialId));

            $this->fail();
        }
    }

    private function fail(): never
    {
        throw ValidationException::withMessages(['credential' => [__('The passkey could not be verified.')]]);
    }
}
