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
        // Never lower the ratchet. The guard above already throws on a regression, so this is
        // belt-and-braces — but a rebound ceremony must not be able to walk the counter backwards.
        $this->passkeys->updateSignCount($stored->credentialId, max($stored->signCount, $newSignCount));

        return $stored->userId;
    }

    /**
     * A regression only counts once a non-zero counter has been seen — synced
     * passkeys legitimately report 0 forever, so 0 is never a clone signal.
     *
     * The test is on the STORED counter alone. Also requiring the incoming one to be non-zero let
     * a clone present `0` against a credential that had reached 10: a textbook regression under
     * WebAuthn L3 §6.1.1, accepted — and then written back, resetting the ratchet so the genuine
     * authenticator's counter never tripped it again either. A synced passkey is unaffected: its
     * stored count is 0 forever, so the first clause is what keeps it from ever being flagged.
     */
    private function guardAgainstClone(PasskeyRecord $stored, int $newSignCount): void
    {
        if ($stored->signCount > 0 && $newSignCount <= $stored->signCount) {
            event(new PasskeyCloneDetected($stored->userId, $stored->credentialId));

            $this->fail();
        }
    }

    private function fail(): never
    {
        throw ValidationException::withMessages(['credential' => [__('The passkey could not be verified.')]]);
    }
}
