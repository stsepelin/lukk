<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Validation\ValidationException;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Events\PasskeyCloneDetected;
use Lukk\Exceptions\PasskeyVerificationFailed;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Support\PasskeyRecord;
use Lukk\Support\VerifiedPasskey;

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
        // Null unless `features.lockout` is on.
        private readonly ?LockoutRepository $lockouts = null,
        private readonly ?string $guard = null,
    ) {}

    /**
     * @param  array<string, mixed>  $response
     * @param  string|null  $userVerification  enforced for THIS ceremony; null for the configured one
     */
    public function __invoke(string $ceremonyId, array $response, ?string $userVerification = null, int|string|null $owner = null): VerifiedPasskey
    {
        $challenge = $this->challenges->pullForCeremony($ceremonyId);

        if ($challenge === null) {
            $this->fail();
        }

        // A missing id is not found under any placeholder, so the '' only states the type.
        $stored = $this->passkeys->findByCredentialId((string) ($response['id'] ?? '')); // @pest-mutate-ignore: EmptyStringToNotEmpty

        if ($stored === null) {
            $this->fail();
        }

        try {
            $assertion = $this->ceremony->verifyAssertion($response, $challenge, $stored, $userVerification, $owner);
        } catch (PasskeyVerificationFailed) {
            $this->fail();
        }

        $newSignCount = $assertion->signCount;
        $this->guardAgainstClone($stored, $newSignCount);

        // Never lower the ratchet, and notice losing a race: two assertions presenting the same next counter
        // (a clone and the real key at once) both passed the check above against the same stale read, and only
        // one can move the counter. The one that cannot is the clone signal WebAuthn L3 §7.2 describes.
        if (! $this->passkeys->updateSignCount($stored->credentialId, max($stored->signCount, $newSignCount))
            && $newSignCount > $stored->signCount) {
            // Or the credential was deleted mid-ceremony, which also writes nothing: refused either
            // way, but only a row still there is a lost race worth an alarm.
            if ($this->passkeys->existsByCredentialId($stored->credentialId)) {
                event(new PasskeyCloneDetected($stored->userId, $stored->credentialId));
            }

            $this->fail();
        }

        return new VerifiedPasskey($stored->userId, $stored->credentialId, $assertion->multiFactor);
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

    /**
     * A verified passkey ends a run of password-confirm failures, as a correct password does: a passkey-
     * primary user must not carry failures a token thief planted months ago. The CALLER decides when — a
     * step-up only once it is accepted, or a refused one would reset the counter every attempt.
     */
    public function releaseConfirmLock(VerifiedPasskey $passkey): void
    {
        $this->lockouts?->release('confirm', (string) $passkey->userId, $this->guard);
    }

    private function fail(): never
    {
        throw ValidationException::withMessages(['credential' => [__('The passkey could not be verified.')]]);
    }
}
