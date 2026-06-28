<?php

declare(strict_types=1);

namespace Lukk\Passkeys;

use Webauthn\Counter\CounterChecker;
use Webauthn\CredentialRecord;

/**
 * No-op counter checker — lukk owns the sign-count regression policy in
 * Actions\FinishPasskeyLogin (so it can fire PasskeyCloneDetected and treat 0
 * correctly), consistent whether the real or a fake ceremony is bound.
 */
class NullCounterChecker implements CounterChecker
{
    public function check(CredentialRecord $credentialRecord, int $currentCounter): void {}
}
