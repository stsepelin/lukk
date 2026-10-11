<?php

declare(strict_types=1);

namespace Lukk\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

/**
 * A recovery code was spent to complete a two-factor sign-in.
 *
 * NIST SP 800-63B-4 §4.2 asks that the subscriber be notified when an account is recovered. A
 * recovery code is the way back in after losing the authenticator — and equally the way in for whoever
 * found the printed list — so lukk announces every successful use. lukk sends no mail: listen for this,
 * tell the user through a channel independent of the request, and prompt them to regenerate the set
 * (`$remaining` is how many unused codes are left; at 0 the next lost authenticator has no way back).
 *
 * Fired once the code is spent, whether or not the sign-in then completes: the code is gone either way.
 */
class RecoveryCodeUsed
{
    // As `RecoveryCodesGenerated`: a queued listener receives the user as an IDENTIFIER, never the model
    // with its password hash, encrypted TOTP secret and the remaining recovery-code hashes.
    use SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly int $remaining,
    ) {}
}
