<?php

declare(strict_types=1);

namespace Lukk\Events;

/**
 * A consecutive-failure run hit the cap and the account is now locked (NIST SP 800-63B §5.2.2).
 *
 * Fired once, on the transition. A locked-out user gets no other signal — they simply can't
 * authenticate — so this is where an app sends the "someone is trying to get into your account"
 * mail, or a release link. `$subject` is the normalized identifier for a login lock and the user id
 * for a two-factor one; it is NOT a resolved user, because a login lock can name an account that
 * doesn't exist.
 */
class AccountLocked
{
    public function __construct(
        public readonly string $purpose,
        public readonly string $subject,
        public readonly ?string $guard,
    ) {}
}
