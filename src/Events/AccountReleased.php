<?php

declare(strict_types=1);

namespace Lukk\Events;

/**
 * A HELD lock was lifted — by a successful authentication, a password reset, `lukk:release`, or the
 * repository API. Not for clearing a counter that never reached the cap, and not for a `release_after`
 * expiry, which is read-only and announces nothing.
 */
class AccountReleased
{
    public function __construct(
        public readonly string $purpose,
        public readonly string $subject,
        public readonly ?string $guard,
    ) {}
}
