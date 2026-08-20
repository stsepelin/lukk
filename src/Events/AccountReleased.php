<?php

declare(strict_types=1);

namespace Lukk\Events;

/** A lock was lifted — by `lukk:release`, the repository API, or an auto-release. */
class AccountReleased
{
    public function __construct(
        public readonly string $purpose,
        public readonly string $subject,
        public readonly ?string $guard,
    ) {}
}
