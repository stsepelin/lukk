<?php

declare(strict_types=1);

namespace Lukk\Support;

/** The outcome of a passkey login or step-up: who it was, and how strongly it was proved. */
class VerifiedPasskey
{
    public function __construct(
        public readonly int|string $userId,
        public readonly string $credentialId,
        public readonly bool $multiFactor,
    ) {}
}
