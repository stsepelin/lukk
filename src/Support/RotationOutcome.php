<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * Result of the rotation decision, returned OUT of the DB transaction so the
 * caller can finalise (revoke + reject) after commit — never inside it.
 */
class RotationOutcome
{
    private function __construct(
        public readonly string $type,            // issued|unknown|revoked|expired|reuse
        public readonly ?string $familyId = null,
        public readonly int|string|null $userId = null,
        public readonly ?string $refreshSecret = null,
    ) {}

    public static function issued(int|string $userId, string $familyId, string $refreshSecret): self
    {
        return new self('issued', $familyId, $userId, $refreshSecret);
    }

    public static function unknown(): self
    {
        return new self('unknown');
    }

    public static function expired(): self
    {
        return new self('expired');
    }

    public static function revoked(string $familyId): self
    {
        return new self('revoked', $familyId);
    }

    public static function reuse(string $familyId): self
    {
        return new self('reuse', $familyId);
    }
}
