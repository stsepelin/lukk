<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * Storage-agnostic snapshot of a refresh-token row, handed to the rotation
 * policy. Timestamps are unix seconds so the policy does no date-library work.
 */
class RefreshTokenRecord
{
    public function __construct(
        public readonly string $id,
        public readonly int|string $userId,
        public readonly string $familyId,
        public readonly ?int $rotatedAt,
        public readonly ?int $revokedAt,
        public readonly int $expiresAt,
        /** The family's own scope claim, or null to derive it per mint. */
        public readonly ?string $scope = null,
        /** When the session started — meaningful to a data subject reading their own export. */
        public readonly ?int $createdAt = null,
    ) {}
}
