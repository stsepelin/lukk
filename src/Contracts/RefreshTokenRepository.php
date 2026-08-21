<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Closure;
use Lukk\Support\RefreshTokenRecord;

/**
 * Storage seam for refresh tokens. Swap the implementation (DB, Redis, ...)
 * without touching the rotation policy in Actions\RotateRefreshToken.
 *
 * The policy runs its read+decide+mutate inside transaction(); findByHashForUpdate
 * MUST acquire a row lock so concurrent rotations of the same token serialize.
 */
interface RefreshTokenRepository
{
    public function transaction(Closure $callback): mixed;

    public function findByHashForUpdate(string $hash): ?RefreshTokenRecord;

    public function persist(int|string $userId, string $familyId, ?string $previousId, string $tokenHash, int $expiresAt): void;

    public function markRotated(string $id): void;

    /**
     * How many live (unrotated, unrevoked, unexpired) tokens the family holds.
     *
     * Only used for the fan-out signal: the grace window tolerates a re-consumption by minting a
     * sibling, so legitimate concurrency settles at two or three, while a family forked by a thief
     * keeps growing. See `Events\RefreshFamilyForked`.
     */
    public function countLiveTokens(string $familyId): int;

    public function revokeFamily(string $familyId): void;

    /**
     * Revoke every active family for the user; return the affected family ids
     * (so the caller can denylist their access tokens).
     *
     * @return array<int,string>
     */
    public function revokeUserFamilies(int|string $userId, ?callable $before = null): array;

    /**
     * Revoke every active family for the user except the given one (logout
     * others); return the affected family ids.
     *
     * @return array<int,string>
     */
    public function revokeUserFamiliesExcept(int|string $userId, string $exceptFamilyId, ?callable $before = null): array;

    public function pruneExpired(): int;
}
