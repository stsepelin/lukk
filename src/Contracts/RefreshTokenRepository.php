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

    /**
     * A plain, NON-locking read. `RotateRefreshToken` uses it to resolve the subject before opening
     * the transaction, so the application's `abilitiesUsing` callback never runs while a row lock is
     * held. A token hash's subject and family are written once and never updated, so reading them
     * outside the lock is safe.
     */
    public function findByHash(string $hash): ?RefreshTokenRecord;

    /**
     * Whether a family owns a PINNED grant — `scope` is non-null on its rows.
     *
     * The authoritative answer to "is this a machine token". The `pin` claim is the fast path, but
     * it is stamped by `TokenIssuer` — a swap seam — so an implementation that forgets to forward
     * `TokenContext::$pinned` would produce a genuinely pinned token that lukk's own gates wave
     * through. This is consulted whenever the claim is absent, which closes that seam.
     *
     * One residual window, stated precisely rather than papered over: a token carrying no `fid` has
     * no family to check, and is treated as not pinned. lukk never mints a pinned token without a
     * family, so this only matters for a custom issuer that drops the family id AND `pinned` while
     * still honouring `$abilities`. Denying instead would break the co-issuer topology, where a
     * token minted by another service sharing the secret legitimately carries no `fid`.
     *
     * Return false when the backing store cannot express a pin at all (e.g. a pre-0.6 schema with
     * no `scope` column): nothing there can be pinned, so nothing there can be wrongly ungated.
     */
    public function familyIsPinned(string $familyId): bool;

    public function findByHashForUpdate(string $hash): ?RefreshTokenRecord;

    /**
     * @param  ?string  $scope  The family's OWN abilities, pinned for its lifetime (a personal
     *                          access token, an impersonation cap). **Null derives them per mint;
     *                          `''` is a grant pinned to nothing.** The two are different tokens and
     *                          the storage must keep them apart — conflating them lets the most
     *                          restricted token widen to the subject's full grant on first refresh.
     */
    public function persist(int|string $userId, string $familyId, ?string $previousId, string $tokenHash, int $expiresAt, ?string $scope = null): void;

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
