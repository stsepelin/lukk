<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Support\UnclaimedSessions;

/**
 * Revoke a single session (family): refresh tokens in the DB + denylist its
 * access tokens so they die within their remaining TTL.
 */
class RevokeSession
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly RefreshTokenRepository $repository,
        private readonly Denylist $denylist,
        private readonly array $config,
        /** Null unless this guard's `claim_seconds` is on. */
        private readonly ?UnclaimedSessions $unclaimed = null,
    ) {}

    public function __invoke(string $familyId): void
    {
        // Denylist FIRST: if the second write fails, a leftover denylist entry is harmless, whereas a
        // DB revoke with no denylist entry would leave the family's access tokens live until expiry.
        //
        // Both defaults are load-bearing, not decoration: a config cached before these keys existed
        // gets no backfill (`mergeConfigDeep` early-returns), the two missing reads add to 0, and
        // `Cache::put()` with a non-positive TTL FORGETS the key instead of writing it — so every
        // revoke, logout included, would silently denylist nothing at all.
        $ttl = (int) ($this->config['access_ttl'] ?? 900) + (int) ($this->config['leeway'] ?? 5);

        $this->denylist->revokeFamily($familyId, $ttl);
        $this->repository->revokeFamily($familyId);

        // Last: a revoked family's marker is harmless (the denylist and the rows already refuse it),
        // so this is tidiness, and it must not stand between a logout and the revocation above.
        $this->unclaimed?->forget($familyId);
    }
}
