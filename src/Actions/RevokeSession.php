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
        $this->denylist->revokeFamily($familyId, $this->config['access_ttl'] + $this->config['leeway']);
        $this->repository->revokeFamily($familyId);

        // Last: a revoked family's marker is harmless (the denylist and the rows already refuse it),
        // so this is tidiness, and it must not stand between a logout and the revocation above.
        $this->unclaimed?->forget($familyId);
    }
}
