<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;

/**
 * Revoke every session for a user except the calling one (logout other devices).
 */
class RevokeOtherSessions
{
    /**
     * @param  array{access_ttl:int,...}  $config
     */
    public function __construct(
        private readonly RefreshTokenRepository $repository,
        private readonly Denylist $denylist,
        private readonly array $config,
    ) {}

    public function __invoke(int|string $userId, string $currentFamilyId): void
    {
        // Denylisted inside the repository's transaction and BEFORE the rows are revoked — see
        // `RevokeSession` for why that direction is the safe one to fail in.
        $this->repository->revokeUserFamiliesExcept($userId, $currentFamilyId, fn (array $ids) => array_map(
            fn (string $familyId) => $this->denylist->revokeFamily(
                $familyId, $this->config['access_ttl'] + $this->config['leeway'],
            ), $ids,
        ));
    }
}
