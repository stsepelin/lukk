<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;

/**
 * Revoke every session for a user (logout-all).
 */
class RevokeAllSessions
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly RefreshTokenRepository $repository,
        private readonly Denylist $denylist,
        private readonly array $config,
    ) {}

    public function __invoke(int|string $userId): void
    {
        // Denylisted inside the repository's transaction and BEFORE the rows are revoked — see
        // `RevokeSession` for why that direction is the safe one to fail in.
        $this->repository->revokeUserFamilies($userId, fn (array $ids) => array_map(
            fn (string $familyId) => $this->denylist->revokeFamily(
                $familyId, $this->config['access_ttl'] + $this->config['leeway'],
            ), $ids,
        ));
    }
}
