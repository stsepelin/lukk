<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Lukk\Actions\Concerns\ComputesDenylistTtl;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;

/**
 * Revoke every session for a user (logout-all).
 */
class RevokeAllSessions
{
    use ComputesDenylistTtl;

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
        $ttl = $this->denylistTtl($this->config);

        // Denylisted inside the repository's transaction and BEFORE the rows are revoked — see
        // `RevokeSession` for why that direction is the safe one to fail in.
        $this->repository->revokeUserFamilies($userId, fn (array $ids) => array_map(
            fn (string $familyId) => $this->denylist->revokeFamily($familyId, $ttl), $ids,
        ));
    }
}
