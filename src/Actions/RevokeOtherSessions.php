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
        foreach ($this->repository->revokeUserFamiliesExcept($userId, $currentFamilyId) as $familyId) {
            $this->denylist->revokeFamily($familyId, $this->config['access_ttl'] + $this->config['leeway']);
        }
    }
}
