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
     * @param  array{access_ttl:int,...}  $config
     */
    public function __construct(
        private readonly RefreshTokenRepository $repository,
        private readonly Denylist $denylist,
        private readonly array $config,
    ) {}

    public function __invoke(int|string $userId): void
    {
        foreach ($this->repository->revokeUserFamilies($userId) as $familyId) {
            $this->denylist->revokeFamily($familyId, $this->config['access_ttl'] + $this->config['leeway']);
        }
    }
}
