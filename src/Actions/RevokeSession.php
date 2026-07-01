<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;

/**
 * Revoke a single session (family): refresh tokens in the DB + denylist its
 * access tokens so they die within their remaining TTL.
 */
class RevokeSession
{
    /**
     * @param  array{access_ttl:int,...}  $config
     */
    public function __construct(
        private readonly RefreshTokenRepository $repository,
        private readonly Denylist $denylist,
        private readonly array $config,
    ) {}

    public function __invoke(string $familyId): void
    {
        // Denylist FIRST: if the second write fails, a leftover denylist entry is harmless, whereas a
        // DB revoke with no denylist entry would leave the family's access tokens live until expiry.
        $this->denylist->revokeFamily($familyId, $this->config['access_ttl'] + $this->config['leeway']);
        $this->repository->revokeFamily($familyId);
    }
}
