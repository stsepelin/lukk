<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Lukk\Actions\Concerns\ComputesDenylistTtl;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Lukk;

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
        /** Captured with the config, so a revoke run outside the guard it was built for still covers its tokens. */
        private readonly string $guard = 'api',
    ) {}

    /**
     * @param  object|null  $presented  The verified claims of the token that ASKED — `DELETE
     *                                  /auth/sessions` passes its bearer's, so a token naming no family of
     *                                  lukk's (a co-issuer's) is ended too. Null for the internal callers
     *                                  (password change and reset, erasure), which present nothing.
     */
    public function __invoke(int|string $userId, ?object $presented = null): void
    {
        $ttl = $this->denylistTtl($this->config, $this->guard);

        // Denylisted inside the repository's transaction and BEFORE the rows are revoked — see
        // `RevokeSession` for why that direction is the safe one to fail in.
        $revoked = $this->repository->revokeUserFamilies($userId, fn (array $ids) => array_map(
            fn (string $familyId) => $this->denylist->revokeFamily($familyId, $ttl), $ids,
        ));

        if ($presented !== null) {
            $this->endPresented($presented, $revoked, $ttl);
        }
    }

    /**
     * "Log out everywhere" includes the token that asked (RFC 7009 §2.1: once revoked, unusable).
     *
     * A co-issuer's token names no family in lukk's table — no `fid`, or one lukk never minted — so the
     * sweep above did not reach it, and it stayed live until it expired while `POST /auth/logout` with
     * the same token ended it. Ended the way logout ends it (`EndSession::endBearerSession()`): its
     * family on the denylist when it names one, otherwise its `jti` for the rest of its life.
     *
     * @param  array<int, string>  $revoked
     */
    private function endPresented(object $presented, array $revoked, int $ttl): void
    {
        $familyId = (string) ($presented->fid ?? '');

        if ($familyId !== '') {
            // Already covered when it is one of the account's own families.
            if (! in_array($familyId, $revoked, true)) {
                $this->denylist->revokeFamily($familyId, $ttl);
            }

            return;
        }

        $jti = (string) ($presented->jti ?? '');

        if ($jti === '' || ! is_numeric($presented->exp ?? null)) {
            return;
        }

        // The verifier's leeway (clamped 0..300), so the entry outlives the token, as logout's does.
        $this->denylist->revokeJti($jti, max(1, (int) $presented->exp - now()->getTimestamp() + Lukk::leeway($this->config)));
    }
}
