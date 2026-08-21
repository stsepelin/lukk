<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Support\Str;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Support\Abilities;
use Lukk\Support\TokenPair;

/**
 * Begin a session at login: a new family + first refresh token + access token.
 */
class StartSession
{
    /**
     * @param  array{refresh_ttl:int,...}  $config
     */
    public function __construct(
        private readonly RefreshTokenRepository $repository,
        private readonly TokenIssuer $issuer,
        private readonly array $config,
    ) {}

    /**
     * @param  array<string,mixed>  $claims  Per-login claims for the access token (e.g. `amr`).
     */
    /**
     * @param  ?array<int, string>  $abilities  The session's OWN abilities, pinned for its lifetime.
     *                                          Null derives them from `Lukk::abilitiesUsing` on
     *                                          every mint, so a revoked ability takes effect within
     *                                          `access_ttl`. Pass a value when the TOKEN owns the
     *                                          grant rather than the user — a personal access
     *                                          token, or an impersonation session capped below what
     *                                          the target user can do.
     */
    public function __invoke(int|string $userId, array $claims = [], ?array $abilities = null): TokenPair
    {
        $familyId = (string) Str::uuid();
        $secret = $this->issuer->newRefreshSecret();
        $expiresAt = now()->getTimestamp() + $this->config['refresh_ttl'];
        $granted = $abilities === null ? null : Abilities::fromArray($abilities);

        $this->repository->persist($userId, $familyId, null, $this->issuer->hash($secret), $expiresAt, $granted?->toScope());

        $access = $this->issuer->accessToken($userId, $familyId, $claims, $granted);

        return new TokenPair($access['token'], $secret, $access['expires_in']);
    }
}
