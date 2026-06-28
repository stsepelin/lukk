<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Support\Str;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
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
    public function __invoke(int|string $userId, array $claims = []): TokenPair
    {
        $familyId = (string) Str::uuid();
        $secret = $this->issuer->newRefreshSecret();
        $expiresAt = now()->getTimestamp() + $this->config['refresh_ttl'];

        $this->repository->persist($userId, $familyId, null, $this->issuer->hash($secret), $expiresAt);

        $access = $this->issuer->accessToken($userId, $familyId, $claims);

        return new TokenPair($access['token'], $secret, $access['expires_in']);
    }
}
