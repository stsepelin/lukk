<?php

declare(strict_types=1);

namespace Lukk\Contracts;

interface TokenIssuer
{
    /**
     * @param  array<string,mixed>  $claims  Per-login claims (e.g. `amr`) merged in; cannot override standard claims.
     * @return array{token:string,jti:string,expires_in:int}
     */
    public function accessToken(int|string $userId, string $familyId, array $claims = []): array;

    public function newRefreshSecret(): string;

    public function hash(string $secret): string;
}
