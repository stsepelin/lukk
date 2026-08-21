<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Lukk\Support\Abilities;

interface TokenIssuer
{
    /**
     * Mint an access token.
     *
     * @param  array<string,mixed>  $claims  Per-login claims (e.g. `amr`) merged in; cannot override standard claims.
     * @param  ?Abilities  $abilities  The token's OWN grant (a personal access token, an
     *                                 impersonation cap), overriding whatever
     *                                 `Lukk::abilitiesUsing` would derive. Null derives.
     * @return array{token:string,jti:string,expires_in:int}
     */
    public function accessToken(int|string $userId, string $familyId, array $claims = [], ?Abilities $abilities = null): array;

    public function newRefreshSecret(): string;

    public function hash(string $secret): string;
}
