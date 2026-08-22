<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Lukk\Support\Abilities;
use Lukk\Support\TokenContext;

interface TokenIssuer
{
    /**
     * Mint an access token for the subject, family and guard in `$context`.
     *
     * A context object rather than positional arguments: subject + family + guard is already three,
     * and mint-time context grows (an impersonating actor is the next one). A new field goes into
     * `TokenContext` without changing this signature — which, unlike a closure a consumer wrote, is
     * a hard break for every custom issuer.
     *
     * @param  array<string,mixed>  $claims  Per-login claims (e.g. `amr`) merged in; cannot override standard claims.
     * @param  ?Abilities  $abilities  The grant to stamp as `scope`, already resolved by the calling
     *                                 Action. Null leaves the claim alone (abilities not in use).
     *                                 An implementation must not derive this itself — that is policy,
     *                                 and policy lives in the Actions.
     * @return array{token:string,jti:string,expires_in:int}
     */
    public function accessToken(TokenContext $context, array $claims = [], ?Abilities $abilities = null): array;

    public function newRefreshSecret(): string;

    public function hash(string $secret): string;
}
