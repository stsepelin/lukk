<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * The result of a login or refresh. `refreshToken` is the opaque plaintext
 * secret and exists only in transit — it is never persisted (only its hash is).
 */
class TokenPair
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $refreshToken,
        public readonly int $expiresIn,
        /**
         * When the refresh token's FAMILY expires (a unix timestamp) — absolute, fixed at sign-in and
         * inherited by every successor. Not serialised; it bounds the refresh cookie's lifetime, which
         * a rotation must not stretch past the point the server would accept it. Null for a pair built
         * by code that does not know it, which then gets the full `refresh_ttl`.
         */
        public readonly ?int $refreshExpiresAt = null,
    ) {}

    /**
     * @return array{access_token:string,refresh_token:string,token_type:string,expires_in:int}
     */
    public function toArray(): array
    {
        return [
            'access_token' => $this->accessToken,
            'refresh_token' => $this->refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => $this->expiresIn,
        ];
    }
}
