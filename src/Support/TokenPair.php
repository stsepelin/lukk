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
