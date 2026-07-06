<?php

declare(strict_types=1);

namespace Lukk\Http\Responses;

use Illuminate\Http\JsonResponse;
use Lukk\Contracts\RegisterResponse as RegisterResponseContract;
use Lukk\Http\Responses\Concerns\EmitsTokens;
use Lukk\Support\TokenPair;

class RegisterResponse implements RegisterResponseContract
{
    use EmitsTokens;

    public function __construct(
        private readonly ?TokenPair $pair,
        private readonly bool $requiresVerification = false,
    ) {}

    public function toResponse($request): JsonResponse
    {
        // No session (register-only, or block_unverified_login): no tokens, just a documented
        // shape — `requires_verification` tells the client "verify your email" vs. "please log in".
        if ($this->pair === null) {
            return $this->noStore(response()->json([
                'registered' => true,
                'requires_verification' => $this->requiresVerification,
            ], 201));
        }

        // Same token-pair body as login, so the client treats register exactly like a login.
        return $this->tokenResponse($this->pair);
    }
}
