<?php

declare(strict_types=1);

namespace Lukk\Http\Responses;

use Illuminate\Http\JsonResponse;
use Lukk\Contracts\RefreshResponse as RefreshResponseContract;
use Lukk\Http\Responses\Concerns\EmitsTokens;
use Lukk\Support\TokenPair;

class RefreshResponse implements RefreshResponseContract
{
    use EmitsTokens;

    public function __construct(private readonly TokenPair $pair) {}

    public function toResponse($request): JsonResponse
    {
        return $this->tokenResponse($this->pair);
    }
}
