<?php

declare(strict_types=1);

namespace Lukk\Http\Responses;

use Illuminate\Http\JsonResponse;
use Lukk\Contracts\TwoFactorChallengeResponse as TwoFactorChallengeResponseContract;
use Lukk\Http\Concerns\PreventsCaching;

class TwoFactorChallengeResponse implements TwoFactorChallengeResponseContract
{
    use PreventsCaching;

    public function __construct(private readonly string $challenge) {}

    public function toResponse($request): JsonResponse
    {
        return $this->noStore(response()->json([
            'two_factor' => true,
            'challenge_token' => $this->challenge,
        ]));
    }
}
