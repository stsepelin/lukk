<?php

declare(strict_types=1);

namespace Lukk\Http\Concerns;

use Illuminate\Http\JsonResponse;
use Lukk\Auth\ChallengeToken;

/**
 * Shared by the step-up confirmation controllers: both the password and passkey
 * earners mint the same short-lived `reauth` token once a credential re-verifies.
 */
trait IssuesConfirmationToken
{
    use PreventsCaching;

    private function confirmed(ChallengeToken $challengeTokens, int|string $userId): JsonResponse
    {
        return $this->noStore(response()->json([
            'confirmation_token' => $challengeTokens->issue('reauth', $userId, (int) config('lukk.confirm.ttl', 300)),
        ]));
    }
}
