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
    use ResolvesPresentingFamily;

    private function confirmed(ChallengeToken $challengeTokens, int|string $userId, ?string $familyId = null): JsonResponse
    {
        return $this->noStore(response()->json([
            'confirmation_token' => $challengeTokens->issue(
                'reauth',
                $userId,
                // Not `config($key, 300)`: that default only applies to an ABSENT key, and a TTL
                // of 0 makes the step-up token expired the moment it is minted.
                (int) (config('lukk.confirm.ttl') ?? 300),
                $familyId,
            ),
        ]));
    }
}
