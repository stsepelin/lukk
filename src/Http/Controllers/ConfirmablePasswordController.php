<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lukk\Actions\ConfirmPassword;
use Lukk\Auth\ChallengeToken;
use Lukk\Http\Concerns\IssuesConfirmationToken;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;

/**
 * Step-up ("sudo") confirmation by password: `store` re-verifies the user's
 * password and mints a short-lived `confirmation_token` that satisfies the
 * `lukk.confirm` gate for the configured window.
 */
class ConfirmablePasswordController
{
    use IssuesConfirmationToken;
    use ResolvesAuthenticatedUser;

    public function __construct(
        private readonly ConfirmPassword $confirmPassword,
        private readonly ChallengeToken $challengeTokens,
    ) {}

    public function store(Request $request): JsonResponse
    {
        ($this->confirmPassword)($this->authenticated($request), (string) $request->input('password'));

        // Bound to the session presenting it, so the confirmation cannot be replayed by another
        // token the same subject holds.
        return $this->confirmed($this->challengeTokens, $this->authenticated($request)->getAuthIdentifier(), $this->presentingFamily($request));
    }
}
