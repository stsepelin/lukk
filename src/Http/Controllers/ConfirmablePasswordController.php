<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lukk\Actions\ConfirmPassword;
use Lukk\Auth\ChallengeToken;
use Lukk\Http\Concerns\IssuesConfirmationToken;

/**
 * Step-up ("sudo") confirmation by password: `store` re-verifies the user's
 * password and mints a short-lived `confirmation_token` that satisfies the
 * `lukk.confirm` gate for the configured window.
 */
class ConfirmablePasswordController
{
    use IssuesConfirmationToken;

    public function __construct(
        private readonly ConfirmPassword $confirmPassword,
        private readonly ChallengeToken $challengeTokens,
    ) {}

    public function store(Request $request): JsonResponse
    {
        ($this->confirmPassword)($request->user(), (string) $request->input('password'));

        return $this->confirmed($this->challengeTokens, $request->user()->getAuthIdentifier());
    }
}
