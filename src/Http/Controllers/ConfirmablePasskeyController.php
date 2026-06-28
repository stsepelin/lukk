<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\FinishPasskeyLogin;
use Lukk\Auth\ChallengeToken;
use Lukk\Http\Concerns\IssuesConfirmationToken;

/**
 * Step-up ("sudo") confirmation by passkey: `store` verifies a passkey assertion
 * belonging to the current user and mints the same `confirmation_token` as the
 * password path. FinishPasskeyLogin is method-injected so the password path never
 * pulls in the optional WebAuthn ceremony.
 */
class ConfirmablePasskeyController
{
    use IssuesConfirmationToken;

    public function __construct(
        private readonly ChallengeToken $challengeTokens,
    ) {}

    public function store(Request $request, FinishPasskeyLogin $finishPasskeyLogin): JsonResponse
    {
        $request->validate(['ceremony_id' => ['required', 'string'], 'credential' => ['required', 'array']]);

        $userId = $finishPasskeyLogin((string) $request->input('ceremony_id'), $request->array('credential'));

        if ((string) $userId !== (string) $request->user()->getAuthIdentifier()) {
            throw ValidationException::withMessages(['credential' => [__('That passkey does not belong to you.')]]);
        }

        return $this->confirmed($this->challengeTokens, $userId);
    }
}
