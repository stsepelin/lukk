<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\Request;
use Lukk\Actions\StartSession;
use Lukk\Actions\VerifyTwoFactorChallenge;
use Lukk\Contracts\LoginResponse;

/**
 * Completes a two-factor login: `store` exchanges the challenge token plus a TOTP
 * or recovery code for a full token pair (`amr: ["pwd","otp"]`).
 */
class TwoFactorChallengedSessionController
{
    public function __construct(
        private readonly VerifyTwoFactorChallenge $verifyChallenge,
        private readonly StartSession $start,
    ) {}

    public function store(Request $request): LoginResponse
    {
        $user = ($this->verifyChallenge)(
            (string) $request->input('challenge_token'),
            $request->input('code'),
            $request->input('recovery_code'),
        );

        return app(LoginResponse::class, ['pair' => ($this->start)($user->getAuthIdentifier(), ['amr' => ['pwd', 'otp']])]);
    }
}
