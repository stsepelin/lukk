<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Lukk\Actions\ConfirmTwoFactor;

/**
 * Confirms two-factor enrolment: `store` verifies the first TOTP code and
 * activates 2FA for the account. Sits behind step-up confirmation.
 */
class ConfirmedTwoFactorAuthenticationController
{
    public function __construct(
        private readonly ConfirmTwoFactor $confirm,
    ) {}

    public function store(Request $request): Response
    {
        ($this->confirm)($request->user(), (string) $request->input('code'));

        return response()->noContent();
    }
}
