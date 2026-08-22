<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Lukk\Actions\ConfirmTwoFactor;
use Lukk\Contracts\TwoFactorAuthenticatable;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;

/**
 * Confirms two-factor enrolment: `store` verifies the first TOTP code and
 * activates 2FA for the account. Sits behind step-up confirmation.
 */
class ConfirmedTwoFactorAuthenticationController
{
    use ResolvesAuthenticatedUser;

    public function __construct(
        private readonly ConfirmTwoFactor $confirm,
    ) {}

    public function store(Request $request): Response
    {
        /** @var Authenticatable&TwoFactorAuthenticatable $user */
        $user = $this->authenticated($request);

        ($this->confirm)($user, (string) $request->input('code'));

        return response()->noContent();
    }
}
