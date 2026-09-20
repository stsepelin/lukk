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

        // Typed before the cast, like every other OTP entry point. This was the one that wasn't: a
        // non-scalar `code` raised an ErrorException on `(string) $array` — a 500 where its sibling
        // `POST /auth/two-factor-challenge` correctly answers 422 for the identical payload.
        $validated = $request->validate(['code' => ['required', 'string']]);

        ($this->confirm)($user, $validated['code']);

        return response()->noContent();
    }
}
