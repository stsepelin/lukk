<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\TwoFactorProvider;

/**
 * Activate 2FA only after the user proves a valid code from the scanned secret —
 * prevents self-lockout on a secret that was never captured.
 */
class ConfirmTwoFactor
{
    public function __construct(private readonly TwoFactorProvider $totp) {}

    public function __invoke(Authenticatable $user, string $code): void
    {
        $secret = $user->twoFactorSecret();

        if ($secret === null || ! $this->totp->verify($secret, $code)) {
            throw ValidationException::withMessages(['code' => [__('The provided two-factor code was invalid.')]]);
        }

        $user->forceFill(['two_factor_confirmed_at' => now()])->save();
    }
}
