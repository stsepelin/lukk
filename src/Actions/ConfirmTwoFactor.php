<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\TwoFactorAuthenticatable;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Events\TwoFactorAuthenticationConfirmed;

/**
 * Activate 2FA only after the user proves a valid code from the scanned secret —
 * prevents self-lockout on a secret that was never captured.
 */
class ConfirmTwoFactor
{
    public function __construct(private readonly TwoFactorProvider $totp) {}

    /** @param  Authenticatable&TwoFactorAuthenticatable  $user */
    public function __invoke(Authenticatable $user, #[\SensitiveParameter] string $code): void
    {
        // Already on: nothing to confirm. Answering 204 overwrote `two_factor_confirmed_at` and fired
        // `TwoFactorAuthenticationConfirmed` again — a "new authenticator" notice for no change. 409, like
        // enrolment on an account that already has it.
        if (method_exists($user, 'hasEnabledTwoFactor') && $user->hasEnabledTwoFactor()) {
            throw ValidationException::withMessages([
                'code' => [__('Two-factor authentication is already enabled.')],
            ])->status(409);
        }

        // A pending secret this key cannot decrypt (APP_KEY rotated without `previous_keys`, a corrupt
        // row) is no secret, as `ChallengeTwoFactor::secretOf()` reads it: the ordinary 422, not a 500.
        try {
            $secret = $user->twoFactorSecret();
        } catch (\Throwable) {
            $secret = null;
        }

        // `''` as well as null — see `ChallengeTwoFactor`: an empty key reaches a permissive
        // custom provider and confirms enrolment from an arbitrary code.
        if ($secret === null || $secret === '' || ! $this->totp->verify($secret, $code)) {
            throw ValidationException::withMessages(['code' => [__('The provided two-factor code was invalid.')]]);
        }

        $user->forceFill(['two_factor_confirmed_at' => now()])->save();

        event(new TwoFactorAuthenticationConfirmed($user));
    }
}
