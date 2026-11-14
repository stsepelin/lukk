<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Lukk\Events\TwoFactorAuthenticationDisabled;

/**
 * Turn 2FA off: wipe the secret + recovery codes + confirmation.
 */
class DisableTwoFactor
{
    /**
     * @return bool whether a CONFIRMED second factor was removed. An enrolment backed out of before it was
     *              confirmed removes a secret too, but never an authenticator: no session was signed in with
     *              it and none carries `mfa` because of it, so nothing on another device needs ending.
     */
    public function __invoke(Authenticatable $user): bool
    {
        // Read the raw attribute: whether anything is bound is a fact about the row, and decrypting
        // the secret (`twoFactorSecret()`) can fail on a rotated key — which must not stop a disable.
        $hadSecret = ($user->getAttribute('two_factor_secret') ?? '') !== '';
        $wasConfirmed = $hadSecret && $user->getAttribute('two_factor_confirmed_at') !== null;

        $user->forceFill([
            'two_factor_secret' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
        ])->save();

        // Only when something was removed: "your two-factor authentication was turned off" is false
        // for an account that never had it.
        if ($hadSecret) {
            event(new TwoFactorAuthenticationDisabled($user));
        }

        return $wasConfirmed;
    }
}
