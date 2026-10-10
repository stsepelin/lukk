<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\TwoFactorAuthenticatable;
use Lukk\Events\RecoveryCodesGenerated;

/**
 * Replace the user's recovery codes with a fresh set; returns the plaintext once.
 */
class RegenerateRecoveryCodes
{
    public function __construct(private readonly int $recoveryCodes) {}

    /**
     * @param  Authenticatable&TwoFactorAuthenticatable  $user
     * @return array<int, string>
     */
    public function __invoke(Authenticatable $user): array
    {
        // Only where two-factor is on or being enrolled: on any other account the set is codes nothing
        // ever asks for, announced as a new authenticator the account does not have. 409, like enabling
        // two-factor twice.
        if (! $this->hasTwoFactor($user)) {
            throw ValidationException::withMessages([
                'two_factor' => [__('Two-factor authentication is not enabled.')],
            ])->status(409);
        }

        $codes = $user->generateRecoveryCodes($this->recoveryCodes);

        event(new RecoveryCodesGenerated($user));

        return $codes;
    }

    /**
     * Confirmed, or pending — a secret stored by enrolment and not yet confirmed.
     *
     * @param  Authenticatable&TwoFactorAuthenticatable  $user
     */
    private function hasTwoFactor(Authenticatable $user): bool
    {
        if ($user->hasEnabledTwoFactor()) {
            return true;
        }

        // A pending secret this key cannot decrypt (APP_KEY rotated without `previous_keys`, a corrupt row)
        // can never be confirmed, so codes for it are as dead as on an account with none — and reading it
        // must not 500. The user disables two-factor and enrols again.
        try {
            return $user->twoFactorSecret() !== null;
        } catch (\Throwable) {
            return false;
        }
    }
}
