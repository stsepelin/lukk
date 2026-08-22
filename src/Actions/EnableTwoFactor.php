<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\TwoFactorAuthenticatable;
use Lukk\Contracts\TwoFactorProvider;

/**
 * Begin 2FA enrolment: store an encrypted secret + hashed recovery codes (NOT yet
 * confirmed) and return the provisioning URI + the plaintext codes ONCE.
 */
class EnableTwoFactor
{
    public function __construct(
        private readonly TwoFactorProvider $totp,
        private readonly int $recoveryCodes,
    ) {}

    /**
     * @param  Authenticatable&TwoFactorAuthenticatable  $user
     * @return array{otpauth_uri: string, recovery_codes: array<int, string>}
     */
    public function __invoke(Authenticatable $user): array
    {
        // Re-enrolling used to overwrite the secret, null `two_factor_confirmed_at` and regenerate
        // the recovery codes — so a user who reopened the QR screen out of curiosity and wandered
        // off was left with 2FA silently OFF. `hasEnabledTwoFactor()` returns false immediately, so
        // login stops challenging, and unlike `DELETE /auth/two-factor` there is nothing an app can
        // hang a "your second factor was removed" notification on. Refuse instead: disabling should
        // be explicit, and the endpoint that does it already exists.
        if (method_exists($user, 'hasEnabledTwoFactor') && $user->hasEnabledTwoFactor()) {
            throw ValidationException::withMessages([
                'two_factor' => [__('Two-factor authentication is already enabled. Disable it first to enrol again.')],
            ])->status(409);
        }

        $secret = $this->totp->generateSecret();

        $user->forceFill([
            'two_factor_secret' => Crypt::encryptString($secret),
            'two_factor_confirmed_at' => null,
        ])->save();

        return [
            'otpauth_uri' => $this->totp->otpauthUri($this->holder($user), $secret),
            'recovery_codes' => $user->generateRecoveryCodes($this->recoveryCodes),
        ];
    }

    private function holder(Authenticatable $user): string
    {
        return $user->email ?? (string) $user->getAuthIdentifier();
    }
}
