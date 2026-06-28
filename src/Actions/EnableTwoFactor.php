<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Crypt;
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
     * @return array{otpauth_uri:string,recovery_codes:array<int,string>}
     */
    public function __invoke(Authenticatable $user): array
    {
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
