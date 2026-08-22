<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Lukk\Contracts\TwoFactorAuthenticatable;

/**
 * Replace the user's recovery codes with a fresh set; returns the plaintext once.
 */
class RegenerateRecoveryCodes
{
    public function __construct(private readonly int $recoveryCodes) {}

    /**
     * @return array<int,string>
     */
    /** @param  Authenticatable&TwoFactorAuthenticatable  $user */
    public function __invoke(Authenticatable $user): array
    {
        return $user->generateRecoveryCodes($this->recoveryCodes);
    }
}
