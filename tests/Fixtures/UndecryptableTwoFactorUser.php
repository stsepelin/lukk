<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

/**
 * Reports two-factor as ENABLED while its secret cannot be read.
 *
 * The realistic shape is an `APP_KEY` rotation: the encrypted column is still populated, so an
 * app-level `hasEnabledTwoFactor()` says yes, but decryption fails and the accessor returns null.
 * A cast of that null to `''` would hand an empty secret to the TOTP provider.
 */
class UndecryptableTwoFactorUser extends User
{
    protected $table = 'users';

    public function hasEnabledTwoFactor(): bool
    {
        return true;
    }

    public function twoFactorSecret(): ?string
    {
        return null;
    }
}
