<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

/**
 * Reports two-factor as ENABLED while its secret cannot be read.
 *
 * This is the CONSUMER-OVERRIDE shape: an accessor that returns null rather than throwing. The
 * bundled trait cannot produce it — `Crypt::decryptString()` throws `DecryptException` on a stale
 * APP_KEY — so the throwing case is covered separately, against a real mis-encrypted column.
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
