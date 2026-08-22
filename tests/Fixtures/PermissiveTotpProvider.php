<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Lukk\Contracts\TwoFactorProvider;

/**
 * A `TwoFactorProvider` that treats an EMPTY secret as "not configured, allow".
 *
 * Not a strawman: the bundled provider throws `SecretKeyTooShortException` on `''`, which is the
 * only reason an empty secret was never exploitable in-tree. `TwoFactorProvider` is a documented
 * swap seam, so lukk must not rely on the bundled implementation's strictness for a security
 * property. This models the permissive half of that seam.
 */
class PermissiveTotpProvider implements TwoFactorProvider
{
    public function generateSecret(): string
    {
        return '';
    }

    public function verify(string $secret, string $code): bool
    {
        return $secret === '' || $secret === $code;
    }

    public function otpauthUri(string $holder, string $secret): string
    {
        return 'otpauth://totp/'.$holder.'?secret='.$secret;
    }
}
