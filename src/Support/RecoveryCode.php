<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Support\Str;

/**
 * A single recovery code: two 10-char halves (~120 bits). Generated in plaintext,
 * shown once, and stored only as a hash.
 */
class RecoveryCode
{
    public static function generate(): string
    {
        return Str::random(10).'-'.Str::random(10);
    }
}
