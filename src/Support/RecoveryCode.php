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
    /** The most codes one set may hold; a set always holds at least one. */
    public const MAX_SET = 100;

    public static function generate(): string
    {
        return Str::random(10).'-'.Str::random(10);
    }

    /**
     * How many codes a set of `$configured` really holds: clamped to 1..100, as generation clamps it.
     * One home for the clamp, so what is reported (`GET two-factor/recovery-codes`) is what is issued.
     */
    public static function setSize(int $configured): int
    {
        return max(1, min(self::MAX_SET, $configured));
    }
}
