<?php

declare(strict_types=1);

namespace Lukk\Support;

use Closure;

/**
 * A validation rule: under bcrypt, a new password may be at most 72 BYTES.
 *
 * bcrypt reads only the first 72 bytes, so a longer password was stored truncated and every string
 * sharing that prefix then signed in — NIST SP 800-63B-4 §3.1.1.2 requires verifying the entire
 * password. With Laravel's own guard on (`hashing.bcrypt.limit`), `Hash::make` threw a 500 on public
 * routes instead. Other drivers have no such limit and pass untouched. Bytes, not characters: 36
 * two-byte characters already fill bcrypt's input.
 */
class HashablePassword
{
    public static function rule(): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail): void {
            if (config('hashing.driver', 'bcrypt') === 'bcrypt' && is_string($value) && strlen($value) > 72) {
                $fail(__('The :attribute may not be longer than 72 bytes.'));
            }
        };
    }
}
