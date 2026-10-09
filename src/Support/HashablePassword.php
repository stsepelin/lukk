<?php

declare(strict_types=1);

namespace Lukk\Support;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Under bcrypt a password may be at most 72 BYTES: a rule for a new one, a check for a presented one.
 *
 * bcrypt reads only the first 72 bytes, so a longer password was stored truncated and every string
 * sharing that prefix then signed in — NIST SP 800-63B-4 §3.1.1.2 requires verifying the entire
 * password. With Laravel's own guard on (`hashing.bcrypt.limit`), `Hash::make` threw a 500 on public
 * routes instead. Other drivers have no such limit and pass untouched. Bytes, not characters: 36
 * two-byte characters already fill bcrypt's input.
 */
class HashablePassword
{
    /**
     * Would checking this password against this stored hash read only part of it?
     *
     * The verifying half of the same limit: a row written outside lukk (an import, a hasher with
     * `limit` off) may hold a longer password, and then every string sharing its first 72 bytes
     * verifies. Decided by the STORED hash, not the configured driver — an argon2id install can still
     * hold bcrypt rows. Call it after the check, so the derivation is paid either way.
     */
    public static function verifiesOnlyInPart(Authenticatable $user, mixed $password): bool
    {
        return is_string($password) && strlen($password) > 72
            && password_get_info((string) $user->getAuthPassword())['algo'] === PASSWORD_BCRYPT;
    }

    public static function rule(): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail): void {
            if (config('hashing.driver', 'bcrypt') === 'bcrypt' && is_string($value) && strlen($value) > 72) {
                $fail(__('The :attribute may not be longer than 72 bytes.'));
            }
        };
    }
}
