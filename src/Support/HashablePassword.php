<?php

declare(strict_types=1);

namespace Lukk\Support;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;

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
    public static function verifiesOnlyInPart(Authenticatable $user, #[\SensitiveParameter] mixed $password): bool
    {
        // By prefix, not `password_get_info()`: that names only `$2y$`, while `password_verify` accepts
        // and truncates `$2a$`/`$2b$`/`$2x$` too — the very hashes an import from Node, Python or Ruby
        // brings, behind `hashing.bcrypt.verify` turned off.
        return is_string($password) && strlen($password) > 72
            && preg_match('/\A\$2[abxy]\$/', (string) $user->getAuthPassword()) === 1;
    }

    /**
     * The answer for a password that matched only in part.
     *
     * Not "incorrect": every released lukk before this one stored such a password truncated, so its
     * owner is typing the right one, and a generic refusal would only spend their lockout attempts.
     * It reveals nothing new — only a caller whose first 72 bytes already match reaches it, and the
     * old code signed that caller straight in.
     */
    public static function mustReset(string $field): ValidationException
    {
        return ValidationException::withMessages([$field => [__('This password is longer than 72 bytes, which can no longer be checked in full. Reset your password to continue.')]]);
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
