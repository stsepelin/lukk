<?php

declare(strict_types=1);

namespace Lukk\Support;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
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

    /**
     * A password as it is HASHED: Unicode-normalized to NFKC.
     *
     * NIST SP 800-63B-4 §3.1.1.2: a verifier accepting Unicode "SHOULD apply the normalization process
     * for stabilized strings using either the NFKC or NFKD normalization". The same text reaches a server
     * as different bytes depending on the keyboard and the platform — `é` as one code point or as `e` plus
     * a combining accent, a full-width digit from an IME — and hashed as typed, a password set on one
     * device was "incorrect" on another.
     *
     * Bytes that are not valid UTF-8 have no normal form and are hashed as they are; so is everything
     * where PHP has no `Normalizer` (neither `ext-intl` nor Symfony's polyfill, which a Laravel
     * application always carries).
     */
    public static function normalize(#[\SensitiveParameter] string $password): string
    {
        $normalized = class_exists(\Normalizer::class) ? \Normalizer::normalize($password, \Normalizer::FORM_KC) : false; // @pest-mutate-ignore: FalseToTrue

        return is_string($normalized) ? $normalized : $password;
    }

    /**
     * The spellings to try a presented password under: as typed, then normalized when that differs.
     *
     * As typed FIRST, and always: every hash stored before normalization was made from the bytes its
     * owner typed, so checking only the normal form would lock out each of them whose password is not
     * already in it. One entry for a password already in normal form — nearly all of them — so the common
     * case costs exactly what it did.
     *
     * @return list<string>
     */
    public static function spellings(#[\SensitiveParameter] string $password): array
    {
        // `array_unique` can only drop the second entry, so the result is a list either way.
        return array_values(array_unique([$password, self::normalize($password)])); // @pest-mutate-ignore: UnwrapArrayValues
    }

    /**
     * Check a presented password under each of its spellings; the one that verified, or null.
     *
     * Each check is wrapped as sign-in always wrapped its one: a stored hash the active hasher refuses
     * (another algorithm, a `$2b$` import with `hashing.bcrypt.verify` on) makes the check THROW, and
     * that is a credential nobody can present — it fails closed, not as a 500.
     *
     * @param  array<string, mixed>  $credentials  as the provider takes them; `password` is replaced per spelling
     */
    public static function verified(UserProvider $users, Authenticatable $user, #[\SensitiveParameter] array $credentials): ?string
    {
        foreach (self::spellings((string) ($credentials['password'] ?? '')) as $spelling) {
            try {
                if ($users->validateCredentials($user, ['password' => $spelling] + $credentials)) {
                    return $spelling;
                }
            } catch (\Throwable) {
                // Fails closed; the next spelling may still be one this hash can check.
            }
        }

        return null;
    }

    public static function rule(): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail): void {
            // Measured as it will be hashed: normalization can lengthen a password (`㈱` becomes `(株)`).
            if (config('hashing.driver', 'bcrypt') === 'bcrypt' && is_string($value) && strlen(self::normalize($value)) > 72) {
                $fail(__('The :attribute may not be longer than 72 bytes.'));
            }
        };
    }
}
