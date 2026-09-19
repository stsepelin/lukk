<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Which password a credential check was made against — so a session can be refused if that password was
 * replaced while it was being started.
 *
 * An HMAC of the stored hash, keyed with the application key: it changes whenever the password does, and
 * it rides inside a two-factor challenge token that the client can read, which must never carry the hash
 * itself. A user with no password fingerprints the empty string.
 */
class PasswordFingerprint
{
    public static function of(Authenticatable $user): string
    {
        return self::under((string) config('app.key'), $user);
    }

    /**
     * Whether `$fingerprint` names `$user`'s current password — under the current key or any of
     * `app.previous_keys`, so rotating APP_KEY the documented way does not refuse every two-factor
     * challenge already in flight.
     */
    public static function matches(string $fingerprint, Authenticatable $user): bool
    {
        foreach ([(string) config('app.key'), ...array_map('strval', (array) config('app.previous_keys'))] as $key) {
            if (hash_equals($fingerprint, self::under($key, $user))) {
                return true;
            }
        }

        return false;
    }

    private static function under(string $key, Authenticatable $user): string
    {
        return hash_hmac('sha256', (string) $user->getAuthPassword(), $key);
    }
}
