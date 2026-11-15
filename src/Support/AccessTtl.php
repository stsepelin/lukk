<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * `access_ttl` in whole seconds — read ONE way, by everything that reads it.
 *
 * It was read two ways. The issuer and the claim window took the default for a value that is no number
 * at all; the revoke actions cast it, and `(int) 'abc'` is 0. So for a per-guard
 * `'access_ttl' => env('LUKK_ADMIN_ACCESS_TTL')` set to `15m` — uncast, unlike the stock key, which the
 * config file casts itself — the issuer minted fifteen-minute tokens while "log out everywhere"
 * denylisted the family for the leeway alone, covered only by whatever `LongestAccessTtl` still
 * remembered in the same store.
 *
 * An integer whatever the config holds: a per-guard `env('…_ACCESS_TTL', 300)` is a STRING once the
 * variable is set. Something that is no number takes the default rather than 0, which would mint tokens
 * already expired.
 */
final class AccessTtl
{
    public const DEFAULT = 900;

    /**
     * @param  array<string, mixed>  $config
     */
    public static function seconds(array $config): int
    {
        $ttl = $config['access_ttl'] ?? null;

        return is_numeric($ttl) ? (int) $ttl : self::DEFAULT;
    }
}
