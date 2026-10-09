<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;

/**
 * The longest access-token lifetime this guard has minted, for as long as a token of that length can
 * still be alive.
 *
 * Revocation denylists a family or token for `access_ttl + leeway`. After `access_ttl` is LOWERED — the
 * usual incident response — tokens minted under the old value outlived that entry and verified again
 * (RFC 7009 §2.2). Every mint records its lifetime here, kept exactly as long as that lifetime, so a
 * revoke covers the longest token that can still exist and forgets it once none can. Kept in the
 * denylist store, so every instance sees it.
 */
class LongestAccessTtl
{
    /**
     * Record one mint's lifetime. ONE write, and never a read-modify-write of a shared maximum: a key per
     * lifetime, living exactly as long as that lifetime. A shared "longest so far" read then written lost
     * a concurrent longer value — in a rolling deploy lowering `access_ttl`, the very case this exists
     * for. The small index of lifetimes seen is touched only when a new value appears, under a lock where
     * the store has one.
     */
    public static function record(int $ttl, string $guard, ?string $store = null): void
    {
        if ($ttl <= 0) {
            return;
        }

        $cache = cache()->store($store);
        $cache->put(self::key($guard, $ttl), true, $ttl);

        if (in_array($ttl, self::index($cache, $guard), true)) {
            return;
        }

        $add = fn () => $cache->forever(self::indexKey($guard), array_values(array_unique([...self::index($cache, $guard), $ttl])));
        $lockable = $cache->getStore();

        $lockable instanceof LockProvider
            ? $lockable->lock(self::indexKey($guard).':lock', 5)->block(5, $add)
            : $add();
    }

    /** The longest lifetime minted on this guard of which a token may still be alive, or 0. */
    public static function current(string $guard, ?string $store = null): int
    {
        $cache = cache()->store($store);

        return array_reduce(
            self::index($cache, $guard),
            fn (int $longest, int $ttl) => $ttl > $longest && $cache->has(self::key($guard, $ttl)) ? $ttl : $longest,
            0,
        );
    }

    /** @return list<int> */
    private static function index(Repository $cache, string $guard): array
    {
        $index = $cache->get(self::indexKey($guard), []);

        // Integers only: a store that hands values back as strings (Redis) or a hand-edited entry.
        return is_array($index) ? array_values(array_map('intval', array_filter($index, 'is_numeric'))) : [];
    }

    private static function key(string $guard, int $ttl): string
    {
        return 'lukk:access-ttl:'.$guard.':'.$ttl;
    }

    private static function indexKey(string $guard): string
    {
        return 'lukk:access-ttls:'.$guard;
    }
}
