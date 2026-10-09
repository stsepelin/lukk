<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Contracts\Cache\Repository;
use Lukk\Lukk;

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
    public static function record(int $ttl): void
    {
        if ($ttl <= 0) {
            return;
        }

        $store = self::store();

        // Only a lifetime at least as long replaces the record, and it restarts the clock: the record
        // must outlive the newest token of the longest length.
        if ($ttl >= (int) $store->get(self::key(), 0)) {
            $store->put(self::key(), $ttl, $ttl);
        }
    }

    public static function current(): int
    {
        return (int) self::store()->get(self::key(), 0);
    }

    private static function store(): Repository
    {
        return cache()->store(Lukk::guardConfig()['denylist_store'] ?? null);
    }

    private static function key(): string
    {
        return 'lukk:longest-access-ttl:'.Lukk::currentGuard();
    }
}
