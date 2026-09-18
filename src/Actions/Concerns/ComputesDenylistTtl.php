<?php

declare(strict_types=1);

namespace Lukk\Actions\Concerns;

/**
 * How long a revoked family's denylist entry must live — past the last access token that family can
 * still present.
 *
 * Both defaults are load-bearing, not decoration. No `lukk` key is guaranteed at runtime: a config
 * cached before a key existed gets no backfill (`mergeConfigDeep` early-returns), and the merge
 * backfills on `array_key_exists`, so an explicitly null value — a per-guard
 * `'access_ttl' => env('LUKK_ADMIN_ACCESS_TTL')` with the variable unset — survives it too.
 * Unguarded, the two missing reads add to 0, and `Cache::put()` with a non-positive TTL FORGETS the
 * key instead of writing it: the revoke would denylist nothing at all while answering as if it had.
 *
 * Shared by the three revoke actions rather than written out in each, because it once WAS written
 * out in each: the guarded read reached one of the three, and the two it missed were logout-all and
 * logout-others — the "sign me out everywhere" button, where denylisting nothing is worst.
 */
trait ComputesDenylistTtl
{
    /**
     * @param  array<string, mixed>  $config
     */
    private function denylistTtl(array $config): int
    {
        return (int) ($config['access_ttl'] ?? 900) + (int) ($config['leeway'] ?? 5);
    }
}
