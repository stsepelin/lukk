<?php

declare(strict_types=1);

namespace Lukk\Actions\Concerns;

use Lukk\Support\LongestAccessTtl;
use Lukk\Support\VerifiedToken;

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
        // The configured lifetime, or the longest one minted that may still be alive if that is longer —
        // `access_ttl` lowered since (see `LongestAccessTtl`).
        $configured = max((int) ($config['access_ttl'] ?? 900), LongestAccessTtl::current()) + (int) ($config['leeway'] ?? 5);

        // The configured window is only exact while every access token's `exp` really is
        // `iat + lukk.access_ttl`. Two ordinary things break that, and both under-cover the revoke:
        //
        //  - `access_ttl` LOWERED between mint and revoke. Cutting it from 3600 to 300 in response to
        //    a suspected leak, then forcing a logout, wrote a 305s entry while the leaked token stayed
        //    valid for another ~55 minutes: it started working again mid-incident.
        //  - a rebound `TokenIssuer`, which owns `exp` outright and is told nothing about
        //    `access_ttl`. Every revocation under-covers, permanently and silently.
        //
        // So take the longer of the configured window and the one the caller's OWN token proves this
        // deployment mints. `EndSession` already derives its per-jti TTL from `exp` this way; family
        // revokes had no token to read until `VerifiedToken` put the verified claims on the request.
        return max($configured, $this->presentedTokenTtl($config));
    }

    /**
     * The remaining life of the access token authenticating this request, plus leeway — or 0 when
     * there is none (a console command, a queued job, a revoke triggered by a refresh rather than a
     * bearer).
     *
     * Best effort by construction: it bounds the revoke from BELOW, so being wrong costs a denylist
     * entry that expires too early only in the case it already did. It reads the token this caller
     * presented, which is representative wherever the issuer mints one lifetime for everyone; a
     * deployment whose tokens vary in length still needs `lukk.access_ttl` set to the longest.
     *
     * @param  array<string, mixed>  $config
     */
    private function presentedTokenTtl(array $config): int
    {
        try {
            $token = VerifiedToken::current(app('request'));
        } catch (\Throwable) {
            // No request bound at all (console, queue). Nothing to learn; the configured window stands.
            return 0;
        }

        // `?? null` already absorbs a missing token; the `?->` states that it may be one.
        $exp = $token?->claims->exp ?? null; // @pest-mutate-ignore: RemoveNullSafeOperator

        // A shortcut: with no numeric `exp` the arithmetic below casts null to 0 and `max(0, …)` answers 0 anyway.
        if (! is_numeric($exp)) {
            // Any value at or below the configured window is equivalent: the caller takes the larger.
            return 0; // @pest-mutate-ignore: RemoveEarlyReturn,DecrementInteger,IncrementInteger
        }

        // `exp` is an int on every verified token and `leeway` an int in config; the casts state the types.
        // No clamp at 0: a verified token has life left, and the caller takes the larger of this and the window.
        return (int) $exp - now()->getTimestamp() + (int) ($config['leeway'] ?? 5); // @pest-mutate-ignore: RemoveIntegerCast
    }
}
