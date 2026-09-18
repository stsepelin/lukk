<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Contracts\TokenVerifier;
use Lukk\Events\RefreshTokenReused;
use Lukk\Lukk;
use Lukk\Support\RefreshTokenRecord;

/**
 * Log out: end the session named by EITHER credential the client holds.
 *
 * Logout used to require a valid access token, so the most ordinary client state there is — an idle
 * tab whose 15-minute token has lapsed — could not end its session: a 401, nothing revoked, and in
 * cookie mode a refresh cookie left valid for its whole TTL. RFC 7009 §2.1–2.2 lets a client revoke
 * with the refresh token it holds, and ASVS 5.0 V7.4.1 wants logout to actually invalidate the
 * session, so the refresh token is now accepted as well.
 *
 * Which refresh tokens the REQUEST may present (the CSRF question) is decided by the HTTP layer; this
 * action trusts the list it is handed. It never throws for a credential that does not resolve, and
 * reports nothing about what it found: the response is the same 204 whether a token existed, was
 * already revoked, or was never real. The one exception is a caller whose UNPRODUCTIVE lookups — a
 * miss, or a family already revoked — have exhausted the lookup budget, refused with a 429 BEFORE
 * anything is looked up; see `refuseWhenExhausted()`.
 */
class EndSession
{
    /**
     * @param  array<string, mixed>  $config  the guard's resolved config
     */
    public function __construct(
        private readonly TokenVerifier $verifier,
        private readonly TokenIssuer $issuer,
        private readonly RefreshTokenRepository $repository,
        private readonly RevokeSession $revokeSession,
        private readonly Denylist $denylist,
        private readonly RateLimiter $limiter,
        private readonly array $config,
        private readonly string $guard = 'api',
    ) {}

    /**
     * @param  array<int, string>  $refreshTokens  the refresh tokens this request may present
     * @param  string  $caller  the caller's throttle identity ({@see Lukk::rateLimitKey()})
     *
     * @throws ThrottleRequestsException when this caller's unproductive lookups have exhausted the
     *                                   budget — nothing has been looked up, and the caller must
     *                                   retry rather than believe it logged out
     */
    public function __invoke(string $bearer, array $refreshTokens, string $caller): void
    {
        // The bearer first, and never metered: a logout named by a valid access token must not be
        // refused because someone else on the same address spent a budget.
        $bearerSpent = $this->endBearerSession($bearer);

        if ($refreshTokens === []) {
            return;
        }

        // Metered only WITHOUT a spent bearer. A valid bearer is revoked (or denylisted) by this very
        // call, so it buys exactly one batch of lookups and cannot be replayed for more — each such
        // batch costs the caller a live session, which only the throttled login mints. Metering it
        // anyway let ordinary BFF logouts (bearer + refresh token) from one address exhaust the bucket
        // for everyone behind it. It still looks up a DIFFERENT family's token: a browser holding an
        // access token from one login and a cookie from a later one means both when it logs out.
        $metered = ! $bearerSpent;

        if ($metered) {
            $this->refuseWhenExhausted($caller);
        }

        foreach ($refreshTokens as $presented) {
            $record = $this->repository->findByHash($this->issuer->hash($presented));

            // An already-revoked family costs the budget like a miss, and does no work. Revoking it
            // again wrote the denylist and ran UPDATEs on every request, so one known token — even a
            // long-dead one — was an unmetered write amplifier for an unauthenticated caller. A
            // legitimate resent logout is a single request.
            if ($record === null || $record->revokedAt !== null) {
                if ($metered) {
                    $this->countMiss($caller);
                }

                continue;
            }

            $this->endRefreshSession($record);
        }
    }

    /**
     * The session of a VALID access token — signature, pinned alg, `iss`, `aud`, `exp`/`nbf`, `typ`
     * and the denylist, exactly as the guard checks it.
     *
     * An expired token is deliberately NOT honoured here, not even with a good signature. Its
     * signature proves only that it was issued once; accepting it would make every access token that
     * ever reached a log, a crash report or a browser history a durable capability to end that
     * session for as long as the family lives — and would need a second, hand-written verification
     * path that skips `exp`, which is precisely the kind of JWS handling this package does not do by
     * hand. The refresh token is the credential that actually represents the live session, and the
     * one a client with a lapsed access token still holds, so that is the fallback.
     *
     * @return bool whether the bearer itself was revoked, and so cannot be presented again
     */
    private function endBearerSession(string $bearer): bool
    {
        // The empty test is a short-circuit, not a decision: `verify('')` cannot return claims — an
        // empty string is not a three-segment JWS, and the verifier turns every throw into null — so
        // any other literal in its place reaches the same `null` by a slower route.
        $claims = $bearer === '' ? null : $this->verifier->verify($bearer); // @pest-mutate-ignore: EmptyStringToNotEmpty

        if ($claims === null) {
            // Likewise equivalent: falling through would read `$claims->fid` and `$claims->jti` under
            // `??`, whose isset semantics answer '' for a property of null without erroring, so both
            // branches below are skipped and the method returns false anyway.
            return false; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        $familyId = (string) ($claims->fid ?? '');

        if ($familyId !== '') {
            ($this->revokeSession)($familyId);

            return true;
        }

        // A co-issuer's token carries no family, so there is no session row to revoke — but the token
        // itself still has to stop working here. Kill it by `jti` for the rest of its life.
        $jti = (string) ($claims->jti ?? '');

        if ($jti === '') {
            // Nothing to revoke it by, so it stays valid — and a replayable bearer must not buy
            // unmetered lookups.
            return false;
        }

        $remaining = (int) $claims->exp - now()->getTimestamp();
        $this->denylist->revokeJti($jti, max(1, $remaining + (int) ($this->config['leeway'] ?? 5)));

        return true;
    }

    /**
     * Meter the refresh-token LOOKUP — the one part of logout an unauthenticated caller could use to
     * probe token hashes at volume.
     *
     * Only MISSES count — and a token whose family is already REVOKED, which does no work. Probing
     * always misses; a token that resolves to a live family — valid, rotated, expired — is one the
     * caller genuinely held, so a BFF pays nothing for the logouts that actually end a session, however
     * many users it ends them for from one address. It is not free of the bucket, though: a logout
     * retried or replayed after the family is already revoked counts exactly like a miss.
     *
     * Its own bucket, per guard and per caller, with the refresh route's
     * limits: not the refresh route's bucket itself, whose junk traffic from a shared address would
     * then refuse a legitimate cookie logout, and keyed by guard so one guard cannot throttle another.
     *
     * The check runs BEFORE the lookup, and an exhausted bucket refuses even a real token: whether a
     * token exists is only knowable by looking it up, which is exactly what an exhausted bucket must
     * not do. Throttled means 429, never a silent skip — a 204 would tell the client it had logged out
     * while its refresh token stayed valid (ASVS 5.0 V7.4.1), and the controller would clear the
     * cookie it needs to retry. A 429 says nothing about whether the token exists.
     */
    private function refuseWhenExhausted(string $caller): void
    {
        if (! $this->limiter->tooManyAttempts($this->throttleKey($caller), $this->maxMisses())) {
            return;
        }

        throw new ThrottleRequestsException('Too Many Attempts.', null, [
            'Retry-After' => max(1, $this->limiter->availableIn($this->throttleKey($caller))),
        ]);
    }

    /**
     * Count a miss — AFTER the lookup, since only then is it known to be one. `hit()` increments
     * atomically, so concurrent misses are all counted.
     *
     * The response of the request that counts never depends on the count. The BUDGET itself is still a
     * side channel, stated plainly: spend max−1 misses, present a candidate, then one known miss — a
     * 204 means the candidate resolved to a live family, a 429 means it missed (or was already
     * revoked). That costs a whole budget per bit about a 256-bit random token, which is why it is
     * accepted rather than engineered away. A burst racing past the pre-check can also overshoot the
     * limit by its own concurrency before the counts land and the next request is refused.
     *
     * And the budget is EXHAUSTIBLE BY ANYONE SHARING THE CALLER IDENTITY. An unauthenticated logout
     * is keyed by address ({@see Lukk::rateLimitKey()}), so junk misses from one client behind a NAT,
     * a carrier or a proxy that does not forward the real address spend the bucket for everyone
     * behind it, and their cookie-only logouts answer 429 until it decays. They are not logged out
     * wrongly and they can retry — a 429 leaves the cookie in place — but the refusal is real, and it
     * is the price of metering a lookup on a route that has no authenticated identity to meter by.
     */
    private function countMiss(string $caller): void
    {
        $this->limiter->hit($this->throttleKey($caller), (int) (((array) ($this->config['rate_limits']['refresh'] ?? []))['decay_seconds'] ?? 60));
    }

    private function throttleKey(string $caller): string
    {
        return 'lukk-logout|'.$this->guard.'|'.$caller;
    }

    private function maxMisses(): int
    {
        return (int) (((array) ($this->config['rate_limits']['refresh'] ?? []))['max_attempts'] ?? 30);
    }

    /**
     * The session a presented refresh token belongs to, looked up by hash on THIS guard's repository —
     * a token minted for another guard resolves to nothing, exactly as it does at `/refresh`.
     *
     * Every live family a presented token resolves to is revoked, whatever state the token is in —
     * rotated or expired: logging out is never refused, and revocation grants nothing. An
     * already-revoked family never reaches here (the caller counts it and moves on), which also
     * dedupes a request naming one family twice: the second read sees it revoked. The read is non-locking; what stops a concurrent rotation from
     * leaving a live successor behind is two things together. `RevokeSession` writes the denylist
     * before the rows, and rotation re-checks the denylist under its lock — that catches a logout
     * that started first. A logout whose denylist write lands AFTER that check is caught instead by
     * the repository's revoke, which on PostgreSQL has to run a second UPDATE to see a successor
     * committed while the first was blocked (see `DatabaseRefreshTokenRepository::revokeFamily`).
     *
     * The theft signal follows rotation's decision order exactly — revoked, then expired, then
     * consumed past grace — so a token that `/refresh` would call reuse is reported as reuse here too,
     * and a merely stale one is not.
     */
    private function endRefreshSession(RefreshTokenRecord $record): void
    {
        ($this->revokeSession)($record->familyId);

        $now = now()->getTimestamp();
        $grace = (int) ($this->config['grace_seconds'] ?? 30);

        $reuse = $record->expiresAt >= $now
            && $record->rotatedAt !== null
            && ($record->rotatedAt + $grace) < $now;

        if ($reuse) {
            event(new RefreshTokenReused($record->familyId, 'reuse'));
        }
    }
}
