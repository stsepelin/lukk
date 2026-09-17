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
 * already revoked, or was never real. The one exception is a throttled refresh-token lookup, which
 * throws a 429 BEFORE looking anything up — see `reserveLookup()`.
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
     * @throws ThrottleRequestsException when the refresh-token lookup is throttled — nothing has been
     *                                   looked up, and the caller must retry rather than believe it
     *                                   logged out
     */
    public function __invoke(string $bearer, array $refreshTokens, string $caller): void
    {
        // The bearer first, and never metered: a logout named by a valid access token must not be
        // refused because someone else on the same address spent a budget.
        [$revoked, $bearerSpent] = $this->endBearerSession($bearer);

        if ($refreshTokens === []) {
            return;
        }

        // Metered only WITHOUT a spent bearer. A valid bearer is revoked (or denylisted) by this very
        // call, so it buys exactly one batch of lookups and cannot be replayed for more — each such
        // batch costs the caller a live session, which only the throttled login mints. Metering it
        // anyway let ordinary BFF logouts (bearer + refresh token) from one address exhaust the bucket
        // for everyone behind it. It still looks up a DIFFERENT family's token: a browser holding an
        // access token from one login and a cookie from a later one means both when it logs out.
        if (! $bearerSpent) {
            $this->reserveLookup($caller);
        }

        foreach ($refreshTokens as $presented) {
            $revoked = $this->endRefreshSession($presented, $revoked);
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
     * @return array{0: array<int, string>, 1: bool} the families revoked, and whether the bearer itself
     *                                               was revoked (and so cannot be presented again)
     */
    private function endBearerSession(string $bearer): array
    {
        $claims = $bearer === '' ? null : $this->verifier->verify($bearer);

        if ($claims === null) {
            return [[], false];
        }

        $familyId = (string) ($claims->fid ?? '');

        if ($familyId !== '') {
            ($this->revokeSession)($familyId);

            return [[$familyId], true];
        }

        // A co-issuer's token carries no family, so there is no session row to revoke — but the token
        // itself still has to stop working here. Kill it by `jti` for the rest of its life.
        $jti = (string) ($claims->jti ?? '');

        if ($jti === '') {
            // Nothing to revoke it by, so it stays valid — and a replayable bearer must not buy
            // unmetered lookups.
            return [[], false];
        }

        $remaining = (int) $claims->exp - now()->getTimestamp();
        $this->denylist->revokeJti($jti, max(1, $remaining + (int) ($this->config['leeway'] ?? 0)));

        return [[], true];
    }

    /**
     * Meter the refresh-token LOOKUP — the one part of logout an unauthenticated caller could use to
     * probe token hashes at volume. One reservation per request, however many tokens it carries.
     *
     * Its own bucket, per guard and per caller, with the refresh route's limits. Not the refresh
     * route's bucket itself: junk `/refresh` traffic from a shared address would then refuse a
     * legitimate cookie logout. The guard is part of the key so one guard's traffic cannot throttle
     * another's.
     *
     * The slot is RESERVED before it is checked — `hit()` increments atomically and returns the new
     * count. `tooManyAttempts()` then `hit()`, which is also what `RateLimiter::attempt()` does, is
     * check-then-act: a concurrent burst all reads "under the limit" before any of it counts.
     *
     * Throttled means 429, never a silent skip. A 204 would tell the client it had logged out while
     * its refresh token stayed valid (ASVS 5.0 V7.4.1) — and the controller would clear the cookie,
     * leaving the client nothing to retry with. A 429 says nothing about whether the token exists.
     */
    private function reserveLookup(string $caller): void
    {
        $limits = (array) ($this->config['rate_limits']['refresh'] ?? []);
        $key = 'lukk-logout|'.$this->guard.'|'.$caller;

        if ($this->limiter->hit($key, (int) ($limits['decay_seconds'] ?? 60)) <= (int) ($limits['max_attempts'] ?? 30)) {
            return;
        }

        throw new ThrottleRequestsException('Too Many Attempts.', null, [
            'Retry-After' => max(1, $this->limiter->availableIn($key)),
        ]);
    }

    /**
     * The session a presented refresh token belongs to, looked up by hash on THIS guard's repository —
     * a token minted for another guard resolves to nothing, exactly as it does at `/refresh`.
     *
     * Every known token is revoked, whatever state it is in: logging out is never refused, and
     * revocation grants nothing. The read is non-locking; what stops a concurrent rotation from
     * leaving a live successor behind is two things together. `RevokeSession` writes the denylist
     * before the rows, and rotation re-checks the denylist under its lock — that catches a logout
     * that started first. A logout whose denylist write lands AFTER that check is caught instead by
     * the repository's revoke, which on PostgreSQL has to run a second UPDATE to see a successor
     * committed while the first was blocked (see `DatabaseRefreshTokenRepository::revokeFamily`).
     *
     * The theft signal follows rotation's decision order exactly — revoked, then expired, then
     * consumed past grace — so a token that `/refresh` would call reuse is reported as reuse here too,
     * and a merely stale one is not.
     *
     * @param  array<int, string>  $revoked
     * @return array<int, string>
     */
    private function endRefreshSession(string $presented, array $revoked): array
    {
        $record = $this->repository->findByHash($this->issuer->hash($presented));

        if ($record === null || in_array($record->familyId, $revoked, true)) {
            return $revoked;
        }

        ($this->revokeSession)($record->familyId);

        $now = now()->getTimestamp();
        $grace = (int) ($this->config['grace_seconds'] ?? 30);

        $reuse = $record->revokedAt === null
            && $record->expiresAt >= $now
            && $record->rotatedAt !== null
            && ($record->rotatedAt + $grace) < $now;

        if ($reuse) {
            event(new RefreshTokenReused($record->familyId, 'reuse'));
        }

        return [...$revoked, $record->familyId];
    }
}
