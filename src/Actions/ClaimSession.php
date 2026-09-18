<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Support\Facades\Log;
use Lukk\Events\SessionUnclaimed;
use Lukk\Support\UnclaimedSessions;
use Throwable;

/**
 * Enforce `claim_seconds` on a session's use: claim it on its first use inside the window, or revoke
 * the whole family when that first use comes after it.
 *
 * Called from the two places a session is USED — request authentication (`JwtGuard`) and refresh
 * (`RotateRefreshToken`, before its transaction opens) — and resolved only when the guard's window is
 * on, so an install that leaves the feature off never touches the cache for it.
 *
 * Revocation goes through `RevokeSession`: denylist first, then the rows, then the marker, and never
 * inside a transaction.
 */
class ClaimSession
{
    /**
     * How far apart the marker and the credential's mint time may be and still be the same sign-in.
     *
     * Deliberately a constant, and deliberately NOT `leeway`. Both timestamps are stamped by THIS
     * server microseconds apart in one sign-in — the marker before the insert, the credential's `iat`
     * / `created_at` at the mint — so the only skew to absorb is a write straddling a second boundary.
     * `leeway` measures something else entirely (drift between the machine that SIGNS a token and the
     * one that VERIFIES it) and is meant to be raised: at `leeway: 120` a successor minted by a
     * refresh 40 s after sign-in passed as the original, so a resurrected marker could log out a
     * session in active use — the one thing the "original credential only" rule exists to prevent.
     */
    private const ORIGINAL_WITHIN_SECONDS = 2;

    /** Per process: the missing-`createdAt` warning is a configuration problem, not a per-request event. */
    private static bool $warnedMissingCreatedAt = false;

    public function __construct(
        private readonly UnclaimedSessions $sessions,
        private readonly RevokeSession $revokeSession,
        /** The EFFECTIVE window ({@see UnclaimedSessions::window()}); 0 = off. */
        private readonly int $window,
        private readonly string $guard = 'api',
    ) {}

    /**
     * Whether the family may be used. False means it has just been revoked.
     *
     * @param  ?int  $mintedAt  when the PRESENTED credential was minted — an access token's `iat`, or a
     *                          never-rotated refresh row's `created_at`. Null when unknown, which is
     *                          never treated as the original.
     * @param  bool  $mintTimeHidden  the presented credential is a never-rotated refresh row whose
     *                                repository did not report `createdAt` — see the warning below
     */
    public function __invoke(string $familyId, ?int $mintedAt, bool $mintTimeHidden = false): bool
    {
        if ($this->window <= 0 || $familyId === '') {
            return true;
        }

        // One cache read per call; nothing else unless there is a marker.
        $issuedAt = $this->sessions->issuedAt($familyId);

        if ($issuedAt === null) {
            return true;
        }

        // A replacement `RefreshTokenRepository` that leaves `RefreshTokenRecord::$createdAt` null — or a
        // `useRefreshTokenModel` subclass with `$timestamps = false`, whose rows have no `created_at` —
        // makes every refresh row unrecognisable as the sign-in's original, so no late first use is ever
        // revoked: the feature is silently off. Only noticeable here, with a marker in hand.
        if ($mintTimeHidden && ! self::$warnedMissingCreatedAt) {
            // Set first: a logger that fails is not retried on every request of this worker.
            self::$warnedMissingCreatedAt = true;

            try {
                // Configuration only — never a family id, hash, user or token.
                Log::warning("lukk: claim_seconds is on for guard [{$this->guard}], but its refresh token "
                    .'records carry no createdAt, so an unclaimed session\'s original refresh token can never '
                    .'be recognised and is never revoked. A replacement RefreshTokenRepository must populate '
                    .'RefreshTokenRecord::$createdAt; a Lukk::useRefreshTokenModel subclass must keep '
                    .'$timestamps enabled.');
            } catch (Throwable) {
                // A diagnostic must never fail the authentication it rides on.
            }
        }

        $late = now()->getTimestamp() - $issuedAt > $this->window;

        // Only the sign-in's ORIGINAL credential is ever revoked — one minted when the family was.
        // Anything minted later exists only because the session was refreshed, which is a use: that is
        // a claim, whatever the marker says. This is what keeps a lost marker delete harmless. A cache
        // restored from a snapshot, or a failover that drops the delete, resurrects the marker of a
        // session in active use, and without this rule that session's next request logged it out.
        $original = $mintedAt !== null && abs($mintedAt - $issuedAt) <= self::ORIGINAL_WITHIN_SECONDS;

        if (! $late || ! $original) {
            $this->sessions->forget($familyId);

            return true;
        }

        try {
            ($this->revokeSession)($familyId);
        } catch (Throwable $e) {
            // A verify-only service can share the cache and the setting yet have no refresh_tokens
            // table. `RevokeSession` writes the denylist FIRST, which is the part that stops the
            // family here; the rows are revoked by the issuer on the family's next refresh. Rejecting
            // is still right, and a 500 is not.
            report($e);
        }

        // Two late requests racing can both reach here; revocation is idempotent, and a duplicate
        // event is the cheaper failure than serialising every first use through a lock.
        event(new SessionUnclaimed($familyId, $this->guard));

        return false;
    }
}
