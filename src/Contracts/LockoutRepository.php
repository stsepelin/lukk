<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Lukk\Auth\LoginRateLimiter;

/**
 * Storage for the consecutive-failure counters behind the account lockout.
 *
 * The swap seam (like `RefreshTokenRepository`): the policy — when to lock, when to release — lives
 * in the actions, so a host app can move the counters to Redis-with-persistence or a shared service
 * without reimplementing any of it. Implementations MUST NOT expire counters on their own; only
 * `release()` and a successful authentication clear one.
 */
interface LockoutRepository
{
    /** Whether this account is currently locked, honouring `release_after` if configured. */
    public function locked(string $purpose, string $subject, ?string $guard): bool;

    /** Record one failure and return the new consecutive count. */
    public function recordFailure(string $purpose, string $subject, ?string $guard): int;

    /**
     * The configured consecutive-failure cap.
     *
     * The actions reserve an attempt by incrementing BEFORE verifying a credential, then compare
     * the returned count against this — so concurrent requests can't all pass a "not locked yet"
     * read and each get a verification. That comparison is policy, so it belongs in the action;
     * the number lives here because this is what clamps and owns it.
     */
    public function maxAttempts(): int;

    /**
     * Clear the counter — a successful authentication, a password reset, or an explicit release.
     * Returns how many locks were actually cleared, so an operator tool can tell a hit from a miss.
     * Implementations MUST fire `AccountReleased` when they clear something, so an audit log sees
     * every unlock and not just the ones that came through the console.
     */
    public function release(string $purpose, string $subject, ?string $guard): int;

    /** Seconds until an auto-release, or null when the lock is held until released manually. */
    public function availableIn(string $purpose, string $subject, ?string $guard): ?int;

    /**
     * Drop counters that can no longer matter, returning how many went.
     *
     * Needed because a row is created for EVERY failed identifier, existing or not, and one below
     * the cap is otherwise immortal — an unauthenticated caller would mint rows forever, and the
     * table would become a log of every address ever probed.
     */
    public function prune(int $staleAfterDays): int;

    /**
     * DELETE every counter for a set of subjects on one guard, across all purposes.
     *
     * Takes a LIST because a single account occupies three key spaces, and nothing else in the
     * erasure path can find any of them:
     *   - `id:<userId>`            — login failures against a resolvable account
     *   - `<userId>`               — step-up confirmation and two-factor failures
     *   - `idn:<normalized>`       — login failures against an identifier resolving to no account
     *
     * Build them with {@see LoginRateLimiter::lockoutSubject()} rather than by hand: the
     * raw identifier is never a key, so a sweep keyed on it silently matches nothing.
     *
     * Guard-scoped, because two accounts sharing a corporate email share a subject — an unguarded
     * sweep let erasing one clear a held NIST §5.2.2 lock on a different, live account.
     *
     * @param  array<int, string>  $subjects
     * @return int rows deleted
     */
    public function forget(array $subjects, ?string $guard): int;
}
