<?php

declare(strict_types=1);

namespace Lukk\Contracts;

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
}
