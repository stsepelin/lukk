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

    /** Clear the counter — a successful authentication, or an explicit release. */
    public function release(string $purpose, string $subject, ?string $guard): void;

    /** Seconds until an auto-release, or null when the lock is held until released manually. */
    public function availableIn(string $purpose, string $subject, ?string $guard): ?int;
}
