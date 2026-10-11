<?php

declare(strict_types=1);

namespace Lukk\Contracts;

/**
 * A `LockoutRepository` that can count an attempt WITHOUT deciding it was a failure.
 *
 * The actions reserve an attempt before verifying the credential — that is what keeps a burst of
 * concurrent requests from each getting a guess past a "not locked yet" read (NIST SP 800-63B-4
 * §3.2.2). `recordFailure()` both counts and locks, so through it the attempt that REACHED the cap
 * locked the account and fired `AccountLocked` before its credential was even checked — and when that
 * credential was right, its own success released the lock and fired `AccountReleased`. An app
 * notifying on those told the owner that someone was breaking in, about their own sign-in.
 *
 * Splitting the two lets the lock land only once the credential check has failed. Optional, so a
 * custom repository written against `LockoutRepository` alone keeps working unchanged: the actions
 * fall back to `recordFailure()`, and to the announcement-on-reservation that comes with it.
 */
interface ReservesLockoutAttempts extends LockoutRepository
{
    /**
     * Count one attempt and return the new consecutive count, WITHOUT locking at the cap.
     *
     * The caller refuses the attempt when the count exceeds `maxAttempts()`. A count past the cap on a
     * row that is not locked means the attempt that reached it never reported back — a crash between
     * the reservation and the verdict, or one still in flight — so implementations lock (and announce)
     * there: otherwise a lost verdict would leave a lock `release_after` can never lift, since it times
     * from `locked_at`.
     */
    public function reserve(string $purpose, string $subject, ?string $guard): int;

    /**
     * The credential check failed: lock if the run has reached the cap and is not locked yet. MUST fire
     * `AccountLocked` exactly once per lock, from whichever caller actually set it.
     */
    public function lockIfSpent(string $purpose, string $subject, ?string $guard): void;
}
