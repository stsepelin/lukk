<?php

declare(strict_types=1);

namespace Lukk\Actions\Concerns;

use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\ReservesLockoutAttempts;

/**
 * Reserve an attempt before a credential is checked, and lock only once it has failed.
 *
 * Shared by every path that counts toward the lockout — login, step-up confirmation, the password
 * change and the two-factor challenge — so the split between "counted" and "failed" cannot drift
 * between them. A repository that implements only `LockoutRepository` keeps the old behaviour: its
 * `recordFailure()` counts and locks at the reservation, and nothing more is asked of it afterwards.
 *
 * Consuming classes implement `lockoutGuard()` (see `ThrowsWhenLocked`). The repository is passed in
 * rather than read off the class, so the "feature off" null stays the caller's to handle.
 */
trait CountsLockoutAttempts
{
    /** The attempt's place in the run — refuse it when this exceeds `maxAttempts()`. */
    private function reserveAttempt(LockoutRepository $lockouts, string $purpose, string $subject): int
    {
        return $lockouts instanceof ReservesLockoutAttempts
            ? $lockouts->reserve($purpose, $subject, $this->lockoutGuard())
            : $lockouts->recordFailure($purpose, $subject, $this->lockoutGuard());
    }

    /** The credential the reserved attempt carried was wrong. */
    private function attemptFailed(?LockoutRepository $lockouts, string $purpose, string $subject): void
    {
        if ($lockouts instanceof ReservesLockoutAttempts) {
            $lockouts->lockIfSpent($purpose, $subject, $this->lockoutGuard());
        }
    }
}
