<?php

declare(strict_types=1);

namespace Lukk\Lockout;

use Illuminate\Support\Carbon;
use Lukk\Contracts\LockoutRepository;
use Lukk\Events\AccountLocked;
use Lukk\Models\Lockout;

/**
 * The default counter store: one row per (purpose, subject, guard).
 *
 * `releaseAfter` of 0 means a lock is held until something explicitly releases it — a successful
 * authentication, `lukk:release`, or the repository API. Any positive value auto-releases that many
 * seconds after the lock was set, which bounds the denial-of-service an attacker gets by burning a
 * known account's budget on purpose.
 */
class DatabaseLockoutRepository implements LockoutRepository
{
    public function __construct(
        private readonly int $maxAttempts,
        private readonly int $releaseAfter,
    ) {}

    public function locked(string $purpose, string $subject, ?string $guard): bool
    {
        $row = $this->find($purpose, $subject, $guard);

        if ($row?->locked_at === null) {
            return false;
        }

        // Auto-release lapsed: drop the row so the next failure starts a fresh run, rather than
        // leaving the account one attempt away from locking again.
        if ($this->expired($row)) {
            $row->delete();

            return false;
        }

        return true;
    }

    public function recordFailure(string $purpose, string $subject, ?string $guard): int
    {
        $row = $this->find($purpose, $subject, $guard)
            ?? new Lockout(['purpose' => $purpose, 'subject' => $subject, 'guard' => $guard, 'attempts' => 0]);

        if ($row->exists && $this->expired($row)) {
            $row->attempts = 0;
            $row->locked_at = null;
        }

        $row->attempts++;

        if ($row->attempts >= $this->maxAttempts && $row->locked_at === null) {
            $row->locked_at = Carbon::now();
            $row->save();

            // Fired once, on the transition — so an app can notify the account's owner that
            // someone is attacking it, which is the only signal a locked-out user gets.
            event(new AccountLocked($purpose, $subject, $guard));

            return $row->attempts;
        }

        $row->save();

        return $row->attempts;
    }

    public function release(string $purpose, string $subject, ?string $guard): void
    {
        Lockout::query()
            ->where('purpose', $purpose)->where('subject', $subject)->where('guard', $guard)
            ->delete();
    }

    public function availableIn(string $purpose, string $subject, ?string $guard): ?int
    {
        $row = $this->find($purpose, $subject, $guard);

        if ($this->releaseAfter <= 0 || $row?->locked_at === null) {
            return null;
        }

        return max(0, $this->releaseAfter - (int) $row->locked_at->diffInSeconds(Carbon::now(), absolute: true));
    }

    private function find(string $purpose, string $subject, ?string $guard): ?Lockout
    {
        return Lockout::query()
            ->where('purpose', $purpose)->where('subject', $subject)->where('guard', $guard)
            ->first();
    }

    private function expired(Lockout $row): bool
    {
        return $this->releaseAfter > 0
            && $row->locked_at !== null
            && $row->locked_at->addSeconds($this->releaseAfter)->isPast();
    }
}
