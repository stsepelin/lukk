<?php

declare(strict_types=1);

namespace Lukk\Lockout;

use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Lukk\Contracts\LockoutRepository;
use Lukk\Events\AccountLocked;
use Lukk\Events\AccountReleased;
use Lukk\Models\Lockout;

/**
 * The default counter store: one row per (purpose, subject, guard).
 *
 * `releaseAfter` of 0 means a lock is held until something explicitly releases it — a successful
 * authentication, a password reset, `lukk:release`, or this API. Any positive value auto-releases
 * that many seconds after the lock was set, which bounds the denial an attacker gets by burning a
 * known account's budget on purpose. That bound has a cost: a run broken by TIME rather than by a
 * success is no longer "consecutive" in the strict NIST SP 800-63B §5.2.2 sense, so the two knobs
 * pull against each other and the docs say so.
 */
class DatabaseLockoutRepository implements LockoutRepository
{
    public function __construct(
        private readonly int $maxAttempts,
        private readonly int $releaseAfter,
    ) {}

    public function locked(string $purpose, string $subject, ?string $guard): bool
    {
        if (! $this->usable($subject)) {
            return false;
        }

        $row = $this->find($purpose, $subject, $guard);

        // Read-only: an expired lock reports unlocked and is reset by the next failure (or pruned).
        // Deleting from here would write on a read path — broken on a replica, and it raced with
        // `availableIn()`, which then reported "no auto-release" for a lock that had one.
        return $row?->locked_at !== null && ! $this->expired($row);
    }

    public function recordFailure(string $purpose, string $subject, ?string $guard): int
    {
        if (! $this->usable($subject)) {
            return 0;
        }

        [$attempts, $justLocked] = DB::transaction(function () use ($purpose, $subject, $guard) {
            $row = $this->locate($purpose, $subject, $guard);

            // An auto-release lapsed: start a fresh run rather than leaving the account one
            // attempt away from locking again.
            if ($this->expired($row)) {
                $row->attempts = 0;
                $row->locked_at = null;
            }

            $row->attempts++;
            $locking = $row->attempts >= $this->maxAttempts && $row->locked_at === null;

            if ($locking) {
                $row->locked_at = Carbon::now();
            }

            $row->save();

            return [$row->attempts, $locking];
        });

        if ($justLocked) {
            // Fired once, on the transition — a locked-out user gets no other signal, so this is
            // where an app tells the account's owner. NOTE for listeners: `subject` is whatever was
            // submitted and need not name a real account, so rate-limit any mail you send off it.
            event(new AccountLocked($purpose, $subject, $guard));
        }

        return $attempts;
    }

    public function release(string $purpose, string $subject, ?string $guard): int
    {
        if (! $this->usable($subject)) {
            return 0;
        }

        // Non-locking existence check first: DELETE on an absent unique value gap-locks under MySQL
        // REPEATABLE READ (the same guard DatabaseRefreshTokenRepository documents), and this runs on
        // the SUCCESSFUL-login hot path, where there is usually nothing to delete.
        if (! $this->query($purpose, $subject, $guard)->exists()) {
            return 0;
        }

        $released = $this->query($purpose, $subject, $guard)->delete();

        if ($released > 0) {
            event(new AccountReleased($purpose, $subject, $guard));
        }

        return $released;
    }

    public function availableIn(string $purpose, string $subject, ?string $guard): ?int
    {
        $row = $this->usable($subject) ? $this->find($purpose, $subject, $guard) : null;

        if ($this->releaseAfter <= 0 || $row?->locked_at === null) {
            return null;
        }

        return max(0, $this->releaseAfter - (int) $row->locked_at->diffInSeconds(Carbon::now(), absolute: true));
    }

    public function prune(int $staleAfterDays): int
    {
        if (! Schema::hasTable((new Lockout)->getTable())) {
            return 0;
        }

        // An auto-released lock is spent, and an untouched counter that old is noise — but a HELD
        // lock is never pruned, whatever its age, or pruning would quietly become a release path.
        $stale = Carbon::now()->subDays(max(1, $staleAfterDays));

        return Lockout::query()
            ->where(fn ($q) => $q->whereNull('locked_at')->where('updated_at', '<', $stale))
            ->when($this->releaseAfter > 0, fn ($q) => $q->orWhere(
                fn ($inner) => $inner->whereNotNull('locked_at')
                    ->where('locked_at', '<', Carbon::now()->subSeconds($this->releaseAfter))
            ))
            ->delete();
    }

    /**
     * Fetch the row for update, creating it if absent.
     *
     * The insert is racy by nature — two first-failures for one subject arrive together — and the
     * unique index is what makes that safe: the loser catches the violation and re-reads the winner's
     * row instead of surfacing a QueryException as a 500 on `/auth/login`.
     */
    private function locate(string $purpose, string $subject, ?string $guard): Lockout
    {
        $row = $this->query($purpose, $subject, $guard)->lockForUpdate()->first();

        if ($row !== null) {
            return $row;
        }

        try {
            return Lockout::query()->create(
                ['purpose' => $purpose, 'subject' => $subject, 'guard' => (string) $guard, 'attempts' => 0]
            );
        } catch (UniqueConstraintViolationException) {
            return $this->query($purpose, $subject, $guard)->lockForUpdate()->firstOrFail();
        }
    }

    /**
     * Whether this subject can be counted at all.
     *
     * An empty subject would put every caller in ONE bucket — and unlike a decaying limiter, that
     * bucket never heals: 100 failures anywhere would lock the whole application, permanently. It
     * happens for real whenever `Lukk::authenticateUsing` reads a field other than `lukk.username`,
     * since the identifier this keys on is then never submitted. Refuse rather than lock everyone;
     * the module warns about that configuration at boot.
     */
    private function usable(string $subject): bool
    {
        return $subject !== '' && Schema::hasTable((new Lockout)->getTable());
    }

    private function find(string $purpose, string $subject, ?string $guard): ?Lockout
    {
        return $this->query($purpose, $subject, $guard)->first();
    }

    private function query(string $purpose, string $subject, ?string $guard)
    {
        // '' rather than null — see the migration: a null in a unique index doesn't dedupe.
        return Lockout::query()
            ->where('purpose', $purpose)->where('subject', $subject)->where('guard', (string) $guard);
    }

    private function expired(Lockout $row): bool
    {
        return $this->releaseAfter > 0
            && $row->locked_at !== null
            && $row->locked_at->addSeconds($this->releaseAfter)->isPast();
    }
}
