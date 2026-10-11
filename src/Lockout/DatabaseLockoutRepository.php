<?php

declare(strict_types=1);

namespace Lukk\Lockout;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Lukk\Contracts\ReservesLockoutAttempts;
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
 * success is no longer "consecutive" in the strict NIST SP 800-63B-4 §3.2.2 sense, so the two knobs
 * pull against each other and the docs say so.
 */
class DatabaseLockoutRepository implements ReservesLockoutAttempts
{
    public function __construct(
        private readonly int $maxAttempts,
        private readonly int $releaseAfter,
    ) {}

    public function maxAttempts(): int
    {
        return $this->maxAttempts;
    }

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
        return $this->count($purpose, $subject, $guard, $this->maxAttempts);
    }

    public function reserve(string $purpose, string $subject, ?string $guard): int
    {
        // Locks only PAST the cap: the attempt that reaches it is still being verified, and locks
        // through `lockIfSpent()` if it fails. Past the cap and not locked, that verdict never came
        // back (see the contract) — lock rather than strand a lock `release_after` cannot time.
        return $this->count($purpose, $subject, $guard, $this->maxAttempts + 1);
    }

    public function lockIfSpent(string $purpose, string $subject, ?string $guard): void
    {
        if (! $this->usable($subject)) {
            return;
        }

        // One conditional statement, so the transition is decided by the write itself: of two failures
        // landing together, only the one whose UPDATE took the row announces it.
        $locked = $this->query($purpose, $subject, $guard)
            ->where('attempts', '>=', $this->maxAttempts)->whereNull('locked_at')
            ->update(['locked_at' => Carbon::now()]);

        if ($locked > 0) {
            event(new AccountLocked($purpose, $subject, $guard));
        }
    }

    /** Count one attempt, locking (and announcing it) once the run reaches `$lockAt`. */
    private function count(string $purpose, string $subject, ?string $guard, int $lockAt): int
    {
        if (! $this->usable($subject)) {
            return 0;
        }

        $this->ensureRow($purpose, $subject, $guard);

        [$attempts, $justLocked] = DB::transaction(function () use ($purpose, $subject, $guard, $lockAt) {
            $row = $this->locate($purpose, $subject, $guard);

            // An auto-release lapsed: start a fresh run rather than leaving the account one
            // attempt away from locking again.
            if ($this->expired($row)) {
                $row->attempts = 0;
                $row->locked_at = null;
            }

            $row->attempts++;
            $locking = $row->attempts >= $lockAt && $row->locked_at === null;

            if ($locking) {
                $row->locked_at = Carbon::now();
            }

            $row->save();

            return [$row->attempts, $locking];
        });

        if ($justLocked) {
            // Fired once, on the transition — a locked-out user gets no other signal, so this is
            // where an app tells the account's owner. NOTE for listeners: only an `id:` (login) or bare
            // user-id (two-factor, confirm) subject names an account; an `idn:` digest names no one.
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

        // `AccountReleased` is the lock→released transition, the mirror of `AccountLocked` — so it is
        // announced only where a lock was HELD. Fired for any deleted counter, every successful sign-in
        // after a typo told an audit log that a locked account had been unlocked. A lock already past
        // `release_after` ended then, and that expiry announces nothing; deleting its row is no release.
        //
        // "Held" is decided BY the deleting statements, never by a read before them: a SELECT then an
        // unconditional DELETE lifted a lock taken in between with no announcement. The held lock goes
        // first and is announced; the second statement takes only what is NOT held, so a lock that
        // arrives between the two is left standing rather than lifted silently.
        $held = $this->held($this->query($purpose, $subject, $guard))->delete();
        $cleared = $this->query($purpose, $subject, $guard)
            ->where(fn ($q) => $q->whereNull('locked_at')->orWhere(fn ($spent) => $this->spent($spent)))
            ->delete();

        // Only the request that deleted the lock announces it, so a concurrent release is not counted twice.
        if ($held > 0) {
            event(new AccountReleased($purpose, $subject, $guard));
        }

        return $held + $cleared;
    }

    public function availableIn(string $purpose, string $subject, ?string $guard): ?int
    {
        $row = $this->usable($subject) ? $this->find($purpose, $subject, $guard) : null;

        if ($this->releaseAfter <= 0 || $row?->locked_at === null) {
            return null;
        }

        return max(0, $this->releaseAfter - (int) $row->locked_at->diffInSeconds(Carbon::now(), absolute: true));
    }

    public function forget(array $subjects, ?string $guard): int
    {
        // The only public method here that guarded on nothing. `usable()` covers the four
        // subject-keyed paths and `prune()` checks inline; this one was safe purely because its
        // single call site happens to check first. A consumer calling the contract directly on an
        // install that never published the lockout migration got a raw SQL error. Checked here
        // rather than through `usable()`, which takes ONE subject and this takes a list.
        if (! $this->published()) {
            return 0;
        }

        // `array_values` only tidies the keys; `whereIn` and the emptiness check below ignore them.
        $subjects = array_values(array_filter($subjects, fn (string $s) => $s !== '')); // @pest-mutate-ignore: UnwrapArrayValues

        if ($subjects === []) {
            return 0;
        }

        // Every purpose, but only THIS guard. Two accounts sharing a corporate email share a lockout
        // subject, so an unguarded sweep let erasing one account clear a held NIST SP 800-63B-4 §3.2.2 login lock
        // on a different, live, possibly privileged one — reachable by anyone controlling any
        // account with that identifier.
        return Lockout::query()->whereIn('subject', $subjects)->where('guard', (string) $guard)->delete();
    }

    public function summariesForSubjects(array $subjects, ?string $guard): array
    {
        // The same empty-subject filter and table guard as `forget()`, so the two can never reach
        // different rows.
        $subjects = array_values(array_filter($subjects, fn (string $s) => $s !== '')); // @pest-mutate-ignore: UnwrapArrayValues

        if ($subjects === [] || ! $this->published()) {
            return [];
        }

        return Lockout::query()
            ->whereIn('subject', $subjects)->where('guard', (string) $guard)
            ->orderBy('purpose')->orderBy('created_at')
            ->get()
            ->map(fn (Lockout $row) => [
                'purpose' => $row->purpose,
                'attempts' => $row->attempts,
                'locked_at' => $row->locked_at?->getTimestamp(),
                'first_failed_at' => $row->created_at?->getTimestamp(),
                'last_failed_at' => $row->updated_at?->getTimestamp(),
            ])->all();
    }

    public function prune(int $staleAfterDays): int
    {
        if (! $this->published()) {
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
     * Create the counter row, if absent, BEFORE the counting transaction opens.
     *
     * Inside it, a first failure ran `SELECT … FOR UPDATE` on an absent row and then INSERTed. Under
     * MySQL REPEATABLE READ that locking read takes a GAP lock, and concurrent first failures for one
     * subject each held the gap while waiting to insert into it — InnoDB killed all but one with 1213
     * (deadlock): a 500 on `/auth/login`, and an uncounted guess, for exactly the burst the counter
     * exists to meter. Measured with eight simultaneous wrong passwords against a fresh account: seven
     * deadlocks. Inserted here, in autocommit, no lock outlives the statement, and the transaction's
     * locking read then finds the row and serialises on it. `insertOrIgnore` (`ON CONFLICT DO NOTHING`
     * on PostgreSQL), so a concurrent insert is no error — and on PostgreSQL, no aborted transaction.
     */
    private function ensureRow(string $purpose, string $subject, ?string $guard): void
    {
        if ($this->query($purpose, $subject, $guard)->exists()) {
            return;
        }

        $now = Carbon::now();

        $model = new Lockout;

        // Past Eloquent, so the model's own ULID (lowercased by `HasUlids`) and timestamps are spelled out.
        $model->newQuery()->insertOrIgnore([
            'id' => $model->newUniqueId(),
            'purpose' => $purpose,
            'subject' => $subject,
            'guard' => (string) $guard,
            // The column defaults to 0 as well; stated so the row reads as written.
            'attempts' => 0, // @pest-mutate-ignore: RemoveArrayItem
            'created_at' => $now,
            // The counting save() that follows stamps it again on every path; stated for a whole row.
            'updated_at' => $now, // @pest-mutate-ignore: RemoveArrayItem
        ]);
    }

    /**
     * Fetch the row for update, creating it if absent — which, after `ensureRow()`, means only that a
     * success released it in between.
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
            // Nested, so Laravel emits a SAVEPOINT: on PostgreSQL a failed INSERT aborts the WHOLE
            // transaction (25P02 on every later statement), which would make this recovery itself
            // the 500 on /auth/login that it exists to prevent. Rolling back to the savepoint keeps
            // the outer transaction — and its `lockForUpdate` — usable. MySQL doesn't need it.
            return DB::transaction(fn () => Lockout::query()->create([
                'purpose' => $purpose,
                'subject' => $subject,
                'guard' => (string) $guard,
                // The column defaults to 0 as well; stated so the model holds the value without a re-read.
                'attempts' => 0, // @pest-mutate-ignore: RemoveArrayItem
            ]));
        } catch (UniqueConstraintViolationException) {
            return $this->query($purpose, $subject, $guard)->lockForUpdate()->firstOrFail();
        }
    }

    /** On the model's own connection and table name; not memoized, so a later migration is seen. */
    private function published(): bool
    {
        $model = new Lockout;

        return Schema::connection($model->getConnectionName())->hasTable($model->getTable());
    }

    /**
     * Whether this subject can be counted at all.
     *
     * An empty subject would put every caller in ONE bucket — and unlike a decaying limiter, that
     * bucket never heals: 100 failures anywhere would lock the whole application, permanently. It
     * happens for real whenever `Lukk::authenticateUsing` reads a field other than `lukk.username`,
     * since the identifier this keys on is then never submitted. Refuse rather than lock everyone —
     * "silently does nothing" is the wrong outcome, but it is the survivable one. `config/lukk.php`
     * documents the constraint next to `features.lockout`; it cannot be checked at boot, because a
     * package provider boots before the application registers its `authenticateUsing` callback.
     */
    private function usable(string $subject): bool
    {
        return $subject !== '' && $this->published();
    }

    private function find(string $purpose, string $subject, ?string $guard): ?Lockout
    {
        return $this->query($purpose, $subject, $guard)->first();
    }

    /** @return Builder<covariant \Lukk\Models\Lockout> */
    private function query(string $purpose, string $subject, ?string $guard)
    {
        // '' rather than null — see the migration: a null in a unique index doesn't dedupe.
        return Lockout::query()
            ->where('purpose', $purpose)->where('subject', $subject)->where('guard', (string) $guard);
    }

    /**
     * @param  Builder<covariant \Lukk\Models\Lockout>  $query
     * @return Builder<covariant \Lukk\Models\Lockout>
     */
    private function held(Builder $query): Builder
    {
        return $query->whereNotNull('locked_at')->when(
            $this->releaseAfter > 0,
            fn ($q) => $q->where('locked_at', '>=', $this->lapsedBefore()),
        );
    }

    /**
     * A lock `release_after` has already lifted — the complement of `held()` among locked rows. Never
     * matches with `release_after` at 0, where only a release ends a lock.
     *
     * @param  Builder<covariant \Lukk\Models\Lockout>  $query
     */
    private function spent(Builder $query): void
    {
        $this->releaseAfter > 0
            ? $query->whereNotNull('locked_at')->where('locked_at', '<', $this->lapsedBefore())
            : $query->whereRaw('1 = 0');
    }

    /**
     * Locks set before this instant have auto-released (`expired()`, as a bound for a WHERE clause).
     *
     * Rounded UP to the second. The bound is bound as `Y-m-d H:i:s`, dropping the fraction `expired()`
     * compares with, so between L+R and L+R+1 the release still took the lock for held — and announced it
     * — while `locked()` already called it lifted. `locked_at` is stored to the whole second, so
     * `locked_at >= ceil(now − R)` is exactly `expired()`'s "not yet past L+R".
     */
    private function lapsedBefore(): Carbon
    {
        return Carbon::now()->subSeconds($this->releaseAfter)->ceilSecond();
    }

    private function expired(Lockout $row): bool
    {
        return $this->releaseAfter > 0
            && $row->locked_at !== null
            && $row->locked_at->addSeconds($this->releaseAfter)->isPast();
    }
}
