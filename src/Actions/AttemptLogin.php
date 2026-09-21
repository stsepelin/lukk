<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\Concerns\ThrowsWhenLocked;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Contracts\LockoutRepository;
use Lukk\Lukk;
use RuntimeException;

/**
 * Resolve + validate credentials into a user. Honors a Lukk::authenticateUsing()
 * closure if registered (a customization hook); otherwise validates email+password
 * against the configured user provider in constant time. Failed attempts are
 * throttled per (email + IP); a success clears the counter.
 */
class AttemptLogin
{
    use ThrowsWhenLocked;

    public function __construct(
        private readonly UserProvider $users,
        private readonly LoginRateLimiter $limiter,
        // Null unless `features.lockout` is on — the consecutive-failure cap is opt-in because a
        // hard lockout is also a denial-of-service primitive against a known account.
        private readonly ?LockoutRepository $lockouts = null,
    ) {}

    public function __invoke(Request $request): Authenticatable
    {
        // Lock first: a locked account whose decaying bucket is also full would otherwise be told
        // "try again in N seconds", which with manual-only release is exactly the untruth that
        // choosing 423 over 429 exists to avoid.
        // Resolved once and reused: the gate, the failure count and the release must all name the
        // same bucket, and re-deriving it per call would mean three provider lookups.
        $this->assertIdentifierColumnExists();

        $subject = $this->lockoutSubject($request);

        $this->ensureIsNotLocked($request, $subject);
        $this->ensureIsNotThrottled($request);

        // RESERVE the attempt before verifying anything. Reading `locked()` and then counting after
        // the credential check is check-then-act: N concurrent requests all read "not locked", all
        // reach `Hash::check`, and all count afterwards — so the realized number of password
        // verifications was `max_attempts + concurrency`, not `max_attempts`. The increment is
        // transactional and row-locked, so consuming it first makes the count authoritative at the
        // moment it is taken. Costs one write per attempt, and only when the feature is on: a hard
        // consecutive cap is not something a decaying counter can approximate.
        $this->reserve($subject);

        try {
            $user = $this->resolve($request);
        } catch (ValidationException $e) {
            $this->limiter->increment($request);

            throw $e;
        }

        $this->limiter->clear($request);
        // "Consecutive" is the whole point of the cap: any success ends the run.
        $this->lockouts?->release('login', $subject, $this->limiter->guard());
        // A step-up lock counts failures against the SAME password, so a successful login is proof
        // enough to clear it — and it's the only self-service escape from a confirm lock an attacker
        // set with a stolen access token (they cannot log in without the password, so this hands
        // them nothing). One extra query on the successful-login path, and only when the feature is
        // on; `release()` does a non-locking existence check first, so it is usually a single SELECT.
        $this->lockouts?->release('confirm', (string) $user->getAuthIdentifier(), $this->limiter->guard());

        return $user;
    }

    /**
     * NIST SP 800-63B §5.2.2. Distinct from the throttles above: those bound a RATE and clear
     * themselves, this bounds a RUN and is held until something releases it. 423 rather than 429
     * because "retry later" may be untrue — with `release_after` at 0 it needs intervention.
     */
    /**
     * Consume this attempt against the cap, and refuse if it was the one that hit it.
     *
     * A success releases the row immediately below, so the counter still means "consecutive
     * failures" from the outside — it is only *held* for the duration of the credential check.
     */
    private function reserve(string $subject): void
    {
        if ($this->lockouts === null) {
            return;
        }

        // Compare the POST-increment count, not `locked()`. The row locks at `>= max`, so gating on
        // it would refuse the very attempt that reached the cap and give `max - 1` usable tries.
        // `> max` keeps the documented meaning — `max` failures happen, then the account is locked —
        // while the atomic increment means only `max` requests can ever win a slot, however many
        // arrive at once.
        if ($this->lockouts->recordFailure('login', $subject, $this->limiter->guard()) > $this->lockouts->maxAttempts()) {
            $this->throwLocked('login', $subject, $this->field());
        }
    }

    private function ensureIsNotLocked(Request $request, string $subject): void
    {
        if ($this->lockouts === null || ! $this->lockouts->locked('login', $subject, $this->limiter->guard())) {
            return;
        }

        $this->throwLocked('login', $subject, $this->field());
    }

    private function resolve(Request $request): Authenticatable
    {
        if (Lukk::$authenticateUsing !== null) {
            $user = (Lukk::$authenticateUsing)($request);

            if ($user instanceof Authenticatable) {
                return $user;
            }

            $this->fail();
        }

        $field = $this->field();
        $credentials = [
            $field => (string) $request->input($field),
            // The identifier cast is load-bearing — a null there becomes `WHERE … IS NULL`, which
            // matches an account with no identifier set. A null password only reaches the hasher,
            // where it fails like any wrong one; the cast keeps it out of a PHP that may refuse it.
            'password' => (string) $request->input('password'), // @pest-mutate-ignore: RemoveStringCast
        ];

        $user = $this->users->retrieveByCredentials($credentials);

        // ONE key-derivation per attempt, on every path, so the answer's timing says nothing about
        // which accounts exist. `Hash::make` runs the same KDF at the same configured cost as the
        // `Hash::check` the real path runs, and — unlike a dummy hash — it needs nothing stored.
        //
        // The previous equalizer memoized a dummy in a `static`, which PHP resets at request
        // shutdown: under PHP-FPM every unknown-identifier attempt paid `make` + `check` while a
        // known one paid a single `check`. Measured at bcrypt cost 12: 472ms vs 236ms — a 2x
        // enumeration oracle, inverted from the one being defended against but just as usable. The
        // memo is also why no test could see it: one process, every request after the first cheap.
        //
        // The second branch is the password-LESS account (passkey-only, SSO, invited-not-yet-set).
        // `EloquentUserProvider::validateCredentials` returns false before hashing when the column
        // is null, and `AbstractHasher::check` does the same for `''` — zero KDF, ~0ms, a single
        // request. That answer identified exactly the accounts worth pivoting to a passkey or a
        // password-reset phish, and this package ships passkeys, so it creates that row shape.
        if ($user === null || ! $this->hasUsablePassword($user)) {
            // The equalizer must never be able to THROW on attacker-controlled input, whatever the
            // hasher is. `password_hash` raises `ValueError` on a NUL byte where `password_verify`
            // only returns false, which turned this branch into a 500 while a real account still got
            // its 422 — a deterministic, single-request account oracle, and one that escaped the
            // failure limiter, since that counts `ValidationException` and not `ValueError`.
            // `LoginRequest` now rejects NUL outright; this is the belt to that braces, and it also
            // covers a rebound hasher with its own opinions about what it will not hash.
            try {
                Hash::make($credentials['password']);
            } catch (\Throwable) {
                // Nothing to report: the work was the only point, and the failure below is the answer.
            }

            $this->fail();
        }

        // Wrapped for the same reason the equalizer above is: `Hash::check` can throw too. With
        // `hashing.driver` on argon2id and a bcrypt row left by an import or a partial migration,
        // `AbstractHasher::check` raises "This password does not use the Argon2id algorithm" — a 500
        // where an unknown identifier gets a 422, which is the same single-request account oracle the
        // NUL byte opened on the branch above, on the neighbouring line. A stored hash the active
        // driver cannot read is not a credential anyone can present, so it fails closed.
        try {
            $valid = $this->users->validateCredentials($user, $credentials);
        } catch (\Throwable) {
            $valid = false;
        }

        if (! $valid) {
            $this->fail();
        }

        return $user;
    }

    private function ensureIsNotThrottled(Request $request): void
    {
        if (! $this->limiter->tooManyAttempts($request)) {
            return;
        }

        event(new Lockout($request));

        $seconds = $this->limiter->availableIn($request);

        // The `(int)` is type hygiene, not behaviour: `ceil()` is always integral, and the value's
        // only consumer is a translation replacement, where `(string) 32.0` and `(string) 32` are
        // the same characters.
        throw ValidationException::withMessages([
            $this->field() => [__('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])], // @pest-mutate-ignore: RemoveIntegerCast
        ])->status(429);
    }

    private function fail(): never
    {
        throw ValidationException::withMessages([
            $this->field() => [__('These credentials do not match our records.')],
        ]);
    }

    /**
     * Refuse a `lukk.username` naming a column the provider's table does not have — in DEBUG only.
     *
     * A typo does not fail loudly on its own. SQLite compiles a double-quoted identifier matching no
     * column to a string LITERAL, so `lukk.username = 'mial'` turns the lookup into `"mial" = ?`:
     * signing in with the literal `mial` matches every row, and the first account's password then
     * signs that account in. PostgreSQL and MySQL raise "column does not exist" instead, which is
     * loud but arrives as a 500 on the login route rather than as an explanation.
     *
     * Behind `app.debug`, and only for the STOCK `EloquentUserProvider`: the hazard lives in its
     * `retrieveByCredentials()`, which does `where($field, $value)`. A subclass that resolves a
     * virtual identifier its own way has no column to have, and refusing it would break a working
     * customization on every developer's machine. Run before the lockout subject is derived, which
     * performs the same lookup — otherwise the driver's error, or a failure counted against whichever
     * account the literal comparison matched, arrives first and this sentence never does.
     *
     * Not memoized: in debug, one extra `pragma`/`information_schema` read per sign-in buys nothing
     * worth the state. `hasColumn()` is case-INSENSITIVE, so a miscased column still passes here and
     * fails on PostgreSQL only.
     */
    private function assertIdentifierColumnExists(): void
    {
        if ($this->users::class !== EloquentUserProvider::class || ! config('app.debug')) {
            return;
        }

        $field = $this->field();
        $model = $this->users->createModel();
        $table = $model->getTable();
        $schema = Schema::connection($model->getConnectionName());

        // Nothing to diagnose on an application that has not migrated yet: every column is missing,
        // and the driver's own "no such table" says it better.
        if (! $schema->hasTable($table) || $schema->hasColumn($table, $field)) {
            return;
        }

        throw new RuntimeException(
            "lukk.username is [{$field}], but the table [{$table}] has no such column. On SQLite that "
            .'makes the sign-in lookup compare two string literals rather than a column, so submitting '
            ."[{$field}] as the identifier matches every row. Set `lukk.username` to the column your "
            .'users authenticate with.'
        );
    }

    /** The identifier field (config `lukk.username`) — the request field + the error key. */
    /**
     * The lockout subject for this attempt. Costs one provider lookup, and only when the feature is
     * on — see `LoginRateLimiter::lockoutSubject()` for why the identifier alone is not safe to key
     * on. The lookup reads `lukk.username`, which is the same field the counter has always keyed
     * on, so a `Lukk::authenticateUsing` callback that authenticates elsewhere is no worse off than
     * before (config/lukk.php documents that it must set `lukk.username` to match).
     */
    private function lockoutSubject(Request $request): string
    {
        if ($this->lockouts === null) {
            // The value is never read: every consumer of the subject short-circuits on this same check.
            return ''; // @pest-mutate-ignore: EmptyStringToNotEmpty
        }

        $identifier = (string) $request->input($this->field());

        return LoginRateLimiter::lockoutSubject(
            $this->users->retrieveByCredentials([$this->field() => $identifier]),
            $identifier,
        );
    }

    private function field(): string
    {
        return Lukk::usernameField();
    }

    /**
     * Whether this user carries a password the hasher would actually do work on.
     *
     * Deliberately only "a non-empty string" — the two states the framework short-circuits on. A
     * stricter test (`Hash::info()` reporting a known algorithm) would also catch a corrupt or
     * foreign hash, but it would lock out every install running a custom hasher whose output
     * `password_get_info` cannot name, which is a far worse failure than the timing it closes.
     */
    private function hasUsablePassword(Authenticatable $user): bool
    {
        // The cast NORMALIZES rather than silences: `Authenticatable::getAuthPassword()` is
        // documented `string`, but the framework does not believe its own docblock —
        // `EloquentUserProvider::validateCredentials()` returns false on `is_null($hashed)` and
        // `AbstractHasher::check()` on `(string) $hashedValue === ''`. Both of those states mean the
        // same thing here (nothing to derive against), and `(string) null` is `''`, so one comparison
        // covers both.
        return (string) $user->getAuthPassword() !== '';
    }

    private function lockoutGuard(): string
    {
        return $this->limiter->guard();
    }
}
