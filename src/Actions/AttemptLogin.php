<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
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
        $this->assertIdentifierColumnExists();

        [$user, $subjects] = $this->resolve($request);

        $this->limiter->clear($request);
        // "Consecutive" is the whole point of the cap: any success ends the run.
        foreach ($subjects as $subject) {
            $this->lockouts?->release('login', $subject, $this->limiter->guard());
        }
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
    /** @param  list<string>  $subjects */
    private function reserve(array $subjects): void
    {
        if ($this->lockouts === null) {
            return;
        }

        // Compare the POST-increment count, not `locked()`. The row locks at `>= max`, so gating on
        // it would refuse the very attempt that reached the cap and give `max - 1` usable tries.
        // `> max` keeps the documented meaning — `max` failures happen, then the account is locked —
        // while the atomic increment means only `max` requests can ever win a slot, however many
        // arrive at once.
        // Every counter takes the attempt before any refuses it, so they stay in step.
        $over = [];

        foreach ($subjects as $subject) {
            if ($this->lockouts->recordFailure('login', $subject, $this->limiter->guard()) > $this->lockouts->maxAttempts()) {
                $over[] = $subject;
            }
        }

        if ($over !== []) {
            $this->throwLocked('login', $over[0], $this->field());
        }
    }

    /** @param  list<string>  $subjects */
    private function ensureIsNotLocked(Request $request, array $subjects): void
    {
        foreach ($subjects as $subject) {
            if ($this->lockouts?->locked('login', $subject, $this->limiter->guard())) {
                $this->throwLocked('login', $subject, $this->field());
            }
        }
    }

    /** @return array{0: Authenticatable, 1: list<string>} the user, and the lockout subjects it counted against */
    private function resolve(Request $request): array
    {
        // Every failure costs the same WALL CLOCK, not merely the same number of key derivations —
        // and the box holds EVERYTHING that differs between a real account and an unknown one: the
        // provider lookup, the lockout reads and writes (a real account has two counters, a non-account
        // one: 15 queries against 7), and the key derivation. An unknown identifier hashes at the
        // CONFIGURED cost while a real account is checked at the cost embedded in its stored hash, so a
        // row left behind by a `BCRYPT_ROUNDS` bump answers several times faster and an unreadable one
        // (`!`, `*`, an import) answers instantly.
        //
        // A Timebox pads a fast path up to the budget and never shortens a slow one, so a budget set
        // below the real cost is ineffective rather than harmful — and `throw`s still propagate, after
        // the padding, so a 422, 423 or 429 keeps its timing too.
        return app(Timebox::class)->call(function (Timebox $timebox) use ($request) {
            // The account the identifier names, looked up ONCE: it keys the counters below and is the
            // row the password is then checked against.
            $candidate = $this->candidate($request);
            $subjects = LoginRateLimiter::lockoutSubjects($candidate, (string) $request->input($this->field()));

            // Lock first: a locked account whose decaying bucket is also full would otherwise be told
            // "try again in N seconds", which with manual-only release is exactly the untruth that
            // choosing 423 over 429 exists to avoid.
            $this->ensureIsNotLocked($request, $subjects);
            $this->ensureIsNotThrottled($request);

            // RESERVE the attempt before verifying anything. Reading `locked()` and then counting after
            // the credential check is check-then-act: N concurrent requests all read "not locked", all
            // reach `Hash::check`, and all count afterwards. The increment is transactional and
            // row-locked, so consuming it first makes the count authoritative at the moment it is taken.
            $this->reserve($subjects);

            try {
                $user = $this->resolveWithin($request, $candidate);
            } catch (ValidationException $e) {
                // Only a failed credential feeds the decaying throttle; a 423 or 429 above never reaches here.
                $this->limiter->increment($request);

                throw $e;
            }

            // A success announces itself in its status code, so padding it hides nothing and only
            // taxes every legitimate sign-in. The box is for telling FAILURES apart.
            $timebox->returnEarly();

            return [$user, $subjects];
            // No `max(0, …)`: a Timebox only sleeps a positive remainder, so a negative budget is
            // already no box. The cast is load-bearing — a string from an uncast `env()` would be a
            // TypeError under strict types.
        }, (int) (Lukk::guardConfig()['login_timebox_micros'] ?? 500_000));
    }

    private function resolveWithin(Request $request, ?Authenticatable $candidate): Authenticatable
    {
        if (Lukk::$authenticateUsing !== null) {
            $user = (Lukk::$authenticateUsing)($request);

            if ($user instanceof Authenticatable) {
                return $user;
            }

            $this->fail();
        }

        $credentials = $this->credentials($request);
        $user = $candidate;

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
        if ($user === null) {
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

        // bcrypt reads 72 bytes, so against a bcrypt row a longer password is verified only in part:
        // every string sharing the prefix says yes. NIST SP 800-63B-4 §3.1.1.2 requires verifying the
        // ENTIRE password, and lukk never stores one this long (`HashablePassword`), so such a row came
        // from elsewhere and its owner resets. Decided AFTER the check, so the derivation is still paid.
        $valid = $valid && ! $this->verifiedOnlyInPart($user, $credentials['password']);

        if (! $valid) {
            // Equalize the COST, not just the count. `Hash::check` runs at the cost embedded in the
            // stored hash; `Hash::make` above runs at the configured one. A row left behind by a
            // `BCRYPT_ROUNDS` bump — Laravel 11 raised the default from 10 to 12 — was checked several
            // times faster than an unknown identifier was equalized (15 ms against 118 ms at cost 11),
            // and an unreadable value (`!`, `*`, an import) answered at once. A Timebox shorter than the
            // hash pads none of that, so these also pay one derivation at the configured cost.
            //
            // That includes the password-LESS account — passkey-only, SSO, invited-not-yet-set. The
            // framework answers a null or empty column without deriving anything, which made those
            // the fastest response of all and pointed an attacker at exactly the accounts worth
            // phishing a passkey or a reset link out of. `needsRehash` says yes for both, so the same
            // line covers them; a separate branch for them used to sit above and is no longer needed.
            if ($this->storedHashIsWeak($user)) {
                try {
                    Hash::make($credentials['password']);
                } catch (\Throwable) {
                    // As above: the work is the point; the failure below is the answer.
                }
            }

            $this->fail();
        }

        // What Laravel's own `SessionGuard` does on every successful login, and lukk never did: bring
        // a weaker stored hash up to the configured cost, so rows written before a cost increase stop
        // being both weaker and distinguishable. Off when the application turned it off.
        if (config('hashing.rehash_on_login', true)) {
            try {
                $this->rehash($user, $credentials['password']);
            } catch (\Throwable $e) {
                // A failed upgrade must not fail a correct sign-in; the next one tries again.
                report($e);
            }
        }

        return $user;
    }

    /** Would a bcrypt stored hash ignore part of this password? */
    private function verifiedOnlyInPart(Authenticatable $user, mixed $password): bool
    {
        return is_string($password) && strlen($password) > 72
            && password_get_info((string) $user->getAuthPassword())['algo'] === PASSWORD_BCRYPT;
    }

    /** Would the hasher rehash this stored value — weaker than configured, or not one it can read? */
    private function storedHashIsWeak(Authenticatable $user): bool
    {
        try {
            // A password-less row arrives here as null. Without the cast PHP still answers true, but
            // logs a null-to-string deprecation on every such attempt — noise, not behaviour.
            return Hash::needsRehash((string) $user->getAuthPassword()); // @pest-mutate-ignore: RemoveStringCast
        } catch (\Throwable) {
            return true;
        }
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

    /**
     * Upgrade a weak stored hash — but only the hash this sign-in checked.
     *
     * The row was read at the start of the attempt. Saving that model, as the provider's own
     * `rehashPasswordIfRequired()` does, wrote `Hash::make(<this password>)` over anything committed
     * since: a password reset landing in between was REVERTED, and the session, fingerprinted from the
     * rehashed model, survived the password-unchanged check. So the write is conditional on the stored
     * value still being the one checked. Losing that race to a concurrent upgrade of the same password
     * is harmless, and the model adopts the winner's hash so its own session is not taken for a change.
     *
     * Eloquent users only: another provider gives no conditional write to make, and lukk does not risk
     * the revert for a cost upgrade.
     */
    private function rehash(Authenticatable $user, string $password): void
    {
        // Only a successful check reaches here, so the password is a string; the cast states it.
        $stored = (string) $user->getAuthPassword(); // @pest-mutate-ignore: RemoveStringCast

        if (! $user instanceof Model || ! Hash::needsRehash($stored)) {
            return;
        }

        $column = $user->getAuthPasswordName();
        $upgraded = Hash::make($password);

        if ($user->newQueryWithoutScopes()->whereKey($user->getKey())->where($column, $stored)->update([$column => $upgraded]) === 1) {
            $this->storeRaw($user, $column, $upgraded);

            return;
        }

        // A row deleted meanwhile reads null, which no check accepts either way; the cast states the type.
        $current = (string) $user->newQueryWithoutScopes()->whereKey($user->getKey())->value($column); // @pest-mutate-ignore: RemoveStringCast

        if (Hash::check($password, $current)) {
            $this->storeRaw($user, $column, $current);
        }
    }

    /**
     * Put a hash on the model as stored, past any mutator: a legacy `setPasswordAttribute()` that hashes
     * what it is given would hash the hash, and the session's password fingerprint, taken from this
     * model, would then match nothing stored.
     */
    private function storeRaw(Model $user, string $column, string $hash): void
    {
        $user->setRawAttributes([...$user->getAttributes(), $column => $hash]);
        // Already stored: left dirty, a later `save()` of this instance would write it again, over a
        // reset that landed meanwhile, and observers keyed on `isDirty()` would see a password change.
        $user->syncOriginalAttribute($column);
    }

    /**
     * The account the identifier names, or null — the one provider lookup a sign-in makes.
     *
     * It keys the persistent lockout (`LoginRateLimiter::lockoutSubject()` explains why the identifier
     * alone is not safe to key on there), and the stock path then checks the
     * password against this same row rather than querying again. The lookup sits outside the
     * Timebox; a hit and a miss are one indexed SELECT each, and the derivation the box exists to
     * hide happens inside it.
     *
     * A `Lukk::authenticateUsing` app may name a `lukk.username` that is no column. The lockout
     * documents that it must match, so for such an app the lookup runs only when the lockout is on;
     * otherwise its buckets keep the identifier fold, as before.
     */
    private function candidate(Request $request): ?Authenticatable
    {
        if ($this->lockouts === null && Lukk::$authenticateUsing !== null) {
            return null;
        }

        return $this->users->retrieveByCredentials($this->credentials($request));
    }

    /** @return array<string, string> the identifier under `lukk.username`, and the password */
    private function credentials(Request $request): array
    {
        $field = $this->field();

        return [
            $field => (string) $request->input($field),
            // The identifier cast is load-bearing — a null there becomes `WHERE … IS NULL`, which
            // matches an account with no identifier set. A null password only reaches the hasher,
            // where it fails like any wrong one; the cast keeps it out of a PHP that may refuse it.
            'password' => (string) $request->input('password'), // @pest-mutate-ignore: RemoveStringCast
        ];
    }

    /** The identifier field (config `lukk.username`) — the request field + the error key. */
    private function field(): string
    {
        return Lukk::usernameField();
    }

    private function lockoutGuard(): string
    {
        return $this->limiter->guard();
    }
}
