<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\Concerns\ThrowsWhenLocked;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Contracts\LockoutRepository;
use Lukk\Lukk;

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
            'password' => (string) $request->input('password'),
        ];

        $user = $this->users->retrieveByCredentials($credentials);

        if ($user === null) {
            // Equivalent hash so an unknown email costs the same as a wrong password (no timing enumeration).
            Hash::check($credentials['password'], $this->timingHash());
            $this->fail();
        }

        if (! $this->users->validateCredentials($user, $credentials)) {
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

        throw ValidationException::withMessages([
            $this->field() => [__('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
        ])->status(429);
    }

    private function fail(): never
    {
        throw ValidationException::withMessages([
            $this->field() => [__('These credentials do not match our records.')],
        ]);
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
            return '';
        }

        $identifier = (string) $request->input($this->field());

        return LoginRateLimiter::lockoutSubject(
            $this->users->retrieveByCredentials([$this->field() => $identifier]),
            $identifier,
        );
    }

    private function field(): string
    {
        return (string) config('lukk.username', 'email');
    }

    private function timingHash(): string
    {
        static $hash;

        return $hash ??= Hash::make('lukk-timing-equalizer');
    }

    private function lockoutGuard(): string
    {
        return $this->limiter->guard();
    }
}
