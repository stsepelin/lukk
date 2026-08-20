<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
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
        $this->ensureIsNotLocked($request);
        $this->ensureIsNotThrottled($request);

        try {
            $user = $this->resolve($request);
        } catch (ValidationException $e) {
            $this->limiter->increment($request);
            $this->lockouts?->recordFailure('login', $this->limiter->subject($request), $this->limiter->guard());

            throw $e;
        }

        $this->limiter->clear($request);
        // "Consecutive" is the whole point of the cap: any success ends the run.
        $this->lockouts?->release('login', $this->limiter->subject($request), $this->limiter->guard());

        return $user;
    }

    /**
     * NIST SP 800-63B §5.2.2. Distinct from the throttles above: those bound a RATE and clear
     * themselves, this bounds a RUN and is held until something releases it. 423 rather than 429
     * because "retry later" may be untrue — with `release_after` at 0 it needs intervention.
     */
    private function ensureIsNotLocked(Request $request): void
    {
        $subject = $this->limiter->subject($request);

        if ($this->lockouts === null || ! $this->lockouts->locked('login', $subject, $this->limiter->guard())) {
            return;
        }

        $seconds = $this->lockouts->availableIn('login', $subject, $this->limiter->guard());

        throw ValidationException::withMessages([
            $this->field() => [$seconds === null
                ? __('This account is locked. Contact support to restore access.')
                : __('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
        ])->status(423);
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
    private function field(): string
    {
        return (string) config('lukk.username', 'email');
    }

    private function timingHash(): string
    {
        static $hash;

        return $hash ??= Hash::make('lukk-timing-equalizer');
    }
}
