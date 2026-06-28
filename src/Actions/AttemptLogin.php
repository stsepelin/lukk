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
    ) {}

    public function __invoke(Request $request): Authenticatable
    {
        $this->ensureIsNotThrottled($request);

        try {
            $user = $this->resolve($request);
        } catch (ValidationException $e) {
            $this->limiter->increment($request);

            throw $e;
        }

        $this->limiter->clear($request);

        return $user;
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

        $credentials = [
            'email' => (string) $request->input('email'),
            'password' => (string) $request->input('password'),
        ];

        $user = $this->users->retrieveByCredentials($credentials);

        if ($user === null) {
            // Run an equivalent hash so an unknown email takes the same time as a
            // wrong password — no user enumeration via timing.
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
            'email' => [__('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
        ])->status(429);
    }

    private function fail(): never
    {
        throw ValidationException::withMessages([
            'email' => [__('These credentials do not match our records.')],
        ]);
    }

    private function timingHash(): string
    {
        static $hash;

        return $hash ??= Hash::make('lukk-timing-equalizer');
    }
}
