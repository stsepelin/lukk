<?php

declare(strict_types=1);

namespace Lukk\Auth;

use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

/**
 * Login throttle: per-account, failures-only. The key is (normalized email + IP),
 * transliterated and lowercased so Unicode look-alikes can't mint a fresh
 * bucket. Only failed attempts increment; a success clears the counter.
 */
class LoginRateLimiter
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly int $maxAttempts,
        private readonly int $decaySeconds,
    ) {}

    public function tooManyAttempts(Request $request): bool
    {
        return $this->limiter->tooManyAttempts($this->key($request), $this->maxAttempts);
    }

    public function increment(Request $request): void
    {
        $this->limiter->hit($this->key($request), $this->decaySeconds);
    }

    public function clear(Request $request): void
    {
        $this->limiter->clear($this->key($request));
    }

    public function availableIn(Request $request): int
    {
        return $this->limiter->availableIn($this->key($request));
    }

    public function key(Request $request): string
    {
        return Str::transliterate(Str::lower((string) $request->input('email')).'|'.$request->ip());
    }
}
