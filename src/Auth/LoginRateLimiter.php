<?php

declare(strict_types=1);

namespace Lukk\Auth;

use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

/**
 * Login throttle: failures-only, over two buckets that trip independently.
 *   - (normalized email + IP), capped at `maxAttempts` — the tight per-request-origin limit.
 *   - (normalized email) alone, capped at `accountMaxAttempts` — an IP-independent per-account
 *     cap so a distributed attacker (many source IPs) can't get `maxAttempts` guesses *per IP*
 *     against one account. Set it higher than `maxAttempts` so a legitimate multi-device user
 *     isn't locked, but a botnet is still bounded.
 * The email is trimmed, lowercased, and transliterated so trailing whitespace or Unicode
 * look-alikes can't mint a fresh bucket. Only failed attempts increment; a success clears both.
 */
class LoginRateLimiter
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly int $maxAttempts,
        private readonly int $decaySeconds,
        private readonly int $accountMaxAttempts,
    ) {}

    public function tooManyAttempts(Request $request): bool
    {
        return $this->limiter->tooManyAttempts($this->key($request), $this->maxAttempts)
            || $this->limiter->tooManyAttempts($this->accountKey($request), $this->accountMaxAttempts);
    }

    public function increment(Request $request): void
    {
        $this->limiter->hit($this->key($request), $this->decaySeconds);
        $this->limiter->hit($this->accountKey($request), $this->decaySeconds);
    }

    public function clear(Request $request): void
    {
        $this->limiter->clear($this->key($request));
        $this->limiter->clear($this->accountKey($request));
    }

    public function availableIn(Request $request): int
    {
        // Whichever bucket is blocking has the longer remaining window.
        return max(
            $this->limiter->availableIn($this->key($request)),
            $this->limiter->availableIn($this->accountKey($request)),
        );
    }

    public function key(Request $request): string
    {
        return $this->email($request).'|'.$request->ip();
    }

    /** IP-independent per-account bucket (distributed brute-force cap). */
    public function accountKey(Request $request): string
    {
        return 'acct|'.$this->email($request);
    }

    private function email(Request $request): string
    {
        return Str::transliterate(Str::lower(trim((string) $request->input('email'))));
    }
}
