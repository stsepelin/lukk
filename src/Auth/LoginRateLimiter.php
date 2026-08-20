<?php

declare(strict_types=1);

namespace Lukk\Auth;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Lukk\Lukk;

/**
 * Login throttle: failures-only, over two buckets that trip independently.
 *   - (normalized identifier + IP), capped at `maxAttempts` — the tight per-request-origin limit.
 *   - (normalized identifier) alone, capped at `accountMaxAttempts` — an IP-independent per-account
 *     cap so a distributed attacker (many source IPs) can't get `maxAttempts` guesses *per IP*
 *     against one account. Set it higher than `maxAttempts` so a legitimate multi-device user
 *     isn't locked, but a botnet is still bounded.
 * The identifier (email/username, per `lukk.username`) is trimmed, lowercased, and transliterated
 * so trailing whitespace or Unicode look-alikes can't mint a fresh bucket. Only failed attempts
 * increment; a success clears both.
 */
class LoginRateLimiter
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly int $maxAttempts,
        private readonly int $decaySeconds,
        private readonly int $accountMaxAttempts,
        private readonly string $username = 'email',
        private readonly string $guard = 'api',
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
        return $this->guard.'|'.$this->identifier($request).'|'.Lukk::rateLimitKey($request);
    }

    /** IP-independent per-account bucket (distributed brute-force cap). Guard-scoped, so a flood
     *  on one guard's login can't lock a colliding account out of another guard. */
    public function accountKey(Request $request): string
    {
        return 'acct|'.$this->guard.'|'.$this->identifier($request);
    }

    /** The guard this limiter is scoped to, so a lock on one guard can't reach another. */
    public function guard(): string
    {
        return $this->guard;
    }

    private function identifier(Request $request): string
    {
        return self::normalize((string) $request->input($this->username));
    }

    /**
     * The lockout subject for a login attempt: IDENTITY when the identifier names an account,
     * the normalized identifier when it doesn't.
     *
     * The persistent counter must not key on `normalize()` alone. That map is many-to-one across
     * distinct accounts — `аdmin@x.com` (Cyrillic а) and `ADMIN@x.com` (on any engine whose unique
     * index compares binary) both fold onto `admin@x.com` — so two real accounts shared one lock
     * row. Since a password reset releases on that subject, whoever controlled a look-alike account
     * could lock the victim, reset their own password, clear the victim's lock, and repeat: the
     * §5.2.2 cap degraded back to the decaying throttle it exists to replace.
     *
     * The fallback keeps the two properties that made normalization right in the first place: an
     * identifier naming no account still gets a counter, so being locked is not an existence
     * oracle, and look-alikes of a non-account still collapse into one bucket rather than minting
     * a fresh run each.
     */
    public static function lockoutSubject(?Authenticatable $user, string $identifier): string
    {
        if ($user !== null) {
            return 'id:'.$user->getAuthIdentifier();
        }

        $normalized = self::normalize($identifier);

        // Stay empty when there is nothing to key on. Prefixing an empty identifier would produce
        // the non-empty `idn:`, slipping past the repository's empty-subject refusal and putting
        // every unkeyable caller into ONE never-decaying bucket — locking the whole application at
        // attempt 100. That refusal is the guard; don't hand it a truthy value.
        return $normalized === '' ? '' : 'idn:'.$normalized;
    }

    /**
     * The canonical bucket/lock subject for an identifier.
     *
     * Bounded in BYTES, not characters. `LoginRequest` caps the input at `max:255` characters, but
     * transliteration expands up to ~6x — 43 copies of `㈱` pass validation and come out at 258
     * bytes. That overflows `lukk_lockouts.subject` (varchar 255) and, on Laravel's default
     * `database` cache store, the `cache.key` column too: MySQL strict mode raises 1406 and
     * PostgreSQL 22001, both surfacing as a 500 on the unauthenticated `/auth/login`. Long values
     * are hashed rather than truncated, so two distinct long identifiers can't be folded into one
     * shared bucket by the fix itself.
     */
    public static function normalize(string $identifier): string
    {
        $normalized = Str::transliterate(Str::lower(trim($identifier)));

        return strlen($normalized) > 190 ? 'sha256:'.hash('sha256', $normalized) : $normalized;
    }
}
