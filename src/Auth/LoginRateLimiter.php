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

    /*
     * `$subject` is the account the identifier names — `lockoutSubject()` — when the caller resolved
     * it. Every attempt then counts in TWO pairs of buckets, and either pair trips the gate:
     *
     *  - the identifier FOLD (case, script), which every spelling shares whether or not an account
     *    exists — so a variant spelling of a real account is throttled exactly like one of a
     *    non-account, and 429 says nothing about existence;
     *  - the ACCOUNT, which only that account's own success clears — so a look-alike account's owner,
     *    who shares the fold and can clear it, cannot reset the victim's count.
     *
     * The price is the fold's: a victim's failures can briefly throttle a look-alike account too.
     */

    public function tooManyAttempts(Request $request, ?string $subject = null): bool
    {
        foreach ($this->buckets($request, $subject) as [$key, $max]) {
            if ($this->limiter->tooManyAttempts($key, $max)) {
                return true;
            }
        }

        return false;
    }

    public function increment(Request $request, ?string $subject = null): void
    {
        foreach ($this->buckets($request, $subject) as [$key]) {
            $this->limiter->hit($key, $this->decaySeconds);
        }
    }

    public function clear(Request $request, ?string $subject = null): void
    {
        foreach ($this->buckets($request, $subject) as [$key]) {
            $this->limiter->clear($key);
        }
    }

    public function availableIn(Request $request, ?string $subject = null): int
    {
        // Whichever bucket is blocking has the longest remaining window.
        return max(array_map(fn (array $bucket) => $this->limiter->availableIn($bucket[0]), $this->buckets($request, $subject)));
    }

    /** @return non-empty-list<array{0: string, 1: int}> each bucket key with its limit */
    private function buckets(Request $request, ?string $subject): array
    {
        $buckets = [[$this->key($request), $this->maxAttempts], [$this->accountKey($request), $this->accountMaxAttempts]];

        if ($subject !== null) {
            $buckets[] = [$this->key($request, $subject), $this->maxAttempts];
            $buckets[] = [$this->accountKey($request, $subject), $this->accountMaxAttempts];
        }

        return $buckets;
    }

    public function key(Request $request, ?string $subject = null): string
    {
        return $this->guard.'|'.$this->identifierKey($request, $subject).'|'.Lukk::rateLimitKey($request);
    }

    /** IP-independent per-account bucket (distributed brute-force cap). Guard-scoped, so a flood
     *  on one guard's login can't lock a colliding account out of another guard. */
    public function accountKey(Request $request, ?string $subject = null): string
    {
        return 'acct|'.$this->guard.'|'.$this->identifierKey($request, $subject);
    }

    /**
     * The identifier's contribution to a cache key: HASHED, never the identifier itself.
     *
     * These keys reach `Illuminate\Cache\RateLimiter` directly, so they never get the md5 that
     * `ThrottleRequests` applies — only `cleanRateLimiterKey`, which is `htmlentities()` plus an
     * entity-shortening regex, i.e. a MANY-TO-ONE fold. `a&b@x.com` and `aab@x.com` are both valid
     * addresses and both land on the key `aab@x.com`, so they shared a bucket. Since a successful
     * login calls `clear()`, and `clear()` cleans the key the same way, whoever registered the
     * look-alike could reset the victim's per-account counter on demand — and that counter is the
     * IP-INDEPENDENT one, the backstop that exists so a distributed attacker can't get
     * `max_attempts` guesses per IP against one account. That left only the per-IP cap it backstops.
     *
     * Hashing also puts the `|` delimiter out of reach of an identifier field that carries no
     * charset rule, so a submitted identifier can no longer shape the key's structure.
     *
     * **Hashing alone does not make these buckets per-account.** `normalize()` is many-to-one by
     * design — `Str::transliterate` folds Cyrillic `а` onto `a` and `Str::lower` folds case, neither
     * of which a binary-collation unique index folds — so `аdmin@x.com` and `admin@x.com` would share
     * a bucket, and a successful sign-in to the look-alike would `clear()` the victim's counter. The
     * fold is deliberate for identifiers that name no account: without it an attacker spreads guesses
     * across spellings and evades the bucket. So `AttemptLogin` resolves the account first and passes
     * `lockoutSubject()`, which keys on identity when there is one and on the fold when there is not.
     *
     * Equality-compared only, so nothing else about the limiter changes. Existing buckets are
     * orphaned on deploy, which costs at most one decay window of counting.
     */
    private function identifierKey(Request $request, ?string $subject): string
    {
        return hash('sha256', $subject ?? $this->identifier($request));
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
        //
        // A DIGEST, never the identifier. What was typed is often someone's real address, or a
        // stranger's; a held lock is never pruned, and no account exists through which its owner
        // could have it erased. The counter only compares for equality, so nothing is lost.
        return $normalized === '' ? '' : 'idn:sha256:'.hash('sha256', $normalized);
    }

    /**
     * The plain-text subject releases before 0.7 wrote for an identifier naming no account. Read
     * only to release, erase and export those rows; nothing writes this form any more.
     */
    public static function legacyLockoutSubject(string $identifier): string
    {
        $normalized = self::normalize($identifier);

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
