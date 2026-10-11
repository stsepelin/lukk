<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\Concerns\CountsLockoutAttempts;
use Lukk\Actions\Concerns\ThrowsWhenLocked;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\LockoutRepository;
use Lukk\Lukk;

/**
 * Exchange a 2FA challenge for the verified user: consume the (single-use)
 * challenge, throttle code guesses per account, verify the TOTP/recovery code.
 * The challenge is burned only on success, so a wrong code stays retryable.
 */
class VerifyTwoFactorChallenge
{
    use CountsLockoutAttempts;
    use ThrowsWhenLocked;

    public function __construct(
        private readonly ChallengeToken $challengeTokens,
        private readonly ChallengeTwoFactor $challenge,
        private readonly RateLimiter $limiter,
        private readonly int $maxAttempts,
        private readonly int $decaySeconds,
        // Null unless `features.lockout` is on. The per-account limiter below bounds a rate; this
        // bounds a consecutive run, which is what NIST SP 800-63B-4 §3.2.2 actually requires.
        private readonly ?LockoutRepository $lockouts = null,
        private readonly ?string $guard = null,
    ) {}

    public function __invoke(#[\SensitiveParameter] string $challengeToken, #[\SensitiveParameter] ?string $code, #[\SensitiveParameter] ?string $recoveryCode): Authenticatable
    {
        $userId = $this->challengeTokens->verify('2fa', $challengeToken);

        if ($userId === null) {
            throw ValidationException::withMessages([
                'challenge_token' => [__('The two-factor challenge is invalid or has expired.')],
            ]);
        }

        // Guard-scoped like every other lukk bucket. 2FA mounts only on the default guard today, so
        // an unprefixed key is not yet reachable — but it is exactly the colliding-ids-across-
        // providers hazard the multi-guard work exists to remove, and it would go live silently the
        // moment the feature surfaces extend to another guard.
        $key = 'lukk:2fa-challenge:'.($this->guard ?? Lukk::defaultGuard()).':'.$userId;
        // `verify()` returns `?string` and the null branch threw above, so this is already a string.
        $subject = (string) $userId; // @pest-mutate-ignore: RemoveStringCast

        // A recovery code is the way OUT of a lock, so it must not be gated by one: it's ~119 bits
        // of entropy, single-use and salted+hashed, so a consecutive cap protects nothing there —
        // while gating it would strand a user whose second factor an attacker deliberately burned.
        //
        // The exemption is for a recovery-code-ONLY attempt. Keying it on the mere PRESENCE of the
        // field handed the cap away: `ChallengeTwoFactor` tries the TOTP code first, so attaching
        // any junk recovery code to a guess skipped the lock and resumed brute-forcing the 6-digit
        // space — including against an account already locked.
        $recoveryOnly = ($code === null || $code === '') && $recoveryCode !== null && $recoveryCode !== '';

        if (! $recoveryOnly && $this->lockouts?->locked('two_factor', $subject, $this->guard)) {
            $this->throwLocked('two_factor', $subject, 'code');
        }

        // COUNTED before the code is checked, and refused on the post-increment count. Reading
        // `tooManyAttempts()` and hitting only after a failure was check-then-act: requests arriving
        // together all read "under budget" before any of them counted, so a burst got as many guesses as
        // it had requests — RFC 6238 §5.2 and NIST SP 800-63B-4 §3.2.2 both ask the verifier to limit
        // failed attempts, which that did not. `hit()` is the cache's atomic increment, so only
        // `max_attempts` requests can ever see a count within budget. A success clears it below, so a
        // correct code costs nothing.
        if ($this->limiter->hit($key, $this->decaySeconds) > $this->maxAttempts) {
            $seconds = $this->limiter->availableIn($key);

            // The cast only tidies the type: the translator stringifies replacements, and `2.0` is "2".
            throw ValidationException::withMessages([
                'code' => [__('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])], // @pest-mutate-ignore: RemoveIntegerCast
            ])->status(429);
        }

        // Reserved before the code is checked, like the login and confirm paths: counting after
        // would let concurrent requests each get a guess past a "not locked yet" read.
        //
        // Only a TOTP attempt is reserved. Counting recovery-code failures too would let someone
        // holding a challenge token drive the account into a two-factor lock without ever guessing
        // a TOTP — and the cap exists for a 6-digit secret, not for a 119-bit one. The decaying
        // limiter above still bounds recovery guessing.
        if (! $recoveryOnly && $this->lockouts !== null
            && $this->reserveAttempt($this->lockouts, 'two_factor', $subject) > $this->lockouts->maxAttempts()) {
            $this->throwLocked('two_factor', $subject, 'code');
        }

        try {
            $user = ($this->challenge)($userId, $code, $recoveryCode);
        } catch (ValidationException $e) {
            // The lock lands only now that the factor failed (`CountsLockoutAttempts`) — and only for an
            // attempt that reserved, so a recovery-code-only failure still drives no lock.
            if (! $recoveryOnly) {
                $this->attemptFailed($this->lockouts, 'two_factor', $subject);
            }

            throw $e;
        }

        // A success ends the run and returns the slot reserved above.
        $this->limiter->clear($key);
        $this->lockouts?->release('two_factor', $subject, $this->guard);
        // Spent atomically: a concurrent request presenting the same challenge with another valid factor
        // loses here, rather than also getting a session.
        if ($this->challengeTokens->consume('2fa', $challengeToken) === null) {
            throw ValidationException::withMessages([
                'challenge_token' => [__('The two-factor challenge is invalid or has expired.')],
            ]);
        }

        return $user;
    }

    private function lockoutGuard(): ?string
    {
        return $this->guard;
    }
}
