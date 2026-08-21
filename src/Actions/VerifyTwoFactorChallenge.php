<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\LockoutRepository;

/**
 * Exchange a 2FA challenge for the verified user: consume the (single-use)
 * challenge, throttle code guesses per account, verify the TOTP/recovery code.
 * The challenge is burned only on success, so a wrong code stays retryable.
 */
class VerifyTwoFactorChallenge
{
    public function __construct(
        private readonly ChallengeToken $challengeTokens,
        private readonly ChallengeTwoFactor $challenge,
        private readonly RateLimiter $limiter,
        private readonly int $maxAttempts,
        private readonly int $decaySeconds,
        // Null unless `features.lockout` is on. The per-account limiter below bounds a rate; this
        // bounds a consecutive run, which is what NIST SP 800-63B §5.2.2 actually requires.
        private readonly ?LockoutRepository $lockouts = null,
        private readonly ?string $guard = null,
    ) {}

    public function __invoke(string $challengeToken, ?string $code, ?string $recoveryCode): Authenticatable
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
        $key = 'lukk:2fa-challenge:'.($this->guard ?? 'api').':'.$userId;
        $subject = (string) $userId;

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
            $this->throwLocked($subject);
        }

        if ($this->limiter->tooManyAttempts($key, $this->maxAttempts)) {
            $seconds = $this->limiter->availableIn($key);

            throw ValidationException::withMessages([
                'code' => [__('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
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
            && $this->lockouts->recordFailure('two_factor', $subject, $this->guard) > $this->lockouts->maxAttempts()) {
            $this->throwLocked($subject);
        }

        try {
            $user = ($this->challenge)($userId, $code, $recoveryCode);
        } catch (ValidationException $e) {
            $this->limiter->hit($key, $this->decaySeconds);

            throw $e;
        }

        // A success ends the run and returns the slot reserved above.
        $this->limiter->clear($key);
        $this->lockouts?->release('two_factor', $subject, $this->guard);
        $this->challengeTokens->consume('2fa', $challengeToken);

        return $user;
    }

    private function throwLocked(string $subject): never
    {
        $seconds = $this->lockouts?->availableIn('two_factor', $subject, $this->guard);

        throw ValidationException::withMessages([
            'code' => [$seconds === null
                ? __('This account is locked. Contact support to restore access.')
                : __('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
        ])->status(423);
    }
}
