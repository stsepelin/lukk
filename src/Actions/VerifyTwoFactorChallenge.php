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

        $key = 'lukk:2fa-challenge:'.$userId;
        $subject = (string) $userId;

        // A recovery code is the way OUT of a lock, so it must not be gated by one: it's ~119 bits
        // of entropy, single-use and salted+hashed, so a consecutive cap protects nothing there —
        // while gating it would strand a user whose second factor an attacker deliberately burned.
        if ($recoveryCode === null && $this->lockouts?->locked('two_factor', $subject, $this->guard)) {
            $seconds = $this->lockouts->availableIn('two_factor', $subject, $this->guard);

            throw ValidationException::withMessages([
                'code' => [$seconds === null
                    ? __('This account is locked. Contact support to restore access.')
                    : __('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
            ])->status(423);
        }

        if ($this->limiter->tooManyAttempts($key, $this->maxAttempts)) {
            $seconds = $this->limiter->availableIn($key);

            throw ValidationException::withMessages([
                'code' => [__('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
            ])->status(429);
        }

        try {
            $user = ($this->challenge)($userId, $code, $recoveryCode);
        } catch (ValidationException $e) {
            $this->limiter->hit($key, $this->decaySeconds);
            $this->lockouts?->recordFailure('two_factor', $subject, $this->guard);

            throw $e;
        }

        $this->limiter->clear($key);
        $this->lockouts?->release('two_factor', $subject, $this->guard);
        $this->challengeTokens->consume('2fa', $challengeToken);

        return $user;
    }
}
