<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;
use Lukk\Auth\ChallengeToken;

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

            throw $e;
        }

        $this->limiter->clear($key);
        $this->challengeTokens->consume('2fa', $challengeToken);

        return $user;
    }
}
