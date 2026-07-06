<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Lukk\Contracts\TwoFactorChallengeResponse;

/**
 * Post-authentication branching shared by the login + registration controllers: whether the
 * resolved user must clear a 2FA challenge, and whether an unverified email should withhold
 * the session (opt-in). Kept in one home so login and register can never drift apart.
 *
 * Using classes must expose a `Lukk\Auth\ChallengeToken $challengeTokens` property (both
 * controllers do) for {@see twoFactorChallenge()}.
 */
trait DeterminesSessionOutcome
{
    private function twoFactorRequired(Authenticatable $user): bool
    {
        return (bool) config('lukk.features.two_factor')
            && method_exists($user, 'hasEnabledTwoFactor')
            && $user->hasEnabledTwoFactor();
    }

    private function twoFactorChallenge(Authenticatable $user): TwoFactorChallengeResponse
    {
        return app(TwoFactorChallengeResponse::class, ['challenge' => $this->challengeTokens->issue(
            '2fa', $user->getAuthIdentifier(), (int) config('lukk.two_factor.challenge_ttl', 300),
        )]);
    }

    private function emailUnverified(Authenticatable $user): bool
    {
        return (bool) config('lukk.features.email_verification')
            && (bool) config('lukk.email_verification.block_unverified_login')
            && $user instanceof MustVerifyEmail
            && ! $user->hasVerifiedEmail();
    }
}
