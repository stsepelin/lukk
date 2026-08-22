<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\TwoFactorChallengeResponse;
use Lukk\Lukk;

/**
 * Post-authentication branching shared by the login + registration controllers: whether the
 * resolved user must clear a 2FA challenge, and whether an unverified email should withhold
 * the session (opt-in). Kept in one home so login and register can never drift apart.
 *
 * `twoFactorChallenge()` takes its `ChallengeToken` as an ARGUMENT rather than reading a property
 * off the using class. It used to require `$this->challengeTokens`, which was an unenforceable
 * contract: `PasskeyAuthenticatedSessionController` uses this trait and has no such property. That
 * was harmless only because passkey login is already multi-factor and never reaches the challenge —
 * an invisible coupling one refactor away from a fatal.
 */
trait DeterminesSessionOutcome
{
    private function twoFactorRequired(Authenticatable $user): bool
    {
        // `Lukk::guardConfig()`, never the global block — the same rule CLAUDE.md records for
        // `features.abilities` and `gate_auth_routes`. Read globally, a guard that switches two-factor
        // OFF was still challenged, and one that switches it ON was not.
        return (bool) (Lukk::guardConfig()['features']['two_factor'] ?? false)
            && method_exists($user, 'hasEnabledTwoFactor')
            && $user->hasEnabledTwoFactor();
    }

    private function twoFactorChallenge(Authenticatable $user, ChallengeToken $challengeTokens): TwoFactorChallengeResponse
    {
        return app(TwoFactorChallengeResponse::class, ['challenge' => $challengeTokens->issue(
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
