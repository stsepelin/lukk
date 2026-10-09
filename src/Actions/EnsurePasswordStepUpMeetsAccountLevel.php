<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Lukk;
use Lukk\Passkeys\PasskeyAssurance;
use Lukk\Support\AuthenticationMethods;
use Lukk\Support\VerifiedToken;

/**
 * A password step-up mints the token that binds and removes authenticators, so it must meet "the
 * maximum AAL currently available in the subscriber account" (NIST SP 800-63B-4 §4.1.2.1).
 *
 * The password is one factor. §2.2.3 lets an AAL2 SESSION reauthenticate with one factor, so the
 * step-up is accepted when the presenting session was multi-factor (`amr` carries `mfa`), or when the
 * account has nothing stronger than the password. It is refused in a single-factor session on an
 * account with a confirmed second factor or a user-verifying passkey — the passkey path's own bar.
 *
 * A session whose token carries no `amr` keeps the old rule: a token minted before the `amr` column
 * existed loses the claim at its first refresh, and a co-issuer's never had one. A token lukk signed
 * cannot be stripped of the claim, so its absence is not something an attacker can arrange.
 */
class EnsurePasswordStepUpMeetsAccountLevel
{
    public function __invoke(Request $request, Authenticatable $user): void
    {
        $amr = VerifiedToken::current($request)?->claims->amr ?? null;

        if (! is_array($amr) || in_array(AuthenticationMethods::MULTI_FACTOR, $amr, true) || ! $this->hasSecondFactor($user)) {
            return;
        }

        throw ValidationException::withMessages(['password' => [
            __('This account has a second factor. Confirm with a passkey that verifies you, or sign in again with your second factor first.'),
        ]]);
    }

    private function hasSecondFactor(Authenticatable $user): bool
    {
        if (method_exists($user, 'hasEnabledTwoFactor') && $user->hasEnabledTwoFactor()) {
            return true;
        }

        // The store first: building the WebAuthn ceremony validates the passkey config, and an account
        // with no passkeys must not have its password step-up fail on a passkey setting.
        return (bool) (Lukk::guardConfig()['features']['passkeys'] ?? false)
            && app(PasskeyRepository::class)->credentialIdsFor($user->getAuthIdentifier()) !== []
            && app(PasskeyAssurance::class)->hasMultiFactorCredential($user);
    }
}
