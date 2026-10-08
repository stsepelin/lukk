<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\ChallengeTwoFactor;
use Lukk\Actions\FinishPasskeyLogin;
use Lukk\Auth\ChallengeToken;
use Lukk\Http\Concerns\IssuesConfirmationToken;
use Lukk\Http\Controllers\Concerns\ChecksPasskeyAssurance;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;
use Lukk\Http\Requests\PasskeyAssertionRequest;
use Lukk\Lukk;

/**
 * Step-up ("sudo") confirmation by passkey: `store` verifies a passkey assertion
 * belonging to the current user and mints the same `confirmation_token` as the
 * password path. FinishPasskeyLogin is method-injected so the password path never
 * pulls in the optional WebAuthn ceremony.
 */
class ConfirmablePasskeyController
{
    use ChecksPasskeyAssurance;
    use IssuesConfirmationToken;
    use ResolvesAuthenticatedUser;

    public function __construct(
        private readonly ChallengeToken $challengeTokens,
    ) {}

    public function store(PasskeyAssertionRequest $request, FinishPasskeyLogin $finishPasskeyLogin): JsonResponse
    {
        // Below `user_verification: required` an assertion proves possession alone, so it must not
        // buy a step-up that the password path charges a password for — gating login and not this
        // made the login gate decorative, since the token minted here unlocks `DELETE
        // /auth/two-factor` and passkey enrolment.
        //
        // Three cases, and only one of them is a refusal:
        //  - the caller HAS a password: refuse, and say so. They have another earner.
        //  - no password but a confirmed second factor: accept the assertion WITH that factor
        //    alongside. Refusing would strand them — `ConfirmPassword` runs `validateCredentials`,
        //    which rejects an empty column, and these two controllers are the only callers of
        //    `IssuesConfirmationToken`, so there would be no way to mint a `reauth` token at all,
        //    including to enrol a second passkey after losing the first. Requiring the factor costs
        //    them nothing they do not already have: they were challenged for it at login.
        //  - neither: accept. Their login is possession-only too on this install, so this route is
        //    not the weak link.
        $user = $this->authenticated($request);

        if (! $this->passkeyIsSecondFactor()) {
            abort_if((string) $user->getAuthPassword() !== '', 403, 'Passkey step-up requires user verification. Confirm with your password instead.');

            // Resolved here, not method-injected: `ChallengeTwoFactor` needs the optional TOTP
            // provider, which an install without `features.two_factor` does not bind.
            if (Lukk::enforcesTwoFactor() && method_exists($user, 'hasEnabledTwoFactor') && $user->hasEnabledTwoFactor()) {
                app(ChallengeTwoFactor::class)($user->getAuthIdentifier(), $request->input('code'), $request->input('recovery_code'));
            }
        }

        // `ceremony_id` is validated as a required string; the cast states it.
        $userId = $finishPasskeyLogin((string) $request->input('ceremony_id'), $request->array('credential')); // @pest-mutate-ignore: RemoveStringCast

        if ((string) $userId !== (string) $this->authenticated($request)->getAuthIdentifier()) {
            throw ValidationException::withMessages(['credential' => [__('That passkey does not belong to you.')]]);
        }

        // Bound to the session presenting it, so the confirmation cannot be replayed by another
        // token the same subject holds.
        return $this->confirmed($this->challengeTokens, $userId, $this->presentingFamily($request));
    }
}
