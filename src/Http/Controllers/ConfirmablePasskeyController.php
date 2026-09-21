<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\FinishPasskeyLogin;
use Lukk\Auth\ChallengeToken;
use Lukk\Http\Concerns\IssuesConfirmationToken;
use Lukk\Http\Controllers\Concerns\ChecksPasskeyAssurance;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;
use Lukk\Http\Requests\PasskeyAssertionRequest;

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
        // Refused only when the caller HAS that password, though. `ConfirmPassword` runs
        // `validateCredentials`, which returns false for an empty column, and these two controllers
        // are the only callers of `IssuesConfirmationToken` — so refusing both leaves a passkey-only,
        // SSO or invited-not-yet-set account no way to mint a `reauth` token at all: it could not
        // enrol a SECOND passkey, which is the only self-service recovery from a lost authenticator,
        // and `features.password_reset` is off by default. That is an unrecoverable account, traded
        // for an assurance level the same install already grants at login: under `preferred` those
        // users sign in on possession alone too, so this route is not the weak link for them.
        //
        // The residual is a password-less account with a CONFIRMED second factor: its login is
        // stronger (the 2FA gate challenges) than this step-up. Refusing would strand it, and there
        // is no flow to demand the second factor here, so it is allowed and recorded as a known gap.
        $confirmable = (string) $this->authenticated($request)->getAuthPassword() !== '';

        abort_if(! $this->passkeyIsSecondFactor() && $confirmable, 403, 'Passkey step-up requires user verification. Confirm with your password instead.');

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
