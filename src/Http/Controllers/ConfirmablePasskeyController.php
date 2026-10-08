<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\FinishPasskeyLogin;
use Lukk\Auth\ChallengeToken;
use Lukk\Http\Concerns\IssuesConfirmationToken;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;
use Lukk\Http\Requests\PasskeyAssertionRequest;
use Lukk\Passkeys\PasskeyAssurance;

/**
 * Step-up ("sudo") confirmation by passkey: `store` verifies a passkey assertion
 * belonging to the current user and mints the same `confirmation_token` as the
 * password path. FinishPasskeyLogin is method-injected so the password path never
 * pulls in the optional WebAuthn ceremony.
 *
 * The bar is the ACCOUNT's own highest available level (NIST SP 800-63B-4 §4.1.2.1) — see
 * `PasskeyAssurance`. A multi-factor assertion always meets it. A single-factor one meets it only
 * when the account has nothing stronger: it is refused when the account has a password or a
 * user-verifying passkey, and accepted for a password-less account whose credentials are all
 * single-factor, which would otherwise have no way to mint a confirmation at all.
 *
 * It takes no TOTP code. A TOTP is possession, the same category as the passkey, so it cannot lift
 * the step-up to AAL2 (§2.2.1) — and accepting one here opened a second TOTP oracle that skipped the
 * two-factor lockout entirely.
 */
class ConfirmablePasskeyController
{
    use IssuesConfirmationToken;
    use ResolvesAuthenticatedUser;

    public function __construct(
        private readonly ChallengeToken $challengeTokens,
    ) {}

    public function store(PasskeyAssertionRequest $request, FinishPasskeyLogin $finishPasskeyLogin, PasskeyAssurance $assurance): JsonResponse
    {
        $user = $this->authenticated($request);

        // The authenticator is asked for user verification whenever the account can reach AAL2, and
        // the SAME requirement is enforced here — not merely hinted in the options — so a client that
        // asked the anonymous login endpoint for laxer options gains nothing.
        // `ceremony_id` is validated as a required string; the cast states it.
        $passkey = $finishPasskeyLogin(
            (string) $request->input('ceremony_id'), // @pest-mutate-ignore: RemoveStringCast
            $request->array('credential'),
            $assurance->requiredUserVerification($user),
        );

        if ((string) $passkey->userId !== (string) $user->getAuthIdentifier()) {
            throw ValidationException::withMessages(['credential' => [__('That passkey does not belong to you.')]]);
        }

        // 422, not 403: on a step-up route 403 means "this TOKEN may never confirm", and clients abandon
        // the prompt on it. Here only the credential fell short; the password or another passkey works.
        if (! $assurance->permitsStepUp($user, $passkey)) {
            throw ValidationException::withMessages(['credential' => [__('This account needs a passkey that verifies you (PIN or biometric), or your password.')]]);
        }

        // Bound to the session presenting it, so the confirmation cannot be replayed by another
        // token the same subject holds.
        return $this->confirmed($this->challengeTokens, $passkey->userId, $this->presentingFamily($request));
    }
}
