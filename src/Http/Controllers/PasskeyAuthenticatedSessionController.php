<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Contracts\Auth\UserProvider;
use Lukk\Actions\FinishPasskeyLogin;
use Lukk\Actions\StartSession;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\LoginResponse;
use Lukk\Contracts\TwoFactorChallengeResponse;
use Lukk\Http\Controllers\Concerns\DeterminesSessionOutcome;
use Lukk\Http\Requests\PasskeyAssertionRequest;

/**
 * Completes a passwordless passkey login: `store` verifies the assertion against
 * the negotiated ceremony and issues a token pair (`amr: ["webauthn"]`).
 */
class PasskeyAuthenticatedSessionController
{
    use DeterminesSessionOutcome;

    public function __construct(
        private readonly FinishPasskeyLogin $finishLogin,
        private readonly StartSession $start,
        private readonly UserProvider $users,
    ) {}

    // `ChallengeToken` is method-injected, like `ConfirmablePasskeyController` injects
    // `FinishPasskeyLogin`: it is only needed on the branch that challenges.
    public function store(PasskeyAssertionRequest $request, ChallengeToken $challengeTokens): LoginResponse|TwoFactorChallengeResponse
    {
        // `ceremony_id` is validated as a required string; the cast states it.
        $userId = ($this->finishLogin)((string) $request->input('ceremony_id'), $request->array('credential')); // @pest-mutate-ignore: RemoveStringCast

        // Resolve the user rather than minting a session straight off the credential row. The
        // password path runs these gates and this one skipped both: `block_unverified_login` was
        // not enforced (reachable in any app that nulls `email_verified_at` on an email change —
        // the user still has a passkey and walks past the block that refuses their password), and
        // a user deleted since registering their passkey still got a refresh-token row.
        $user = $this->users->retrieveById($userId);

        abort_if($user === null, 401, 'Unauthenticated.');
        abort_if($this->emailUnverified($user), 403, 'Your email address is not verified.');

        // A passkey stands in for the second factor only when user verification is REQUIRED — see
        // `passkeyIsSecondFactor()`. Below that it is possession alone, and skipping a confirmed TOTP
        // for it would hand whoever holds the authenticator a full session, then let them spend it on
        // `DELETE /auth/two-factor`. The password path has always run this gate; this one is the third
        // gate it turned out to be missing, after `block_unverified_login` and the deleted-user check.
        if (! $this->passkeyIsSecondFactor() && $this->twoFactorRequired($user)) {
            return $this->twoFactorChallenge($user, $challengeTokens, ['webauthn']);
        }

        return app(LoginResponse::class, ['pair' => ($this->start)($user->getAuthIdentifier(), ['amr' => ['webauthn']])]);
    }
}
