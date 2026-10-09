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
use Lukk\Support\AuthenticationMethods;

/**
 * Completes a passwordless passkey login: `store` verifies the assertion against
 * the negotiated ceremony and issues a token pair (`amr: ["pop","user"]`, plus `"mfa"` for a multi-factor assertion).
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
        $passkey = ($this->finishLogin)((string) $request->input('ceremony_id'), $request->array('credential')); // @pest-mutate-ignore: RemoveStringCast

        // Resolve the user rather than minting a session straight off the credential row. The
        // password path runs these gates and this one skipped both: `block_unverified_login` was
        // not enforced (reachable in any app that nulls `email_verified_at` on an email change —
        // the user still has a passkey and walks past the block that refuses their password), and
        // a user deleted since registering their passkey still got a refresh-token row.
        $user = $this->users->retrieveById($passkey->userId);

        abort_if($user === null, 401, 'Unauthenticated.');
        abort_if($this->emailUnverified($user), 403, 'Your email address is not verified.');

        // A passkey stands in for an enrolled second factor only when THIS assertion was multi-factor:
        // its UV flag set on a credential already `uvInitialized` (WebAuthn L3 §4). Not when config
        // says `required` — config is what was asked for; the assertion is what happened, and the
        // spec forbids relying on the flag of a credential that has never shown it to us, which is
        // exactly what a stolen no-PIN key with a PIN set by the thief looks like.
        //
        // The password path has always run this gate; this is the third one the passkey path turned
        // out to be missing, after `block_unverified_login` and the deleted-user check.
        $methods = AuthenticationMethods::passkey($passkey->multiFactor);

        if (! $passkey->multiFactor && $this->twoFactorRequired($user)) {
            return $this->twoFactorChallenge($user, $challengeTokens, $methods);
        }

        // Only now, with a session granted, and only for a multi-factor assertion. It ends a run of
        // password-confirm failures, so it must prove at least what a step-up would: a presence-only
        // key is mere possession, and with a stolen access token it would wipe the count between
        // password guesses forever (NIST SP 800-63B-4 §3.2.2). A refused sign-in proves nothing.
        if ($passkey->multiFactor) {
            $this->finishLogin->releaseConfirmLock($passkey);
        }

        return app(LoginResponse::class, ['pair' => ($this->start)($user->getAuthIdentifier(), ['amr' => $methods])]);
    }
}
