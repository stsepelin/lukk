<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Validation\ValidationException;
use Lukk\Actions\ChallengeTwoFactor;
use Lukk\Actions\ConfirmPasswordUnchanged;
use Lukk\Actions\StartSession;
use Lukk\Actions\VerifyTwoFactorChallenge;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\LoginResponse;
use Lukk\Http\Controllers\Concerns\DeterminesSessionOutcome;
use Lukk\Http\Requests\TwoFactorChallengeRequest;
use Lukk\Support\AuthenticationMethods;

/**
 * Completes a two-factor login: `store` exchanges the challenge token plus a TOTP
 * or recovery code for a full token pair (`amr: ["pwd","otp","mfa"]`, or the
 * passkey's methods in place of `pwd` when a passkey sign-in was routed here).
 */
class TwoFactorChallengedSessionController
{
    use DeterminesSessionOutcome;

    public function __construct(
        private readonly VerifyTwoFactorChallenge $verifyChallenge,
        private readonly StartSession $start,
        private readonly ChallengeToken $challengeTokens,
        private readonly ConfirmPasswordUnchanged $passwordUnchanged,
        private readonly ChallengeTwoFactor $challengeTwoFactor,
    ) {}

    public function store(TwoFactorChallengeRequest $request): LoginResponse
    {
        // `TwoFactorChallengeRequest` validates it `required|string`, so the cast is the declared type, not a conversion.
        $challenge = (string) $request->input('challenge_token'); // @pest-mutate-ignore: RemoveStringCast
        // Read before the challenge is spent — a consumed one no longer decodes.
        $checked = $this->challengeTokens->passwordFingerprintOf('2fa', $challenge);
        // Same reason, same place. How the FIRST factor was proved, so the session records it
        // truthfully instead of hardcoding `['pwd','otp']`: a passkey login routed here by the
        // user-verification gate was asserting a password the account may not even have, and `amr`
        // is durable now, so that would ride every rotation for the family's whole life. A challenge
        // that does not say — an older one, or a co-issuer's — is assumed to be the password path.
        $firstFactor = $this->challengeTokens->firstFactorOf('2fa', $challenge) ?? AuthenticationMethods::password();

        // A challenge whose password has been replaced since — or that never said which one it stands in
        // for — is refused BEFORE the second factor is checked. It used to be refused only after: by then
        // the factor was spent (a single-use recovery code burned, a TOTP code marked used) and a session
        // started only to be revoked. A challenge that does not decode is left to the verification below,
        // which answers it the same way. The check after the session is written still runs: it is the one
        // that closes the race with a change landing in between.
        $subject = $this->challengeTokens->verify('2fa', $challenge);

        if ($subject !== null && ! $this->passwordUnchanged->holds($subject, $checked)) {
            throw ValidationException::withMessages(['challenge_token' => [__('The two-factor challenge is invalid or has expired.')]]);
        }

        // The email-verification gate, likewise BEFORE the factor is checked. It used to run only after:
        // a challenge that outlived the account's verified state — minted before an email change nulled
        // `email_verified_at`, or before the flag was switched on — burned a single-use recovery code on a
        // sign-in that was always going to be refused. Answering 403 to a holder who has not presented a
        // valid factor tells them nothing new: the challenge proves they passed the password, and login
        // answers the same 403 at that same point.
        $candidate = $subject === null ? null : $this->challengeTwoFactor->subject($subject);
        abort_if($candidate !== null && $this->emailUnverified($candidate), 403, 'Your email address is not verified.');

        $user = ($this->verifyChallenge)(
            $challenge,
            $request->input('code'),
            $request->input('recovery_code'),
        );

        // The same gate again, on the user the factor was verified for: the check above does not close the
        // race with an email change landing while the factor was being checked, and losing it would be a
        // session for an account the policy says must not have one.
        abort_if($this->emailUnverified($user), 403, 'Your email address is not verified.');

        $pair = ($this->start)($user->getAuthIdentifier(), ['amr' => AuthenticationMethods::withOneTimePassword($firstFactor)]);

        // The first factor was a password checked up to `challenge_ttl` ago. Changed or reset since, the
        // challenge stood in for a credential the account no longer has — see `ConfirmPasswordUnchanged`.
        ($this->passwordUnchanged)(
            $user->getAuthIdentifier(), $checked, $pair,
            'challenge_token', __('The two-factor challenge is invalid or has expired.'),
        );

        return app(LoginResponse::class, ['pair' => $pair]);
    }
}
