<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Lukk\Actions\ConfirmPasswordUnchanged;
use Lukk\Actions\StartSession;
use Lukk\Actions\VerifyTwoFactorChallenge;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\LoginResponse;
use Lukk\Http\Controllers\Concerns\DeterminesSessionOutcome;
use Lukk\Http\Requests\TwoFactorChallengeRequest;

/**
 * Completes a two-factor login: `store` exchanges the challenge token plus a TOTP
 * or recovery code for a full token pair (`amr: ["pwd","otp"]`).
 */
class TwoFactorChallengedSessionController
{
    use DeterminesSessionOutcome;

    public function __construct(
        private readonly VerifyTwoFactorChallenge $verifyChallenge,
        private readonly StartSession $start,
        private readonly ChallengeToken $challengeTokens,
        private readonly ConfirmPasswordUnchanged $passwordUnchanged,
    ) {}

    public function store(TwoFactorChallengeRequest $request): LoginResponse
    {
        // `TwoFactorChallengeRequest` validates it `required|string`, so the cast is the declared type, not a conversion.
        $challenge = (string) $request->input('challenge_token'); // @pest-mutate-ignore: RemoveStringCast
        // Read before the challenge is spent — a consumed one no longer decodes.
        $checked = $this->challengeTokens->passwordFingerprintOf('2fa', $challenge);

        $user = ($this->verifyChallenge)(
            $challenge,
            $request->input('code'),
            $request->input('recovery_code'),
        );

        // The same gate as every other session-minting path. Login already refuses an unverified
        // account before issuing a challenge; this covers a challenge that outlived the account's
        // verified state — minted before an email change nulled `email_verified_at`, or before the
        // flag was switched on. It runs after the second factor verified because only then is the
        // subject known, so in that narrow window a recovery code is spent; the alternative is a
        // session for an account the policy says must not have one.
        abort_if($this->emailUnverified($user), 403, 'Your email address is not verified.');

        $pair = ($this->start)($user->getAuthIdentifier(), ['amr' => ['pwd', 'otp']]);

        // The first factor was a password checked up to `challenge_ttl` ago. Changed or reset since, the
        // challenge stood in for a credential the account no longer has — see `ConfirmPasswordUnchanged`.
        ($this->passwordUnchanged)(
            $user->getAuthIdentifier(), $checked, $pair,
            'challenge_token', __('The two-factor challenge is invalid or has expired.'),
        );

        return app(LoginResponse::class, ['pair' => $pair]);
    }
}
