<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Contracts\Support\Responsable;
use Lukk\Actions\Register;
use Lukk\Actions\StartSession;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\RegisterResponse;
use Lukk\Http\Controllers\Concerns\DeterminesSessionOutcome;
use Lukk\Http\Requests\RegisterRequest;

/**
 * First-party registration. `store` creates the user (via `Lukk::registerUsing` or the default
 * create) and fires `Registered`, then — mirroring login — returns a token pair (auto-login), a
 * 2FA challenge if the new user is already enrolled, or a no-session `201` when the account can't
 * log in yet (`registration.login` off, or `block_unverified_login`). Thin: runs the Register
 * action, then returns the bound Response contract.
 */
class RegisteredUserController
{
    use DeterminesSessionOutcome;

    public function __construct(
        private readonly Register $register,
        private readonly StartSession $start,
        private readonly ChallengeToken $challengeTokens,
    ) {}

    public function store(RegisterRequest $request): Responsable
    {
        $user = ($this->register)($request->validated());

        // Auto-login (default): issue a session like login, honoring the same 2FA branch. Skipped
        // when `registration.login` is off (register-only) or block_unverified_login withholds it.
        if (config('lukk.registration.login', true) && ! $this->emailUnverified($user)) {
            if ($this->twoFactorRequired($user)) {
                return $this->twoFactorChallenge($user);
            }

            return app(RegisterResponse::class, ['pair' => ($this->start)($user->getAuthIdentifier(), ['amr' => ['pwd']])]);
        }

        // No session: a 201 with no tokens — never a false 403. `requires_verification` tells the
        // client whether the email must be verified before they can log in (vs. just "please log in").
        return app(RegisterResponse::class, ['pair' => null, 'requiresVerification' => $this->emailUnverified($user)]);
    }
}
