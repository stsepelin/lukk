<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Lukk\Actions\AttemptLogin;
use Lukk\Actions\RevokeSession;
use Lukk\Actions\StartSession;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\LoginResponse;
use Lukk\Contracts\LogoutResponse;
use Lukk\Contracts\TokenVerifier;
use Lukk\Http\Controllers\Concerns\DeterminesSessionOutcome;
use Lukk\Http\Requests\LoginRequest;

/**
 * The password-authenticated session: `store` logs in (issuing a token pair, or a
 * 2FA challenge when enrolled), `destroy` logs the current session out. Thin —
 * each method runs an Action and returns the bound Response contract.
 */
class AuthenticatedSessionController
{
    use DeterminesSessionOutcome;

    public function __construct(
        private readonly AttemptLogin $attempt,
        private readonly StartSession $start,
        private readonly RevokeSession $revoke,
        private readonly ChallengeToken $challengeTokens,
    ) {}

    public function store(LoginRequest $request): Responsable
    {
        $user = ($this->attempt)($request);

        if ($this->twoFactorRequired($user)) {
            return $this->twoFactorChallenge($user);
        }

        // Opt-in: refuse login for an unverified email. Runs only after a successful credential
        // check, so it never touches the constant-time unknown-user / wrong-password path.
        abort_if($this->emailUnverified($user), 403, 'Your email address is not verified.');

        return app(LoginResponse::class, ['pair' => ($this->start)($user->getAuthIdentifier(), ['amr' => ['pwd']])]);
    }

    public function destroy(Request $request, TokenVerifier $verifier): LogoutResponse
    {
        $claims = $verifier->verify((string) $request->bearerToken());

        if ($claims !== null && isset($claims->fid)) {
            ($this->revoke)((string) $claims->fid);
        }

        return app(LogoutResponse::class);
    }
}
