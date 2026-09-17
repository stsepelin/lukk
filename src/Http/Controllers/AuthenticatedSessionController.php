<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Lukk\Actions\AttemptLogin;
use Lukk\Actions\EndSession;
use Lukk\Actions\StartSession;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\LoginResponse;
use Lukk\Contracts\LogoutResponse;
use Lukk\Http\Controllers\Concerns\DeterminesSessionOutcome;
use Lukk\Http\Controllers\Concerns\ReadsLogoutCredentials;
use Lukk\Http\Requests\LoginRequest;
use Lukk\Lukk;

/**
 * The password-authenticated session: `store` logs in (issuing a token pair, or a
 * 2FA challenge when enrolled), `destroy` logs the current session out — named by a valid access
 * token or by the refresh token the client holds. Thin — each method runs an Action and returns
 * the bound Response contract.
 */
class AuthenticatedSessionController
{
    use DeterminesSessionOutcome;
    use ReadsLogoutCredentials;

    public function __construct(
        private readonly AttemptLogin $attempt,
        private readonly StartSession $start,
        private readonly EndSession $end,
        private readonly ChallengeToken $challengeTokens,
    ) {}

    public function store(LoginRequest $request): Responsable
    {
        $user = ($this->attempt)($request);

        // Opt-in: refuse login for an unverified email. Runs only after a successful credential
        // check, so it never touches the constant-time unknown-user / wrong-password path.
        //
        // BEFORE the two-factor branch. It used to run after, so an enrolled account was handed a
        // challenge and the redemption route minted a session without ever asking — enrolling a
        // second factor exempted the account from the verification policy. Refusing here rather
        // than only at redemption leaks nothing new (a challenge already says "password correct",
        // exactly as this 403 does on the password-only path) and never lets the client spend a
        // single-use recovery code on a login that is going to be refused.
        abort_if($this->emailUnverified($user), 403, 'Your email address is not verified.');

        if ($this->twoFactorRequired($user)) {
            return $this->twoFactorChallenge($user, $this->challengeTokens);
        }

        return app(LoginResponse::class, ['pair' => ($this->start)($user->getAuthIdentifier(), ['amr' => ['pwd']])]);
    }

    public function destroy(Request $request): LogoutResponse
    {
        $bearer = (string) $request->bearerToken();

        // BEFORE the session is revoked, while the bearer still verifies.
        $this->authenticateBearer($request, $bearer);

        ['tokens' => $refreshTokens, 'cookie' => $cookie] = $this->logoutCredentials($request);

        ($this->end)($bearer, $refreshTokens, Lukk::rateLimitKey($request));

        // Clear the cookie only when one was presented on a request allowed to use it. Clearing on any
        // other request is exactly the cross-site forced logout the credential check exists to stop.
        // A throttled lookup never reaches this line (EndSession throws a 429), so a cookie is never
        // cleared for a session that is still alive.
        return app(LogoutResponse::class, ['clearRefreshCookie' => $cookie]);
    }

    /**
     * Authenticate the request as a valid bearer's user, as `auth:{guard}` did when logout sat behind
     * it — so a rebound `LogoutResponse`, or anything else reading `$request->user()`, still sees the
     * subject. A refresh-token-only logout authenticates nobody: that token proves possession of a
     * session, not an identity check the rest of the app should build on.
     */
    private function authenticateBearer(Request $request, string $bearer): void
    {
        $guard = Lukk::currentGuard();

        if ($bearer !== '' && app('auth')->guard($guard)->check()) {
            app('auth')->shouldUse($guard);
        }
    }
}
