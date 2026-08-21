<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\Request;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\Denylist;
use Lukk\Lukk;
use Symfony\Component\HttpFoundation\Response;

/**
 * Gate a route behind a recent step-up confirmation ("sudo" mode). The client
 * earns a confirmation token (POST /auth/confirm-password, or a passkey assertion)
 * and presents it in the configured header; the token is valid for the whole
 * `confirm.ttl` window. Returns 423 Locked when missing/expired/foreign.
 */
class RequireConfirmation
{
    public function __construct(
        private readonly AuthManager $auth,
        private readonly Denylist $denylist,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $token = (string) $request->header((string) config('lukk.confirm.header', 'X-Lukk-Confirmation'), '');
        $subject = $this->challenges()->verify('reauth', $token);

        abort_if(
            $subject === null || $subject !== (string) $request->user()?->getAuthIdentifier(),
            423,
            'This action requires confirmation.',
        );

        return $next($request);
    }

    /**
     * The challenge verifier for the guard that ACTUALLY authenticated this request.
     *
     * Resolving `ChallengeToken` from the container would build it from `GuardContext`, which is
     * set by the `lukk.set-guard` middleware — and that only runs inside lukk's own route groups,
     * never on a consumer's `['auth:admin', 'lukk.confirm']` route. The guard would silently fall
     * back to the default, so an admin route verified its step-up against the USERS guard's key
     * and audience: a confirmation earned on the users guard, for an id that collides across the
     * two providers, satisfied the admin gate. Guards are required to hold distinct audiences
     * (`assertGuardsIsolated`), so verifying under the right one is what closes it.
     *
     * Resolved from the auth manager rather than from `GuardContext`, deliberately. `Authenticate`
     * calls `shouldUse()` for the guard that passed, so the manager always names the guard that
     * authenticated THIS request — whereas `GuardContext` is only reset by `lukk.set-guard`, and a
     * long-lived worker (Octane) would carry the previous request's value into a consumer route
     * that never runs it.
     */
    private function challenges(): ChallengeToken
    {
        return new ChallengeToken(Lukk::guardConfig((string) $this->auth->getDefaultDriver()), $this->denylist);
    }
}
