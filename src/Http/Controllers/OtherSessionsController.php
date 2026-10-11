<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Lukk\Actions\RevokeOtherSessions;
use Lukk\Contracts\TokenVerifier;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;
use Lukk\Http\Controllers\Concerns\ResolvesCurrentFamily;
use Lukk\Lukk;

/**
 * The user's *other* sessions: `destroy` revokes every session except the one
 * making the request (resolved from the bearer token's family id).
 *
 * Answers a bare 204 directly, NOT through `LogoutResponse`. That contract ends the CALLER's session
 * client-side — in cookie mode it clears the refresh cookie — while this route deliberately keeps the
 * caller's session alive, so borrowing it left the client unable to refresh a session the server
 * still considered live. A fixed acknowledgement is not a swap seam (CLAUDE.md), so no contract.
 */
class OtherSessionsController
{
    use ResolvesAuthenticatedUser;
    use ResolvesCurrentFamily;

    public function __construct(
        private readonly RevokeOtherSessions $revokeOthers,
    ) {}

    public function destroy(Request $request, TokenVerifier $verifier): Response|JsonResponse
    {
        $currentFamilyId = $this->currentFamilyId($request, $verifier);

        if ($currentFamilyId === null) {
            // A bearer that names no session: a co-issuer sharing the secret, in the verify-only
            // topology. "Others" is defined relative to THIS session, so with no family to except
            // there is nothing this route can honestly do — revoking everything would take the
            // caller's own session with it, which is the one thing it promises not to do (that is
            // why it exists alongside `DELETE /auth/sessions`).
            //
            // So it refuses instead of pretending. It used to answer 204 having revoked nothing,
            // which is the worse of the two failures: the user pressed "log out my other devices",
            // the client read success, and an attacker's session stayed live for the rest of its
            // refresh_ttl with nothing anywhere saying so. Revoking nothing is the right ACTION;
            // reporting it as success was the defect.
            if ((string) $request->bearerToken() !== '') {
                return response()->json(['message' => $this->noSessionMessage($request)], 409);
            }

            // No bearer at all: `Lukk::actingAs()` authenticates the guard directly. A test harness,
            // not a deployment — refusing here would fail every consumer test using the package's
            // own documented helper, so it keeps the historical no-op.
            return response()->noContent();
        }

        ($this->revokeOthers)($this->authenticated($request)->getAuthIdentifier(), $currentFamilyId);

        return response()->noContent();
    }

    /**
     * The refusal, naming the revoke-all route where THIS guard mounts it — read from the route that
     * answered, so a custom `lukk.path` or an extra guard's own path is honoured. It said
     * `DELETE /auth/sessions` everywhere, pointing such a caller at a 404 as the way out. And not at all
     * where this guard switched `logout_all` off, since the route is then not mounted.
     */
    private function noSessionMessage(Request $request): string
    {
        $message = 'This token names no session, so there are no other sessions to revoke.';

        if (! (Lukk::guardConfig()['features']['logout_all'] ?? true)) {
            return $message;
        }

        // The prefix as configured may carry slashes at either end (Laravel trims only the leading one),
        // and is absent for a mount at the root. A controller only ever runs on a matched route, so the
        // `?->` never meets a null; the cast turns an absent prefix into '' rather than handing `trim()` a
        // null, which it would accept with a deprecation and answer the same.
        $prefix = trim((string) $request->route()?->getPrefix(), '/'); // @pest-mutate-ignore: RemoveNullSafeOperator,RemoveStringCast
        $path = ltrim($prefix.'/sessions', '/');

        return $message.' Use DELETE /'.$path.' to revoke every session, including this one.';
    }
}
