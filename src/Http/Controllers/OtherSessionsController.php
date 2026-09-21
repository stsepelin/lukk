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
                return response()->json([
                    'message' => 'This token names no session, so there are no other sessions to revoke. Use DELETE /auth/sessions to revoke every session, including this one.',
                ], 409);
            }

            // No bearer at all: `Lukk::actingAs()` authenticates the guard directly. A test harness,
            // not a deployment — refusing here would fail every consumer test using the package's
            // own documented helper, so it keeps the historical no-op.
            return response()->noContent();
        }

        ($this->revokeOthers)($this->authenticated($request)->getAuthIdentifier(), $currentFamilyId);

        return response()->noContent();
    }
}
