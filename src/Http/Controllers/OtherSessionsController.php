<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Lukk\Actions\RevokeOtherSessions;
use Lukk\Contracts\TokenVerifier;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;

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

    public function __construct(
        private readonly RevokeOtherSessions $revokeOthers,
    ) {}

    public function destroy(Request $request, TokenVerifier $verifier): Response
    {
        // No bearer at all under `Lukk::actingAs()`, which authenticates the guard directly.
        $claims = $verifier->verify((string) $request->bearerToken());

        if ($claims !== null && isset($claims->fid)) {
            ($this->revokeOthers)($this->authenticated($request)->getAuthIdentifier(), (string) $claims->fid);
        }

        return response()->noContent();
    }
}
