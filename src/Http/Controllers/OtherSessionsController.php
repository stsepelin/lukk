<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\Request;
use Lukk\Actions\RevokeOtherSessions;
use Lukk\Contracts\LogoutResponse;
use Lukk\Contracts\TokenVerifier;

/**
 * The user's *other* sessions: `destroy` revokes every session except the one
 * making the request (resolved from the bearer token's family id).
 */
class OtherSessionsController
{
    public function __construct(
        private readonly RevokeOtherSessions $revokeOthers,
    ) {}

    public function destroy(Request $request, TokenVerifier $verifier): LogoutResponse
    {
        $claims = $verifier->verify((string) $request->bearerToken());

        if ($claims !== null && isset($claims->fid)) {
            ($this->revokeOthers)($request->user()->getAuthIdentifier(), (string) $claims->fid);
        }

        return app(LogoutResponse::class);
    }
}
