<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\Request;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Contracts\LogoutResponse;

/**
 * The user's session collection: `destroy` revokes every session (all devices),
 * the global logout. Requires `logout_all`.
 */
class SessionController
{
    public function __construct(
        private readonly RevokeAllSessions $revokeAll,
    ) {}

    public function destroy(Request $request): LogoutResponse
    {
        ($this->revokeAll)($request->user()->getAuthIdentifier());

        return app(LogoutResponse::class);
    }
}
