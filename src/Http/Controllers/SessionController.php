<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\Request;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Contracts\LogoutResponse;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;

/**
 * The user's session collection: `destroy` revokes every session (all devices),
 * the global logout. Requires `logout_all`.
 */
class SessionController
{
    use ResolvesAuthenticatedUser;

    public function __construct(
        private readonly RevokeAllSessions $revokeAll,
    ) {}

    public function destroy(Request $request): LogoutResponse
    {
        ($this->revokeAll)($this->authenticated($request)->getAuthIdentifier());

        return app(LogoutResponse::class);
    }
}
