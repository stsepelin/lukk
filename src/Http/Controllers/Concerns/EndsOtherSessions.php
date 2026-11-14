<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Actions\RevokeOtherSessions;
use Lukk\Contracts\TokenVerifier;

/**
 * End every session but the caller's, after an authenticator was removed from the account.
 *
 * Deleting a passkey or turning two-factor off is what a user does about a device they no longer
 * trust or hold — and the sessions that device signed in stayed alive, some still carrying an `amr`
 * earned with the very authenticator just removed. A password change has always swept the other
 * sessions for the same reason (`ChangePassword`); removing a factor now does too.
 *
 * The caller's own session is the one named by their verified bearer (`ResolvesCurrentFamily`), and
 * survives. A bearer naming none — a co-issuer's token — has no lukk session to spare, so every
 * session goes, as `ChangePassword` decides it. Both revokes denylist before they write, so the access
 * tokens stop at once rather than at the end of their lifetime.
 */
trait EndsOtherSessions
{
    use ResolvesCurrentFamily;

    private function endOtherSessions(Request $request, Authenticatable $user): void
    {
        $current = $this->currentFamilyId($request, app(TokenVerifier::class));

        $current === null
            ? app(RevokeAllSessions::class)($user->getAuthIdentifier())
            : app(RevokeOtherSessions::class)($user->getAuthIdentifier(), $current);
    }
}
