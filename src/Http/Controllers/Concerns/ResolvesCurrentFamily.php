<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers\Concerns;

use Illuminate\Http\Request;
use Lukk\Contracts\TokenVerifier;

/**
 * The caller's own refresh-token family, read from their VERIFIED bearer token.
 *
 * Change-password needs it to name the caller's session without letting the caller name someone
 * else's — taking it from the request body would do exactly that. It comes from the same token the
 * guard authenticated with, so `sub` and `fid` are structurally consistent. (Logout does not use
 * it: it may also be named by a refresh token, and that policy lives in `Actions\EndSession`.)
 *
 * Null when the token carries no `fid`, or an empty one — a co-issuer sharing the secret, in the verify-only
 * topology. Callers must decide what that means for them rather than assuming a family exists.
 */
trait ResolvesCurrentFamily
{
    private function currentFamilyId(Request $request, TokenVerifier $verifier): ?string
    {
        // No bearer at all under `Lukk::actingAs()`, which authenticates the guard directly.
        $claims = $verifier->verify((string) $request->bearerToken());
        $familyId = $claims !== null && isset($claims->fid) ? (string) $claims->fid : '';

        // An EMPTY `fid` names no session, as `VerifiedToken` and `ResolvesPresentingFamily` read it.
        // `isset()` alone took `""` for one, and `DELETE /auth/sessions/others` then excepted the family
        // `''` — which is none — so "log out my other devices" logged out every device.
        return $familyId === '' ? null : $familyId;
    }
}
