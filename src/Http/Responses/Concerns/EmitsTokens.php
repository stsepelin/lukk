<?php

declare(strict_types=1);

namespace Lukk\Http\Responses\Concerns;

use Illuminate\Http\JsonResponse;
use Lukk\Http\Concerns\PreventsCaching;
use Lukk\Lukk;
use Lukk\Support\RefreshCookie;
use Lukk\Support\TokenPair;

/**
 * Shared token-emission logic for login/refresh responses.
 *
 * Two modes (config 'cookie_mode'):
 *  - false (BFF, default): access + refresh in the JSON body; the Nuxt BFF seals
 *    them server-side and the browser never sees them.
 *  - true (direct browser client): refresh goes into a __Host- HttpOnly cookie;
 *    only the access token + expiry are in the body.
 */
trait EmitsTokens
{
    use PreventsCaching;

    private function tokenResponse(TokenPair $pair): JsonResponse
    {
        // Per-guard, like the cookie name below: a guard-level `cookie_mode` override was read
        // from the top-level config and silently ignored.
        if (! ((Lukk::guardConfig()['cookie_mode'] ?? false))) {
            return $this->noStore(response()->json($pair->toArray()));
        }

        $response = response()->json([
            'access_token' => $pair->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $pair->expiresIn,
        ]);

        $response->withCookie(cookie()->make(
            name: RefreshCookie::name(),
            value: $pair->refreshToken,
            minutes: RefreshCookie::ttlMinutes(),
            path: '/',
            domain: null,
            secure: RefreshCookie::secure(),
            httpOnly: true,
            raw: false,
            // Strict, not Lax: the refresh call is an XHR, never a navigation, so
            // Strict costs nothing and blocks the cross-site CSRF that Lax allows.
            sameSite: 'Strict',
        ));

        return $this->noStore($response);
    }
}
