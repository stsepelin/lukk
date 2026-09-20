<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers\Concerns;

use Illuminate\Http\Request;
use Lukk\Support\RefreshCookie;

/**
 * The refresh token a request presents — the body field, else the guard's refresh cookie.
 *
 * Used by `/refresh`. In cookie mode the only ambient credential it accepts is the `SameSite=Strict`,
 * `__Host-`, HttpOnly cookie.
 *
 * Deliberately WITHOUT the request-shape check `/logout` applies (`ReadsLogoutCredentials`). A same-site
 * sibling page can still get the cookie sent on a form POST here, but all a forged refresh achieves
 * is a rotation: the new pair lands in a response the attacker cannot read and a cookie the victim's
 * browser keeps, so the victim's session carries on. A forged logout, by contrast, ends the session.
 * Refusing form-shaped refreshes would also break any client that refreshes without a JSON body.
 */
trait ReadsPresentedRefreshToken
{
    private function presentedRefreshToken(Request $request): string
    {
        // `input()` unions the QUERY STRING for every content type, so `POST /auth/refresh?refresh_token=…`
        // worked — putting a 30-day opaque credential into access logs, proxy logs and Referer
        // headers, the one place a token kept out of caches and hashed at rest must never appear
        // (RFC 9700 §4.3.2). Body only. `post()` covers form encoding, `json()` the JSON body.
        $presented = $request->post('refresh_token') ?? $request->json('refresh_token');

        // An array would raise "Array to string conversion" and hash the literal "Array".
        $cookie = $request->cookie(RefreshCookie::name());

        // No token resolves under any placeholder, so the '' only states the type.
        return is_string($presented) ? $presented : (is_string($cookie) ? $cookie : ''); // @pest-mutate-ignore: EmptyStringToNotEmpty
    }
}
