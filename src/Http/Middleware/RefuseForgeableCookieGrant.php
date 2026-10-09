<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Lukk\Lukk;
use Lukk\Support\FormProofRequest;
use Symfony\Component\HttpFoundation\Response;

/**
 * In cookie mode, refuse a request that would SET the refresh cookie unless a cross-site form could not
 * have sent it (`FormProofRequest`).
 *
 * Login CSRF: `SameSite=Strict` stops the cookie being SENT cross-site, not being SET — RFC 6265bis §5.7
 * stores a SameSite cookie from the response to a cross-site top-level navigation. A page on any site
 * could auto-submit a form to `/login` with the attacker's own credentials (or to `/refresh` with the
 * attacker's token) and plant the attacker's session in the victim's browser, whose SPA then refreshes
 * into the attacker's account. 415: the request must be JSON (RFC 9110 §15.5.16).
 *
 * Body mode needs none of this: the tokens come back in a response the attacker's page cannot read.
 */
class RefuseForgeableCookieGrant
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! (Lukk::guardConfig()['cookie_mode'] ?? false) || FormProofRequest::check($request)) {
            return $next($request);
        }

        return response()->json(['message' => 'This request must be sent as JSON.'], 415);
    }
}
