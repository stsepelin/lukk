<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Forces `Accept: application/json` so authentication and validation failures
 * render as JSON regardless of the host app's exception config. Applied to lukk's
 * own `/auth` routes, and exposed to consumers as the `lukk.force-json` alias.
 *
 * Must sort before `Authenticate` in the middleware priority (wired in the service
 * provider); see docs/installation.md for the rationale.
 *
 * It also stamps the `WWW-Authenticate` challenge RFC 6750 §3 requires on a 401 — see `challenge()`.
 */
class ForceJsonRequest
{
    public function handle(Request $request, Closure $next): Response
    {
        $request->headers->set('Accept', 'application/json');

        $response = $next($request);

        if ($response->getStatusCode() === 401 && ! $response->headers->has('WWW-Authenticate')) {
            $response->headers->set('WWW-Authenticate', $this->challenge($request));
        }

        return $response;
    }

    /**
     * RFC 6750 §3: a resource server refusing a request "MUST include the HTTP `WWW-Authenticate`
     * response header field". lukk emitted it on 403 (`insufficient_scope`, with the scope that would
     * have sufficed) and on nothing else, so a generic OAuth client or gateway was told why it was
     * refused at 403 and given nothing at 401 — unable to tell "expired, refresh and retry" from
     * "wrong audience, give up".
     *
     * §3.1: `invalid_token` covers "expired, revoked, malformed, or invalid for other reasons". With no
     * credential at all there is no token to call invalid, so the bare challenge is correct.
     */
    private function challenge(Request $request): string
    {
        return $request->bearerToken() === null
            ? 'Bearer'
            : 'Bearer error="invalid_token", error_description="The access token is expired, revoked, or otherwise invalid."';
    }
}
