<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Lukk\Exceptions\RetryableValidationException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Forces `Accept: application/json` so authentication and validation failures
 * render as JSON regardless of the host app's exception config. Applied to lukk's
 * own `/auth` routes, and exposed to consumers as the `lukk.force-json` alias.
 *
 * Must sort before `Authenticate` in the middleware priority (wired in the service
 * provider); see docs/installation.md for the rationale.
 *
 * It also stamps the `WWW-Authenticate` challenge RFC 6750 §3 requires on a 401 — see `challenge()` —
 * and `Retry-After` on a throttled or locked action (`RetryableValidationException`).
 */
class ForceJsonRequest
{
    public function handle(Request $request, Closure $next): Response
    {
        $request->headers->set('Accept', 'application/json');

        $response = $next($request);

        if ($response->getStatusCode() === 401 && ! $response->headers->has('WWW-Authenticate')) {
            $response->headers->set('WWW-Authenticate', $this->challenge($request, $response));
        }

        // RFC 9110 §10.2.3: the wait a throttled or locked action names, as the header a client can act on.
        $refusal = $response->exception ?? null;

        if ($refusal instanceof RetryableValidationException && ! $response->headers->has('Retry-After')) {
            $response->headers->set('Retry-After', (string) $refusal->retryAfter);
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
     *
     * And `invalid_token` is a statement about the ACCESS token, so it is made only when authentication
     * is what refused the request. `/auth/refresh` answers 401 for a dead refresh token; a client that
     * also sent a perfectly good bearer was told that bearer was "expired, revoked, or otherwise
     * invalid". Any other 401 keeps the bare challenge RFC 9110 §15.5.2 requires.
     */
    private function challenge(Request $request, Response $response): string
    {
        // Laravel's pipeline attaches the exception it rendered; a response built by hand has none.
        $refused = ($response->exception ?? null) instanceof AuthenticationException;

        return $refused && $request->bearerToken() !== null
            ? 'Bearer error="invalid_token", error_description="The access token is expired, revoked, or otherwise invalid."'
            : 'Bearer';
    }
}
