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
 */
class ForceJsonRequest
{
    public function handle(Request $request, Closure $next): Response
    {
        $request->headers->set('Accept', 'application/json');

        return $next($request);
    }
}
