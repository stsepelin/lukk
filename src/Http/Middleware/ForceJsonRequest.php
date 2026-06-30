<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Force `Accept: application/json` on lukk's own routes.
 *
 * lukk is a JSON API, but the host app controls exception rendering. Laravel's
 * default `redirectGuestsTo(fn () => route('login'))` makes the `Authenticate`
 * middleware EAGERLY resolve `route('login')` whenever `! $request->expectsJson()`
 * — throwing `RouteNotFoundException` (a 500) inside the middleware, before any
 * handler-level `shouldRenderJsonWhen` can intervene. A request that reaches lukk
 * without an `Accept: application/json` header (a misconfigured client, curl, or a
 * BFF proxy that strips `Accept`) would therefore 500 instead of returning a clean
 * 401.
 *
 * Stamping JSON `Accept` here makes `expectsJson()` true for lukk's routes, so
 * authentication and validation failures always render as JSON — immune to how the
 * request arrives or the host app's exception configuration. lukk's responses are
 * JSON regardless, so this changes only the error path.
 */
class ForceJsonRequest
{
    public function handle(Request $request, Closure $next): Response
    {
        $request->headers->set('Accept', 'application/json');

        return $next($request);
    }
}
