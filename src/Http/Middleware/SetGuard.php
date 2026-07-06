<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Lukk\Lukk;
use Symfony\Component\HttpFoundation\Response;

/**
 * Stamps the lukk guard for the current request from the route group it's applied to, so the
 * public login/refresh endpoints (which don't run through `auth:{guard}`) mint + rotate tokens
 * with that guard's crypto identity and refresh-token scope. Applied to every per-guard group.
 */
class SetGuard
{
    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        Lukk::useGuard($guard);

        return $next($request);
    }
}
