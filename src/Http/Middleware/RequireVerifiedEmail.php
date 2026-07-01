<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Gate a route behind a verified email. Returns 409 Conflict when the authenticated
 * user implements MustVerifyEmail and hasn't verified — a distinct status from a plain
 * authz 403 so a client can prompt "verify your email" specifically. Read fresh off the
 * resolved user each request (never a token claim), so it reflects a just-verified user.
 * A user model that doesn't implement MustVerifyEmail is never gated.
 */
class RequireVerifiedEmail
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        abort_if(
            $user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail(),
            409,
            'Your email address is not verified.',
        );

        return $next($request);
    }
}
