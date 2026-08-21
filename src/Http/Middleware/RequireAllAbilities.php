<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** `lukk.abilities:a,b` — the token must carry ALL of them. See {@see RequireAbility}. */
class RequireAllAbilities extends RequireAbility
{
    public function handle(Request $request, Closure $next, string ...$abilities): Response
    {
        return $this->authorize($request, $abilities, requireAll: true, next: $next);
    }
}
