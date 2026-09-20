<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Lukk\Http\Middleware\Concerns\AuthorizesAbilities;
use Symfony\Component\HttpFoundation\Response;

/** `lukk.abilities:a,b` — the token must carry ALL of them. See {@see RequireAbility}. */
class RequireAllAbilities
{
    use AuthorizesAbilities;

    public function handle(Request $request, Closure $next, string ...$abilities): Response
    {
        // A variadic is already a list; `array_values` only states it.
        $this->authorize($request, array_values($abilities), requireAll: true); // @pest-mutate-ignore: UnwrapArrayValues

        return $next($request);
    }
}
