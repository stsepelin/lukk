<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Lukk\Http\Middleware\Concerns\AuthorizesAbilities;
use Symfony\Component\HttpFoundation\Response;

/**
 * Gate a route on the token's `scope`. Two aliases, mirroring Sanctum so the semantics are the ones
 * people already expect:
 *
 *   `lukk.ability:a,b`    — ANY of them
 *   `lukk.abilities:a,b`  — ALL of them
 *
 * Reads the token the guard verified and left on the request, so it costs no second verification
 * and works whatever the user model is. **Deny by default**: a token with no `scope` is refused,
 * because a permission check that passes when nothing was configured is worse than one that fails
 * loudly.
 */
class RequireAbility
{
    use AuthorizesAbilities;

    public function handle(Request $request, Closure $next, string ...$abilities): Response
    {
        $this->authorize($request, array_values($abilities), requireAll: false);

        return $next($request);
    }
}
