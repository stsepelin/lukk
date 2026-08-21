<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Lukk\Support\Abilities;
use Symfony\Component\HttpFoundation\Response;

/**
 * Gate a route on the token's `scope`. Two aliases, mirroring Sanctum so the semantics are the ones
 * people already expect:
 *
 *   `lukk.ability:a,b`    — ANY of them
 *   `lukk.abilities:a,b`  — ALL of them
 *
 * Reads the claims the guard stashed on the request, so it costs no second verification and works
 * whatever the user model is. **Deny by default**: a token with no `scope` is refused, because a
 * permission check that passes when nothing was configured is worse than one that fails loudly.
 */
class RequireAbility
{
    public function handle(Request $request, Closure $next, string ...$abilities): Response
    {
        return $this->authorize($request, $abilities, requireAll: false, next: $next);
    }

    /**
     * @param  array<int, string>  $abilities
     */
    protected function authorize(Request $request, array $abilities, bool $requireAll, Closure $next): Response
    {
        // The guard verified this token already; it left the claims here so the check is free.
        $claims = $request->attributes->get('lukk.claims');
        $granted = Abilities::fromScope(is_object($claims) ? ($claims->scope ?? null) : null);

        // Split on comma so `lukk.ability:a,b` and `lukk.ability:a|b`-style lists both behave.
        $required = array_values(array_filter(array_map('trim', explode(',', implode(',', $abilities)))));

        abort_if(
            $required === [] || ! ($requireAll ? $granted->canAll($required) : $granted->canAny($required)),
            403,
            'This action requires a token with the ability to perform it.',
        );

        return $next($request);
    }
}
