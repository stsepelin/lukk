<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware\Concerns;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Lukk\Support\Abilities;
use Lukk\Support\VerifiedToken;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * The shared half of `lukk.ability` / `lukk.abilities`. A trait rather than a base class the other
 * extends: `RequireAllAbilities extends RequireAbility` reads as "an ALL gate is a kind of ANY
 * gate", which is exactly backwards, and it let the wrong alias inherit a future override silently.
 */
trait AuthorizesAbilities
{
    /**
     * @param  array<int, string>  $abilities
     */
    protected function authorize(Request $request, array $abilities, bool $requireAll): void
    {
        // Split on comma so `lukk.ability:a,b` and repeated parameters both behave. Filtered with an
        // explicit predicate — bare `array_filter` also drops `'0'`, and while a lone `'0'` is a
        // strange ability name, losing it out of an ALL list quietly weakens the requirement.
        $required = array_values(array_filter(
            array_map('trim', explode(',', implode(',', $abilities))),
            fn (string $ability) => $ability !== '',
        ));

        if ($required === []) {
            // A gate that requires nothing. Denying would hide the mistake behind a 403 someone
            // debugs as a permissions problem; this is a route definition bug, so say so.
            throw new InvalidArgumentException(
                'The lukk ability middleware needs at least one ability — e.g. `lukk.ability:orders.read`.',
            );
        }

        $token = VerifiedToken::current($request);

        // Nobody at all is 401, not 403: 403 tells a client "you are known and refused", so it stops
        // retrying and never learns it simply needs to log in. RFC 6750 §3.1. Reachable only on a
        // route that gates without authenticating — the priority registration puts `auth:api` first
        // — but a route that forgot it must still say the right thing.
        if ($token === null && $request->user() === null) {
            throw new AuthenticationException;
        }

        // Authenticated, but through something that left no lukk token — a session guard, or
        // `Lukk::actingAs` without abilities. Deny by default rather than 401: the caller IS known,
        // they simply hold nothing, and logging in again would not change that.
        $granted = $token?->abilities ?? Abilities::fromArray([]);

        if ($requireAll ? $granted->canAll($required) : $granted->canAny($required)) {
            return;
        }

        // `insufficient_scope` + the scope that would have sufficed, per RFC 6750 §3.1 — enough for
        // a generic OAuth client (or an API gateway) to report what is missing without guessing.
        throw new HttpException(403, 'This action requires a token with the ability to perform it.', headers: [
            'WWW-Authenticate' => sprintf(
                'Bearer error="insufficient_scope", error_description="The token lacks the required ability.", scope="%s"',
                Abilities::fromArray($required)->toScope() ?? '',
            ),
        ]);
    }
}
