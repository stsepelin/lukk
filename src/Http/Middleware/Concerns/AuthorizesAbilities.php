<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware\Concerns;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Lukk\Events\TokenAbilityDenied;
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

        // Validated here, not where the challenge header is built. Doing it there meant a
        // route-definition typo (`lukk.ability:orders read`) threw only for callers being DENIED:
        // the happy path stayed green and the misconfiguration first appeared in production, as a
        // 500, to exactly the users already being refused.
        $required = Abilities::fromArray($required)->all();

        if ($required === []) {
            // A gate that requires nothing. Denying would hide the mistake behind a 403 someone
            // debugs as a permissions problem; this is a route definition bug, so say so.
            throw new InvalidArgumentException(
                'The lukk ability middleware needs at least one ability — e.g. `lukk.ability:orders.read`.',
            );
        }

        $user = $request->user();

        // Nobody at all is 401, not 403: 403 tells a client "you are known and refused", so it stops
        // retrying and never learns it simply needs to log in. RFC 6750 §3.1. Reachable only on a
        // route that gates without authenticating — the priority registration puts `auth:api` first
        // — but a route that forgot it must still say the right thing.
        if ($user === null && VerifiedToken::current($request) === null) {
            throw new AuthenticationException;
        }

        // Bound to the AUTHENTICATED SUBJECT, not merely to whichever token the request happens to
        // carry. Picking by guard alone never checked that the token's subject was the user the
        // route authenticated, so in an app where something else resolves lukk's guard in passing —
        // telemetry, a log-context middleware — the gate could authorize request A using a token
        // belonging to B. It also made the middleware and `$user->tokenCan()`, the documented
        // per-user API, answer differently for the same ability in the same request; going through
        // `forUser` is what makes them agree by construction.
        $token = $user === null ? null : VerifiedToken::forUser($request, $user);

        // Authenticated, but through something that left no lukk token — a session guard, or
        // `Lukk::actingAs` without abilities. Deny by default rather than 401: the caller IS known,
        // they simply hold nothing, and logging in again would not change that.
        $granted = $token?->abilities ?? Abilities::fromArray([]);

        if ($requireAll ? $granted->canAll($required) : $granted->canAny($required)) {
            return;
        }

        // Only a real token can be refused for its SCOPE. A caller authenticated by other means
        // holds no lukk token, so there is no subject/guard/family to report and nothing that
        // resembles a token probing its limits — the event would be noise without identifiers.
        if ($token !== null) {
            event(new TokenAbilityDenied(
                $token->userId,
                $token->guard,
                $token->familyId,
                $required,
                $requireAll,
            ));
        }

        // `insufficient_scope` + the scope that would have sufficed, per RFC 6750 §3.1 — enough for
        // a generic OAuth client (or an API gateway) to report what is missing without guessing.
        throw new HttpException(403, 'This action requires a token with the ability to perform it.', headers: [
            'WWW-Authenticate' => sprintf(
                'Bearer error="insufficient_scope", error_description="The token lacks the required ability.", scope="%s"',
                implode(' ', $required),
            ),
        ]);
    }
}
