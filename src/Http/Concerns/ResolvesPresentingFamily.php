<?php

declare(strict_types=1);

namespace Lukk\Http\Concerns;

use Illuminate\Http\Request;
use Lukk\Contracts\TokenVerifier;
use Lukk\Lukk;

/**
 * The refresh-token family of the access token making THIS request.
 *
 * Shared by the two halves of the step-up binding — the controller that MINTS a confirmation and the
 * middleware that CHECKS one — because they must agree, and they did not. The check side re-verified
 * the bearer while the issue side read the request-scoped `VerifiedToken`, which is absent whenever
 * the guard did not resolve during this request. The asymmetry failed OPEN in the direction that
 * mattered: an absent record made the check side refuse (a functional break) but made the issue side
 * mint a confirmation with no binding at all — which the check side then accepted from any token the
 * subject held, restoring the exact replay the binding exists to prevent.
 *
 * Verifying the bearer is deterministic regardless of guard state. It costs one HMAC on routes that
 * have just re-verified a password.
 */
trait ResolvesPresentingFamily
{
    private function presentingFamily(Request $request): ?string
    {
        $bearer = (string) $request->bearerToken();

        // A shortcut: verifying an empty bearer answers null too.
        if ($bearer === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        // `getDefaultDriver()` is declared to return a string; the cast states it.
        $guard = (string) app('auth')->getDefaultDriver(); // @pest-mutate-ignore: RemoveStringCast
        // The bound verifier, pinned to the guard that authenticated — the same one the guard itself uses,
        // so a rebound `TokenVerifier` decides both or neither.
        $claims = Lukk::onGuard($guard, fn () => app(TokenVerifier::class))->verify($bearer);
        $family = $claims === null ? null : (string) ($claims->fid ?? '');

        return $family === '' ? null : $family;
    }
}
