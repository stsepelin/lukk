<?php

declare(strict_types=1);

namespace Lukk\Http\Concerns;

use Illuminate\Http\Request;
use Lukk\Contracts\Denylist;
use Lukk\Lukk;
use Lukk\Tokens\Jwt\FirebaseTokenVerifier;

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

        if ($bearer === '') {
            return null;
        }

        $guard = (string) app('auth')->getDefaultDriver();
        $claims = (new FirebaseTokenVerifier(Lukk::guardConfig($guard), app(Denylist::class)))->verify($bearer);
        $family = $claims === null ? null : (string) ($claims->fid ?? '');

        return $family === '' ? null : $family;
    }
}
