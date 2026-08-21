<?php

declare(strict_types=1);

namespace Lukk\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Lukk\Contracts\TokenVerifier;
use Lukk\Support\Abilities;

/**
 * Request guard (Sanctum Guard analog): pulls the bearer token, verifies it
 * (signature + claims + denylist), and resolves the user. Wired via
 * Auth::extend('lukk-jwt', ...) inside a RequestGuard.
 */
class JwtGuard
{
    public function __construct(
        private readonly TokenVerifier $verifier,
        private readonly UserProvider $users,
    ) {}

    public function __invoke(Request $request): ?Authenticatable
    {
        $token = $request->bearerToken();

        if ($token === null || $token === '') {
            return null;
        }

        $claims = $this->verifier->verify($token);

        if ($claims === null) {
            return null;
        }

        $user = $this->users->retrieveById($claims->sub);

        if ($user === null) {
            return null;
        }

        // Stash the VERIFIED claims for anything downstream that needs them — the ability
        // middleware reads `scope` from here rather than verifying the token a second time.
        $request->attributes->set('lukk.claims', $claims);

        // Abilities belong to the TOKEN, not the user: the same person on two devices may hold
        // tokens granting different things. Set per request so a model can never report a previous
        // request's. Optional trait, so a user model that doesn't use it is unaffected.
        if (method_exists($user, 'withTokenAbilities')) {
            $user->withTokenAbilities(Abilities::fromScope($claims->scope ?? null));
        }

        return $user;
    }
}
