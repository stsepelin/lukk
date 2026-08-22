<?php

declare(strict_types=1);

namespace Lukk\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Lukk\Contracts\TokenVerifier;
use Lukk\Support\Abilities;
use Lukk\Support\VerifiedToken;

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
        private readonly string $guard = 'api',
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

        // Record the VERIFIED token on the request. Everything downstream — the ability middleware,
        // `$user->tokenCan()` — reads from here rather than verifying a second time, and abilities
        // belong to the TOKEN, not the user: the same person on two devices may hold tokens granting
        // different things.
        VerifiedToken::put($request, new VerifiedToken(
            guard: $this->guard,
            userId: $claims->sub,
            userClass: $user::class,
            familyId: (string) ($claims->fid ?? ''),
            abilities: Abilities::fromScope($claims->scope ?? null),
            claims: $claims,
        ));

        // Kept for anything already reading it directly.
        $request->attributes->set('lukk.claims', $claims);

        return $user;
    }
}
