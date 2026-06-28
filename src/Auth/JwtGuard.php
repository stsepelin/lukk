<?php

declare(strict_types=1);

namespace Lukk\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Lukk\Contracts\TokenVerifier;

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

        return $this->users->retrieveById($claims->sub);
    }
}
