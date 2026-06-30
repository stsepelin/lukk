<?php

declare(strict_types=1);

use Illuminate\Auth\Middleware\Authenticate;
use Symfony\Component\Routing\Exception\RouteNotFoundException;

// The static redirect callback leaks across tests; reset it.
afterEach(fn () => Authenticate::redirectUsing(fn () => null));

it('renders a JSON 401 for lukk routes even with a guest redirect and no JSON Accept', function () {
    // Reproduce the framework default that 500s a header-less request: a guest
    // redirect that fails to resolve (as `route('login')` does with no login route).
    Authenticate::redirectUsing(function () {
        throw new RouteNotFoundException('Route [login] not defined.');
    });

    // No JSON Accept (a BFF proxy strips it). Without `ForceJsonRequest` this would
    // take the guest-redirect branch → RouteNotFoundException → 500. The middleware
    // forces `Accept: application/json`, so `expectsJson()` is true → clean 401 JSON.
    $this->call('DELETE', '/auth/sessions', server: ['HTTP_ACCEPT' => 'text/html'])
        ->assertUnauthorized() // 401, not 500
        ->assertHeader('content-type', 'application/json')
        ->assertJson(['message' => 'Unauthenticated.']);
});
