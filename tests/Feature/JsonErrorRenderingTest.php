<?php

declare(strict_types=1);

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Support\Facades\Route;
use Symfony\Component\Routing\Exception\RouteNotFoundException;

// The static redirect callback leaks across tests; reset it.
afterEach(fn () => Authenticate::redirectUsing(fn () => null));

// Simulate Laravel's default guest redirect that can't resolve `route('login')` —
// the eager lookup that turns an Accept-less unauthenticated request into a 500.
function throwingGuestRedirect(): void
{
    Authenticate::redirectUsing(function () {
        throw new RouteNotFoundException('Route [login] not defined.');
    });
}

it('renders a JSON 401 for lukk routes even with a guest redirect and no JSON Accept', function () {
    throwingGuestRedirect();

    // No JSON Accept (a BFF proxy strips it). Without `ForceJsonRequest` this would
    // take the guest-redirect branch → RouteNotFoundException → 500. The middleware
    // forces `Accept: application/json`, so `expectsJson()` is true → clean 401 JSON.
    $this->call('DELETE', '/auth/sessions', server: ['HTTP_ACCEPT' => 'text/html'])
        ->assertUnauthorized() // 401, not 500
        ->assertHeader('content-type', 'application/json')
        ->assertJson(['message' => 'Unauthenticated.']);
});

it('reproduces the 500 on a bare consumer auth:api route (no alias)', function () {
    // A consumer-owned protected route with only the framework guard — the case lukk
    // does NOT cover automatically.
    Route::middleware('auth:api')->get('/_bare', fn () => ['ok' => true]);
    throwingGuestRedirect();

    // Non-JSON Accept → !expectsJson() → eager `route('login')` → RouteNotFoundException.
    $this->call('GET', '/_bare', server: ['HTTP_ACCEPT' => 'text/html'])
        ->assertStatus(500);
});

it('lets a consumer get a clean 401 JSON by attaching the lukk.force-json alias', function () {
    // Same consumer route, now opting in to lukk's alias ahead of the guard.
    Route::middleware(['lukk.force-json', 'auth:api'])->get('/_guarded', fn () => ['ok' => true]);
    throwingGuestRedirect();

    // The alias forces `Accept: application/json` (and is ordered before `Authenticate`),
    // so the same Accept-less request yields a clean 401 JSON instead of the 500 above.
    $this->call('GET', '/_guarded', server: ['HTTP_ACCEPT' => 'text/html'])
        ->assertUnauthorized()
        ->assertHeader('content-type', 'application/json')
        ->assertJson(['message' => 'Unauthenticated.']);
});
