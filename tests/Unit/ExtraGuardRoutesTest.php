<?php

declare(strict_types=1);

use Illuminate\Routing\Route as RouteDefinition;
use Illuminate\Support\Facades\Route;
use Lukk\Http\Middleware\ForceJsonRequest;

uses()->group('multi-guard');

/** Mount lukk's routes again with an `admin` guard configured, and return its login route. */
function adminLoginRoute(array $admin): RouteDefinition
{
    config([
        'auth.guards.admin' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
        'lukk.guards.admin' => ['audience' => ['https://admin.test'], 'path' => 'staff', ...$admin],
    ]);

    require dirname(__DIR__, 2).'/src/routes/api.php';

    return collect(Route::getRoutes()->getRoutes())
        ->first(fn (RouteDefinition $route) => $route->uri() === 'staff/login');
}

it('mounts an extra guard on its own domain', function () {
    expect(adminLoginRoute(['domain' => 'admin.test'])->getDomain())->toBe('admin.test');
});

it('mounts an extra guard behind the api group, forced JSON and its own guard context', function () {
    expect(adminLoginRoute([])->middleware())->toContain('api', ForceJsonRequest::class, 'lukk.set-guard:admin');
});
