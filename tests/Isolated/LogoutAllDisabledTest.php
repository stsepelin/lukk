<?php

declare(strict_types=1);

use Lukk\Tests\Fixtures\User;
use Lukk\Tests\LogoutAllDisabledTestCase;

uses(LogoutAllDisabledTestCase::class)->group('multi-guard');

function mounted(string $method, string $uri): bool
{
    return collect(app('router')->getRoutes())
        ->contains(fn ($route) => $route->uri() === $uri && in_array($method, $route->methods(), true));
}

it('does not mount DELETE /sessions on a guard whose logout_all is off', function () {
    // The flag was documented as a switch and read by nothing, so turning it off left the global
    // logout exposed on an install that had decided not to offer it.
    expect(mounted('DELETE', 'auth/sessions'))->toBeFalse();

    $pair = User::factory()->create()->startSession();

    $this->withToken($pair->accessToken)->deleteJson('/auth/sessions')->assertNotFound();
});

it('reads logout_all per guard', function () {
    // Global off, admin override on: the admin mount keeps the route. Read from the global block,
    // a per-guard override would be silently dropped — the pattern CLAUDE.md records as exploitable.
    expect(mounted('DELETE', 'admin/auth/sessions'))->toBeTrue();
});

it('leaves the calling-session routes alone when logout_all is off', function () {
    // `logout` ends the caller's own session and `sessions/others` is a different feature; neither is
    // "log out everywhere".
    expect(mounted('POST', 'auth/logout'))->toBeTrue()
        ->and(mounted('DELETE', 'auth/sessions/others'))->toBeTrue();
});
