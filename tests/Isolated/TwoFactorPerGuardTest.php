<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lukk\Tests\TwoFactorPerGuardTestCase;

uses(TwoFactorPerGuardTestCase::class)->group('multi-guard', 'two-factor');

it('mounts the challenge redemption from each guard\'s own flag', function () {
    $mounted = fn (string $uri) => collect(app('router')->getRoutes())
        ->contains(fn ($route) => $route->uri() === $uri && in_array('POST', $route->methods(), true));

    expect($mounted('admin/auth/two-factor-challenge'))->toBeTrue()
        ->and($mounted('auth/two-factor-challenge'))->toBeFalse();
});

it('guards the extra guard\'s challenge route against a cross-site form', function () {
    // It sets the refresh cookie like login does; see `RefuseForgeableCookieGrant`.
    config(['lukk.guards.admin.cookie_mode' => true]);

    $this->withHeaders(['Sec-Fetch-Site' => 'cross-site', 'Content-Type' => 'application/x-www-form-urlencoded'])
        ->post('/admin/auth/two-factor-challenge', [])->assertStatus(415);
});

it('attaches the extra guard\'s own throttle to its challenge route', function () {
    $route = app('router')->getRoutes()->match(Request::create('/admin/auth/two-factor-challenge', 'POST'));

    expect($route->gatherMiddleware())->toContain('throttle:lukk-admin-2fa');
});
