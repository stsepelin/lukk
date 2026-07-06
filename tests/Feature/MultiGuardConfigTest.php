<?php

declare(strict_types=1);

use Lukk\Lukk;

uses()->group('multi-guard');

it('is a no-op for a single-guard app', function () {
    expect(Lukk::isMultiGuard())->toBeFalse();

    Lukk::assertGuardsIsolated(); // no guards → nothing to validate; returns without throwing
});

it('refuses two guards that share an audience (tokens would cross)', function () {
    config([
        'auth.guards.evil' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
        'lukk.guards.evil' => [
            'audience' => (array) config('lukk.audience'), // same audience as the default guard
            'path' => 'evil/auth',
        ],
    ]);

    expect(fn () => Lukk::assertGuardsIsolated())->toThrow(RuntimeException::class, 'share the audience');
});

it('requires every guard to declare a non-empty audience', function () {
    config([
        'auth.guards.admin' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
        'lukk.guards.admin' => ['audience' => [], 'path' => 'admin/auth'],
    ]);

    expect(fn () => Lukk::assertGuardsIsolated())->toThrow(RuntimeException::class, 'non-empty audience');
});

it('refuses two guards that mount at the same host and path', function () {
    config([
        'auth.guards.admin' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
        // distinct audience, but no path/domain → inherits path 'auth' → shadows the default guard.
        'lukk.guards.admin' => ['audience' => ['https://admin.test']],
    ]);

    expect(fn () => Lukk::assertGuardsIsolated())->toThrow(RuntimeException::class, 'same host and path');
});

it('allows a shared secret when the audience differs (the compliant control)', function () {
    config([
        'auth.guards.admin' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
        'lukk.guards.admin' => [
            'secret' => config('lukk.secret'),          // shared key is fine…
            'audience' => ['https://admin.test'],       // …because the audience is distinct
            'path' => 'admin/auth',
        ],
    ]);

    Lukk::assertGuardsIsolated();

    // The guard's config inherits the top-level defaults, overriding only what it declares.
    expect(Lukk::guardConfig('admin')['audience'])->toBe(['https://admin.test'])
        ->and(Lukk::guardConfig('admin')['access_ttl'])->toBe(config('lukk.access_ttl'));
});

it('requires each extra guard to be declared in config/auth.php as lukk-jwt', function () {
    config(['lukk.guards.admin' => ['audience' => ['https://admin.test']]]); // no auth.guards.admin

    expect(fn () => Lukk::assertGuardsIsolated())->toThrow(RuntimeException::class, 'config/auth.php');
});

it('lists the default guard plus every configured guard', function () {
    config(['lukk.guards' => ['admin' => [], 'partner' => []]]);

    expect(Lukk::guardNames())->toBe(['api', 'admin', 'partner'])
        ->and(Lukk::isMultiGuard())->toBeTrue();
});
