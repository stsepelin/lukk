<?php

declare(strict_types=1);

use Lukk\Lukk;

uses()->group('multi-guard');

it('refuses to boot a lukk-jwt guard that has no config block of its own', function () {
    // Without a `lukk.guards.admin` block, `guardConfig('admin')` deep-merges nothing over the
    // top-level block — so the second guard gets the default guard's secret AND audience. Audience
    // is the control that stops one guard's token verifying on another, so a CUSTOMER's token
    // authenticates as whatever the admin provider returns for that id: a different user, in a
    // different table. Verified reachable before this check existed (a customer token reached an
    // `auth:admin` route as Admin#1, HTTP 200).
    config([
        'auth.guards.admin' => ['driver' => 'lukk-jwt', 'provider' => 'admins'],
        'lukk.guards' => [],
    ]);

    expect(fn () => Lukk::assertGuardsIsolated())
        ->toThrow(RuntimeException::class, 'has no `lukk.guards.admin` config block');
});

it('accepts a lukk-jwt guard that carries its own isolated identity', function () {
    config([
        'auth.guards.admin' => ['driver' => 'lukk-jwt', 'provider' => 'admins'],
        'lukk.guards' => ['admin' => [
            'issuer' => 'https://admin.test',
            'audience' => ['https://admin.test'],
            'secret' => str_repeat('b', 64),
            'path' => 'admin/auth',
        ]],
    ]);

    expect(fn () => Lukk::assertGuardsIsolated())->not->toThrow(Exception::class);
});

it('ignores guards that are not lukk\'s, and the default guard itself', function () {
    // A `session` guard alongside lukk's is the ordinary hybrid app; it must not trip the check.
    config([
        'auth.guards.web' => ['driver' => 'session', 'provider' => 'users'],
        'auth.guards.api' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
        'lukk.guards' => [],
    ]);

    expect(Lukk::driverGuardNames())->toBe(['api'])
        ->and(fn () => Lukk::assertGuardsIsolated())->not->toThrow(Exception::class);
});
