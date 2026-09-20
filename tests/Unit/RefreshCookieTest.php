<?php

declare(strict_types=1);

use Lukk\Lukk;
use Lukk\Support\RefreshCookie;

it('reads the Secure flag as a boolean, including the strings env hands over', function (mixed $value, bool $secure) {
    config(['lukk.cookie.secure' => $value]);

    expect(RefreshCookie::secure())->toBe($secure);
})->with([
    'unset' => [null, true],
    'true' => [true, true],
    '"1" from env' => ['1', true],
    '"0" from env' => ['0', false],
    'an empty env line' => ['', false],
    'false' => [false, false],
]);

it('uses the configured cookie name, dropping the __Host- prefix only when Secure is off', function () {
    config(['lukk.cookie.refresh_name' => '__Host-session']);
    expect(RefreshCookie::name())->toBe('__Host-session');

    config(['lukk.cookie.secure' => false]);
    expect(RefreshCookie::name())->toBe('session');
});

it('keeps the unsuffixed name for the default guard, even when lukk.guard is null', function () {
    config(['lukk.guard' => null]);

    expect(RefreshCookie::name())->toBe('__Host-refresh');
});

it('keeps the unsuffixed name for a renamed default guard', function () {
    config([
        'lukk.guard' => 'members',
        'auth.defaults.guard' => 'members',
        'auth.guards.members' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
    ]);

    expect(Lukk::onGuard('members', fn () => RefreshCookie::name()))->toBe('__Host-refresh');
});

it('suffixes the name with any other guard', function () {
    config([
        'auth.guards.admin' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
        'lukk.guards.admin' => ['audience' => ['https://admin.test']],
    ]);

    expect(Lukk::onGuard('admin', fn () => RefreshCookie::name()))->toBe('__Host-refresh-admin');
});

it('converts the refresh TTL from seconds to whole minutes', function (mixed $ttl, int $minutes) {
    config(['lukk.refresh_ttl' => $ttl]);

    expect(RefreshCookie::ttlMinutes())->toBe($minutes);
})->with([
    'an hour' => [3600, 60],
    'a part-minute rounds down' => [3601, 60],
    'a string from env' => ['7200', 120],
    'unset: thirty days' => [null, 43200],
    'garbage: zero, not a TypeError' => ['garbage', 0],
]);
