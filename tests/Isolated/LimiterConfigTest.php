<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Lukk\Lukk;
use Lukk\Tests\Fixtures\Admin;
use Lukk\Tests\LimiterConfigTestCase;

uses(LimiterConfigTestCase::class)->group('multi-guard');

/** @return array<int, Limit> */
function limitsOf(string $name, ?Request $request = null): array
{
    $limits = app(RateLimiter::class)->limiter($name)($request ?? visitor());

    return is_array($limits) ? $limits : [$limits];
}

function visitor(): Request
{
    return Request::create('/', 'POST', server: ['REMOTE_ADDR' => '203.0.113.9']);
}

it('gives each extra guard the limits configured for it, read as numbers from env strings', function (string $limiter, int $max, int $decay) {
    // `env()` hands these over as strings, and `Limit` takes ints: under strict_types every cast is what
    // stands between a configured limit and a TypeError on the route it guards.
    [$limit] = limitsOf($limiter);

    expect($limit->maxAttempts)->toBe($max)
        ->and($limit->decaySeconds)->toBe($decay)
        ->and($limit->key)->toBe(Lukk::rateLimitKey(visitor()));
})->with([
    ['lukk-admin-login', 7, 71],
    ['lukk-admin-refresh', 8, 81],
    ['lukk-admin-2fa', 9, 91],
]);

it('meters an extra guard\'s step-up per address AND per user, with its own limits', function () {
    $admin = Admin::factory()->create();
    $request = visitor();
    $request->setUserResolver(fn (?string $guard = null) => $guard === 'admin' ? $admin : null);

    [$byAddress, $byUser] = limitsOf('lukk-admin-confirm', $request);

    expect([$byAddress->maxAttempts, $byAddress->decaySeconds, $byAddress->key])->toBe([4, 41, Lukk::rateLimitKey($request)])
        ->and([$byUser->maxAttempts, $byUser->decaySeconds, $byUser->key])->toBe([4, 41, 'lukk-admin-confirm|admin|user|'.$admin->getKey()]);
});

it('meters an extra guard\'s step-up per address alone when nobody is signed in', function () {
    expect(limitsOf('lukk-admin-confirm'))->toHaveCount(1);
});

it('keys the session claim per user of that guard, with the guard\'s refresh limits', function () {
    $admin = Admin::factory()->create();
    $request = visitor();
    $request->setUserResolver(fn (?string $guard = null) => $guard === 'admin' ? $admin : null);

    [$limit] = limitsOf('lukk-admin-claim', $request);
    [$anonymous] = limitsOf('lukk-admin-claim');

    expect([$limit->maxAttempts, $limit->decaySeconds, $limit->key])->toBe([8, 81, 'lukk-admin-claim|admin|user|'.$admin->getKey()])
        ->and($anonymous->key)->toBe('lukk-admin-claim|'.Lukk::rateLimitKey(visitor()));
});
