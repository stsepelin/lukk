<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Lukk\Auth\LoginRateLimiter;

it('reports the wait of whichever bucket blocks longer', function () {
    // The IP bucket and the per-account bucket fill at different times; the caller has to wait out
    // the later one, or the retry it was told to make is refused again.
    $this->freezeSecond();
    $limiter = new LoginRateLimiter(app(RateLimiter::class), 5, 60, 5);
    $request = Request::create('/auth/login', 'POST', ['email' => 'ada@example.test'], server: ['REMOTE_ADDR' => '203.0.113.9']);

    app(RateLimiter::class)->hit($limiter->key($request), 60);
    $this->travel(30)->seconds();
    app(RateLimiter::class)->hit($limiter->accountKey($request), 60);

    expect($limiter->availableIn($request))->toBe(60);
});

/** A login request for `$identifier` from `$ip`. */
function loginRequest(string $identifier = 'ada@example.test', string $ip = '203.0.113.9'): Request
{
    return Request::create('/auth/login', 'POST', ['email' => $identifier], server: ['REMOTE_ADDR' => $ip]);
}

it('composes both bucket keys from the guard, the identifier and — for the IP bucket — the caller', function () {
    // Spelled out because the two buckets must stay distinct and guard-scoped: collapse them and a
    // flood on one guard locks a colliding account out of another, or the account cap becomes the
    // IP cap.
    $limiter = new LoginRateLimiter(app(RateLimiter::class), 5, 60, 5, 'email', 'admin');
    $request = loginRequest();

    expect($limiter->key($request))->toBe('admin|ada@example.test|'.Lukk\Lukk::rateLimitKey($request))
        ->and($limiter->accountKey($request))->toBe('acct|admin|ada@example.test');
});

it('clears both buckets on a successful sign-in', function () {
    // The account bucket survives an IP change by design, so leaving it behind means a user who
    // finally gets their password right still carries the failures to their next attempt.
    $limiter = new LoginRateLimiter(app(RateLimiter::class), 5, 60, 5);
    $request = loginRequest();
    $limiter->increment($request);

    $limiter->clear($request);

    expect(app(RateLimiter::class)->attempts($limiter->key($request)))->toBe(0)
        ->and(app(RateLimiter::class)->attempts($limiter->accountKey($request)))->toBe(0);
});

it('normalizes an identifier before it becomes a bucket', function () {
    // Trimmed, lower-cased and transliterated, so `  Ada@Example.test ` shares one bucket with the
    // address the user actually typed at their last attempt.
    expect(LoginRateLimiter::normalize('  Ada@Example.test '))->toBe('ada@example.test');
});

it('hashes an identifier longer than 190 characters, and keeps one that is not', function () {
    // Cache keys are bounded; the boundary itself is pinned so a long address cannot slip past it
    // and blow the key length.
    $at190 = str_repeat('a', 184).'@x.com';
    $at191 = str_repeat('a', 185).'@x.com';

    expect(strlen($at190))->toBe(190)
        ->and(LoginRateLimiter::normalize($at190))->toBe($at190)
        ->and(LoginRateLimiter::normalize($at191))->toBe('sha256:'.hash('sha256', $at191));
});
