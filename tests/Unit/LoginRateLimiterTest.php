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
