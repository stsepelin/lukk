<?php

declare(strict_types=1);

use Lukk\Tests\Fixtures\User;

it('throttles token refresh per the configured rate limit', function () {
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);

    $this->postJson('/auth/refresh', ['refresh_token' => 'x']);                    // 1st — allowed through
    $this->postJson('/auth/refresh', ['refresh_token' => 'x'])->assertStatus(429); // 2nd — throttled
});

it('throttles passkey endpoints per the configured rate limit', function () {
    config(['lukk.rate_limits.passkeys.max_attempts' => 1]);

    $this->postJson('/auth/passkeys/login-options');                              // 1st — allowed
    $this->postJson('/auth/passkeys/login-options')->assertStatus(429);           // 2nd — throttled
});

it('does not lock out login when a published config predates ip_max_attempts', function () {
    // Simulate a stale published config: mergeConfigFrom does not deep-merge
    // nested arrays, so a config written before this key existed lacks it
    // entirely. The limiter must fall back to a sane cap, not Limit(0) (429-all).
    config(['lukk.rate_limits.login' => ['max_attempts' => 5, 'decay_seconds' => 60]]);

    User::factory()->create(['email' => 'drift@y.com']);

    $this->postJson('/auth/login', ['email' => 'drift@y.com', 'password' => 'password'])->assertOk();
});

it('caps total login attempts per IP, defeating spraying across emails', function () {
    config(['lukk.rate_limits.login.ip_max_attempts' => 2]);

    // A different email each time, so the per-account failure limiter never
    // trips — but the per-IP cap still bounds the total.
    $this->postJson('/auth/login', ['email' => 'a@y.com', 'password' => 'x']);
    $this->postJson('/auth/login', ['email' => 'b@y.com', 'password' => 'x']);
    $this->postJson('/auth/login', ['email' => 'c@y.com', 'password' => 'x'])->assertStatus(429);
});
