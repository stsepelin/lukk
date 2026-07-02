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

it('caps failures per account across changing source IPs (distributed brute force)', function () {
    // The IP-independent account cap bounds a distributed attacker who rotates IPs
    // to dodge the (email + IP) and per-IP limits. Small caps keep the test fast.
    config([
        'lukk.rate_limits.login.max_attempts' => 2,          // per (email + IP)
        'lukk.rate_limits.login.ip_max_attempts' => 100,     // not the bound here
        'lukk.rate_limits.login.account_max_attempts' => 3,  // per account, any IP
    ]);

    User::factory()->create(['email' => 'victim@y.com']);

    // Three failures against the account, each from a fresh IP so neither the
    // (email + IP) nor the per-IP limiter ever trips.
    foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3'] as $ip) {
        $this->app['auth']->forgetGuards();
        $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'bad'])
            ->assertStatus(422);
    }

    // A fourth attempt from yet another new IP is now blocked by the account cap.
    $this->app['auth']->forgetGuards();
    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.4'])
        ->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'bad'])
        ->assertStatus(429);
});

it('does not let trailing whitespace split the per-account login bucket', function () {
    config(['lukk.rate_limits.login.account_max_attempts' => 2]);

    User::factory()->create(['email' => 'trim@y.com']);

    // MySQL treats "trim@y.com" and "trim@y.com  " as the same row; the limiter key
    // must too (it trims), so padded variants share one bucket instead of minting fresh ones.
    $this->postJson('/auth/login', ['email' => 'trim@y.com', 'password' => 'bad'])->assertStatus(422);
    $this->app['auth']->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'trim@y.com  ', 'password' => 'bad'])->assertStatus(422);
    $this->app['auth']->forgetGuards();
    $this->postJson('/auth/login', ['email' => '  trim@y.com', 'password' => 'bad'])->assertStatus(429);
});
