<?php

declare(strict_types=1);

use Lukk\Lukk;
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

beforeEach(function () {
    Lukk::$rateLimitKeyUsing = null;
});

it('buckets an IPv6 visitor by /64, so rotating within their prefix does not mint fresh limits', function () {
    // A subscriber is typically handed a whole /64. Keyed on the full address, one visitor could
    // mint effectively unlimited buckets and walk through every per-IP limit — which only starts to
    // bite once a BFF forwards the real client instead of its own address.
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);

    $this->withServerVariables(['REMOTE_ADDR' => '2001:db8:1:2::1'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x']);

    $this->withServerVariables(['REMOTE_ADDR' => '2001:db8:1:2:aaaa:bbbb:cccc:dddd'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x'])
        ->assertStatus(429);
});

it('keeps separate /64s in separate buckets', function () {
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);

    $this->withServerVariables(['REMOTE_ADDR' => '2001:db8:1:2::1'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x']);

    // A different prefix is a different subscriber — it must not inherit the neighbour's budget.
    // 401 (the bogus token was actually rejected) proves the request reached the handler at all.
    $this->withServerVariables(['REMOTE_ADDR' => '2001:db8:1:3::1'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x'])
        ->assertStatus(401);
});

it('unwraps an IPv4-mapped address instead of collapsing every one into ::/64', function () {
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);

    $this->withServerVariables(['REMOTE_ADDR' => '::ffff:1.2.3.4'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x']);

    // Truncating these to /64 would put every mapped address in one shared bucket, so an unrelated
    // visitor would inherit the first one's exhausted budget.
    $this->withServerVariables(['REMOTE_ADDR' => '::ffff:5.6.7.8'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x'])
        ->assertStatus(401);
});

it('keeps NAT64-translated callers apart instead of collapsing them into one bucket', function () {
    // An IPv6-only network behind a NAT64 gateway reaches us as 64:ff9b::<v4>. Masking those to a
    // /64 would put the entire translated client population on one counter — a self-inflicted 429
    // storm — so the embedded IPv4 is unwrapped first.
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);

    $this->withServerVariables(['REMOTE_ADDR' => '64:ff9b::1.2.3.4'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x']);

    $this->withServerVariables(['REMOTE_ADDR' => '64:ff9b::5.6.7.8'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x'])
        ->assertStatus(401);
});

it('honours a configured ipv6_prefix, for networks where a /64 is the wrong boundary', function () {
    // An office LAN shares one /64, so /64 buckets the whole floor together; 128 gives each host
    // its own. The knob exists because the right boundary is a property of the deployment.
    config(['lukk.rate_limits.refresh.max_attempts' => 1, 'lukk.rate_limits.ipv6_prefix' => 128]);

    $this->withServerVariables(['REMOTE_ADDR' => '2001:db8:1:2::1'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x']);

    $this->withServerVariables(['REMOTE_ADDR' => '2001:db8:1:2::2'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x'])
        ->assertStatus(401);
});

it('falls back to the address when a custom key resolver returns nothing', function () {
    // An empty return would silently put EVERY caller in one bucket — the deployment looks healthy
    // until it 429s all at once. Falling back keeps the limiter per-caller.
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);
    Lukk::rateLimitKeyUsing(fn ($request) => $request->header('X-Absent', ''));

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x']);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.2'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x'])
        ->assertStatus(401);
});

it('lets an app replace the throttle identity entirely via rateLimitKeyUsing', function () {
    // For deployments where the source address is not the right identity — a shared API gateway, a
    // tenant-scoped limit, a CDN's own visitor token.
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);
    Lukk::rateLimitKeyUsing(fn ($request) => 'tenant-'.$request->header('X-Tenant', 'none'));

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x'], ['X-Tenant' => 'acme']);

    // Different IP, same tenant — one bucket, because the app said so.
    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.2'])
        ->postJson('/auth/refresh', ['refresh_token' => 'x'], ['X-Tenant' => 'acme'])
        ->assertStatus(429);
});

it('caps verification resends per user, so rotating IPs cannot mail-bomb one address', function () {
    // The route is authenticated but was keyed only on IP, so a single session could rotate source
    // addresses and resend without limit. The user is the identity this endpoint actually acts on.
    config(['lukk.rate_limits.email_verification.max_attempts' => 2]);
    $user = User::factory()->create(['email_verified_at' => null]);
    $token = $user->startSession()->accessToken;

    foreach (['10.0.0.1', '10.0.0.2'] as $ip) {
        $this->app['auth']->forgetGuards();
        $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->withToken($token)
            ->postJson('/auth/email/verification-notification')
            ->assertStatus(202);
    }

    $this->app['auth']->forgetGuards();
    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.3'])
        ->withToken($token)
        ->postJson('/auth/email/verification-notification')
        ->assertStatus(429);
});

it('does not let one user\'s verification resends throttle another user', function () {
    config(['lukk.rate_limits.email_verification.max_attempts' => 1]);
    $first = User::factory()->create(['email_verified_at' => null]);
    $second = User::factory()->create(['email_verified_at' => null]);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->withToken($first->startSession()->accessToken)
        ->postJson('/auth/email/verification-notification')
        ->assertStatus(202);

    // A different user from a different address shares neither bucket. Distinct IPs are the point:
    // with the same IP the per-IP limit would answer first and this would prove nothing about the
    // per-user one being correctly scoped.
    $this->app['auth']->forgetGuards();
    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.2'])
        ->withToken($second->startSession()->accessToken)
        ->postJson('/auth/email/verification-notification')
        ->assertStatus(202);
});
