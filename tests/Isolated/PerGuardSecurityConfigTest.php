<?php

declare(strict_types=1);

use Illuminate\Testing\TestResponse;
use Lukk\Tests\Fixtures\Admin;
use Lukk\Tests\MultiGuardTestCase;

// A guard that hardens itself — the lockout on, tighter caps — as the multiple-guards docs recommend for
// an admin guard. These were read from the GLOBAL block, so the override was silently dropped and the
// admin guard got no lockout and the user guard's looser limits: the same fail-open class as the
// per-guard `features.abilities` incident. They are read through `Lukk::guardConfig()` now.
uses(MultiGuardTestCase::class)->group('multi-guard');

function adminFail(object $test, string $email = 'boss@corp.com'): TestResponse
{
    app('auth')->forgetGuards();

    return $test->postJson('/admin/auth/login', ['email' => $email, 'password' => 'wrong']);
}

it('applies a lockout switched on for one guard only', function () {
    config([
        'lukk.features.lockout' => false,
        'lukk.guards.admin.features.lockout' => true,
        'lukk.guards.admin.lockout.max_attempts' => 2,
        'lukk.guards.admin.rate_limits.login.max_attempts' => 500,
        'lukk.guards.admin.rate_limits.login.account_max_attempts' => 500,
        'lukk.guards.admin.rate_limits.login.ip_max_attempts' => 500,
    ]);
    Admin::factory()->create(['email' => 'boss@corp.com']);

    adminFail($this)->assertStatus(422);
    adminFail($this)->assertStatus(422);
    adminFail($this)->assertStatus(423);
});

it('applies one guard\'s own login limits', function () {
    config([
        'lukk.rate_limits.login.max_attempts' => 500,
        'lukk.guards.admin.rate_limits.login.max_attempts' => 2,
        'lukk.guards.admin.rate_limits.login.ip_max_attempts' => 500,
    ]);
    Admin::factory()->create(['email' => 'boss@corp.com']);

    adminFail($this)->assertStatus(422);
    adminFail($this)->assertStatus(422);
    adminFail($this)->assertStatus(429);
});
