<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Lukk\Events\AccountLocked;
use Lukk\Models\Lockout;
use Lukk\Tests\Fixtures\User;

beforeEach(function () {
    // The cap is what's under test, so keep the decaying throttles out of the way.
    config([
        'lukk.features.lockout' => true,
        'lukk.lockout.max_attempts' => 3,
        'lukk.lockout.release_after' => 0,
        'lukk.rate_limits.login.max_attempts' => 500,
        'lukk.rate_limits.login.ip_max_attempts' => 500,
        'lukk.rate_limits.login.account_max_attempts' => 500,
    ]);
});

/** One failed login, with guards forgotten so each attempt is a fresh request (see CLAUDE.md). */
function failLogin(string $email = 'victim@y.com')
{
    app('auth')->forgetGuards();

    return test()->postJson('/auth/login', ['email' => $email, 'password' => 'wrong']);
}

it('locks an account after the configured run of consecutive failures', function () {
    User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);

    failLogin()->assertStatus(422);
    failLogin()->assertStatus(422);
    failLogin()->assertStatus(422); // hits the cap

    // 423 rather than 429: with release_after at 0 "retry later" would be a lie.
    failLogin()->assertStatus(423);

    // And the lock holds even against the RIGHT password — that's what a lockout means.
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'correct'])->assertStatus(423);
});

it('counts consecutive failures, so a success in between clears the run', function () {
    User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);

    failLogin();
    failLogin();

    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'correct'])->assertOk();

    // The run restarted, so two more failures don't reach the cap of three.
    failLogin()->assertStatus(422);
    failLogin()->assertStatus(422);
    expect(Lockout::query()->where('subject', 'victim@y.com')->value('attempts'))->toBe(2);
});

it('locks one account without touching another', function () {
    User::factory()->create(['email' => 'victim@y.com']);
    User::factory()->create(['email' => 'bystander@y.com', 'password' => bcrypt('correct')]);

    for ($i = 0; $i < 3; $i++) {
        failLogin();
    }

    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'bystander@y.com', 'password' => 'correct'])->assertOk();
});

it('fires AccountLocked once, on the transition', function () {
    Event::fake([AccountLocked::class]);
    User::factory()->create(['email' => 'victim@y.com']);

    for ($i = 0; $i < 5; $i++) { // two past the cap
        failLogin();
    }

    // A locked-out user gets no other signal, so an app needs exactly one notification to hang off.
    Event::assertDispatchedTimes(AccountLocked::class, 1);
    Event::assertDispatched(AccountLocked::class, fn ($e) => $e->purpose === 'login' && $e->subject === 'victim@y.com');
});

it('auto-releases once release_after has elapsed', function () {
    config(['lukk.lockout.release_after' => 300]);
    User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);

    for ($i = 0; $i < 3; $i++) {
        failLogin();
    }
    failLogin()->assertStatus(423);

    // Bounding the denial is the point: a hard lockout is also a DoS primitive.
    $this->travel(301)->seconds();
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'correct'])->assertOk();
});

it('releases a lock from the console', function () {
    User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);

    for ($i = 0; $i < 3; $i++) {
        failLogin();
    }
    failLogin()->assertStatus(423);

    $this->artisan('lukk:release', ['subject' => 'victim@y.com'])->assertSuccessful();

    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'correct'])->assertOk();
});

it('stays completely inert while the feature is off', function () {
    config(['lukk.features.lockout' => false]);
    User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);

    for ($i = 0; $i < 10; $i++) {
        failLogin()->assertStatus(422); // never 423
    }

    expect(Lockout::query()->count())->toBe(0);
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'correct'])->assertOk();
});
