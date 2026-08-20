<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Lukk\Tests\Fixtures\User;

uses()->group('confirmation');

// A throwaway route gated by step-up confirmation, to exercise the middleware
// in isolation (the 2FA/passkey management routes use the same gate).
beforeEach(function () {
    Route::middleware(['auth:api', 'lukk.confirm'])
        ->post('/_test/sensitive', fn () => response()->json(['ok' => true]));
});

it('earns a confirmation token by re-entering the password', function () {
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)
        ->postJson('/auth/confirm-password', ['password' => 'password'])
        ->assertOk()
        ->assertJsonStructure(['confirmation_token']);
});

it('rejects confirmation with a wrong password', function () {
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)
        ->postJson('/auth/confirm-password', ['password' => 'wrong-pw'])
        ->assertStatus(422)
        ->assertJsonValidationErrors(['password']);
});

it('locks a gated route (423) when no confirmation is presented', function () {
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)->postJson('/_test/sensitive')->assertStatus(423);
});

it('locks a gated route (423) when the confirmation token is garbage', function () {
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)
        ->withHeaders(['X-Lukk-Confirmation' => 'not-a-real-token'])
        ->postJson('/_test/sensitive')
        ->assertStatus(423);
});

it('allows a gated route once a fresh confirmation is presented', function () {
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)
        ->withHeaders(confirmedHeaders($access))
        ->postJson('/_test/sensitive')
        ->assertOk()
        ->assertJson(['ok' => true]);
});

it('rejects a confirmation token earned by another user', function () {
    $alice = User::factory()->create()->startSession()->accessToken;
    $bob = User::factory()->create()->startSession()->accessToken;

    // Alice earns a confirmation, Bob tries to spend it.
    $aliceConfirmation = confirmedHeaders($alice);
    $this->app['auth']->forgetGuards(); // model the per-request guard boundary

    $this->withToken($bob)
        ->withHeaders($aliceConfirmation)
        ->postJson('/_test/sensitive')
        ->assertStatus(423);
});

it('expires the confirmation after the configured window', function () {
    $access = User::factory()->create()->startSession()->accessToken;

    // Earn the token at a clock far enough in the past that it is already expired.
    $stale = $this->travel(-(int) config('lukk.confirm.ttl') - 10)
        ->seconds(fn () => confirmedHeaders($access));

    $this->withToken($access)
        ->withHeaders($stale)
        ->postJson('/_test/sensitive')
        ->assertStatus(423);
});

// ---------------------------------------------------------------------------
// Throttling. `/auth/confirm-password` re-verifies the SAME secret as login, so
// leaving it unmetered made the sudo gate an unlimited password oracle for
// anyone already holding an access token.
// ---------------------------------------------------------------------------

/** One failed confirmation, with guards forgotten so each attempt is a fresh request (see CLAUDE.md). */
function failConfirm(string $access, array $server = [])
{
    app('auth')->forgetGuards();

    return test()->withToken($access)->withServerVariables($server)
        ->postJson('/auth/confirm-password', ['password' => 'wrong-pw']);
}

it('throttles password confirmation instead of allowing unlimited guesses', function () {
    config(['lukk.rate_limits.confirm.max_attempts' => 3]);
    $access = User::factory()->create()->startSession()->accessToken;

    failConfirm($access)->assertStatus(422);
    failConfirm($access)->assertStatus(422);
    failConfirm($access)->assertStatus(422);

    failConfirm($access)->assertStatus(429);
});

it('buckets confirmation per user, so one account cannot throttle another', function () {
    // Distinct addresses, or the per-IP half of the limit would fire first and prove nothing.
    config(['lukk.rate_limits.confirm.max_attempts' => 2]);
    $victim = User::factory()->create()->startSession()->accessToken;
    $other = User::factory()->create()->startSession()->accessToken;

    failConfirm($victim, ['REMOTE_ADDR' => '203.0.113.1']);
    failConfirm($victim, ['REMOTE_ADDR' => '203.0.113.1']);
    failConfirm($victim, ['REMOTE_ADDR' => '203.0.113.1'])->assertStatus(429);

    failConfirm($other, ['REMOTE_ADDR' => '203.0.113.2'])->assertStatus(422);
});

it('bounds a token thief who rotates addresses, because the bucket is the user', function () {
    // The per-IP limit alone is worthless here: a stolen token is one identity behind as many
    // addresses as the attacker cares to use.
    config(['lukk.rate_limits.confirm.max_attempts' => 2]);
    $access = User::factory()->create()->startSession()->accessToken;

    failConfirm($access, ['REMOTE_ADDR' => '198.51.100.1']);
    failConfirm($access, ['REMOTE_ADDR' => '198.51.100.2']);

    failConfirm($access, ['REMOTE_ADDR' => '198.51.100.3'])->assertStatus(429);
});
