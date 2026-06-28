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
