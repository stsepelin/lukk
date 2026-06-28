<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Lukk;
use Lukk\Tests\Fixtures\User;

afterEach(function () {
    Lukk::$authenticateUsing = null;
});

it('fires a Lockout event when the login throttle trips', function () {
    Event::fake([Lockout::class]);
    User::factory()->create(['email' => 'lock@y.com']);

    foreach (range(1, 6) as $i) {
        $this->postJson('/auth/login', ['email' => 'lock@y.com', 'password' => 'bad']);
    }

    Event::assertDispatched(Lockout::class);
});

it('authenticates valid email + password against the user provider', function () {
    User::factory()->create(['email' => 'x@y.com']);

    $this->postJson('/auth/login', ['email' => 'x@y.com', 'password' => 'password'])
        ->assertOk()
        ->assertJsonStructure(['access_token', 'refresh_token', 'token_type', 'expires_in']);
});

it('rejects bad credentials with a 422 and no token', function () {
    User::factory()->create(['email' => 'x@y.com']);

    $this->postJson('/auth/login', ['email' => 'x@y.com', 'password' => 'wrong-pw'])
        ->assertStatus(422)
        ->assertJsonMissing(['access_token']);
});

it('rejects an unknown user with a 422 (constant-time path, no leak)', function () {
    $this->postJson('/auth/login', ['email' => 'ghost@y.com', 'password' => 'whatever'])
        ->assertStatus(422);
});

it('stamps amr=[pwd] on a password-only login token', function () {
    User::factory()->create(['email' => 'x@y.com']);

    $access = $this->postJson('/auth/login', ['email' => 'x@y.com', 'password' => 'password'])->json('access_token');

    expect(verifier()->verify($access)->amr)->toBe(['pwd']);
});

it('returns an identical response for an unknown user and a wrong password', function () {
    User::factory()->create(['email' => 'real@y.com']);

    $wrongPassword = $this->postJson('/auth/login', ['email' => 'real@y.com', 'password' => 'wrong-pw']);
    $unknownUser = $this->postJson('/auth/login', ['email' => 'ghost@y.com', 'password' => 'wrong-pw']);

    expect($wrongPassword->status())->toBe($unknownUser->status())
        ->and($wrongPassword->json())->toEqual($unknownUser->json());
});

it('honors a custom authenticateUsing hook over the default provider', function () {
    $user = User::factory()->create(['email' => 'hook@y.com']);

    Lukk::authenticateUsing(fn ($request) => $request->input('email') === 'hook@y.com' ? $user : null);

    // Wrong password, but the hook ignores it and authenticates by email alone.
    $this->postJson('/auth/login', ['email' => 'hook@y.com', 'password' => 'irrelevant'])
        ->assertOk()
        ->assertJsonStructure(['access_token', 'refresh_token']);
});

it('fails the login when the authenticateUsing hook returns null', function () {
    Lukk::authenticateUsing(fn ($request) => null);

    $this->postJson('/auth/login', ['email' => 'anyone@y.com', 'password' => 'x'])
        ->assertStatus(422);
});

it('locks out after too many failed attempts with a 429 validation error', function () {
    User::factory()->create(['email' => 'target@y.com']);

    foreach (range(1, 5) as $i) {
        $this->postJson('/auth/login', ['email' => 'target@y.com', 'password' => 'bad']);
    }

    $this->postJson('/auth/login', ['email' => 'target@y.com', 'password' => 'bad'])
        ->assertStatus(429)
        ->assertJsonValidationErrors(['email']);
});

it('clears the throttle counter on a successful login', function () {
    User::factory()->create(['email' => 'target@y.com']);

    foreach (range(1, 4) as $i) {
        $this->postJson('/auth/login', ['email' => 'target@y.com', 'password' => 'bad']);
    }

    $this->postJson('/auth/login', ['email' => 'target@y.com', 'password' => 'password'])->assertOk();

    // Counter reset: further failures are a fresh window, not an immediate lockout.
    $this->postJson('/auth/login', ['email' => 'target@y.com', 'password' => 'bad'])->assertStatus(422);
    $this->postJson('/auth/login', ['email' => 'target@y.com', 'password' => 'bad'])->assertStatus(422);
});

it('keys the throttle on a normalized email so case does not split the bucket', function () {
    $limiter = app(LoginRateLimiter::class);

    $upper = Request::create('/', 'POST', ['email' => 'USER@Example.com']);
    $lower = Request::create('/', 'POST', ['email' => 'user@example.com']);

    expect($limiter->key($upper))->toBe($limiter->key($lower));
});
