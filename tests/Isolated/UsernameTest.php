<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\UsernameTestCase;

// Outside Feature/ so this file can bind its own base case — one that boots with the identifier
// overridden to `username` and a matching users table — proving login + register by a non-email column.
uses(UsernameTestCase::class)->group('registration');

it('authenticates by username instead of email', function () {
    User::factory()->create(['username' => 'ada']);

    $this->postJson('/auth/login', ['username' => 'ada', 'password' => 'password'])
        ->assertOk()
        ->assertJsonStructure(['access_token', 'refresh_token']);
});

it('keys a failed-login error on the configured identifier, not email', function () {
    User::factory()->create(['username' => 'ada']);

    $this->postJson('/auth/login', ['username' => 'ada', 'password' => 'wrong-pw'])
        ->assertStatus(422)
        ->assertJsonValidationErrors('username');
});

it('registers by username instead of email', function () {
    Notification::fake();

    $this->postJson('/auth/register', [
        'name' => 'New User',
        'username' => 'newbie',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ])->assertOk()->assertJsonStructure(['access_token']);

    $user = User::where('username', 'newbie')->first();
    expect($user)->not->toBeNull()->and($user->name)->toBe('New User');
});
