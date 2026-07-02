<?php

declare(strict_types=1);

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Notifications\ResetPassword as ResetPasswordNotification;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Schema;
use Lukk\Tests\Fixtures\User;

uses()->group('password-reset');

it('sends a reset link to a registered user', function () {
    Notification::fake();
    $user = User::factory()->create(['email' => 'a@b.c']);

    $this->postJson('/auth/forgot-password', ['email' => 'a@b.c'])
        ->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertJson(['status' => 'password-reset-link-sent']);

    Notification::assertSentTo($user, ResetPasswordNotification::class);
});

it('returns the same generic response for an unknown email (no enumeration)', function () {
    Notification::fake();

    $this->postJson('/auth/forgot-password', ['email' => 'ghost@y.com'])
        ->assertOk()
        ->assertJson(['status' => 'password-reset-link-sent']);

    Notification::assertNothingSent();
});

it('validates the email on forgot-password', function () {
    $this->postJson('/auth/forgot-password', ['email' => 'not-an-email'])->assertStatus(422);
});

it('points the reset link at the SPA frontend with the token + email', function () {
    $user = User::factory()->create(['email' => 'a@b.c']);
    $notification = new ResetPasswordNotification('the-token');

    config(['lukk.password_reset.frontend_url' => 'https://app.test/reset']);
    expect($notification->toMail($user)->actionUrl)->toBe('https://app.test/reset?token=the-token&email=a%40b.c');

    // Joins with `&` when the configured URL already carries a query string.
    config(['lukk.password_reset.frontend_url' => 'https://app.test/reset?ref=x']);
    expect($notification->toMail($user)->actionUrl)->toBe('https://app.test/reset?ref=x&token=the-token&email=a%40b.c');
});

it('resets the password with a valid token and fires PasswordReset', function () {
    Event::fake([PasswordReset::class]);
    $user = User::factory()->create(['email' => 'a@b.c']);
    $token = Password::createToken($user);

    $this->postJson('/auth/reset-password', [
        'token' => $token,
        'email' => 'a@b.c',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ])->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertJson(['status' => 'password-reset']);

    expect(Hash::check('new-password-123', $user->fresh()->password))->toBeTrue();
    Event::assertDispatched(PasswordReset::class);
});

it('returns an identical error for an unknown email as for a bad token (no enumeration)', function () {
    User::factory()->create(['email' => 'known@b.c']);

    $unknownEmail = $this->postJson('/auth/reset-password', [
        'token' => 'garbage-token',
        'email' => 'ghost@y.com',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ]);

    $knownEmailBadToken = $this->postJson('/auth/reset-password', [
        'token' => 'garbage-token',
        'email' => 'known@b.c',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ]);

    // Same status AND same body — the reset endpoint can't be used to tell which emails exist.
    $unknownEmail->assertStatus(422);
    $knownEmailBadToken->assertStatus(422);
    expect($unknownEmail->json('message'))->toBe($knownEmailBadToken->json('message'));
    expect($unknownEmail->json('errors'))->toEqual($knownEmailBadToken->json('errors'));
});

it('rejects a reset with an invalid token (422, password unchanged)', function () {
    $user = User::factory()->create(['email' => 'a@b.c']);

    $this->postJson('/auth/reset-password', [
        'token' => 'wrong-token',
        'email' => 'a@b.c',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ])->assertStatus(422);

    expect(Hash::check('password', $user->fresh()->password))->toBeTrue();
});

it('enforces password confirmation on reset', function () {
    $user = User::factory()->create(['email' => 'a@b.c']);
    $token = Password::createToken($user);

    $this->postJson('/auth/reset-password', [
        'token' => $token,
        'email' => 'a@b.c',
        'password' => 'new-password-123',
        'password_confirmation' => 'different-123',
    ])->assertStatus(422);
});

it('revokes every existing session on reset (default)', function () {
    $user = User::factory()->create(['email' => 'a@b.c']);
    $pair = $user->startSession(); // a session that predates the reset

    $this->postJson('/auth/reset-password', [
        'token' => Password::createToken($user),
        'email' => 'a@b.c',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ])->assertOk();

    // the pre-reset refresh token no longer works
    $this->postJson('/auth/refresh', ['refresh_token' => $pair->refreshToken])->assertStatus(401);
});

it('keeps existing sessions when revoke_sessions is disabled', function () {
    config(['lukk.password_reset.revoke_sessions' => false]);
    $user = User::factory()->create(['email' => 'a@b.c']);
    $pair = $user->startSession();

    $this->postJson('/auth/reset-password', [
        'token' => Password::createToken($user),
        'email' => 'a@b.c',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ])->assertOk();

    $this->postJson('/auth/refresh', ['refresh_token' => $pair->refreshToken])->assertOk();
});

it('mints and verifies reset tokens through the configured broker', function () {
    // A second broker backed by its own token table.
    Schema::create('alt_reset_tokens', function (Blueprint $table) {
        $table->string('email')->primary();
        $table->string('token');
        $table->timestamp('created_at')->nullable();
    });
    config([
        'auth.passwords.alt' => ['provider' => 'users', 'table' => 'alt_reset_tokens', 'expire' => 60, 'throttle' => 0],
        'lukk.password_reset.broker' => 'alt',
    ]);
    $user = User::factory()->create(['email' => 'a@b.c']);

    // forgot-password mints into the configured broker's table, not the default one.
    Notification::fake();
    $this->postJson('/auth/forgot-password', ['email' => 'a@b.c'])->assertOk();
    expect(DB::table('alt_reset_tokens')->where('email', 'a@b.c')->exists())->toBeTrue();
    expect(DB::table('password_reset_tokens')->where('email', 'a@b.c')->exists())->toBeFalse();

    // reset-password verifies against the same configured broker.
    $this->postJson('/auth/reset-password', [
        'token' => Password::broker('alt')->createToken($user),
        'email' => 'a@b.c',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ])->assertOk();
    expect(Hash::check('new-password-123', $user->fresh()->password))->toBeTrue();
});

it('logs in with the new password after a reset', function () {
    $user = User::factory()->create(['email' => 'a@b.c']);

    $this->postJson('/auth/reset-password', [
        'token' => Password::createToken($user),
        'email' => 'a@b.c',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ])->assertOk();

    $this->postJson('/auth/login', ['email' => 'a@b.c', 'password' => 'new-password-123'])
        ->assertOk()->assertJsonStructure(['access_token']);
});
