<?php

declare(strict_types=1);

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Notifications\ResetPassword as ResetPasswordNotification;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
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

    // Unset (an unset env, or a config cached before the key): a relative link, not a TypeError from
    // `str_contains(null, …)` under strict_types.
    config(['lukk.password_reset.frontend_url' => null]);
    expect($notification->toMail($user)->actionUrl)->toBe('?token=the-token&email=a%40b.c');

    // `env()` turns the literal "false" into a boolean — the same relative link, not a TypeError.
    config(['lukk.password_reset.frontend_url' => false]);
    expect($notification->toMail($user)->actionUrl)->toBe('?token=the-token&email=a%40b.c');
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

    expect(Hash::check('new-password-123', $user->refresh()->password))->toBeTrue();
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

    expect(Hash::check('password', $user->refresh()->password))->toBeTrue();
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
    expect(Hash::check('new-password-123', $user->refresh()->password))->toBeTrue();
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

/** Spy on the Timebox; read `->seen` for the budget each forgot-password request was boxed in. */
function resetBudgets(): object
{
    $spy = new class extends Timebox
    {
        /** @var list<int> */
        public array $seen = [];

        public function call(callable $callback, int $microseconds)
        {
            $this->seen[] = $microseconds;

            return $callback($this);
        }
    };
    app()->instance(Timebox::class, $spy);

    return $spy;
}

it('boxes a known and an unknown address in the same budget, so timing cannot enumerate', function () {
    // The RESPONSE was already constant; the TIMING was not. The broker pads every outcome to its
    // own 200 ms box, and lukk then ran an equalizing `Hash::make` AFTER it on a miss — so a miss
    // cost 200 ms plus a hash while a hit cost ~200 ms in total: measured 460 ms against 259 ms at
    // bcrypt cost 12, never overlapping. Equal WORK was the wrong invariant, because one derivation
    // sat inside a padded box and the other outside it. The whole call is now boxed.
    config(['lukk.password_reset.timebox_micros' => 600_000]);
    User::factory()->create(['email' => 'known@y.com']);
    $spy = resetBudgets();

    $this->postJson('/auth/forgot-password', ['email' => 'known@y.com'])->assertOk();
    $this->postJson('/auth/forgot-password', ['email' => 'nobody@y.com'])->assertOk();

    expect($spy->seen)->toBe([600_000, 600_000]);
});

it('does no extra hashing on a miss — the box, not a second derivation, equalizes it', function () {
    // The post-broker `Hash::make` is what put the two outcomes 200 ms apart; it must not come back.
    Hash::swap($hasher = new class(app('hash')->driver()) implements Hasher
    {
        public int $made = 0;

        public function __construct(private readonly Hasher $inner) {}

        public function info($hashedValue): array
        {
            return $this->inner->info($hashedValue);
        }

        public function make($value, array $options = []): string
        {
            $this->made++;

            return $this->inner->make($value, $options);
        }

        public function check($value, $hashedValue, array $options = []): bool
        {
            return $this->inner->check($value, $hashedValue, $options);
        }

        public function needsRehash($hashedValue, array $options = []): bool
        {
            return $this->inner->needsRehash($hashedValue, $options);
        }
    });

    $this->postJson('/auth/forgot-password', ['email' => 'nobody@y.com'])->assertOk();

    expect($hasher->made)->toBe(0);
});

it('falls back to a one-second reset budget when the key is missing', function () {
    // Above the broker's own 200 ms box plus one bcrypt derivation at cost 12 plus dispatching the
    // notification — the three things a hit pays that a miss does not. A config cached before the key
    // existed must get that, not no box at all.
    $lukk = (array) config('lukk');
    unset($lukk['password_reset']['timebox_micros']);
    config()->set('lukk', $lukk);
    $spy = resetBudgets();

    $this->postJson('/auth/forgot-password', ['email' => 'nobody@y.com'])->assertOk();

    expect($spy->seen)->toBe([1_000_000]);
});

it('reads a reset budget that arrives as a string', function () {
    config(['lukk.password_reset.timebox_micros' => '1']);

    $this->postJson('/auth/forgot-password', ['email' => 'nobody@y.com'])->assertOk();
});

it('revokes existing sessions when revoke_sessions is unset — the default is on', function () {
    $lukk = (array) config('lukk');
    unset($lukk['password_reset']['revoke_sessions']);
    config()->set('lukk', $lukk);
    $user = User::factory()->create(['email' => 'a@b.c']);
    $pair = $user->startSession();

    $this->postJson('/auth/reset-password', [
        'token' => Password::createToken($user),
        'email' => 'a@b.c',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ])->assertOk();

    $this->postJson('/auth/refresh', ['refresh_token' => $pair->refreshToken])->assertStatus(401);
});

it('answers every failed reset with the one generic token message', function () {
    User::factory()->create(['email' => 'a@b.c']);

    $this->postJson('/auth/reset-password', [
        'token' => 'not-a-token', 'email' => 'a@b.c',
        'password' => 'new-password-123', 'password_confirmation' => 'new-password-123',
    ])->assertStatus(422)->assertJsonValidationErrors(['email' => __('passwords.token')]);
});
