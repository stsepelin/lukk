<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Listeners\SendEmailVerificationNotification;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Contracts\Validation\Rule;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Validation\Rules\Password;
use Lukk\Actions\Register;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Lukk;
use Lukk\Support\RefreshCookie;
use Lukk\Tests\Fixtures\User;

uses()->group('registration');

afterEach(function () {
    Lukk::$registerUsing = null;
    Lukk::$registerValidation = null;
});

function registerPayload(array $overrides = []): array
{
    return array_merge([
        'name' => 'New User',
        'email' => 'new@user.com',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ], $overrides);
}

it('registers a new user and returns a token pair (BFF mode)', function () {
    Notification::fake();

    $this->postJson('/auth/register', registerPayload())
        ->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertJsonStructure(['access_token', 'refresh_token', 'expires_in']);

    // The default create writes Laravel's `name` out of the box (stock schema).
    $user = User::where('email', 'new@user.com')->first();
    expect($user)->not->toBeNull()->and($user->name)->toBe('New User');
});

it('requires the name field by default (stock Laravel schema)', function () {
    $this->postJson('/auth/register', registerPayload(['name' => null]))
        ->assertStatus(422)
        ->assertJsonValidationErrors('name');
});

it('creates the account without a session when registration.login is off', function () {
    Notification::fake();
    config(['lukk.registration.login' => false]);

    $this->postJson('/auth/register', registerPayload())
        ->assertStatus(201)
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertJson(['registered' => true, 'requires_verification' => false])
        ->assertJsonMissingPath('access_token');

    expect(User::where('email', 'new@user.com')->exists())->toBeTrue();
});

it('hashes the password (never stores plaintext)', function () {
    Notification::fake();

    $this->postJson('/auth/register', registerPayload())->assertOk();

    $user = User::where('email', 'new@user.com')->first();
    expect($user->password)->not->toBe('new-password-123')
        ->and(Hash::check('new-password-123', $user->password))->toBeTrue();
});

it('registers in cookie mode: access token in body, refresh in a cookie', function () {
    Notification::fake();
    config(['lukk.cookie_mode' => true]);

    $this->postJson('/auth/register', registerPayload())
        ->assertOk()
        ->assertJsonStructure(['access_token', 'expires_in'])
        ->assertJsonMissingPath('refresh_token')
        ->assertCookie(RefreshCookie::name());
});

it('fires the Registered event (so email verification can send its link)', function () {
    Event::fake([Registered::class]);

    $this->postJson('/auth/register', registerPayload())->assertOk();

    Event::assertDispatched(Registered::class);
});

it('sends the verification link on register when the app listens for Registered', function () {
    Notification::fake();
    Event::listen(Registered::class, SendEmailVerificationNotification::class);

    $this->postJson('/auth/register', registerPayload())->assertOk();

    Notification::assertSentTo(User::where('email', 'new@user.com')->first(), VerifyEmail::class);
});

it('lets registerUsing fully control user creation', function () {
    Notification::fake();
    Lukk::registerUsing(fn (array $payload) => User::forceCreate([
        'email' => $payload['email'],
        'password' => Hash::make($payload['password']),
        // Mark verified on creation — proves OUR hook ran (the default create leaves this null).
        'email_verified_at' => now(),
    ]));

    $this->postJson('/auth/register', registerPayload())->assertOk();

    expect(User::where('email', 'new@user.com')->firstOrFail()->email_verified_at)->not->toBeNull();
});

it('accepts an invokable class-string for registerUsing', function () {
    Notification::fake();
    Lukk::registerUsing(RegistersMarkedUser::class);

    $this->postJson('/auth/register', registerPayload())->assertOk();

    expect(User::where('email', 'new@user.com')->firstOrFail()->email_verified_at)->not->toBeNull();
});

it('lets registerValidation declare custom required fields', function () {
    Notification::fake();
    Lukk::registerValidation(fn ($request) => [
        'name' => ['required', 'string'],
        'email' => ['required', 'email'],
        'password' => ['required', 'confirmed', 'min:8'],
        'username' => ['required', 'string'], // an extra field the default rules don't have
    ]);

    // Missing the custom field → 422.
    $this->postJson('/auth/register', registerPayload())->assertStatus(422)->assertJsonValidationErrors('username');

    // With it → created.
    $this->postJson('/auth/register', registerPayload(['username' => 'newbie']))->assertOk();
    expect(User::where('email', 'new@user.com')->exists())->toBeTrue();
});

it('returns a 2FA challenge when the new user is already enrolled', function () {
    Notification::fake();
    Lukk::registerUsing(function (array $payload) {
        $user = User::forceCreate(['email' => $payload['email'], 'password' => Hash::make($payload['password'])]);
        $user->forceFill([
            'two_factor_secret' => Crypt::encryptString(app(TwoFactorProvider::class)->generateSecret()),
            'two_factor_confirmed_at' => now(),
        ])->save();

        return $user;
    });

    $this->postJson('/auth/register', registerPayload())
        ->assertOk()
        ->assertJson(['two_factor' => true])
        ->assertJsonStructure(['challenge_token'])
        ->assertJsonMissingPath('access_token');
});

it('does not issue a session when block_unverified_login is on', function () {
    Notification::fake();
    config(['lukk.email_verification.block_unverified_login' => true]);

    $this->postJson('/auth/register', registerPayload())
        ->assertStatus(201)
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertJson(['registered' => true, 'requires_verification' => true])
        ->assertJsonMissingPath('access_token');

    expect(User::where('email', 'new@user.com')->exists())->toBeTrue();
});

it('rejects a duplicate email with a 422', function () {
    User::factory()->create(['email' => 'taken@user.com']);

    $this->postJson('/auth/register', registerPayload(['email' => 'taken@user.com']))
        ->assertStatus(422)
        ->assertJsonValidationErrors('email');
});

it('requires a confirmed password', function () {
    $this->postJson('/auth/register', registerPayload(['password_confirmation' => 'different-123']))
        ->assertStatus(422)
        ->assertJsonValidationErrors('password');
});

it('bounds the password length (verifier DoS)', function () {
    $long = str_repeat('a', 256);

    $this->postJson('/auth/register', registerPayload(['password' => $long, 'password_confirmation' => $long]))
        ->assertStatus(422)
        ->assertJsonValidationErrors('password');
});

it('rejects a malformed email with a 422, not a 500', function () {
    $this->postJson('/auth/register', registerPayload(['email' => 'not-an-email']))
        ->assertStatus(422)
        ->assertJsonValidationErrors('email');
});

it('rejects a registerUsing hook that does not return an Authenticatable', function () {
    Lukk::registerUsing(fn (array $payload) => 'not-a-user');

    expect(fn () => app(Register::class)(['email' => 'x@y.com', 'password' => 'secret-123456']))
        ->toThrow(RuntimeException::class);
});

it('rejects a registerUsing hook that returns an existing user (no takeover)', function () {
    $existing = User::factory()->create(['email' => 'existing@user.com']);
    // Re-fetch so wasRecentlyCreated is false — i.e. a firstOrCreate-style existing account.
    Lukk::registerUsing(fn (array $payload) => User::find($existing->getKey()));

    expect(fn () => app(Register::class)(['email' => 'x@y.com', 'password' => 'secret-123456']))
        ->toThrow(RuntimeException::class);
});

it('rejects the default create when the payload lacks email or password', function () {
    expect(fn () => app(Register::class)(['email' => 'x@y.com']))
        ->toThrow(RuntimeException::class);
});

it('throttles the register endpoint per IP', function () {
    Notification::fake();
    config(['lukk.rate_limits.registration.max_attempts' => 2]);

    $this->postJson('/auth/register', registerPayload(['email' => 'a1@x.com']))->assertOk();
    $this->postJson('/auth/register', registerPayload(['email' => 'a2@x.com']))->assertOk();
    $this->postJson('/auth/register', registerPayload(['email' => 'a3@x.com']))->assertStatus(429);
});

/** An invokable "create user" action, to exercise the class-string form of Lukk::registerUsing. */
class RegistersMarkedUser
{
    public function __invoke(array $payload): User
    {
        return User::forceCreate([
            'email' => $payload['email'],
            'password' => Hash::make($payload['password']),
            'email_verified_at' => now(),
        ]);
    }
}

it('answers a malformed identifier with 422, never a 500 — even from the throttle', function () {
    // Throttle middleware runs BEFORE the FormRequest, so anything reading raw input there has to
    // tolerate a malformed type. A per-identifier registration limit once broke exactly this.
    $this->postJson('/auth/register', ['email' => ['a', 'b'], 'password' => 'x'])->assertStatus(422);
    $this->postJson('/auth/register', ['email' => ['x' => 'y'], 'password' => 'x'])->assertStatus(422);
});

it('bounds the signup identifier length on this unauthenticated endpoint', function () {
    // `email` + `unique` against an unbounded string is real work for an anonymous caller.
    $this->postJson('/auth/register', ['name' => 'A', 'email' => str_repeat('a', 300).'@y.com', 'password' => 'x'])
        ->assertStatus(422)
        ->assertJsonValidationErrors('email');
});

it('signs the new user in when registration.login is unset — the default is on', function () {
    Notification::fake();
    $lukk = (array) config('lukk');
    unset($lukk['registration']['login']);
    config()->set('lukk', $lukk);

    $access = $this->postJson('/auth/register', registerPayload())->assertOk()->json('access_token');

    expect(claims($access)->amr)->toBe(['pwd']);
});

it('refuses a password that is not a string under the default rules, whatever Password::defaults() is', function () {
    // The default set relied on the app's `Password::defaults()` to say "string"; an app registering its
    // own rule object there let a JSON number through to be cast and stored.
    Notification::fake();
    Password::defaults(fn () => new class implements Rule
    {
        public function passes($attribute, $value): bool
        {
            return true;
        }

        public function message(): string
        {
            return '';
        }
    });

    try {
        $this->postJson('/auth/register', registerPayload(['password' => 12345678, 'password_confirmation' => 12345678]))
            ->assertStatus(422)->assertJsonValidationErrors('password');
    } finally {
        // Process-static: left set, it would leak into every later test.
        Password::$defaultCallback = null;
    }
});

it('refuses a name that is not valid UTF-8 before the insert', function () {
    // PostgreSQL refuses an invalid UTF-8 sequence in a query parameter (SQLSTATE 22021): a 500 on a
    // public route. `email` already refuses such an address; the name reached the INSERT.
    $this->post('/auth/register', [
        'name' => "\xFF", 'email' => 'new@example.test', 'password' => 'password-123', 'password_confirmation' => 'password-123',
    ], ['Accept' => 'application/json'])->assertStatus(422)->assertJsonValidationErrors('name');

    expect(User::where('email', 'new@example.test')->exists())->toBeFalse();
});

it('never runs the uniqueness query for an address the earlier rules refused', function () {
    // `unique` asks the database with the value, and PostgreSQL refuses an invalid UTF-8 sequence (SQLSTATE
    // 22021). Laravel skips `unique` once an earlier rule failed; this pins that the address never gets there.
    DB::enableQueryLog();

    $this->post('/auth/register', [
        'name' => 'Ada', 'email' => "\xFF@x.com", 'password' => 'password-123', 'password_confirmation' => 'password-123',
    ], ['Accept' => 'application/json'])->assertStatus(422)->assertJsonValidationErrors('email');

    expect(collect(DB::getQueryLog())->filter(fn ($q) => str_contains($q['query'], 'users')))->toBeEmpty();
});
