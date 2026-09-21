<?php

declare(strict_types=1);

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Lukk;
use Lukk\Tests\Fixtures\User;

afterEach(function () {
    Lukk::$authenticateUsing = null;
});

/**
 * Install a hasher that tallies what the login path asks of it, and hand it back.
 *
 * The constant-time claim can only be tested through its MECHANISM: a wall-clock assertion would
 * flake in CI and prove nothing on a loaded runner, while what the code actually owes is one
 * password comparison per attempt whether the account exists or not. Wraps the real driver rather
 * than replacing it, so every hash the request makes or checks is still a genuine bcrypt one.
 */
function countingHasher(): object
{
    $spy = new class(app('hash')->driver()) implements Hasher
    {
        /** @var array<int, string> */
        public array $checked = [];

        public int $makes = 0;

        public function __construct(private readonly Hasher $inner) {}

        public function info($hashedValue): array
        {
            return $this->inner->info($hashedValue);
        }

        public function make(#[SensitiveParameter] $value, array $options = []): string
        {
            $this->makes++;

            return $this->inner->make($value, $options);
        }

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = []): bool
        {
            $this->checked[] = (string) $value;

            return $this->inner->check($value, $hashedValue, $options);
        }

        public function needsRehash($hashedValue, array $options = []): bool
        {
            return $this->inner->needsRehash($hashedValue, $options);
        }
    };

    Hash::extend('counting', fn () => $spy);
    config(['hashing.driver' => 'counting']);

    return $spy;
}

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

it('returns 422, not a 500, for a malformed credential type', function () {
    $this->postJson('/auth/login', ['email' => ['array'], 'password' => 'p'])
        ->assertStatus(422);
});

it('stamps amr=[pwd] on a password-only login token', function () {
    User::factory()->create(['email' => 'x@y.com']);

    $access = $this->postJson('/auth/login', ['email' => 'x@y.com', 'password' => 'password'])->json('access_token');

    expect(claims($access)->amr)->toBe(['pwd']);
});

it('returns an identical response for an unknown user and a wrong password', function () {
    User::factory()->create(['email' => 'real@y.com']);

    $wrongPassword = $this->postJson('/auth/login', ['email' => 'real@y.com', 'password' => 'wrong-pw']);
    $unknownUser = $this->postJson('/auth/login', ['email' => 'ghost@y.com', 'password' => 'wrong-pw']);

    expect($wrongPassword->status())->toBe($unknownUser->status())
        ->and($wrongPassword->json())->toEqual($unknownUser->json());
});

/** The SHAPE of one attempt's work: which primitive ran, and how many times. */
function kdfWork(object $hasher): array
{
    return ['makes' => $hasher->makes, 'checks' => count($hasher->checked)];
}

it('spends the same key-derivation work on every shape of failed attempt', function () {
    // Constant-time by construction: whether the identifier resolves, resolves to a password-less
    // account, or resolves to one with a wrong password, the attempt owes exactly ONE derivation.
    // A wall-clock assertion would flake on a loaded runner and prove nothing; the work is the
    // invariant, so the work is what is counted.
    //
    // The SHAPE, not the total. Both earlier assertions here were written around the implementation
    // and outlived the property — one pinned `Hash::check` specifically, the other allowed
    // `makes <= 1` because the dummy was memoized in a function `static`. And a first replacement,
    // which summed the two counters, inherited the same blind spot: restore the memo and every test
    // after the first in a shared process reads `makes: 0, checks: 1` for the unknown path, whose
    // SUM is the same 1 a real account costs. That is precisely the PHP-FPM bug — a fresh process
    // per request pays `make` + `check` there against a single `check` here, 472ms vs 236ms at
    // bcrypt cost 12 — so the sum can never see it and the counters must be read apart.
    User::factory()->create(['email' => 'real@y.com']);
    User::factory()->create(['email' => 'passwordless@y.com', 'password' => null]);
    User::factory()->create(['email' => 'emptypassword@y.com', 'password' => '']);

    $attempts = [
        'unknown identifier' => 'ghost@y.com',
        'wrong password' => 'real@y.com',
        'password is null' => 'passwordless@y.com',
        'password is empty' => 'emptypassword@y.com',
    ];

    // Installed ONCE: the user provider is handed its hasher when the guard is first built, so a
    // counter swapped in afterwards would see none of the work and every count would read zero.
    $hasher = countingHasher();

    $work = [];
    foreach ($attempts as $label => $email) {
        $hasher->checked = [];
        $hasher->makes = 0;
        app('auth')->forgetGuards();
        $this->postJson('/auth/login', ['email' => $email, 'password' => 'whatever'])->assertStatus(422);
        $work[$label] = kdfWork($hasher);
    }

    // One derivation each, and the no-usable-password shapes must all take the SAME branch as an
    // unknown identifier — `password is empty` is the one that catches narrowing the guard to a
    // bare `!== null`, which leaves `''` to reach the hasher and derive nothing.
    expect($work)->toBe([
        'unknown identifier' => ['makes' => 1, 'checks' => 0],
        'wrong password' => ['makes' => 0, 'checks' => 1],
        'password is null' => ['makes' => 1, 'checks' => 0],
        'password is empty' => ['makes' => 1, 'checks' => 0],
    ]);
});

it('still refuses a password-less account rather than admitting it', function () {
    // The equalizer must not become a way in: `null` and `''` both have to fail closed, including
    // when the submitted password is itself empty.
    foreach ([null, ''] as $stored) {
        $user = User::factory()->create(['password' => $stored]);

        app('auth')->forgetGuards();
        $this->postJson('/auth/login', ['email' => $user->email, 'password' => ''])->assertStatus(422);
        app('auth')->forgetGuards();
        $this->postJson('/auth/login', ['email' => $user->email, 'password' => (string) $stored])->assertStatus(422);
    }
});

it('names the wait in both seconds and minutes when the throttle trips', function () {
    // The framework's English line interpolates only `:seconds`, so nothing about the minute figure
    // is visible until a locale phrases the wait in minutes — which is the whole reason it is
    // passed. Supply such a line and pin what it renders. The window is deliberately not a round
    // number of minutes: 1889s is 31.48 minutes, so a figure that is rounded DOWN (or to nearest)
    // would tell a locked-out user "31 minutes" for a wait that has not elapsed by then.
    User::factory()->create(['email' => 'x@y.com']);
    config(['lukk.rate_limits.login.max_attempts' => 1, 'lukk.rate_limits.login.decay_seconds' => 1889]);
    app('translator')->addLines(['auth.throttle' => 'Retry in :seconds seconds (:minutes minutes).'], 'en');

    $this->freezeSecond(function () {
        $this->postJson('/auth/login', ['email' => 'x@y.com', 'password' => 'bad'])->assertStatus(422);

        app('auth')->forgetGuards();
        $this->postJson('/auth/login', ['email' => 'x@y.com', 'password' => 'bad'])
            ->assertStatus(429)
            ->assertJsonPath('errors.email.0', 'Retry in 1889 seconds (32 minutes).');
    });
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

it('lets the hook refuse a login the password column would have allowed', function () {
    // The hook is authoritative in BOTH directions. Falling back to the provider when it declines
    // would silently restore password login for an app that replaced it — one authenticating
    // against a directory would still admit a user it disabled there, through the local `password`
    // column lukk is no longer supposed to consult.
    User::factory()->create(['email' => 'hook@y.com']);

    Lukk::authenticateUsing(fn ($request) => null);

    $this->postJson('/auth/login', ['email' => 'hook@y.com', 'password' => 'password'])
        ->assertStatus(422)
        ->assertJsonMissing(['access_token']);
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

it('refuses a lukk.username naming a column the users table does not have', function () {
    // Not loud on its own: SQLite reads `"mial"` as a string literal, so the lookup compares two
    // literals — and submitting `mial` as the identifier then matches every row, handing back the
    // first account for whoever knows its password.
    config(['app.debug' => true, 'lukk.username' => 'mial']);
    User::factory()->create();
    $this->withoutExceptionHandling();

    expect(fn () => $this->postJson('/auth/login', ['mial' => 'mial', 'password' => 'password']))
        ->toThrow(RuntimeException::class, 'lukk.username is [mial], but the table [users] has no such column. On SQLite that makes the sign-in lookup compare two string literals rather than a column, so submitting [mial] as the identifier matches every row. Set `lukk.username` to the column your users authenticate with.');
});

it('says nothing about the identifier column outside debug', function () {
    // One array lookup in production, and no schema query.
    config(['app.debug' => false, 'lukk.username' => 'mial']);
    User::factory()->create();

    // An identifier that is not the column name matches no row, so this is the ordinary refusal —
    // the point is only that no schema query and no exception happen here.
    $this->postJson('/auth/login', ['mial' => 'nobody@example.test', 'password' => 'password'])->assertStatus(422);
});

it('leaves a provider whose table lukk cannot see alone', function () {
    // A provider lukk cannot introspect has no table to ask about, so the check is skipped rather
    // than guessed at — and nothing calls a model factory it does not have.
    config(['app.debug' => true, 'lukk.username' => 'mial']);
    Auth::provider('tableless', fn () => new class implements UserProvider
    {
        public function retrieveById($identifier) {}

        public function retrieveByToken($identifier, $token) {}

        public function updateRememberToken(Authenticatable $user, $token) {}

        public function retrieveByCredentials(array $credentials) {}

        public function validateCredentials(Authenticatable $user, array $credentials)
        {
            return false;
        }

        public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false) {}
    });
    config(['auth.providers.users' => ['driver' => 'tableless']]);

    $this->postJson('/auth/login', ['mial' => 'whoever', 'password' => 'password'])->assertStatus(422);
});

it('never matches an account whose identifier column is null when the field is omitted', function () {
    // The field is read as a string: an omitted one is '', which matches nothing. Left as null, the
    // lookup becomes `where username is null` — and an account with no identifier set would then be
    // signed in by anyone who knows its password and sends no username at all.
    Schema::table('users', fn (Blueprint $table) => $table->string('username')->nullable());
    config(['lukk.username' => 'username']);
    User::factory()->create(['username' => null]);

    $this->postJson('/auth/login', ['password' => 'password'])->assertStatus(422);
});

it('refuses a sign-in with no password as a wrong credential, not as an error', function () {
    // Read as a string, so an omitted password is '' — which no hash matches. Left as null it reaches
    // the hasher, where PHP's deprecation for a null subject is one upgrade away from a 500.
    User::factory()->create(['email' => 'ada@example.test']);

    $this->postJson('/auth/login', ['email' => 'ada@example.test'])
        ->assertStatus(422)
        ->assertJsonValidationErrors(['email' => 'These credentials do not match our records.']);
});

it('leaves an EloquentUserProvider subclass that resolves its own identifier alone', function () {
    // The hazard is the stock provider's `where($field, $value)`. A subclass that answers a VIRTUAL
    // identifier has no column to have, and refusing it would break a working customization on every
    // machine with APP_DEBUG on.
    config(['app.debug' => true, 'lukk.username' => 'login']);
    User::factory()->create(['email' => 'ada@example.test']);
    Auth::provider('virtual-identifier', fn ($app, array $config) => new class($app['hash'], User::class) extends EloquentUserProvider
    {
        public function retrieveByCredentials(array $credentials)
        {
            return User::query()->where('email', 'like', ($credentials['login'] ?? '').'@%')->first();
        }
    });
    config(['auth.providers.users' => ['driver' => 'virtual-identifier']]);

    $this->postJson('/auth/login', ['login' => 'ada', 'password' => 'password'])->assertOk();
});

it('says nothing about the column on an application that has not migrated yet', function () {
    // Every column is missing from a table that does not exist, and the driver says that better than
    // a confident "no such column" on the first route a developer hits.
    config(['app.debug' => true]);
    Schema::drop('users');
    $this->withoutExceptionHandling();

    expect(fn () => $this->postJson('/auth/login', ['email' => 'ada@example.test', 'password' => 'password']))
        ->toThrow(QueryException::class);
});

it('answers a password containing a NUL byte identically whatever the account is', function () {
    // The equalizer must not be able to THROW on attacker-controlled input. `password_hash` raises
    // `ValueError: Bcrypt password must not contain null character` while `password_verify` merely
    // returns false — so equalizing the two branches with `Hash::make` turned a NUL byte into a
    // deterministic, single-request account oracle: 500 where no usable password exists, 422 where
    // one does. That is strictly stronger than the 2x timing channel it replaced, and it re-exposed
    // the passwordless shape the same change was written to protect. It also escaped the failure
    // limiter, which counts `ValidationException` and not `ValueError`.
    User::factory()->create(['email' => 'real@y.com']);
    User::factory()->create(['email' => 'passwordless@y.com', 'password' => null]);

    $statuses = [];
    foreach (['real@y.com', 'ghost@y.com', 'passwordless@y.com'] as $email) {
        app('auth')->forgetGuards();
        $statuses[$email] = $this->postJson('/auth/login', ['email' => $email, 'password' => "a\0b"])->status();
    }

    expect(array_values(array_unique($statuses)))->toBe([422])
        ->and($statuses)->not->toContain(500);
});

it('still answers 422 when the hasher itself refuses to hash', function () {
    // The try/catch half, pinned on its own — and on the case the rule cannot reach. A rebound
    // hasher may refuse input for reasons lukk knows nothing about (`hashing.bcrypt.limit`, a
    // custom driver, an argon2 build without the algorithm). If the equalizer can throw there, the
    // no-usable-password branches answer 500 while a real account answers 422: the same
    // single-request account oracle, reached without a NUL byte.
    Hash::extend('refuses', fn () => new class implements Hasher
    {
        public function info($hashedValue): array
        {
            return [];
        }

        public function make(#[SensitiveParameter] $value, array $options = []): string
        {
            throw new RuntimeException('this hasher will not hash that');
        }

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = []): bool
        {
            return false;
        }

        public function needsRehash($hashedValue, array $options = []): bool
        {
            return false;
        }
    });
    config(['hashing.driver' => 'refuses']);

    User::factory()->create(['email' => 'real@y.com']);

    $this->postJson('/auth/login', ['email' => 'ghost@y.com', 'password' => 'whatever'])->assertStatus(422);
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'real@y.com', 'password' => 'whatever'])->assertStatus(422);
});

it('answers 422, not 500, for an account whose stored hash the driver cannot read', function () {
    // The mirror of the above on the REAL branch: a row imported from another system, or the
    // widespread `!`/`*`/`x` "unusable password" placeholder, is a non-empty string — so
    // `hasUsablePassword()` passes it to `Hash::check`, which throws "This password does not use
    // the Bcrypt algorithm". One crafted request per address, 500 versus 422, and it escapes the
    // failure limiter, which counts ValidationException.
    User::factory()->create(['email' => 'imported@y.com', 'password' => '!']);

    $this->postJson('/auth/login', ['email' => 'imported@y.com', 'password' => 'whatever'])->assertStatus(422);
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'ghost@y.com', 'password' => 'whatever'])->assertStatus(422);
});
