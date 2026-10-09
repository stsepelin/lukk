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
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
use Lukk\Actions\AttemptLogin;
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
            // Count only a check that DERIVES something. `AbstractHasher::check` returns false at once
            // for a null or empty stored value, so counting that call would report work that never
            // happened — and hide exactly the zero-work answer these tests exist to catch.
            if ((string) $hashedValue !== '') {
                $this->checked[] = (string) $value;
            }

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

    // One derivation each, and the no-usable-password shapes must cost what an unknown identifier
    // costs — one `make` at the configured cost. `password is empty` is the row that catches a guard
    // treating only null as unusable, which leaves `''` to reach the hasher and derive nothing.
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

it('spends the same wall-clock budget on every shape of failed attempt, not just the same number of hashes', function () {
    // Counting derivations was the WRONG property, and the test that counted them said so out loud:
    // it asserted the unknown path runs `makes:1, checks:0` and a real account `makes:0, checks:1`,
    // i.e. that the two run DIFFERENT primitives at different costs, and called that equal work.
    // A stopwatch reads cost, not count. Measured at bcrypt cost 11: an unknown identifier hashes at
    // the CONFIGURED cost (118 ms) while `Hash::check` runs at the cost embedded in the STORED hash
    // — 15 ms for a row left at cost 8 by a `BCRYPT_ROUNDS` bump (Laravel 11 raised the default from
    // 10 to 12, and lukk never calls `rehashPasswordIfRequired`, so those rows stay), and ~0 ms for
    // the `!`/`*` placeholder an import leaves behind. 8x and effectively infinite, one request each.
    //
    // A `Timebox` fixes it regardless of which primitive ran or what the row cost — the framework's
    // own answer, and the one the password broker uses. Pinned through the mechanism rather than the
    // clock: a wall-clock assertion flakes on a loaded runner, and at the suite's bcrypt cost of 4
    // the differences are too small to measure anyway.
    //
    // The suite runs with no box at all (`TestCase`), so this test sets a budget of its own.
    config(['lukk.login_timebox_micros' => 250_000]);
    $budgets = [];
    app()->instance(Timebox::class, new class($budgets) extends Timebox
    {
        public function __construct(public array &$seen) {}

        public function call(callable $callback, int $microseconds)
        {
            $this->seen[] = $microseconds;

            return $callback($this);
        }
    });

    User::factory()->create(['email' => 'real@y.com']);
    User::factory()->create(['email' => 'nopassword@y.com', 'password' => null]);
    User::factory()->create(['email' => 'imported@y.com', 'password' => '!']);

    foreach (['ghost@y.com', 'real@y.com', 'nopassword@y.com', 'imported@y.com'] as $email) {
        app('auth')->forgetGuards();
        $this->postJson('/auth/login', ['email' => $email, 'password' => 'whatever'])->assertStatus(422);
    }

    // One budget per attempt, all identical — the point is that no shape escapes the box.
    expect($budgets)->toHaveCount(4)
        ->and(array_unique($budgets))->toHaveCount(1)
        ->and($budgets[0])->toBeGreaterThan(0);
});

it('keeps a real sign-in budget when the config key is missing entirely', function () {
    // A degraded config must not switch the equalizer OFF. `config:cache` run before this key
    // existed leaves it unset forever, and a Timebox of 0 is no Timebox — the timing oracle back
    // exactly where it was, silently, on the install least likely to notice.
    config(['lukk.login_timebox_micros' => null]);

    $budgets = [];
    app()->instance(Timebox::class, new class($budgets) extends Timebox
    {
        public function __construct(public array &$seen) {}

        public function call(callable $callback, int $microseconds)
        {
            $this->seen[] = $microseconds;

            return $callback($this);
        }
    });

    $this->postJson('/auth/login', ['email' => 'ghost@y.com', 'password' => 'whatever'])->assertStatus(422);

    // 500 ms, not the 250 ms this started at: 250 ms was measured BELOW a single bcrypt derivation
    // at cost 12 (243–358 ms), and a box shorter than the work pads nothing.
    expect($budgets)->toBe([500_000]);
});

/** Configure a bcrypt cost ABOVE the one a row was stored at, and rebuild the hasher with it. */
function raiseBcryptCostTo(int $rounds): void
{
    config(['hashing.bcrypt.rounds' => $rounds]);
    app('hash')->forgetDrivers();
}

it('also derives at the configured cost when the stored hash is weaker than it', function () {
    // `Hash::check` runs at the cost embedded in the STORED hash, `Hash::make` at the configured one.
    // A row left at cost 10 by a `BCRYPT_ROUNDS` bump (Laravel 11 raised the default from 10 to 12)
    // was therefore checked several times faster than an unknown identifier was equalized — measured
    // 15 ms against 118 ms at cost 11 — and a Timebox shorter than the hash pads nothing. So a failed
    // check against a hash the hasher wants to rehash also pays one derivation at the configured cost.
    User::factory()->create(['email' => 'legacy@y.com', 'password' => password_hash('password', PASSWORD_BCRYPT, ['cost' => 4])]);
    raiseBcryptCostTo(5);
    $hasher = countingHasher();

    $this->postJson('/auth/login', ['email' => 'legacy@y.com', 'password' => 'wrong'])->assertStatus(422);

    expect(kdfWork($hasher))->toBe(['makes' => 1, 'checks' => 1]);
});

it('also derives at the configured cost for a stored value the hasher cannot read', function () {
    // The `!`/`*` "unusable password" placeholder, or a row imported from another system: the check
    // returns or throws before deriving anything, so on its own it answered in ~0 ms.
    User::factory()->create(['email' => 'imported@y.com', 'password' => '!']);
    $hasher = countingHasher();

    $this->postJson('/auth/login', ['email' => 'imported@y.com', 'password' => 'wrong'])->assertStatus(422);

    expect($hasher->makes)->toBe(1);
});

it('rehashes a weaker stored password once the user signs in with it', function () {
    // Laravel's own `SessionGuard` does this on every successful login (`hashing.rehash_on_login`,
    // default true); lukk never did, so rows hashed before a cost increase stayed weaker — and
    // distinguishable by timing — for as long as their owners kept signing in.
    $user = User::factory()->create(['password' => password_hash('password', PASSWORD_BCRYPT, ['cost' => 4])]);
    raiseBcryptCostTo(5);

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertOk();

    expect(password_get_info($user->refresh()->password)['options']['cost'])->toBe(5);
});

it('leaves the password alone when the application turned rehash-on-login off', function () {
    config(['hashing.rehash_on_login' => false]);
    $user = User::factory()->create(['password' => password_hash('password', PASSWORD_BCRYPT, ['cost' => 4])]);
    raiseBcryptCostTo(5);

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertOk();

    expect(password_get_info($user->refresh()->password)['options']['cost'])->toBe(4);
});

it('does not hold a successful sign-in for the rest of the box', function () {
    // The box exists to hide WHICH failure happened. A success announces itself in its status code,
    // so padding it only taxes every legitimate login.
    config(['lukk.login_timebox_micros' => 250_000]);
    $returnedEarly = [];
    app()->instance(Timebox::class, new class($returnedEarly) extends Timebox
    {
        public function __construct(public array &$early) {}

        public function call(callable $callback, int $microseconds)
        {
            try {
                return $callback($this);
            } finally {
                $this->early[] = $this->earlyReturn;
            }
        }
    });

    $user = User::factory()->create();

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'wrong'])->assertStatus(422);
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertOk();

    expect($returnedEarly)->toBe([false, true]);
});

it('reads a sign-in budget that arrives as a string', function () {
    // A published config can carry `env('LUKK_LOGIN_TIMEBOX_MICROS')` without the `(int)` cast, and
    // `Timebox::call()` takes an int — under strict types a string budget is a TypeError on every
    // failed sign-in.
    config(['lukk.login_timebox_micros' => '1']);

    $this->postJson('/auth/login', ['email' => 'ghost@y.com', 'password' => 'whatever'])->assertStatus(422);
});

it('rehashes on sign-in when the application never set rehash_on_login', function () {
    // Laravel's own default for a missing key is TRUE (`SessionGuard`), and lukk must agree: an app
    // whose `config/hashing.php` predates the key still expects weaker hashes to be upgraded.
    $user = User::factory()->create(['password' => password_hash('password', PASSWORD_BCRYPT, ['cost' => 4])]);
    raiseBcryptCostTo(5);
    $hashing = config('hashing');
    unset($hashing['rehash_on_login']);
    config(['hashing' => $hashing]);

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertOk();

    expect(password_get_info($user->refresh()->password)['options']['cost'])->toBe(5);
});

it('uses the configured sign-in budget, not the fallback', function () {
    // A mutation run surfaced this one only as a TIMEOUT: ignoring the configured value and always
    // boxing at the 500 ms fallback made every failed test login sleep, so the run timed out and Pest
    // scored it "caught". Re-measured serially, nothing failed. The value must actually be read.
    config(['lukk.login_timebox_micros' => 123_456]);
    $budgets = [];
    app()->instance(Timebox::class, new class($budgets) extends Timebox
    {
        public function __construct(public array &$seen) {}

        public function call(callable $callback, int $microseconds)
        {
            $this->seen[] = $microseconds;

            return $callback($this);
        }
    });

    $this->postJson('/auth/login', ['email' => 'ghost@y.com', 'password' => 'whatever'])->assertStatus(422);

    expect($budgets)->toBe([123_456]);
});

it('does not let a look-alike account clear another account\'s failure count', function () {
    // With the persistent lockout off — the default — the IP-independent account bucket is the only
    // cap on consecutive failures (NIST SP 800-63B-4 §3.2.2). Keyed only on the NORMALIZED identifier,
    // which folds `аdmin@y.com` (Cyrillic а) onto `admin@y.com`, a success by the look-alike's owner
    // cleared it, so they could reset the victim's count between bursts. Failures now also count
    // against the account itself, which only the account's own success clears.
    config(['lukk.rate_limits.login.max_attempts' => 100, 'lukk.rate_limits.login.account_max_attempts' => 3]);
    User::factory()->create(['email' => 'admin@y.com', 'password' => bcrypt('correct')]);
    User::factory()->create(['email' => "\u{0430}dmin@y.com", 'password' => bcrypt('correct')]);

    foreach (range(1, 2) as $i) {
        $this->postJson('/auth/login', ['email' => 'admin@y.com', 'password' => 'wrong'])->assertStatus(422);
    }

    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => "\u{0430}dmin@y.com", 'password' => 'correct'])->assertOk();

    // Third failure reaches the account's cap; the look-alike's success did not reset it.
    $this->postJson('/auth/login', ['email' => 'admin@y.com', 'password' => 'wrong'])->assertStatus(422);
    $this->postJson('/auth/login', ['email' => 'admin@y.com', 'password' => 'wrong'])->assertStatus(429);
});

it('throttles a spelling variant the same whether or not the account exists', function () {
    // Keyed on the account alone, a variant spelling of an EXISTING account landed in a fresh bucket
    // while a variant of a non-account shared the full one — 422 versus 429, an existence oracle on
    // the default throttle. The folded bucket still gates every attempt.
    config(['lukk.rate_limits.login.max_attempts' => 3, 'lukk.rate_limits.login.account_max_attempts' => 100]);
    User::factory()->create(['email' => 'real@y.com', 'password' => bcrypt('correct')]);

    $answers = [];
    foreach (['real@y.com', 'ghost@y.com'] as $identifier) {
        foreach (range(1, 3) as $i) {
            $this->postJson('/auth/login', ['email' => $identifier, 'password' => 'wrong'])->assertStatus(422);
        }
        $answers[$identifier] = $this->postJson('/auth/login', ['email' => strtoupper($identifier), 'password' => 'wrong'])->status();
    }

    expect($answers)->toBe(['real@y.com' => 429, 'ghost@y.com' => 429]);
});

it('does not undo a password change that lands while a sign-in is rehashing the old one', function () {
    // The row is read once at the start of a sign-in. If the stored hash needs upgrading and a reset
    // commits between that read and the rehash, saving the stale model wrote `Hash::make(<old>)` over
    // the new hash: the reset was reverted, and the session — fingerprinted from the rehashed model —
    // survived the password-unchanged check. The upgrade must only replace the hash it checked.
    $user = User::factory()->create(['email' => 'race@y.com', 'password' => password_hash('oldpw', PASSWORD_BCRYPT, ['cost' => 4])]);
    raiseBcryptCostTo(5);
    resetLandsDuringCheck($user, 'newpw');

    $this->postJson('/auth/login', ['email' => 'race@y.com', 'password' => 'oldpw'])->assertStatus(422);

    $stored = (string) DB::table('users')->where('id', $user->id)->value('password');
    expect(password_verify('newpw', $stored))->toBeTrue()
        ->and(password_verify('oldpw', $stored))->toBeFalse();
});

it('keeps a sign-in whose rehash lost the race to another rehash of the same password', function () {
    // Two first sign-ins after a cost bump each upgrade the hash. The loser must not revoke its own
    // session as if the password had changed: the row still holds the password it just proved.
    $user = User::factory()->create(['email' => 'twin@y.com', 'password' => password_hash('samepw', PASSWORD_BCRYPT, ['cost' => 4])]);
    raiseBcryptCostTo(5);
    resetLandsDuringCheck($user, 'samepw');

    $this->postJson('/auth/login', ['email' => 'twin@y.com', 'password' => 'samepw'])->assertOk();
});

/** A hasher whose first successful check writes `$newPassword` to the row — a concurrent change. */
function resetLandsDuringCheck(User $user, string $newPassword): void
{
    $inner = app('hash')->driver();
    $fired = false;
    app('hash')->extend('racing', fn () => new class($inner, $user->id, $newPassword, $fired) implements Hasher
    {
        public function __construct(private readonly Hasher $inner, private readonly int $id, private readonly string $next, private bool &$fired) {}

        public function info($hashedValue): array
        {
            return $this->inner->info($hashedValue);
        }

        public function make(#[SensitiveParameter] $value, array $options = []): string
        {
            return $this->inner->make($value, $options);
        }

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = []): bool
        {
            $ok = $this->inner->check($value, $hashedValue, $options);
            if ($ok && ! $this->fired) {
                $this->fired = true;
                DB::table('users')->where('id', $this->id)->update(['password' => $this->inner->make($this->next)]);
            }

            return $ok;
        }

        public function needsRehash($hashedValue, array $options = []): bool
        {
            return $this->inner->needsRehash($hashedValue, $options);
        }
    });
    config(['hashing.driver' => 'racing']);
    app('hash')->forgetDrivers();
}

it('still counts an identifier that names no account in one bucket per spelling fold', function () {
    // Without an account to key on, the bucket stays on the normalized identifier, so spreading
    // guesses across case or look-alike spellings of a non-account still lands in one bucket — and
    // a non-account throttles exactly like a real one, so 429 is not an existence oracle.
    config(['lukk.rate_limits.login.max_attempts' => 100, 'lukk.rate_limits.login.account_max_attempts' => 3]);

    foreach (['ghost@y.com', 'GHOST@y.com', 'ghost@y.com '] as $spelling) {
        $this->postJson('/auth/login', ['email' => $spelling, 'password' => 'wrong'])->assertStatus(422);
    }
    $this->postJson('/auth/login', ['email' => 'Ghost@Y.com', 'password' => 'wrong'])->assertStatus(429);
});

it('does not look the identifier up as a column for a custom authenticator with the lockout off', function () {
    // Keying the buckets on the account means one provider lookup by `lukk.username`. A
    // `Lukk::authenticateUsing` app may name a field that is no column at all; the lockout documents
    // that it must match, but an app with the lockout off was never told, and its every sign-in
    // would become a query error.
    config(['lukk.username' => 'login']);
    User::factory()->create(['email' => 'custom@y.com', 'password' => bcrypt('correct')]);
    Lukk::authenticateUsing(function ($request) {
        $user = User::query()->where('email', $request->input('login'))->first();

        return $user !== null && Hash::check((string) $request->input('password'), $user->password) ? $user : null;
    });

    // SQLite reads an unknown double-quoted column as a string LITERAL, so it would not error here;
    // PostgreSQL and MySQL would. Assert the query is never issued.
    $sql = [];
    DB::listen(function ($query) use (&$sql) {
        $sql[] = $query->sql;
    });

    $this->postJson('/auth/login', ['login' => 'custom@y.com', 'password' => 'correct'])->assertOk();

    expect(array_filter($sql, fn (string $q) => str_contains($q, '"login"')))->toBe([]);
});

it('honours a custom authenticator\'s refusal even when the password would pass', function () {
    // With the lockout on, the account row has already been looked up for the counter. A callback
    // that says no — a disabled account, an extra rule — must end the attempt there, not fall
    // through to a stock password check against that row.
    config(['lukk.features.lockout' => true]);
    User::factory()->create(['email' => 'disabled@y.com', 'password' => bcrypt('correct')]);
    Lukk::authenticateUsing(fn () => null);

    $this->postJson('/auth/login', ['email' => 'disabled@y.com', 'password' => 'correct'])->assertStatus(422);
});

it('leaves a current-cost hash exactly as it is', function () {
    // Only a hash the hasher wants upgraded is rewritten; an unconditional write would change the
    // stored value on every sign-in, and with it every session's password fingerprint.
    $user = User::factory()->create(['email' => 'current@y.com']);
    $before = (string) DB::table('users')->where('id', $user->id)->value('password');

    $this->postJson('/auth/login', ['email' => 'current@y.com', 'password' => 'password'])->assertOk();

    expect((string) DB::table('users')->where('id', $user->id)->value('password'))->toBe($before);
});

it('checks the password once when the upgrade wins its write', function () {
    // The re-read and second check are for a LOST race only.
    User::factory()->create(['email' => 'once@y.com', 'password' => password_hash('password', PASSWORD_BCRYPT, ['cost' => 4])]);
    raiseBcryptCostTo(5);
    $spy = countingHasher();

    $this->postJson('/auth/login', ['email' => 'once@y.com', 'password' => 'password'])->assertOk();

    expect($spy->checked)->toHaveCount(1);
});

it('attempts no upgrade, and reports nothing, for a user that is not an Eloquent model', function () {
    // The database provider returns a `GenericUser`, which offers no conditional write. lukk skips the
    // upgrade rather than risk reverting a concurrent password change.
    Exceptions::fake();
    config(['auth.providers.users' => ['driver' => 'database', 'table' => 'users']]);
    app('auth')->forgetGuards();
    $user = User::factory()->create(['email' => 'generic@y.com', 'password' => password_hash('password', PASSWORD_BCRYPT, ['cost' => 4])]);
    $before = (string) DB::table('users')->where('id', $user->id)->value('password');
    raiseBcryptCostTo(5);

    $this->postJson('/auth/login', ['email' => 'generic@y.com', 'password' => 'password'])->assertOk();

    Exceptions::assertNothingReported();
    expect((string) DB::table('users')->where('id', $user->id)->value('password'))->toBe($before);
});

it('gives a real account and a non-account the same throttle timing, whatever spellings are mixed', function () {
    // Any bucket only a real account has is visible through its timer, even when the gate itself answers
    // alike: a spelling the database does not resolve (another case on a binary collation, a Cyrillic а)
    // counts only in the fold, so the account's own bucket drifts from it, and both the Retry-After and,
    // after one bucket expires, the status itself told the two apart.
    $this->freezeSecond();
    config(['lukk.rate_limits.login.max_attempts' => 3, 'lukk.rate_limits.login.account_max_attempts' => 100]);
    User::factory()->create(['email' => 'real@y.com', 'password' => bcrypt('correct')]);

    $probe = function (string $email) {
        $this->postJson('/auth/login', ['email' => strtoupper($email), 'password' => 'wrong']);
        $this->travel(40)->seconds();
        $this->postJson('/auth/login', ['email' => $email, 'password' => 'wrong']);
        $this->postJson('/auth/login', ['email' => $email, 'password' => 'wrong']);
        $throttled = $this->postJson('/auth/login', ['email' => $email, 'password' => 'wrong']);
        $this->travel(25)->seconds();
        $this->postJson('/auth/login', ['email' => $email, 'password' => 'wrong']);
        $after = $this->postJson('/auth/login', ['email' => $email, 'password' => 'wrong']);

        return [$throttled->status(), $throttled->json('message'), $after->status()];
    };

    expect($probe('real@y.com'))->toBe($probe('ghost@y.com'));
});

it('lets a success reset the caller\'s own per-address count, but not the account-wide one', function () {
    // The IP-independent bucket only decays. A success clearing it is what let a look-alike account's
    // owner — sharing the fold — reset the victim's count; letting it decay costs a real user nothing
    // short of `account_max_attempts` failures inside one window.
    config(['lukk.rate_limits.login.max_attempts' => 3, 'lukk.rate_limits.login.account_max_attempts' => 4]);
    User::factory()->create(['email' => 'own@y.com', 'password' => bcrypt('correct')]);

    $this->postJson('/auth/login', ['email' => 'own@y.com', 'password' => 'wrong'])->assertStatus(422);
    $this->postJson('/auth/login', ['email' => 'own@y.com', 'password' => 'wrong'])->assertStatus(422);
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'own@y.com', 'password' => 'correct'])->assertOk();

    // Two more failures fit: the per-address bucket (3) was reset by the success. The account-wide one
    // (4) was not, so the attempt after them is refused.
    $this->postJson('/auth/login', ['email' => 'own@y.com', 'password' => 'wrong'])->assertStatus(422);
    $this->postJson('/auth/login', ['email' => 'own@y.com', 'password' => 'wrong'])->assertStatus(422);
    $this->postJson('/auth/login', ['email' => 'own@y.com', 'password' => 'wrong'])->assertStatus(429);
});

it('keeps the session when a password mutator hashes what it is given', function () {
    // The upgraded hash is put on the model as stored. Through `setAttribute()` a legacy
    // `setPasswordAttribute()` hashed the hash in memory, so the session's fingerprint matched nothing
    // stored and the first sign-in after a cost bump answered 422.
    $user = MutatingPasswordUser::query()->create(['name' => 'm', 'email' => 'mut@y.com', 'password' => 'plain-ignored']);
    DB::table('users')->where('id', $user->id)->update(['password' => password_hash('password', PASSWORD_BCRYPT, ['cost' => 4])]);
    config(['auth.providers.users.model' => MutatingPasswordUser::class]);
    app('auth')->forgetGuards();
    raiseBcryptCostTo(5);

    $this->postJson('/auth/login', ['email' => 'mut@y.com', 'password' => 'password'])->assertOk();
});

class MutatingPasswordUser extends User
{
    protected $table = 'users';

    public function setPasswordAttribute(string $value): void
    {
        $this->attributes['password'] = Hash::make($value);
    }
}

it('hands back a user whose upgraded password is not left dirty', function () {
    // The hash is already stored. Left dirty, any later `save()` of this instance in the same request —
    // a consumer's hook stamping `last_login_at` — writes it AGAIN, over a reset that landed meanwhile,
    // and fires every observer keyed on `isDirty('password')` as if the password had changed.
    User::factory()->create(['email' => 'clean@y.com', 'password' => password_hash('password', PASSWORD_BCRYPT, ['cost' => 4])]);
    raiseBcryptCostTo(5);

    $user = app(AttemptLogin::class)(Request::create('/auth/login', 'POST', ['email' => 'clean@y.com', 'password' => 'password']));

    expect(password_get_info($user->getAuthPassword())['options']['cost'])->toBe(5)
        ->and($user->isDirty('password'))->toBeFalse();
});

/** A hasher wrapping the real one, with chosen methods throwing — for the paths that must not 500. */
function throwingHasher(array $throws): void
{
    $inner = app('hash')->driver();
    app('hash')->extend('throwing', fn () => new class($inner, $throws) implements Hasher
    {
        public function __construct(private readonly Hasher $inner, private readonly array $throws) {}

        public function info($hashedValue): array
        {
            return $this->inner->info($hashedValue);
        }

        public function make(#[SensitiveParameter] $value, array $options = []): string
        {
            in_array('make', $this->throws, true) && throw new RuntimeException('make failed');

            return $this->inner->make($value, $options);
        }

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = []): bool
        {
            return $this->inner->check($value, $hashedValue, $options);
        }

        public function needsRehash($hashedValue, array $options = []): bool
        {
            in_array('needsRehash', $this->throws, true) && throw new RuntimeException('needsRehash failed');

            return $this->inner->needsRehash($hashedValue, $options);
        }
    });
    config(['hashing.driver' => 'throwing']);
    app('hash')->forgetDrivers();
}

it('answers a wrong password on a weak hash with 422 even when the equalizing derivation throws', function () {
    User::factory()->create(['email' => 'weakthrow@y.com', 'password' => password_hash('password', PASSWORD_BCRYPT, ['cost' => 4])]);
    raiseBcryptCostTo(5);
    throwingHasher(['make']);

    $this->postJson('/auth/login', ['email' => 'weakthrow@y.com', 'password' => 'wrong'])->assertStatus(422);
});

it('treats a stored hash the hasher cannot judge as weak, and still answers 422', function () {
    User::factory()->create(['email' => 'unjudged@y.com']);
    throwingHasher(['needsRehash']);

    $this->postJson('/auth/login', ['email' => 'unjudged@y.com', 'password' => 'wrong'])->assertStatus(422);
});

it('signs in when the hash upgrade fails, and reports the failure', function () {
    Exceptions::fake();
    User::factory()->create(['email' => 'upgradefail@y.com', 'password' => password_hash('password', PASSWORD_BCRYPT, ['cost' => 4])]);
    raiseBcryptCostTo(5);
    throwingHasher(['make']);

    $this->postJson('/auth/login', ['email' => 'upgradefail@y.com', 'password' => 'password'])->assertOk();

    Exceptions::assertReported(RuntimeException::class);
});
