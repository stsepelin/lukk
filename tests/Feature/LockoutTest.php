<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Contracts\LockoutRepository;
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
    expect(Lockout::query()->where('subject', 'id:'.User::first()->getKey())->value('attempts'))->toBe(2);
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
    Event::assertDispatched(AccountLocked::class, fn ($e) => $e->purpose === 'login' && $e->subject === 'id:'.User::first()->getKey());
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

it('never locks on an empty subject, which would lock the whole application', function () {
    // `Lukk::authenticateUsing` can authenticate on a field lukk never sees, and then EVERY login
    // keys on ''. Unlike a decaying limiter that bucket never heals, so 100 failures anywhere would
    // lock every account permanently. Refusing to count an empty subject is what stops that.
    for ($i = 0; $i < 5; $i++) {
        app('auth')->forgetGuards();
        $this->postJson('/auth/login', ['password' => 'no-identifier-at-all'])->assertStatus(422);
    }

    expect(Lockout::query()->count())->toBe(0);
});

it('does not break login when the feature is on but the table was never published', function () {
    // The flag is one config line; the migration is a separate publish group. Without a guard this
    // 500s EVERY login, including with the correct password — a total auth outage from a typo.
    Schema::drop('lukk_lockouts');
    $user = User::factory()->create(['email' => 'ok@y.com', 'password' => bcrypt('correct')]);

    failLogin('ok@y.com')->assertStatus(422);
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'ok@y.com', 'password' => 'correct'])->assertOk();
});

it('refuses a max_attempts of 0, which would lock every account on its owner\'s first typo', function () {
    // A non-numeric env value casts to 0 and `attempts >= 0` locks immediately. Same footgun class
    // as a missing rate-limit key resolving to Limit(0).
    config(['lukk.lockout.max_attempts' => 'one hundred']);
    $user = User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);

    failLogin()->assertStatus(422);
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'correct'])->assertOk();
});

it('lets a password reset release the lock — the only self-service way out', function () {
    $user = User::factory()->create(['email' => 'victim@y.com']);

    for ($i = 0; $i < 3; $i++) {
        failLogin();
    }
    failLogin()->assertStatus(423);

    $token = Password::createToken($user);
    app('auth')->forgetGuards();
    $this->postJson('/auth/reset-password', [
        'token' => $token, 'email' => 'victim@y.com',
        'password' => 'new-password-123', 'password_confirmation' => 'new-password-123',
    ])->assertOk();

    // Proving control of the address is stronger evidence than the password — being still locked
    // after it would leave a support ticket as the user's only option.
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'new-password-123'])->assertOk();
});

it('reports honestly when lukk:release finds nothing, and matches a differently-cased subject', function () {
    User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);
    for ($i = 0; $i < 3; $i++) {
        failLogin();
    }

    // Nothing to release must not report success — during an incident the operator would move on.
    $this->artisan('lukk:release', ['subject' => 'never-locked@y.com'])->assertFailed();

    // The realistic flow: paste the address as the user wrote it.
    $this->artisan('lukk:release', ['subject' => '  Victim@Y.com '])->assertSuccessful();
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'correct'])->assertOk();
});

it('prunes spent counters but never a lock that is still held', function () {
    User::factory()->create(['email' => 'victim@y.com']);
    failLogin('probe-a@y.com');
    failLogin('probe-b@y.com');
    for ($i = 0; $i < 3; $i++) {
        failLogin();
    }

    expect(Lockout::query()->count())->toBe(3);

    $this->travel(31)->days();
    $this->artisan('lukk:prune')->assertSuccessful();

    // The two stale probe counters go; the held lock stays, or pruning would be a release path.
    expect(Lockout::query()->pluck('subject')->all())->toBe(['id:'.User::first()->getKey()]);
});

it('rejects an unknown --purpose rather than releasing something else', function () {
    $this->artisan('lukk:release', ['subject' => 'x@y.com', '--purpose' => 'nonsense'])->assertFailed();
});

it('restarts the run after an auto-release rather than leaving it one attempt from locking', function () {
    config(['lukk.lockout.release_after' => 60]);
    User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);

    for ($i = 0; $i < 3; $i++) {
        failLogin();
    }
    failLogin()->assertStatus(423);

    $this->travel(61)->seconds();

    // A fresh run: the next failure is attempt 1, not attempt 4 re-locking immediately.
    failLogin()->assertStatus(422);
    expect(Lockout::query()->where('subject', 'id:'.User::first()->getKey())->value('attempts'))->toBe(1);
});

it('prunes nothing, without erroring, when the table was never published', function () {
    Schema::drop('lukk_lockouts');

    $this->artisan('lukk:prune')->assertSuccessful();
});

it('recovers when it loses the insert race for a brand-new subject', function () {
    // The real race: two first-failures both miss the row and both INSERT, and the loser hits the
    // unique index. Left uncaught that is a QueryException — a 500 on /auth/login — AND the loser's
    // guess goes uncounted, so deliberate concurrency would be strictly better for an attacker.
    //
    // The winner's row has to be committed BEFORE the loser's INSERT opens its savepoint, or the
    // rollback to that savepoint would take the winner's row with it. So it is inserted from a
    // `DB::listen` hook on the lookup SELECT that just missed — the exact instant the real winner
    // would have committed — rather than from the loser's own `creating` event.
    $armed = true;
    DB::listen(function ($query) use (&$armed) {
        // Match the LOOKUP specifically. A looser `lukk_lockouts` match also catches the
        // `hasTable` probe that runs first, which would insert the row before the lookup — the
        // lookup would then find it, no INSERT would collide, and this test would pass while
        // exercising nothing.
        if (! $armed || ! str_contains($query->sql, 'from "lukk_lockouts" where "purpose"')) {
            return;
        }
        $armed = false;
        DB::table('lukk_lockouts')->insert([
            'id' => (string) Str::ulid(), 'purpose' => 'login', 'subject' => 'idn:raced@y.com',
            'guard' => 'api', 'attempts' => 4, 'created_at' => now(), 'updated_at' => now(),
        ]);
    });

    // The loser re-reads the winner's row and increments it, rather than throwing.
    expect(app(LockoutRepository::class)->recordFailure('login', 'idn:raced@y.com', 'api'))->toBe(5);
});

// ---------------------------------------------------------------------------
// Step-up confirmation. Same secret as login, so it counts toward the same
// §5.2.2 cap — keyed on the user id, since the caller is already authenticated.
// ---------------------------------------------------------------------------

/** One failed step-up confirmation. */
function failStepUp(string $access)
{
    app('auth')->forgetGuards();

    return test()->withToken($access)->postJson('/auth/confirm-password', ['password' => 'wrong-pw']);
}

it('locks step-up confirmation after a run of consecutive failures', function () {
    config(['lukk.rate_limits.confirm.max_attempts' => 500]);
    $user = User::factory()->create(['password' => bcrypt('correct')]);
    $access = $user->startSession()->accessToken;

    failStepUp($access)->assertStatus(422);
    failStepUp($access)->assertStatus(422);
    failStepUp($access)->assertStatus(422); // hits the cap of three

    failStepUp($access)->assertStatus(423);

    // The lock holds against the right password too — otherwise it isn't a lock.
    app('auth')->forgetGuards();
    $this->withToken($access)->postJson('/auth/confirm-password', ['password' => 'correct'])
        ->assertStatus(423);

    expect(Lockout::where('purpose', 'confirm')->where('subject', (string) $user->getKey())->exists())->toBeTrue();
});

it('keeps the confirm and login counters separate, so burning one does not spend the other', function () {
    config(['lukk.rate_limits.confirm.max_attempts' => 500]);
    $user = User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);
    $access = $user->startSession()->accessToken;

    failStepUp($access);
    failStepUp($access);
    failStepUp($access);
    failStepUp($access)->assertStatus(423);

    // Step-up is locked; login is untouched and still takes its own full run.
    failLogin()->assertStatus(422);
});

it('clears a step-up lock on a successful login, the self-service way out', function () {
    // An attacker with a stolen access token can lock step-up; they cannot log in without the
    // password, so letting a successful login clear it hands them nothing.
    config(['lukk.rate_limits.confirm.max_attempts' => 500]);
    $user = User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);
    $access = $user->startSession()->accessToken;

    failStepUp($access);
    failStepUp($access);
    failStepUp($access);
    failStepUp($access)->assertStatus(423);

    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'correct'])->assertOk();

    app('auth')->forgetGuards();
    $this->withToken($access)->postJson('/auth/confirm-password', ['password' => 'correct'])->assertOk();
});

it('clears a step-up lock on a password reset, since those failures are now meaningless', function () {
    config(['lukk.features.password_reset' => true, 'lukk.rate_limits.confirm.max_attempts' => 500]);
    $user = User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('correct')]);
    $access = $user->startSession()->accessToken;

    failStepUp($access);
    failStepUp($access);
    failStepUp($access);
    failStepUp($access)->assertStatus(423);

    app('auth')->forgetGuards();
    $this->postJson('/auth/reset-password', [
        'email' => 'victim@y.com',
        'token' => Password::broker()->createToken($user),
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertOk();

    expect(Lockout::where('purpose', 'confirm')->exists())->toBeFalse();
});

it('releases a confirm lock from the console', function () {
    config(['lukk.rate_limits.confirm.max_attempts' => 500]);
    $user = User::factory()->create(['password' => bcrypt('correct')]);
    $access = $user->startSession()->accessToken;

    failStepUp($access);
    failStepUp($access);
    failStepUp($access);
    failStepUp($access)->assertStatus(423);

    $this->artisan('lukk:release', ['subject' => (string) $user->getKey(), '--purpose' => 'confirm'])
        ->assertSuccessful();

    app('auth')->forgetGuards();
    $this->withToken($access)->postJson('/auth/confirm-password', ['password' => 'correct'])->assertOk();
});

it('bounds the subject in bytes, so a transliteration blow-up cannot 500 the login route', function () {
    // `LoginRequest` caps the identifier at 255 CHARACTERS, but transliteration expands up to ~6x:
    // 43 copies of `㈱` pass validation and come out at 258 bytes. That overflows the `subject`
    // column (varchar 255) and the database cache store's `key` column — MySQL 1406 / PG 22001,
    // both a 500 on an unauthenticated endpoint. SQLite doesn't enforce the length, so this asserts
    // on the stored value rather than relying on the engine to catch it.
    $long = str_repeat('㈱', 43);

    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => $long, 'password' => 'wrong'])->assertStatus(422);

    $subject = (string) Lockout::where('purpose', 'login')->value('subject');

    expect(strlen($subject))->toBeLessThanOrEqual(255)
        ->and($subject)->toStartWith('idn:sha256:');
});

it('releases a user-id lock whose case matters, like a ULID', function () {
    // Only the `login` subject is a normalized identifier. Lower-casing a `two_factor`/`confirm`
    // subject breaks a ULID (uppercase Crockford base32) everywhere comparison is binary, so the
    // documented operator escape hatch would silently no-op.
    $ulid = (string) Str::ulid();
    app(LockoutRepository::class)->recordFailure('two_factor', $ulid, 'api');

    $this->artisan('lukk:release', ['subject' => $ulid, '--purpose' => 'two_factor'])->assertSuccessful();

    expect(Lockout::where('subject', $ulid)->exists())->toBeFalse();
});

it('does not let a look-alike account share, or clear, another account\'s lock', function () {
    // The subject used to be `transliterate(lower(trim(...)))`, which is many-to-one across real
    // accounts: `аdmin@y.com` (Cyrillic а) folds onto `admin@y.com`. Both shared one lock row, and
    // since a password reset releases on that subject, whoever controlled the look-alike could lock
    // the victim, reset their OWN password, clear the victim's lock, and repeat — reducing the
    // §5.2.2 cap back to the decaying throttle it exists to replace.
    config(['lukk.features.password_reset' => true]);
    $victim = User::factory()->create(['email' => 'admin@y.com', 'password' => bcrypt('correct')]);
    $lookalike = User::factory()->create(['email' => "\u{0430}dmin@y.com", 'password' => bcrypt('correct')]);

    // Same normalization, different accounts — the premise of the attack.
    expect(LoginRateLimiter::normalize($lookalike->email))
        ->toBe(LoginRateLimiter::normalize($victim->email));

    foreach (range(1, 3) as $i) {
        failLogin('admin@y.com');
    }
    failLogin('admin@y.com')->assertStatus(423);

    // The look-alike is a different account, so it holds a different counter and is not locked.
    failLogin("\u{0430}dmin@y.com")->assertStatus(422);

    // And resetting the look-alike's password must not release the victim's lock.
    app('auth')->forgetGuards();
    $this->postJson('/auth/reset-password', [
        'email' => $lookalike->email,
        'token' => Password::broker()->createToken($lookalike),
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertOk();

    failLogin('admin@y.com')->assertStatus(423);
});

it('still counts an identifier that names no account, so being locked is not an existence oracle', function () {
    foreach (range(1, 3) as $i) {
        failLogin('ghost@y.com');
    }

    // A non-existent address locks exactly like a real one — otherwise 423-vs-422 would answer
    // "does this account exist?" for free.
    failLogin('ghost@y.com')->assertStatus(423);
    expect(Lockout::where('subject', 'idn:ghost@y.com')->exists())->toBeTrue();
});
