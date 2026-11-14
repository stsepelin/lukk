<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Hashing\AbstractHasher;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\ChangePassword;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Actions\RevokeOtherSessions;
use Lukk\Contracts\LockoutRepository;
use Lukk\Events\PasswordChanged;
use Lukk\Models\Lockout;
use Lukk\Models\RefreshToken;
use Lukk\Tests\Fixtures\PasswdColumnUser;
use Lukk\Tests\Fixtures\User;

uses()->group('change-password');

/** A signed-in user plus the pair for the session they're doing it from. */
function signedIn(string $password = 'password'): array
{
    $user = User::factory()->create(['password' => bcrypt($password)]);

    return [$user, $user->startSession()];
}

it('changes the password once the current one is proven', function () {
    [$user, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertOk()->assertJson(['status' => 'password-changed']);

    expect(Hash::check('new-password-1', $user->refresh()->password))->toBeTrue();

    // And the new password is one the LOGIN route will actually accept — the bound length exists
    // so a change can't lock someone out of the account they just secured.
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'new-password-1'])->assertOk();
});

it('refuses a wrong current password, and changes nothing', function () {
    // The point of asking: a stolen access token alone must not be enough to take the account
    // over permanently, which is exactly what changing the password would do.
    [$user, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'not-the-password',
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertStatus(422)->assertJsonValidationErrors(['current_password']);

    expect(Hash::check('password', $user->refresh()->password))->toBeTrue();
});

it('requires authentication', function () {
    $this->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertStatus(401);
});

it('revokes every other session but keeps the one it was done from', function () {
    // Changing a password is what someone does when they think another party is in the account, so
    // leaving those sessions alive would defeat the point — but logging the user out of the tab
    // they just did it in is a bad answer to a good instinct.
    [$user, $current] = signedIn();
    app('auth')->forgetGuards();
    $other = $user->startSession();

    app('auth')->forgetGuards();
    $this->withToken($current->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertOk();

    // The other session's refresh token is dead...
    app('auth')->forgetGuards();
    $this->postJson('/auth/refresh', ['refresh_token' => $other->refreshToken])->assertStatus(401);

    // ...and this one still rotates.
    app('auth')->forgetGuards();
    $this->postJson('/auth/refresh', ['refresh_token' => $current->refreshToken])->assertOk();
});

it('fires PasswordChanged with the user', function () {
    Event::fake([PasswordChanged::class]);
    [$user, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertOk();

    Event::assertDispatched(PasswordChanged::class, fn ($e) => $e->user->is($user));
});

it('rejects a new password that fails confirmation, or repeats the current one', function () {
    [$user, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'new-password-1',
        'password_confirmation' => 'mismatched',
    ])->assertStatus(422)->assertJsonValidationErrors(['password']);

    // A no-op would report success for a change that didn't happen — and this endpoint revokes
    // every other session, which is a lot of collateral for nothing.
    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'password',
        'password_confirmation' => 'password',
    ])->assertStatus(422)->assertJsonValidationErrors(['password']);

    expect(Hash::check('password', $user->refresh()->password))->toBeTrue();
});

it('shares the step-up throttle, so it is not a second budget for the same secret', function () {
    // Two independent allowances for guessing one password is just a larger allowance.
    config(['lukk.rate_limits.confirm.max_attempts' => 3]);
    [, $pair] = signedIn();

    $wrong = fn () => test()->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'wrong', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ]);

    app('auth')->forgetGuards();
    $wrong()->assertStatus(422);
    app('auth')->forgetGuards();
    $wrong()->assertStatus(422);

    // The third attempt is spent on the CONFIRM endpoint — same budget, so this one is out.
    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/confirm-password', ['password' => 'wrong'])->assertStatus(422);

    app('auth')->forgetGuards();
    $wrong()->assertStatus(429);
});

it('counts a wrong current password toward the confirm lockout', function () {
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.rate_limits.confirm.max_attempts' => 500]);
    [$user, $pair] = signedIn();

    foreach (range(1, 3) as $i) {
        app('auth')->forgetGuards();
        $this->withToken($pair->accessToken)->postJson('/auth/password', [
            'current_password' => 'wrong', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
        ])->assertStatus(422);
    }

    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertStatus(423);

    expect(Lockout::where('purpose', 'confirm')->where('subject', (string) $user->getKey())->exists())->toBeTrue();
});

it('clears the confirm lock on success, since those failures were against the old password', function () {
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 500, 'lukk.rate_limits.confirm.max_attempts' => 500]);
    [, $pair] = signedIn();

    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'wrong', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertStatus(422);

    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertOk();

    expect(Lockout::where('purpose', 'confirm')->exists())->toBeFalse();
});

it('revokes every session when the token carries no family', function () {
    // A token with no `fid` was not minted by this package's session flow — it comes from a
    // co-issuer sharing the secret (the verify-only topology). There is no lukk-tracked session of
    // the caller's among these rows to protect, so the sweep must take all of them. Skipping it
    // returned "password-changed" while every session the user believed they'd killed stayed live.
    $user = User::factory()->create(['password' => bcrypt('password')]);
    $a = $user->startSession();
    app('auth')->forgetGuards();
    $b = $user->startSession();

    // Minted by hand, because the issuer always stamps `fid` — that is the whole point of the case.
    $now = now()->getTimestamp();
    $fidless = JWT::encode([
        'iss' => config('lukk.issuer'), 'aud' => config('lukk.audience')[0] ?? config('lukk.audience'),
        'sub' => (string) $user->getKey(), 'jti' => (string) Str::uuid(),
        'iat' => $now, 'nbf' => $now, 'exp' => $now + 900,
    ], config('lukk.secret'), 'HS256', head: ['typ' => 'at+jwt']);

    app('auth')->forgetGuards();
    $this->withToken($fidless)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertOk();

    // Both families gone — asserted on `revoked_at`, not on row count: revocation is a soft update,
    // so counting rows can never fail and would pin nothing.
    expect(RefreshToken::query()->whereNull('revoked_at')->count())->toBe(0);

    foreach ([$a, $b] as $dead) {
        app('auth')->forgetGuards();
        $this->postJson('/auth/refresh', ['refresh_token' => $dead->refreshToken])->assertStatus(401);
    }
});

it('marks the response uncacheable', function () {
    // The siblings pin this; without it, deleting `noStore()` from the controller fails no test.
    [, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertHeader('Cache-Control', 'no-store, private');
});

it('rejects a missing current password without spending a lockout attempt', function () {
    // `different:current_password` is SKIPPED when the compared key is absent from the payload, so
    // `required` is the only thing standing between that and a no-op change being accepted.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3]);
    [$user, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'password' => 'password', 'password_confirmation' => 'password',
    ])->assertStatus(422)->assertJsonValidationErrors(['current_password']);

    expect(Hash::check('password', $user->refresh()->password))->toBeTrue()
        // A shape error is not a wrong password — it must not consume the cap.
        ->and(Lockout::where('purpose', 'confirm')->exists())->toBeFalse();
});

it('refuses a change that lost the reservation race', function () {
    // The state a concurrent overrun leaves: several requests passed the "not locked" gate together
    // and incremented past the cap before any of them locked the row. Seeded directly, because it
    // is by definition not reachable one request at a time.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.rate_limits.confirm.max_attempts' => 500]);
    [$user, $pair] = signedIn();
    Lockout::create([
        'purpose' => 'confirm', 'subject' => (string) $user->getKey(), 'guard' => 'api',
        'attempts' => 3, 'locked_at' => null,
    ]);

    // `locked_at` is null so the gate lets it through — the reservation is what stops it. Even the
    // CORRECT current password is refused, which is what "no verification happened" looks like.
    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertStatus(423);

    expect(Hash::check('password', $user->refresh()->password))->toBeTrue();
});

it('clears the LOGIN lock too, so the change actually restores access', function () {
    // Releasing only the confirm counter left a user who was being brute-forced, noticed, and did
    // the right thing still locked out of login on every other device — permanently, with
    // release_after at 0, and the only way out was the reset email this endpoint exists to avoid.
    config([
        'lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 2, 'lukk.lockout.release_after' => 0,
        'lukk.rate_limits.login.max_attempts' => 500, 'lukk.rate_limits.login.ip_max_attempts' => 500,
        'lukk.rate_limits.login.account_max_attempts' => 500,
    ]);
    $user = User::factory()->create(['email' => 'victim@y.com', 'password' => bcrypt('password')]);
    $pair = $user->startSession();

    foreach (range(1, 3) as $i) {
        app('auth')->forgetGuards();
        $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'wrong']);
    }
    expect(Lockout::where('purpose', 'login')->exists())->toBeTrue();

    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertOk();

    // The whole point: the new password actually works.
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'new-password-1'])->assertOk();
});

it('rejects a NUL byte in the new password instead of 500ing', function () {
    // `Hash::make` throws "Bcrypt hashing not supported" on a NUL byte, and nothing else in the
    // rule set rejects one — so it surfaced as a 500. Shared with register and reset, which had
    // the same hole.
    [, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => "new-password\0evil",
        'password_confirmation' => "new-password\0evil",
    ])->assertStatus(422)->assertJsonValidationErrors(['password']);
});

it('answers a held confirm lock with its auto-release wait, and counts nothing more', function () {
    // Checked before a failure is reserved, so a request refused by the lock does not extend the run;
    // and read on the guard the lock was recorded under, or the wait reads as "contact support".
    $this->freezeSecond();
    app('translator')->addLines(['auth.throttle' => 'Wait :seconds s.'], 'en');
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.lockout.release_after' => 600,
        'lukk.rate_limits.confirm.max_attempts' => 500]);
    [$user, $pair] = signedIn();
    Lockout::create(['purpose' => 'confirm', 'subject' => (string) $user->getKey(), 'guard' => 'api', 'attempts' => 3, 'locked_at' => now()]);

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertStatus(423)->assertJsonValidationErrors(['current_password' => 'Wait 600 s.']);

    expect(Lockout::query()->value('attempts'))->toBe(3);
});

/** A co-issuer access token whose `fid` arrives as a JSON number. */
function numericFidToken(User $user): string
{
    $cfg = Lukk\Lukk::guardConfig();

    return JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => (string) $user->getAuthIdentifier(), 'fid' => 42,
        'jti' => 'numeric-fid-'.$user->getAuthIdentifier(), 'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);
}

it('reads a session id that another issuer encoded as a number', function () {
    // It names the same session, and must not become a 500 on the way to naming it.
    [$user] = signedIn();

    $this->withToken(numericFidToken($user))->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertOk();
    app('auth')->forgetGuards();

    $this->withToken(numericFidToken($user))->deleteJson('/auth/sessions/others')->assertNoContent();
});

it('answers a password that is not a string with 422, not a 500', function () {
    [, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => ['x'], 'password_confirmation' => ['x'],
    ])->assertStatus(422)->assertJsonValidationErrors(['password']);
});

it('changes the password and signs out other sessions for a user authenticated with actingAs', function () {
    // `Lukk::actingAs()` authenticates the guard with no bearer at all, so nothing here may assume one.
    [$user] = signedIn();
    Lukk\Lukk::actingAs($user);

    $this->deleteJson('/auth/sessions/others')->assertNoContent();
    $this->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertOk();
});

it('writes the new password to the column the model names', function () {
    Schema::table('users', fn (Blueprint $t) => $t->string('passwd')->nullable());
    $user = PasswdColumnUser::query()->create(['name' => 'p', 'email' => 'cp@y.com', 'password' => 'unused']);
    DB::table('users')->where('id', $user->id)->update(['passwd' => Hash::make('old-password')]);
    config(['auth.providers.users.model' => PasswdColumnUser::class]);
    app('auth')->forgetGuards();
    $access = start()($user->id)->accessToken;

    $this->withToken($access)->postJson('/auth/password', [
        'current_password' => 'old-password', 'password' => 'brand-new-pass-1', 'password_confirmation' => 'brand-new-pass-1',
    ])->assertSuccessful();

    expect(Hash::check('brand-new-pass-1', (string) DB::table('users')->where('id', $user->id)->value('passwd')))->toBeTrue();
});

/**
 * `ChangePassword`, with something happening to the row between the check of the current password and
 * the write of the new one — the moment a concurrent request's commit lands.
 */
function changeWithInterleaving(User $user, Closure $meanwhile, ?LockoutRepository $lockouts = null): void
{
    $provider = new class(app('hash'), User::class) extends EloquentUserProvider
    {
        public ?Closure $meanwhile = null;

        public function validateCredentials(Authenticatable $user, #[SensitiveParameter] array $credentials): bool
        {
            // A provider may read more of the user than its password (a tenant, a status column): the
            // re-check hands it the whole account, with only the hash replaced by the one now stored.
            $valid = parent::validateCredentials($user, $credentials) && $user->getAuthIdentifier() !== null && $user->email !== null;

            if ($this->meanwhile !== null) {
                [$meanwhile, $this->meanwhile] = [$this->meanwhile, null];
                $meanwhile();
            }

            return $valid;
        }
    };
    $provider->meanwhile = $meanwhile;

    (new ChangePassword($provider, app(RevokeOtherSessions::class), app(RevokeAllSessions::class), $lockouts, 'api'))($user, 'password', 'attacker-chosen-1', null);
}

it('does not write over a recovery reset that committed after the current password was checked', function () {
    // Someone holds the OLD password and a live token; the owner resets. The change had verified `password`
    // against the hash loaded when its request began, then wrote unconditionally — over the owner's new one.
    $user = User::factory()->create();
    $recovered = Hash::make('owner-recovered-1');

    expect(fn () => changeWithInterleaving($user, fn () => DB::table('users')->where('id', $user->id)->update(['password' => $recovered])))
        ->toThrow(fn (ValidationException $e) => expect($e->errors())->toHaveKey('current_password'));

    expect(DB::table('users')->where('id', $user->id)->value('password'))->toBe($recovered)
        ->and(DB::transactionLevel())->toBe(1);
});

it('still changes the password when a concurrent sign-in only rehashed the same one', function () {
    // The hash moved, the password did not: refusing here would fail a legitimate change at random.
    $user = User::factory()->create();

    changeWithInterleaving($user, fn () => DB::table('users')->where('id', $user->id)->update(['password' => Hash::make('password', ['rounds' => 5])]));

    expect(Hash::check('attacker-chosen-1', DB::table('users')->where('id', $user->id)->value('password')))->toBeTrue();
});

it('refuses a change for an account deleted meanwhile, rather than recreating anything', function () {
    $user = User::factory()->create();

    expect(fn () => changeWithInterleaving($user, fn () => DB::table('users')->where('id', $user->id)->delete()))
        ->toThrow(ValidationException::class);

    expect(DB::table('users')->count())->toBe(0);
});

it('counts a change refused because the password moved under it as a wrong guess', function () {
    // The second check of the current password is a check like the first: one that fails has to reach
    // the lockout, or the holder of an old password gets a free guess every time the owner resets.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 1]);
    $user = User::factory()->create();

    expect(fn () => changeWithInterleaving(
        $user,
        fn () => DB::table('users')->where('id', $user->id)->update(['password' => Hash::make('owner-recovered-1')]),
        app(LockoutRepository::class),
    ))->toThrow(ValidationException::class);

    expect(Lockout::where('purpose', 'confirm')->where('subject', (string) $user->getKey())->whereNotNull('locked_at')->exists())->toBeTrue();
});

it('tells the user model\'s observers once the password is stored, outside any transaction of its own', function () {
    // The write is a conditional query, so Eloquent fires nothing by itself. An audit observer on the
    // user model still has to hear of a password change — and must not run inside a transaction lukk
    // holds: on PostgreSQL an observer that swallowed a failed query aborted it, `COMMIT` became
    // `ROLLBACK`, and the change answered "password-changed" having stored nothing.
    $user = User::factory()->create();
    $level = DB::transactionLevel();
    $seen = [];
    $note = function (string $event) use (&$seen) {
        return function (User $changed) use (&$seen, $event) {
            $seen[] = [
                $event, $changed->wasChanged('password'), DB::transactionLevel(),
                Hash::check('attacker-chosen-1', (string) DB::table('users')->where('id', $changed->id)->value('password')),
            ];
        };
    };
    User::updating($note('updating'));
    User::updated($note('updated'));
    User::saved($note('saved'));

    changeWithInterleaving($user, fn () => null);

    expect($seen)->toBe([['updated', true, $level, true], ['saved', true, $level, true]])
        ->and($user->isDirty())->toBeFalse()
        ->and(Hash::check('attacker-chosen-1', $user->password))->toBeTrue();
});

class PasswordAudited
{
    public function __construct(public User $user) {}
}

class AuditedUser extends User
{
    protected $table = 'users';

    protected $dispatchesEvents = ['updated' => PasswordAudited::class];
}

it('fires the event class a model maps to `updated`, as a save would', function () {
    Event::fake([PasswordAudited::class]);
    $user = AuditedUser::query()->findOrFail(User::factory()->create()->getKey());

    changeWithInterleaving($user, fn () => null);

    Event::assertDispatched(PasswordAudited::class, fn (PasswordAudited $event) => $event->user->is($user) && $event->user->wasChanged('password'));
});

it('takes the password as written when the row already holds the very hash it was writing', function () {
    // MySQL reports rows CHANGED, not rows matched: an UPDATE that sets the value it found answers 0,
    // exactly as one that matched nothing does. With a hasher that derives the same hash twice — no
    // salt, as some legacy and test hashers have none — retrying that write would never end. Reproduced
    // here by another request storing the same new password first.
    Hash::extend('unsalted', fn () => new class extends AbstractHasher implements Hasher
    {
        public function make(#[SensitiveParameter] $value, array $options = []): string
        {
            return 'unsalted:'.hash('sha256', (string) $value);
        }

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = []): bool
        {
            return hash_equals((string) $hashedValue, $this->make($value));
        }

        public function needsRehash($hashedValue, array $options = []): bool
        {
            return false;
        }
    });
    config(['hashing.driver' => 'unsalted']);
    $user = User::factory()->create(['password' => Hash::make('password')]);

    changeWithInterleaving($user, fn () => DB::table('users')->where('id', $user->id)->update(['password' => Hash::make('attacker-chosen-1')]));

    expect(DB::table('users')->where('id', $user->id)->value('password'))->toBe(Hash::make('attacker-chosen-1'));
});

it('changes the password for a model with no event dispatcher', function () {
    // `Model::unsetEventDispatcher()` — a console command or a seeder that switched model events off.
    $user = User::factory()->create();
    $dispatcher = User::getEventDispatcher();
    User::unsetEventDispatcher();

    try {
        changeWithInterleaving($user, fn () => null);
    } finally {
        User::setEventDispatcher($dispatcher);
    }

    expect(Hash::check('attacker-chosen-1', (string) DB::table('users')->where('id', $user->id)->value('password')))->toBeTrue();
});

function changeTo(string $access, string $password = 'new-password-1')
{
    return test()->withToken($access)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => $password, 'password_confirmation' => $password,
    ]);
}

it('drops a reset link requested before the change', function () {
    // A reset token outlives the password it was requested for. Whoever asked for one could let the owner
    // change the password and then undo that with the older link.
    [$user, $pair] = signedIn();
    $token = Password::broker()->createToken($user);

    changeTo($pair->accessToken)->assertOk();

    expect(DB::table('password_reset_tokens')->where('email', $user->email)->exists())->toBeFalse();
    $this->postJson('/auth/reset-password', [
        'email' => $user->email, 'token' => $token, 'password' => 'undo-the-change-1', 'password_confirmation' => 'undo-the-change-1',
    ])->assertStatus(422);
});

it('drops it from the broker lukk is configured with', function () {
    Schema::create('other_resets', function (Blueprint $table) {
        $table->string('email')->primary();
        $table->string('token');
        $table->timestamp('created_at')->nullable();
    });
    config(['auth.passwords.other' => ['provider' => 'users', 'table' => 'other_resets', 'expire' => 60, 'throttle' => 0], 'lukk.password_reset.broker' => 'other']);
    [$user, $pair] = signedIn();
    Password::broker('other')->createToken($user);
    Password::broker()->createToken($user);

    changeTo($pair->accessToken)->assertOk();

    // The configured broker's row is gone; the default broker's is not lukk's to touch.
    expect(DB::table('other_resets')->count())->toBe(0)
        ->and(DB::table('password_reset_tokens')->count())->toBe(1);
});

it('changes the password where the reset table was never published', function () {
    Schema::drop('password_reset_tokens');
    [$user, $pair] = signedIn();
    Exceptions::fake();

    changeTo($pair->accessToken)->assertOk();

    // Not attempted and swallowed: with no table there is nothing to ask the broker for.
    Exceptions::assertNothingReported();

    expect(Hash::check('new-password-1', $user->fresh()->password))->toBeTrue();
});

it('reports, and does not fail the change on, a broker that cannot delete', function () {
    // The password is already written: a 500 here would tell the user it failed when it had not.
    [$user, $pair] = signedIn();
    Exceptions::fake();
    Password::shouldReceive('broker')->andThrow(new RuntimeException('broker down'));

    changeTo($pair->accessToken)->assertOk();

    Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'broker down');
    expect(Hash::check('new-password-1', $user->fresh()->password))->toBeTrue();
});

/** An account model that takes no part in password resets. */
class AccountWithoutResets extends Model implements Authenticatable
{
    use Illuminate\Auth\Authenticatable;

    public $timestamps = false;

    protected $table = 'users';

    protected $guarded = [];
}

it('asks the broker nothing for a model that cannot reset its password', function () {
    // `deleteToken()` takes a `CanResetPassword`; a model that is not one has no reset rows to drop.
    $user = AccountWithoutResets::query()->find(User::factory()->create()->id);
    Exceptions::fake();

    (new ChangePassword(new EloquentUserProvider(app('hash'), AccountWithoutResets::class), app(RevokeOtherSessions::class), app(RevokeAllSessions::class)))($user, 'password', 'new-password-1', null);

    Exceptions::assertNothingReported();
    expect(Hash::check('new-password-1', $user->fresh()->password))->toBeTrue();
});
