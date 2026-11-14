<?php

declare(strict_types=1);

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Casts\AsStringable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Lukk\Lukk;
use Lukk\Models\Lockout;
use Lukk\Tests\Fixtures\User;

/*
 * The login throttle and the lockout key on the identifier's FOLD, which caps guessing only while every
 * spelling the DATABASE resolves to an account folds to that account's key. No fold reaches the engine's
 * own equality — `tests/Concurrency/IdentifierRespellingTest.php` pins the MySQL collation cases — so
 * `AttemptLogin::spelledAsStored()` refuses a row found under a spelling that does not fold to the
 * identifier it stores.
 *
 * sqlite compares text byte for byte, so the looseness is provided here by a NUMERIC identifier column,
 * which every engine compares numerically: `05550100` finds the row storing `5550100`, and the two fold
 * to different keys.
 */

beforeEach(function () {
    Schema::table('users', fn (Blueprint $table) => $table->unsignedBigInteger('phone')->nullable());

    config([
        'lukk.username' => 'phone',
        'lukk.rate_limits.login.max_attempts' => 500,
        'lukk.rate_limits.login.ip_max_attempts' => 500,
        'lukk.rate_limits.login.account_max_attempts' => 3,
    ]);
});

function phoneUser(): User
{
    return tap(User::factory()->create(['password' => bcrypt('correct')]), fn (User $user) => $user->forceFill(['phone' => 5550100])->save());
}

function loginAs(string $phone, string $password = 'correct')
{
    app('auth')->forgetGuards();

    return test()->postJson('/auth/login', ['phone' => $phone, 'password' => $password]);
}

/** A value object with no string form: nothing lukk can fold. */
class OpaquePhone
{
    public function __construct(public readonly int $digits) {}
}

class OpaquePhoneCast implements CastsAttributes
{
    public function get(Model $model, string $key, mixed $value, array $attributes): ?OpaquePhone
    {
        return $value === null ? null : new OpaquePhone((int) $value);
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): mixed
    {
        return $value instanceof OpaquePhone ? $value->digits : $value;
    }
}

class OpaquePhoneUser extends User
{
    protected $table = 'users';

    protected function casts(): array
    {
        return ['phone' => OpaquePhoneCast::class];
    }
}

class StringablePhoneUser extends User
{
    protected $table = 'users';

    protected function casts(): array
    {
        return ['phone' => AsStringable::class];
    }
}

it('signs in under the spelling the row stores, whatever type the column hands back', function () {
    phoneUser();

    // The column is an integer and the request a string: compared as text, not by identity.
    expect(loginAs('5550100')->assertOk()->json('access_token'))->not->toBeNull();
});

it('gives no verified guess to a spelling the database resolves and the throttle keys apart', function () {
    phoneUser();

    foreach (range(1, 3) as $ignored) {
        loginAs('5550100', 'wrong')->assertStatus(422);
    }
    loginAs('5550100')->assertStatus(429);

    // The attack: the account's bucket is spent, so guess under a spelling the lookup still resolves to
    // it. The RIGHT password, so anything but a refusal means the guess was checked.
    foreach (['05550100', '5550100.0', '+5550100'] as $respelled) {
        $response = loginAs($respelled);

        expect($response->status())->toBe(422)
            ->and($response->json('access_token'))->toBeNull()
            ->and($response->json('errors.phone.0'))->toBe('These credentials do not match our records.');
    }
});

it('counts a refused respelling against its own fold only, never the account it resolves to', function () {
    // With the lockout on, the resolved account's `id:` counter was reachable under any spelling: a run
    // of failures on `05550100` locked `id:1`, after which the canonical spelling answered 423 for an
    // account and 422 for none — an existence oracle, and a way to lock someone out under a spelling
    // their own failures never touch.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 2, 'lukk.lockout.release_after' => 0, 'lukk.rate_limits.login.account_max_attempts' => 500]);
    $user = phoneUser();

    foreach (range(1, 3) as $ignored) {
        loginAs('05550100', 'wrong');
    }

    expect(Lockout::query()->where('subject', 'id:'.$user->getKey())->exists())->toBeFalse()
        ->and(Lockout::query()->count())->toBe(1);

    loginAs('5550100')->assertOk();
});

it('leaves the spelling to authenticateUsing, which may resolve an identifier of its own', function () {
    // The hook decides who signs in; lukk's lookup only names the lockout counters. A custom resolver
    // (a formatted phone number, a tenant-qualified name) was never promised to equal the column.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 5, 'lukk.rate_limits.login.account_max_attempts' => 500]);
    $user = phoneUser();
    Lukk::authenticateUsing(fn () => null);

    loginAs('05550100', 'wrong')->assertStatus(422);

    expect(Lockout::query()->where('subject', 'id:'.$user->getKey())->exists())->toBeTrue();
});

it('leaves the spelling to a provider subclass', function () {
    // Exactly the stock providers, never `instanceof`: a subclass may decode or reformat the identifier.
    phoneUser();
    Auth::provider('custom-eloquent', fn ($app, array $config) => new class($app['hash'], $config['model']) extends EloquentUserProvider {});
    config(['auth.providers.users.driver' => 'custom-eloquent']);

    loginAs('05550100')->assertOk();
});

it('holds the stock database provider to the stored spelling too', function () {
    phoneUser();
    config(['auth.providers.users' => ['driver' => 'database', 'table' => 'users']]);

    loginAs('05550100')->assertStatus(422);
    loginAs('5550100')->assertOk();
});

it('folds a stored identifier that is an object with a string form', function () {
    phoneUser();
    config(['auth.providers.users.model' => StringablePhoneUser::class]);

    loginAs('05550100')->assertStatus(422);
    loginAs('5550100')->assertOk();
});

it('does not judge a stored identifier it cannot read as text', function () {
    // Refusing here would lock every account of an install that casts the column to a value object.
    phoneUser();
    config(['auth.providers.users.model' => OpaquePhoneUser::class]);

    loginAs('05550100')->assertOk();
});
