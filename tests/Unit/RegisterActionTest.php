<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\Register;
use Lukk\Lukk;
use Lukk\Tests\Fixtures\User;

uses()->group('registration');

afterEach(fn () => Lukk::$registerUsing = null);

function registerAction(string $username = 'email'): Register
{
    return new Register(User::class, $username);
}

it('names the contract a registerUsing hook broke', function () {
    Lukk::registerUsing(fn (array $payload) => 'not-a-user');

    expect(fn () => registerAction()(['email' => 'a@b.test']))
        ->toThrow(RuntimeException::class, 'Lukk::registerUsing must return an Illuminate\Contracts\Auth\Authenticatable.');
});

it('accepts a user that is not an Eloquent model from registerUsing', function () {
    // The "must be newly created" check reads `wasRecentlyCreated`, which only a Model has; any other
    // Authenticatable has no such notion and is taken as returned.
    $user = new GenericUser(['id' => 7]);
    Lukk::registerUsing(fn (array $payload) => $user);

    expect(registerAction()(['email' => 'a@b.test']))->toBe($user);
});

it('names the field the default create is missing', function (string $missing, string $username) {
    $payload = ['name' => 'Ada', $username => 'ada', 'password' => 'secret-123456'];
    unset($payload[$missing]);

    expect(fn () => registerAction($username)($payload))
        ->toThrow(RuntimeException::class, "The default registration create needs `{$missing}`;");
})->with([
    'name' => ['name', 'email'],
    'the identifier column' => ['login', 'login'],
    'password' => ['password', 'email'],
]);

/**
 * Another request's INSERT of the same address, landed after this one's `unique` rule passed. The action
 * is called directly, so nothing re-validates: the row is simply there when the INSERT runs.
 */
function loseTheRaceFor(string $email): void
{
    DB::table('users')->insert(['name' => 'First', 'email' => $email, 'password' => 'x']);
}

$payload = ['name' => 'Second', 'email' => 'dup@example.com', 'password' => 'Str0ng-passw0rd!'];

it('answers the unique rule\'s 422 to the registration that lost a race, not a 500', function () use ($payload) {
    // Two posts of one address both pass `Rule::unique`; a key derivation later, the second INSERT hits
    // the index. That was an unhandled `UniqueConstraintViolationException`.
    loseTheRaceFor('dup@example.com');

    try {
        registerAction()($payload);
        $this->fail('The losing registration was accepted.');
    } catch (ValidationException $e) {
        expect($e->status)->toBe(422)
            ->and($e->errors())->toBe(['email' => [__('validation.unique', ['attribute' => 'email'])]]);
    }

    expect(User::query()->where('email', 'dup@example.com')->count())->toBe(1);
});

it('leaves a unique violation on some other column the error it was', function () use ($payload) {
    // Only a row carrying THIS identifier makes it the race. Anything else is the application's own
    // constraint, and calling it "email taken" would be a lie told with a 422.
    User::creating(fn () => throw new UniqueConstraintViolationException('sqlite', 'insert into "users"', [], new Exception('UNIQUE constraint failed: users.tenant_slug')));

    expect(fn () => registerAction()($payload))->toThrow(UniqueConstraintViolationException::class);
});

it('fails the insert inside a savepoint, so a caller\'s transaction survives the lost race', function () use ($payload) {
    // On PostgreSQL a failed statement aborts the surrounding transaction: the lookup that follows would
    // raise 25P02 and the caller's COMMIT would silently roll back. The create therefore runs one level
    // deeper than the caller, and that level is gone again by the time the 422 is thrown.
    $levels = [];
    User::creating(function () use (&$levels) {
        $levels[] = DB::transactionLevel();
    });
    loseTheRaceFor('dup@example.com');
    $outside = DB::transactionLevel();

    expect(fn () => registerAction()($payload))->toThrow(ValidationException::class);

    expect($levels)->toBe([$outside + 1])
        ->and(DB::transactionLevel())->toBe($outside);
});
