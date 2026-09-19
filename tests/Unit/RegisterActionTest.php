<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
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
