<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;
use Lukk\Http\Requests\RegisterRequest;
use Lukk\Tests\Fixtures\Admin;
use Lukk\Tests\Fixtures\User;

uses()->group('registration');

/**
 * The rules that failed for `$field` when registering with `$overrides`.
 *
 * Asserting on the failed RULE rather than on a 422 is what pins each rule on its own: most bad
 * inputs trip two rules, so dropping either one still answers 422.
 *
 * @return array<string, mixed>
 */
function failedRules(string $field, array $overrides): array
{
    $data = array_merge([
        'name' => 'New User',
        'email' => 'new@user.com',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ], $overrides);

    $validator = Validator::make($data, (new RegisterRequest)->rules());
    $validator->fails();

    return $validator->failed()[$field] ?? [];
}

it('applies each default rule on its own', function (string $field, array $overrides, string $rule) {
    User::factory()->create(['email' => 'taken@user.com']);

    expect(failedRules($field, $overrides))->toHaveKey($rule);
})->with([
    'name required' => ['name', ['name' => null], 'Required'],
    'name a string' => ['name', ['name' => ['x']], 'String'],
    'name bounded' => ['name', ['name' => str_repeat('a', 256)], 'Max'],
    'email required' => ['email', ['email' => null], 'Required'],
    'email a string' => ['email', ['email' => ['x']], 'String'],
    'email bounded' => ['email', ['email' => str_repeat('a', 250).'@x.com'], 'Max'],
    'email well-formed' => ['email', ['email' => 'not-an-email'], 'Email'],
    'email unique' => ['email', ['email' => 'taken@user.com'], 'Unique'],
    'password required' => ['password', ['password' => null], 'Required'],
    'password confirmed' => ['password', ['password_confirmation' => 'other-password-123'], 'Confirmed'],
    'password bounded' => ['password', ['password' => str_repeat('a', 256), 'password_confirmation' => str_repeat('a', 256)], 'Max'],
    'password without a NUL byte' => ['password', ['password' => "new-pass\0word-123", 'password_confirmation' => "new-pass\0word-123"], 'NotRegex'],
    'password meets the defaults' => ['password', ['password' => 'short', 'password_confirmation' => 'short'], Password::class],
]);

it('applies each rule to a username identifier too', function (array $overrides, string $rule) {
    Schema::table('users', fn (Blueprint $table) => $table->string('username')->nullable());
    config(['lukk.username' => 'username']);
    User::factory()->create(['username' => 'taken']);

    expect(failedRules('username', $overrides))->toHaveKey($rule);
})->with([
    'required' => [[], 'Required'],
    'a string' => [['username' => ['x']], 'String'],
    'bounded' => [['username' => str_repeat('a', 256)], 'Max'],
    'unique' => [['username' => 'taken'], 'Unique'],
]);

it('keys the identifier on email when lukk.username is null', function () {
    config(['lukk.username' => null]);

    expect((new RegisterRequest)->rules())->toHaveKey('email')->not->toHaveKey('');
});

it('checks uniqueness against the configured user provider\'s table', function () {
    Schema::create('admins', function (Blueprint $table) {
        $table->id();
        $table->string('email')->unique();
        $table->string('password');
    });
    config([
        'lukk.user_provider' => 'admins',
        'auth.providers.admins' => ['driver' => 'eloquent', 'model' => Admin::class],
    ]);
    Admin::query()->forceCreate(['email' => 'boss@user.com', 'password' => 'x']);

    expect(failedRules('email', ['email' => 'boss@user.com']))->toHaveKey('Unique');
});
