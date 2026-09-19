<?php

declare(strict_types=1);

use Illuminate\Validation\Rules\Password;
use Lukk\Http\Requests\ResetPasswordRequest;

it('applies each reset rule on its own', function (string $field, array $overrides, string $rule) {
    $data = array_merge([
        'token' => str_repeat('t', 60),
        'email' => 'ada@example.test',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ], $overrides);

    expect(failedRulesFor((new ResetPasswordRequest)->rules(), $data, $field))->toHaveKey($rule);
})->with([
    'token required' => ['token', ['token' => null], 'Required'],
    'token a string' => ['token', ['token' => ['x']], 'String'],
    'token bounded' => ['token', ['token' => str_repeat('t', 256)], 'Max'],
    'email required' => ['email', ['email' => null], 'Required'],
    'email a string' => ['email', ['email' => ['x']], 'String'],
    'email well-formed' => ['email', ['email' => 'not-an-email'], 'Email'],
    'email bounded' => ['email', ['email' => str_repeat('a', 250).'@x.com'], 'Max'],
    'password required' => ['password', ['password' => null], 'Required'],
    'password confirmed' => ['password', ['password_confirmation' => 'other-password-123'], 'Confirmed'],
    'password bounded' => ['password', ['password' => str_repeat('a', 256), 'password_confirmation' => str_repeat('a', 256)], 'Max'],
    'password without a NUL byte' => ['password', ['password' => "new-pass\0word-123", 'password_confirmation' => "new-pass\0word-123"], 'NotRegex'],
    'password meets the defaults' => ['password', ['password' => 'short', 'password_confirmation' => 'short'], Password::class],
]);
