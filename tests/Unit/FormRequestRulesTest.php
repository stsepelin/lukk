<?php

declare(strict_types=1);

use Illuminate\Validation\Rules\Password;
use Lukk\Http\Requests\ChangePasswordRequest;
use Lukk\Http\Requests\ForgotPasswordRequest;
use Lukk\Http\Requests\PasskeyAssertionRequest;
use Lukk\Http\Requests\PasskeyRegistrationRequest;
use Lukk\Http\Requests\TwoFactorChallengeRequest;

// Each rule pinned on its own (see `failedRulesFor`). A null field that should be allowed is pinned
// by failing NOTHING, which is what `nullable` buys: without it, `string` rejects the null.

it('applies each change-password rule on its own', function (string $field, array $overrides, string $rule) {
    $data = array_merge([
        'current_password' => 'old-password-123',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ], $overrides);

    expect(failedRulesFor((new ChangePasswordRequest)->rules(), $data, $field))->toHaveKey($rule);
})->with([
    'current required' => ['current_password', ['current_password' => null], 'Required'],
    'current a string' => ['current_password', ['current_password' => ['x']], 'String'],
    'current bounded' => ['current_password', ['current_password' => str_repeat('a', 256)], 'Max'],
    'new required' => ['password', ['password' => null], 'Required'],
    'new confirmed' => ['password', ['password_confirmation' => 'other-password-123'], 'Confirmed'],
    'new differs from current' => ['password', ['current_password' => 'new-password-123'], 'Different'],
    'new bounded' => ['password', ['password' => str_repeat('a', 256), 'password_confirmation' => str_repeat('a', 256)], 'Max'],
    'new without a NUL byte' => ['password', ['password' => "new-pass\0word-123", 'password_confirmation' => "new-pass\0word-123"], 'NotRegex'],
    'new meets the defaults' => ['password', ['password' => 'short', 'password_confirmation' => 'short'], Password::class],
]);

it('applies each two-factor challenge rule on its own', function (string $field, array $data, string $rule) {
    expect(failedRulesFor((new TwoFactorChallengeRequest)->rules(), ['challenge_token' => 'ct', ...$data], $field))->toHaveKey($rule);
})->with([
    'challenge required' => ['challenge_token', ['challenge_token' => null], 'Required'],
    'challenge a string' => ['challenge_token', ['challenge_token' => ['x']], 'String'],
    'code a string' => ['code', ['code' => ['x']], 'String'],
    'code excludes a recovery code' => ['code', ['code' => '123456', 'recovery_code' => 'r'], 'Prohibits'],
    'recovery code a string' => ['recovery_code', ['recovery_code' => ['x']], 'String'],
    'recovery code excludes a code' => ['recovery_code', ['code' => '123456', 'recovery_code' => 'r'], 'Prohibits'],
]);

it('lets either two-factor credential be null', function (string $field) {
    $data = ['challenge_token' => 'ct', 'code' => null, 'recovery_code' => null];

    expect(failedRulesFor((new TwoFactorChallengeRequest)->rules(), $data, $field))->toBe([]);
})->with(['code', 'recovery_code']);

it('applies each passkey registration rule on its own', function (string $field, array $data, string $rule) {
    expect(failedRulesFor((new PasskeyRegistrationRequest)->rules(), $data, $field))->toHaveKey($rule);
})->with([
    'credential required' => ['credential', [], 'Required'],
    'credential an array' => ['credential', ['credential' => 'x'], 'Array'],
    'name a string' => ['name', ['credential' => ['id' => 'x'], 'name' => ['x']], 'String'],
    'name bounded' => ['name', ['credential' => ['id' => 'x'], 'name' => str_repeat('a', 256)], 'Max'],
]);

it('lets a passkey be registered without a name', function () {
    expect(failedRulesFor((new PasskeyRegistrationRequest)->rules(), ['credential' => ['id' => 'x'], 'name' => null], 'name'))->toBe([]);
});

it('applies each passkey assertion rule on its own', function (string $field, array $data, string $rule) {
    $data = array_merge(['ceremony_id' => 'c', 'credential' => ['id' => 'x']], $data);

    expect(failedRulesFor((new PasskeyAssertionRequest)->rules(), $data, $field))->toHaveKey($rule);
})->with([
    'ceremony required' => ['ceremony_id', ['ceremony_id' => null], 'Required'],
    'ceremony a string' => ['ceremony_id', ['ceremony_id' => ['x']], 'String'],
    'credential required' => ['credential', ['credential' => null], 'Required'],
    'credential an array' => ['credential', ['credential' => 'x'], 'Array'],
    'credential id required' => ['credential.id', ['credential' => ['type' => 'public-key']], 'Required'],
    'credential id a string' => ['credential.id', ['credential' => ['id' => ['x']]], 'String'],
]);

it('applies each forgot-password rule on its own', function (array $data, string $rule) {
    expect(failedRulesFor((new ForgotPasswordRequest)->rules(), $data, 'email'))->toHaveKey($rule);
})->with([
    'required' => [[], 'Required'],
    'a string' => [['email' => ['x']], 'String'],
    'well-formed' => [['email' => 'not-an-email'], 'Email'],
    'bounded' => [['email' => str_repeat('a', 250).'@x.com'], 'Max'],
]);
