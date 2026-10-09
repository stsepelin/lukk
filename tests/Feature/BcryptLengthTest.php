<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Lukk\Lukk;
use Lukk\Support\HashablePassword;
use Lukk\Tests\Fixtures\User;

/*
 * NIST SP 800-63B-4 §3.1.1.2: the verifier SHALL verify the ENTIRE submitted password. bcrypt reads only
 * the first 72 bytes, so a longer password was stored truncated — `72×a + "SECRET-TAIL"` then accepted
 * `72×a + "anything"` — and with Laravel's own guard on (`hashing.bcrypt.limit`) `Hash::make` threw a 500
 * on these public routes. Under bcrypt a new password over 72 bytes is now a 422; other drivers have no
 * such limit and are left alone.
 */

$long = str_repeat('a', 72).'-and-the-tail';

beforeEach(fn () => config(['lukk.features.registration' => true, 'lukk.features.password_reset' => true]));

it('refuses an over-long password at registration under bcrypt', function () use ($long) {
    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'long@y.com', 'password' => $long, 'password_confirmation' => $long])
        ->assertStatus(422)->assertJsonValidationErrors('password');
});

it('refuses it at reset under bcrypt', function () use ($long) {
    $user = User::factory()->create();

    $this->postJson('/auth/reset-password', [
        'email' => $user->email, 'token' => Password::createToken($user), 'password' => $long, 'password_confirmation' => $long,
    ])->assertStatus(422)->assertJsonValidationErrors('password');
});

it('refuses it at change-password under bcrypt', function () use ($long) {
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)->postJson('/auth/password', ['current_password' => 'password', 'password' => $long, 'password_confirmation' => $long])
        ->assertStatus(422)->assertJsonValidationErrors('password');
});

it('counts bytes, not characters', function () {
    // 36 two-byte characters are 72 bytes, the most bcrypt reads; one more is over.
    $fits = str_repeat('é', 36);
    $over = str_repeat('é', 37);

    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'fits@y.com', 'password' => $fits, 'password_confirmation' => $fits])->assertSuccessful();
    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'over@y.com', 'password' => $over, 'password_confirmation' => $over])->assertStatus(422);
    // And the boundary in single bytes: 72 is accepted, 73 is not.
    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'b72@y.com', 'password' => str_repeat('b', 72), 'password_confirmation' => str_repeat('b', 72)])->assertSuccessful();
    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'b73@y.com', 'password' => str_repeat('b', 73), 'password_confirmation' => str_repeat('b', 73)])->assertStatus(422);
});

it('leaves a driver without the limit alone', function () use ($long) {
    config(['hashing.driver' => 'argon2id']);
    app('hash')->forgetDrivers();

    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'argon@y.com', 'password' => $long, 'password_confirmation' => $long])->assertSuccessful();
});

it('refuses it at registration even when registerValidation replaces the rules', function () use ($long) {
    // The hook replaces the rule set wholesale, and a consumer's set naturally omits a bcrypt detail;
    // the default create then stored the password truncated.
    Lukk::registerValidation(fn () => ['name' => ['required'], 'email' => ['required', 'email'], 'password' => ['required', 'confirmed']]);

    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'hook@y.com', 'password' => $long, 'password_confirmation' => $long])
        ->assertStatus(422)->assertJsonValidationErrors('password');
    expect(User::where('email', 'hook@y.com')->exists())->toBeFalse();
});

it('adds nothing for a password the hook already refused, nor one that fits', function () {
    Lukk::registerValidation(fn () => ['name' => ['required'], 'email' => ['required', 'email'], 'password' => ['required', 'confirmed']]);
    $fits = str_repeat('b', 72);

    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'fit@y.com', 'password' => $fits, 'password_confirmation' => $fits])->assertSuccessful();
    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'arr@y.com', 'password' => ['x'], 'password_confirmation' => ['x']])->assertStatus(422);
});

it('keeps to the hook\'s own message when it already refused the password', function () use ($long) {
    Lukk::registerValidation(fn () => ['name' => ['required'], 'email' => ['required', 'email'], 'password' => ['required', 'min:200']]);

    $errors = $this->postJson('/auth/register', ['name' => 'n', 'email' => 'min@y.com', 'password' => $long])
        ->assertStatus(422)->json('errors.password');
    expect($errors)->toHaveCount(1);
});

it('leaves an absent password to a hook that does not require one', function () {
    // A passwordless sign-up (magic link, SSO) creates its own user; nothing here is lukk's to hash.
    Lukk::registerValidation(fn () => ['email' => ['required', 'email']]);
    Lukk::registerUsing(fn (array $payload) => User::forceCreate(['name' => 'n', 'email' => $payload['email'], 'password' => '']));

    $this->postJson('/auth/register', ['email' => 'nopw@y.com'])->assertSuccessful();
});

it('refuses a password bcrypt would verify only in part at step-up and change-password', function () {
    // The same truncation sign-in now refuses (NIST SP 800-63B-4 §3.1.1.2): a row written outside lukk
    // with a longer password accepted any string sharing its first 72 bytes as the CURRENT password.
    $prefix = str_repeat('a', 72);
    $user = User::factory()->create();
    DB::table('users')->where('id', $user->id)
        ->update(['password' => password_hash($prefix.'-original', PASSWORD_BCRYPT, ['cost' => 4])]);
    $access = $user->startSession()->accessToken;

    $this->withToken($access)->postJson('/auth/confirm-password', ['password' => $prefix.'-guess'])
        ->assertStatus(422)->assertJsonValidationErrors('password');
    $this->withToken($access)->postJson('/auth/password', ['current_password' => $prefix.'-guess', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1'])
        ->assertStatus(422)->assertJsonValidationErrors('current_password');
});

it('tells the owner of a password stored truncated to reset it, instead of calling it wrong', function () {
    // Every release before this one stored an over-72-byte password truncated, so its owner types the
    // right one. Only a caller whose first 72 bytes match reaches this answer — one the old code let in.
    $prefix = str_repeat('a', 72);
    $user = User::factory()->create(['email' => 'trunc@y.com']);
    DB::table('users')->where('id', $user->id)->update(['password' => password_hash($prefix.'-mine', PASSWORD_BCRYPT, ['cost' => 4])]);
    $access = $user->startSession()->accessToken;
    $reset = 'This password is longer than 72 bytes, which can no longer be checked in full. Reset your password to continue.';

    $this->postJson('/auth/login', ['email' => 'trunc@y.com', 'password' => $prefix.'-mine'])->assertStatus(422)->assertJsonPath('errors.email.0', $reset);
    $this->withToken($access)->postJson('/auth/confirm-password', ['password' => $prefix.'-mine'])->assertStatus(422)->assertJsonPath('errors.password.0', $reset);
    $this->withToken($access)->postJson('/auth/password', ['current_password' => $prefix.'-mine', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1'])
        ->assertStatus(422)->assertJsonPath('errors.current_password.0', $reset);
    // A wrong password is still just wrong.
    $this->postJson('/auth/login', ['email' => 'trunc@y.com', 'password' => 'b'.$prefix])->assertStatus(422)->assertJsonPath('errors.email.0', 'These credentials do not match our records.');
});

it('refuses partial verification for every bcrypt prefix password_verify accepts', function (string $prefix) {
    // `password_get_info()` names only $2y$; an import from Node, Python or Ruby brings the others,
    // behind `hashing.bcrypt.verify` turned off so the framework accepts them at all.
    config(['hashing.bcrypt.verify' => false]);
    app('hash')->forgetDrivers();
    $long = str_repeat('a', 72);
    $user = User::factory()->create(['email' => "p{$prefix}@y.com"]);
    $hash = $prefix.substr(password_hash($long.'-original', PASSWORD_BCRYPT, ['cost' => 4]), 4);
    DB::table('users')->where('id', $user->id)->update(['password' => $hash]);

    $this->postJson('/auth/login', ['email' => "p{$prefix}@y.com", 'password' => $long.'-anything'])->assertStatus(422);
})->with(['$2a$', '$2b$', '$2x$', '$2y$']);

it('refuses a NUL byte under a custom rule set, where the default create would 500 on it', function () {
    Lukk::registerValidation(fn () => ['name' => ['required'], 'email' => ['required', 'email'], 'password' => ['required', 'confirmed']]);

    // Short, so only the NUL check can refuse it; and long, so the answer stays single.
    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'nul@y.com', 'password' => "abc\0def", 'password_confirmation' => "abc\0def"])
        ->assertStatus(422)->assertJsonValidationErrors('password');
    $nul = "abc\0".str_repeat('d', 80);
    $errors = $this->postJson('/auth/register', ['name' => 'n', 'email' => 'nul2@y.com', 'password' => $nul, 'password_confirmation' => $nul])
        ->assertStatus(422)->json('errors.password');
    expect($errors)->toHaveCount(1);
});

it('leaves the password to a registerUsing hook, which does its own create', function () use ($long) {
    // Its user may live at an IdP that takes 100-byte passphrases; lukk's checks guard lukk's own create.
    Lukk::registerValidation(fn () => ['email' => ['required', 'email'], 'password' => ['required']]);
    Lukk::registerUsing(fn (array $payload) => User::forceCreate(['name' => 'n', 'email' => $payload['email'], 'password' => '']));

    $this->postJson('/auth/register', ['email' => 'idp@y.com', 'password' => $long])->assertSuccessful();
});

it('says it once under the default rules, which already carry the check', function () use ($long) {
    $errors = $this->postJson('/auth/register', ['name' => 'n', 'email' => 'once@y.com', 'password' => $long, 'password_confirmation' => $long])
        ->assertStatus(422)->json('errors.password');

    expect($errors)->toBe(['The password may not be longer than 72 bytes.']);
});

it('names the field when a custom rule set let an array password through', function () {
    Lukk::registerValidation(fn () => ['name' => ['required'], 'email' => ['required', 'email'], 'password' => ['required', 'confirmed']]);

    $this->postJson('/auth/register', ['name' => 'n', 'email' => 'arr2@y.com', 'password' => ['x'], 'password_confirmation' => ['x']])
        ->assertStatus(422)->assertJsonPath('errors.password.0', 'The password field must be a string.');
});

it('draws the line at 73 bytes against a stored hash, not further out', function () {
    $user = User::factory()->create(['email' => 'b73@y.com']);
    DB::table('users')->where('id', $user->id)->update(['password' => password_hash(str_repeat('c', 73), PASSWORD_BCRYPT, ['cost' => 4])]);

    $this->postJson('/auth/login', ['email' => 'b73@y.com', 'password' => str_repeat('c', 73)])->assertStatus(422);
});

it('answers false, not a TypeError, for an account with no stored password', function () {
    // Public, so a consumer may call it outside lukk's own order, where the credential check runs first.
    expect(HashablePassword::verifiesOnlyInPart(new GenericUser(['password' => null]), str_repeat('a', 80)))->toBeFalse();
});

it('still refuses an array or a NUL byte for a registerUsing hook, which would 500 hashing either', function (mixed $password) {
    // The documented hook shape hands the password to `Hash::make`; only the 72-byte rule is bcrypt's own.
    Lukk::registerValidation(fn () => ['email' => ['required', 'email'], 'password' => ['required']]);
    Lukk::registerUsing(fn (array $payload) => User::forceCreate(['name' => 'n', 'email' => $payload['email'], 'password' => Hash::make($payload['password'])]));

    $this->postJson('/auth/register', ['email' => 'hook2@y.com', 'password' => $password])->assertStatus(422)->assertJsonValidationErrors('password');
})->with(['array' => [['x']], 'NUL byte' => ["abc\0def"]]);

it('answers 422, not 500, at step-up and change-password on a stored hash the hasher refuses', function () {
    // With `hashing.bcrypt.verify` on (the default), a `$2b$` row makes `Hash::check` throw. Sign-in
    // already failed that closed; these two let it escape, and with the lockout on each 500 still cost
    // an attempt.
    $user = User::factory()->create();
    DB::table('users')->where('id', $user->id)->update(['password' => '$2b$'.substr(password_hash('password', PASSWORD_BCRYPT, ['cost' => 4]), 4)]);
    $access = $user->startSession()->accessToken;

    $this->withToken($access)->postJson('/auth/confirm-password', ['password' => 'password'])->assertStatus(422);
    $this->withToken($access)->postJson('/auth/password', ['current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1'])->assertStatus(422);
});
