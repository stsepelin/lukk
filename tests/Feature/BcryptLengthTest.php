<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Password;
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
