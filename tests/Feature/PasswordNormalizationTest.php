<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Lukk\Support\HashablePassword;
use Lukk\Tests\Fixtures\User;

/*
 * NIST SP 800-63B-4 §3.1.1.2: a verifier that accepts Unicode SHOULD normalize (NFKC or NFKD) before
 * hashing. The same text arrives as different bytes from different keyboards — `é` as U+00E9 or as `e`
 * plus U+0301 — and hashed as typed, a password set on one device was "incorrect" on another.
 */

const COMPOSED = "Caf\u{00E9}-passphrase-1";      // NFC: one code point for é
const DECOMPOSED = "Cafe\u{0301}-passphrase-1";   // NFD: e + combining acute — the same text

function storedHash(User $user): string
{
    return (string) DB::table('users')->where('id', $user->id)->value('password');
}

function login(string $email, string $password)
{
    app('auth')->forgetGuards();

    return test()->postJson('/auth/login', ['email' => $email, 'password' => $password]);
}

it('normalizes to NFKC, and leaves alone what has no normal form', function () {
    expect(HashablePassword::normalize(DECOMPOSED))->toBe(COMPOSED)
        ->and(HashablePassword::normalize(COMPOSED))->toBe(COMPOSED)
        // Compatibility forms fold too: a full-width digit from an IME is the digit.
        ->and(HashablePassword::normalize("pass\u{FF11}"))->toBe('pass1')
        ->and(HashablePassword::normalize('plain-ascii'))->toBe('plain-ascii')
        ->and(HashablePassword::normalize(''))->toBe('')
        // Not valid UTF-8: hashed as the bytes it is, never as `false` or an empty string.
        ->and(HashablePassword::normalize("bad\xFFbytes"))->toBe("bad\xFFbytes");
});

it('tries a password as typed first, then normalized, and only once when they are the same', function () {
    expect(HashablePassword::spellings(DECOMPOSED))->toBe([DECOMPOSED, COMPOSED])
        ->and(HashablePassword::spellings(COMPOSED))->toBe([COMPOSED])
        ->and(HashablePassword::spellings("bad\xFFbytes"))->toBe(["bad\xFFbytes"]);
});

it('signs in under either spelling of a password set through lukk', function (string $registered) {
    config(['lukk.features.registration' => true]);
    $this->postJson('/auth/register', ['name' => 'N', 'email' => 'n@y.com', 'password' => $registered, 'password_confirmation' => $registered])->assertSuccessful();

    expect(Hash::check(COMPOSED, (string) DB::table('users')->where('email', 'n@y.com')->value('password')))->toBeTrue();

    login('n@y.com', COMPOSED)->assertOk();
    login('n@y.com', DECOMPOSED)->assertOk();
})->with(['registered composed' => [COMPOSED], 'registered decomposed' => [DECOMPOSED]]);

it('still accepts a password hashed, before normalization, from the bytes its owner typed', function () {
    // Every hash older than this change. Checking only the normal form would lock out each account whose
    // password is not already in it — so the bytes as typed are always tried first.
    $user = User::factory()->create(['password' => Hash::make(DECOMPOSED)]);

    login($user->email, DECOMPOSED)->assertOk();
    // The other spelling of a pre-normalization hash was never accepted, and still is not.
    login($user->email, COMPOSED)->assertStatus(422);
});

it('stores a reset password normalized', function () {
    $user = User::factory()->create();

    $this->postJson('/auth/reset-password', [
        'email' => $user->email, 'token' => Password::broker()->createToken($user),
        'password' => DECOMPOSED, 'password_confirmation' => DECOMPOSED,
    ])->assertOk();

    expect(Hash::check(COMPOSED, storedHash($user)))->toBeTrue();
});

it('checks the current password under either spelling, and stores the new one normalized', function () {
    $user = User::factory()->create(['password' => Hash::make(COMPOSED)]);
    $access = $user->startSession()->accessToken;

    $this->withToken($access)->postJson('/auth/password', [
        'current_password' => DECOMPOSED, 'password' => "New-pass\u{FF11}-phrase", 'password_confirmation' => "New-pass\u{FF11}-phrase",
    ])->assertSuccessful();

    expect(Hash::check('New-pass1-phrase', storedHash($user)))->toBeTrue();
});

it('confirms a step-up under either spelling', function () {
    $user = User::factory()->create(['password' => Hash::make(COMPOSED)]);
    $access = $user->startSession()->accessToken;

    $this->withToken($access)->postJson('/auth/confirm-password', ['password' => DECOMPOSED])->assertOk();
    $this->withToken($access)->postJson('/auth/confirm-password', ['password' => 'Cafe-passphrase-1'])->assertStatus(422);
});

it('upgrades a weak hash with the spelling that verified, not the one that was typed', function () {
    // The stored hash is of the normal form; the user types the other. Rehashing what was TYPED would
    // replace a hash both spellings open with one only this device's spelling does.
    $user = User::factory()->create(['password' => Hash::make(COMPOSED, ['rounds' => 5])]);

    login($user->email, DECOMPOSED)->assertOk();

    expect(Hash::needsRehash(storedHash($user)))->toBeFalse()
        ->and(Hash::check(COMPOSED, storedHash($user)))->toBeTrue();
});

it('measures the bcrypt limit on the password as it will be hashed', function () {
    // 24 × `㈱` is 72 bytes as typed and 120 once normalized to `(株)`: inside the limit on the wire and
    // truncated in the hash — or, with Laravel's own guard on, a 500 from `Hash::make`.
    config(['lukk.features.registration' => true]);
    $password = str_repeat("\u{3231}", 24);
    expect(strlen($password))->toBe(72);

    $this->postJson('/auth/register', ['name' => 'N', 'email' => 'n@y.com', 'password' => $password, 'password_confirmation' => $password])
        ->assertStatus(422)->assertJsonValidationErrorFor('password');
});

it('fails closed on a hash the hasher refuses, and still tries the next spelling', function () {
    $users = new class implements UserProvider
    {
        /** @var list<string> */
        public array $tried = [];

        public function validateCredentials(Authenticatable $user, #[SensitiveParameter] array $credentials): bool
        {
            $this->tried[] = $credentials['password'];

            return $credentials['password'] === DECOMPOSED
                ? throw new RuntimeException('This password does not use the Argon2id algorithm.')
                : $credentials['email'] === 'kept@y.com';
        }

        public function retrieveById($identifier) {}

        public function retrieveByToken($identifier, #[SensitiveParameter] $token) {}

        public function updateRememberToken(Authenticatable $user, #[SensitiveParameter] $token) {}

        public function retrieveByCredentials(#[SensitiveParameter] array $credentials) {}

        public function rehashPasswordIfRequired(Authenticatable $user, #[SensitiveParameter] array $credentials, bool $force = false) {}
    };

    // The provider is handed the other credentials untouched, and the password per spelling.
    expect(HashablePassword::verified($users, new User, ['email' => 'kept@y.com', 'password' => DECOMPOSED]))->toBe(COMPOSED)
        ->and($users->tried)->toBe([DECOMPOSED, COMPOSED])
        ->and(HashablePassword::verified($users, new User, ['email' => 'other@y.com', 'password' => DECOMPOSED]))->toBeNull()
        ->and(HashablePassword::verified($users, new User, ['email' => 'kept@y.com']))->toBe('')
        // A JSON body may carry a number where the password goes: read as its text, not a TypeError.
        ->and(HashablePassword::verified($users, new User, ['email' => 'kept@y.com', 'password' => 12345678]))->toBe('12345678');
});
