<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\Rules\Password as PasswordRule;
use Lukk\Http\Requests\RegisterRequest;
use Lukk\Lukk;
use Lukk\Support\HashablePassword;
use Lukk\Tests\Fixtures\StricterRegisterRequest;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\Fixtures\WordedRegisterRequest;

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

it('holds a new password to the policy as it will be stored, not as it was typed', function (Closure $submit) {
    // Four `e`, each followed by a combining accent: eight characters as typed, four once composed. Judged
    // as typed it passed the eight-character minimum and was stored — and signed in with — as four.
    $shrinks = str_repeat("e\u{0301}", 4);
    expect(mb_strlen($shrinks))->toBe(8)->and(mb_strlen(HashablePassword::normalize($shrinks)))->toBe(4);

    $submit()($shrinks)->assertStatus(422)->assertJsonValidationErrorFor('password');
    // The same accents on eight letters are eight characters either way: accepted.
    $submit()(str_repeat("e\u{0301}", 8))->assertSuccessful();
})->with([
    'registration' => [fn () => fn (string $password) => test()->postJson('/auth/register', [
        'name' => 'Ada', 'email' => 'policy@example.test', 'password' => $password, 'password_confirmation' => $password,
    ])],
    'reset' => [fn () => function (string $password) {
        $user = User::query()->firstOrCreate(['email' => 'reset-policy@example.test'], ['name' => 'Ada', 'password' => Hash::make('old-password-1')]);

        return test()->postJson('/auth/reset-password', [
            'email' => $user->email, 'token' => Password::broker()->createToken($user),
            'password' => $password, 'password_confirmation' => $password,
        ]);
    }],
    'change' => [fn () => function (string $password) {
        $user = User::query()->firstOrCreate(['email' => 'change-policy@example.test'], ['name' => 'Ada', 'password' => Hash::make('old-password-1')]);
        app('auth')->forgetGuards();

        return test()->withToken($user->startSession()->accessToken)->postJson('/auth/password', [
            'current_password' => 'old-password-1', 'password' => $password, 'password_confirmation' => $password,
        ]);
    }],
]);

it('holds a password to a custom registration rule set as it will be stored too', function (Closure $rules) {
    // `registerValidation()` replaces the rules wholesale, lukk's own judging of the stored spelling
    // included: an application's `min:8` was answered about the eight characters typed, and four stored.
    config(['lukk.features.registration' => true]);
    Lukk::registerValidation($rules());
    $register = fn (string $email, string $password) => $this->postJson('/auth/register', [
        'name' => 'Ada', 'email' => $email, 'password' => $password, 'password_confirmation' => $password,
    ]);

    try {
        $response = $register('custom-short@example.test', str_repeat("e\u{0301}", 4))->assertStatus(422);
        // In the rule's own words, once.
        expect($response->json('errors.password'))->toBe(['The password field must be at least 8 characters.'])
            ->and(User::where('email', 'custom-short@example.test')->exists())->toBeFalse();

        // Eight letters under the same accents are eight either way; so is a password with nothing to
        // normalize, which is not asked about twice.
        $register('custom-long@example.test', str_repeat("e\u{0301}", 8))->assertSuccessful();
        $register('custom-plain@example.test', 'plain-ascii-1')->assertSuccessful();
    } finally {
        Lukk::$registerValidation = null;
    }
})->with([
    'a string rule' => [fn () => fn () => ['name' => ['required'], 'email' => ['required', 'email'], 'password' => ['required', 'confirmed', 'min:8']]],
    'a rule object' => [fn () => fn () => ['name' => ['required'], 'email' => ['required', 'email'], 'password' => ['required', 'confirmed', PasswordRule::min(8)]]],
]);

it('compares the confirmation as stored too, and leaves the input as it was typed', function () {
    config(['lukk.features.registration' => true]);
    $seen = [];
    $asked = [];
    $names = 0;
    // A rule on the password that reads the request: it must still see what was sent. And one that
    // compares it with a field of the set's own naming, which has to be there, and respelled with it.
    Lukk::registerValidation(function ($request) use (&$seen, &$asked, &$names) {
        // Only the password's rules are asked again: the name's run once per request, and the email stays
        // the email, so `different:email` still has something else to differ from.
        return ['name' => ['required', function () use (&$names) {
            $names++;
        }], 'email' => ['required', 'email'], 'password' => ['required', 'confirmed', 'min:8', 'same:password_again', 'different:email', function (string $attribute, mixed $value) use ($request, &$seen, &$asked) {
            $seen[] = $request->input('password');
            $asked[] = $value;
        }]];
    });

    try {
        // Typed decomposed, confirmed the same way: equal as typed and equal as stored.
        $this->postJson('/auth/register', [
            'name' => 'Ada', 'email' => 'confirmed@example.test', 'password' => DECOMPOSED, 'password_confirmation' => DECOMPOSED, 'password_again' => DECOMPOSED,
        ])->assertSuccessful();
        $this->postJson('/auth/register', [
            'name' => 'Ada', 'email' => 'plain@example.test', 'password' => 'plain-ascii-1', 'password_confirmation' => 'plain-ascii-1', 'password_again' => 'plain-ascii-1',
        ])->assertSuccessful();
    } finally {
        Lukk::$registerValidation = null;
    }

    // Asked as typed, then as stored — and a password with nothing to normalize only once.
    expect($seen)->toBe([DECOMPOSED, DECOMPOSED, 'plain-ascii-1'])
        ->and($asked)->toBe([DECOMPOSED, COMPOSED, 'plain-ascii-1'])
        ->and($names)->toBe(2)
        ->and(Hash::check(COMPOSED, storedHash(User::where('email', 'confirmed@example.test')->firstOrFail())))->toBeTrue();
});

it('finds a repeated password wherever the rule set keeps it, a nested field included', function () {
    config(['lukk.features.registration' => true]);
    Lukk::registerValidation(fn () => ['name' => ['required'], 'email' => ['required', 'email'], 'password' => ['required', 'min:8', 'same:confirm.password']]);

    try {
        // Typed the same in both places: equal as typed, and so equal as stored.
        $this->postJson('/auth/register', [
            'name' => 'Ada', 'email' => 'nested@example.test', 'password' => DECOMPOSED, 'confirm' => ['password' => DECOMPOSED],
        ])->assertSuccessful();
    } finally {
        Lukk::$registerValidation = null;
    }
});

it('does not ask lukk\'s own rules twice: they judge the stored spelling themselves', function () {
    // Asked again, `Password::defaults()` ran twice for such a password — with `uncompromised()`, two
    // lookups of one password against the breach list.
    config(['lukk.features.registration' => true]);
    $asked = 0;
    PasswordRule::defaults(function () use (&$asked) {
        $asked++;

        return PasswordRule::min(8);
    });

    try {
        $this->postJson('/auth/register', [
            'name' => 'Ada', 'email' => 'default-rules@example.test', 'password' => DECOMPOSED, 'password_confirmation' => DECOMPOSED,
        ])->assertSuccessful();
    } finally {
        PasswordRule::$defaultCallback = null;
    }

    expect($asked)->toBe(1);
});

it('asks a rule a subclass adds to lukk\'s own, though lukk\'s own were its starting point', function () {
    // `parent::rules()` plus a `min:12`: lukk's policy rule judges the stored spelling by itself, the
    // added one does not. Ten decomposed letters are twenty characters typed and ten stored.
    config(['lukk.features.registration' => true]);
    app()->bind(RegisterRequest::class, StricterRegisterRequest::class);
    $register = fn (string $email, string $password) => $this->postJson('/auth/register', [
        'name' => 'Ada', 'email' => $email, 'password' => $password, 'password_confirmation' => $password,
    ]);

    $response = $register('stricter-short@example.test', str_repeat("e\u{0301}", 10))->assertStatus(422);
    expect($response->json('errors.password'))->toBe(['The password field must be at least 12 characters.']);

    $register('stricter-long@example.test', str_repeat("e\u{0301}", 12))->assertSuccessful();
});

it('answers for a rebound request in that request\'s own words', function () {
    config(['lukk.features.registration' => true]);
    app()->bind(RegisterRequest::class, WordedRegisterRequest::class);
    $short = str_repeat("e\u{0301}", 4);

    $response = $this->postJson('/auth/register', [
        'name' => 'Ada', 'email' => 'worded@example.test', 'password' => $short, 'password_confirmation' => $short,
    ])->assertStatus(422);

    expect($response->json('errors.password'))->toBe(['Your passphrase is too short.']);
});

it('leaves a password a registerUsing hook will store to the rules as typed', function () {
    // The hook owns what is stored — as typed, if it likes — so the stored spelling is not lukk's to judge.
    config(['lukk.features.registration' => true]);
    Lukk::registerValidation(fn () => ['name' => ['required'], 'email' => ['required', 'email'], 'password' => ['required', 'confirmed', 'min:8']]);
    Lukk::registerUsing(fn (array $payload) => User::create(['name' => $payload['name'], 'email' => $payload['email'], 'password' => Hash::make($payload['password'])]));

    try {
        $short = str_repeat("e\u{0301}", 4);
        $this->postJson('/auth/register', [
            'name' => 'Ada', 'email' => 'hook@example.test', 'password' => $short, 'password_confirmation' => $short,
        ])->assertSuccessful();
    } finally {
        Lukk::$registerValidation = null;
        Lukk::$registerUsing = null;
    }
});

it('says what the application\'s own policy says, about the attribute it was asked about', function () {
    PasswordRule::defaults(fn () => PasswordRule::min(12));
    $user = User::factory()->create(['password' => Hash::make('old-password-1')]);

    try {
        $response = $this->withToken($user->startSession()->accessToken)->postJson('/auth/password', [
            'current_password' => 'old-password-1', 'password' => 'ten-chars!', 'password_confirmation' => 'ten-chars!',
        ])->assertStatus(422);
    } finally {
        PasswordRule::$defaultCallback = null;
    }

    expect($response->json('errors.password'))->toBe(['The password field must be at least 12 characters.']);
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
