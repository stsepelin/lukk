<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Lukk\Tests\ConcurrencyTestCase;
use Lukk\Tests\Fixtures\User;

uses(ConcurrencyTestCase::class)->group('concurrency');

/*
 * The login throttle keys on the identifier's FOLD (`LoginRateLimiter::normalize()`), and with the
 * lockout off — the default — its IP-independent account bucket is the only thing bounding a
 * distributed guesser (NIST SP 800-63B-4 §3.2.2). The fold must therefore never be FINER than the
 * database's own equality: a spelling the database resolves to the victim but the fold keys apart is a
 * fresh bucket, and every such spelling is another `account_max_attempts` guesses.
 *
 * Both engines had one. pdo_pgsql passes a bound string as a C string, so it ends at the first NUL —
 * `victim@example.com\0<n>` looks up the victim, and each `<n>` folded to its own key. MySQL's
 * `utf8mb4_unicode_ci` gives default-ignorable code points (U+200B, U+034F) no weight and pads trailing
 * U+3000 like a space, so those match the victim too, while `Str::transliterate` kept them as `' '`/`?`.
 * Only visible on a real engine: sqlite compares bytes.
 */

dataset('respellings', [
    'NUL suffix (pdo_pgsql truncates)' => ["victim@example.com\0x1"],
    'zero-width space (ignorable)' => ["victim\u{200B}@example.com"],
    'combining grapheme joiner (ignorable)' => ["victim\u{034F}@example.com"],
    'trailing ideographic space (PAD SPACE)' => ["victim@example.com\u{3000}"],
    'combining mark (accent-insensitive)' => ["vi\u{0301}ctim@example.com"],
]);

it('gives a respelled identifier no guesses past the account cap', function (string $respelled) {
    config([
        'lukk.rate_limits.login.max_attempts' => 500,
        'lukk.rate_limits.login.ip_max_attempts' => 500,
        'lukk.rate_limits.login.account_max_attempts' => 3,
    ]);
    User::factory()->create(['email' => 'victim@example.com', 'password' => bcrypt('correct')]);

    foreach (range(1, 3) as $ignored) {
        $this->postJson('/auth/login', ['email' => 'victim@example.com', 'password' => 'wrong'])->assertStatus(422);
    }
    $this->postJson('/auth/login', ['email' => 'victim@example.com', 'password' => 'correct'])->assertStatus(429);

    // The attack: the canonical bucket is spent, so guess under a spelling the database still resolves
    // to the victim. With the RIGHT password, so a 200 means the guess was verified.
    $response = $this->postJson('/auth/login', ['email' => $respelled, 'password' => 'correct']);

    expect($response->status())->toBeIn([422, 429])
        ->and($response->json('access_token'))->toBeNull();
})->with('respellings');

it('stores no truncated identifier: NUL is refused wherever one is written or looked up', function (string $route, array $body) {
    // pdo_pgsql stored `"a\0b"` as `"a"`, so a registration carrying a NUL wrote a DIFFERENT value than
    // the one validated — `unique` checked the full string, the INSERT kept the prefix. Refused instead.
    $response = $this->postJson($route, $body);

    expect($response->status())->toBe(422)
        ->and(DB::table('users')->where('email', 'like', 'new%')->exists())->toBeFalse();
})->with([
    'registration identifier' => ['/auth/register', ['name' => 'New', 'email' => "new@example.com\0x", 'password' => 'Str0ng-passw0rd!', 'password_confirmation' => 'Str0ng-passw0rd!']],
    'registration name' => ['/auth/register', ['name' => "New\0Admin", 'email' => 'new@example.com', 'password' => 'Str0ng-passw0rd!', 'password_confirmation' => 'Str0ng-passw0rd!']],
    'forgot password' => ['/auth/forgot-password', ['email' => "victim@example.com\0x"]],
    'reset password' => ['/auth/reset-password', ['token' => 't', 'email' => "victim@example.com\0x", 'password' => 'Str0ng-passw0rd!', 'password_confirmation' => 'Str0ng-passw0rd!']],
]);
