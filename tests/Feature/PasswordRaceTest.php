<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Lukk\Actions\AttemptLogin;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Actions\StartSession;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Lukk;
use Lukk\Support\PasswordFingerprint;
use Lukk\Support\TokenPair;
use Lukk\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

/**
 * A sign-in checked against a password that is replaced before its session exists.
 *
 * Change and reset write the new hash, THEN sweep the account's sessions. A sign-in that had already
 * checked the OLD password and wrote its session after that sweep survived it — the one sign-in a
 * recovery reset exists to shut out. These interleave the two by hand; the real race is the same order.
 */
uses()->group('two-factor');

/** A password change or reset, exactly as both run it: the hash first, then the sweep. */
function replacePassword(User $user): void
{
    $user->forceFill(['password' => Hash::make('the-new-password')])->save();
    app(RevokeAllSessions::class)($user->getKey());
}

function liveFamilies(User $user): int
{
    return DB::table('refresh_tokens')->where('user_id', $user->getKey())->whereNull('revoked_at')->count();
}

function enrolled(User $user): string
{
    $secret = app(TwoFactorProvider::class)->generateSecret();
    $user->forceFill(['two_factor_secret' => Crypt::encryptString($secret), 'two_factor_confirmed_at' => now()])->save();

    return $secret;
}

it('takes back a session whose password was replaced after it was checked', function () {
    // The change completes between the check and the session write, so its sweep runs before the session
    // exists and cannot see it.
    $user = User::factory()->create();
    app()->extend(StartSession::class, fn (StartSession $start) => new class($start, $user) extends StartSession
    {
        public function __construct(private StartSession $inner, private User $user) {}

        public function __invoke(int|string $userId, array $claims = [], ?array $abilities = null): TokenPair
        {
            replacePassword($this->user);

            return ($this->inner)($userId, $claims, $abilities);
        }
    });

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertUnprocessable()
        ->assertJsonValidationErrors(['email' => 'These credentials do not match our records.'])
        ->assertJsonMissingPath('access_token');

    expect(liveFamilies($user))->toBe(0);
});

it('still signs in when the password is unchanged', function () {
    $user = User::factory()->create();

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertOk();

    expect(liveFamilies($user))->toBe(1);
});

it('refuses a two-factor challenge whose password was replaced before it was redeemed', function () {
    // The window here is the whole `challenge_ttl`: the password is checked at login, the session started
    // minutes later at redemption.
    $user = User::factory()->create();
    $secret = enrolled($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->json('challenge_token');

    $user->refresh();
    replacePassword($user);

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => app(Google2FA::class)->getCurrentOtp($secret)])
        ->assertUnprocessable()
        ->assertJsonValidationErrors(['challenge_token' => 'The two-factor challenge is invalid or has expired.'])
        ->assertJsonMissingPath('access_token');

    expect(liveFamilies($user))->toBe(0);
});

it('redeems a two-factor challenge whose password is unchanged', function () {
    $user = User::factory()->create();
    $secret = enrolled($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => app(Google2FA::class)->getCurrentOtp($secret)])
        ->assertOk()->assertJsonStructure(['access_token']);
});

it('refuses a challenge that does not say which password it stands in for', function () {
    // A co-issuer's, or one minted before the claim existed. Nothing can show its password is unchanged,
    // so it is not taken as unchanged — the cost is one fresh sign-in.
    $user = User::factory()->create();
    $secret = enrolled($user);
    $challenge = app(ChallengeToken::class)->issue('2fa', $user->getKey(), 300);

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => app(Google2FA::class)->getCurrentOtp($secret)])
        ->assertUnprocessable()->assertJsonValidationErrors('challenge_token');

    expect(liveFamilies($user))->toBe(0);
});

it('fingerprints the password without carrying it', function () {
    // The fingerprint rides in a challenge token the client can read: never the hash, and never stable
    // across a change.
    $user = User::factory()->create();
    $before = PasswordFingerprint::of($user);

    expect($before)->not->toContain($user->getAuthPassword())
        ->and($before)->toMatch('/^[0-9a-f]{64}$/')
        ->and(PasswordFingerprint::of($user))->toBe($before);

    $user->forceFill(['password' => Hash::make('other')]);
    expect(PasswordFingerprint::of($user))->not->toBe($before);
});

/** Run the password change inside the sign-in, after the check and before the session is written. */
function changePasswordMidSignIn(User $user): void
{
    app()->extend(StartSession::class, fn (StartSession $start) => new class($start, $user) extends StartSession
    {
        public function __construct(private StartSession $inner, private User $user) {}

        public function __invoke(int|string $userId, array $claims = [], ?array $abilities = null): TokenPair
        {
            replacePassword($this->user);

            return ($this->inner)($userId, $claims, $abilities);
        }
    });
}

describe('with Lukk::authenticateUsing', function () {
    afterEach(fn () => Lukk::$authenticateUsing = null);

    it('signs in a user the callback returns without its password loaded', function () {
        // SSO and LDAP callbacks check no local password and often load only what they need. Compared
        // against that model, every sign-in read as "password changed" and answered 422.
        $user = User::factory()->create();
        Lukk::authenticateUsing(fn () => User::query()->select(['id', 'email'])->find($user->getKey()));

        $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'anything'])->assertOk();
        expect(liveFamilies($user))->toBe(1);
    });

    it('still takes back a session whose stored password changed after the callback returned', function () {
        $user = User::factory()->create();
        Lukk::authenticateUsing(fn () => User::query()->select(['id', 'email'])->find($user->getKey()));
        changePasswordMidSignIn($user);

        $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'anything'])->assertUnprocessable();
        expect(liveFamilies($user))->toBe(0);
    });
});

it('re-reads the password from the primary, not a replica behind the change', function () {
    // A read replica still holding the OLD hash would answer "unchanged", and the session would survive.
    // Laravel reads through the write connection while a transaction is open on it, so the re-read opens
    // one. Pinned structurally: this suite already runs inside a transaction, so a replica could not be
    // consulted here anyway — what can be seen is that the last read of the user opens one of its own.
    $user = User::factory()->create();
    $base = DB::transactionLevel();
    $levels = [];
    DB::listen(function ($query) use (&$levels) {
        if (str_contains($query->sql, 'from "users"')) {
            $levels[] = DB::transactionLevel();
        }
    });

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertOk();

    expect(end($levels))->toBeGreaterThan($base);
});

it('answers 422, not 500, when the user is gone by the time the password is re-read', function () {
    $user = User::factory()->create();
    app()->extend(StartSession::class, fn (StartSession $start) => new class($start, $user) extends StartSession
    {
        public function __construct(private StartSession $inner, private User $user) {}

        public function __invoke(int|string $userId, array $claims = [], ?array $abilities = null): TokenPair
        {
            $pair = ($this->inner)($userId, $claims, $abilities);
            DB::table('users')->where('id', $this->user->getKey())->delete();

            return $pair;
        }
    });

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertUnprocessable();
});

it('keys the fingerprint with the app key, and honours the previous keys across a rotation', function () {
    $user = User::factory()->create();
    $secret = enrolled($user);
    $before = PasswordFingerprint::of($user);
    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->json('challenge_token');

    // Rotated the documented way: the old key moves to `app.previous_keys`.
    $old = config('app.key');
    config(['app.key' => 'base64:'.base64_encode(random_bytes(32)), 'app.previous_keys' => [$old]]);
    expect(PasswordFingerprint::of($user))->not->toBe($before);

    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $challenge, 'code' => app(Google2FA::class)->getCurrentOtp($secret)])
        ->assertOk();

    // Without the previous key, a challenge from before the rotation names a password nobody can confirm.
    config(['app.previous_keys' => []]);
    app('auth')->forgetGuards();
    $late = app(ChallengeToken::class)->issue('2fa', $user->getKey(), 300, passwordFingerprint: $before);
    $this->postJson('/auth/two-factor-challenge', ['challenge_token' => $late, 'code' => app(Google2FA::class)->getCurrentOtp($secret)])
        ->assertUnprocessable();
});

it('takes back a session whose password changed right after the check, before anything else read it', function () {
    // The baseline is the model the check read — not a second read after it, which would already see the
    // new password and call the session "unchanged".
    $user = User::factory()->create();
    app()->extend(AttemptLogin::class, fn (AttemptLogin $attempt) => new class($attempt, $user) extends AttemptLogin
    {
        public function __construct(private AttemptLogin $inner, private User $user) {}

        public function __invoke(Request $request): Authenticatable
        {
            $checked = ($this->inner)($request);
            replacePassword($this->user);

            return $checked;
        }
    });

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertUnprocessable();
    expect(liveFamilies($user))->toBe(0);
});

it('works with Laravel\'s database user provider as well as Eloquent', function () {
    // The primary read is arranged through the Eloquent model's connection; any other provider is asked
    // directly, and must not be treated as one.
    config(['auth.providers.users' => ['driver' => 'database', 'table' => 'users']]);
    $user = User::factory()->create();

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertOk();
});

it('reports the race under the configured identifier field', function () {
    config(['lukk.username' => 'name']);
    $user = User::factory()->create(['name' => 'ada']);
    changePasswordMidSignIn($user);

    $this->postJson('/auth/login', ['name' => 'ada', 'password' => 'password'])
        ->assertUnprocessable()->assertJsonValidationErrors('name');
});

it('fingerprints without a TypeError when the key, the password or the previous keys are not strings', function (Closure $configure) {
    // `strict_types`: every one of these reached hash_hmac() as null or an int, and a 500 on sign-in.
    $user = User::factory()->create();
    $configure($user);

    expect(PasswordFingerprint::of($user))->toMatch('/^[0-9a-f]{64}$/')
        ->and(PasswordFingerprint::matches(PasswordFingerprint::of($user), $user))->toBeTrue()
        // A fingerprint no key produced walks EVERY previous key — including a non-string one.
        ->and(PasswordFingerprint::matches(str_repeat('0', 64), $user))->toBeFalse();
})->with([
    'no app key' => [fn () => config(['app.key' => null])],
    'no previous keys at all' => [fn () => config(['app.previous_keys' => null])],
    'a non-string previous key' => [fn () => config(['app.previous_keys' => [12345]])],
    'a user with no password' => [fn (User $user) => $user->forceFill(['password' => null])],
]);
