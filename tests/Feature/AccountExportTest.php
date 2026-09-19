<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Schema;
use Lukk\Actions\ExportAccount;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Tests\Fixtures\RecordingLockoutRepository;
use Lukk\Tests\Fixtures\User;

uses()->group('account-deletion');

it('exports the sessions, passkeys and two-factor state lukk holds', function () {
    config(['lukk.features.two_factor' => true]);
    $user = User::factory()->create(['email' => 'subject@example.test']);
    $user->startSession();
    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString('JBSWY3DPEHPK3PXP'),
        'two_factor_confirmed_at' => now(),
    ])->save();

    $export = app(ExportAccount::class)($user->refresh());

    expect($export['account']['identifier'])->toBe('subject@example.test')
        ->and($export['sessions'])->toHaveCount(1)
        ->and($export['sessions'][0])->toHaveKeys(['session', 'created_at', 'expires_at'])
        ->and($export['two_factor']['enabled'])->toBeTrue();

    // VALUES, not just keys. `toHaveKeys` passes on `null`, so every timestamp could be null and
    // this test stayed green — while `RefreshTokenRecord::$createdAt` exists specifically to feed
    // this export. An export of nulls is a technically-complete Art. 15 answer that tells the
    // subject nothing.
    expect($export['sessions'][0]['session'])->toBeString()->not->toBeEmpty()
        ->and($export['sessions'][0]['created_at'])->toBeString()
        ->and($export['sessions'][0]['expires_at'])->toBeString()
        ->and($export['generated_at'])->toBeString();

    // ISO-8601, and actually parseable — the format the whole file claims to emit.
    expect(Carbon::parse($export['sessions'][0]['created_at'])->toIso8601String())
        ->toBe($export['sessions'][0]['created_at']);
});

it('never exports credential material', function () {
    // A TOTP secret, recovery codes and a refresh-token hash are not personal data the subject is
    // entitled to receive in any useful sense — they are secrets whose only use is authenticating AS
    // them. Art. 15(4): the right of access must not adversely affect others, and handing a live
    // second factor to whoever intercepts the export is exactly that.
    config(['lukk.features.two_factor' => true]);
    $user = User::factory()->create();
    $pair = $user->startSession();
    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString('JBSWY3DPEHPK3PXP'),
        'two_factor_recovery_codes' => Crypt::encryptString(json_encode(['code-one'])),
        'two_factor_confirmed_at' => now(),
    ])->save();

    $serialized = json_encode(app(ExportAccount::class)($user->refresh()));

    expect($serialized)->not->toContain('JBSWY3DPEHPK3PXP')
        ->and($serialized)->not->toContain('code-one')
        ->and($serialized)->not->toContain(hash('sha256', $pair->refreshToken))
        ->and($serialized)->not->toContain($pair->refreshToken);
});

it('exports over HTTP behind step-up, and refuses without it', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();

    $this->withToken($pair->accessToken)->getJson('/auth/account/export')->assertStatus(423);

    app('auth')->forgetGuards();
    $headers = confirmedHeaders($pair->accessToken);
    app('auth')->forgetGuards();

    $this->withToken($pair->accessToken)->getJson('/auth/account/export', $headers)
        ->assertOk()
        ->assertJsonStructure(['generated_at', 'account', 'sessions', 'passkeys', 'two_factor'])
        ->assertHeader('Cache-Control', 'no-store, private');
});

it('reports two-factor as off when the feature is not in use', function () {
    $user = User::factory()->create();

    expect(app(ExportAccount::class)($user)['two_factor']['enabled'])->toBeFalse();
});

it('formats the two-factor timestamp whether the model casts it or not', function () {
    // `two_factor_confirmed_at` is a column on the CONSUMER's users table, and whether it is cast to
    // a date is their decision. Assuming Carbon turned a data-subject export into a 500.
    config(['lukk.features.two_factor' => true]);
    $user = User::factory()->create();
    $export = app(ExportAccount::class);

    $user->two_factor_confirmed_at = new DateTimeImmutable('2026-03-04T05:06:07+00:00');
    expect($export($user)['two_factor']['confirmed_at'])->toStartWith('2026-03-04T05:06:07');

    // An uncast model hands over a raw string.
    $user->two_factor_confirmed_at = '2026-03-04 05:06:07';
    expect($export($user)['two_factor']['confirmed_at'])->toStartWith('2026-03-04T05:06:07');

    $user->two_factor_confirmed_at = null;
    expect($export($user)['two_factor']['confirmed_at'])->toBeNull();
});

it('exports the lockout counters erasure would delete, in all three key spaces', function () {
    // Art. 15 completeness: `DeleteAccount` erases lukk_lockouts rows as personal data, so the export
    // has to disclose the same rows — an erasure that destroys what an access request never showed is
    // the "half-answer that looks whole" this action warns about.
    $user = User::factory()->create(['email' => 'Locked@Example.test']);
    $lockouts = app(LockoutRepository::class);

    $lockouts->recordFailure('login', LoginRateLimiter::lockoutSubject($user, ''), 'api');          // id:<id>
    $lockouts->recordFailure('login', LoginRateLimiter::lockoutSubject($user, ''), 'api');
    $lockouts->recordFailure('confirm', (string) $user->getKey(), 'api');                          // <id>
    $lockouts->recordFailure('login', LoginRateLimiter::lockoutSubject(null, $user->email), 'api'); // idn:<normalized>

    // Someone else's counter, which must not appear.
    $other = User::factory()->create();
    $lockouts->recordFailure('login', LoginRateLimiter::lockoutSubject($other, ''), 'api');

    $export = app(ExportAccount::class)($user);

    expect($export['lockouts'])->toHaveCount(3)
        ->and(collect($export['lockouts'])->pluck('purpose')->sort()->values()->all())->toBe(['confirm', 'login', 'login'])
        ->and(collect($export['lockouts'])->pluck('attempts')->sort()->values()->all())->toBe([1, 1, 2])
        ->and($export['lockouts'][0])->toHaveKeys(['purpose', 'attempts', 'locked_at', 'first_failed_at', 'last_failed_at'])
        ->and($export['lockouts'][0]['last_failed_at'])->toBeString()
        // lukk's internal key format is not the subject's data; the purpose and counts are.
        ->and(json_encode($export['lockouts']))->not->toContain('idn:')->not->toContain('id:');
});

it('exports no lockouts when the lockout table was never published', function () {
    Schema::drop('lukk_lockouts');

    expect(app(ExportAccount::class)(User::factory()->create())['lockouts'])->toBe([]);
});

it('exports no lockouts for a construction that passes none, with the table published', function () {
    // The OTHER half of that guard. The provider always supplies the repository, so this half is only
    // reachable through a direct construction written against 0.6 — which the nullable parameter exists
    // to keep working. Unreached, turning the `||` into an `&&` is invisible, and that one character
    // puts a method call on null: a 500 on a GDPR export route for exactly those consumers.
    $export = new ExportAccount(
        app(RefreshTokenRepository::class),
        app(PasskeyRepository::class),
        'email',
    );

    expect(Schema::hasTable('lukk_lockouts'))->toBeTrue()
        ->and($export(User::factory()->create())['lockouts'])->toBe([]);
});

function exporter(string $identifierColumn = 'email', ?LockoutRepository $lockouts = null): ExportAccount
{
    return new ExportAccount(app(RefreshTokenRepository::class), app(PasskeyRepository::class), $identifierColumn, $lockouts, 'api');
}

it('exports every session field and the account id', function () {
    $user = User::factory()->create();
    $user->startSession();

    $export = app(ExportAccount::class)($user);

    expect($export['account']['id'])->toBe($user->getKey())
        ->and(array_keys($export['sessions'][0]))->toBe(['session', 'created_at', 'last_rotated_at', 'revoked_at', 'expires_at']);
});

it('formats a raw string timestamp from a model that does not cast it, and reads an empty one as none', function () {
    // The fixture model casts the column, so a string set on it arrives as a Carbon. A model that
    // does not cast hands over the raw value.
    $export = exporter()(new GenericUser(['id' => 5, 'two_factor_confirmed_at' => '2026-03-04 05:06:07']));
    expect($export['two_factor']['confirmed_at'])->toBe('2026-03-04T05:06:07+00:00');

    expect(exporter()(new GenericUser(['id' => 5, 'two_factor_confirmed_at' => '']))['two_factor']['confirmed_at'])->toBeNull();
});

it('exports a numeric identifier as a string', function () {
    expect(exporter('phone')(new GenericUser(['id' => 5, 'phone' => 5551234]))['account']['identifier'])->toBe('5551234');
});

it('asks the lockout store about all three key spaces, as strings', function () {
    // The contract hands a replacement repository `array<int, string>`; an int id there is a
    // strict comparison waiting to miss.
    $spy = new RecordingLockoutRepository;
    exporter('email', $spy)(new GenericUser(['id' => 5, 'email' => 'Ada@Example.test']));
    expect($spy->summarised)->toBe(['id:5', '5', 'idn:ada@example.test']);

    // No identifier: the third key space is empty, which the repository skips.
    exporter('email', $spy)(new GenericUser(['id' => 5]));
    expect($spy->summarised)->toBe(['id:5', '5', '']);
});
