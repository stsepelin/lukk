<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Crypt;
use Lukk\Actions\ExportAccount;
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

    $export = app(ExportAccount::class)($user->fresh());

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

    $serialized = json_encode(app(ExportAccount::class)($user->fresh()));

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
