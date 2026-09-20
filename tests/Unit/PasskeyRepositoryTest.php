<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Models\Passkey;
use Lukk\Support\NewPasskey;
use Lukk\Tests\Fixtures\Admin;

uses()->group('passkeys');

function passkeys(): PasskeyRepository
{
    return app(PasskeyRepository::class);
}

it('stores and finds a credential, encrypting the public key at rest', function () {
    passkeys()->store(7, new NewPasskey('cred-1', 'COSE-PUBLIC-KEY', 0, ['internal'], 'aaguid-x'), 'My iPhone');

    $record = passkeys()->findByCredentialId('cred-1');

    expect($record->credentialId)->toBe('cred-1')
        ->and($record->userId)->toEqual(7)
        ->and($record->publicKey)->toBe('COSE-PUBLIC-KEY')
        ->and($record->transports)->toBe(['internal'])
        ->and($record->aaguid)->toBe('aaguid-x')
        ->and($record->name)->toBe('My iPhone');

    expect(Passkey::findOrFail('cred-1')->public_key)->not->toBe('COSE-PUBLIC-KEY');
});

it('returns null for an unknown credential', function () {
    expect(passkeys()->findByCredentialId('nope'))->toBeNull();
});

it('lists a user’s credential ids and records', function () {
    passkeys()->store(7, new NewPasskey('a', 'k', 0));
    passkeys()->store(7, new NewPasskey('b', 'k', 0));
    passkeys()->store(9, new NewPasskey('c', 'k', 0));

    expect(passkeys()->credentialIdsFor(7))->toEqualCanonicalizing(['a', 'b']);
    expect(passkeys()->summariesForUser(7))->toHaveCount(2)
        ->and(passkeys()->summariesForUser(7)[0])->toHaveKeys(['credential_id', 'name', 'last_used_at']);
});

it('summarises each credential by id, name and last use', function () {
    $this->freezeSecond();
    passkeys()->store(7, new NewPasskey('a', 'k', 0), 'My iPhone');
    passkeys()->updateSignCount('a', 1);

    expect(passkeys()->summariesForUser(7))->toBe([
        ['credential_id' => 'a', 'name' => 'My iPhone', 'last_used_at' => now()->getTimestamp()],
    ]);
});

it('updates the sign count', function () {
    passkeys()->store(7, new NewPasskey('a', 'k', 5));
    passkeys()->updateSignCount('a', 9);

    expect(notNull(passkeys()->findByCredentialId('a'))->signCount)->toBe(9);
});

it('stamps the last use when the sign count moves', function () {
    $this->freezeSecond();
    passkeys()->store(7, new NewPasskey('a', 'k', 5));
    expect(notNull(passkeys()->findByCredentialId('a'))->lastUsedAt)->toBeNull();

    passkeys()->updateSignCount('a', 6);

    expect(notNull(passkeys()->findByCredentialId('a'))->lastUsedAt)->toBe(now()->getTimestamp());
});

it('prunes nothing, and says so, on an install without the passkeys table', function () {
    Schema::drop('passkeys');

    expect(passkeys()->pruneOrphaned())->toBe(0);
});

it('judges orphans against the configured user provider, not the default users table', function () {
    // A single-guard install whose users live in `admins`: judged against `users`, every one of
    // their passkeys would read as orphaned and be deleted by the daily prune.
    Schema::create('admins', function (Blueprint $table) {
        $table->id();
        $table->string('email')->unique();
        $table->string('password');
    });
    config([
        'lukk.user_provider' => 'admins',
        'auth.providers.admins' => ['driver' => 'eloquent', 'model' => Admin::class],
    ]);
    $admin = Admin::query()->forceCreate(['id' => 500, 'email' => 'a@example.test', 'password' => 'x']);
    passkeys()->store($admin->getKey(), new NewPasskey('admin-cred', 'k', 0));
    passkeys()->store(999, new NewPasskey('ghost', 'k', 0));

    expect(passkeys()->pruneOrphaned())->toBe(1)
        ->and(Passkey::find('admin-cred'))->not->toBeNull();
});

it('enforces global credential-id uniqueness', function () {
    passkeys()->store(7, new NewPasskey('dup', 'k', 0));

    expect(fn () => passkeys()->store(9, new NewPasskey('dup', 'k', 0)))->toThrow(QueryException::class);
});

it('deletes only the owner’s credential', function () {
    passkeys()->store(7, new NewPasskey('mine', 'k', 0));

    expect(passkeys()->delete(9, 'mine'))->toBeFalse();
    expect(passkeys()->findByCredentialId('mine'))->not->toBeNull();

    expect(passkeys()->delete(7, 'mine'))->toBeTrue();
    expect(passkeys()->findByCredentialId('mine'))->toBeNull();
});

it('reads the sign count as an integer whatever the driver hands back', function () {
    // Some PDO drivers return integer columns as strings.
    expect((new Passkey)->forceFill(['sign_count' => '7'])->sign_count)->toBe(7);
});
