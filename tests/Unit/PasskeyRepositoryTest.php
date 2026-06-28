<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Models\Passkey;
use Lukk\Support\NewPasskey;

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
        ->and($record->name)->toBe('My iPhone');

    expect(Passkey::find('cred-1')->public_key)->not->toBe('COSE-PUBLIC-KEY');
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

it('updates the sign count', function () {
    passkeys()->store(7, new NewPasskey('a', 'k', 5));
    passkeys()->updateSignCount('a', 9);

    expect(passkeys()->findByCredentialId('a')->signCount)->toBe(9);
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
