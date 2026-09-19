<?php

declare(strict_types=1);

use Lukk\Contracts\WebAuthnCeremony;

uses()->group('passkeys');

function ceremony(): WebAuthnCeremony
{
    app()->forgetInstance(WebAuthnCeremony::class);

    return app(WebAuthnCeremony::class);
}

it('builds the ceremony from the configured relying party', function () {
    config(['lukk.passkeys' => [
        'rp_id' => 'example.com', 'rp_name' => 'Example Shop',
        'origins' => ['https://app.example.com'], 'user_verification' => 'preferred',
    ]]);

    $options = ceremony()->registrationOptions(1, 'ada', rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='), []);

    expect($options['rp'])->toEqual(['name' => 'Example Shop', 'id' => 'example.com'])
        ->and($options['authenticatorSelection']['userVerification'])->toBe('preferred');
});

it('refuses with its own message when the passkeys block is missing entirely', function () {
    // Not an ErrorException from indexing null: the ceremony's "set LUKK_PASSKEY_RP_ID" is the message
    // that tells the operator what is missing.
    config(['lukk.passkeys' => null]);

    expect(fn () => ceremony())->toThrow(InvalidArgumentException::class, 'Passkeys require lukk.passkeys.rp_id');
});
